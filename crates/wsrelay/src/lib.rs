//! WireGuard datagrams over WebSocket. One WG datagram = one binary WS message.
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::Connector;
use tracing::{debug, info, trace, warn};

/// Largest WireGuard datagram we are willing to move in either direction.
pub const MAX_DATAGRAM:usize=65535;
const IDLE:Duration=Duration::from_secs(300);
const PING_EVERY:Duration=Duration::from_secs(30);
const BACKOFF_MIN:Duration=Duration::from_millis(250);
const BACKOFF_MAX:Duration=Duration::from_secs(8);
const QUEUE:usize=1024;
/// Concurrent relay connections accepted at once, each of which owns a UDP socket and a 64KB buffer.
pub const MAX_CONNS:usize=1024;

/// TLS material for the relay listener. None means plain ws (behind a reverse proxy).
#[derive(Clone, Debug)]
pub struct TlsFiles{pub cert:PathBuf, pub key:PathBuf}

fn ws_config()->WebSocketConfig{
	// write_buffer_size 0 keeps latency down: every datagram hits the socket immediately.
	WebSocketConfig::default().read_buffer_size(16*1024).write_buffer_size(0).max_message_size(Some(MAX_DATAGRAM)).max_frame_size(Some(MAX_DATAGRAM))
}

/// Accept WS connections on `listener` at `path`; each connection gets its own UDP socket connected to `target`.
pub async fn serve(listener:TcpListener, tls:Option<TlsFiles>, path:String, target:SocketAddr)->anyhow::Result<()>{
	serve_limited(listener, tls, path, target, MAX_CONNS).await
}

/// Same as [`serve`] but with an explicit ceiling on concurrent connections.
pub async fn serve_limited(listener:TcpListener, tls:Option<TlsFiles>, path:String, target:SocketAddr, max_conns:usize)->anyhow::Result<()>{
	let _=rustls::crypto::ring::default_provider().install_default();
	let limit=Arc::new(tokio::sync::Semaphore::new(max_conns));
	let acceptor=match &tls{
		Some(f)=>{
			let certs=rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(&f.cert)?)).collect::<Result<Vec<_>, _>>()?;
			anyhow::ensure!(!certs.is_empty(), "no certificates in {}", f.cert.display());
			let key=rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(&f.key)?))?.ok_or_else(|| anyhow::anyhow!("no private key in {}", f.key.display()))?;
			let mut cfg=rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
			cfg.alpn_protocols=vec![b"http/1.1".to_vec()];
			Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
		}
		None=>None,
	};
	info!(listen=%listener.local_addr()?, %path, %target, tls=acceptor.is_some(), max_conns, "relay listening");
	loop{
		let (stream, peer)=match listener.accept().await{
			Ok(v)=>v,
			Err(e)=>{warn!(error=%e, "accept failed"); tokio::time::sleep(Duration::from_millis(50)).await; continue}
		};
		let Ok(permit)=limit.clone().try_acquire_owned() else{debug!(%peer, "at the connection limit, refusing"); continue};
		let (acceptor, path)=(acceptor.clone(), path.clone());
		tokio::spawn(async move{
			let _permit=permit;
			let r=match acceptor{
				Some(a)=>match a.accept(stream).await{
					Ok(s)=>relay_conn(s, peer, path, target).await,
					Err(e)=>Err(anyhow::anyhow!("tls handshake: {e}")),
				},
				None=>relay_conn(stream, peer, path, target).await,
			};
			if let Err(e)=r{debug!(%peer, error=%e, "connection ended with an error")}
		});
	}
}

/// One accepted transport: handshake on `path`, then pump a private UDP socket against the WS.
async fn relay_conn<S>(stream:S, peer:SocketAddr, path:String, target:SocketAddr)->anyhow::Result<()>
where S:AsyncRead+AsyncWrite+Unpin{
	let ws=tokio_tungstenite::accept_hdr_async_with_config(stream, move |req:&Request, resp:Response|->Result<Response, ErrorResponse>{
		if req.uri().path()==path{Ok(resp)}else{Err(Response::builder().status(404).body(Some("not found".to_string())).unwrap())}
	}, Some(ws_config())).await?;
	let udp=UdpSocket::bind(if target.is_ipv4(){SocketAddr::from((Ipv4Addr::LOCALHOST, 0))}else{SocketAddr::from((Ipv6Addr::LOCALHOST, 0))}).await?;
	udp.connect(target).await?;
	info!(%peer, %target, "ws connected");
	let (mut tx, mut rx)=ws.split();
	let mut buf=vec![0u8; MAX_DATAGRAM];
	let mut ping=tokio::time::interval(PING_EVERY);
	ping.tick().await;
	let mut deadline=Instant::now()+IDLE;
	let reason=loop{
		tokio::select!{
			msg=rx.next()=>{
				// tungstenite queues the pong for incoming pings itself, so only binary matters here.
				match msg{
					None=>break "closed",
					Some(Err(e))=>{debug!(%peer, error=%e, "ws read failed"); break "error"}
					Some(Ok(Message::Binary(b)))=>{
						deadline=Instant::now()+IDLE;
						if b.len()<=MAX_DATAGRAM{if let Err(e)=udp.send(&b).await{warn!(%peer, error=%e, "udp send failed")}}
					}
					Some(Ok(Message::Close(_)))=>break "closed",
					Some(Ok(_))=>{}
				}
			}
			n=udp.recv(&mut buf)=>{
				let n=match n{Ok(n)=>n, Err(e)=>{warn!(%peer, error=%e, "udp recv failed"); continue}};
				deadline=Instant::now()+IDLE;
				tx.send(Message::Binary(Bytes::copy_from_slice(&buf[..n]))).await?;
			}
			_=ping.tick()=>tx.send(Message::Ping(Bytes::new())).await?,
			_=tokio::time::sleep_until(deadline)=>break "idle",
		}
	};
	info!(%peer, reason, "ws disconnected");
	let _=tx.send(Message::Close(None)).await;
	Ok(())
}

/// Listen on `listen` (UDP); each local source address gets one WS connection to `url` (lazy, reconnecting).
pub async fn run_client(listen:SocketAddr, url:String, insecure:bool)->anyhow::Result<()>{
	run_client_on(UdpSocket::bind(listen).await?, url, insecure).await
}

/// Same as [`run_client`] but on an already bound socket, so callers can pick an ephemeral port and know it.
pub async fn run_client_on(sock:UdpSocket, url:String, insecure:bool)->anyhow::Result<()>{
	let _=rustls::crypto::ring::default_provider().install_default();
	let connector=if insecure{
		Some(Connector::Rustls(Arc::new(rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth())))
	}else{None};
	let sock=Arc::new(sock);
	info!(listen=%sock.local_addr()?, %url, insecure, "bridge listening");
	let (mut peers, mut buf)=(HashMap::<SocketAddr, mpsc::Sender<Bytes>>::new(), [0u8; MAX_DATAGRAM]);
	let mut sweep=tokio::time::interval(Duration::from_secs(60));
	loop{
		tokio::select!{
			r=sock.recv_from(&mut buf)=>{
				let (n, src)=match r{Ok(v)=>v, Err(e)=>{warn!(error=%e, "udp recv failed"); continue}};
				let tx=match peers.get(&src).filter(|tx| !tx.is_closed()).cloned(){
					Some(tx)=>tx,
					None=>{
						let (tx, rx)=mpsc::channel(QUEUE);
						tokio::spawn(client_peer(sock.clone(), src, url.clone(), connector.clone(), rx));
						peers.insert(src, tx.clone());
						tx
					}
				};
				if tx.try_send(Bytes::copy_from_slice(&buf[..n])).is_err(){debug!(%src, "upstream queue full, dropping datagram")}
			}
			_=sweep.tick()=>peers.retain(|_, tx| !tx.is_closed()),
		}
	}
}

/// One local UDP source address mapped onto one WS connection, reconnecting until it goes idle.
async fn client_peer(sock:Arc<UdpSocket>, peer:SocketAddr, url:String, connector:Option<Connector>, mut rx:mpsc::Receiver<Bytes>){
	let (mut backoff, mut deadline)=(BACKOFF_MIN, Instant::now()+IDLE);
	loop{
		match tokio_tungstenite::connect_async_tls_with_config(url.as_str(), Some(ws_config()), true, connector.clone()).await{
			Ok((ws, _))=>{
				backoff=BACKOFF_MIN;
				info!(%peer, %url, "ws connected");
				let (mut tx, mut stream)=ws.split();
				let reason=loop{
					tokio::select!{
						d=rx.recv()=>{
							let Some(d)=d else{return};
							deadline=Instant::now()+IDLE;
							let n=d.len();
							if let Err(e)=tx.send(Message::Binary(d)).await{debug!(%peer, error=%e, "ws write failed"); break "write error"}
							trace!(%peer, n, "frame sent");
						}
						m=stream.next()=>{
							match m{
								None=>break "closed",
								Some(Err(e))=>{debug!(%peer, error=%e, "ws read failed"); break "read error"}
								Some(Ok(Message::Binary(b)))=>{
									deadline=Instant::now()+IDLE;
									trace!(%peer, n=b.len(), "frame received");
									if let Err(e)=sock.send_to(&b, peer).await{warn!(%peer, error=%e, "udp send failed")}
								}
								Some(Ok(Message::Close(_)))=>break "closed",
								Some(Ok(_))=>{}
							}
						}
						_=tokio::time::sleep_until(deadline)=>{info!(%peer, "idle, dropping mapping"); return}
					}
				};
				info!(%peer, reason, "ws disconnected, reconnecting");
			}
			Err(e)=>warn!(%peer, %url, error=%e, "ws connect failed"),
		}
		if Instant::now()>=deadline{info!(%peer, "idle, dropping mapping"); return}
		tokio::time::sleep(backoff).await;
		backoff=(backoff*2).min(BACKOFF_MAX);
	}
}

/// Accepts any server certificate. Only reachable through `--insecure`, for self-signed testing.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify{
	fn verify_server_cert(&self, _e:&rustls::pki_types::CertificateDer<'_>, _i:&[rustls::pki_types::CertificateDer<'_>], _n:&rustls::pki_types::ServerName<'_>, _o:&[u8], _t:rustls::pki_types::UnixTime)->Result<rustls::client::danger::ServerCertVerified, rustls::Error>{
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(&self, _m:&[u8], _c:&rustls::pki_types::CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)->Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>{
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}
	fn verify_tls13_signature(&self, _m:&[u8], _c:&rustls::pki_types::CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)->Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>{
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}
	fn supported_verify_schemes(&self)->Vec<rustls::SignatureScheme>{
		rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
	}
}
