//! The whole client engine against a real in-process server: mock tun -> wgclient -> ws bridge or udp
//! -> server -> mock SOCKS5 -> fake DNS responder, and the answer all the way back out of the mock tun.
use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice};
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wgclient::{ClientConfig, Endpoint, Tun, Tunnel};

const CLIENT:[u8;4]=[10, 7, 0, 2];
const RESOLVER:[u8;4]=[1, 1, 1, 1];
const DNS_QUERY:&[u8]=b"\x12\x34\x01\x00fake-query";
const DNS_ANSWER:&[u8]=b"\x12\x34\x81\x80fake-answer";

/// Minimal no-auth SOCKS5 CONNECT proxy that records every target and sends all of them to `backend`.
async fn socks5_proxy(backend:SocketAddr)->(SocketAddr, Arc<Mutex<Vec<String>>>){
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	let seen=Arc::new(Mutex::new(Vec::new()));
	let recorder=seen.clone();
	tokio::spawn(async move{
		loop{
			let Ok((mut client, _))=listener.accept().await else{return};
			let recorder=recorder.clone();
			tokio::spawn(async move{
				let mut hello=[0u8;2];
				if client.read_exact(&mut hello).await.is_err()|| hello[0]!=5{return}
				let mut methods=vec![0u8;hello[1] as usize];
				if client.read_exact(&mut methods).await.is_err(){return}
				if client.write_all(&[5, 0]).await.is_err(){return}
				let mut head=[0u8;4];
				if client.read_exact(&mut head).await.is_err()|| head[1]!=1|| head[3]!=1{return}
				let mut ip=[0u8;4];
				let mut port=[0u8;2];
				if client.read_exact(&mut ip).await.is_err()|| client.read_exact(&mut port).await.is_err(){return}
				recorder.lock().unwrap().push(format!("{}:{}", std::net::Ipv4Addr::from(ip), u16::from_be_bytes(port)));
				let Ok(mut upstream)=TcpStream::connect(backend).await else{
					let _=client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
					return;
				};
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err(){return}
				let _=tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
			});
		}
	});
	(addr, seen)
}

/// DNS over TCP: 2 byte big endian length, then the message.
async fn dns_responder()->SocketAddr{
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			tokio::spawn(async move{
				let mut len=[0u8;2];
				if s.read_exact(&mut len).await.is_err(){return}
				let mut query=vec![0u8;u16::from_be_bytes(len) as usize];
				if s.read_exact(&mut query).await.is_err(){return}
				let mut out=(DNS_ANSWER.len() as u16).to_be_bytes().to_vec();
				out.extend_from_slice(DNS_ANSWER);
				let _=s.write_all(&out).await;
			});
		}
	});
	addr
}

/// Packet device over two channels. The test pushes into `up` and reads whatever lands in `down`.
/// The mutexes are never both held, so the read and write threads never wait on each other.
struct MockTun{up:Mutex<Receiver<Vec<u8>>>, down:Mutex<Sender<Vec<u8>>>}

impl Tun for MockTun{
	fn recv(&self, buf:&mut [u8])->io::Result<usize>{
		let p=self.up.lock().unwrap().recv().map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
		buf[..p.len()].copy_from_slice(&p);
		Ok(p.len())
	}
	fn send(&self, packet:&[u8])->io::Result<()>{
		self.down.lock().unwrap().send(packet.to_vec()).map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
	}
}

struct Wgw{udp:SocketAddr, ws:Option<SocketAddr>, server_public:String, client_private:String}

/// One peer, no dns override, egress pinned to `upstream`. `ws` swaps listen_udp for a plain ws relay.
async fn spawn_server(upstream:&str, ws:bool)->Wgw{
	let private=wgcore::generate_key();
	let client=wgcore::generate_key();
	let listen=if ws{r#""listen_ws":{"addr":"127.0.0.1:0","path":"/tunnel"}"#.to_string()}else{r#""listen_udp":"127.0.0.1:0""#.to_string()};
	let json=format!(
		r#"{{"private_key":"{}","address":"10.7.0.1/24","mtu":1420,{listen},"upstream":"{upstream}",
		 "peers":[{{"public_key":"{}","allowed_ips":["10.7.0.2/32"]}}]}}"#,
		wgcore::encode_key(&private), wgcore::encode_key(&wgcore::public_key(&client)));
	let cfg:server::config::Config=serde_json::from_str(&json).unwrap();
	cfg.validate().unwrap();
	let running=server::start(cfg).await.unwrap();
	Wgw{udp:running.udp_addr, ws:running.ws_addr, server_public:wgcore::encode_key(&wgcore::public_key(&private)), client_private:wgcore::encode_key(&client)}
}

fn config(wgw:&Wgw, endpoint:Endpoint)->ClientConfig{
	ClientConfig{
		private_key:wgw.client_private.clone(),
		peer_public_key:wgw.server_public.clone(),
		preshared_key:None,
		address:"10.7.0.2/32".parse().unwrap(),
		dns:vec![RESOLVER.into()],
		endpoint,
		allowed_ips:vec!["0.0.0.0/0".parse().unwrap()],
		mtu:1380,
		keepalive:Some(15),
	}
}

/// Pushes one DNS query into the tun and returns the answer payload that comes back out of it.
async fn answer(up:&Sender<Vec<u8>>, down:&Receiver<Vec<u8>>)->Vec<u8>{
	let builder=PacketBuilder::ipv4(CLIENT, RESOLVER, 64).udp(40005, 53);
	let mut packet=Vec::with_capacity(builder.size(DNS_QUERY.len()));
	builder.write(&mut packet, DNS_QUERY).unwrap();
	up.send(packet).unwrap();
	let deadline=tokio::time::Instant::now()+Duration::from_secs(10);
	while tokio::time::Instant::now()<deadline{
		let Ok(reply)=down.try_recv() else{tokio::time::sleep(Duration::from_millis(20)).await; continue};
		let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
		let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
		assert_eq!((ip.source, ip.destination), (RESOLVER, CLIENT));
		let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
		return payload.to_vec();
	}
	panic!("no dns answer came back out of the tun")
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn dns_round_trips_over_the_ws_transport(){
	let (proxy, seen)=socks5_proxy(dns_responder().await).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), true).await;
	let url=format!("ws://{}/tunnel", wgw.ws.unwrap());
	let (up_tx, up_rx)=channel();
	let (down_tx, down_rx)=channel();
	let tunnel=Tunnel::connect(config(&wgw, Endpoint::Ws{url, insecure:false}), Box::new(MockTun{up:Mutex::new(up_rx), down:Mutex::new(down_tx)})).await.unwrap();
	assert_eq!(answer(&up_tx, &down_rx).await, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"]);
	let stats=tunnel.stats();
	assert!(stats.last_handshake.is_some(), "no handshake recorded");
	assert!(stats.tx_bytes>0 && stats.rx_bytes>0, "counters did not move: {stats:?}");
	tunnel.close().await;
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn dns_round_trips_over_the_udp_transport(){
	let (proxy, seen)=socks5_proxy(dns_responder().await).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), false).await;
	let (up_tx, up_rx)=channel();
	let (down_tx, down_rx)=channel();
	let tunnel=Tunnel::connect(config(&wgw, Endpoint::Udp(wgw.udp)), Box::new(MockTun{up:Mutex::new(up_rx), down:Mutex::new(down_tx)})).await.unwrap();
	assert_eq!(answer(&up_tx, &down_rx).await, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"]);
	let stats=tunnel.stats();
	assert!(stats.last_handshake.is_some(), "no handshake recorded");
	assert!(stats.tx_bytes>0 && stats.rx_bytes>0, "counters did not move: {stats:?}");
	tunnel.close().await;
}

/// The GUI parks the tunnel in shared Tauri state, so these have to stay thread safe.
#[test]
fn the_public_types_are_send_and_sync(){
	fn check<T:Send+Sync>(){}
	check::<Tunnel>();
	check::<ClientConfig>();
	check::<wgclient::Stats>();
}
