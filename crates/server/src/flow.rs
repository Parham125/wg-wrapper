use crate::config::Upstream;
use ipstack::{IpStackTcpStream, IpStackUdpStream};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

const DIAL_TIMEOUT:Duration=Duration::from_secs(10);
const DNS_TIMEOUT:Duration=Duration::from_secs(5);
/// An ipv4 header plus a udp header, the overhead ipstack silently clips a datagram against.
const UDP_OVERHEAD:usize=28;

/// The one and only egress path. Every byte a peer sends leaves through this SOCKS5 CONNECT.
pub async fn dial(up:&Upstream, dst:SocketAddr)->anyhow::Result<Socks5Stream<TcpStream>>{
	let connect=async{
		Ok::<_, tokio_socks::Error>(match &up.auth{
			Some((user, pass))=>Socks5Stream::connect_with_password(up.addr.as_str(), dst, user, pass).await?,
			None=>Socks5Stream::connect(up.addr.as_str(), dst).await?,
		})
	};
	match tokio::time::timeout(DIAL_TIMEOUT, connect).await{
		Ok(r)=>Ok(r?),
		Err(_)=>anyhow::bail!("socks5 connect to {dst} timed out"),
	}
}

pub async fn handle_tcp(mut stream:IpStackTcpStream, up:Upstream){
	let dst=stream.peer_addr();
	let mut remote=match dial(&up, dst).await{
		Ok(r)=>r,
		Err(e)=>{tracing::debug!("tcp {dst}: socks5 connect failed: {e}"); return}
	};
	tracing::debug!("tcp {} -> {dst} established", stream.local_addr());
	if let Err(e)=tokio::io::copy_bidirectional(&mut stream, &mut remote).await{tracing::debug!("tcp {dst}: {e}")}
}

/// Only DNS gets a UDP path, and it is tunnelled as DNS over TCP so it still rides the SOCKS5.
pub async fn handle_udp(mut stream:IpStackUdpStream, up:Upstream, dns:Option<SocketAddr>, mtu:u16){
	let dst=stream.peer_addr();
	if dst.port()!=53{tracing::debug!("dropping udp to {dst}, only dns is forwarded"); return}
	let (target, cap)=(dns.unwrap_or(dst), (mtu as usize).saturating_sub(UDP_OVERHEAD));
	let mut query=vec![0u8;1500];
	loop{
		let n=match stream.read(&mut query).await{Ok(0)| Err(_)=>return, Ok(n)=>n};
		let mut remote=match dial(&up, target).await{
			Ok(r)=>r,
			Err(e)=>{tracing::debug!("dns {target}: socks5 connect failed: {e}"); continue}
		};
		let mut framed=Vec::with_capacity(n+2);
		framed.extend_from_slice(&(n as u16).to_be_bytes());
		framed.extend_from_slice(&query[..n]);
		let exchange=async{
			remote.write_all(&framed).await?;
			let mut len=[0u8;2];
			remote.read_exact(&mut len).await?;
			let mut answer=vec![0u8;u16::from_be_bytes(len) as usize];
			remote.read_exact(&mut answer).await?;
			Ok::<Vec<u8>, std::io::Error>(answer)
		};
		let mut answer=match tokio::time::timeout(DNS_TIMEOUT, exchange).await{
			Ok(Ok(a))=>a,
			_=>{tracing::debug!("dns {target}: exchange failed or timed out"); continue}
		};
		if answer.len()>cap{
			// ipstack would clip the tail without saying so, so flag it truncated and let the client retry over tcp.
			if answer.len()>=3{answer[2]|=0x02}
			answer.truncate(cap);
		}
		// One write is one datagram here, and a short write would duplicate rather than continue.
		if stream.write(&answer).await.is_err(){return}
	}
}
