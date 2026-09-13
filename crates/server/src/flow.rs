use crate::config::Upstream;
use ipstack::{IpStackTcpStream, IpStackUdpStream};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_socks::tcp::Socks5Stream;

const DIAL_TIMEOUT:Duration=Duration::from_secs(10);
const DNS_TIMEOUT:Duration=Duration::from_secs(5);
const ASSOCIATE_TIMEOUT:Duration=Duration::from_secs(10);
const MAX_DATAGRAM:usize=65535;
/// An ipv4 header plus a udp header, the overhead ipstack silently clips a datagram against.
const UDP_OVERHEAD:usize=28;
/// Upstreams we have already complained about, so a proxy without udp support logs once, not per flow.
static NO_UDP:OnceLock<Mutex<HashSet<String>>>=OnceLock::new();

/// RFC 1928 section 7 request header: two reserved bytes, the fragment number, then the destination.
fn udp_header(dst:SocketAddr)->Vec<u8>{
	let mut h=vec![0, 0, 0];
	match dst.ip(){
		IpAddr::V4(a)=>{h.push(1); h.extend_from_slice(&a.octets())}
		IpAddr::V6(a)=>{h.push(4); h.extend_from_slice(&a.octets())}
	}
	h.extend_from_slice(&dst.port().to_be_bytes());
	h
}

/// Strips that header off a reply, refusing fragments and address types we cannot parse. The source is
/// only noted, not enforced: the association is per flow and the proxy at the other end is trusted.
fn unwrap_udp(datagram:&[u8], dst:SocketAddr)->Option<&[u8]>{
	if datagram.len()<4|| datagram[2]!=0{return None}
	let (src, body)=match datagram[3]{
		1 if datagram.len()>=10=>(SocketAddr::from((Ipv4Addr::from(<[u8;4]>::try_from(&datagram[4..8]).ok()?), u16::from_be_bytes([datagram[8], datagram[9]]))), &datagram[10..]),
		4 if datagram.len()>=22=>(SocketAddr::from((Ipv6Addr::from(<[u8;16]>::try_from(&datagram[4..20]).ok()?), u16::from_be_bytes([datagram[20], datagram[21]]))), &datagram[22..]),
		_=>return None,
	};
	if src!=dst{tracing::trace!("udp {dst}: reply carried source {src}")}
	Some(body)
}

/// Opens a UDP ASSOCIATE on `up` and returns the control connection that owns it plus a socket
/// connected to the relay. The association lives exactly as long as the returned TcpStream.
async fn associate(up:&Upstream)->anyhow::Result<(TcpStream, UdpSocket)>{
	let mut control=TcpStream::connect(up.addr.as_str()).await?;
	control.write_all(&[5, 2, 0, 2]).await?;
	let mut chosen=[0u8;2];
	control.read_exact(&mut chosen).await?;
	anyhow::ensure!(chosen[0]==5, "upstream did not answer socks5");
	match chosen[1]{
		0=>{}
		2=>{
			let (user, pass)=up.auth.as_ref().ok_or_else(|| anyhow::anyhow!("upstream wants credentials we do not have"))?;
			anyhow::ensure!(user.len()<256 && pass.len()<256, "credentials do not fit rfc 1929");
			let mut req=vec![1, user.len() as u8];
			req.extend_from_slice(user.as_bytes());
			req.push(pass.len() as u8);
			req.extend_from_slice(pass.as_bytes());
			control.write_all(&req).await?;
			let mut ok=[0u8;2];
			control.read_exact(&mut ok).await?;
			anyhow::ensure!(ok[1]==0, "upstream rejected the credentials");
		}
		m=>anyhow::bail!("upstream picked auth method {m}"),
	}
	control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
	let mut head=[0u8;4];
	control.read_exact(&mut head).await?;
	anyhow::ensure!(head[0]==5, "upstream did not answer socks5");
	anyhow::ensure!(head[1]==0, "upstream refused udp associate with reply {}", head[1]);
	let bound=match head[3]{
		1=>{let mut b=[0u8;6]; control.read_exact(&mut b).await?; SocketAddr::from((Ipv4Addr::from([b[0], b[1], b[2], b[3]]), u16::from_be_bytes([b[4], b[5]])))}
		4=>{let mut b=[0u8;18]; control.read_exact(&mut b).await?; SocketAddr::from((Ipv6Addr::from(<[u8;16]>::try_from(&b[..16])?), u16::from_be_bytes([b[16], b[17]])))}
		a=>anyhow::bail!("upstream bound udp to address type {a}, which we do not speak"),
	};
	// A wildcard BND.ADDR means "same host as the control connection", which we already know.
	let relay_addr=if bound.ip().is_unspecified(){SocketAddr::new(control.peer_addr()?.ip(), bound.port())}else{bound};
	let local:SocketAddr=if relay_addr.is_ipv4(){(Ipv4Addr::UNSPECIFIED, 0).into()}else{(Ipv6Addr::UNSPECIFIED, 0).into()};
	let relay=UdpSocket::bind(local).await?;
	relay.connect(relay_addr).await?;
	Ok((control, relay))
}

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

/// DNS goes over TCP so it can ride a plain CONNECT; everything else gets a UDP ASSOCIATE.
pub async fn handle_udp(stream:IpStackUdpStream, up:Upstream, dns:Option<SocketAddr>, mtu:u16, idle:Duration){
	let dst=stream.peer_addr();
	if dst.port()==53{dns_over_tcp(stream, up, dns.unwrap_or(dst), mtu).await}else{udp_relay(stream, up, dst, mtu, idle).await}
}

/// Peer datagrams wrapped in the SOCKS5 UDP header and pumped against the relay the proxy handed us.
async fn udp_relay(mut stream:IpStackUdpStream, up:Upstream, dst:SocketAddr, mtu:u16, idle:Duration){
	let (mut control, relay)=match tokio::time::timeout(ASSOCIATE_TIMEOUT, associate(&up)).await{
		Ok(Ok(v))=>v,
		Ok(Err(e))=>{
			if NO_UDP.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner()).insert(up.addr.clone()){
				tracing::warn!("upstream {} cannot relay udp, dropping non dns udp flows through it: {e}", up.addr);
			}else{tracing::debug!("udp {dst}: associate failed: {e}")}
			return;
		}
		Err(_)=>{tracing::debug!("udp {dst}: associate timed out"); return}
	};
	tracing::debug!("udp {} -> {dst} associated via {}", stream.local_addr(), up.addr);
	let (header, cap)=(udp_header(dst), (mtu as usize).saturating_sub(UDP_OVERHEAD));
	let (mut from_peer, mut from_relay, mut sink)=(vec![0u8;MAX_DATAGRAM], vec![0u8;MAX_DATAGRAM], [0u8;1]);
	let mut wrapped=Vec::with_capacity(MAX_DATAGRAM);
	loop{
		tokio::select!{
			r=stream.read(&mut from_peer)=>{
				let Ok(n)=r else{return};
				if n==0{return}
				wrapped.clear();
				wrapped.extend_from_slice(&header);
				wrapped.extend_from_slice(&from_peer[..n]);
				if let Err(e)=relay.send(&wrapped).await{tracing::debug!("udp {dst}: relay send: {e}"); return}
			}
			r=relay.recv(&mut from_relay)=>{
				let Ok(n)=r else{return};
				let Some(payload)=unwrap_udp(&from_relay[..n], dst) else{continue};
				if payload.len()>cap{tracing::debug!("udp {dst}: dropping a {} byte reply, over the {cap} byte mtu", payload.len()); continue}
				if stream.write(payload).await.is_err(){return}
			}
			// The association dies with its control connection, so anything on it ends the flow.
			_=control.read(&mut sink)=>{tracing::debug!("udp {dst}: upstream closed the association"); return}
			_=tokio::time::sleep(idle)=>{tracing::debug!("udp {dst}: idle for {idle:?}"); return}
		}
	}
}

/// DNS with a 2 byte big endian length prefix, so the query rides an ordinary SOCKS5 CONNECT.
async fn dns_over_tcp(mut stream:IpStackUdpStream, up:Upstream, target:SocketAddr, mtu:u16){
	let cap=(mtu as usize).saturating_sub(UDP_OVERHEAD);
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

#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn udp_headers_round_trip(){
		let v4:SocketAddr="93.184.216.34:9999".parse().unwrap();
		let mut datagram=udp_header(v4);
		assert_eq!(datagram[..4], [0, 0, 0, 1]);
		datagram.extend_from_slice(b"payload");
		assert_eq!(unwrap_udp(&datagram, v4).unwrap(), b"payload");
		let v6:SocketAddr="[2606:4700::1111]:53".parse().unwrap();
		let mut six=udp_header(v6);
		assert_eq!(six[..4], [0, 0, 0, 4]);
		six.extend_from_slice(b"payload");
		assert_eq!(unwrap_udp(&six, v6).unwrap(), b"payload");
	}

	#[test]
	fn replies_from_elsewhere_are_accepted(){
		let dst:SocketAddr="93.184.216.34:9999".parse().unwrap();
		let mut datagram=udp_header(dst);
		datagram.extend_from_slice(b"payload");
		for other in ["93.184.216.34:1", "1.1.1.1:9999", "[2606:4700::1111]:9999"]{
			assert_eq!(unwrap_udp(&datagram, other.parse().unwrap()), Some(&b"payload"[..]), "source {other} was refused");
		}
		let mut fragment=datagram.clone();
		fragment[2]=1;
		assert!(unwrap_udp(&fragment, dst).is_none(), "a fragment was accepted");
		for short in [0, 3, 9]{assert!(unwrap_udp(&datagram[..short], dst).is_none(), "a {short} byte datagram was accepted")}
		let mut domain=datagram.clone();
		domain[3]=3;
		assert!(unwrap_udp(&domain, dst).is_none(), "a domain reply was accepted");
	}
}
