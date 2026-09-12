use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, TcpHeader, TransportHeader};
use ipnet::IpNet;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{Receiver, Sender};

/// Isolation gate. Peers may only reach the public internet: never each other, never the gateway, never
/// the host, never anything link-local, unspecified, multicast or broadcast, and unless `allow_private`
/// is set, nothing in a private, shared or reserved range either.
pub fn allowed_dst(wg_net:&IpNet, ip:IpAddr, allow_private:bool)->bool{
	if wg_net.contains(&ip){return false}
	match ip{
		IpAddr::V4(a)=>{
			let o=a.octets();
			if a.is_loopback()|| a.is_unspecified()|| a.is_multicast()|| a.is_broadcast()|| a.is_link_local()|| o[0]==0{return false}
			// RFC1918, CGNAT, IETF protocol assignments, benchmarking, and the reserved 240/4 block.
			allow_private|| !(o[0]==10|| (o[0]==172 && (o[1]&0xf0)==16)|| (o[0]==192 && o[1]==168)|| (o[0]==100 && (o[1]&0xc0)==64)|| (o[0]==192 && o[1]==0 && o[2]==0)|| (o[0]==198 && (o[1]&0xfe)==18)|| (o[0]&0xf0)==240)
		}
		IpAddr::V6(a)=>{
			if let Some(v4)=a.to_ipv4_mapped(){return allowed_dst(wg_net, IpAddr::V4(v4), allow_private)}
			if a.is_loopback()|| a.is_unspecified()|| a.is_multicast()|| (a.segments()[0]&0xffc0)==0xfe80{return false}
			allow_private|| (a.segments()[0]&0xfe00)!=0xfc00
		}
	}
}

/// Longest-prefix match of `ip` over `(allowed_ip, peer index)` pairs.
pub fn peer_for(allowed:&[(IpNet, usize)], ip:IpAddr)->Option<usize>{
	allowed.iter().filter(|(n, _)| n.contains(&ip)).max_by_key(|(n, _)| n.prefix_len()).map(|(_, i)| *i)
}

/// Builds the RST/ACK we bounce back when a peer aims a TCP SYN at a forbidden destination.
pub fn tcp_rst(packet:&[u8])->Option<Vec<u8>>{
	let parsed=PacketHeaders::from_ip_slice(packet).ok()?;
	let NetHeaders::Ipv4(ip, _)=parsed.net? else{return None};
	let TransportHeader::Tcp(tcp)=parsed.transport? else{return None};
	if tcp.rst{return None}
	let mut h=TcpHeader::new(tcp.destination_port, tcp.source_port, 0, 0);
	h.rst=true;
	h.ack=true;
	h.acknowledgment_number=tcp.sequence_number.wrapping_add(1);
	let builder=PacketBuilder::ipv4(ip.destination, ip.source, 64).tcp_header(h);
	let mut out=Vec::with_capacity(builder.size(0));
	builder.write(&mut out, &[]).ok()?;
	Some(out)
}

/// Packet-boundary preserving device for ipstack: one read yields exactly one IP packet and one
/// write consumes exactly one. `tokio::io::duplex` cannot do this, it coalesces writes into a stream.
pub struct PacketDev{rx:Receiver<Vec<u8>>, tx:Sender<Vec<u8>>}

impl PacketDev{
	pub fn new(rx:Receiver<Vec<u8>>, tx:Sender<Vec<u8>>)->PacketDev{PacketDev{rx, tx}}
}

impl AsyncRead for PacketDev{
	fn poll_read(mut self:Pin<&mut Self>, cx:&mut Context<'_>, buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{
		loop{
			match self.rx.poll_recv(cx){
				Poll::Ready(Some(p))=>{
					if p.len()<=buf.remaining(){buf.put_slice(&p); return Poll::Ready(Ok(()))}
					tracing::debug!("dropping {} byte packet, over mtu", p.len());
				}
				// Closed channel parks the stack instead of spinning on a zero-length read.
				_=>return Poll::Pending,
			}
		}
	}
}

impl AsyncWrite for PacketDev{
	fn poll_write(self:Pin<&mut Self>, _cx:&mut Context<'_>, buf:&[u8])->Poll<io::Result<usize>>{
		if self.tx.try_send(buf.to_vec()).is_err(){tracing::debug!("tunnel queue full, dropping {} byte packet", buf.len())}
		Poll::Ready(Ok(buf.len()))
	}
	fn poll_flush(self:Pin<&mut Self>, _cx:&mut Context<'_>)->Poll<io::Result<()>>{Poll::Ready(Ok(()))}
	fn poll_shutdown(self:Pin<&mut Self>, _cx:&mut Context<'_>)->Poll<io::Result<()>>{Poll::Ready(Ok(()))}
}

#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn isolation_blocks_the_tunnel_and_the_host(){
		let net:IpNet="10.7.0.1/24".parse().unwrap();
		for blocked in ["10.7.0.1", "10.7.0.2", "10.7.0.255", "10.7.0.0", "127.0.0.1", "127.9.9.9", "0.0.0.0", "0.1.2.3", "169.254.1.1", "224.0.0.1", "239.1.2.3", "255.255.255.255"]{
			assert!(!allowed_dst(&net, blocked.parse().unwrap(), true), "{blocked} must be refused");
		}
		for blocked in ["::1", "::", "ff02::1", "fe80::1", "febf::1", "::ffff:127.0.0.1", "::ffff:10.7.0.2"]{
			assert!(!allowed_dst(&net, blocked.parse().unwrap(), true), "{blocked} must be refused");
		}
		for ok in ["1.1.1.1", "8.8.8.8", "93.184.216.34"]{
			assert!(allowed_dst(&net, ok.parse().unwrap(), false), "{ok} must be allowed");
		}
		for ok in ["2606:4700:4700::1111", "::ffff:1.1.1.1"]{
			assert!(allowed_dst(&net, ok.parse().unwrap(), false), "{ok} must be allowed");
		}
	}

	#[test]
	fn private_ranges_need_the_opt_in(){
		let net:IpNet="10.7.0.1/24".parse().unwrap();
		for private in ["10.8.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "100.64.0.1", "100.127.0.1", "192.0.0.8", "198.18.0.1", "198.19.255.1", "240.0.0.1", "fc00::1", "fd00::1"]{
			let ip=private.parse().unwrap();
			assert!(!allowed_dst(&net, ip, false), "{private} must be refused by default");
			assert!(allowed_dst(&net, ip, true), "{private} must be allowed with allow_private");
		}
		// Neighbours of those ranges stay reachable either way.
		for public in ["11.0.0.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "100.63.0.1", "100.128.0.1", "198.17.0.1", "198.20.0.1", "192.0.1.1", "223.255.255.254", "fe00::1"]{
			assert!(allowed_dst(&net, public.parse().unwrap(), false), "{public} must be allowed");
		}
	}

	#[test]
	fn isolation_follows_the_configured_subnet(){
		let wide:IpNet="10.0.0.1/8".parse().unwrap();
		assert!(!allowed_dst(&wide, "10.8.0.1".parse().unwrap(), true));
		assert!(allowed_dst(&wide, "11.0.0.1".parse().unwrap(), true));
	}

	#[test]
	fn longest_prefix_wins(){
		let allowed=vec![("10.7.0.0/24".parse().unwrap(), 0), ("10.7.0.5/32".parse().unwrap(), 1)];
		assert_eq!(peer_for(&allowed, "10.7.0.5".parse().unwrap()), Some(1));
		assert_eq!(peer_for(&allowed, "10.7.0.9".parse().unwrap()), Some(0));
		assert_eq!(peer_for(&allowed, "10.8.0.9".parse().unwrap()), None);
	}

	#[test]
	fn rst_mirrors_the_syn(){
		let mut syn=TcpHeader::new(40000, 80, 12345, 65535);
		syn.syn=true;
		let builder=PacketBuilder::ipv4([10, 7, 0, 2], [10, 7, 0, 3], 64).tcp_header(syn);
		let mut packet=Vec::new();
		builder.write(&mut packet, &[]).unwrap();
		let rst=tcp_rst(&packet).unwrap();
		let parsed=PacketHeaders::from_ip_slice(&rst).unwrap();
		let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
		let TransportHeader::Tcp(tcp)=parsed.transport.unwrap() else{panic!("not tcp")};
		assert_eq!((ip.source, ip.destination), ([10, 7, 0, 3], [10, 7, 0, 2]));
		assert_eq!((tcp.source_port, tcp.destination_port), (80, 40000));
		assert!(tcp.rst && tcp.ack && !tcp.syn);
		assert_eq!(tcp.acknowledgment_number, 12346);
		assert!(tcp_rst(&rst).is_none(), "never answer an RST with an RST");
	}
}
