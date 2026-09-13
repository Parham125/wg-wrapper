//! Shared WireGuard core (boringtun multi-peer wrapper). Owned by the server task, reused by the Windows client later.
use anyhow::{anyhow, bail};
use base64::Engine;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Largest datagram or IP packet we ever hand to boringtun.
pub const MAX_PACKET:usize=65535;
/// Handshake messages per second before we start demanding a valid cookie.
const HANDSHAKE_RATE_LIMIT:u64=100;

pub fn decode_key(s:&str)->anyhow::Result<[u8;32]>{
	let v=base64::engine::general_purpose::STANDARD.decode(s.trim())?;
	v.try_into().map_err(|_| anyhow!("key must decode to 32 bytes"))
}

pub fn encode_key(k:&[u8;32])->String{base64::engine::general_purpose::STANDARD.encode(k)}

pub fn public_key(private:&[u8;32])->[u8;32]{PublicKey::from(&StaticSecret::from(*private)).to_bytes()}

/// Fresh clamped x25519 private key, same shape as `wg genkey`.
pub fn generate_key()->[u8;32]{
	let mut k=[0u8;32];
	rand_core::OsRng.fill_bytes(&mut k);
	k[0]&=248;
	k[31]&=127;
	k[31]|=64;
	k
}

/// Source address of an IPv4/IPv6 packet (boringtun only exposes the destination).
pub fn src_address(packet:&[u8])->Option<IpAddr>{
	match packet.first()?>>4{
		4 if packet.len()>=20=>Some(IpAddr::from(<[u8;4]>::try_from(&packet[12..16]).ok()?)),
		6 if packet.len()>=40=>Some(IpAddr::from(<[u8;16]>::try_from(&packet[8..24]).ok()?)),
		_=>None,
	}
}

/// Destination address of an IPv4/IPv6 packet.
pub fn dst_address(packet:&[u8])->Option<IpAddr>{Tunn::dst_address(packet)}

pub struct Peer{
	pub public_key:[u8;32],
	/// Last address a valid datagram arrived from, for roaming.
	pub endpoint:Option<SocketAddr>,
	tunn:Tunn,
}

/// Multi-peer WireGuard endpoint. Pure state machine, it never touches sockets.
pub struct Wg{
	private:StaticSecret,
	public:PublicKey,
	peers:Vec<Peer>,
	by_key:HashMap<[u8;32], usize>,
	scratch:Vec<u8>,
	limiter:Arc<RateLimiter>,
	last_reset:Instant,
}

impl Wg{
	pub fn new(private_key:[u8;32])->Wg{
		let private=StaticSecret::from(private_key);
		let public=PublicKey::from(&private);
		let limiter=Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT));
		Wg{private, public, peers:Vec::new(), by_key:HashMap::new(), scratch:vec![0u8;MAX_PACKET], limiter, last_reset:Instant::now()}
	}

	pub fn public_key(&self)->[u8;32]{self.public.to_bytes()}

	/// Registers a peer and returns its index, which boringtun also uses as the session index prefix.
	pub fn add_peer(&mut self, public_key:[u8;32], preshared_key:Option<[u8;32]>, keepalive:Option<u16>)->anyhow::Result<usize>{
		if self.by_key.contains_key(&public_key){bail!("duplicate peer public key")}
		let idx=self.peers.len();
		let tunn=Tunn::new(self.private.clone(), PublicKey::from(public_key), preshared_key, keepalive, idx as u32, Some(self.limiter.clone()));
		self.peers.push(Peer{public_key, endpoint:None, tunn});
		self.by_key.insert(public_key, idx);
		Ok(idx)
	}

	pub fn peers(&self)->&[Peer]{&self.peers}

	pub fn endpoint(&self, idx:usize)->Option<SocketAddr>{self.peers.get(idx).and_then(|p| p.endpoint)}

	/// Feeds one datagram from the network. Appends datagrams destined back to that peer into `net_out`
	/// and decrypted IP packets into `ip_out`. Returns the peer the datagram belonged to.
	pub fn recv_from_network(&mut self, from:SocketAddr, datagram:&[u8], net_out:&mut Vec<Vec<u8>>, ip_out:&mut Vec<Vec<u8>>)->Option<usize>{
		// Check mac1/mac2 before anything else. A cookie reply only proves the sender knows our public
		// key, which is public, so such a datagram must never identify a peer or move its endpoint.
		let limiter=self.limiter.clone();
		let (idx, kind)=match limiter.verify_packet(Some(from.ip()), datagram, &mut self.scratch){
			Ok(Packet::HandshakeInit(p))=>{
				let hs=parse_handshake_anon(&self.private, &self.public, &p).ok()?;
				let idx=*self.by_key.get(&hs.peer_static_public)?;
				tracing::debug!("handshake init from {from} for peer {idx}");
				(idx, 1u8)
			}
			Ok(Packet::HandshakeResponse(p))=>((p.receiver_idx>>8) as usize, 2),
			Ok(Packet::PacketCookieReply(p))=>((p.receiver_idx>>8) as usize, 3),
			Ok(Packet::PacketData(p))=>((p.receiver_idx>>8) as usize, 4),
			Err(TunnResult::WriteToNetwork(cookie))=>{tracing::debug!("under load, cookie reply to {from}"); net_out.push(cookie.to_vec()); return None}
			Err(e)=>{tracing::debug!("datagram from {from} failed the mac check: {e:?}"); return None}
		};
		if idx>=self.peers.len(){return None}
		let before=net_out.len();
		let Wg{peers, scratch, ..}=self;
		let peer=&mut peers[idx];
		let mut input:&[u8]=datagram;
		let mut decrypted=false;
		loop{
			match peer.tunn.decapsulate(Some(from.ip()), input, scratch){
				TunnResult::Done=>break,
				TunnResult::Err(e)=>{tracing::debug!("peer {idx} decapsulate: {e:?}"); return None}
				TunnResult::WriteToNetwork(b)=>{net_out.push(b.to_vec()); input=&[]}
				TunnResult::WriteToTunnelV4(b, _)=>{ip_out.push(b.to_vec()); decrypted=true; break}
				TunnResult::WriteToTunnelV6(b, _)=>{ip_out.push(b.to_vec()); decrypted=true; break}
			}
		}
		// Roam only on proof of the peer's private key: a decrypted packet, an accepted data packet, or a
		// handshake that produced something other than another cookie reply.
		let answered=net_out[before..].iter().any(|d| d.first()!=Some(&3));
		if decrypted|| kind==4|| (kind!=3 && answered){peer.endpoint=Some(from)}
		Some(idx)
	}

	/// Encrypts one IP packet for `idx`. With no live session it emits a handshake initiation and queues the packet.
	pub fn encapsulate(&mut self, idx:usize, packet:&[u8], net_out:&mut Vec<Vec<u8>>){
		let Wg{peers, scratch, ..}=self;
		let Some(peer)=peers.get_mut(idx) else{return};
		match peer.tunn.encapsulate(packet, scratch){
			TunnResult::WriteToNetwork(b)=>net_out.push(b.to_vec()),
			TunnResult::Err(e)=>tracing::debug!("peer {idx} encapsulate: {e:?}"),
			_=>{}
		}
	}

	/// Time since that peer's last completed handshake, None while it has no live session.
	pub fn time_since_last_handshake(&self, idx:usize)->Option<std::time::Duration>{self.peers.get(idx)?.tunn.time_since_last_handshake()}

	/// Drives every peer's timers. Call roughly every 250ms and send whatever lands in `out`.
	pub fn update_timers(&mut self, out:&mut Vec<(usize, Vec<u8>)>){
		// We own the limiter, so boringtun's own per-tunnel reset never runs and we must do it here.
		if self.last_reset.elapsed()>=Duration::from_secs(1){
			self.limiter.reset_count();
			self.last_reset=Instant::now();
		}
		let Wg{peers, scratch, ..}=self;
		for (i, peer) in peers.iter_mut().enumerate(){
			match peer.tunn.update_timers(scratch){
				TunnResult::WriteToNetwork(b)=>out.push((i, b.to_vec())),
				TunnResult::Err(e)=>tracing::debug!("peer {i} timers: {e:?}"),
				_=>{}
			}
		}
	}
}

#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn keys_roundtrip(){
		let k=generate_key();
		assert_eq!(decode_key(&encode_key(&k)).unwrap(), k);
		assert_eq!(public_key(&k), PublicKey::from(&StaticSecret::from(k)).to_bytes());
		assert!(decode_key("bm90IDMyIGJ5dGVz").is_err());
	}

	#[test]
	fn addresses_parse(){
		let mut p=vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
		p.extend_from_slice(&[10, 7, 0, 2]);
		p.extend_from_slice(&[1, 1, 1, 1]);
		assert_eq!(src_address(&p).unwrap(), "10.7.0.2".parse::<IpAddr>().unwrap());
		assert_eq!(Tunn::dst_address(&p).unwrap(), "1.1.1.1".parse::<IpAddr>().unwrap());
		assert!(src_address(&[]).is_none());
	}

	#[test]
	fn a_forged_flood_cannot_steal_an_endpoint(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		let ia=wg.add_peer(public_key(&a), None, None).unwrap();
		let peer:SocketAddr="127.0.0.1:1111".parse().unwrap();
		let attacker:SocketAddr="127.0.0.1:2222".parse().unwrap();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		assert_eq!(wg.recv_from_network(peer, &init, &mut net, &mut ip), Some(ia));
		assert_eq!(wg.endpoint(ia), Some(peer));
		// Anyone can recompute mac1 from our public key, so past the rate limit these draw a cookie reply.
		// A cookie reply proves nothing about the sender and must never move the peer.
		let mut cookies=0;
		for _ in 0..(HANDSHAKE_RATE_LIMIT as usize)*3{
			net.clear();
			assert_eq!(wg.recv_from_network(attacker, &init, &mut net, &mut ip), None);
			cookies+=net.iter().filter(|d| d.first()==Some(&3)).count();
		}
		assert!(cookies>0, "the flood never reached the rate limit, so nothing was proven");
		assert_eq!(wg.endpoint(ia), Some(peer), "a flood of forged handshakes moved the endpoint");
	}

	#[test]
	fn the_limiter_recovers_after_a_reset(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		wg.add_peer(public_key(&a), None, None).unwrap();
		let from:SocketAddr="127.0.0.1:1111".parse().unwrap();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		for _ in 0..(HANDSHAKE_RATE_LIMIT as usize)*2{wg.recv_from_network(from, &init, &mut net, &mut ip);}
		assert!(net.iter().any(|d| d.first()==Some(&3)), "the limiter never engaged");
		// boringtun keeps its own one second floor on reset_count, so this has to wait it out.
		std::thread::sleep(Duration::from_millis(1100));
		wg.update_timers(&mut Vec::new());
		net.clear();
		wg.recv_from_network(from, &init, &mut net, &mut ip);
		assert!(net.iter().all(|d| d.first()!=Some(&3)), "still handing out cookies after a reset");
	}

	#[test]
	fn handshake_routes_to_the_right_peer(){
		let (srv, a, b)=(generate_key(), generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		let ia=wg.add_peer(public_key(&a), None, None).unwrap();
		let ib=wg.add_peer(public_key(&b), None, None).unwrap();
		assert!(wg.add_peer(public_key(&b), None, None).is_err());
		let from:SocketAddr="127.0.0.1:1234".parse().unwrap();
		for (key, want) in [(b, ib), (a, ia)]{
			let mut client=Tunn::new(StaticSecret::from(key), PublicKey::from(public_key(&srv)), None, None, 0, None);
			let mut buf=vec![0u8;MAX_PACKET];
			let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
			let init=init.to_vec();
			let (mut net, mut ip)=(Vec::new(), Vec::new());
			assert_eq!(wg.recv_from_network(from, &init, &mut net, &mut ip), Some(want));
			assert_eq!(net.len(), 1, "expected a handshake response");
			assert_eq!(wg.endpoint(want), Some(from));
		}
	}
}
