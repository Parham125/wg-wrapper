//! In-process end to end: a boringtun client talks WireGuard to the server, which may only egress
//! through a local SOCKS5 proxy we control and observe.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const GATEWAY:[u8;4]=[10, 7, 0, 1];
const PEER_A:[u8;4]=[10, 7, 0, 2];
const PEER_B:[u8;4]=[10, 7, 0, 3];
const GREETING:&[u8]=b"hello-from-upstream";
const DNS_ANSWER:&[u8]=b"\x12\x34\x81\x80fake-answer";

/// Minimal no-auth SOCKS5 proxy speaking CONNECT and UDP ASSOCIATE. It records every requested target
/// and routes to the fake backends by port, so the test needs no real network. `refuse_udp` makes it
/// answer an association with REP 0x07, the way a proxy without UDP support does.
async fn socks5_proxy(dns_backend:SocketAddr, tcp_backend:SocketAddr, udp_backend:SocketAddr, refuse_udp:bool)->(SocketAddr, Arc<Mutex<Vec<String>>>){
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
				if client.read_exact(&mut head).await.is_err()|| !(head[1]==1|| head[1]==3){return}
				let host=match head[3]{
					1=>{let mut b=[0u8;4]; if client.read_exact(&mut b).await.is_err(){return} std::net::Ipv4Addr::from(b).to_string()}
					3=>{
						let mut n=[0u8;1];
						if client.read_exact(&mut n).await.is_err(){return}
						let mut b=vec![0u8;n[0] as usize];
						if client.read_exact(&mut b).await.is_err(){return}
						String::from_utf8_lossy(&b).into_owned()
					}
					4=>{let mut b=[0u8;16]; if client.read_exact(&mut b).await.is_err(){return} std::net::Ipv6Addr::from(b).to_string()}
					_=>return,
				};
				let mut port=[0u8;2];
				if client.read_exact(&mut port).await.is_err(){return}
				let port=u16::from_be_bytes(port);
				if head[1]==3{
					recorder.lock().unwrap().push(format!("associate {host}:{port}"));
					if refuse_udp{let _=client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await; return}
					let Ok(relay)=UdpSocket::bind("127.0.0.1:0").await else{return};
					let mut reply=vec![5, 0, 0, 1, 127, 0, 0, 1];
					reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
					if client.write_all(&reply).await.is_err(){return}
					let (mut framed, mut echo, mut sink)=(vec![0u8;65535], vec![0u8;65535], [0u8;1]);
					loop{
						tokio::select!{
							r=relay.recv_from(&mut framed)=>{
								let Ok((n, peer))=r else{return};
								if n<10|| framed[2]!=0|| framed[3]!=1{continue}
								let dst=SocketAddr::from((std::net::Ipv4Addr::from(<[u8;4]>::try_from(&framed[4..8]).unwrap()), u16::from_be_bytes([framed[8], framed[9]])));
								recorder.lock().unwrap().push(format!("udp {dst}"));
								let Ok(out)=UdpSocket::bind("127.0.0.1:0").await else{continue};
								if out.send_to(&framed[10..n], udp_backend).await.is_err(){continue}
								let Ok(Ok(m))=timeout(Duration::from_secs(2), out.recv(&mut echo)).await else{continue};
								// Answer as the destination the peer asked for, not as the loopback backend.
								let mut wrapped=framed[..10].to_vec();
								wrapped.extend_from_slice(&echo[..m]);
								let _=relay.send_to(&wrapped, peer).await;
							}
							// The association lives exactly as long as this control connection.
							_=client.read(&mut sink)=>return,
						}
					}
				}
				recorder.lock().unwrap().push(format!("{host}:{port}"));
				let backend=if port==53{dns_backend}else{tcp_backend};
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

async fn tcp_responder()->(SocketAddr, Arc<AtomicUsize>){
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	let hits=Arc::new(AtomicUsize::new(0));
	let counter=hits.clone();
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			counter.fetch_add(1, Ordering::SeqCst);
			tokio::spawn(async move{
				let _=s.write_all(GREETING).await;
				let mut sink=[0u8;256];
				let _=s.read(&mut sink).await;
			});
		}
	});
	(addr, hits)
}

/// DNS over TCP: 2 byte big endian length, then the message.
/// Echoes every datagram back with an `echo:` prefix.
async fn udp_responder()->(SocketAddr, Arc<AtomicUsize>){
	let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr=sock.local_addr().unwrap();
	let hits=Arc::new(AtomicUsize::new(0));
	let counter=hits.clone();
	tokio::spawn(async move{
		let mut buf=vec![0u8;2048];
		loop{
			let Ok((n, from))=sock.recv_from(&mut buf).await else{return};
			counter.fetch_add(1, Ordering::SeqCst);
			let mut reply=b"echo:".to_vec();
			reply.extend_from_slice(&buf[..n]);
			let _=sock.send_to(&reply, from).await;
		}
	});
	(addr, hits)
}

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

struct Wgw{addr:SocketAddr, ws:Option<SocketAddr>, public:[u8;32], keys:[[u8;32];2]}

async fn spawn_server(upstream:&str, dns:Option<&str>)->Wgw{
	spawn_listening(r#""listen_udp":"127.0.0.1:0""#, upstream, dns, "").await
}

async fn spawn_listening(listeners:&str, upstream:&str, dns:Option<&str>, extra:&str)->Wgw{
	let private=wgcore::generate_key();
	let keys=[wgcore::generate_key(), wgcore::generate_key()];
	let dns=dns.map(|d| format!(r#","dns":"{d}""#)).unwrap_or_default();
	let json=format!(
		r#"{{"private_key":"{}","address":"10.7.0.1/24","mtu":1420,{listeners},"upstream":"{upstream}"{dns}{extra},
		 "peers":[{{"public_key":"{}","allowed_ips":["10.7.0.2/32"]}},{{"public_key":"{}","allowed_ips":["10.7.0.3/32"]}}]}}"#,
		wgcore::encode_key(&private), wgcore::encode_key(&wgcore::public_key(&keys[0])), wgcore::encode_key(&wgcore::public_key(&keys[1])));
	let cfg:server::config::Config=serde_json::from_str(&json).unwrap();
	cfg.validate().unwrap();
	let running=server::start(cfg).await.unwrap();
	Wgw{addr:running.udp_addr, ws:running.ws_addr, public:wgcore::public_key(&private), keys}
}

struct Client{tunn:Tunn, sock:UdpSocket, init:Vec<u8>}

impl Client{
	async fn connect(private:[u8;32], server_public:[u8;32], server:SocketAddr)->Client{
		let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(server).await.unwrap();
		let mut tunn=Tunn::new(StaticSecret::from(private), PublicKey::from(server_public), None, None, 0, None);
		let mut scratch=vec![0u8;2048];
		let TunnResult::WriteToNetwork(init)=tunn.format_handshake_initiation(&mut scratch, false) else{panic!("no handshake initiation")};
		let init=init.to_vec();
		sock.send(&init).await.unwrap();
		let mut datagram=vec![0u8;2048];
		let n=timeout(Duration::from_secs(3), sock.recv(&mut datagram)).await.expect("handshake timed out").unwrap();
		let mut out=vec![0u8;2048];
		if let TunnResult::WriteToNetwork(b)=tunn.decapsulate(None, &datagram[..n], &mut out){
			let keepalive=b.to_vec();
			sock.send(&keepalive).await.unwrap();
		}
		Client{tunn, sock, init}
	}

	async fn send_ip(&mut self, packet:&[u8]){
		let mut out=vec![0u8;packet.len()+2048];
		let TunnResult::WriteToNetwork(b)=self.tunn.encapsulate(packet, &mut out) else{panic!("encapsulate produced nothing")};
		let datagram=b.to_vec();
		self.sock.send(&datagram).await.unwrap();
	}

	/// Next decrypted IP packet, pumping boringtun's own traffic along the way.
	async fn recv_ip(&mut self, budget:Duration)->Option<Vec<u8>>{
		let deadline=Instant::now()+budget;
		loop{
			let left=deadline.checked_duration_since(Instant::now())?;
			let mut datagram=vec![0u8;2048];
			let n=match timeout(left, self.sock.recv(&mut datagram)).await{Ok(Ok(n))=>n, _=>return None};
			let mut input:&[u8]=&datagram[..n];
			loop{
				let mut out=vec![0u8;2048];
				match self.tunn.decapsulate(None, input, &mut out){
					TunnResult::WriteToNetwork(b)=>{
						let reply=b.to_vec();
						let _=self.sock.send(&reply).await;
						input=&[];
					}
					TunnResult::WriteToTunnelV4(b, _)=>return Some(b.to_vec()),
					_=>break,
				}
			}
		}
	}
}

fn ip_tcp(src:[u8;4], dst:[u8;4], tcp:TcpHeader, payload:&[u8])->Vec<u8>{
	let builder=PacketBuilder::ipv4(src, dst, 64).tcp_header(tcp);
	let mut out=Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

fn ip_udp(src:[u8;4], dst:[u8;4], sport:u16, dport:u16, payload:&[u8])->Vec<u8>{
	let builder=PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
	let mut out=Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

fn parse_tcp(packet:&[u8])->Option<(TcpHeader, Vec<u8>)>{
	let parsed=PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp)=parsed.transport? else{return None};
	let payload=match parsed.payload{PayloadSlice::Tcp(p)=>p.to_vec(), _=>Vec::new()};
	Some((tcp, payload))
}

fn syn(sport:u16, dport:u16)->TcpHeader{
	let mut h=TcpHeader::new(sport, dport, 1000, 65535);
	h.syn=true;
	h
}

/// SYN, wait for SYN/ACK, ACK. Returns the server's initial sequence number.
async fn handshake(client:&mut Client, dst:[u8;4], sport:u16, dport:u16)->u32{
	client.send_ip(&ip_tcp(PEER_A, dst, syn(sport, dport), &[])).await;
	let reply=client.recv_ip(Duration::from_secs(3)).await.expect("no SYN/ACK");
	let (tcp, _)=parse_tcp(&reply).expect("reply was not tcp");
	assert!(tcp.syn && tcp.ack, "expected SYN/ACK, got {tcp:?}");
	let mut ack=TcpHeader::new(sport, dport, 1001, 65535);
	ack.ack=true;
	ack.acknowledgment_number=tcp.sequence_number.wrapping_add(1);
	client.send_ip(&ip_tcp(PEER_A, dst, ack, &[])).await;
	tcp.sequence_number
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn tcp_reaches_the_responder_through_the_socks5(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40001, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "peer did not receive the upstream bytes");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"], "socks5 did not observe the CONNECT");
}

/// A stranger flooding replayed handshake initiations must not steal peer A's endpoint. Past the rate limit
/// those forgeries draw a cookie reply, and the cookie path is the one that used to move the endpoint.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_forged_handshake_flood_cannot_steal_the_endpoint(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	let attacker=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	attacker.connect(wgw.addr).await.unwrap();
	for _ in 0..300{let _=attacker.send(&client.init).await;}
	handshake(&mut client, [93, 184, 216, 34], 40007, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "downstream traffic followed the forged handshakes instead of the real peer");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"]);
}

/// Same success as above, but with no public UDP listener: the peer only ever talks to the WS relay.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn tcp_reaches_the_responder_over_the_ws_relay(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_listening(r#""listen_ws":{"addr":"127.0.0.1:0","path":"/wg"}"#, &format!("socks5://{proxy}"), None, "").await;
	let bridge=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge_addr=bridge.local_addr().unwrap();
	tokio::spawn(wsrelay::run_client_on(bridge, format!("ws://{}/wg", wgw.ws.unwrap()), false));
	let mut client=Client::connect(wgw.keys[0], wgw.public, bridge_addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40006, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "peer did not receive the upstream bytes through the relay");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"], "socks5 did not observe the CONNECT");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn nothing_gets_through_when_the_socks5_is_down(){
	let (backend, hits)=tcp_responder().await;
	let dead=TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let wgw=spawn_server(&format!("socks5://{dead}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40002, 80).await;
	let mut got=Vec::new();
	let deadline=Instant::now()+Duration::from_millis(1500);
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let Some(packet)=client.recv_ip(left).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert!(got.is_empty(), "got {got:?} with no proxy running");
	assert_eq!(hits.load(Ordering::SeqCst), 0, "server fell back to a direct connection");
	let _=backend;
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn peers_cannot_reach_each_other_or_the_gateway(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	for (dst, sport) in [(PEER_B, 40003u16), (GATEWAY, 40004)]{
		client.send_ip(&ip_tcp(PEER_A, dst, syn(sport, 80), &[])).await;
		let deadline=Instant::now()+Duration::from_secs(1);
		let mut refused=false;
		while let Some(left)=deadline.checked_duration_since(Instant::now()){
			let Some(packet)=client.recv_ip(left).await else{break};
			let Some((tcp, _))=parse_tcp(&packet) else{continue};
			assert!(!(tcp.syn && tcp.ack), "{dst:?} answered a SYN/ACK");
			refused|=tcp.rst;
		}
		assert!(refused, "{dst:?} should have been RST");
	}
	assert!(seen.lock().unwrap().is_empty(), "blocked traffic still reached the proxy");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn dns_is_forwarded_over_tcp_through_the_socks5(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), Some("1.1.1.1:53")).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	let builder=PacketBuilder::ipv4(PEER_A, [9, 9, 9, 9], 64).udp(40005, 53);
	let query=b"\x12\x34\x01\x00fake-query";
	let mut packet=Vec::with_capacity(builder.size(query.len()));
	builder.write(&mut packet, query).unwrap();
	client.send_ip(&packet).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no dns reply");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), ([9, 9, 9, 9], PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"], "dns override was not used");
}

/// Without a forced resolver, port 53 is plain udp through an association, so apps that speak their own protocol on 53
/// still reach hosts that never answer dns over tcp.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn port_53_rides_an_association_without_an_override(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	client.send_ip(&ip_udp(PEER_A, [54, 194, 213, 130], 40020, 53, b"custom")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no reply on port 53");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, b"echo:custom");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"udp 54.194.213.130:53".to_string()), "port 53 did not go through the association: {seen:?}");
	assert!(!seen.contains(&"54.194.213.130:53".to_string()), "port 53 still went over tcp: {seen:?}");
}

/// A proxy without udp still resolves: port 53 falls back to dns over tcp to the address the peer asked for.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn port_53_falls_back_to_tcp_when_the_proxy_refuses_udp(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	client.send_ip(&ip_udp(PEER_A, [9, 9, 9, 9], 40021, 53, b"\x12\x34\x01\x00fake-query")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no dns reply after the fallback");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"associate 0.0.0.0:0".to_string()), "udp was not tried first: {seen:?}");
	assert!(seen.contains(&"9.9.9.9:53".to_string()), "no tcp fallback to the asked resolver: {seen:?}");
}

/// Non dns udp rides a real SOCKS5 UDP ASSOCIATE: the peer gets its echo back and the proxy saw both
/// the association and the wrapped destination.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn udp_reaches_the_responder_through_an_association(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	client.send_ip(&ip_udp(PEER_A, [93, 184, 216, 34], 40010, 9999, b"ping")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no udp reply");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), ([93, 184, 216, 34], PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, b"echo:ping");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"associate 0.0.0.0:0".to_string()), "no association was opened: {seen:?}");
	assert!(seen.contains(&"udp 93.184.216.34:9999".to_string()), "wrong relayed destination: {seen:?}");
}

/// A proxy that answers an association with REP 0x07 just loses the datagram, and the tunnel lives on.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_refused_association_drops_the_datagram(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let wgw=spawn_server(&format!("socks5://{proxy}"), None).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	client.send_ip(&ip_udp(PEER_A, [93, 184, 216, 34], 40011, 9999, b"ping")).await;
	assert!(client.recv_ip(Duration::from_millis(1500)).await.is_none(), "a refused association still answered");
	assert_eq!(hits.load(Ordering::SeqCst), 0, "the datagram reached the backend anyway");
	assert!(seen.lock().unwrap().iter().any(|s| s=="associate 0.0.0.0:0"), "the association was never attempted");
	// Whatever the proxy said about udp, tcp through the same server still works.
	handshake(&mut client, [93, 184, 216, 34], 40012, 80).await;
}

/// Opens a flow, lets it go quiet for 2.5s, then pokes it: true if the server reset it in the meantime.
async fn flow_reset_while_idle(tcp_idle:u64, sport:u16)->bool{
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let wgw=spawn_listening(r#""listen_udp":"127.0.0.1:0""#, &format!("socks5://{proxy}"), None, &format!(r#","tcp_idle_secs":{tcp_idle}"#)).await;
	let mut client=Client::connect(wgw.keys[0], wgw.public, wgw.addr).await;
	let dst=[93, 184, 216, 34];
	let isn=handshake(&mut client, dst, sport, 80).await;
	let (mut got, mut rst)=(0usize, false);
	while got<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((tcp, payload))=parse_tcp(&packet){rst|=tcp.rst; got+=payload.len()}
	}
	assert_eq!(got, GREETING.len(), "the greeting never arrived");
	tokio::time::sleep(Duration::from_millis(2500)).await;
	let mut data=TcpHeader::new(sport, 80, 1001, 65535);
	data.ack=true;
	data.psh=true;
	data.acknowledgment_number=isn.wrapping_add(1+got as u32);
	client.send_ip(&ip_tcp(PEER_A, dst, data, b"still-there")).await;
	let deadline=Instant::now()+Duration::from_secs(2);
	let mut acked=false;
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let Some(packet)=client.recv_ip(left).await else{break};
		let Some((tcp, _))=parse_tcp(&packet) else{continue};
		rst|=tcp.rst;
		acked|=tcp.ack && !tcp.rst;
		if rst{break}
	}
	assert!(rst|| acked, "the flow neither answered nor reset");
	rst
}

/// An idle TCP flow is torn down on the configured schedule, not ipstack's hardcoded 60 seconds.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_idle_tcp_flow_lives_exactly_as_long_as_tcp_idle_secs(){
	assert!(flow_reset_while_idle(1, 40020).await, "a 1 second idle timeout did not reset a flow quiet for 2.5s");
	assert!(!flow_reset_while_idle(30, 40021).await, "a 30 second idle timeout reset a flow quiet for only 2.5s");
}

#[test]
fn egress_never_dials_directly(){
	let src=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	for entry in std::fs::read_dir(&src).unwrap(){
		let path=entry.unwrap().path();
		let text=std::fs::read_to_string(&path).unwrap();
		// The only direct dial allowed is the control connection to the proxy itself.
		for line in text.lines().filter(|l| l.contains("TcpStream::connect")){
			assert!(line.contains("up.addr"), "{} dials {} without the proxy", path.display(), line.trim());
		}
	}
}
