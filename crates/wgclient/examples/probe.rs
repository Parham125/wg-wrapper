//! Real-world probe: `cargo run -p wgclient --example probe -- client.conf`. Connects through whatever the conf
//! says, sends one DNS query for example.com to 1.1.1.1 through the tunnel and prints what came back.
use etherparse::{NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice};
use std::io;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use wgclient::{Tun, Tunnel};

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

const QUERY:&[u8]=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

#[tokio::main]
async fn main()->anyhow::Result<()>{
	tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
	let path=std::env::args().nth(1).expect("usage: probe <client.conf>");
	let cfg=wgclient::parse_conf(&std::fs::read_to_string(path)?)?;
	let client=match cfg.address.addr(){std::net::IpAddr::V4(a)=>a.octets(), _=>anyhow::bail!("ipv4 conf only")};
	let (up_tx, up_rx)=channel();
	let (down_tx, down_rx)=channel();
	let started=Instant::now();
	let tunnel=Tunnel::connect(cfg, Box::new(MockTun{up:Mutex::new(up_rx), down:Mutex::new(down_tx)})).await?;
	println!("handshake ok in {:?}", started.elapsed());
	let builder=PacketBuilder::ipv4(client, [1, 1, 1, 1], 64).udp(40005, 53);
	let mut packet=Vec::with_capacity(builder.size(QUERY.len()));
	builder.write(&mut packet, QUERY)?;
	up_tx.send(packet)?;
	let sent=Instant::now();
	let reply=down_rx.recv_timeout(Duration::from_secs(10)).map_err(|_| anyhow::anyhow!("no dns answer within 10s"))?;
	let parsed=PacketHeaders::from_ip_slice(&reply)?;
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{anyhow::bail!("reply not ipv4")};
	let PayloadSlice::Udp(payload)=parsed.payload else{anyhow::bail!("reply not udp")};
	let answers=u16::from_be_bytes([payload[6], payload[7]]);
	let rcode=payload[3]&0x0f;
	println!("dns reply from {:?} in {:?}: {} bytes, rcode {rcode}, {answers} answer(s), last A record {:?}", ip.source, sent.elapsed(), payload.len(), payload.len().checked_sub(4).map(|i| &payload[i..]));
	// Plain UDP that is not DNS exercises the server's SOCKS5 UDP ASSOCIATE path: an NTP request to time.cloudflare.com.
	let mut ntp=vec![0u8;48];
	ntp[0]=0x23;
	let builder=PacketBuilder::ipv4(client, [162, 159, 200, 1], 64).udp(40006, 123);
	let mut packet=Vec::with_capacity(builder.size(ntp.len()));
	builder.write(&mut packet, &ntp)?;
	up_tx.send(packet)?;
	let sent=Instant::now();
	match down_rx.recv_timeout(Duration::from_secs(10)){
		Ok(reply)=>{
			let parsed=PacketHeaders::from_ip_slice(&reply)?;
			let PayloadSlice::Udp(payload)=parsed.payload else{anyhow::bail!("ntp reply not udp")};
			println!("ntp reply in {:?}: {} bytes, stratum {}", sent.elapsed(), payload.len(), payload.get(1).copied().unwrap_or(0));
		}
		Err(_)=>println!("ntp: no reply within 10s (upstream SOCKS5 may not support UDP ASSOCIATE)"),
	}
	// PROBE_BURST=a.b.c.d,e.f.g.h,... fires one NTP request per address at once, like a game pinging many relays.
	if let Ok(list)=std::env::var("PROBE_BURST"){
		let ips:Vec<[u8;4]>=list.split(",").filter_map(|s| s.trim().parse::<std::net::Ipv4Addr>().ok()).map(|a| a.octets()).collect();
		for (i, ip) in ips.iter().enumerate(){
			let builder=PacketBuilder::ipv4(client, *ip, 64).udp(41000+i as u16, 123);
			let mut packet=Vec::with_capacity(builder.size(ntp.len()));
			builder.write(&mut packet, &ntp)?;
			up_tx.send(packet)?;
		}
		let started=Instant::now();
		let mut got=std::collections::HashSet::new();
		while got.len()<ips.len() && started.elapsed()<Duration::from_secs(8){
			if let Ok(reply)=down_rx.recv_timeout(Duration::from_millis(200)){
				if let Ok(parsed)=PacketHeaders::from_ip_slice(&reply){if let Some(NetHeaders::Ipv4(ip, _))=parsed.net{got.insert(ip.source);}}
			}
		}
		println!("burst: {} of {} relays answered within {:?}", got.len(), ips.len(), started.elapsed());
	}
	let s=tunnel.stats();
	println!("stats: tx {} rx {} last_handshake {:?}", s.tx_bytes, s.rx_bytes, s.last_handshake.map(|t| t.elapsed().unwrap_or_default()));
	tunnel.close().await;
	Ok(())
}
