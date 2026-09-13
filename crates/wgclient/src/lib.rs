//! Single-peer WireGuard client engine (any OS, sockets only) plus the Windows adapter/route layer.
//! Transport is either plain UDP or WSS through an in-process `wsrelay::run_client_to` bridge.
use anyhow::{anyhow, bail, Context};
use ipnet::IpNet;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use wgcore::{Wg, MAX_PACKET};

/// How long `connect` waits for the first handshake before giving up.
const HANDSHAKE_TIMEOUT:Duration=Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint{Udp(SocketAddr), UdpHost(String), Ws{url:String, insecure:bool}}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig{
	pub private_key:String,
	pub peer_public_key:String,
	pub preshared_key:Option<String>,
	/// This client's tunnel address with prefix, e.g. 10.7.0.2/32.
	pub address:IpNet,
	pub dns:Vec<IpAddr>,
	pub endpoint:Endpoint,
	pub allowed_ips:Vec<IpNet>,
	pub mtu:u16,
	pub keepalive:Option<u16>,
}

/// Parses a standard WireGuard .conf. `Endpoint = wss://host/path` or `ws://` selects the WebSocket transport,
/// `InsecureTls = true` under [Peer] skips certificate verification. MTU defaults to 1420 (udp) or 1380 (ws).
pub fn parse_conf(text:&str)->anyhow::Result<ClientConfig>{
	let (mut section, mut iface, mut peer)=(String::new(), HashMap::<String, String>::new(), HashMap::<String, String>::new());
	for raw in text.lines(){
		let line=raw.split('#').next().unwrap_or("").trim();
		if line.is_empty(){continue}
		if let Some(name)=line.strip_prefix('['){
			section=name.trim_end_matches(']').trim().to_ascii_lowercase();
			continue;
		}
		let Some((k, v))=line.split_once('=') else{bail!("malformed line {raw:?}")};
		let (k, v)=(k.trim().to_ascii_lowercase(), v.trim().to_string());
		match section.as_str(){
			"interface"=>{iface.insert(k, v);}
			"peer"=>{peer.insert(k, v);}
			other=>bail!("key {k:?} sits in unknown section [{other}]"),
		}
	}
	let private_key=iface.remove("privatekey").ok_or_else(|| anyhow!("[Interface] PrivateKey is required"))?;
	wgcore::decode_key(&private_key).context("[Interface] PrivateKey")?;
	let peer_public_key=peer.remove("publickey").ok_or_else(|| anyhow!("[Peer] PublicKey is required"))?;
	wgcore::decode_key(&peer_public_key).context("[Peer] PublicKey")?;
	let preshared_key=peer.remove("presharedkey");
	if let Some(psk)=&preshared_key{wgcore::decode_key(psk).context("[Peer] PresharedKey")?;}
	let address=iface.remove("address").ok_or_else(|| anyhow!("[Interface] Address is required"))?;
	let first=address.split(',').next().unwrap_or("").trim().to_string();
	let address=match first.split_once('/'){
		Some(_)=>first.parse::<IpNet>().context("[Interface] Address")?,
		None=>{
			let ip:IpAddr=first.parse().context("[Interface] Address")?;
			IpNet::new(ip, if ip.is_ipv4(){32}else{128})?
		}
	};
	// wg-quick lets DNS carry search domains too, so anything that is not an address is skipped.
	let dns=iface.remove("dns").map(|v| v.split(',').filter_map(|d| d.trim().parse().ok()).collect()).unwrap_or_default();
	let allowed_ips=match peer.remove("allowedips"){
		Some(v)=>v.split(',').filter(|s| !s.trim().is_empty()).map(|s| s.trim().parse::<IpNet>().with_context(|| format!("[Peer] AllowedIPs entry {s:?}"))).collect::<anyhow::Result<Vec<_>>>()?,
		None=>Vec::new(),
	};
	let raw_endpoint=peer.remove("endpoint").ok_or_else(|| anyhow!("[Peer] Endpoint is required"))?;
	let insecure=peer.remove("insecuretls").is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "true"|"1"|"yes"|"on"));
	let lower=raw_endpoint.to_ascii_lowercase();
	let endpoint=if lower.starts_with("wss://")|| lower.starts_with("ws://"){
		Endpoint::Ws{url:raw_endpoint, insecure}
	}else{
		match raw_endpoint.parse::<SocketAddr>(){
			Ok(a)=>Endpoint::Udp(a),
			Err(_)=>{
				let (host, port)=raw_endpoint.rsplit_once(':').ok_or_else(|| anyhow!("[Peer] Endpoint {raw_endpoint:?} must be host:port or a ws:// url"))?;
				if host.is_empty()|| port.parse::<u16>().is_err(){bail!("[Peer] Endpoint {raw_endpoint:?} must be host:port or a ws:// url")}
				Endpoint::UdpHost(raw_endpoint)
			}
		}
	};
	let mtu=iface.remove("mtu").map(|m| m.parse::<u16>()).transpose().context("[Interface] MTU")?
		.unwrap_or(if matches!(endpoint, Endpoint::Ws{..}){1380}else{1420});
	let keepalive=peer.remove("persistentkeepalive").map(|k| k.parse::<u16>()).transpose().context("[Peer] PersistentKeepalive")?.filter(|k| *k>0);
	Ok(ClientConfig{private_key, peer_public_key, preshared_key, address, dns, endpoint, allowed_ips, mtu, keepalive})
}

/// Blocking packet device. The engine drives it from one thread per direction, so `recv` and `send`
/// have to tolerate being in flight at once (a tun fd, a wintun session and a pair of channels all do).
pub trait Tun:Send+Sync+'static{
	fn recv(&self, buf:&mut [u8])->io::Result<usize>;
	fn send(&self, packet:&[u8])->io::Result<()>;
}

#[derive(Clone, Debug)]
pub struct Stats{pub rx_bytes:u64, pub tx_bytes:u64, pub v6_dropped:u64, pub last_handshake:Option<SystemTime>, pub connected_since:SystemTime}

struct Counters{rx:AtomicU64, tx:AtomicU64, v6_dropped:AtomicU64}

pub struct Tunnel{
	wg:Arc<Mutex<Wg>>,
	counters:Arc<Counters>,
	to_tun:mpsc::UnboundedSender<Vec<u8>>,
	tasks:Vec<JoinHandle<()>>,
	shutdown:Arc<AtomicBool>,
	connected_since:SystemTime,
}

impl Tunnel{
	/// Brings the tunnel up and returns once the first handshake completed (10s timeout).
	pub async fn connect(cfg:ClientConfig, tun:Box<dyn Tun>)->anyhow::Result<Tunnel>{
		let endpoint=resolve_endpoint(&cfg).await?;
		Tunnel::connect_to(cfg, tun, endpoint).await
	}

	/// Same as [`Tunnel::connect`] but with the endpoint already resolved, so nothing here depends on
	/// DNS. The Windows client needs this: by the time it dials, its catch-all NRPT rule already points
	/// at the tunnel's resolver, which is unreachable until the tunnel is up.
	pub async fn connect_to(cfg:ClientConfig, tun:Box<dyn Tun>, endpoint:SocketAddr)->anyhow::Result<Tunnel>{
		let mut wg=Wg::new(wgcore::decode_key(&cfg.private_key).context("private key")?);
		let psk=cfg.preshared_key.as_deref().map(wgcore::decode_key).transpose().context("preshared key")?;
		wg.add_peer(wgcore::decode_key(&cfg.peer_public_key).context("peer public key")?, psk, cfg.keepalive)?;
		let mut tasks:Vec<JoinHandle<()>>=Vec::new();
		// The ws bridge owns one loopback socket and maps our source port onto a single WS connection.
		let peer=match &cfg.endpoint{
			Endpoint::Ws{url, insecure}=>{
				let bridge=UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
				let local=bridge.local_addr()?;
				let (url, insecure)=(url.clone(), *insecure);
				tasks.push(tokio::spawn(async move{if let Err(e)=wsrelay::run_client_to(bridge, url, insecure, Some(endpoint)).await{tracing::error!("ws bridge stopped: {e}")}}));
				local
			}
			_=>endpoint,
		};
		let bind=if peer.is_ipv4(){SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))}else{SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))};
		let sock=Arc::new(UdpSocket::bind(bind).await?);
		sock.connect(peer).await.with_context(|| format!("connecting to {peer}"))?;
		let wg=Arc::new(Mutex::new(wg));
		let counters=Arc::new(Counters{rx:AtomicU64::new(0), tx:AtomicU64::new(0), v6_dropped:AtomicU64::new(0)});
		let shutdown=Arc::new(AtomicBool::new(false));
		let tun:Arc<dyn Tun>=Arc::from(tun);
		let (from_tun, mut from_tun_rx)=mpsc::unbounded_channel::<Vec<u8>>();
		let (to_tun, mut to_tun_rx)=mpsc::unbounded_channel::<Vec<u8>>();
		std::thread::spawn({
			let (tun, shutdown)=(tun.clone(), shutdown.clone());
			move ||{
				let mut buf=vec![0u8;MAX_PACKET];
				while !shutdown.load(Ordering::Relaxed){
					match tun.recv(&mut buf){
						Ok(0)=>continue,
						Ok(n)=>if from_tun.send(buf[..n].to_vec()).is_err(){break},
						Err(e)=>{tracing::debug!("tun recv stopped: {e}"); break}
					}
				}
			}
		});
		std::thread::spawn({
			let tun=tun.clone();
			move ||{while let Some(p)=to_tun_rx.blocking_recv(){if let Err(e)=tun.send(&p){tracing::debug!("tun send stopped: {e}"); break}}}
		});
		tasks.push(tokio::spawn({
			let (wg, sock, counters, to_tun)=(wg.clone(), sock.clone(), counters.clone(), to_tun.clone());
			async move{
				let mut buf=vec![0u8;MAX_PACKET];
				let (mut net_out, mut ip_out)=(Vec::new(), Vec::new());
				loop{
					// A connected UDP socket reports ICMP unreachable as a read error, so never spin on it.
					let n=match sock.recv(&mut buf).await{Ok(n)=>n, Err(_)=>{tokio::time::sleep(Duration::from_millis(5)).await; continue}};
					counters.rx.fetch_add(n as u64, Ordering::Relaxed);
					net_out.clear();
					ip_out.clear();
					let idx=wg.lock().unwrap().recv_from_network(peer, &buf[..n], &mut net_out, &mut ip_out);
					if counters.rx.load(Ordering::Relaxed)<2048{tracing::debug!("{n} bytes from {peer}: peer {idx:?}, {} to send, {} decrypted", net_out.len(), ip_out.len())}
					for d in &net_out{counters.tx.fetch_add(d.len() as u64, Ordering::Relaxed); let _=sock.send(d).await;}
					for p in ip_out.drain(..){if to_tun.send(p).is_err(){return}}
				}
			}
		}));
		tasks.push(tokio::spawn({
			let (wg, sock, counters)=(wg.clone(), sock.clone(), counters.clone());
			async move{
				let mut net_out=Vec::new();
				while let Some(p)=from_tun_rx.recv().await{
					// IPv6 is blocked on the client for now, so it is black-holed here instead of reaching the server.
					// Windows floods a fresh adapter with v6 neighbour discovery, so only the first and every 500th drop is logged.
					if p.first().is_some_and(|b| b>>4==6){let n=counters.v6_dropped.fetch_add(1, Ordering::Relaxed); if n%500==0{tracing::debug!("dropped an ipv6 packet of {} bytes from the tun ({} so far)", p.len(), n+1)} continue}
					net_out.clear();
					wg.lock().unwrap().encapsulate(0, &p, &mut net_out);
					for d in &net_out{counters.tx.fetch_add(d.len() as u64, Ordering::Relaxed); let _=sock.send(d).await;}
				}
			}
		}));
		tasks.push(tokio::spawn({
			let (wg, sock, counters)=(wg.clone(), sock.clone(), counters.clone());
			async move{
				let mut tick=tokio::time::interval(Duration::from_millis(250));
				let mut out=Vec::new();
				loop{
					tick.tick().await;
					out.clear();
					wg.lock().unwrap().update_timers(&mut out);
					for (_, d) in &out{counters.tx.fetch_add(d.len() as u64, Ordering::Relaxed); let _=sock.send(d).await;}
				}
			}
		}));
		// An empty packet with no live session is exactly boringtun's handshake initiation path.
		let mut init=Vec::new();
		wg.lock().unwrap().encapsulate(0, &[], &mut init);
		for d in &init{counters.tx.fetch_add(d.len() as u64, Ordering::Relaxed); sock.send(d).await?; tracing::debug!("sent handshake init, {} bytes from {} to {peer}", d.len(), sock.local_addr()?);}
		let deadline=tokio::time::Instant::now()+HANDSHAKE_TIMEOUT;
		while wg.lock().unwrap().time_since_last_handshake(0).is_none(){
			if tokio::time::Instant::now()>=deadline{
				shutdown.store(true, Ordering::Relaxed);
				for t in &tasks{t.abort()}
				bail!("no handshake from {peer} within {}s", HANDSHAKE_TIMEOUT.as_secs());
			}
			tokio::time::sleep(Duration::from_millis(25)).await;
		}
		tracing::info!("tunnel to {peer} up");
		Ok(Tunnel{wg, counters, to_tun, tasks, shutdown, connected_since:SystemTime::now()})
	}

	pub fn stats(&self)->Stats{
		let since=self.wg.lock().unwrap().time_since_last_handshake(0);
		Stats{
			rx_bytes:self.counters.rx.load(Ordering::Relaxed),
			tx_bytes:self.counters.tx.load(Ordering::Relaxed),
			v6_dropped:self.counters.v6_dropped.load(Ordering::Relaxed),
			last_handshake:since.and_then(|d| SystemTime::now().checked_sub(d)),
			connected_since:self.connected_since,
		}
	}

	/// Stops every task and the tun write thread. The read thread can still be parked inside `Tun::recv`;
	/// it leaves on the next return, so unblock the device (drop it, or `Session::shutdown` on wintun).
	pub async fn close(self){
		self.shutdown.store(true, Ordering::Relaxed);
		for t in &self.tasks{t.abort()}
		drop(self.to_tun);
		for t in self.tasks{let _=t.await;}
	}
}

/// Resolves the endpoint host to an IP before any route changes, so the host route can pin it.
pub async fn resolve_endpoint(cfg:&ClientConfig)->anyhow::Result<SocketAddr>{
	match &cfg.endpoint{
		Endpoint::Udp(a)=>Ok(*a),
		Endpoint::UdpHost(h)=>lookup_host(h.as_str()).await.with_context(|| format!("resolving {h}"))?.next().ok_or_else(|| anyhow!("{h} resolved to nothing")),
		Endpoint::Ws{url, ..}=>{
			let (scheme, rest)=url.split_once("://").ok_or_else(|| anyhow!("endpoint {url:?} is not a url"))?;
			let default=match scheme.to_ascii_lowercase().as_str(){"wss"=>443, "ws"=>80, s=>bail!("unsupported endpoint scheme {s:?}")};
			let authority=rest.split(['/', '?', '#']).next().unwrap_or(rest);
			let authority=authority.rsplit_once('@').map_or(authority, |(_, h)| h);
			let (host, port)=match authority.strip_prefix('['){
				Some(r)=>{
					let (h, tail)=r.split_once(']').ok_or_else(|| anyhow!("endpoint {url:?} has an unterminated ipv6 host"))?;
					(h.to_string(), tail.strip_prefix(':').map(str::parse::<u16>).transpose()?.unwrap_or(default))
				}
				None=>match authority.rsplit_once(':'){
					Some((h, p))=>(h.to_string(), p.parse().with_context(|| format!("endpoint {url:?} port"))?),
					None=>(authority.to_string(), default),
				},
			};
			if host.is_empty(){bail!("endpoint {url:?} has no host")}
			let found=lookup_host((host.as_str(), port)).await.with_context(|| format!("resolving {host}"))?.next();
			found.ok_or_else(|| anyhow!("{host} resolved to nothing"))
		}
	}
}

/// Reads the "Active Routes" table of `route print -4`: the lowest-metric default route as (gateway, interface ip)
/// and the on-link subnets sitting on that same interface, which are the LAN prefixes a full tunnel has to swallow.
pub fn parse_routes(text:&str)->(Option<(Ipv4Addr, Ipv4Addr)>, Vec<(Ipv4Addr, Ipv4Addr)>){
	let (mut rows, mut active)=(Vec::new(), false);
	for raw in text.lines(){
		let line=raw.trim();
		if line.starts_with("Active Routes:"){active=true; continue}
		if line.starts_with("Persistent Routes:"){break}
		if !active{continue}
		let f:Vec<&str>=line.split_whitespace().collect();
		if f.len()!=5{continue}
		let (Ok(dest), Ok(mask), Ok(iface), Ok(metric))=(f[0].parse::<Ipv4Addr>(), f[1].parse::<Ipv4Addr>(), f[3].parse::<Ipv4Addr>(), f[4].parse::<u32>()) else{continue};
		rows.push((dest, mask, f[2], iface, metric));
	}
	let mut best:Option<(u32, Ipv4Addr, Ipv4Addr)>=None;
	for (dest, mask, gw, iface, metric) in &rows{
		if !dest.is_unspecified()|| !mask.is_unspecified(){continue}
		let Ok(gw)=gw.parse::<Ipv4Addr>() else{continue};
		if best.is_none_or(|(m, _, _)| *metric<m){best=Some((*metric, gw, *iface))}
	}
	let Some((_, gateway, ifaceip))=best else{return (None, Vec::new())};
	// 127/8, 224/4 and the all-ones broadcast are never someone's LAN, and a /32 is a host route, not a subnet.
	let lan=rows.iter().filter(|(dest, mask, gw, iface, _)| *iface==ifaceip && gw.eq_ignore_ascii_case("on-link") && *mask!=Ipv4Addr::BROADCAST
		&& dest.octets()[0]!=127 && dest.octets()[0]&0xf0!=224 && *dest!=Ipv4Addr::BROADCAST).map(|(dest, mask, _, _, _)| (*dest, *mask)).collect();
	(Some((gateway, ifaceip)), lan)
}

#[cfg(windows)]
pub mod win{
	use super::*;
	use std::collections::HashSet;
	use std::os::windows::process::CommandExt;
	use std::process::Command;

	const NAME:&str="wg-wrapper";
	const RING:u32=4*1024*1024;
	const CREATE_NO_WINDOW:u32=0x0800_0000;
	/// Drops every NRPT rule we own, both the stale ones a crashed run left behind and our own on the way out.
	const NRPT_CLEAR:&str="Get-DnsClientNrptRule | Where-Object Comment -eq 'wg-wrapper' | Remove-DnsClientNrptRule -Force";

	fn run(program:&str, args:&[String])->anyhow::Result<String>{
		tracing::debug!("{program} {}", args.join(" "));
		let out=Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output().with_context(|| format!("running {program}"))?;
		let text=String::from_utf8_lossy(&out.stdout).into_owned();
		if !out.status.success(){bail!("{program} {} failed: {}", args.join(" "), text.trim())}
		Ok(text)
	}

	fn argv(args:&[&str])->Vec<String>{args.iter().map(|s| s.to_string()).collect()}

	struct Device(Arc<wintun_bindings::Session>);

	impl Tun for Device{
		fn recv(&self, buf:&mut [u8])->io::Result<usize>{
			let packet=self.0.receive_blocking().map_err(io::Error::other)?;
			let bytes=packet.bytes();
			if bytes.len()>buf.len(){return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the read buffer"))}
			buf[..bytes.len()].copy_from_slice(bytes);
			Ok(bytes.len())
		}
		fn send(&self, packet:&[u8])->io::Result<()>{
			let mut out=self.0.allocate_send_packet(packet.len() as u16).map_err(io::Error::other)?;
			out.bytes_mut().copy_from_slice(packet);
			self.0.send_packet(out);
			Ok(())
		}
	}

	/// Wintun adapter plus the routes and DNS applied for it. Dropping it restores the system.
	pub struct Adapter{
		name:String,
		dns:bool,
		/// Full argv (program first) of everything needed to undo what `open` added.
		undo:Vec<Vec<String>>,
		session:Arc<wintun_bindings::Session>,
		_adapter:Arc<wintun_bindings::Adapter>,
	}

	/// Creates the adapter, assigns `cfg.address`, mtu and dns, adds the allowed_ips routes and a host route to
	/// `server` via the current default gateway (killswitch by routing). `dll` is the path of wintun.dll.
	pub fn open(cfg:&ClientConfig, server:IpAddr, dll:&std::path::Path)->anyhow::Result<(Adapter, Box<dyn Tun>)>{
		let wintun=unsafe{wintun_bindings::load_from_path(dll)}.with_context(|| format!("loading {}", dll.display()))?;
		let adapter=match wintun_bindings::Adapter::open(&wintun, NAME){
			Ok(a)=>a,
			Err(_)=>wintun_bindings::Adapter::create(&wintun, NAME, NAME, None).context("creating the wintun adapter")?,
		};
		let session=adapter.start_session(RING).context("starting the wintun session")?;
		let (name, index)=(adapter.get_name()?, adapter.get_adapter_index()?);
		let mut dev=Adapter{name:name.clone(), dns:false, undo:Vec::new(), session:session.clone(), _adapter:adapter};
		let (ip, mask)=(cfg.address.addr(), cfg.address.netmask());
		run("netsh", &argv(&["interface", "ipv4", "set", "address", &format!("name={name}"), "static", &ip.to_string(), &mask.to_string()]))?;
		run("netsh", &argv(&["interface", "ipv4", "set", "subinterface", &format!("interface={name}"), &format!("mtu={}", cfg.mtu), "store=persistent"]))?;
		// Every route below is added at metric 1, so the interface metric has to be 1 too for the tunnel to
		// outrank the physical link on the LAN subnets it re-routes. Nothing here depends on a DNS line.
		for (family, af) in [("ipv4", "IPv4"), ("ipv6", "IPv6")]{
			run("netsh", &argv(&["interface", family, "set", "interface", &name, "metric=1"]))?;
			// An explicit metric turns the automatic one off, so the undo has to turn it back on.
			dev.undo.push(argv(&["powershell", "-NoProfile", "-NonInteractive", "-Command", &format!("Set-NetIPInterface -InterfaceAlias '{name}' -AddressFamily {af} -AutomaticMetric Enabled")]));
		}
		// Smart multi-homed name resolution queries every interface at once, so setting the adapter's servers is
		// not enough: the tunnel also has to hold a catch-all NRPT rule for every name, on top of the metric above.
		if let Some((first, rest))=cfg.dns.split_first(){
			run("netsh", &argv(&["interface", "ipv4", "set", "dnsservers", &format!("name={name}"), "static", &first.to_string(), "primary", "no"]))?;
			for (i, d) in rest.iter().enumerate(){
				run("netsh", &argv(&["interface", "ipv4", "add", "dnsservers", &format!("name={name}"), &d.to_string(), &format!("index={}", i+2), "validate=no"]))?;
			}
			let servers=cfg.dns.iter().filter(|d| d.is_ipv4()).map(|d| d.to_string()).collect::<Vec<_>>();
			if !servers.is_empty(){
				let _=run("powershell", &argv(&["-NoProfile", "-NonInteractive", "-Command", NRPT_CLEAR]));
				run("powershell", &argv(&["-NoProfile", "-NonInteractive", "-Command", &format!("Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment '{NAME}'", servers.join(","))]))?;
				dev.undo.push(argv(&["powershell", "-NoProfile", "-NonInteractive", "-Command", NRPT_CLEAR]));
			}
			run("ipconfig", &argv(&["/flushdns"]))?;
			dev.dns=true;
		}else{
			tracing::warn!("the conf carries no DNS servers, so names keep resolving through the physical adapter and will leak");
		}
		// Pin the server to the real default gateway first, so the tunnel routes below cannot swallow it.
		let (default, lan)=parse_routes(&run("route", &argv(&["print", "-4"]))?);
		let (gateway, ifaceip)=default.ok_or_else(|| anyhow!("no ipv4 default gateway to pin {server} to"))?;
		// Windows reads a next hop equal to the interface's own address as on-link, so this keeps the gateway
		// reachable on the physical link even once the LAN subnet below has been pulled into the tunnel.
		let ongw=argv(&[&gateway.to_string(), "mask", "255.255.255.255", &ifaceip.to_string()]);
		run("route", &[argv(&["add"]), ongw.clone(), argv(&["metric", "1"])].concat())?;
		dev.undo.push([argv(&["route", "delete"]), ongw].concat());
		let host=argv(&[&server.to_string(), "mask", "255.255.255.255", &gateway.to_string()]);
		run("route", &[argv(&["add"]), host.clone(), argv(&["metric", "1"])].concat())?;
		dev.undo.push([argv(&["route", "delete"]), host].concat());
		for net in &cfg.allowed_ips{
			// A default route is split in two halves so it outranks the real one without replacing it.
			let parts:Vec<IpNet>=match net{
				IpNet::V4(n) if n.prefix_len()==0=>vec!["0.0.0.0/1".parse()?, "128.0.0.0/1".parse()?],
				other=>vec![*other],
			};
			for part in parts{
				match part{
					IpNet::V4(n)=>{
						let route=argv(&[&n.addr().to_string(), "mask", &n.netmask().to_string(), &ip.to_string()]);
						run("route", &[argv(&["add"]), route.clone(), argv(&["metric", "1", "if", &index.to_string()])].concat())?;
						dev.undo.push([argv(&["route", "delete"]), route].concat());
					}
					IpNet::V6(n)=>{
						let route=argv(&[&n.to_string(), &format!("interface={index}")]);
						run("netsh", &[argv(&["interface", "ipv6", "add", "route"]), route.clone()].concat())?;
						dev.undo.push([argv(&["netsh", "interface", "ipv6", "delete", "route"]), route].concat());
					}
				}
			}
		}
		// A full tunnel has to swallow the LAN too: the physical link's on-link subnet routes are more specific
		// than the two /1 halves and would otherwise keep winning, so each one is re-added through the adapter.
		if cfg.allowed_ips.iter().any(|n| matches!(n, IpNet::V4(v) if v.prefix_len()==0)){
			let mut taken=0;
			for (dest, netmask) in &lan{
				if IpAddr::V4(*dest)==cfg.address.network() && IpAddr::V4(*netmask)==mask{continue}
				let route=argv(&[&dest.to_string(), "mask", &netmask.to_string(), &ip.to_string()]);
				run("route", &[argv(&["add"]), route.clone(), argv(&["metric", "1", "if", &index.to_string()])].concat())?;
				dev.undo.push([argv(&["route", "delete"]), route].concat());
				taken+=1;
			}
			tracing::info!("{taken} local network subnet(s) routed into the tunnel, only {gateway} and {server} stay outside");
		}
		// IPv6 is blocked while the tunnel is up: both halves of ::/0 point at the adapter, which drops them.
		for half in ["::/1", "8000::/1"]{
			let net=half.parse::<IpNet>()?;
			if cfg.allowed_ips.contains(&net){continue}
			let route=argv(&[half, &format!("interface={index}")]);
			run("netsh", &[argv(&["interface", "ipv6", "add", "route"]), route.clone(), argv(&["metric=1"])].concat())?;
			dev.undo.push([argv(&["netsh", "interface", "ipv6", "delete", "route"]), route].concat());
		}
		// Each server also gets its own route, so DNS never rides on whatever allowed_ips happened to cover.
		let mut seen=HashSet::new();
		for d in cfg.dns.iter().filter(|d| seen.insert(**d)){
			match d{
				IpAddr::V4(a)=>{
					let route=argv(&[&a.to_string(), "mask", "255.255.255.255", &ip.to_string()]);
					run("route", &[argv(&["add"]), route.clone(), argv(&["metric", "1", "if", &index.to_string()])].concat())?;
					dev.undo.push([argv(&["route", "delete"]), route].concat());
				}
				IpAddr::V6(a)=>{
					let route=argv(&[&format!("{a}/128"), &format!("interface={index}")]);
					run("netsh", &[argv(&["interface", "ipv6", "add", "route"]), route.clone()].concat())?;
					dev.undo.push([argv(&["netsh", "interface", "ipv6", "delete", "route"]), route].concat());
				}
			}
		}
		Ok((dev, Box::new(Device(session))))
	}

	impl Drop for Adapter{
		fn drop(&mut self){
			for cmd in self.undo.iter().rev(){if let Err(e)=run(&cmd[0], &cmd[1..]){tracing::debug!("undo failed: {e}")}}
			if self.dns{
				let reset=argv(&["interface", "ipv4", "set", "dnsservers", &format!("name={}", self.name), "dhcp"]);
				if let Err(e)=run("netsh", &reset){tracing::debug!("dns reset failed: {e}")}
				if let Err(e)=run("ipconfig", &argv(&["/flushdns"])){tracing::debug!("dns flush failed: {e}")}
			}
			// Unblocks whichever thread is parked in `Device::recv` so the engine's read thread can exit.
			if let Err(e)=self.session.shutdown(){tracing::debug!("session shutdown failed: {e}")}
		}
	}
}

#[cfg(test)]
mod tests{
	use super::*;

	const PRIV:&str="qJ9Uq0Ie6/1bV2h0TaXGqUcyqO5qOZ0JqJLQqPqXmFo=";
	const PUB:&str="1Y0HGMRPPPDCF9BZSGKbiRKFJvCDSCgjF3gVCFkFYxc=";

	const ROUTE_PRINT:&str="\
===========================================================================
Interface List
 54...00 00 00 00 00 00 ......wg-wrapper
 12...a4 b1 c1 d2 e3 f4 ......Intel(R) Wi-Fi 6 AX201 160MHz
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.70.1   192.168.70.101     50
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     192.168.70.0    255.255.255.0         On-link    192.168.70.101    306
   192.168.70.101  255.255.255.255         On-link    192.168.70.101    306
   192.168.70.255  255.255.255.255         On-link    192.168.70.101    306
       10.244.0.0    255.255.255.0         On-link    192.168.70.101    306
        10.10.0.0    255.255.255.0         On-link      10.10.0.5      15
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.70.101    306
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.70.101    306
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      10.10.0.1  Default
===========================================================================
";

	#[test]
	fn route_print_yields_the_gateway_and_the_lan(){
		let (default, lan)=parse_routes(ROUTE_PRINT);
		assert_eq!(default, Some(("192.168.70.1".parse().unwrap(), "192.168.70.101".parse().unwrap())));
		assert_eq!(lan, vec![
			("192.168.70.0".parse::<Ipv4Addr>().unwrap(), "255.255.255.0".parse::<Ipv4Addr>().unwrap()),
			("10.244.0.0".parse().unwrap(), "255.255.255.0".parse().unwrap()),
		], "only the default interface's non-host, non-loopback, non-multicast on-link subnets count");
		assert_eq!(parse_routes("nothing here"), (None, Vec::new()));
	}

	#[test]
	fn the_lowest_metric_default_route_wins(){
		let two=ROUTE_PRINT.replace("Active Routes:\n", "Active Routes:\n          0.0.0.0          0.0.0.0        10.10.0.1         10.10.0.5     25\n");
		let (default, lan)=parse_routes(&two);
		assert_eq!(default, Some(("10.10.0.1".parse().unwrap(), "10.10.0.5".parse().unwrap())));
		assert_eq!(lan, vec![("10.10.0.0".parse::<Ipv4Addr>().unwrap(), "255.255.255.0".parse::<Ipv4Addr>().unwrap())]);
		let flipped=two.replace("     25\n", "     55\n");
		assert_eq!(parse_routes(&flipped).0, Some(("192.168.70.1".parse().unwrap(), "192.168.70.101".parse().unwrap())));
	}

	#[test]
	fn full_conf_parses(){
		let cfg=parse_conf(&format!("
			[Interface]  # our side
			PrivateKey = {PRIV}
			Address = 10.7.0.2/32, fd00::2/128
			DNS = 1.1.1.1, 9.9.9.9, corp.example
			MTU=1400

			[Peer]
			PublicKey={PUB}
			PresharedKey = {PRIV}
			allowedips = 0.0.0.0/0, ::/0
			Endpoint = vpn.example.com:51820
			PersistentKeepalive = 25
		")).unwrap();
		assert_eq!(cfg.address, "10.7.0.2/32".parse::<IpNet>().unwrap());
		assert_eq!(cfg.dns, vec!["1.1.1.1".parse::<IpAddr>().unwrap(), "9.9.9.9".parse().unwrap()]);
		assert_eq!(cfg.mtu, 1400);
		assert_eq!(cfg.keepalive, Some(25));
		assert_eq!(cfg.allowed_ips.len(), 2);
		assert_eq!(cfg.preshared_key.as_deref(), Some(PRIV));
		assert_eq!(cfg.endpoint, Endpoint::UdpHost("vpn.example.com:51820".into()));
	}

	#[test]
	fn endpoints_pick_their_transport(){
		let base=format!("[Interface]\nPrivateKey={PRIV}\nAddress=10.7.0.2\n[Peer]\nPublicKey={PUB}\n");
		let ws=parse_conf(&format!("{base}Endpoint = wss://vpn.example.com/tunnel\nInsecureTls = true\n")).unwrap();
		assert_eq!(ws.endpoint, Endpoint::Ws{url:"wss://vpn.example.com/tunnel".into(), insecure:true});
		assert_eq!(ws.mtu, 1380);
		assert_eq!(ws.address, "10.7.0.2/32".parse::<IpNet>().unwrap());
		let udp=parse_conf(&format!("{base}Endpoint = 203.0.113.9:51820\n")).unwrap();
		assert_eq!(udp.endpoint, Endpoint::Udp("203.0.113.9:51820".parse().unwrap()));
		assert_eq!((udp.mtu, udp.keepalive), (1420, None));
		assert!(udp.allowed_ips.is_empty() && udp.dns.is_empty());
		let upper=parse_conf(&format!("{base}Endpoint = WS://host:8080/x\n")).unwrap();
		assert_eq!(upper.endpoint, Endpoint::Ws{url:"WS://host:8080/x".into(), insecure:false});
	}

	#[test]
	fn missing_and_broken_keys_are_rejected(){
		let full=format!("[Interface]\nPrivateKey={PRIV}\nAddress=10.7.0.2/32\n[Peer]\nPublicKey={PUB}\nEndpoint=203.0.113.9:51820\n");
		parse_conf(&full).unwrap();
		for gone in ["PrivateKey", "Address", "PublicKey", "Endpoint"]{
			let trimmed=full.lines().filter(|l| !l.starts_with(gone)).collect::<Vec<_>>().join("\n");
			assert!(parse_conf(&trimmed).is_err(), "a conf without {gone} must not parse");
		}
		assert!(parse_conf(&full.replace(PRIV, "notakey")).is_err());
		assert!(parse_conf(&full.replace("203.0.113.9:51820", "vpn.example.com")).is_err());
		assert!(parse_conf(&format!("PrivateKey={PRIV}")).is_err(), "a key outside any section must not parse");
	}

	#[tokio::test]
	async fn endpoints_resolve_to_the_right_port(){
		let mut cfg=parse_conf(&format!("[Interface]\nPrivateKey={PRIV}\nAddress=10.7.0.2/32\n[Peer]\nPublicKey={PUB}\nEndpoint=203.0.113.9:51820\n")).unwrap();
		assert_eq!(resolve_endpoint(&cfg).await.unwrap(), "203.0.113.9:51820".parse().unwrap());
		cfg.endpoint=Endpoint::UdpHost("localhost:51820".into());
		assert_eq!(resolve_endpoint(&cfg).await.unwrap().port(), 51820);
		for (url, port) in [("wss://127.0.0.1/tunnel", 443), ("ws://127.0.0.1/tunnel", 80), ("wss://127.0.0.1:8443/a?b=c", 8443), ("wss://[::1]:9443/x", 9443)]{
			cfg.endpoint=Endpoint::Ws{url:url.into(), insecure:false};
			assert_eq!(resolve_endpoint(&cfg).await.unwrap().port(), port, "{url}");
		}
		cfg.endpoint=Endpoint::Ws{url:"http://127.0.0.1/x".into(), insecure:false};
		assert!(resolve_endpoint(&cfg).await.is_err());
	}
}
