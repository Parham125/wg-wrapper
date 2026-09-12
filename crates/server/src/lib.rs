//! Userspace WireGuard server: terminates peers and egresses only through an upstream SOCKS5 proxy.
pub mod config;
pub mod flow;
pub mod net;

use crate::config::{parse_upstream, Config, Upstream};
use crate::net::{allowed_dst, peer_for, tcp_rst, PacketDev};
use ipnet::IpNet;
use ipstack::{IpStack, IpStackConfig, IpStackStream};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use wgcore::{dst_address, src_address, Wg, MAX_PACKET};

/// Concurrent proxied flows, in total and per peer, so one peer cannot exhaust the process.
const MAX_FLOWS:usize=4096;
const MAX_FLOWS_PER_PEER:usize=512;
/// Packets in flight between the tunnel and the stack in either direction.
const QUEUE:usize=4096;

pub struct Running{
	pub udp_addr:SocketAddr,
	pub ws_addr:Option<SocketAddr>,
}

/// Frees a flow's global permit and its peer's slot once the task ends, however it ends.
struct FlowGuard{counts:Arc<Vec<AtomicUsize>>, idx:usize, _permit:OwnedSemaphorePermit}

impl Drop for FlowGuard{
	fn drop(&mut self){self.counts[self.idx].fetch_sub(1, Ordering::SeqCst);}
}

/// Brings up every listener and task and returns once they are bound. Tasks run until the process exits.
pub async fn start(cfg:Config)->anyhow::Result<Running>{
	let global=parse_upstream(&cfg.upstream)?;
	let wg_net=cfg.address;
	let allow_private=cfg.allow_private;
	let mtu=cfg.mtu();
	let mut wg=Wg::new(wgcore::decode_key(&cfg.private_key)?);
	let mut allowed:Vec<(IpNet, usize)>=Vec::new();
	let mut upstreams:Vec<Upstream>=Vec::new();
	for p in &cfg.peers{
		let psk=p.preshared_key.as_deref().map(wgcore::decode_key).transpose()?;
		let idx=wg.add_peer(wgcore::decode_key(&p.public_key)?, psk, None)?;
		for n in &p.allowed_ips{allowed.push((*n, idx))}
		upstreams.push(p.upstream.as_deref().map(parse_upstream).transpose()?.unwrap_or_else(|| global.clone()));
	}
	tracing::info!("server public key {}", wgcore::encode_key(&wg.public_key()));
	let sock=Arc::new(UdpSocket::bind(cfg.listen_udp.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))).await?);
	let udp_addr=sock.local_addr()?;
	let wg=Arc::new(Mutex::new(wg));
	let allowed:Arc<Vec<(IpNet, usize)>>=Arc::new(allowed);
	let (to_stack, from_wg)=mpsc::channel::<Vec<u8>>(QUEUE);
	let (to_wg, mut from_stack)=mpsc::channel::<Vec<u8>>(QUEUE);
	let flows=Arc::new(Semaphore::new(MAX_FLOWS));
	let counts:Arc<Vec<AtomicUsize>>=Arc::new(cfg.peers.iter().map(|_| AtomicUsize::new(0)).collect());
	let mut stack_cfg=IpStackConfig::default();
	stack_cfg.mtu_unchecked(mtu).packet_information(false);
	let mut stack=IpStack::new(stack_cfg, PacketDev::new(from_wg, to_wg));
	// Peer -> stack: decrypt, enforce cryptokey routing and isolation, then hand the IP packet up.
	tokio::spawn({
		let (wg, sock, allowed)=(wg.clone(), sock.clone(), allowed.clone());
		async move{
			let mut buf=vec![0u8;MAX_PACKET];
			let (mut net_out, mut ip_out)=(Vec::new(), Vec::new());
			loop{
				let Ok((n, from))=sock.recv_from(&mut buf).await else{continue};
				net_out.clear();
				ip_out.clear();
				let idx=wg.lock().unwrap_or_else(|e| e.into_inner()).recv_from_network(from, &buf[..n], &mut net_out, &mut ip_out);
				for d in &net_out{let _=sock.send_to(d, from).await;}
				let Some(idx)=idx else{continue};
				for packet in &ip_out{
					let (Some(src), Some(dst))=(src_address(packet), dst_address(packet)) else{continue};
					if peer_for(&allowed, src)!=Some(idx){
						tracing::debug!("peer {idx} sent spoofed source {src}, dropping");
						continue;
					}
					if !allowed_dst(&wg_net, dst, allow_private){
						tracing::debug!("peer {idx} aimed at forbidden {dst}, refusing");
						if let Some(rst)=tcp_rst(packet){
							net_out.clear();
							wg.lock().unwrap_or_else(|e| e.into_inner()).encapsulate(idx, &rst, &mut net_out);
							for d in &net_out{let _=sock.send_to(d, from).await;}
						}
						continue;
					}
					if to_stack.try_send(packet.clone()).is_err(){tracing::debug!("stack queue full, dropping a packet from peer {idx}")}
				}
			}
		}
	});
	// Stack -> peer: route the reply by destination address and encrypt it for that peer.
	tokio::spawn({
		let (wg, sock, allowed)=(wg.clone(), sock.clone(), allowed.clone());
		async move{
			let mut net_out=Vec::new();
			while let Some(packet)=from_stack.recv().await{
				let Some(dst)=dst_address(&packet) else{continue};
				let Some(idx)=peer_for(&allowed, dst) else{continue};
				net_out.clear();
				let endpoint={
					let mut wg=wg.lock().unwrap_or_else(|e| e.into_inner());
					wg.encapsulate(idx, &packet, &mut net_out);
					wg.endpoint(idx)
				};
				let Some(endpoint)=endpoint else{continue};
				for d in &net_out{let _=sock.send_to(d, endpoint).await;}
			}
		}
	});
	tokio::spawn({
		let (wg, sock)=(wg.clone(), sock.clone());
		async move{
			let mut tick=tokio::time::interval(Duration::from_millis(250));
			let mut out=Vec::new();
			loop{
				tick.tick().await;
				out.clear();
				let targets:Vec<Option<SocketAddr>>={
					let mut wg=wg.lock().unwrap_or_else(|e| e.into_inner());
					wg.update_timers(&mut out);
					out.iter().map(|(i, _)| wg.endpoint(*i)).collect()
				};
				for ((_, d), endpoint) in out.iter().zip(targets){
					if let Some(endpoint)=endpoint{let _=sock.send_to(d, endpoint).await;}
				}
			}
		}
	});
	// Accepted flows: pick the upstream from the source address, then egress through SOCKS5.
	tokio::spawn({
		let (allowed, flows, counts)=(allowed.clone(), flows.clone(), counts.clone());
		let dns=cfg.dns;
		async move{
			loop{
				let stream=match stack.accept().await{
					Ok(s)=>s,
					Err(e)=>{tracing::error!("ipstack accept: {e}"); return}
				};
				let (src, dst)=(stream.local_addr(), stream.peer_addr());
				if !allowed_dst(&wg_net, dst.ip(), allow_private){tracing::debug!("refusing flow to {dst}"); continue}
				let Some(idx)=peer_for(&allowed, src.ip()) else{tracing::debug!("no peer owns source {src}, dropping"); continue};
				let Ok(permit)=flows.clone().try_acquire_owned() else{tracing::debug!("flow table full, dropping {src} -> {dst}"); continue};
				if counts[idx].fetch_add(1, Ordering::SeqCst)>=MAX_FLOWS_PER_PEER{
					counts[idx].fetch_sub(1, Ordering::SeqCst);
					tracing::debug!("peer {idx} is at its flow cap, dropping {src} -> {dst}");
					continue;
				}
				let (guard, up)=(FlowGuard{counts:counts.clone(), idx, _permit:permit}, upstreams[idx].clone());
				match stream{
					IpStackStream::Tcp(s)=>{tokio::spawn(async move{let _guard=guard; flow::handle_tcp(s, up).await});}
					IpStackStream::Udp(s)=>{tokio::spawn(async move{let _guard=guard; flow::handle_udp(s, up, dns, mtu).await});}
					_=>tracing::debug!("ignoring non tcp/udp flow from {src}"),
				}
			}
		}
	});
	let mut ws_addr=None;
	if let Some(ws)=&cfg.listen_ws{
		// The relay always talks to the WG socket over loopback, even when we bound a wildcard address.
		let target=if udp_addr.ip().is_unspecified(){SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), udp_addr.port())}else{udp_addr};
		let listener=TcpListener::bind(ws.addr).await?;
		ws_addr=Some(listener.local_addr()?);
		let tls=match (&ws.cert, &ws.key){
			(Some(cert), Some(key))=>Some(wsrelay::TlsFiles{cert:cert.clone(), key:key.clone()}),
			_=>None,
		};
		let path=ws.path.clone();
		tokio::spawn(async move{
			if let Err(e)=wsrelay::serve(listener, tls, path, target).await{tracing::error!("wsrelay: {e}")}
		});
	}
	tracing::info!("wireguard on {udp_addr}, {} peer(s), egress via {}", cfg.peers.len(), global.addr);
	Ok(Running{udp_addr, ws_addr})
}
