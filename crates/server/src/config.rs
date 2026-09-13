use crate::net::allowed_dst;
use anyhow::{anyhow, bail, Context};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Clone, Debug)]
pub struct WsListen{
	pub addr:SocketAddr,
	pub path:String,
	#[serde(default)] pub cert:Option<PathBuf>,
	#[serde(default)] pub key:Option<PathBuf>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct PeerConfig{
	pub public_key:String,
	#[serde(default)] pub preshared_key:Option<String>,
	pub allowed_ips:Vec<IpNet>,
	#[serde(default)] pub upstream:Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct Config{
	pub private_key:String,
	pub address:IpNet,
	#[serde(default)] pub mtu:Option<u16>,
	#[serde(default)] pub listen_udp:Option<SocketAddr>,
	#[serde(default)] pub listen_ws:Option<WsListen>,
	pub upstream:String,
	#[serde(default)] pub dns:Option<SocketAddr>,
	/// Opt back in to private, shared and reserved destination ranges. Off means public internet only.
	#[serde(default)] pub allow_private:bool,
	/// How long a relayed UDP flow may sit with no traffic in either direction before it is torn down.
	#[serde(default)] pub udp_idle_secs:Option<u64>,
	/// How long a relayed TCP flow may sit with no traffic in either direction before it is reset.
	#[serde(default)] pub tcp_idle_secs:Option<u64>,
	pub peers:Vec<PeerConfig>,
}

/// A parsed `socks5://[user:pass@]host:port` upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream{pub addr:String, pub auth:Option<(String, String)>}

/// Percent-decoding for the credential halves, so a password may carry `@`, `:` or `/` as %40, %3A, %2F.
fn percent_decode(s:&str)->String{
	let (raw, mut out)=(s.as_bytes(), Vec::with_capacity(s.len()));
	let mut i=0;
	while i<raw.len(){
		match u8::from_str_radix(s.get(i+1..i+3).unwrap_or(""), 16){
			Ok(b) if raw[i]==b'%'=>{out.push(b); i+=3}
			_=>{out.push(raw[i]); i+=1}
		}
	}
	String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_upstream(s:&str)->anyhow::Result<Upstream>{
	let rest=s.strip_prefix("socks5://").ok_or_else(|| anyhow!("upstream {s:?} must start with socks5://"))?;
	let (auth, hostport)=match rest.rsplit_once('@'){
		Some((a, h))=>{
			let (u, p)=a.split_once(':').ok_or_else(|| anyhow!("upstream {s:?} credentials must be user:pass"))?;
			(Some((percent_decode(u), percent_decode(p))), h)
		}
		None=>(None, rest),
	};
	let (host, port)=hostport.rsplit_once(':').ok_or_else(|| anyhow!("upstream {s:?} must end in host:port"))?;
	if host.is_empty()|| port.parse::<u16>().is_err(){bail!("upstream {s:?} must end in host:port")}
	Ok(Upstream{addr:hostport.to_string(), auth})
}

impl Config{
	pub fn load(path:&Path)->anyhow::Result<Config>{
		let text=std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
		let cfg:Config=serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
		cfg.validate()?;
		Ok(cfg)
	}

	pub fn mtu(&self)->u16{self.mtu.unwrap_or(1420)}

	pub fn udp_idle(&self)->std::time::Duration{std::time::Duration::from_secs(self.udp_idle_secs.unwrap_or(60))}

	/// Long by default: keep-alive connections from games and browsers go quiet for a long time and
	/// must survive it, unlike ipstack's own 60 second default.
	pub fn tcp_idle(&self)->std::time::Duration{std::time::Duration::from_secs(self.tcp_idle_secs.unwrap_or(7200))}

	pub fn validate(&self)->anyhow::Result<()>{
		if self.listen_udp.is_none() && self.listen_ws.is_none(){bail!("set at least one of listen_udp or listen_ws")}
		wgcore::decode_key(&self.private_key).context("private_key")?;
		parse_upstream(&self.upstream)?;
		if let Some(ws)=&self.listen_ws{
			if ws.cert.is_some()!=ws.key.is_some(){bail!("listen_ws needs both cert and key, or neither")}
			if !ws.path.starts_with('/'){bail!("listen_ws.path must start with /")}
		}
		if let Some(dns)=self.dns{
			if !allowed_dst(&self.address, dns.ip(), self.allow_private){bail!("dns {dns} is in a range the isolation rules refuse")}
		}
		if self.peers.is_empty(){bail!("no peers configured")}
		let mut seen:Vec<IpNet>=Vec::new();
		for p in &self.peers{
			wgcore::decode_key(&p.public_key).with_context(|| format!("peer {} public_key", p.public_key))?;
			if let Some(psk)=&p.preshared_key{wgcore::decode_key(psk).context("preshared_key")?;}
			if let Some(u)=&p.upstream{parse_upstream(u)?;}
			if p.allowed_ips.is_empty(){bail!("peer {} has no allowed_ips", p.public_key)}
			for net in &p.allowed_ips{
				if !self.address.contains(net){bail!("allowed_ip {net} is outside address {}", self.address)}
				if let Some(other)=seen.iter().find(|o| o.contains(&net.addr())|| net.contains(&o.addr())){
					bail!("allowed_ip {net} overlaps {other}")
				}
				seen.push(*net);
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn upstreams_parse(){
		assert_eq!(parse_upstream("socks5://host:1080").unwrap(), Upstream{addr:"host:1080".into(), auth:None});
		let with_auth=parse_upstream("socks5://u:p@1.2.3.4:1080").unwrap();
		assert_eq!(with_auth.addr, "1.2.3.4:1080");
		assert_eq!(with_auth.auth, Some(("u".into(), "p".into())));
		let encoded=parse_upstream("socks5://a%40b:p%3Aa%2Fss%25@1.2.3.4:1080").unwrap();
		assert_eq!(encoded.auth, Some(("a@b".into(), "p:a/ss%".into())));
		for bad in ["http://host:1080", "socks5://host", "socks5://u@host:1080", "socks5://:1080", "socks5://host:abc"]{
			assert!(parse_upstream(bad).is_err(), "{bad} should not parse");
		}
	}

	fn cfg(peers:&str)->String{
		format!(r#"{{"private_key":"{}","address":"10.7.0.1/24","listen_udp":"0.0.0.0:51820","upstream":"socks5://h:1080","peers":[{peers}]}}"#, wgcore::encode_key(&wgcore::generate_key()))
	}

	#[test]
	fn rejects_bad_peer_subnets(){
		let key=wgcore::encode_key(&wgcore::public_key(&wgcore::generate_key()));
		let ok=cfg(&format!(r#"{{"public_key":"{key}","allowed_ips":["10.7.0.2/32"]}}"#));
		serde_json::from_str::<Config>(&ok).unwrap().validate().unwrap();
		let outside=cfg(&format!(r#"{{"public_key":"{key}","allowed_ips":["10.8.0.2/32"]}}"#));
		assert!(serde_json::from_str::<Config>(&outside).unwrap().validate().is_err());
		let overlap=cfg(&format!(r#"{{"public_key":"{key}","allowed_ips":["10.7.0.0/25","10.7.0.2/32"]}}"#));
		assert!(serde_json::from_str::<Config>(&overlap).unwrap().validate().is_err());
	}

	#[test]
	fn dns_must_survive_the_isolation_rules(){
		let key=wgcore::encode_key(&wgcore::public_key(&wgcore::generate_key()));
		let peer=format!(r#"{{"public_key":"{key}","allowed_ips":["10.7.0.2/32"]}}"#);
		for (dns, ok) in [("1.1.1.1:53", true), ("127.0.0.1:53", false), ("10.7.0.1:53", false), ("192.168.1.1:53", false)]{
			let json=cfg(&peer).replace(r#""upstream""#, &format!(r#""dns":"{dns}","upstream""#));
			assert_eq!(serde_json::from_str::<Config>(&json).unwrap().validate().is_ok(), ok, "dns {dns}");
		}
	}

	#[test]
	fn shipped_example_validates(){
		Config::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.json")).unwrap();
	}
}
