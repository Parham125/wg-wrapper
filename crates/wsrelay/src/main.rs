use std::net::SocketAddr;
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use wsrelay::TlsFiles;

#[derive(Parser)]
#[command(name="wgw-bridge", version, about="WireGuard over WebSocket bridge")]
struct Cli{#[command(subcommand)] cmd:Cmd}

#[derive(Subcommand)]
enum Cmd{
	/// Local UDP endpoint for a WireGuard peer, tunnelled to a relay over ws/wss
	Client{
		#[arg(long, default_value="127.0.0.1:51820")] listen:SocketAddr,
		#[arg(long)] url:String,
		/// Skip TLS certificate verification, for self-signed testing only
		#[arg(long)] insecure:bool,
	},
	/// Server side: accept ws/wss on a path and forward datagrams to a local WireGuard endpoint
	Relay{
		#[arg(long, default_value="0.0.0.0:443")] listen:SocketAddr,
		#[arg(long, default_value="/wg")] path:String,
		#[arg(long, default_value="127.0.0.1:51820")] target:SocketAddr,
		/// PEM certificate chain; omit both cert and key to serve plain ws behind a reverse proxy
		#[arg(long, requires="key")] cert:Option<PathBuf>,
		#[arg(long, requires="cert")] key:Option<PathBuf>,
		/// Ceiling on concurrent relay connections
		#[arg(long, default_value_t=wsrelay::MAX_CONNS)] max_conns:usize,
	},
}

#[tokio::main]
async fn main()->anyhow::Result<()>{
	tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))).init();
	match Cli::parse().cmd{
		Cmd::Client{listen, url, insecure}=>wsrelay::run_client(listen, url, insecure).await,
		Cmd::Relay{listen, path, target, cert, key, max_conns}=>{
			let tls=match (cert, key){(Some(cert), Some(key))=>Some(TlsFiles{cert, key}), _=>None};
			wsrelay::serve_limited(tokio::net::TcpListener::bind(listen).await?, tls, path, target, max_conns).await
		}
	}
}
