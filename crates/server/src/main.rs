use clap::{Parser, Subcommand};
use server::config::Config;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name="wgw-server", about="Userspace WireGuard server egressing through a SOCKS5 proxy")]
struct Cli{
	#[arg(long, short, global=true, default_value="config.json")]
	config:PathBuf,
	#[command(subcommand)]
	command:Option<Command>,
}

#[derive(Subcommand)]
enum Command{
	/// Print a fresh private key and its public key
	Genkey,
}

#[tokio::main]
async fn main()->anyhow::Result<()>{
	let cli=Cli::parse();
	if let Some(Command::Genkey)=cli.command{
		let private=wgcore::generate_key();
		println!("private_key: {}", wgcore::encode_key(&private));
		println!("public_key:  {}", wgcore::encode_key(&wgcore::public_key(&private)));
		return Ok(());
	}
	tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
	server::start(Config::load(&cli.config)?).await?;
	tokio::signal::ctrl_c().await?;
	Ok(())
}
