#![cfg_attr(not(debug_assertions), windows_subsystem="windows")]
//! Tauri shell around the `wgclient` engine. The UI is static HTML in ../ui and talks to the commands below.
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::UpdaterExt;
use tracing::Level;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

static HANDLE:OnceLock<AppHandle>=OnceLock::new();
static START:OnceLock<Instant>=OnceLock::new();
static LOGS:OnceLock<Mutex<VecDeque<String>>>=OnceLock::new();
const LOG_KEEP:usize=200;

fn logbuf()->&'static Mutex<VecDeque<String>>{LOGS.get_or_init(|| Mutex::new(VecDeque::new()))}

/// Appends to the ring buffer and pushes the same line to the webview as a `log` event.
fn push_log(line:String){
	let mut buf=logbuf().lock().unwrap();
	while buf.len()>=LOG_KEEP{buf.pop_front();}
	buf.push_back(line.clone());
	drop(buf);
	if let Some(h)=HANDLE.get(){let _=h.emit("log", line);}
}

struct LogLayer;
struct Message(String);

impl tracing::field::Visit for Message{
	fn record_debug(&mut self, field:&tracing::field::Field, value:&dyn std::fmt::Debug){
		if field.name()=="message"{self.0=format!("{value:?}")}else{self.0.push_str(&format!(" {}={:?}", field.name(), value))}
	}
	fn record_str(&mut self, field:&tracing::field::Field, value:&str){
		if field.name()=="message"{self.0=value.to_string()}else{self.0.push_str(&format!(" {}={}", field.name(), value))}
	}
}

impl<S:tracing::Subscriber> Layer<S> for LogLayer{
	fn on_event(&self, event:&tracing::Event<'_>, _:Context<'_, S>){
		let meta=event.metadata();
		if meta.level()>&Level::DEBUG{return}
		let mut msg=Message(String::new());
		event.record(&mut msg);
		let secs=START.get().map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
		push_log(format!("{secs:7.2}  {:<5}  {}  {}", meta.level(), meta.target(), msg.0));
	}
}

#[derive(Default)]
struct Session{
	state:String,
	error:Option<String>,
	endpoint:Option<String>,
	tunnel:Option<wgclient::Tunnel>,
	#[cfg(windows)]
	adapter:Option<wgclient::win::Adapter>,
}

struct Shared{session:tokio::sync::Mutex<Session>}

#[derive(Serialize)]
struct StatsOut{rx_bytes:u64, tx_bytes:u64, last_handshake_secs_ago:Option<u64>, connected_secs:u64}

#[derive(Serialize)]
struct StatusOut{state:String, error:Option<String>, stats:Option<StatsOut>, endpoint:Option<String>}

#[derive(Serialize, Deserialize)]
struct Profile{name:String, conf:String}

#[derive(Serialize)]
struct UpdateInfo{available:bool, version:String, notes:String, current:String}

#[derive(Serialize, Deserialize)]
struct Settings{auto_update:bool}

impl Default for Settings{fn default()->Self{Settings{auto_update:true}}}

#[cfg(windows)]
type Dialed=(wgclient::Tunnel, String, wgclient::win::Adapter);
#[cfg(not(windows))]
type Dialed=(wgclient::Tunnel, String);

/// Everything that can fail while bringing the tunnel up, so `connect` only has to record the outcome.
#[cfg(windows)]
async fn dial(app:&AppHandle, conf:&str)->Result<Dialed, String>{
	let cfg=wgclient::parse_conf(conf).map_err(|e| format!("config: {e}"))?;
	let label=match &cfg.endpoint{wgclient::Endpoint::Udp(a)=>a.to_string(), wgclient::Endpoint::UdpHost(h)=>h.clone(), wgclient::Endpoint::Ws{url, ..}=>url.clone()};
	tracing::info!("resolving {label}");
	let server=wgclient::resolve_endpoint(&cfg).await.map_err(|e| format!("resolve: {e}"))?;
	let dll=app.path().resolve("resources/wintun.dll", tauri::path::BaseDirectory::Resource).map_err(|e| format!("wintun.dll: {e}"))?;
	tracing::info!("opening adapter via {}", dll.display());
	let (adapter, tun)=wgclient::win::open(&cfg, server.ip(), &dll).map_err(|e| format!("adapter: {e}"))?;
	let tunnel=wgclient::Tunnel::connect_to(cfg, tun, server).await.map_err(|e| format!("handshake: {e}"))?;
	Ok((tunnel, label, adapter))
}

#[cfg(not(windows))]
async fn dial(_app:&AppHandle, _conf:&str)->Result<Dialed, String>{Err("Windows only".to_string())}

#[tauri::command]
async fn connect(app:AppHandle, shared:State<'_, Shared>, conf:String)->Result<(), String>{
	{
		let mut s=shared.session.lock().await;
		if s.tunnel.is_some(){return Err("Already connected".to_string())}
		s.state="connecting".to_string();
		s.error=None;
		s.endpoint=None;
	}
	tracing::info!("connect requested");
	match dial(&app, &conf).await{
		Ok(dialed)=>{
			let mut s=shared.session.lock().await;
			s.state="connected".to_string();
			s.endpoint=Some(dialed.1);
			s.tunnel=Some(dialed.0);
			#[cfg(windows)]
			{s.adapter=Some(dialed.2);}
			tracing::info!("tunnel up");
			Ok(())
		}
		Err(e)=>{
			let mut s=shared.session.lock().await;
			s.state="error".to_string();
			s.error=Some(e.clone());
			tracing::error!("connect failed: {e}");
			Err(e)
		}
	}
}

#[tauri::command]
async fn disconnect(shared:State<'_, Shared>)->Result<(), String>{
	let mut s=shared.session.lock().await;
	if let Some(t)=s.tunnel.take(){t.close().await;}
	#[cfg(windows)]
	{s.adapter=None;} // dropping the adapter restores routes and dns
	s.state="disconnected".to_string();
	s.endpoint=None;
	s.error=None;
	tracing::info!("tunnel down");
	Ok(())
}

#[tauri::command]
async fn status(shared:State<'_, Shared>)->Result<StatusOut, String>{
	let s=shared.session.lock().await;
	let stats=s.tunnel.as_ref().map(|t|{
		let st=t.stats();
		StatsOut{
			rx_bytes:st.rx_bytes,
			tx_bytes:st.tx_bytes,
			last_handshake_secs_ago:st.last_handshake.and_then(|h| h.elapsed().ok()).map(|d| d.as_secs()),
			connected_secs:st.connected_since.elapsed().map(|d| d.as_secs()).unwrap_or(0),
		}
	});
	Ok(StatusOut{state:s.state.clone(), error:s.error.clone(), stats, endpoint:s.endpoint.clone()})
}

#[tauri::command]
fn log_history()->Vec<String>{logbuf().lock().unwrap().iter().cloned().collect()}

fn profiles_dir(app:&AppHandle)->Result<PathBuf, String>{
	let dir=app.path().app_config_dir().map_err(|e| e.to_string())?.join("profiles");
	std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
	Ok(dir)
}

/// Profile names are free text, so the file name is a flattened form of it and the real name lives inside.
fn slug(name:&str)->String{
	let s:String=name.chars().map(|c| if c.is_ascii_alphanumeric(){c.to_ascii_lowercase()}else{'-'}).collect();
	let s=s.trim_matches('-').to_string();
	if s.is_empty(){"profile".to_string()}else{s}
}

#[tauri::command]
fn list_profiles(app:AppHandle)->Result<Vec<Profile>, String>{
	let mut out=Vec::new();
	for entry in std::fs::read_dir(profiles_dir(&app)?).map_err(|e| e.to_string())?.flatten(){
		if entry.path().extension().and_then(|e| e.to_str())!=Some("json"){continue}
		let text=match std::fs::read_to_string(entry.path()){Ok(t)=>t, Err(_)=>continue};
		if let Ok(p)=serde_json::from_str::<Profile>(&text){out.push(p)}
	}
	out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
	Ok(out)
}

#[tauri::command]
fn save_profile(app:AppHandle, name:String, conf:String)->Result<(), String>{
	let name=name.trim().to_string();
	if name.is_empty(){return Err("Name the profile before saving it".to_string())}
	if conf.trim().is_empty(){return Err("Paste a WireGuard config before saving".to_string())}
	let path=profiles_dir(&app)?.join(format!("{}.json", slug(&name)));
	let body=serde_json::to_string_pretty(&Profile{name:name.clone(), conf}).map_err(|e| e.to_string())?;
	std::fs::write(&path, body).map_err(|e| e.to_string())?;
	tracing::info!("saved profile {name}");
	Ok(())
}

#[tauri::command]
fn delete_profile(app:AppHandle, name:String)->Result<(), String>{
	let path=profiles_dir(&app)?.join(format!("{}.json", slug(&name)));
	if path.exists(){std::fs::remove_file(&path).map_err(|e| e.to_string())?;}
	tracing::info!("removed profile {name}");
	Ok(())
}

#[tauri::command]
async fn check_update(app:AppHandle)->Result<UpdateInfo, String>{
	let current=app.package_info().version.to_string();
	let found=app.updater().map_err(|e| format!("updater unavailable: {e}"))?.check().await.map_err(|e| format!("update check failed: {e}"))?;
	match found{
		Some(u)=>{tracing::info!("update {} available", u.version); Ok(UpdateInfo{available:true, version:u.version.clone(), notes:u.body.clone().unwrap_or_default(), current})}
		None=>Ok(UpdateInfo{available:false, version:current.clone(), notes:String::new(), current}),
	}
}

#[tauri::command]
async fn install_update(app:AppHandle, shared:State<'_, Shared>)->Result<(), String>{
	let update=app.updater().map_err(|e| format!("updater unavailable: {e}"))?.check().await.map_err(|e| format!("update check failed: {e}"))?.ok_or_else(|| "Already up to date".to_string())?;
	let up=shared.session.lock().await.tunnel.is_some();
	if up{disconnect(shared).await?;} // installer restarts the app, so drop the adapter first to restore routes and dns
	tracing::info!("installing update {}", update.version);
	let handle=app.clone();
	let mut downloaded=0usize;
	update.download_and_install(move |chunk, total|{
		downloaded+=chunk;
		let _=handle.emit("update-progress", serde_json::json!({"downloaded":downloaded, "total":total}));
	}, ||{}).await.map_err(|e| format!("update failed: {e}"))?;
	tracing::info!("update installed, restarting");
	app.restart()
}

fn settings_path(app:&AppHandle)->Result<PathBuf, String>{
	let dir=app.path().app_config_dir().map_err(|e| e.to_string())?;
	std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
	Ok(dir.join("settings.json"))
}

#[tauri::command]
async fn get_settings(app:AppHandle)->Result<Settings, String>{
	let path=settings_path(&app)?;
	Ok(std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default())
}

#[tauri::command]
async fn set_settings(app:AppHandle, settings:Settings)->Result<(), String>{
	let body=serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
	std::fs::write(settings_path(&app)?, body).map_err(|e| e.to_string())
}

fn main(){
	let _=START.set(Instant::now());
	tracing_subscriber::registry().with(LogLayer).init();
	tauri::Builder::default()
		.plugin(tauri_plugin_process::init())
		.manage(Shared{session:tokio::sync::Mutex::new(Session{state:"disconnected".to_string(), ..Default::default()})})
		.invoke_handler(tauri::generate_handler![connect, disconnect, status, log_history, list_profiles, save_profile, delete_profile, check_update, install_update, get_settings, set_settings])
		.setup(|app|{
			let _=HANDLE.set(app.handle().clone());
			// Shrinks the default 640px height onto short laptop screens; the work area already excludes the taskbar. Any failure keeps the default.
			if let Some(w)=app.get_webview_window("main"){
				if let (Ok(Some(m)), Ok(outer), Ok(inner))=(w.current_monitor(), w.outer_size(), w.inner_size()){
					let fit=m.work_area().size.height.saturating_sub(outer.height-inner.height).max((420.0*m.scale_factor()) as u32);
					if outer.height>m.work_area().size.height&&fit<inner.height{let _=w.set_size(tauri::PhysicalSize::new(inner.width, fit)); let _=w.center();}
				}
			}
			#[cfg(desktop)]
			app.handle().plugin(tauri_plugin_updater::Builder::new().build())?;
			tracing::info!("client ready");
			Ok(())
		})
		.run(tauri::generate_context!())
		.expect("failed to start the tauri application");
}
