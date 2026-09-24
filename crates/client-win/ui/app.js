"use strict";
const TICKS=60, WORDS={disconnected:"Disconnected", connecting:"Connecting", connected:"Connected", error:"Failed"};
const el=id=>document.getElementById(id);
const api=()=>window.__TAURI__;
const invoke=(cmd, args)=>api().core.invoke(cmd, args);
const hist=Array.from({length:TICKS}, ()=>({rate:0, hs:false}));
const tickEls=[];
let profiles=[], current=null, timer=null, prev=null, busy=false, last={state:"disconnected"};
let release=null, upError=null, checking=false, installing=false, checked=false, dismissed=false;

function fmtBytes(n){
	if(n<1024){return n+" B"}
	const u=["KB", "MB", "GB", "TB"];
	let v=n/1024, i=0;
	while(v>=1024&&i<u.length-1){v/=1024; i++}
	return (v>=100?v.toFixed(0):v.toFixed(1))+" "+u[i];
}
function fmtDur(s){
	const h=Math.floor(s/3600), m=Math.floor(s%3600/60), x=Math.floor(s%60), p=n=>String(n).padStart(2, "0");
	return h?`${h}:${p(m)}:${p(x)}`:`${m}:${p(x)}`;
}
function fmtAgo(s){
	if(s===null||s===undefined){return "none yet"}
	return s<60?`${s}s ago`:`${Math.floor(s/60)}m ${String(s%60).padStart(2, "0")}s ago`;
}
// Splits "17.2 MB" so the figure can sit large and the unit small beside it.
function setAmount(numId, unitId, n){
	const s=fmtBytes(n), i=s.indexOf(" ");
	el(numId).textContent=s.slice(0, i);
	el(unitId).textContent=s.slice(i+1);
}
function endpointOf(conf){
	const m=/^[ \t]*Endpoint[ \t]*=[ \t]*(.+?)[ \t]*$/mi.exec(conf||"");
	return m?m[1]:"no endpoint in config";
}
// The engine only knows it cannot run here; say what that means for the person looking at the window.
function explain(e){
	const s=String(e);
	return s==="Windows only"?"Tunnels only open on Windows. This build runs the interface so the layout can be checked elsewhere.":s;
}

function drawTicks(live){
	const max=Math.max(1, ...hist.map(h=>h.rate));
	let top=0;
	for(let i=0; i<TICKS; i++){
		const h=hist[i], t=tickEls[i], pc=h.rate>0?Math.max(2, Math.pow(h.rate/max, 0.55)*100):0;
		t.style.height=pc+"%";
		t.classList.toggle("on", live&&h.rate>0);
		t.classList.toggle("hs", h.hs);
		if(pc>top){top=pc}
	}
	const marker=el("peak"), show=live&&max>1;
	marker.hidden=!show;
	if(show){
		marker.style.bottom=top+"%";
		el("peakLabel").textContent="peak "+fmtBytes(max)+"/s";
	}
}
function pushSample(rate, hs){
	hist.shift();
	hist.push({rate, hs});
}
function resetPulse(){
	for(let i=0; i<TICKS; i++){hist[i]={rate:0, hs:false}}
	prev=null;
}

function paint(s){
	last=s;
	const st=s.state||"disconnected", live=st==="connected";
	el("statusline").dataset.state=st;
	el("stateWord").textContent=WORDS[st]||"Disconnected";
	const sub=el("stateSub"), empty=profiles.length===0;
	el("stage").dataset.empty=empty?"1":"0";
	el("stage").dataset.state=st;
	document.body.dataset.state=st;
	document.body.dataset.empty=empty?"1":"0";
	sub.className="state-sub";
	if(empty){
		el("stateWord").textContent="No profiles yet";
		sub.className="state-sub lead";
		sub.textContent="Add the WireGuard config your relay gave you. It needs an Endpoint line like this one:";
	}else if(st==="connected"){sub.textContent=s.endpoint||"connected"}
	else if(st==="connecting"){sub.textContent="reaching "+(current?endpointOf(current.conf):"the relay")}
	else{sub.textContent=current?endpointOf(current.conf):"Choose a profile to begin"}
	const stats=s.stats;
	setAmount("rx", "rxUnit", stats?stats.rx_bytes:0);
	setAmount("tx", "txUnit", stats?stats.tx_bytes:0);
	el("hs").textContent=stats?fmtAgo(stats.last_handshake_secs_ago):"none yet";
	el("uptime").textContent=fmtDur(stats?stats.connected_secs:0);
	const peak=Math.max(0, ...hist.map(h=>h.rate)), shook=hist.some(h=>h.hs);
	el("caption").textContent=empty?"":live?(peak>0?(shook?"Traffic, last 60 seconds. Notches mark handshakes.":"Traffic, last 60 seconds"):"Tunnel is up, nothing moving yet"):st==="connecting"?"Waiting for the first handshake":"Traffic shows here once the tunnel is up";
	drawTicks(live);
	const btn=el("action");
	btn.textContent=empty?"Add profile":live?"Disconnect":st==="connecting"?"Connecting":"Connect";
	btn.dataset.mode=empty?"add":live?"disconnect":"connect";
	btn.disabled=!empty&&(busy||st==="connecting"||(!live&&!current));
	const notice=el("notice");
	if(st==="error"&&s.error){notice.textContent=explain(s.error); notice.hidden=false}
	else{notice.hidden=true}
}

async function poll(){
	try{paint(await invoke("status"))}
	catch(e){console.error(e)}
}
function tick(){
	invoke("status").then(s=>{
		if(s.state==="connected"&&s.stats){
			const total=s.stats.rx_bytes+s.stats.tx_bytes, ago=s.stats.last_handshake_secs_ago;
			const fresh=ago!==null&&ago!==undefined&&(prev===null||prev.ago===null||prev.ago===undefined||ago<prev.ago);
			pushSample(prev===null?0:Math.max(0, total-prev.total), fresh);
			prev={total, ago};
		}
		paint(s);
	}).catch(e=>console.error(e));
}
function watch(on){
	if(timer){clearInterval(timer); timer=null}
	if(on){timer=setInterval(tick, 1000)}
}

async function onAction(){
	if(busy){return}
	if(el("action").dataset.mode==="add"){openPanel(el("sheet")); openPanel(el("addForm")); el("addName").focus(); return}
	busy=true;
	paint(last);
	try{
		if(last.state==="connected"){
			await invoke("disconnect");
			watch(false);
			resetPulse();
		}else{
			if(!current){return}
			resetPulse();
			watch(true);
			paint({state:"connecting"});
			await invoke("connect", {conf:current.conf});
		}
	}catch(e){
		el("notice").textContent=explain(e);
		el("notice").hidden=false;
		watch(false);
	}finally{
		busy=false;
		await poll();
	}
}

function renderProfiles(){
	const list=el("plist");
	list.textContent="";
	el("plistEmpty").hidden=profiles.length>0;
	for(const p of profiles){
		const li=document.createElement("li");
		li.className="pitem";
		if(current&&current.name===p.name){li.dataset.current="1"}
		const main=document.createElement("button");
		main.type="button";
		main.className="pitem-main";
		main.innerHTML=`<span class="pitem-name"></span><span class="pitem-ep"></span>`;
		main.querySelector(".pitem-name").textContent=p.name;
		main.querySelector(".pitem-ep").textContent=endpointOf(p.conf);
		main.onclick=()=>{select(p); closeSheet()};
		const act=document.createElement("button");
		act.type="button";
		act.className="pitem-act";
		act.textContent="Remove";
		act.onclick=async ()=>{
			if(act.dataset.armed!=="1"){act.dataset.armed="1"; act.textContent="Confirm"; act.classList.add("confirm"); return}
			await invoke("delete_profile", {name:p.name});
			if(current&&current.name===p.name){select(null)}
			await loadProfiles();
		};
		li.append(main, act);
		list.append(li);
	}
}
function select(p){
	current=p;
	el("profileName").textContent=p?p.name:"No profile";
	try{p?localStorage.setItem("profile", p.name):localStorage.removeItem("profile")}catch(e){}
	paint(last);
}
async function loadProfiles(){
	profiles=await invoke("list_profiles");
	let want=null;
	try{want=localStorage.getItem("profile")}catch(e){}
	const found=profiles.find(p=>p.name===(current?current.name:want));
	select(found||profiles[0]||null);
	renderProfiles();
}

function openPanel(node){
	node.hidden=false;
	requestAnimationFrame(()=>{node.dataset.open="1"});
}
function closePanel(node){
	node.dataset.open="0";
	setTimeout(()=>{if(node.dataset.open!=="1"){node.hidden=true}}, 200);
}
function closeSheet(){
	closePanel(el("sheet"));
	closePanel(el("addForm"));
}

function paintUpdate(){
	const ready=!!(release&&release.available), check=el("checkUpdate"), line=el("updateLine"), notes=el("updateNotes"), install=el("installUpdate");
	check.disabled=checking||installing;
	check.textContent=checking?"Checking":"Check for updates";
	line.className="update-line"+(upError?" bad":ready?" good":"");
	line.textContent=upError?upError:checking?"":ready?release.version+" available":release?"Up to date, "+release.current:"";
	notes.hidden=!(ready&&release.notes);
	if(ready&&release.notes){notes.textContent=release.notes}
	install.hidden=!ready;
	install.disabled=installing;
	install.textContent=installing?"Installing":"Install and restart";
	el("progress").hidden=!installing;
	el("appVersion").textContent=release?release.current:"";
	const show=ready&&!dismissed&&!installing;
	el("banner").hidden=!show;
	document.body.dataset.banner=show?"1":"0";
	if(show){el("bannerText").textContent="Update "+release.version+" is ready"}
}
async function runCheck(){
	if(checking||installing){return}
	checking=true;
	checked=true;
	upError=null;
	paintUpdate();
	try{release=await invoke("check_update")}
	catch(e){release=null; upError=explain(e)}
	finally{checking=false; paintUpdate()}
}
// install_update drops the tunnel itself, then the app exits behind the installer, so the bar is never cleared on success.
async function runInstall(){
	if(installing){return}
	installing=true;
	upError=null;
	el("bar").classList.remove("wait");
	el("barFill").style.width="0%";
	el("progressLine").textContent="Starting download";
	paintUpdate();
	try{
		await invoke("install_update");
		el("progressLine").textContent="Installer started. wg-wrapper closes to finish.";
	}catch(e){
		installing=false;
		upError=explain(e);
		paintUpdate();
	}
}
function setAuto(on){
	el("autoUpdate").dataset.on=on?"1":"0";
	el("autoUpdate").setAttribute("aria-checked", String(on));
}

function addLine(text){
	const body=el("logLines");
	const blank=body.querySelector(".blank");
	if(blank){blank.remove()}
	const p=document.createElement("p");
	p.className="ln"+(/\bERROR\b/.test(text)?" bad":(/\bWARN\b/.test(text)?" warn":""));
	p.textContent=text;
	body.append(p);
	while(body.childElementCount>200){body.firstElementChild.remove()}
	body.scrollTop=body.scrollHeight;
}

function boot(){
	const track=el("track");
	for(let i=0; i<TICKS; i++){
		const d=document.createElement("div");
		d.className="tick";
		d.style.height="0";
		track.append(d);
		tickEls.push(d);
	}
	el("action").onclick=onAction;
	el("picker").onclick=()=>{el("sheet").dataset.open==="1"?closeSheet():openPanel(el("sheet"))};
	el("sheetClose").onclick=closeSheet;
	el("addOpen").onclick=()=>{el("addError").hidden=true; openPanel(el("addForm")); el("addName").focus()};
	el("addCancel").onclick=()=>closePanel(el("addForm"));
	el("logToggle").onclick=()=>{
		const d=el("logPanel"), on=d.dataset.open==="1";
		on?closePanel(d):openPanel(d);
		el("logToggle").setAttribute("aria-expanded", String(!on));
	};
	el("logClose").onclick=()=>{closePanel(el("logPanel")); el("logToggle").setAttribute("aria-expanded", "false")};
	el("settingsOpen").onclick=()=>{closeSheet(); openPanel(el("settings")); if(!checked){runCheck()}};
	el("settingsClose").onclick=()=>closePanel(el("settings"));
	el("checkUpdate").onclick=runCheck;
	el("installUpdate").onclick=runInstall;
	el("bannerInstall").onclick=()=>{openPanel(el("settings")); runInstall()};
	el("bannerLater").onclick=()=>{dismissed=true; paintUpdate()};
	el("autoUpdate").onclick=()=>{
		const on=el("autoUpdate").dataset.on!=="1";
		setAuto(on);
		invoke("set_settings", {settings:{auto_update:on}}).catch(e=>{setAuto(!on); upError=explain(e); paintUpdate()});
	};
	el("logCopy").onclick=()=>{
		const text=[...el("logLines").querySelectorAll(".ln")].map(p=>p.textContent).join("\n");
		navigator.clipboard.writeText(text).then(()=>{el("logCopy").textContent="Copied"; setTimeout(()=>el("logCopy").textContent="Copy", 1200)}, ()=>{el("logCopy").textContent="Copy failed"});
	};
	el("addForm").onsubmit=async ev=>{
		ev.preventDefault();
		const name=el("addName").value.trim(), conf=el("addConf").value;
		const err=el("addError");
		if(!name){err.textContent="Give the profile a name so you can find it again."; err.hidden=false; return}
		if(!/^[ \t]*Endpoint[ \t]*=/mi.test(conf)){err.textContent="The config needs an Endpoint line, for example Endpoint = wss://vpn.example.com/wg"; err.hidden=false; return}
		try{
			await invoke("save_profile", {name, conf});
			el("addName").value="";
			el("addConf").value="";
			err.hidden=true;
			current={name, conf};
			await loadProfiles();
			closeSheet();
		}catch(e){err.textContent=explain(e); err.hidden=false}
	};
	document.addEventListener("keydown", ev=>{
		if(ev.key!=="Escape"){return}
		closeSheet();
		closePanel(el("settings"));
		closePanel(el("logPanel"));
		el("logToggle").setAttribute("aria-expanded", "false");
	});
	if(!api()){
		el("notice").textContent="The app backend is not running, so nothing here will connect.";
		el("notice").hidden=false;
		return;
	}
	api().event.listen("log", ev=>addLine(ev.payload));
	api().event.listen("update-progress", ev=>{
		const p=ev.payload||{}, total=p.total, a=fmtBytes(p.downloaded).split(" "), b=total?fmtBytes(total).split(" "):null;
		el("bar").classList.toggle("wait", !total);
		el("barFill").style.width=total?Math.min(100, Math.round(p.downloaded/total*100))+"%":"100%";
		el("progressLine").textContent=b?"Downloading "+(a[1]===b[1]?a[0]:a.join(" "))+" of "+b.join(" "):"Downloading "+a.join(" ");
	});
	invoke("get_settings").then(s=>{setAuto(!!s.auto_update); if(s.auto_update){runCheck()}}).catch(()=>{});
	invoke("log_history").then(lines=>lines.forEach(addLine)).catch(()=>{});
	loadProfiles().then(poll).catch(e=>{
		el("notice").textContent=explain(e);
		el("notice").hidden=false;
	});
}
boot();
