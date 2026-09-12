// Dev only. Stands in for the Tauri bridge so the UI can be opened in a plain browser and screenshotted.
// Never shipped: tauri.conf.json points frontendDist at ../ui, which does not contain this file.
(function(){
	const q=new URLSearchParams(location.search), scene=q.get("scene")||"default";
	const CONF=n=>`[Interface]\nPrivateKey = 4H9x...redacted\nAddress = 10.7.0.${n}/32\nDNS = 1.1.1.1\nMTU = 1380\n\n[Peer]\nPublicKey = kP2v...redacted\nEndpoint = wss://${n===2?"fra.example.com/wg":n===3?"lab.example.net/tunnel":"ams.example.org/wg"}\nInsecureTls = true\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25`;
	let store=scene==="empty"?[]:[{name:"Frankfurt relay", conf:CONF(2)}, {name:"Home lab", conf:CONF(3)}, {name:"Amsterdam backup", conf:CONF(4)}];
	let state=scene==="connected"||scene==="log"?"connected":scene==="error"?"error":scene==="connecting"?"connecting":"disconnected";
	let error=scene==="error"?"Windows only":null, clock=0, rx=0, tx=0, subs={};
	const emit=(ev, payload)=>(subs[ev]||[]).forEach(f=>f({payload}));
	const rate=t=>t%53<4?0:Math.round((0.45+0.4*Math.sin(t/11)+0.2*Math.sin(t/3.1))*(t%37<6?1250000:320000));
	const lines=["   0.01  INFO   wg_wrapper_client  client ready", "   0.02  INFO   wg_wrapper_client  connect requested", "   0.03  INFO   wgclient  resolving wss://fra.example.com/wg", "   0.21  INFO   wgclient  endpoint 203.0.113.44:443", "   0.24  INFO   wgclient  opening adapter via wintun.dll", "   0.58  WARN   wgclient  InsecureTls set, certificate not verified", "   0.90  INFO   wsrelay  websocket open, 1380 byte datagrams", "   1.41  INFO   wgclient  handshake complete with peer kP2v", "   1.42  INFO   wg_wrapper_client  tunnel up"];
	function advanceSecond(){
		clock++;
		const r=rate(clock);
		rx+=Math.round(r*0.72);
		tx+=Math.round(r*0.28);
	}
	function stats(){
		if(state!=="connected"){return null}
		return {rx_bytes:rx, tx_bytes:tx, last_handshake_secs_ago:clock%120, connected_secs:clock};
	}
	window.__TAURI__={
		core:{invoke:async (cmd, args)=>{
			if(cmd==="status"){return {state, error, stats:stats(), endpoint:state==="connected"?"wss://fra.example.com/wg":null}}
			if(cmd==="log_history"){return state==="connected"?lines:lines.slice(0, 1)}
			if(cmd==="list_profiles"){return store.slice()}
			if(cmd==="save_profile"){store=store.filter(p=>p.name!==args.name).concat([{name:args.name, conf:args.conf}]).sort((a, b)=>a.name.localeCompare(b.name)); return null}
			if(cmd==="delete_profile"){store=store.filter(p=>p.name!==args.name); return null}
			if(cmd==="disconnect"){state="disconnected"; error=null; clock=0; rx=0; tx=0; emit("log", "  99.00  INFO   wg_wrapper_client  tunnel down"); return null}
			if(cmd==="connect"){
				state="connecting";
				emit("log", "   0.02  INFO   wg_wrapper_client  connect requested");
				await new Promise(r=>setTimeout(r, 700));
				if(q.get("fail")==="1"){state="error"; error="Windows only"; throw "Windows only"}
				state="connected";
				lines.slice(2).forEach(l=>emit("log", l));
				return null;
			}
			throw "unknown command "+cmd;
		}},
		event:{listen:async (ev, fn)=>{(subs[ev]=subs[ev]||[]).push(fn); return ()=>{}}}
	};
	// Replays N seconds through the real polling path so the traffic strip has believable history in a screenshot.
	window.__advance=async n=>{for(let i=0; i<n; i++){advanceSecond(); tick(); await new Promise(r=>setTimeout(r, 2))}};
})();
