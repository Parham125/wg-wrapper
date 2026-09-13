//! Loopback end-to-end: test socket -> run_client -> serve -> UDP echo, and back.
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use wsrelay::TlsFiles;

/// Bind a UDP echo server that bounces every datagram back to its sender.
async fn echo_server()->SocketAddr{
	let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr=sock.local_addr().unwrap();
	tokio::spawn(async move{
		let mut buf=[0u8; 65535];
		while let Ok((n, src))=sock.recv_from(&mut buf).await{let _=sock.send_to(&buf[..n], src).await;}
	});
	addr
}

/// Bring up echo + relay + bridge and return the bridge's local UDP address.
async fn stack(tls:Option<TlsFiles>, scheme:&str)->SocketAddr{
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	tokio::spawn(async move{wsrelay::serve(listener, tls, "/wg".to_string(), target).await.unwrap()});
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr=client.local_addr().unwrap();
	let url=format!("{scheme}://127.0.0.1:{}/wg", relay.port());
	tokio::spawn(async move{wsrelay::run_client_on(client, url, true).await.unwrap()});
	addr
}

/// Send every payload from a fresh socket and assert the echoes come back in the same order.
async fn roundtrip(bridge:SocketAddr, payloads:&[Vec<u8>]){
	let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(bridge).await.unwrap();
	for p in payloads{sock.send(p).await.unwrap();}
	let mut buf=[0u8; 65535];
	for p in payloads{
		let n=tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf)).await.expect("timed out waiting for echo").unwrap();
		assert_eq!(&buf[..n], &p[..], "echo mismatch for a {} byte datagram", p.len());
	}
}

fn payloads()->Vec<Vec<u8>>{
	vec![b"hello wireguard".to_vec(), (0..1400u32).map(|i| (i%251) as u8).collect(), vec![0x7f]]
}

#[tokio::test]
async fn plain_ws_roundtrip(){
	let bridge=stack(None, "ws").await;
	let p=payloads();
	tokio::join!(roundtrip(bridge, &p), roundtrip(bridge, &p));
}

#[tokio::test]
async fn tls_roundtrip_with_self_signed_cert(){
	let ck=rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
	let dir=std::env::temp_dir().join(format!("wsrelay-test-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (cert, key)=(dir.join("cert.pem"), dir.join("key.pem"));
	std::fs::write(&cert, ck.cert.pem()).unwrap();
	std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
	let bridge=stack(Some(TlsFiles{cert, key}), "wss").await;
	roundtrip(bridge, &payloads()).await;
	let _=std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pre_resolved_address_skips_dns(){
	let target=echo_server().await;
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let relay=listener.local_addr().unwrap();
	tokio::spawn(async move{wsrelay::serve(listener, None, "/wg".to_string(), target).await.unwrap()});
	let client=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge=client.local_addr().unwrap();
	// The host in the url never resolves, so an echo only comes back if the bridge dialled `relay` itself.
	let url=format!("ws://does-not-resolve.invalid:{}/wg", relay.port());
	tokio::spawn(async move{wsrelay::run_client_to(client, url, false, Some(relay)).await.unwrap()});
	roundtrip(bridge, &payloads()).await;
}
