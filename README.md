<h1 align="center">wg-wrapper</h1>

<p align="center">
WireGuard that can only leave through your SOCKS5, carried over WebSocket where UDP is blocked,<br>
with a Windows client that needs one <code>.conf</code> and one button.
</p>

<p align="center">
<a href="https://github.com/Parham125/wg-wrapper/actions/workflows/ci.yml"><img alt="ci" src="https://github.com/Parham125/wg-wrapper/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/Parham125/wg-wrapper/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/Parham125/wg-wrapper?display_name=tag"></a>
<a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-8FC9A9"></a>
</p>

## What it does

```mermaid
flowchart LR
    P[WireGuard peer] -- "wss://host/wg" --> R[wgw-bridge relay<br>or Caddy]
    R -- "udp 127.0.0.1" --> S["wgw-server<br>boringtun + userspace TCP/IP"]
    S -- "socks5 CONNECT / UDP ASSOCIATE" --> X[upstream SOCKS5]
    X --> I((internet))
    S x--x O[other peers, gateway,<br>host, private ranges]
```

- **SOCKS5 only.** There is no TUN device and no kernel routing. Every TCP flow, every UDP flow and every DNS query a peer sends is terminated in userspace and re-dialed through the proxy. There is nothing else it could go through.
- **Peers are alone.** A peer sees the public internet through the proxy and nothing else: not other peers, not the gateway, not the host, not the private network behind the proxy unless you opt in.
- **WebSocket transport.** One WireGuard datagram is one binary WebSocket frame. Works behind Caddy or nginx on 443 next to a real website, and with a stock WireGuard client through the bridge.
- **No root, no kernel module.** A static musl binary, one JSON file, done.

## Quick start

### 1. Server (~3 min)

Download `wgw-server-x86_64-unknown-linux-musl` from the [latest release](https://github.com/Parham125/wg-wrapper/releases/latest), then:

```
chmod +x wgw-server && ./wgw-server genkey
```

Put the private key in `config.json` (start from [`config.example.json`](config.example.json)), add one peer, then:

```
RUST_LOG=info ./wgw-server --config config.json
```

The server prints its public key on startup. Give that and the peer's private key to the client.

### 2. Client with a stock WireGuard app (~1 min)

```
wgw-bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

Then set `Endpoint = 127.0.0.1:51820` in the WireGuard app. Add `--insecure` for a self-signed relay.

### 3. Windows client (~1 min)

Install `wg-wrapper_<version>_x64-setup.exe` from the release, paste a `.conf` whose `Endpoint` is the `wss://` URL, press Connect.

<p align="center">
<img src="crates/client-win/screenshots/06-connected.png" width="380" alt="wg-wrapper Windows client, connected">
</p>

## Server config

`config.json`, all keys except the first four and `peers` are optional:

| Key | What it does |
|---|---|
| `private_key` | Server key, base64. `wgw-server genkey` makes one. |
| `address` | Tunnel subnet with the gateway address, e.g. `10.7.0.1/24`. |
| `upstream` | `socks5://user:pass@host:1080`. Credentials may be percent-encoded. |
| `peers[]` | `public_key`, `allowed_ips`, optional `preshared_key` and per-peer `upstream`. |
| `listen_udp` | Public WireGuard UDP listener. Omit for WebSocket only. |
| `listen_ws` | `{addr, path, cert, key}`. Omit `cert`/`key` to run plain `ws://` behind a reverse proxy. |
| `dns` | Force every peer's DNS to this `ip:53` instead of whatever they asked for. |
| `mtu` | Default `1420`. |
| `udp_idle_secs` | Idle timeout for UDP flows through the proxy. Default `60`. |
| `allow_private` | `true` lets peers reach private ranges through the proxy. Default `false`. |

## How traffic is handled

| Peer sends | Server does |
|---|---|
| TCP to a public address | SOCKS5 `CONNECT`, bidirectional copy |
| UDP to port 53 | DNS over TCP through the proxy, `TC` bit set if the answer would not fit |
| Any other UDP | SOCKS5 `UDP ASSOCIATE`, one association per flow |
| Anything to the tunnel subnet, gateway, loopback, link-local, multicast, broadcast | TCP gets an `RST`, the rest is dropped |
| Anything to 10/8, 172.16/12, 192.168/16, 100.64/10, 192.0.0/24, 198.18/15, 240/4, fc00::/7 | Same, unless `allow_private` |
| A packet whose source is not in that peer's `allowed_ips` | Dropped before it reaches the stack |
| A handshake flood | Rate limited with WireGuard cookies, endpoints only move on authenticated packets |

Flows are capped at 4096 in total and 512 per peer, with timeouts on every proxy dial.

## WebSocket relay

`wgw-bridge relay` terminates the WebSocket side and forwards to any WireGuard UDP port, ours or the kernel's. Each connection gets its own local UDP socket, so roaming and multiple clients behind one NAT work.

Standalone with TLS:

```
wgw-bridge relay --listen 0.0.0.0:443 --path /wg --target 127.0.0.1:51820 \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key  /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Behind Caddy, which then owns the certificate and can serve a normal site on the same host:

```
wgw-bridge relay --listen 127.0.0.1:8443 --path /wg --target 127.0.0.1:51820
```

```caddyfile
vpn.example.com {
	reverse_proxy /wg 127.0.0.1:8443
	respond "hello" 200
}
```

`wgw-server` can also open the WebSocket listener itself via `listen_ws`, in which case no separate relay process is needed. `--max-conns` (default 1024) caps concurrent relay connections.

## Windows client

`crates/client-win` is a Tauri app. It reads a normal WireGuard `.conf`, opens a Wintun adapter, and runs the tunnel in-process over WSS. No bridge process, no WireGuard installation.

```
[Interface]
PrivateKey = <client private key>
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = wss://vpn.example.com/wg
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`Endpoint` may be `wss://`, `ws://` or `host:port` for plain UDP. `InsecureTls = true` under `[Peer]` skips certificate verification for a self-signed relay.

While connected:

- **Routing is the killswitch.** `0.0.0.0/0` becomes two half routes through the adapter plus one host route to the relay through the old gateway. Nothing else can leave.
- **DNS goes where the conf says.** The adapter gets the lowest interface metric, each `DNS` address gets a route through the tunnel, and a catch-all Name Resolution Policy Table rule points every name at those servers. Without a `DNS` line none of this is applied.
- **IPv6 is blocked.** Both halves of `::/0` are routed into the adapter and dropped locally.

Disconnecting removes every route and rule it added, resets the metric and DNS, and flushes the resolver cache. The app asks for administrator rights at launch because Wintun and the routing table need them.

## Build from source

```
cargo build --release --workspace
```

The Windows client is outside the workspace and needs `wintun.dll`, which is not in the repository:

```
crates/client-win/scripts/fetch-wintun.sh
cd crates/client-win/src-tauri && npx --yes @tauri-apps/cli@^2 build
```

Tagging `v*` builds everything in CI and attaches the binaries and the installer to the release.

## Layout

| Crate | Role |
|---|---|
| `wgcore` | Multi-peer boringtun wrapper: handshake routing, cookies, timers, authenticated roaming |
| `server` | `wgw-server`: ipstack, isolation rules, SOCKS5 egress, config |
| `wsrelay` | `wgw-bridge`: WebSocket relay and UDP client bridge |
| `wgclient` | Single-peer engine plus the Wintun, route and DNS layer for Windows |
| `client-win` | Tauri desktop app |

## License

MIT, see [LICENSE](LICENSE).
