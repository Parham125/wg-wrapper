# wg-wrapper

A userspace WireGuard server whose peer traffic egresses only through a SOCKS5 proxy, with peers isolated
from each other, plus a bridge that carries WireGuard over WebSocket (ws/wss) for networks that block UDP.

## Isolation

A peer may reach the public internet and nothing else. The server refuses the tunnel subnet itself (so peers
cannot reach each other or the gateway), loopback, link-local, unspecified, multicast and broadcast, and by
default every private, shared or reserved range too: 10/8, 172.16/12, 192.168/16, 100.64/10, 192.0.0/24,
198.18/15, 240/4 and fc00::/7. Blocked TCP gets an RST, everything else is dropped. Set `"allow_private": true`
in the config if the proxy is meant to reach a private network. Decrypted packets are also checked against the
sending peer's `allowed_ips`, so a peer cannot spoof another's source address.

## Binaries

- `wgw-server` - the WireGuard server. Configured by a JSON file, see `config.example.json`.
- `wgw-bridge` - the WebSocket bridge, both halves. One WireGuard datagram is one binary WebSocket message.

## Bridge

On the client machine, listen on a local UDP port and tunnel it to the relay. Point the WireGuard peer's
`Endpoint` at `--listen`:

```
wgw-bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

On the server, terminate TLS and hand datagrams to the local WireGuard endpoint:

```
wgw-bridge relay --listen 0.0.0.0:443 --path /wg --target 127.0.0.1:51820 \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key  /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Add `--insecure` to the client to skip certificate verification against a self-signed relay. Requests to any
path other than `--path` get a 404, so the relay can share a hostname with a real site.

## Behind Caddy

Drop `--cert`/`--key`, bind the relay to localhost, and let Caddy own port 443 and the certificate:

```
wgw-bridge relay --listen 127.0.0.1:8443 --path /wg --target 127.0.0.1:51820
```

```caddyfile
vpn.example.com {
	reverse_proxy /wg 127.0.0.1:8443
	respond "hello" 200
}
```

Set `RUST_LOG=debug` for per-connection detail; the default is `info`.

## Windows client

`crates/client-win` is a small Tauri desktop app that dials one relay. It reads a standard WireGuard `.conf`,
opens a Wintun adapter, and runs the tunnel in-process over WSS, so no separate `wgw-bridge` is needed on the
client. Profiles are saved as JSON in the app config directory. The window shows connection state, the last
minute of traffic, byte counters, and the time since the last handshake.

It must run as administrator. Creating the Wintun adapter and editing the routing table both require it, so the
exe carries a manifest that asks for elevation at launch.

The config it expects is a normal WireGuard file with the peer endpoint pointed at the relay:

```
[Interface]
PrivateKey = <client private key>
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = wss://vpn.example.com/wg
InsecureTls = true
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`Endpoint` may be `wss://`, `ws://` or a plain `host:port` for UDP. `InsecureTls = true` skips certificate
verification, which you only want against a self-signed relay.

There is no separate killswitch. `AllowedIPs = 0.0.0.0/0` installs default routes through the adapter and a
single host route to the relay through the old gateway, so nothing but the relay connection can leave the
machine while the tunnel is up. Disconnecting drops the adapter, which restores the routes and DNS.

Every name is resolved through the servers in the conf. Windows normally queries all interfaces at once, so
the client gives the adapter the lowest interface metric, routes each `DNS` address through the tunnel, and
installs a catch-all Name Resolution Policy Table rule that points every namespace at those servers.
Disconnecting removes the rule, the routes and the metric, and flushes the resolver cache. If the conf has no
`DNS` line none of this is applied and name resolution keeps using the physical adapter's resolvers.

IPv6 is blocked for as long as the tunnel is up: both halves of `::/0` are routed into the adapter and every
v6 packet that lands there is dropped locally instead of being sent to the server.

Building it needs `wintun.dll`, which is not in the repository:

```
crates/client-win/scripts/fetch-wintun.sh
cd crates/client-win/src-tauri && npx --yes @tauri-apps/cli@^2 build
```

That produces an NSIS installer under `src-tauri/target/release/bundle/nsis`. Release tags build it in CI and
attach it to the GitHub release. Screenshots of the interface are in `crates/client-win/screenshots`.

## License

MIT, see LICENSE.
