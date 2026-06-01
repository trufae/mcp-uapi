# Go net Scripting API

The JavaScript `net` global exposes synchronous Go package `net` style helpers for TCP/IP, UDP, Unix domain sockets, domain name resolution, address parsing, and interface discovery. It is separate from the lower-level `sys.socket` wrappers: use `net.*` when you want Go's address parsing, DNS resolver, deadlines, and `net.Conn`/`net.Listener`/`net.PacketConn` behavior.

Every helper accepts one object argument and returns JSON. Successful calls return `ok: true`. Go network errors return `ok: false` with `error`, `error_type`, and when available `op`, `network`, `addr`, `timeout`, `temporary`, `errno`, and `errno_name` fields.

## Handles

- `net.dial` and `net.listenerAccept` return managed connection handles in both `conn` and `handle`.
- `net.listen` returns a managed listener handle in `listener`.
- `net.listenPacket` returns a managed packet socket handle in `packet`.
- Close them with `net.connClose({conn})`, `net.listenerClose({listener})`, or `net.packetClose({packet})`.
- `io` endpoints can read from or write to managed network connections with `{conn: "name"}`.

## TCP Streams

```javascript
const listener = net.listen({network: "tcp", address: "127.0.0.1:0", handle: "tcpListener"});
const address = net.listenerAddr({listener: "tcpListener"}).addr.address;
const client = net.dial({network: "tcp", address, timeout_ms: 1000, handle: "tcpClient"});
const server = net.listenerAccept({listener: "tcpListener", conn_handle: "tcpServer", timeout_ms: 1000});
net.connWrite({conn: "tcpClient", data_utf8: "ping", timeout_ms: 1000});
const got = net.connRead({conn: "tcpServer", length: 4, encoding: "utf8", timeout_ms: 1000});
net.connClose({conn: "tcpClient"});
net.connClose({conn: "tcpServer"});
net.listenerClose({listener: "tcpListener"});
return got;
```

## UDP Packets

```javascript
const server = net.listenPacket({network: "udp", address: "127.0.0.1:0", handle: "udpServer"});
const client = net.listenPacket({network: "udp", address: "127.0.0.1:0", handle: "udpClient"});
const address = net.packetLocalAddr({packet: "udpServer"}).addr.address;
net.packetWriteTo({packet: "udpClient", address, data_utf8: "hello", timeout_ms: 1000});
const got = net.packetReadFrom({packet: "udpServer", length: 32, encoding: "utf8", timeout_ms: 1000});
net.packetClose({packet: "udpClient"});
net.packetClose({packet: "udpServer"});
return got;
```

## Unix Domain Sockets

```javascript
const path = os.tempDir().dir + "/mcp-uapi-example.sock";
os.remove({name: path});
const listener = net.listen({network: "unix", address: path, handle: "unixListener"});
const client = net.dial({network: "unix", address: path, handle: "unixClient", timeout_ms: 1000});
const server = net.listenerAccept({listener: "unixListener", conn_handle: "unixServer", timeout_ms: 1000});
net.connWrite({conn: "unixClient", data_utf8: "hello", timeout_ms: 1000});
const got = io.readFull({src: {conn: "unixServer"}, length: 5, encoding: "utf8"});
net.connClose({conn: "unixClient"});
net.connClose({conn: "unixServer"});
net.listenerClose({listener: "unixListener"});
os.remove({name: path});
return got;
```

## DNS And Address Helpers

- `net.lookupHost({host})`, `net.lookupIP({network:"ip", host})`, `net.lookupPort({network:"tcp", service})`
- `net.lookupCNAME`, `net.lookupAddr`, `net.lookupMX`, `net.lookupNS`, `net.lookupTXT`, `net.lookupSRV`
- `net.resolveTCPAddr`, `net.resolveUDPAddr`, `net.resolveIPAddr`, `net.resolveUnixAddr`
- `net.joinHostPort`, `net.splitHostPort`, `net.parseIP`, `net.parseCIDR`
- `net.interfaces`, `net.interfaceAddrs`, `net.interfaceByName`, `net.interfaceByIndex`

DNS helpers accept `timeout_ms` to bound resolver calls. Connection and packet read/write helpers also accept `timeout_ms`, which applies a temporary read or write deadline for that operation.