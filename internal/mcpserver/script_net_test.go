package mcpserver

import (
	"encoding/json"
	stdnet "net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestEvalNetTCPDNSAndIOAPI(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
let listener = null;
let client = null;
let server = null;
let listenerResult = null;
let clientResult = null;
let serverResult = null;
try {
  const constants = net.constants();
  const host = net.lookupHost({host: "localhost", timeout_ms: 1000});
  const ips = net.lookupIP({network: "ip", host: "localhost", timeout_ms: 1000});
  const port = net.lookupPort({network: "tcp", service: "80", timeout_ms: 1000});
  const parsed = net.parseIP({ip: "127.0.0.1"});
  const cidr = net.parseCIDR({cidr: "127.0.0.0/8"});
  const interfaces = net.interfaces();

	listener = net.listen({network: "tcp", address: "127.0.0.1:0", handle: "tcpListener"});
	listenerResult = listener;
  const addr = net.listenerAddr({listener: "tcpListener"});
  const split = net.splitHostPort({address: addr.addr.address});
  const joined = net.joinHostPort({host: split.host, port: split.port});
  client = net.dial({network: "tcp", address: joined.address, timeout_ms: 1000, handle: "tcpClient"});
	clientResult = client;
  server = net.listenerAccept({listener: "tcpListener", conn_handle: "tcpServer", timeout_ms: 1000});
	serverResult = server;

  const noDelay = net.tcpConnSetNoDelay({conn: "tcpClient", no_delay: true});
  const write = net.connWrite({conn: "tcpClient", data_utf8: "ping", timeout_ms: 1000});
  const read = io.readFull({src: {conn: "tcpServer"}, length: 4, encoding: "utf8"});
  const echoWrite = io.writeString({dst: {conn: "tcpServer"}, data: "pong"});
  const echoRead = net.connRead({conn: "tcpClient", length: 4, encoding: "utf8", timeout_ms: 1000});
  const local = net.connLocalAddr({conn: "tcpClient"});
  const remote = net.connRemoteAddr({conn: "tcpClient"});

  net.connClose({conn: "tcpClient"});
  client = null;
  net.connClose({conn: "tcpServer"});
  server = null;
  net.listenerClose({listener: "tcpListener"});
  listener = null;

  const caps = sys.capabilities().scripting_api;
  return {
    types: {net: typeof net.lookupHost, netAlias: typeof net.LookupHost},
	constants, host, ips, port, parsed, cidr, interfaces, listener: listenerResult, addr, split, joined,
	client: clientResult, server: serverResult, noDelay, write, read, echoWrite, echoRead, local, remote,
    wrappers: {net: caps.net_wrappers.indexOf("dial") >= 0 && caps.net_wrappers.indexOf("lookupHost") >= 0},
    state: sys.state()
  };
} finally {
  if (client && client.ok) net.connClose({conn: "tcpClient"});
  if (server && server.ok) net.connClose({conn: "tcpServer"});
  if (listener && listener.ok) net.listenerClose({listener: "tcpListener"});
}
`})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	types := nestedMap(t, value, "types")
	if types["net"] != "function" || types["netAlias"] != "function" {
		t.Fatalf("net wrapper types = %#v", types)
	}
	for _, key := range []string{"constants", "host", "ips", "port", "parsed", "cidr", "interfaces", "listener", "addr", "split", "joined", "client", "server", "noDelay", "write", "read", "echoWrite", "echoRead", "local", "remote"} {
		requireNestedOK(t, value, key)
	}
	if got := nestedMap(t, value, "read")["data_utf8"]; got != "ping" {
		t.Fatalf("server read = %#v", got)
	}
	if got := nestedMap(t, value, "echoRead")["data_utf8"]; got != "pong" {
		t.Fatalf("client read = %#v", got)
	}
	if addrs, ok := nestedMap(t, value, "host")["addrs"].([]any); !ok || len(addrs) == 0 {
		t.Fatalf("lookupHost addrs = %#v", nestedMap(t, value, "host"))
	}
	if wrappers := nestedMap(t, value, "wrappers"); wrappers["net"] != true {
		t.Fatalf("capabilities missing net wrappers: %#v", wrappers)
	}
	state := nestedMap(t, value, "state")
	for _, key := range []string{"net_connections", "net_listeners", "net_packet_conns"} {
		if entries, ok := state[key].([]any); ok && len(entries) != 0 {
			t.Fatalf("expected script to close %s, state=%#v", key, state)
		}
	}
}

func TestEvalNetUDPAndUnixDomainSockets(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	socketPath := shortUnixSocketPath(t, "echo.sock")
	resp, result := callEvalForTest(t, app, map[string]any{"script": `
let udpServer = null;
let udpClient = null;
let unixListener = null;
let unixClient = null;
let unixServer = null;
let udpServerResult = null;
let udpClientResult = null;
let unixListenerResult = null;
let unixClientResult = null;
let unixServerResult = null;
try {
  udpServer = net.listenPacket({network: "udp", address: "127.0.0.1:0", handle: "udpServer"});
	udpServerResult = udpServer;
  const udpAddr = net.packetLocalAddr({packet: "udpServer"});
  udpClient = net.listenPacket({network: "udp", address: "127.0.0.1:0", handle: "udpClient"});
	udpClientResult = udpClient;
  const udpWrite = net.packetWriteTo({packet: "udpClient", address: udpAddr.addr.address, data_utf8: "datagram", timeout_ms: 1000});
  const udpRead = net.packetReadFrom({packet: "udpServer", length: 32, encoding: "utf8", timeout_ms: 1000});
  net.packetClose({packet: "udpClient"});
  udpClient = null;
  net.packetClose({packet: "udpServer"});
  udpServer = null;

  os.remove({name: args.socketPath});
  unixListener = net.listen({network: "unix", address: args.socketPath, handle: "unixListener"});
	unixListenerResult = unixListener;
  unixClient = net.dial({network: "unix", address: args.socketPath, handle: "unixClient", timeout_ms: 1000});
	unixClientResult = unixClient;
  unixServer = net.listenerAccept({listener: "unixListener", conn_handle: "unixServer", timeout_ms: 1000});
	unixServerResult = unixServer;
  const unixWrite = net.connWrite({conn: "unixClient", data_utf8: "hello unix", timeout_ms: 1000});
  const unixRead = io.readFull({src: {conn: "unixServer"}, length: 10, encoding: "utf8"});
  const unixReplyWrite = io.writeString({dst: {conn: "unixServer"}, data: "reply"});
  const unixReply = net.connRead({conn: "unixClient", length: 5, encoding: "utf8", timeout_ms: 1000});
  net.connClose({conn: "unixClient"});
  unixClient = null;
  net.connClose({conn: "unixServer"});
  unixServer = null;
  net.listenerClose({listener: "unixListener"});
  unixListener = null;
  os.remove({name: args.socketPath});

	return {udpServer: udpServerResult, udpAddr, udpClient: udpClientResult, udpWrite, udpRead, unixListener: unixListenerResult, unixClient: unixClientResult, unixServer: unixServerResult, unixWrite, unixRead, unixReplyWrite, unixReply, state: sys.state()};
} finally {
  if (udpClient && udpClient.ok) net.packetClose({packet: "udpClient"});
  if (udpServer && udpServer.ok) net.packetClose({packet: "udpServer"});
  if (unixClient && unixClient.ok) net.connClose({conn: "unixClient"});
  if (unixServer && unixServer.ok) net.connClose({conn: "unixServer"});
  if (unixListener && unixListener.ok) net.listenerClose({listener: "unixListener"});
  os.remove({name: args.socketPath});
}
`, "args": map[string]any{"socketPath": socketPath}})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	for _, key := range []string{"udpServer", "udpAddr", "udpClient", "udpWrite", "udpRead", "unixListener", "unixClient", "unixServer", "unixWrite", "unixRead", "unixReplyWrite", "unixReply"} {
		requireNestedOK(t, value, key)
	}
	if got := nestedMap(t, value, "udpRead")["data_utf8"]; got != "datagram" {
		t.Fatalf("udp read = %#v", got)
	}
	if got := nestedMap(t, value, "unixRead")["data_utf8"]; got != "hello unix" {
		t.Fatalf("unix read = %#v", got)
	}
	if got := nestedMap(t, value, "unixReply")["data_utf8"]; got != "reply" {
		t.Fatalf("unix reply = %#v", got)
	}
	state := nestedMap(t, value, "state")
	for _, key := range []string{"net_connections", "net_listeners", "net_packet_conns"} {
		if entries, ok := state[key].([]any); ok && len(entries) != 0 {
			t.Fatalf("expected script to close %s, state=%#v", key, state)
		}
	}
}

func TestEmbeddedNetExamplesExecuteThroughMCP(t *testing.T) {
	app, srv := New(Config{})
	defer app.Close()

	client, err := mcpclient.NewInProcessClient(srv)
	if err != nil {
		t.Fatalf("new in-process client: %v", err)
	}
	defer client.Close()
	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start client: %v", err)
	}
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{Name: "mcp-uapi-net-example-test", Version: "1.0.0"}
	if _, err := client.Initialize(t.Context(), initRequest); err != nil {
		t.Fatalf("initialize client: %v", err)
	}

	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for scanner example: %v", err)
	}
	defer listener.Close()
	_, portText, err := stdnet.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}

	scanner := callExampleThroughMCP(t, client, "uapi://examples/010-net-tcp-port-scanner.js", map[string]any{"target": "127.0.0.1", "ports": []int{port}, "timeout_ms": 500})
	scannerResult := scanner.Result.(map[string]any)
	openPorts, ok := scannerResult["open"].([]any)
	if !ok || len(openPorts) != 1 {
		t.Fatalf("scanner open ports = %#v", scannerResult["open"])
	}

	socketPath := shortUnixSocketPath(t, "example.sock")
	unixEcho := callExampleThroughMCP(t, client, "uapi://examples/011-net-unix-domain-socket-echo.js", map[string]any{"path": socketPath, "message": "mcp unix", "timeout_ms": 1000})
	unixResult := unixEcho.Result.(map[string]any)
	if unixResult["ok"] != true {
		t.Fatalf("unix socket example failed: %#v", unixResult)
	}
}

func shortUnixSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mcp-uapi-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return filepath.Join(dir, name)
}

func callExampleThroughMCP(t *testing.T, client *mcpclient.Client, uri string, args map[string]any) evalResponse {
	t.Helper()
	readRequest := mcp.ReadResourceRequest{}
	readRequest.Params.URI = uri
	read, err := client.ReadResource(t.Context(), readRequest)
	if err != nil {
		t.Fatalf("read example %s: %v", uri, err)
	}
	if len(read.Contents) != 1 {
		t.Fatalf("example %s contents = %d", uri, len(read.Contents))
	}
	text, ok := read.Contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("example %s content type = %T", uri, read.Contents[0])
	}
	callRequest := mcp.CallToolRequest{}
	callRequest.Params.Name = "eval"
	callRequest.Params.Arguments = map[string]any{"script": text.Text, "args": args, "timeout_ms": 5000}
	called, err := client.CallTool(t.Context(), callRequest)
	if err != nil {
		t.Fatalf("eval example %s protocol error: %v", uri, err)
	}
	data, err := json.Marshal(called.StructuredContent)
	if err != nil {
		t.Fatalf("marshal eval response for %s: %v", uri, err)
	}
	var resp evalResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal eval response for %s: %v", uri, err)
	}
	if called.IsError || !resp.OK {
		t.Fatalf("example %s failed: result=%#v resp=%#v", uri, called, resp)
	}
	return resp
}
