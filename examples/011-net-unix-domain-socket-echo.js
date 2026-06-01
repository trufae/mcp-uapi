// name: net_unix_domain_socket_echo
// title: Unix domain socket echo with net
// description: Creates a Unix domain socket listener, dials it, exchanges a message, and cleans up the socket path.
// tags: net, unix-socket, ipc

const tempDir = os.tempDir().dir;
const socketPath = args.path || (tempDir + "/mcp-uapi-net-" + os.getpid().pid + "-" + Date.now() + ".sock");
const message = args.message || "hello over unix sockets";
const timeoutMS = args.timeout_ms || 1000;
const suffix = String(os.getpid().pid) + "." + String(Date.now());

const listenerHandle = "unixListener." + suffix;
const clientHandle = "unixClient." + suffix;
const serverHandle = "unixServer." + suffix;

let listener = null;
let client = null;
let server = null;

try {
  os.remove({name: socketPath});

  listener = net.listen({network: "unix", address: socketPath, handle: listenerHandle});
  if (!listener.ok) {
    return {socket_path: socketPath, listener};
  }

  client = net.dial({network: "unix", address: socketPath, handle: clientHandle, timeout_ms: timeoutMS});
  if (!client.ok) {
    return {socket_path: socketPath, listener, client};
  }

  server = net.listenerAccept({listener: listenerHandle, conn_handle: serverHandle, timeout_ms: timeoutMS});
  if (!server.ok) {
    return {socket_path: socketPath, listener, client, server};
  }

  const sent = net.connWrite({conn: clientHandle, data_utf8: message, timeout_ms: timeoutMS});
  const received = io.readFull({src: {conn: serverHandle}, length: message.length, encoding: "utf8"});
  const replyText = "echo: " + received.data_utf8;
  const replied = io.writeString({dst: {conn: serverHandle}, data: replyText});
  const reply = net.connRead({conn: clientHandle, length: replyText.length, encoding: "utf8", timeout_ms: timeoutMS});

  return {
    socket_path: socketPath,
    listener,
    client,
    server,
    sent,
    received,
    replied,
    reply,
    ok: received.ok && received.data_utf8 === message && reply.ok && reply.data_utf8 === replyText,
  };
} finally {
  if (server && server.ok) {
    net.connClose({conn: serverHandle});
  }
  if (client && client.ok) {
    net.connClose({conn: clientHandle});
  }
  if (listener && listener.ok) {
    net.listenerClose({listener: listenerHandle});
  }
  os.remove({name: socketPath});
}