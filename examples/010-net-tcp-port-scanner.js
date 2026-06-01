// name: net_tcp_port_scanner
// title: TCP port scanner with net.dial
// description: Scans a target host with Go net-style TCP dialing and reports open, closed, refused, and timed-out ports.
// tags: net, tcp, scanner, dns

const target = args.target || "127.0.0.1";
const network = args.network || "tcp";
const timeoutMS = args.timeout_ms || 200;
const inputPorts = args.ports || [22, 80, 443, 8080, 8443];

function resolvePort(value) {
  if (typeof value === "number") {
    return {port: value, label: String(value)};
  }
  const text = String(value);
  if (/^[0-9]+$/.test(text)) {
    return {port: parseInt(text, 10), label: text};
  }
  const lookup = net.lookupPort({network, service: text, timeout_ms: timeoutMS});
  if (!lookup.ok) {
    return {label: text, error: lookup};
  }
  return {port: lookup.port, label: text};
}

const started = Date.now();
const results = [];

for (const input of inputPorts) {
  const resolved = resolvePort(input);
  if (!resolved.port || resolved.port < 1 || resolved.port > 65535) {
    results.push({input, service: resolved.label, open: false, skipped: true, error: resolved.error || "invalid port"});
    continue;
  }

  const joined = net.joinHostPort({host: target, port: resolved.port});
  const dial = net.dial({network, address: joined.address, timeout_ms: timeoutMS});
  const entry = {
    input,
    service: resolved.label,
    port: resolved.port,
    address: joined.address,
    open: dial.ok === true,
    timeout: dial.timeout === true,
    error: dial.error || "",
    error_name: dial.error_name || "",
    errno_name: dial.errno_name || "",
  };
  if (dial.ok) {
    entry.local_addr = dial.local_addr;
    entry.remote_addr = dial.remote_addr;
    net.connClose({conn: dial.conn});
  }
  results.push(entry);
}

return {
  target,
  network,
  timeout_ms: timeoutMS,
  scanned: results.length,
  open: results.filter(port => port.open),
  results,
  duration_ms: Date.now() - started,
};