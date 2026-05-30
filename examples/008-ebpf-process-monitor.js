// name: ebpf_process_exec_monitor
// title: eBPF process exec monitor via tracepoint
// description: Attaches a ringbuf_event eBPF program to the syscalls:sys_enter_execve tracepoint, collects exec events for a configurable duration, enriches each with parent PID, comm, and command line from /proc, and cleans up all managed eBPF state. Short-lived processes may exit before /proc enrichment completes, leaving parent_pid/comm/command_line empty — eBPF-level pid, tid, and ktime_ns are always captured. Use longer-duration processes or daemon workloads for full enrichment. Requires kernel eBPF support and CAP_BPF/CAP_SYS_ADMIN or equivalent.
// tags: ebpf, process-monitor, ringbuf, tracepoint, exec, self-contained

var prefix = args.prefix || "procMon";
var durationMs = args.duration_ms || 5000;
var mapHandle = prefix + "Events";
var progHandle = prefix + "Prog";
var linkHandle = prefix + "Link";
var readerHandle = prefix + "Reader";
var pollTimeoutMs = args.poll_timeout_ms || 250;

// ringbuf max_entries must be a power-of-two multiple of page size.
// Provide ring_pages (default 64 pages = 256 KiB on 4k-pages hosts).
var ringPages = args.ring_pages || 64;
var pageSize = 4096;
try {
  var uname = sys.uname();
  var clockTicks = sys.sysconf({name: "_SC_PAGESIZE"});
  if (clockTicks.ok && clockTicks.value > 0) pageSize = clockTicks.value;
} catch (e) {}
var ringSize = ringPages * pageSize;

var result = {
  ok: false,
  info: sys.ebpfInfo(),
  duration_ms: durationMs,
  events: [],
  setup: []
};

var createdMap = false;
var createdProg = false;
var createdLink = false;
var createdReader = false;

// ------------- helpers -------------

function failEarly(msg) {
  result.error = msg;
  cleanup();
  return result;
}

function cleanup() {
  if (createdReader) {
    try { sys.ebpfRingbufClose({reader: readerHandle}); } catch (e) {}
    createdReader = false;
  }
  if (createdLink) {
    try { sys.ebpfLinkClose({link: linkHandle}); } catch (e) {}
    createdLink = false;
  }
  if (createdProg) {
    try { sys.ebpfProgramClose({program: progHandle}); } catch (e) {}
    createdProg = false;
  }
  if (createdMap) {
    try { sys.ebpfMapClose({map: mapHandle}); } catch (e) {}
    createdMap = false;
  }
}

function safeSetup(call) {
  result.setup.push(call);
  var actual = call.call || call;
  if (!actual.ok) {
    result.error = "setup failed: " + JSON.stringify(actual);
    cleanup();
    return false;
  }
  if (call.step === "map_create") createdMap = true;
  if (call.step === "program_load") createdProg = true;
  if (call.step === "attach") createdLink = true;
  if (call.step === "reader_create") createdReader = true;
  return true;
}

function parentInfoFor(pid) {
  try {
    var stat = os.readFile({name: "/proc/" + pid + "/stat", encoding: "utf8"});
    if (!stat.ok) return {parent_pid: 0, comm: ""};
    var parts = stat.data_utf8.split(" ");
    if (parts.length < 4) return {parent_pid: 0, comm: ""};
    var ppid = parseInt(parts[3], 10);
    var comm = (parts[1] || "").replace(/^\(/, "").replace(/\)$/, "");
    return {parent_pid: isNaN(ppid) ? 0 : ppid, comm: comm};
  } catch (e) {
    return {parent_pid: 0, comm: ""};
  }
}

function commandLineFor(pid) {
  try {
    var cmd = os.readFile({name: "/proc/" + pid + "/cmdline", encoding: "utf8"});
    if (!cmd.ok) return "";
    return (cmd.data_utf8 || "").replace(/\0/g, " ").trim();
  } catch (e) {
    return "";
  }
}

function isIdleRingbufPoll(read) {
  if (read.errno_name === "EAGAIN" || read.errno_name === "ETIMEDOUT") return true;
  if (read.errno === 11 || read.errno === 110) return true;
  var text = String(read.error || read.error_name || "").toLowerCase();
  return text.indexOf("timeout") >= 0 || text.indexOf("deadline") >= 0;
}

// ------------- probe -------------

var featProg = sys.ebpfFeatureProbe({kind: "program_type", type: "tracepoint"});
var featMap = sys.ebpfFeatureProbe({kind: "map_type", type: "ringbuf"});
result.feature = {program_type: featProg, map_type: featMap};

if (featProg.ok && featProg.supported === false) {
  return failEarly("tracepoint eBPF programs are not supported by this kernel");
}
if (featMap.ok && featMap.supported === false) {
  return failEarly("ringbuf maps are not supported by this kernel");
}

// ------------- setup -------------

var mapRes = sys.ebpfMapCreate({
  handle: mapHandle,
  type: "ringbuf",
  key_size: 0,
  value_size: 0,
  max_entries: ringSize
});
if (!safeSetup({step: "map_create", call: mapRes})) return result;

var prog = sys.ebpfProgramLoad({
  handle: progHandle,
  kind: "ringbuf_event",
  type: "tracepoint",
  event_map: mapHandle,
  log_level: "BPF_LOG_LEVEL1",
  log_size_start: 65536
});
if (!safeSetup({step: "program_load", call: prog})) return result;

var tp = args.tracepoint || "syscalls/sys_enter_execve";
var parts = tp.split("/");
if (parts.length < 2) return failEarly("tracepoint must be group/name, e.g. syscalls/sys_enter_execve");
var tpGroup = parts[0];
var tpName = parts[1];

var link = sys.ebpfAttachTracepoint({
  handle: linkHandle,
  program: progHandle,
  group: tpGroup,
  name: tpName
});
if (!safeSetup({step: "attach", call: link})) return result;

var readerRes = sys.ebpfRingbufReaderCreate({
  handle: readerHandle,
  map: mapHandle
});
if (!safeSetup({step: "reader_create", reader: readerHandle, call: readerRes})) return result;

// ------------- collect -------------

var deadline = Date.now() + durationMs;
while (Date.now() < deadline) {
  var remaining = Math.max(1, deadline - Date.now());
  var pollMs = Math.min(pollTimeoutMs, remaining);
  var read = sys.ebpfRingbufRead({reader: readerHandle, timeout_ms: pollMs, encoding: "hex"});
  if (!read.ok) {
    if (isIdleRingbufPoll(read)) {
      continue;
    }
    break;
  }
  var event = {
    ktime_ns: read.ktime_ns,
    pid: read.pid,
    tid: read.tid,
    pid_tgid: read.pid_tgid
  };
  var parent = parentInfoFor(event.pid);
  event.parent_pid = parent.parent_pid;
  event.comm = parent.comm;
  event.command_line = commandLineFor(event.pid);
  result.events.push(event);
}

// ------------- cleanup -------------

cleanup();

result.ok = true;
return result;