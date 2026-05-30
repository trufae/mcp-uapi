// name: ebpf_process_exec_monitor
// title: eBPF process exec monitor via tracepoint
// description: Attaches a ringbuf_event eBPF program to the syscalls:sys_enter_execve tracepoint, queues each event briefly so execve can complete, enriches it with parent PID, comm, and command line from /proc with retries, and cleans up all managed eBPF state. Very short-lived processes may still exit before /proc enrichment completes, leaving parent_pid/comm/command_line empty; eBPF-level pid, tid, and ktime_ns are always captured. Requires kernel eBPF support and CAP_BPF/CAP_SYS_ADMIN or equivalent.
// tags: ebpf, process-monitor, ringbuf, tracepoint, exec, self-contained

var prefix = args.prefix || "procMon";
var durationMs = args.duration_ms || 5000;
var mapHandle = prefix + "Events";
var progHandle = prefix + "Prog";
var linkHandle = prefix + "Link";
var readerHandle = prefix + "Reader";
var tracepoint = args.tracepoint || "syscalls/sys_enter_execve";
var pollTimeoutMs = args.poll_timeout_ms || 250;
var enrichDelayMs = args.enrich_delay_ms;
if (enrichDelayMs === undefined || enrichDelayMs === null) {
  enrichDelayMs = tracepoint === "syscalls/sys_enter_execve" ? 25 : 0;
}
var enrichRetries = args.enrich_retries;
if (enrichRetries === undefined || enrichRetries === null) enrichRetries = 8;
var enrichRetryMs = args.enrich_retry_ms;
if (enrichRetryMs === undefined || enrichRetryMs === null) enrichRetryMs = 10;

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
  enrich: {
    delay_ms: enrichDelayMs,
    retries: enrichRetries,
    retry_ms: enrichRetryMs
  },
  events: [],
  setup: []
};

function pidNamespaceInfo() {
  var out = {ok: false};
  try {
    var stat = os.stat({name: "/proc/self/ns/pid"});
    if (stat.ok && stat.info && stat.info.stat) {
      out.ok = true;
      out.dev = stat.info.stat.dev;
      out.ino = stat.info.stat.ino;
    }
    var link = os.readlink({name: "/proc/self/ns/pid"});
    if (link.ok) out.target = link.target;
  } catch (e) {}
  return out;
}

result.pid_namespace = pidNamespaceInfo();

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

function sleepMs(ms) {
  if (!ms || ms <= 0) return;
  try { sys.nanosleep({duration_ms: ms}); } catch (e) {}
}

function infoFor(pid) {
  var out = {ok: false, parent_pid: 0, comm: "", command_line: ""};
  try {
    var stat = os.readFile({name: "/proc/" + pid + "/stat", encoding: "utf8"});
    if (!stat.ok) return out;
    var text = stat.data_utf8 || "";
    var open = text.indexOf("(");
    var close = text.lastIndexOf(")");
    if (open < 0 || close <= open) return out;
    out.comm = text.substring(open + 1, close);
    var rest = text.substring(close + 2).split(" ");
    if (rest.length >= 2) {
      var ppid = parseInt(rest[1], 10);
      out.parent_pid = isNaN(ppid) ? 0 : ppid;
    }
  } catch (e) { return out; }

  try {
    var cmd = os.readFile({name: "/proc/" + pid + "/cmdline", encoding: "utf8"});
    if (cmd.ok) out.command_line = (cmd.data_utf8 || "").replace(/\0/g, " ").trim();
  } catch (e) {}

  out.ok = true;
  return out;
}

function parentInfoFor(ppid) {
  return infoFor(ppid);
}

function tryEnrichEvent(event) {
  if (event._enrich_started_ms === undefined) {
    event._enrich_started_ms = Date.now();
    event.enrich_attempts = 0;
  }
  event.enrich_attempts++;

  var childInfo = infoFor(event.pid);
  event.parent_pid = childInfo.parent_pid;
  event.comm = childInfo.comm;
  event.command_line = childInfo.command_line;
  event.proc_stat_ok = childInfo.ok && childInfo.comm !== "";
  event.proc_cmdline_ok = childInfo.ok && childInfo.command_line !== "";

  // Resolve parent comm and command line if we have a parent PID
  if (childInfo.parent_pid > 0) {
    var parentInfo = infoFor(childInfo.parent_pid);
    event.parent_comm = parentInfo.comm;
    event.parent_command_line = parentInfo.command_line;
    event.parent_proc_stat_ok = parentInfo.ok && parentInfo.comm !== "";
    event.parent_proc_cmdline_ok = parentInfo.ok && parentInfo.command_line !== "";
  } else {
    event.parent_comm = "";
    event.parent_command_line = "";
    event.parent_proc_stat_ok = false;
    event.parent_proc_cmdline_ok = false;
  }

  event.enrich_elapsed_ms = Date.now() - event._enrich_started_ms;

  // Consider enriched if we got child comm and command_line
  var childDone = event.proc_stat_ok && event.proc_cmdline_ok;
  return childDone || event.enrich_attempts > enrichRetries;
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
  pidns_dev: result.pid_namespace.ok ? result.pid_namespace.dev : 0,
  pidns_ino: result.pid_namespace.ok ? result.pid_namespace.ino : 0,
  log_level: "BPF_LOG_LEVEL1",
  log_size_start: 65536
});
if (!prog.ok && result.pid_namespace.ok) {
  result.setup.push({step: "program_load_namespace", call: prog});
  prog = sys.ebpfProgramLoad({
    handle: progHandle,
    kind: "ringbuf_event",
    type: "tracepoint",
    event_map: mapHandle,
    log_level: "BPF_LOG_LEVEL1",
    log_size_start: 65536
  });
  result.pid_namespace.fallback = true;
}
if (!safeSetup({step: "program_load", call: prog})) return result;

var parts = tracepoint.split("/");
if (parts.length < 2) return failEarly("tracepoint must be group/name, e.g. syscalls/sys_enter_execve");
var tpGroup = parts[0];
var tpName = parts[1];
result.tracepoint = tpGroup + "/" + tpName;

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

var pending = [];

function nextPendingDelayMs() {
  if (pending.length === 0) return null;
  var now = Date.now();
  var next = pending[0].ready_at_ms;
  for (var i = 1; i < pending.length; i++) {
    if (pending[i].ready_at_ms < next) next = pending[i].ready_at_ms;
  }
  return Math.max(0, next - now);
}

function drainReadyEvents(force) {
  var kept = [];
  for (var i = 0; i < pending.length; i++) {
    var item = pending[i];
    var waitMs = item.ready_at_ms - Date.now();
    if (!force && waitMs > 0) {
      kept.push(item);
      continue;
    }
    if (force && waitMs > 0) sleepMs(waitMs);
    if (tryEnrichEvent(item.event)) {
      delete item.event._enrich_started_ms;
      result.events.push(item.event);
    } else {
      item.ready_at_ms = Date.now() + enrichRetryMs;
      kept.push(item);
    }
  }
  pending = kept;
}

function drainAllPendingEvents() {
  while (pending.length > 0) {
    drainReadyEvents(true);
  }
}

var deadline = Date.now() + durationMs;
while (Date.now() < deadline) {
  drainReadyEvents(false);
  var remaining = Math.max(1, deadline - Date.now());
  var pollMs = Math.min(pollTimeoutMs, remaining);
  var pendingDelay = nextPendingDelayMs();
  if (pendingDelay !== null) pollMs = Math.min(pollMs, Math.max(1, pendingDelay));
  var read = sys.ebpfRingbufRead({reader: readerHandle, timeout_ms: pollMs, encoding: "hex"});
  if (!read.ok) {
    if (isIdleRingbufPoll(read)) {
      drainReadyEvents(false);
      continue;
    }
    result.read_error = read;
    break;
  }
  var eventPid = read.ns_pid || read.pid;
  var eventTid = read.ns_tid || read.tid;
  var event = {
    ktime_ns: read.ktime_ns,
    pid: eventPid,
    tid: eventTid,
    kernel_pid: read.pid,
    kernel_tid: read.tid,
    pid_tgid: read.pid_tgid,
    ns_pid_tgid: read.ns_pid_tgid || 0,
    observed_at_ms: Date.now()
  };
  pending.push({event: event, ready_at_ms: Date.now() + enrichDelayMs});
}
drainAllPendingEvents();

// ------------- cleanup -------------

cleanup();

result.ok = true;
return result;