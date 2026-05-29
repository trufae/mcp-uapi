// name: strace_syscall_trace
// title: strace-like syscall tracer using ptrace
// description: Attaches to a target PID, uses ptrace syscall stops plus ptrace register reads to print syscall names, arguments, and return values, then detaches cleanly. Does not kill the target process.
// tags: strace, ptrace, syscall, registers, process

// Configuration
var targetPid = args.pid || 292;
var maxEvents = args.max_events || 25;
var maxSeconds = args.max_seconds || 10;
var attachTimeoutMs = args.attach_timeout_ms || 5000;
var waitTimeoutMs = args.wait_timeout_ms || 1000;
var detachTimeoutMs = args.detach_timeout_ms || 2000;
var includeArgs = args.include_args !== false;

if (typeof targetPid !== "number" || targetPid < 1) {
  return {error: "pid must be a positive integer"};
}

function syscallName(syscall) {
  if (syscall && syscall.name) return syscall.name;
  if (syscall && typeof syscall.nr !== "undefined") return "sys_" + syscall.nr;
  return "sys_unknown";
}

function smallHexToNumber(hex) {
  if (typeof hex !== "string") return null;
  var n = parseInt(hex, 16);
  return isNaN(n) ? null : n;
}

function formatArgs(values) {
  if (!includeArgs) return "...";
  if (!values || values.length === 0) return "";
  return values.join(", ");
}

function formatReturn(syscall) {
  if (!syscall || !syscall.retval) return "?";
  if (syscall.retval_errno) return syscall.retval_signed + " " + syscall.retval_errno;
  var small = smallHexToNumber(syscall.retval);
  if (small !== null && small <= 4096) return String(small);
  return syscall.retval;
}

function processLines(pid) {
  var status = os.readFile({name: "/proc/" + pid + "/status", encoding: "utf8"});
  var out = {state: "?", tracer: "?", seccomp: "?", name: "?"};
  if (!status.ok) return out;
  var lines = status.data_utf8.split("\n");
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].indexOf("Name:") === 0) out.name = lines[i].trim();
    if (lines[i].indexOf("State:") === 0) out.state = lines[i].trim();
    if (lines[i].indexOf("TracerPid:") === 0) out.tracer = lines[i].trim();
    if (lines[i].indexOf("Seccomp:") === 0) out.seccomp = lines[i].trim();
  }
  return out;
}

function isSyscallStop(status) {
  if (!status || !status.stopped) return false;
  return status.stop_signal === 133 || status.stop_signal === 5;
}

function statusSummary(status) {
  if (!status) return "unknown";
  if (status.exited) return "exited(" + status.exit_status + ")";
  if (status.signaled) return "signaled(" + status.signal + ")";
  if (status.stopped) return "stopped(" + status.stop_signal + ")";
  if (status.continued) return "continued";
  return "raw=" + status.raw;
}

function prepareStoppedDetach(pid, alreadyStopped) {
  if (alreadyStopped) {
    return {already_stopped: true, wait: null};
  }

  var probe = sys.wait4({pid: pid, options: "WUNTRACED|WNOHANG", timeout_ms: 0});
  if (probe.ok && probe.waited_pid === pid && probe.status && probe.status.stopped) {
    return {already_stopped: true, wait: probe};
  }

  var stop = sys.kill({pid: pid, signal: "SIGSTOP"});
  var wait = sys.wait4({pid: pid, options: "WUNTRACED", timeout_ms: detachTimeoutMs});
  return {already_stopped: false, sent_stop: stop.ok === true, stop: stop, wait: wait};
}

var uname = sys.uname();
var before = processLines(targetPid);
console.log("[probe] pid", targetPid, "machine", uname.machine || "?", "|", before.name, "|", before.state, "|", before.tracer, "|", before.seccomp);

var attached = false;
var targetExited = false;
var detachResult = null;
var detachPrep = null;
var resumeResult = null;
var traceeStopped = false;
var events = [];
var summary = {};
var start = Date.now();

try {
  var attach = sys.ptraceAttach({pid: targetPid, wait: true, timeout_ms: attachTimeoutMs});
  if (!attach.ok) {
    return {ok: false, error: "ptrace attach failed", detail: attach, target: {pid: targetPid, status: before}};
  }
  attached = true;
  traceeStopped = true;
  console.log("[attach] ok", statusSummary(attach.status));

  var options = sys.ptraceSetOptions({pid: targetPid, options: "PTRACE_O_TRACESYSGOOD"});
  if (!options.ok) console.warn("[options] PTRACE_O_TRACESYSGOOD failed:", options.error);

  console.log("[trace] max", maxEvents, "syscalls,", maxSeconds + "s");
  console.log("---");

  var pendingSignal = 0;
  for (var i = 0; i < maxEvents; i++) {
    if (Date.now() - start > maxSeconds * 1000) {
      console.log("  (time limit reached)");
      break;
    }

    var enterStep = sys.ptraceSyscall({pid: targetPid, signal: pendingSignal});
    pendingSignal = 0;
    if (!enterStep.ok) {
      console.log("  ptraceSyscall(entry):", enterStep.error);
      break;
    }
    traceeStopped = false;

    var enterWait = sys.wait4({pid: targetPid, options: "WUNTRACED", timeout_ms: waitTimeoutMs});
    if (!enterWait.ok) {
      console.log("  wait4(entry):", enterWait.error);
      break;
    }
    if (enterWait.status && (enterWait.status.exited || enterWait.status.signaled)) {
      targetExited = true;
      console.log("  target", statusSummary(enterWait.status));
      break;
    }
    traceeStopped = true;
    if (!isSyscallStop(enterWait.status)) {
      pendingSignal = enterWait.status && enterWait.status.stopped ? enterWait.status.stop_signal : 0;
      console.log("  signal-stop", statusSummary(enterWait.status));
      i--;
      continue;
    }

    var enterRegs = sys.ptraceGetRegs({pid: targetPid});
    if (!enterRegs.ok || !enterRegs.syscall) {
      console.log("  ptraceGetRegs(entry):", enterRegs.error || "no syscall ABI mapping");
      break;
    }

    var sc = enterRegs.syscall;
    var name = syscallName(sc);
    var event = {
      nr: sc.nr,
      name: name,
      args: includeArgs ? (sc.args || []) : [],
      arch: enterRegs.arch,
      pc: sc.pc || null
    };

    var exitStep = sys.ptraceSyscall({pid: targetPid, signal: 0});
    if (!exitStep.ok) {
      console.log(name + "(" + formatArgs(event.args) + ") = ?  # ptraceSyscall(exit): " + exitStep.error);
      events.push(event);
      break;
    }
    traceeStopped = false;

    var exitWait = sys.wait4({pid: targetPid, options: "WUNTRACED", timeout_ms: waitTimeoutMs});
    if (!exitWait.ok) {
      console.log(name + "(" + formatArgs(event.args) + ") = ?  # wait4(exit): " + exitWait.error);
      events.push(event);
      break;
    }
    if (exitWait.status && (exitWait.status.exited || exitWait.status.signaled)) {
      targetExited = true;
      console.log(name + "(" + formatArgs(event.args) + ") = ?  # target " + statusSummary(exitWait.status));
      events.push(event);
      break;
    }
    traceeStopped = true;
    if (!isSyscallStop(exitWait.status)) {
      pendingSignal = exitWait.status && exitWait.status.stopped ? exitWait.status.stop_signal : 0;
      console.log(name + "(" + formatArgs(event.args) + ") = ?  # signal-stop " + statusSummary(exitWait.status));
      events.push(event);
      continue;
    }

    var exitRegs = sys.ptraceGetRegs({pid: targetPid});
    if (exitRegs.ok && exitRegs.syscall) {
      event.retval = exitRegs.syscall.retval || null;
      event.retval_signed = exitRegs.syscall.retval_signed || null;
      event.retval_errno = exitRegs.syscall.retval_errno || null;
      console.log(name + "(" + formatArgs(event.args) + ") = " + formatReturn(exitRegs.syscall));
    } else {
      console.log(name + "(" + formatArgs(event.args) + ") = ?");
    }

    events.push(event);
    summary[name] = (summary[name] || 0) + 1;
  }
} finally {
  if (attached && !targetExited) {
    console.log("---");
    detachPrep = prepareStoppedDetach(targetPid, traceeStopped);
    if (detachPrep.wait && detachPrep.wait.status) {
      console.log("[detach] prepared", statusSummary(detachPrep.wait.status));
    }
    detachResult = sys.ptraceDetach({pid: targetPid});
    console.log("[detach]", detachResult.ok ? "ok" : detachResult.error);
    if (detachResult.ok && detachPrep && detachPrep.sent_stop && before.state.indexOf("(stopped)") < 0) {
      resumeResult = sys.kill({pid: targetPid, signal: "SIGCONT"});
      console.log("[resume]", resumeResult.ok ? "ok" : resumeResult.error);
    }
  }
}

var after = processLines(targetPid);
var durationMS = Date.now() - start;
console.log("[done]", events.length, "syscalls in", (durationMS / 1000).toFixed(2) + "s", "|", after.tracer, "|", after.state);

return {
  ok: true,
  target: {pid: targetPid, before: before, after: after},
  arch: uname.machine || "unknown",
  events: events,
  event_count: events.length,
  summary: summary,
  detach: {
    ok: targetExited || (detachResult ? detachResult.ok : false),
    target_exited: targetExited,
    prep: detachPrep,
    resume: resumeResult,
    result: detachResult
  },
  duration_ms: durationMS
};
