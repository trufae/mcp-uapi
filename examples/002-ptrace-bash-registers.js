// name: ptrace_bash_registers
// title: Ptrace PoC — spawn bash, attach, read registers
// description: Spawns a new bash process, attaches with ptrace, reads register values via sys.ptraceGetRegs (architecture-agnostic), then detaches and cleans up.
// tags: ptrace, process, registers

// ── Step 1: Spawn a bash process ──────────────────────────────────
console.log("[1/4] Spawning /bin/bash...");
const proc = os.startProcess({
  name: "/bin/bash",
  argv: ["/bin/bash", "-c", "sleep 10"],
  handle: "bash_target"
});

if (!proc.ok) {
  return {error: "failed to spawn bash", detail: proc};
}

const pid = proc.pid;
console.log("  bash spawned, pid:", pid);

// ── Step 2: Attach with ptrace ────────────────────────────────────
console.log("[2/4] Attaching with ptrace...");
const attach = sys.ptraceAttach({pid: pid, wait: true, timeout_ms: 5000});

if (!attach.ok) {
  // Clean up on failure
  os.processKill({handle: "bash_target"});
  os.processRelease({handle: "bash_target"});
  return {error: "ptrace attach failed", detail: attach, pid: pid};
}
console.log("  attached, waited_pid:", attach.waited_pid);

// ── Step 3: Read register values ──────────────────────────────────
console.log("[3/4] Reading register values...");

// sys.ptraceGetRegs returns architecture-aware registers and
// normalized syscall metadata (nr, name, args, retval, pc, sp).
// No need to hardcode register layouts per architecture.
const regsResult = sys.ptraceGetRegs({pid: pid});

let registers = null;
if (regsResult.ok) {
  registers = {
    arch: regsResult.arch || "unknown",
    registers: regsResult.registers || null,
    syscall: regsResult.syscall || null
  };
  if (regsResult.syscall) {
    console.log("  syscall nr:", regsResult.syscall.nr,
                "name:", regsResult.syscall.name || "(unknown)",
                "args:", JSON.stringify(regsResult.syscall.args),
                "sp:", regsResult.syscall.sp,
                "pc:", regsResult.syscall.pc);
  }
} else {
  console.log("  ptraceGetRegs failed:", regsResult.error);
}

// Also read /proc/<pid>/stat for additional process state context
const statPath = "/proc/" + pid + "/stat";
const statRaw = os.readFile({name: statPath, encoding: "utf8"});

// Parse key fields from /proc/<pid>/stat (pid, comm, state, ppid, ...)
let statParsed = null;
if (statRaw.ok && statRaw.data_utf8) {
  // stat format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
  const match = statRaw.data_utf8.match(/^(\d+)\s+\((.+)\)\s+(\w)\s+(\d+)/);
  if (match) {
    const statTokens = statRaw.data_utf8.split(/\s+/);
    statParsed = {
      pid: parseInt(match[1]),
      comm: match[2],
      state: match[3],
      ppid: parseInt(match[4]),
      // These fields are at known fixed positions after comm
      pgrp: statTokens[4] || null,
      session: statTokens[5] || null,
      tty_nr: statTokens[6] || null,
      tpgid: statTokens[7] || null,
      flags: statTokens[8] ? parseInt(statTokens[8]) : null,
      minflt: statTokens[9] || null,
      cminflt: statTokens[10] || null,
      majflt: statTokens[11] || null,
      cmajflt: statTokens[12] || null,
      utime: statTokens[13] || null,
      stime: statTokens[14] || null,
      // kstkesp (kernel stack pointer) at index 28
      kstkesp: statTokens[28] || null,
      kstkeip: statTokens[29] || null,
    };
  }
}

// ── Step 4: Detach and clean up ───────────────────────────────────
console.log("[4/4] Detaching and cleaning up...");
const detach = sys.ptraceDetach({pid: pid});

// Kill the bash process since we no longer need it
os.processKill({handle: "bash_target"});

// Release process handle
os.processRelease({handle: "bash_target"});

return {
  ok: true,
  spawned: {
    pid: pid,
    handle: proc.handle
  },
  attach: {
    attached: attach.attached,
    wait_status: attach.status || null
  },
  registers: registers,
  proc_stat: statParsed,
  proc_stat_raw: statRaw.ok ? statRaw.data_utf8 : null,
  detach: {
    detached: detach.ok && detach.detached === true
  }
};