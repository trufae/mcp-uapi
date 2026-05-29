// name: ptrace_bash_registers
// title: Ptrace PoC — spawn bash, attach, read registers
// description: Spawns a new bash process, attaches with ptrace, reads register values via /proc/<pid>/syscall, then detaches and cleans up.
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

// /proc/<pid>/syscall exposes current register state:
//   syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc [status]
const syscallPath = "/proc/" + pid + "/syscall";
const syscallRaw = os.readFile({name: syscallPath, encoding: "utf8"});

let registers = null;
if (syscallRaw.ok && syscallRaw.data_utf8) {
  const parts = syscallRaw.data_utf8.trim().split(/\s+/);
  // First field is syscall number (often 0xfffffffffffffe00 = not in syscall)
  // followed by register values in hex
  const syscallNr = parts[0] || "";

  // Detect architecture from uname
  const uname = sys.uname();

  // Build register map based on architecture
  if (uname.machine && uname.machine.indexOf("x86_64") !== -1) {
    // x86_64: rax(syscall_nr), rdi, rsi, rdx, r10, r8, r9, rsp, rip
    registers = {
      arch: "x86_64",
      rax: parts[0] || null,   // syscall number / return value
      rdi: parts[1] || null,   // arg0
      rsi: parts[2] || null,   // arg1
      rdx: parts[3] || null,   // arg2
      r10: parts[4] || null,   // arg3
      r8:  parts[5] || null,   // arg4
      r9:  parts[6] || null,   // arg5
      rsp: parts[7] || null,   // stack pointer
      rip: parts[8] || null,   // instruction pointer
      raw: syscallRaw.data_utf8.trim()
    };
  } else if (uname.machine && uname.machine.indexOf("aarch64") !== -1) {
    // ARM64: x8(syscall_nr), x0-x5, sp, pc
    registers = {
      arch: "aarch64",
      x8:  parts[0] || null,   // syscall number
      x0:  parts[1] || null,
      x1:  parts[2] || null,
      x2:  parts[3] || null,
      x3:  parts[4] || null,
      x4:  parts[5] || null,
      x5:  parts[6] || null,
      sp:  parts[7] || null,   // stack pointer
      pc:  parts[8] || null,   // program counter
      raw: syscallRaw.data_utf8.trim()
    };
  } else if (uname.machine && uname.machine.indexOf("arm") !== -1) {
    // ARM32: r7(syscall_nr), r0-r5, sp, pc
    registers = {
      arch: "arm",
      r7:  parts[0] || null,   // syscall number
      r0:  parts[1] || null,
      r1:  parts[2] || null,
      r2:  parts[3] || null,
      r3:  parts[4] || null,
      r4:  parts[5] || null,
      r5:  parts[6] || null,
      sp:  parts[7] || null,   // stack pointer
      pc:  parts[8] || null,   // program counter
      raw: syscallRaw.data_utf8.trim()
    };
  } else {
    // Generic fallback
    registers = {
      arch: uname.machine || "unknown",
      syscall_nr: parts[0] || null,
      args: parts.slice(1),
      raw: syscallRaw.data_utf8.trim()
    };
  }
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