// name: ps_remote_listing
// title: Remote process listing via ps axu piped through startProcess
// description: Runs `ps axu` via os.startProcess with a pipe for stdout (no temp file), reads the output directly from the pipe, and parses every row into structured JSON with USER, PID, %CPU, %MEM, VSZ, RSS, TTY, STAT, START, TIME, and COMMAND fields. Demonstrates os.pipe, os.startProcess files redirection, sys.wait4, and sys.read for an end-to-end subprocess capture workflow.
// tags: process, pipe, startProcess, ps, listing, remote

// ── Configuration ──────────────────────────────────────────────────
var psBin = args.ps_bin || "/usr/bin/ps";
var psArgs = args.ps_args || ["ps", "axu"];

// ── Step 1: Open /dev/null for stdin/stderr and create a pipe ─────
console.log("[1/4] Opening /dev/null and creating pipe...");
var suffix = "_" + Date.now();
var devNullR = os.openFile({ name: "/dev/null", flags: "O_RDONLY", handle: "psStdin" + suffix });
var devNullW = os.openFile({ name: "/dev/null", flags: "O_WRONLY", handle: "psStderr" + suffix });
var pipePair = os.pipe();

if (!devNullR.ok || !devNullW.ok || !pipePair.ok) {
  // Clean up anything that did succeed
  if (devNullR.ok) os.fileClose({ handle: devNullR.handle });
  if (devNullW.ok) os.fileClose({ handle: devNullW.handle });
  if (pipePair.ok) { os.fileClose({ handle: pipePair.handles[0] }); os.fileClose({ handle: pipePair.handles[1] }); }
  return { error: "setup failed", devNullR: devNullR, devNullW: devNullW, pipe: pipePair };
}

// ── Step 2: Start ps with stdout redirected into the pipe ──────────
console.log("[2/4] Starting " + psArgs.join(" ") + "...");
var proc = os.startProcess({
  name: psBin,
  argv: psArgs,
  files: [
    { handle: "psStdin" + suffix },       // fd 0: stdin  ← /dev/null (O_RDONLY)
    { handle: pipePair.handles[1] },       // fd 1: stdout → pipe write end
    { handle: "psStderr" + suffix }       // fd 2: stderr ← /dev/null (O_WRONLY)
  ],
  handle: "psProc" + suffix
});

// Close our end of the pipe write side and the devnull handles.
// The child process holds dup'd copies that outlive these closes.
os.fileClose({ handle: pipePair.handles[1] });
os.fileClose({ handle: "psStdin" + suffix });
os.fileClose({ handle: "psStderr" + suffix });

if (!proc.ok) {
  os.fileClose({ handle: pipePair.handles[0] });
  return { error: "startProcess failed", detail: proc };
}
console.log("  PID:", proc.pid);

// ── Step 3: Wait for the process, then read stdout from the pipe ──
console.log("[3/4] Waiting for ps to complete...");
var waitRes = sys.wait4({ pid: proc.pid, options: 0, timeout_ms: 5000 });

console.log("[4/4] Reading output from pipe...");
var output = sys.read({ handle: pipePair.handles[0], length: 131072, encoding: "utf8" });
os.fileClose({ handle: pipePair.handles[0] });

if (!output.ok) {
  return { error: "read failed", wait: waitRes, detail: output };
}

// ── Parse ps axu output ────────────────────────────────────────────
// Columns: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
var lines = output.data_utf8.split("\n");
var procs = [];
for (var i = 1; i < lines.length; i++) {
  var line = lines[i].trim();
  if (!line) continue;
  var m = line.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/);
  if (m) {
    procs.push({
      user:    m[1],
      pid:     parseInt(m[2]),
      cpu:     parseFloat(m[3]),
      mem:     parseFloat(m[4]),
      vsz:     parseInt(m[5]),
      rss:     parseInt(m[6]),
      tty:     m[7],
      stat:    m[8],
      start:   m[9],
      time:    m[10],
      command: m[11]
    });
  }
}

// ── Summary ─────────────────────────────────────────────────────────
var summary = {};
for (var j = 0; j < procs.length; j++) {
  var user = procs[j].user;
  summary[user] = (summary[user] || 0) + 1;
}

return {
  ok: true,
  header: lines[0],
  total: procs.length,
  by_user: summary,
  wait: {
    exit_code: waitRes.status ? waitRes.status.exit_status : null,
    signaled: waitRes.status ? waitRes.status.signaled : null
  },
  processes: procs
};