// name: process_memory_env_scanner
// title: Process memory env var scanner with processVMReadv
// description: Spawns a target process, reads /proc/<pid>/maps to locate the [stack] region, scans the entire stack with processVMReadv in chunks, extracts KEY=VALUE environment variables via null-byte splitting and regex matching.
// tags: process, memory, processVMReadv, env

// ── Step 1: Spawn target process with known env vars ─────────────
console.log("[1/4] Spawning target process...");
const proc = os.startProcess({
  name: "/bin/bash",
  argv: ["/bin/bash", "-c", "env; sleep 30"],
  handle: "scan_target",
  env: [
    "MY_TEST_VAR=hello_world_from_env",
    "ANOTHER_SECRET=xyzzy123",
    "SOME_NUMBER=42",
    'QUOTED_VAL="with spaces and = signs"',
  ],
});

if (!proc.ok) {
  return {error: "failed to spawn target process", detail: proc};
}
const pid = proc.pid;
console.log("  PID:", pid);

// ── Step 2: Locate [stack] region from /proc/<pid>/maps ──────────
console.log("[2/4] Reading /proc/" + pid + "/maps for [stack] region...");
const mapsRaw = os.readFile({name: "/proc/" + pid + "/maps", encoding: "utf8"});
if (!mapsRaw.ok) {
  os.processKill({handle: "scan_target"});
  os.processRelease({handle: "scan_target"});
  return {error: "failed to read maps", detail: mapsRaw};
}

let stackStart = null, stackEnd = null;
for (const line of mapsRaw.data_utf8.split("\n")) {
  const m = line.match(/^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s*\[stack\]/);
  if (m) {
    stackStart = parseInt(m[1], 16);
    stackEnd = parseInt(m[2], 16);
    break;
  }
}

if (!stackStart) {
  os.processKill({handle: "scan_target"});
  os.processRelease({handle: "scan_target"});
  return {error: "no [stack] region found in maps", maps: mapsRaw.data_utf8};
}

const stackSizeKb = (stackEnd - stackStart) / 1024;
console.log("  Stack: 0x" + stackStart.toString(16) + " - 0x" + stackEnd.toString(16) + " (" + stackSizeKb + " KB)");

// ── Step 3: Scan entire stack with processVMReadv in 8 KB chunks ─
console.log("[3/4] Scanning stack memory with processVMReadv...");
const CHUNK = 8192;
let allHex = "";

for (let addr = stackStart; addr < stackEnd; addr += CHUNK) {
  const len = Math.min(CHUNK, stackEnd - addr);
  const res = sys.processVMReadv({
    pid: pid,
    address: addr,
    length: len,
    encoding: "hex",
  });
  if (res.ok && res.data_hex) {
    allHex += res.data_hex;
  }
}

const totalBytes = allHex.length / 2;
console.log("  Read", totalBytes, "bytes");

// ── Step 4: Decode, null-split, regex-filter env vars ────────────
console.log("[4/4] Extracting environment variables...");

// Convert hex to a sentinel-delimited view: printable ASCII stays,
// everything else becomes \x00 (the Linux env var terminator).
let sentinelView = "";
for (let i = 0; i < allHex.length; i += 2) {
  const b = parseInt(allHex.substr(i, 2), 16);
  sentinelView += (b >= 32 && b <= 126) ? String.fromCharCode(b) : "\x00";
}

// Split on null bytes and filter for KEY=VALUE pattern
const envRegex = /^[A-Za-z_][A-Za-z0-9_]*=.+$/;
const envVars = sentinelView.split("\x00").filter(function(s) {
  return s.length >= 3 && envRegex.test(s);
});

console.log("  Found", envVars.length, "environment variables");
for (var i = 0; i < envVars.length; i++) {
  console.log("    " + envVars[i]);
}

// ── Cleanup ──────────────────────────────────────────────────────
os.processKill({handle: "scan_target"});
os.processRelease({handle: "scan_target"});

return {
  pid: pid,
  stack: {
    start: "0x" + stackStart.toString(16),
    end: "0x" + stackEnd.toString(16),
    size_kb: stackSizeKb,
  },
  bytes_read: totalBytes,
  environment_variables: envVars,
};