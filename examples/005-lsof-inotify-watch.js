// name: lsof_inotify_watch
// title: lsof-style open file listing with inotify-based write/create detection
// description: Enumerates all open file descriptors for a target PID (lsof), categorises by type (file, socket, pipe, anon_inode, etc.), and optionally monitors directories containing opened files for IN_CREATE / IN_CLOSE_WRITE / IN_MODIFY events via inotify.
// tags: lsof, inotify, filesystem, process, watch

// ── Configuration ──────────────────────────────────────────────────
var pid = args.pid || sys.getpid().pid;
var watchEnabled = args.watch !== false; // enable inotify monitoring
var watchTimeoutMs = args.watch_timeout_ms || 5000;
var pollIntervalMs = args.poll_interval_ms || 250;

if (typeof pid !== "number" || pid < 1) {
  return {error: "pid must be a positive integer"};
}

var fdPath = "/proc/" + pid + "/fd";

// ── Helper: classify an fd link target ─────────────────────────────
function classifyTarget(target) {
  if (!target || target === "?") return "unknown";
  if (target.startsWith("/")) return "file";
  if (target.startsWith("socket:[")) return "socket";
  if (target.startsWith("pipe:[")) return "pipe";
  if (target.startsWith("anon_inode:")) return "anon_inode";
  if (target.startsWith("/dev/")) return "device";
  return "other";
}

// ── Helper: map open flags from /proc/PID/fdinfo/N ─────────────────
function parseFlags(flagsStr) {
  if (!flagsStr) return [];
  var flags = parseInt(flagsStr, 8);
  var names = [];
  // Linux open.h flags (common subset)
  if (flags & 0o1) names.push("O_WRONLY");
  if (flags & 0o2) names.push("O_RDWR");
  if (flags & 0o100) names.push("O_CREAT");
  if (flags & 0o200) names.push("O_EXCL");
  if (flags & 0o400) names.push("O_NOCTTY");
  if (flags & 0o1000) names.push("O_TRUNC");
  if (flags & 0o2000) names.push("O_APPEND");
  if (flags & 0o4000) names.push("O_NONBLOCK");
  if (flags & 0o10000) names.push("O_DSYNC");
  if (flags & 0o40000) names.push("O_DIRECTORY");
  if (flags & 0o100000) names.push("O_NOFOLLOW");
  if (flags & 0o200000) names.push("O_CLOEXEC");
  if (flags & 0o400000) names.push("O_SYNC");
  if (flags & 0o1000000) names.push("O_PATH");
  if (flags & 0o2000000) names.push("O_TMPFILE");
  if (!(flags & 0o3)) names.push("O_RDONLY");
  return names;
}

function parseFdinfo(data) {
  var info = {};
  if (!data) return info;
  for (var _i = 0, _a = data.split("\n"); _i < _a.length; _i++) {
    var line = _a[_i];
    var idx = line.indexOf(":");
    if (idx < 0) continue;
    var key = line.substring(0, idx).trim();
    var val = line.substring(idx + 1).trim();
    info[key] = val;
  }
  return info;
}

console.log("lsof scan for PID:", pid);

// ── Step 1: List all FDs ───────────────────────────────────────────
var dir = os.readDir({name: fdPath});
if (!dir.ok) {
  return {error: "cannot read /proc/" + pid + "/fd", detail: dir};
}

var openFiles = [];
var dirsToWatch = {}; // dedup directories to watch with inotify

for (var ei = 0; ei < dir.entries.length; ei++) {
  var entry = dir.entries[ei];
  var fdNum = entry.name;
  var fullFdPath = fdPath + "/" + fdNum;

  var link = sys.readlink({path: fullFdPath});
  var target = link.ok ? link.target : "?";

  // Read fdinfo for position, flags, mount-id, inode
  var fdinfoRaw = os.readFile({name: "/proc/" + pid + "/fdinfo/" + fdNum, encoding: "utf8"});
  var fdinfo = parseFdinfo(fdinfoRaw.ok ? fdinfoRaw.data_utf8 : "");

  var category = classifyTarget(target);

  var entryData = {
    fd: parseInt(fdNum),
    target: target,
    category: category,
    flags: parseFlags(fdinfo.flags),
    pos: fdinfo.pos != null ? parseInt(fdinfo.pos) : null,
    mnt_id: fdinfo.mnt_id != null ? parseInt(fdinfo.mnt_id) : null,
    ino_fdinfo: fdinfo.ino != null ? parseInt(fdinfo.ino) : null,
  };

  // If it's a regular file, collect the directory for inotify
  if (category === "file" || category === "device") {
    var lastSlash = target.lastIndexOf("/");
    if (lastSlash > 0) {
      var dirname = target.substring(0, lastSlash);
      if (dirsToWatch[dirname] === undefined) {
        // Check if we can access it
        var canAccess = sys.access({path: dirname, mode: "R_OK"});
        dirsToWatch[dirname] = canAccess.ok;
      }
    }
  }

  openFiles.push(entryData);
}

console.log("Found", openFiles.length, "open file descriptors");

// ── Group by category ──────────────────────────────────────────────
var byCategory = {};
for (var ci = 0; ci < openFiles.length; ci++) {
  var cat = openFiles[ci].category;
  if (!byCategory[cat]) byCategory[cat] = [];
  byCategory[cat].push(openFiles[ci]);
}

// ── Step 2: Inotify monitoring ─────────────────────────────────────
var inotifyEvents = [];
var inotifyCycles = 0;

if (watchEnabled) {
  var watchableDirs = [];
  for (var d in dirsToWatch) {
    if (dirsToWatch[d]) watchableDirs.push(d);
  }

  console.log("Watchable directories:", watchableDirs.length);

  if (watchableDirs.length > 0) {
    // IN_NONBLOCK = 2048, IN_CLOEXEC = 524288
    var IN_NONBLOCK = 2048;
    var IN_CLOEXEC = 524288;

    var ino = sys.inotifyInit1({
      flags: IN_NONBLOCK | IN_CLOEXEC,
      handle: "lsof_inotify"
    });

    if (!ino.ok) {
      console.warn("inotify_init1 failed:", ino.error);
    } else {
      try {
        // Add watches for all directories
        var watchEntries = [];
        for (var di = 0; di < watchableDirs.length; di++) {
          var w = sys.inotifyAddWatch({
            handle: "lsof_inotify",
            path: watchableDirs[di],
            mask: "IN_CREATE|IN_CLOSE_WRITE|IN_MODIFY|IN_DELETE|IN_MOVED_TO|IN_MOVED_FROM"
          });
          if (w.ok) {
            watchEntries.push({dir: watchableDirs[di], wd: w.wd});
          }
        }
        console.log("Inotify watches:", watchEntries.length);

        // Event struct = 16 bytes header before name
        var EVENT_HEADER = 16;

        // Hex parsing helpers
        function readByte(h, off) { return parseInt(h.substr(off * 2, 2), 16); }
        function readU32LE(h, off) {
          return readByte(h, off) +
            (readByte(h, off + 1) << 8) +
            (readByte(h, off + 2) << 16) +
            (readByte(h, off + 3) * 0x1000000);
        }

        var IN_CREATE = 256;
        var IN_MODIFY = 2;
        var IN_CLOSE_WRITE = 8;
        var IN_DELETE = 512;
        var IN_MOVED_FROM = 64;
        var IN_MOVED_TO = 128;

        function maskLabel(m) {
          var names = [];
          if (m & IN_CREATE) names.push("IN_CREATE");
          if (m & IN_MODIFY) names.push("IN_MODIFY");
          if (m & IN_CLOSE_WRITE) names.push("IN_CLOSE_WRITE");
          if (m & IN_DELETE) names.push("IN_DELETE");
          if (m & IN_MOVED_FROM) names.push("IN_MOVED_FROM");
          if (m & IN_MOVED_TO) names.push("IN_MOVED_TO");
          return names.join(",");
        }

        // Poll loop
        var startTime = Date.now();
        while ((Date.now() - startTime) < watchTimeoutMs) {
          inotifyCycles++;
          var remaining = watchTimeoutMs - (Date.now() - startTime);
          var pollTimeout = Math.min(pollIntervalMs, Math.max(remaining, 0));

          var ready = sys.poll({
            fds: [{handle: "lsof_inotify", events: "POLLIN"}],
            timeout_ms: pollTimeout
          });

          if (!ready.ok) break;

          var fdInfo = ready.fds && ready.fds[0];
          if (!fdInfo || !(fdInfo.revents & 0x001)) continue;

          var data = sys.read({handle: "lsof_inotify", length: 4096, encoding: "hex"});
          if (!data.ok) {
            if (data.errno_name === "EAGAIN" || data.errno_name === "EWOULDBLOCK") continue;
            break;
          }

          var hex = data.data_hex;
          if (!hex || hex.length === 0) continue;

          var offset = 0;
          var totalBytes = hex.length / 2;
          while (offset + EVENT_HEADER <= totalBytes) {
            var wd = readU32LE(hex, offset);
            var mask = readU32LE(hex, offset + 4);
            var cookie = readU32LE(hex, offset + 8);
            var nameLen = readU32LE(hex, offset + 12);

            if (offset + EVENT_HEADER + nameLen > totalBytes) break;

            var name = "";
            if (nameLen > 0) {
              for (var ni = 0; ni < nameLen; ni++) {
                var ch = readByte(hex, offset + EVENT_HEADER + ni);
                if (ch === 0) break;
                name += String.fromCharCode(ch);
              }
            }

            // Find which directory this wd belongs to
            var dirName = "?";
            for (var wj = 0; wj < watchEntries.length; wj++) {
              if (watchEntries[wj].wd === wd) { dirName = watchEntries[wj].dir; break; }
            }

            if (name) {
              inotifyEvents.push({
                directory: dirName,
                file: name,
                mask_labels: maskLabel(mask),
                timestamp_ms: Date.now() - startTime
              });
            }

            offset += EVENT_HEADER + nameLen;
          }
        }
      } finally {
        sys.close({handle: "lsof_inotify"});
      }
    }
  }
}

// ── Result ─────────────────────────────────────────────────────────
return {
  pid: pid,
  total_fds: openFiles.length,
  by_category: byCategory,
  open_files: openFiles,
  inotify: {
    watchable_directories: Object.keys(dirsToWatch).filter(function(d) { return dirsToWatch[d]; }),
    watch_cycles: inotifyCycles,
    events: inotifyEvents,
    events_count: inotifyEvents.length
  }
};