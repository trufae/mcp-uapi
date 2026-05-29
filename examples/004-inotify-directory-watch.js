// name: inotify_directory_watch
// title: Watch directory for file create/write/delete events with inotify
// description: Sets up an inotify watch on a directory, polls for IN_CREATE, IN_MODIFY, IN_CLOSE_WRITE, IN_DELETE, and IN_MOVED_TO/FROM events, reads raw inotify event structures, and parses them into a structured result.
// tags: inotify, filesystem, watch, poll

// ── Hex parsing helpers for inotify event structures ───────────────
function readByte(hex, offset) {
  return parseInt(hex.substr(offset * 2, 2), 16);
}

function readU32LE(hex, offset) {
  return readByte(hex, offset) +
    (readByte(hex, offset + 1) << 8) +
    (readByte(hex, offset + 2) << 16) +
    (readByte(hex, offset + 3) * 0x1000000);
}

// ── Mask bit constants matching linux/inotify.h ───────────────────
var IN_ACCESS = 1;
var IN_MODIFY = 2;
var IN_ATTRIB = 4;
var IN_CLOSE_WRITE = 8;
var IN_CLOSE_NOWRITE = 16;
var IN_OPEN = 32;
var IN_MOVED_FROM = 64;
var IN_MOVED_TO = 128;
var IN_CREATE = 256;
var IN_DELETE = 512;
var IN_DELETE_SELF = 1024;
var IN_MOVE_SELF = 2048;
var IN_ISDIR = 0x40000000;

function maskNames(m) {
  var names = [];
  if (m & IN_ACCESS) names.push("IN_ACCESS");
  if (m & IN_MODIFY) names.push("IN_MODIFY");
  if (m & IN_ATTRIB) names.push("IN_ATTRIB");
  if (m & IN_CLOSE_WRITE) names.push("IN_CLOSE_WRITE");
  if (m & IN_CLOSE_NOWRITE) names.push("IN_CLOSE_NOWRITE");
  if (m & IN_OPEN) names.push("IN_OPEN");
  if (m & IN_MOVED_FROM) names.push("IN_MOVED_FROM");
  if (m & IN_MOVED_TO) names.push("IN_MOVED_TO");
  if (m & IN_CREATE) names.push("IN_CREATE");
  if (m & IN_DELETE) names.push("IN_DELETE");
  if (m & IN_DELETE_SELF) names.push("IN_DELETE_SELF");
  if (m & IN_MOVE_SELF) names.push("IN_MOVE_SELF");
  if (m & IN_ISDIR) names.push("IN_ISDIR");
  return names;
}

// ── Configuration ──────────────────────────────────────────────────
var watchPath = args.path || "/tmp";
var timeoutMs = args.timeout_ms || 5000;
var pollIntervalMs = args.poll_interval_ms || 500;
// inotify event struct: 4+4+4+4 = 16 byte header before name
var EVENT_HEADER = 16;

// IN_NONBLOCK = 2048, IN_CLOEXEC = 524288
var IN_NONBLOCK = 2048;
var IN_CLOEXEC = 524288;

console.log("Watching directory:", watchPath);
console.log("Timeout:", timeoutMs, "ms, Poll interval:", pollIntervalMs, "ms");

// ── Step 1: Create inotify instance ────────────────────────────────
var ino = sys.inotifyInit1({
  flags: IN_NONBLOCK | IN_CLOEXEC,
  handle: "inotify_watch"
});
if (!ino.ok) {
  return {error: "inotify_init1 failed", detail: ino};
}
console.log("Inotify FD created, handle:", ino.handle);

try {
  // ── Step 2: Add watch on the target directory ────────────────────
  var watchMask = "IN_CREATE|IN_MODIFY|IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE|IN_MOVED_FROM";
  var watch = sys.inotifyAddWatch({
    handle: "inotify_watch",
    path: watchPath,
    mask: watchMask
  });
  if (!watch.ok) {
    return {error: "inotify_add_watch failed", detail: watch, path: watchPath};
  }
  console.log("Watch added, wd:", watch.wd, "mask:", watchMask);

  // ── Step 3: Poll loop ────────────────────────────────────────────
  var startTime = Date.now();
  var allEvents = [];
  var pollCycles = 0;

  while ((Date.now() - startTime) < timeoutMs) {
    pollCycles++;
    var remaining = timeoutMs - (Date.now() - startTime);
    var pollTimeout = Math.min(pollIntervalMs, Math.max(remaining, 0));

    var ready = sys.poll({
      fds: [{handle: "inotify_watch", events: "POLLIN"}],
      timeout_ms: pollTimeout
    });

    if (!ready.ok) {
      console.warn("Poll error:", ready.error);
      break;
    }

    // POLLIN revents bit = 0x001
    var fdInfo = ready.fds && ready.fds[0];
    if (!fdInfo || !(fdInfo.revents & 0x001)) {
      continue;
    }

    // ── Step 4: Read raw inotify events ────────────────────────────
    var data = sys.read({
      handle: "inotify_watch",
      length: 4096,
      encoding: "hex"
    });

    if (!data.ok) {
      if (data.errno_name === "EAGAIN" || data.errno_name === "EWOULDBLOCK") {
        continue;
      }
      console.warn("Read error:", data.error);
      break;
    }

    var hex = data.data_hex;
    if (!hex || hex.length === 0) {
      continue;
    }

    // ── Step 5: Parse inotify event structures ─────────────────────
    var offset = 0;
    var totalBytes = hex.length / 2;

    while (offset + EVENT_HEADER <= totalBytes) {
      var wd = readU32LE(hex, offset);
      var mask = readU32LE(hex, offset + 4);
      var cookie = readU32LE(hex, offset + 8);
      var nameLen = readU32LE(hex, offset + 12);

      if (offset + EVENT_HEADER + nameLen > totalBytes) break;

      // Extract filename (nameLen includes null terminator)
      var name = "";
      if (nameLen > 0) {
        for (var i = 0; i < nameLen; i++) {
          var ch = readByte(hex, offset + EVENT_HEADER + i);
          if (ch === 0) break;
          name += String.fromCharCode(ch);
        }
      }

      allEvents.push({
        wd: wd,
        mask: "0x" + mask.toString(16).padStart(8, "0"),
        mask_names: maskNames(mask),
        cookie: cookie,
        name: name
      });

      offset += EVENT_HEADER + nameLen;
    }
  }

  console.log("Poll cycles:", pollCycles, "Events collected:", allEvents.length);

  return {
    watched_path: watchPath,
    watch_descriptor: watch.wd,
    poll_cycles: pollCycles,
    total_events: allEvents.length,
    events: allEvents
  };

} finally {
  sys.close({handle: "inotify_watch"});
  console.log("Inotify instance closed.");
}