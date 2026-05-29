# sys/unix Vector I/O And Transfer

This resource covers vector I/O and kernel-to-kernel transfer wrappers: `readv`, `writev`, `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendmsg`, `recvmsg`, `splice`, `tee`, `vmsplice`, `sendfile`, and `copyFileRange`.

## Iovec Shape

Write-style iovecs accept the same byte sources as `sys.write`:

```javascript
{data_utf8: "text"}
{data_hex: "414243"}
{data_base64: "QUJD"}
{buffer: "payload", buffer_offset: 0, length: 64}
```

Read-style iovecs allocate bounded local buffers:

```javascript
{length: 128}
```

Read results include a combined encoded payload and an `iovecs` array with per-segment byte counts and encoded data. The total read allocation is bounded by `max_read_bytes`.

## File Example

```javascript
const fd = sys.memfdCreate({name: "vec", flags: "MFD_CLOEXEC", handle: "vec"});
try {
  const wrote = sys.writev({handle: "vec", iovecs: [
    {data_utf8: "alpha"},
    {data_utf8: ":"},
    {data_hex: "62657461"}
  ]});
  const read = sys.preadv({handle: "vec", offset: 0, iovecs: [{length: 6}, {length: 4}], encoding: "utf8"});
  return {wrote, read};
} finally {
  sys.close({handle: "vec"});
}
```

## Message Example

`sendmsg` and `recvmsg` support payload bytes, optional out-of-band bytes, optional destination sockaddrs, and Unix FD rights.

```javascript
const pair = sys.socketpair({handles: ["left", "right"]});
try {
  const sent = sys.sendmsg({handle: "left", data_utf8: "ping"});
  const got = sys.recvmsg({handle: "right", length: 4, encoding: "utf8"});
  return {sent, got};
} finally {
  sys.close({handle: "left"});
  sys.close({handle: "right"});
}
```

FD passing over Unix sockets:

```javascript
const pair = sys.socketpair({handles: ["send", "recv"]});
const file = sys.memfdCreate({name: "shared", flags: "MFD_CLOEXEC", handle: "shared"});
try {
  sys.sendmsg({handle: "send", data_utf8: "F", rights_handles: ["shared"]});
  const got = sys.recvmsg({handle: "recv", length: 1, oob_length: 256, parse_rights: true, encoding: "utf8"});
  return got.rights;
} finally {
  sys.close({handle: "send"});
  sys.close({handle: "recv"});
  sys.close({handle: "shared"});
}
```

## Pipe Transfer Example

```javascript
const pipeA = sys.pipe2({flags: "O_CLOEXEC", handles: ["aR", "aW"]});
const pipeB = sys.pipe2({flags: "O_CLOEXEC", handles: ["bR", "bW"]});
try {
  sys.write({handle: "aW", data_utf8: "splice"});
  const moved = sys.tee({in_handle: "aR", out_handle: "bW", length: 6});
  const copy = sys.read({handle: "bR", length: 6, encoding: "utf8"});
  return {moved, copy};
} finally {
  for (const handle of ["aR", "aW", "bR", "bW"]) sys.close({handle});
}
```

`splice` moves bytes between pipe and file/socket descriptors. `tee` duplicates bytes between pipes. `vmsplice` writes local iovecs into a pipe. These calls can block; use nonblocking flags and `sys.poll` for robust scripts.