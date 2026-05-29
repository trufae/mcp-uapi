# Examples

## Read A File

```json
{
  "name": "eval",
  "arguments": {
    "script": "const fd = sys.open({path:'/proc/version', flags:'O_RDONLY|O_CLOEXEC', handle:'version'}); try { return sys.read({handle: fd.handle, length:4096, encoding:'utf8'}); } finally { sys.close({handle: fd.handle}); }"
  }
}
```

## Anonymous Mmap

```json
{
  "name": "eval",
  "arguments": {
    "script": "const mapped = sys.mmap({length:4096, handle:'scratch'}); sys.memWrite({mapping:'scratch', data_hex:'41424344'}); const got = sys.memRead({mapping:'scratch', length:4, encoding:'utf8'}); sys.munmap({mapping:'scratch'}); return got;"
  }
}
```

## Ioctl With A Managed Buffer

```javascript
const pair = sys.socketpair({handles: ["w", "r"]});
sys.write({handle: "w", data_utf8: "abc"});
sys.bufferAlloc({name: "argp", size: 8});
const ioctl = sys.ioctl({handle: "r", request: "FIONREAD", buffer: "argp", buffer_length: 4});
const argp = sys.bufferRead({name: "argp", length: 4, encoding: "hex"});
sys.close({handle: "w"});
sys.close({handle: "r"});
return {ioctl, argp};
```

## Socket Payload Loop

```javascript
const payloads = args.payloads || ["00", "414243", "ff00ff"];
const results = [];
for (let i = 0; i < payloads.length; i++) {
  const pair = sys.socketpair({});
  const sent = sys.sendto({handle: pair.handles[0], data_hex: payloads[i]});
  const recv = sys.recvfrom({handle: pair.handles[1], length: 64, encoding: "hex"});
  sys.close({handle: pair.handles[0]});
  sys.close({handle: pair.handles[1]});
  results.push({iteration: i, sent, recv});
}
return results;
```

## At-Family And Xattr Probe

```javascript
const path = args.path;
const fd = sys.openat({path, flags: "O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC", mode: "0600", handle: "target"});
sys.write({handle: "target", data_utf8: "hello"});
sys.setxattr({path, name: "user.mcp_uapi", data_utf8: "ok"});
const xattr = sys.getxattr({path, name: "user.mcp_uapi", encoding: "utf8"});
const statx = sys.statx({path, mask: "STATX_BASIC_STATS"});
sys.close({handle: "target"});
return {fd, xattr, statx};
```