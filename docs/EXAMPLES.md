# Examples

## Read A File

```json
{"name":"uapi_open","arguments":{"path":"/proc/version","flags":"O_RDONLY|O_CLOEXEC","handle":"version"}}
```

```json
{"name":"uapi_read","arguments":{"handle":"version","length":4096,"encoding":"utf8"}}
```

```json
{"name":"uapi_close","arguments":{"handle":"version"}}
```

## Anonymous Mmap

```json
{"name":"uapi_mmap","arguments":{"length":4096,"handle":"scratch"}}
```

```json
{"name":"uapi_mem_write","arguments":{"mapping":"scratch","data_hex":"41424344"}}
```

```json
{"name":"uapi_mem_read","arguments":{"mapping":"scratch","length":4,"encoding":"utf8"}}
```

## Ioctl With A Managed Buffer

```javascript
const pair = uapi.socketpair({handles: ["w", "r"]});
uapi.write({handle: "w", data_utf8: "abc"});
uapi.bufferAlloc({name: "argp", size: 8});
const ioctl = uapi.ioctl({handle: "r", request: "FIONREAD", buffer: "argp", buffer_length: 4});
const argp = uapi.bufferRead({name: "argp", length: 4, encoding: "hex"});
return {ioctl, argp};
```

## Deterministic Socket Fuzz Skeleton

```javascript
const seed = args.seed || "550e8400-e29b-41d4-a716-446655440000";
const results = [];
for (let i = 0; i < 16; i++) {
  const r = rng.create({originalSeed: seed, iteration: i});
  const payload = r.bytes(r.range(1, 64), "hex");
  const pair = uapi.socketpair({});
  const sent = uapi.sendto({handle: pair.handles[0], data_hex: payload});
  const recv = uapi.recvfrom({handle: pair.handles[1], length: 64, encoding: "hex"});
  uapi.close({handle: pair.handles[0]});
  uapi.close({handle: pair.handles[1]});
  results.push({iteration: i, seed: r.info().seed, sent, recv});
}
return results;
```