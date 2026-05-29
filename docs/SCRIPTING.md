# Scripting API

The `eval` tool runs JavaScript in a fresh Goja runtime for each call. Scripts execute inside a function body, so use `return` for the JSON result. Console output is captured.

```json
{
  "script": "const caps = uapi.capabilities(); return {name: caps.name, uname: uapi.uname()};",
  "args": {},
  "timeout_ms": 5000,
  "max_log_entries": 200,
  "max_result_bytes": 1048576
}
```

Globals:

- `args`: caller JSON.
- `console.log/info/warn/error` and `print`: captured logs.
- `uapi`: wrappers around MCP tools plus `uapi.state()` and `uapi.hex(value, width)`.
- `sys`: alias for `uapi`.
- `rng`: deterministic local RNG.

Safe discovery probe:

```javascript
const caps = uapi.capabilities();
return {
  wrappers: caps.scripting_api.uapi_wrappers,
  uname: uapi.uname(),
  openFlags: uapi.constants({group: "open_flags"}).constants
};
```

Socketpair example:

```javascript
const pair = uapi.socketpair({handles: ["left", "right"]});
uapi.write({handle: "left", data_utf8: "ping"});
const ready = uapi.poll({fds: [{handle: "right", events: "POLLIN"}], timeout_ms: 100});
const got = uapi.read({handle: "right", length: 4, encoding: "utf8"});
uapi.close({handle: "left"});
uapi.close({handle: "right"});
return {ready, got};
```

RNG example:

```javascript
const r = rng.local("550e8400-e29b-41d4-a716-446655440000");
return {
  u32: r.uint32(),
  u64: r.uint64(),
  bytes: r.bytes(16, "hex"),
  pick: r.choice(["open", "connect", "ioctl"])
};
```

`uint64()` returns hex strings and `uint64Decimal()` returns decimal strings so JavaScript number precision cannot corrupt 64-bit values.