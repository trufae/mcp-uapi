# sys/unix Process Memory

This resource covers `processVMReadv`, `processVMWritev`, and the ptrace helpers. These wrappers are useful for child-process instrumentation, controlled debugging, and memory proof-of-concept work. Kernel ptrace/Yama policy still applies.

## processVMReadv

Simple form:

```javascript
const read = sys.processVMReadv({
  pid: args.pid,
  address: args.address,
  length: 64,
  encoding: "hex"
});
return read;
```

Advanced form with explicit local and remote iovecs:

```javascript
return sys.processVMReadv({
  pid: args.pid,
  remote_iovs: [
    {address: args.addr1, length: 16},
    {address: args.addr2, length: 16}
  ],
  local_iovs: [{length: 16}, {length: 16}],
  encoding: "hex"
});
```

The total local read allocation is bounded by `max_read_bytes`. Results include `bytes_read`, a combined encoded payload, and per-iovec segment data.

## processVMWritev

Simple form:

```javascript
return sys.processVMWritev({
  pid: args.pid,
  address: args.address,
  data_hex: "41424344"
});
```

Advanced form:

```javascript
return sys.processVMWritev({
  pid: args.pid,
  local_iovs: [{data_utf8: "A"}, {data_utf8: "B"}],
  remote_iovs: [{address: args.address, length: 2}]
});
```

## Ptrace Workflow

Use ptrace when the target must be stopped, stepped, or modified through ptrace semantics:

```javascript
const attach = sys.ptraceAttach({pid: args.pid, wait: true, timeout_ms: 5000});
if (!attach.ok) return attach;
try {
  const bytes = sys.ptraceRead({pid: args.pid, address: args.address, length: 32, encoding: "hex"});
  return {attach, bytes};
} finally {
  sys.ptraceDetach({pid: args.pid});
}
```

Use `processVMReadv` when you only need a bulk memory copy and policy allows it. Use ptrace when you need stop-the-world semantics or ptrace-specific control.

## Common Failures

- `EPERM` or `EACCES`: denied by kernel policy, missing `CAP_SYS_PTRACE`, target is not an allowed child, or Yama `ptrace_scope` blocks the operation.
- `ESRCH`: target PID no longer exists.
- `EFAULT`: one of the remote address ranges is invalid.
- `EINVAL`: malformed iovec layout or unsupported flags.