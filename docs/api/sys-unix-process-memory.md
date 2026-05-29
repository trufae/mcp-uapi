# sys/unix Process Memory

This resource covers `processVMReadv`, `processVMWritev`, and the ptrace helpers. These wrappers are useful for child-process instrumentation, controlled debugging, and memory proof-of-concept work. Kernel ptrace/Yama policy still applies.

Inside eval, ptrace helpers automatically pin the eval goroutine to a single OS thread until the script returns. Keep multi-step ptrace flows in one eval call so Linux sees a consistent tracer task.

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
  sys.ptraceSetOptions({pid: args.pid, options: "PTRACE_O_TRACESYSGOOD"});
  const regs = sys.ptraceGetRegs({pid: args.pid});
  const bytes = sys.ptraceRead({pid: args.pid, address: args.address, length: 32, encoding: "hex"});
  return {attach, regs, bytes};
} finally {
  sys.ptraceDetach({pid: args.pid});
}
```

`sys.ptraceGetRegs({pid})` returns raw architecture registers as hex strings under `registers` and, where the architecture ABI is known, a normalized `syscall` object with `nr`, `name`, `args`, `retval`, `pc`, and `sp`. Syscall names are generated from `golang.org/x/sys/unix` syscall-number tables at build time. `sys.ptraceSetOptions({pid, options})` accepts constants such as `PTRACE_O_TRACESYSGOOD`.

Use `processVMReadv` when you only need a bulk memory copy and policy allows it. Use ptrace when you need stop-the-world semantics or ptrace-specific control.

## Common Failures

- `EPERM` or `EACCES`: denied by kernel policy, missing `CAP_SYS_PTRACE`, target is not an allowed child, or Yama `ptrace_scope` blocks the operation.
- `ESRCH`: target PID no longer exists.
- `EFAULT`: one of the remote address ranges is invalid.
- `EINVAL`: malformed iovec layout or unsupported flags.