# eBPF Scripting API

The eBPF helpers expose a self-contained runtime built on `github.com/cilium/ebpf`. Scripts do not compile C, invoke clang, call bpftool, provide raw assembly, or load ELF objects on the target. Instead, `sys.ebpfProgramLoad` accepts built-in program kinds and the MCP binary generates the eBPF instructions internally.

Use this API for compact monitoring workflows on deployed Linux targets, including embedded systems where extra toolchains are not practical.

## Platform Requirements

The MCP binary can be cross-built for the Linux targets listed in the README, including `linux/arm64`, `linux/arm`, `linux/mips*`, `linux/riscv64`, `linux/ppc64*`, `linux/s390x`, `linux/386`, and `linux/amd64`.

All listed targets build with the eBPF helpers included. On `linux/mips`, `sys.ebpfPerfReaderCreate` returns `ErrNotSupported`; use ring buffers or map polling for event delivery on that target.

Runtime eBPF support depends on the kernel and process privileges:

- Linux kernel with the `bpf` syscall and eBPF enabled.
- Kernel support for the requested map type, program type, helper, and link type.
- Capabilities such as `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, or `CAP_SYS_ADMIN`, depending on the operation and kernel version.
- Sufficient locked-memory allowance on kernels that charge BPF objects to `RLIMIT_MEMLOCK`; `sys.ebpfRemoveMemlock()` can lift it when permitted.
- Mounted bpffs when pinning or loading pinned maps, programs, or links.

Probe before relying on a feature:

```javascript
return {
  info: sys.ebpfInfo(),
  map: sys.ebpfFeatureProbe({kind: "map_type", type: "array"}),
  prog: sys.ebpfFeatureProbe({kind: "program_type", type: "socket_filter"}),
  helper: sys.ebpfFeatureProbe({kind: "helper", program_type: "kprobe", helper: "ktime_get_ns"})
};
```

## Program Kinds

`sys.ebpfProgramLoad({kind, ...})` supports these self-contained kinds:

- `return`: returns `return_value`, defaulting to a safe value for the program type.
- `socket_filter_pass`: socket filter that accepts packets, default return value `0xffff`.
- `socket_filter_drop`: socket filter that drops packets, return value `0`.
- `counter`: increments an 8-byte value in a 4-byte-key counter map each time the program runs.
- `perf_event`: writes a 16-byte event (`u64 ktime_ns; u64 pid_tgid`) to a `PerfEventArray` map.
- `ringbuf_event`: writes the same 16-byte event to a `RingBuf` map.

The `counter`, `perf_event`, and `ringbuf_event` kinds are intended for monitoring hooks such as kprobes, kretprobes, tracepoints, raw tracepoints, and XDP where the selected program type is valid for the chosen attach point.

## Maps

Create maps with `sys.ebpfMapCreate`:

```javascript
const counters = sys.ebpfMapCreate({
  handle: "counts",
  name: "counts",
  type: "array",
  key_size: 4,
  value_size: 8,
  max_entries: 1
});
```

Map values can be read and written with scalar fields or byte encodings:

```javascript
sys.ebpfMapUpdate({map: "counts", key: 0, value: 0});
return sys.ebpfMapLookup({map: "counts", key: 0});
```

Use `type: "ringbuf"` with `key_size: 0`, `value_size: 0`, and a power-of-two page-sized `max_entries` for ring buffers. Use `type: "perf_event_array"`, `key_size: 4`, `value_size: 4`, and `max_entries` equal to `sys.ebpfInfo().possible_cpus` for perf event output.

## Attach And Monitor

A counter kprobe workflow:

```javascript
const setup = [];
setup.push(sys.ebpfMapCreate({handle: "counts", type: "array", key_size: 4, value_size: 8, max_entries: 1}));
setup.push(sys.ebpfMapUpdate({map: "counts", key: 0, value: 0}));
setup.push(sys.ebpfProgramLoad({handle: "countOpen", type: "kprobe", kind: "counter", counter_map: "counts"}));
setup.push(sys.ebpfAttachKprobe({handle: "openLink", program: "countOpen", symbol: "do_sys_openat2"}));
return setup;
```

A ring buffer event workflow:

```javascript
const page = os.getpagesize ? os.getpagesize() : 4096;
const ring = sys.ebpfMapCreate({handle: "events", type: "ringbuf", key_size: 0, value_size: 0, max_entries: page});
if (!ring.ok) return ring;
const reader = sys.ebpfRingbufReaderCreate({handle: "eventsReader", map: "events"});
if (!reader.ok) return reader;
const prog = sys.ebpfProgramLoad({handle: "emit", type: "kprobe", kind: "ringbuf_event", event_map: "events"});
if (!prog.ok) return prog;
const link = sys.ebpfAttachKprobe({handle: "emitLink", program: "emit", symbol: "do_sys_openat2"});
return {ring, reader, prog, link};
```

Read events without blocking indefinitely. A `timeout_ms` of `0` performs a nonblocking poll:

```javascript
return sys.ebpfRingbufRead({reader: "eventsReader", timeout_ms: 100, encoding: "hex"});
```

For perf events, create a `PerfEventArray`, then a perf reader:

```javascript
const cpus = sys.ebpfInfo().possible_cpus || 1;
const events = sys.ebpfMapCreate({handle: "perfEvents", type: "perf_event_array", key_size: 4, value_size: 4, max_entries: cpus});
const reader = sys.ebpfPerfReaderCreate({handle: "perfReader", map: "perfEvents", per_cpu_buffer: 4096});
```

## Link Lifecycle

Attach helpers return managed link handles:

- `sys.ebpfAttachKprobe({program, symbol})`
- `sys.ebpfAttachKretprobe({program, symbol})`
- `sys.ebpfAttachTracepoint({program, group, name})`
- `sys.ebpfAttachRawTracepoint({program, name})`
- `sys.ebpfAttachXDP({program, ifindex, flags})`

Inspect and release links with `sys.ebpfLinkInfo`, `sys.ebpfLinkUpdate`, `sys.ebpfLinkPin`, `sys.ebpfLinkUnpin`, `sys.ebpfLinkDetach`, and `sys.ebpfLinkClose`. Closing an unpinned link detaches the program.

Socket filters are attached directly to socket FDs with `sys.ebpfAttachSocketFilter({program, handle})` and removed with `sys.ebpfSocketFilterDetach({handle})`.

## Cleanup

Close resources when finished:

```javascript
sys.ebpfRingbufClose({reader: "eventsReader"});
sys.ebpfPerfReaderClose({reader: "perfReader"});
sys.ebpfLinkClose({link: "openLink"});
sys.ebpfProgramClose({program: "countOpen"});
sys.ebpfMapClose({map: "counts"});
```

Pinned objects can outlive the MCP process. Use pinning only when persistence is intentional.
