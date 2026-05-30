# mcp-uapi

> **Work in progress — Proof of Concept.** APIs, flags, and scripting interfaces may change without notice.

`mcp-uapi` is a Go MCP server that exposes Linux user-mode APIs from `golang.org/x/sys/unix` through a single JavaScript `eval` tool. It is designed for embedded systems testing workflows: attack surface reconnaissance, socket/client experiments, ioctl exploration, ptrace memory probes, fuzzing harnesses, and compact proof-of-concept development.

The server does not implement fuzzing policy, scheduling, minimization, or corpus management. Instead, it provides reliable building blocks that AI agents compose inside the built-in Goja scripting layer.

## What It Exposes

- Public MCP surface: `eval` only, plus discovery resources and prompts.
- Metadata: capabilities, constants, errno decoding, `uname`, process identity, groups, resource limits, resource usage, and live handle state.
- File descriptors: `open/openat`, `close`, `dup/dup2/dup3`, `pipe/pipe2`, `read`, `write`, `pread`, `pwrite`, `lseek`, `fstat/fstatat`, `stat/statx/statfs/fstatfs`, `readlink/readlinkat`, truncate, sync, nonblocking, and `fcntlInt`.
- Filesystem mutation: access checks, chmod/chown families, mkdir/mkfifo/mknod families, link/symlink, rename/renameat2, unlink/unlinkat, and rmdir.
- Managed buffers: bounded byte buffers for ioctl payloads, socket sends, file writes, and explicit test data.
- Memory mappings: anonymous and file-backed `mmap`, `munmap`, `mprotect`, `msync`, `madvise`, mapping read/write.
- Networking: socket, socketpair, bind/connect/listen/accept, send/recv, socket names, integer sockopts, shutdown.
- Readiness and events: `poll`, `epoll_create`, `epoll_ctl`, `epoll_wait`, `eventfd`, `inotify`, `memfd_create`, and close-range helpers.
- Process control: `kill`, `wait4`, `prctl`, `ptrace` attach/detach/read/write/continue/syscall/get-registers/set-options.
- Extended attributes and transfer: get/list/set/remove xattr families, `sendfile`, and `copy_file_range`.
- `ioctl`: integer argument or pointer to a managed buffer range.
- eBPF: self-contained `github.com/cilium/ebpf` helpers for maps, built-in program kinds, links, ringbuf/perf readers, feature probes, BTF inspection, and pinning. Scripts do not need clang, bpftool, a C compiler, raw assembly, or ELF loading on the target.
- Go standard library wrappers: `os.*` and `io.*` globals for package `os` and package `io` style filesystem, root, process, env, copy, read, and write workflows over managed handles and explicit byte encodings.
- `eval`: Goja JavaScript with synchronous `sys.*`/`uapi.*`, `os.*`, and `io.*` wrappers, captured logs, timeout enforcement, and JSON results.

Agents should read MCP resources `uapi://agent-guide`, `uapi://capabilities`, `uapi://scripting-api`, and `uapi://api-reference` immediately after connecting. These are MCP resources read by the client, not JavaScript URLs inside eval. Inside eval, use `sys.capabilities()` instead of nonexistent helpers such as `uapi.request`, `sys.request`, `fetch`, `require`, or `import`.

The documentation resources are backed by the markdown files in `docs/` and embedded into the binary at build time. Reusable eval scripts are backed by individual files in `examples/`, also embedded at build time, and exposed under `uapi://examples/<file>.js`. Start with `uapi://docs` and `uapi://examples` for the resource indexes.

## Safety Model

This server intentionally exposes direct Linux syscalls. It can create files, open sockets, signal processes, attach to ptrace-allowed processes, mutate mappings, and issue arbitrary ioctls. Run it only in an isolated lab environment with a trusted MCP client.

Raw integer FD access is disabled by default. Prefer managed handles returned by script calls such as `sys.open`, `os.open`, `os.create`, `os.openRoot`, `sys.socket`, `sys.socketpair`, `sys.epollCreate`, `sys.bufferAlloc`, `sys.mmap`, `sys.memfdCreate`, and `sys.eventfd`. Start with `--allow-raw-fd` only when a workflow truly needs externally supplied FDs.

eBPF loading and attachment can observe or affect kernel execution depending on program type, return value, and hook. Kernel policy and capabilities still apply. Prefer explicit cleanup with `sys.ebpfLinkClose`, `sys.ebpfProgramClose`, `sys.ebpfMapClose`, and reader close helpers unless a pin is intentionally used to persist an object.

Linux syscall failures are returned as structured data instead of MCP tool errors:

```json
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
```

Malformed script arguments, unknown handles, invalid ranges, and oversized reads are returned as eval errors.

## Quick Start

Install the local Go toolchain and dependencies:

```bash
cd mcp-uapi
./install-deps.sh
```

Build:

```bash
./scripts/build.sh
```

Run tests:

```bash
./scripts/test.sh
```

Run over stdio for a local MCP client:

```bash
./bin/mcp-uapi --transport stdio
```

Run Streamable HTTP for remote agents:

```bash
./bin/mcp-uapi --transport http --listen 127.0.0.1:8080 --endpoint /mcp
```

The HTTP MCP endpoint will be `http://127.0.0.1:8080/mcp`.

Useful startup flags:

- `--max-read-bytes`: maximum bytes returned by read-like script helpers. Default: 1 MiB.
- `--max-buffer-bytes`: maximum managed buffer or mapping size. Default: 16 MiB.
- `--allow-raw-fd`: permit tools to operate on integer FDs not opened by this server.

## Supported Targets

All targets are Linux-only. Cross builds are pure Go with cgo disabled. The eBPF API is compiled into the same binary on these targets, but runtime support depends on the deployed kernel, enabled BPF features, privilege policy, memlock accounting, and bpffs availability.

| Target              | Binary                         |
|---------------------|--------------------------------|
| `linux/386`         | `bin/mcp-uapi-linux-386`       |
| `linux/amd64`       | `bin/mcp-uapi-linux-amd64`     |
| `linux/arm`         | `bin/mcp-uapi-linux-arm`       |
| `linux/arm64`       | `bin/mcp-uapi-linux-arm64`     |
| `linux/loong64`     | `bin/mcp-uapi-linux-loong64`   |
| `linux/mips`        | `bin/mcp-uapi-linux-mips`      |
| `linux/mips64`      | `bin/mcp-uapi-linux-mips64`    |
| `linux/mips64le`    | `bin/mcp-uapi-linux-mips64le`  |
| `linux/mipsle`      | `bin/mcp-uapi-linux-mipsle`    |
| `linux/ppc64`       | `bin/mcp-uapi-linux-ppc64`     |
| `linux/ppc64le`     | `bin/mcp-uapi-linux-ppc64le`   |
| `linux/riscv64`     | `bin/mcp-uapi-linux-riscv64`   |
| `linux/s390x`       | `bin/mcp-uapi-linux-s390x`     |

Build a specific target:

```bash
./scripts/build-target.sh linux/arm64
./scripts/build-target.sh linux/arm
./scripts/build-target.sh linux/riscv64
```

Build all targets at once:

```bash
./scripts/build-all-targets.sh
```

For eBPF on embedded targets such as ARM64 routers, build and deploy only the MCP binary. The target does not need a C compiler or eBPF toolchain. Use `sys.ebpfInfo()` and `sys.ebpfFeatureProbe()` from eval to discover what the running kernel permits.

The eBPF helpers cross-build for every target above. On `linux/mips`, `sys.ebpfPerfReaderCreate` returns `ErrNotSupported`; use ring buffers or map polling for event delivery on that target.

## Examples

Create a local socketpair and exchange bytes:

```javascript
const pair = sys.socketpair({handles: ['a', 'b']});
sys.write({handle: 'a', data_utf8: 'ping'});
const got = sys.read({handle: 'b', length: 4, encoding: 'utf8'});
sys.close({handle: 'a'});
sys.close({handle: 'b'});
return got;
```

Prepare an ioctl buffer and call `FIONREAD` on a socket:

```javascript
sys.bufferAlloc({name: 'ioctl', size: 8});
const ioctl = sys.ioctl({
  handle: args.socket,
  request: 'FIONREAD',
  buffer: 'ioctl',
  buffer_length: 4,
});
const argp = sys.bufferRead({name: 'ioctl', length: 4, encoding: 'hex'});
return {ioctl, argp};
```

Attach to a permitted child process and read memory:

```javascript
const attach = sys.ptraceAttach({pid: args.pid, wait: true, timeout_ms: 5000});
if (!attach.ok) return attach;
try {
  return sys.ptraceRead({pid: args.pid, address: args.address, length: 64, encoding: 'hex'});
} finally {
  sys.ptraceDetach({pid: args.pid});
}
```

Trace a few syscalls from an allowed process:

```javascript
const src = os.readFile({name: 'examples/006-strace-syscall-trace.js', encoding: 'utf8'});
const run = new Function('args', 'console', 'print', 'sys', 'uapi', 'os', 'io', src.data_utf8);
return run({pid: args.pid, max_events: 8, wait_timeout_ms: 1000}, console, print, sys, uapi, os, io);
```

Copy a file with the `os` and `io` scripting globals:

```javascript
os.writeFile({name: args.path, data_utf8: 'hello', perm: '0600'});
const src = os.open({name: args.path, handle: 'src'});
const dst = os.create({name: args.copy, handle: 'dst'});
try {
  const copied = io.copy({dst: {handle: 'dst'}, src: {handle: 'src'}});
  const got = os.readFile({name: args.copy, encoding: 'utf8'});
  return {copied, got};
} finally {
  os.fileClose({handle: 'src'});
  os.fileClose({handle: 'dst'});
}
```

Load a self-contained eBPF socket filter without a target-side compiler:

```javascript
const prog = sys.ebpfProgramLoad({kind: "socket_filter_pass", handle: "passAll"});
if (!prog.ok) return prog;
const pair = sys.socketpair({type: "SOCK_DGRAM|SOCK_CLOEXEC", handles: ["left", "right"]});
const attach = sys.ebpfAttachSocketFilter({program: "passAll", handle: "left"});
return {prog, attach, info: sys.ebpfInfo()};
```

More ready-to-run scripts live in [examples/](examples/).

## Documentation

Reference documentation lives in [docs/](docs/).