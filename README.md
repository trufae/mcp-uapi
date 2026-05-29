# mcp-uapi

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
- Process control: `kill`, `wait4`, `prctl`, `ptrace` attach/detach/read/write/continue/syscall.
- Extended attributes and transfer: get/list/set/remove xattr families, `sendfile`, and `copy_file_range`.
- `ioctl`: integer argument or pointer to a managed buffer range.
- `eval`: Goja JavaScript with synchronous `sys.*`/`uapi.*` wrappers, captured logs, timeout enforcement, and JSON results.

Agents should read `uapi://capabilities` and `uapi://scripting-api` immediately after connecting. The capability document includes bootstrap hints, constants, resources, prompts, and scripting metadata.

## Safety Model

This server intentionally exposes direct Linux syscalls. It can create files, open sockets, signal processes, attach to ptrace-allowed processes, mutate mappings, and issue arbitrary ioctls. Run it only in an isolated lab environment with a trusted MCP client.

Raw integer FD access is disabled by default. Prefer managed handles returned by script calls such as `sys.open`, `sys.socket`, `sys.socketpair`, `sys.epollCreate`, `sys.bufferAlloc`, `sys.mmap`, `sys.memfdCreate`, and `sys.eventfd`. Start with `--allow-raw-fd` only when a workflow truly needs externally supplied FDs.

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

## Cross Builds

Build for the host platform:

```bash
./scripts/build.sh
```

Build for embedded Linux targets:

```bash
./scripts/build-target.sh linux/amd64
./scripts/build-target.sh linux/arm64
./scripts/build-target.sh linux/arm/v7
```

The output is written under `bin/` with the target tuple in the filename. Cross builds are pure Go and disable cgo by default.

## Examples

Create a local socketpair and exchange bytes with `eval`:

```json
{
  "name": "eval",
  "arguments": {
    "script": "const pair = sys.socketpair({handles:['a','b']}); sys.write({handle:'a', data_utf8:'ping'}); const got = sys.read({handle:'b', length:4, encoding:'utf8'}); sys.close({handle:'a'}); sys.close({handle:'b'}); return got;"
  }
}
```

Prepare an ioctl buffer and call `FIONREAD` on a socket:

```json
{
  "name": "eval",
  "arguments": {
    "script": "sys.bufferAlloc({name:'ioctl', size:8}); const ioctl = sys.ioctl({handle: args.socket, request:'FIONREAD', buffer:'ioctl', buffer_length:4}); const argp = sys.bufferRead({name:'ioctl', length:4, encoding:'hex'}); return {ioctl, argp};",
    "args": {"socket": "sock"}
  }
}
```

Attach to a permitted child process and read memory:

```json
{
  "name": "eval",
  "arguments": {
    "script": "const attach = sys.ptraceAttach({pid: args.pid, wait:true, timeout_ms:5000}); if (!attach.ok) return attach; try { return sys.ptraceRead({pid: args.pid, address: args.address, length:64, encoding:'hex'}); } finally { sys.ptraceDetach({pid: args.pid}); }",
    "args": {"pid": 1234, "address": "0x7ffd00000000"}
  }
}
```

## Documentation

- [docs/API.md](docs/API.md): scripting groups, result model, and workflow notes.
- [docs/SCRIPTING.md](docs/SCRIPTING.md): Goja `eval` globals, wrappers, and examples.
- [docs/EXAMPLES.md](docs/EXAMPLES.md): concrete eval workflows.
- [docs/SECURITY.md](docs/SECURITY.md): safety model and deployment guidance.