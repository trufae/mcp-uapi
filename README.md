# mcp-uapi

`mcp-uapi` is a Go MCP server that exposes Linux user-mode APIs from `golang.org/x/sys/unix` as agent-friendly primitives. It is designed for embedded systems testing workflows: attack surface reconnaissance, socket/client experiments, ioctl exploration, ptrace memory probes, fuzzing harnesses, and compact proof-of-concept development.

The server does not implement fuzzing policy, scheduling, minimization, or corpus management. Instead, it provides reliable building blocks that AI agents can compose directly through MCP tools or through the built-in Goja `eval` scripting layer.

## What It Exposes

- Metadata: capabilities, constants, errno decoding, `uname`, process identity, live handle state.
- File descriptors: `open`, `close`, `read`, `write`, `pread`, `pwrite`, `lseek`, `fstat`, `stat`, `readlink`.
- Managed buffers: bounded byte buffers for ioctl payloads, socket sends, file writes, and deterministic test data.
- Memory mappings: anonymous and file-backed `mmap`, `munmap`, `mprotect`, `msync`, `madvise`, mapping read/write.
- Networking: socket, socketpair, bind/connect/listen/accept, send/recv, socket names, integer sockopts, shutdown.
- Readiness: `poll`, `epoll_create`, `epoll_ctl`, `epoll_wait`.
- Process control: `kill`, `wait4`, `prctl`, `ptrace` attach/detach/read/write/continue/syscall.
- `ioctl`: integer argument or pointer to a managed buffer range.
- `eval`: Goja JavaScript with synchronous `uapi.*` wrappers, captured logs, timeout enforcement, and deterministic RNG helpers.

Agents should call `uapi_capabilities` or read `uapi://capabilities` immediately after connecting. The capability document includes bootstrap hints, tool summaries, constants, resources, prompts, and scripting metadata.

## Safety Model

This server intentionally exposes direct Linux syscalls. It can create files, open sockets, signal processes, attach to ptrace-allowed processes, mutate mappings, and issue arbitrary ioctls. Run it only in an isolated lab environment with a trusted MCP client.

Raw integer FD access is disabled by default. Prefer managed handles returned by tools such as `uapi_open`, `uapi_socket`, `uapi_socketpair`, `uapi_epoll_create`, `uapi_buffer_alloc`, and `uapi_mmap`. Start with `--allow-raw-fd` only when a workflow truly needs externally supplied FDs.

Linux syscall failures are returned as structured data instead of MCP tool errors:

```json
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
```

Malformed arguments, unknown handles, invalid ranges, and oversized reads remain MCP tool errors.

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

- `--max-read-bytes`: maximum bytes returned by read-like tools. Default: 1 MiB.
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
    "script": "const pair = uapi.socketpair({handles:['a','b']}); uapi.write({handle:'a', data_utf8:'ping'}); const got = uapi.read({handle:'b', length:4, encoding:'utf8'}); uapi.close({handle:'a'}); uapi.close({handle:'b'}); return got;"
  }
}
```

Prepare an ioctl buffer and call `FIONREAD` on a socket:

```json
{"name":"uapi_buffer_alloc","arguments":{"name":"ioctl","size":8}}
```

```json
{"name":"uapi_ioctl","arguments":{"handle":"sock","request":"FIONREAD","buffer":"ioctl","buffer_length":4}}
```

Attach to a permitted child process and read memory:

```json
{"name":"uapi_ptrace_attach","arguments":{"pid":1234,"wait":true,"timeout_ms":5000}}
```

```json
{"name":"uapi_ptrace_read","arguments":{"pid":1234,"address":"0x7ffd00000000","length":64,"encoding":"hex"}}
```

Always detach when done:

```json
{"name":"uapi_ptrace_detach","arguments":{"pid":1234}}
```

## Documentation

- [docs/API.md](docs/API.md): tool groups, result model, and workflow notes.
- [docs/SCRIPTING.md](docs/SCRIPTING.md): Goja `eval` globals, wrappers, RNG, and examples.
- [docs/EXAMPLES.md](docs/EXAMPLES.md): concrete MCP/eval workflows.
- [docs/SECURITY.md](docs/SECURITY.md): safety model and deployment guidance.