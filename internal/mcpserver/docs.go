package mcpserver

func apiReferenceMarkdown() string {
	return `# Linux UAPI MCP API Reference

Agents should begin with ` + "`uapi_capabilities`" + ` or ` + "`uapi://capabilities`" + `, then read ` + "`uapi_constants`" + ` for symbolic values accepted by schemas. Numeric fields accept JSON numbers, decimal strings, hex strings, or constant expressions such as ` + "`O_RDWR|O_CREAT|O_CLOEXEC`" + `.

## Result Model

Malformed arguments, unknown handles, oversized reads, and invalid buffer ranges are MCP tool errors. Linux syscall failures are normal observations and return structured JSON like:

` + "```json" + `
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
` + "```" + `

Successful syscall wrappers return ` + "`ok: true`" + ` plus syscall-specific fields. Prefer managed handles over raw FDs. Raw integer FDs require ` + "`--allow-raw-fd`" + `.

## Core Workflows

- Reconnaissance: ` + "`uapi_uname`" + `, ` + "`uapi_stat`" + `, ` + "`uapi_readlink`" + `, ` + "`uapi_open`" + `, ` + "`uapi_read`" + `, and ` + "`uapi_close`" + `.
- Socket clients: ` + "`uapi_socket`" + ` or ` + "`uapi_socketpair`" + `, then ` + "`uapi_connect`" + `, ` + "`uapi_sendto`" + `, ` + "`uapi_recvfrom`" + `, ` + "`uapi_poll`" + ` or ` + "`uapi_epoll_wait`" + `.
- ioctl probing: allocate a buffer with ` + "`uapi_buffer_alloc`" + `, initialize it with ` + "`uapi_buffer_write`" + `, call ` + "`uapi_ioctl`" + ` with ` + "`buffer`" + `, then inspect with ` + "`uapi_buffer_read`" + `.
- ptrace memory reads: ` + "`uapi_ptrace_attach`" + ` with wait enabled, ` + "`uapi_ptrace_read`" + ` bounded ranges, then ` + "`uapi_ptrace_detach`" + `.
- mmap experiments: ` + "`uapi_mmap`" + ` anonymous or file-backed memory, mutate with ` + "`uapi_mem_write`" + `, inspect with ` + "`uapi_mem_read`" + `, and clean up with ` + "`uapi_munmap`" + `.

## Safety Notes

This server intentionally exposes primitives useful for embedded systems testing and low-level research. It can modify the filesystem, signal processes, attach to processes permitted by Linux ptrace policy, and issue arbitrary ioctls. Run it in an isolated lab environment with a trusted MCP client.
`
}

func scriptingAPIMarkdown() string {
	return `# Linux UAPI Scripting API

The ` + "`eval`" + ` tool executes JavaScript with Goja. Scripts run inside a function body, so use ` + "`return`" + ` to produce JSON. ` + "`console.log/info/warn/error`" + ` output is captured in the response.

Input shape:

` + "```json" + `
{
  "script": "const caps = uapi.capabilities(); return {name: caps.name, uname: uapi.uname()};",
  "args": {},
  "timeout_ms": 5000,
  "max_log_entries": 200,
  "max_result_bytes": 1048576
}
` + "```" + `

Globals:

- ` + "`args`" + `: caller-provided JSON object.
- ` + "`console`" + ` and ` + "`print`" + `: captured logging.
- ` + "`uapi`" + `: synchronous wrappers for MCP tools, plus ` + "`uapi.state()`" + ` and ` + "`uapi.hex(value, width)`" + `.
- ` + "`sys`" + `: alias for ` + "`uapi`" + `.
- ` + "`rng`" + `: deterministic local RNG for repeatable payloads.

Safe bootstrap:

` + "```javascript" + `
const caps = uapi.capabilities();
return {
  name: caps.name,
  wrappers: caps.scripting_api.uapi_wrappers,
  uname: uapi.uname(),
  openFlags: uapi.constants({group: "open_flags"}).constants
};
` + "```" + `

Socketpair round trip:

` + "```javascript" + `
const pair = uapi.socketpair({type: "SOCK_STREAM|SOCK_CLOEXEC"});
uapi.write({handle: pair.handles[0], data_utf8: "ping"});
const got = uapi.read({handle: pair.handles[1], length: 4, encoding: "utf8"});
uapi.close({handle: pair.handles[0]});
uapi.close({handle: pair.handles[1]});
return got;
` + "```" + `

Deterministic payload generation:

` + "```javascript" + `
const r = rng.local(args.seed || "550e8400-e29b-41d4-a716-446655440000");
return {u64: r.uint64(), bytes: r.bytes(32, "hex"), pick: r.choice(["read", "write", "ioctl"])};
` + "```" + `

Every wrapper accepts the same JSON shape as the corresponding MCP tool. Syscall errno results are returned as normal data, so scripts should check ` + "`result.ok === false`" + ` when exploring expected failure cases.
`
}
