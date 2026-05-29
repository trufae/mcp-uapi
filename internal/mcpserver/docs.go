package mcpserver

func apiReferenceMarkdown() string {
	return `# Linux UAPI API Reference

Agents should begin by reading ` + "`uapi://capabilities`" + ` and ` + "`uapi://scripting-api`" + `. The only public MCP tool is ` + "`eval`" + `; all Linux UAPI operations are available inside eval through the ` + "`sys`" + ` object, with ` + "`uapi`" + ` kept as an alias for older scripts. Numeric fields accept JSON numbers, decimal strings, hex strings, or constant expressions such as ` + "`O_RDWR|O_CREAT|O_CLOEXEC`" + `.

## Result Model

Malformed script arguments, unknown handles, oversized reads, and invalid buffer ranges are eval errors. Linux syscall failures are normal observations and return structured JSON like:

` + "```json" + `
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
` + "```" + `

Successful syscall wrappers return ` + "`ok: true`" + ` plus syscall-specific fields. Prefer managed handles over raw FDs. Raw integer FDs require ` + "`--allow-raw-fd`" + `.

## Core Workflows

- Reconnaissance: ` + "`sys.uname()`" + `, ` + "`sys.stat()`" + `, ` + "`sys.statx()`" + `, ` + "`sys.readlink()`" + `, ` + "`sys.open()`" + `, ` + "`sys.read()`" + `, and ` + "`sys.close()`" + `.
- Filesystem mutation: ` + "`sys.openat()`" + `, ` + "`sys.fstatat()`" + `, ` + "`sys.mkdirat()`" + `, ` + "`sys.renameat2()`" + `, ` + "`sys.fchmodat()`" + `, and ` + "`sys.unlinkat()`" + `.
- Socket clients: ` + "`sys.socket()`" + ` or ` + "`sys.socketpair()`" + `, then ` + "`sys.connect()`" + `, ` + "`sys.sendto()`" + `, ` + "`sys.recvfrom()`" + `, ` + "`sys.poll()`" + ` or ` + "`sys.epollWait()`" + `.
- ioctl probing: allocate a buffer with ` + "`sys.bufferAlloc()`" + `, initialize it with ` + "`sys.bufferWrite()`" + `, call ` + "`sys.ioctl()`" + ` with ` + "`buffer`" + `, then inspect with ` + "`sys.bufferRead()`" + `.
- ptrace memory reads: ` + "`sys.ptraceAttach()`" + ` with wait enabled, ` + "`sys.ptraceRead()`" + ` bounded ranges, then ` + "`sys.ptraceDetach()`" + `.
- mmap experiments: ` + "`sys.mmap()`" + ` anonymous or file-backed memory, mutate with ` + "`sys.memWrite()`" + `, inspect with ` + "`sys.memRead()`" + `, and clean up with ` + "`sys.munmap()`" + `.
- Event and metadata helpers: ` + "`sys.eventfd()`" + `, ` + "`sys.memfdCreate()`" + `, ` + "`sys.inotifyInit1()`" + `, ` + "`sys.getxattr()`" + `, ` + "`sys.setxattr()`" + `, ` + "`sys.sendfile()`" + `, and ` + "`sys.copyFileRange()`" + `.

## Safety Notes

This server intentionally exposes primitives useful for embedded systems testing and low-level research. Eval scripts can modify the filesystem, signal processes, attach to processes permitted by Linux ptrace policy, and issue arbitrary ioctls. Run it in an isolated lab environment with a trusted MCP client.
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
- ` + "`sys`" + `: synchronous Linux sys/unix scripting API with managed FD, buffer, mmap, socket, process, xattr, and event helpers.
- ` + "`uapi`" + `: alias for ` + "`sys`" + ` for compatibility with older scripts.

Safe bootstrap:

` + "```javascript" + `
const caps = sys.capabilities();
return {
  name: caps.name,
  wrappers: caps.scripting_api.uapi_wrappers,
  uname: sys.uname(),
  openFlags: sys.constants({group: "open_flags"}).constants
};
` + "```" + `

Socketpair round trip:

` + "```javascript" + `
const pair = sys.socketpair({type: "SOCK_STREAM|SOCK_CLOEXEC"});
sys.write({handle: pair.handles[0], data_utf8: "ping"});
const got = sys.read({handle: pair.handles[1], length: 4, encoding: "utf8"});
sys.close({handle: pair.handles[0]});
sys.close({handle: pair.handles[1]});
return got;
` + "```" + `

At-family file workflow:

` + "```javascript" + `
const file = sys.openat({path: args.path, flags: "O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC", mode: "0600"});
sys.write({handle: file.handle, data_utf8: args.payload || "hello"});
sys.fsync({handle: file.handle});
const stat = sys.fstatat({path: args.path});
sys.close({handle: file.handle});
return stat;
` + "```" + `

Legacy wrappers such as ` + "`sys.open()`" + ` and ` + "`sys.socketpair()`" + ` accept the same JSON shape they used before. New script-only wrappers follow the lower camel-case form of their ` + "`golang.org/x/sys/unix`" + ` names where possible, such as ` + "`sys.fstatat()`" + `, ` + "`sys.memfdCreate()`" + `, and ` + "`sys.copyFileRange()`" + `. Syscall errno results are returned as normal data, so scripts should check ` + "`result.ok === false`" + ` when exploring expected failure cases.
`
}
