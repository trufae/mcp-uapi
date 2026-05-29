package mcpserver

func agentGuideMarkdown() string {
	return `# MCP-UAPI Agent Guide

This server is intentionally eval-first. The only public MCP tool to call is ` + "`eval`" + `. Discovery documents, references, and prompts are still exposed as MCP resources and prompts so a new agent can learn the API before it writes a script.

## Correct Bootstrap

Use the MCP client's resource APIs before calling ` + "`eval`" + `:

1. Read MCP resource ` + "`uapi://agent-guide`" + ` for this orientation.
2. Read MCP resource ` + "`uapi://scripting-api`" + ` for JavaScript globals, wrapper groups, and examples.
3. Read MCP resource ` + "`uapi://api-reference`" + ` for result conventions, handles, constants, and workflow notes.
4. Read MCP resource ` + "`uapi://capabilities`" + ` when you need machine-readable wrapper names, constants, prompts, and resources.
5. Call MCP tool ` + "`eval`" + ` for every syscall workflow.

Do not try to fetch resources from inside JavaScript. These are wrong and will fail because they are not part of the eval runtime:

` + "```javascript" + `
uapi.request('GET', 'uapi://capabilities')
sys.request('GET', 'uapi://capabilities')
fetch('uapi://capabilities')
require('fs')
` + "```" + `

Inside eval, use ` + "`sys.capabilities()`" + ` for the same machine-readable capability document after the resource-reading phase.

## Eval Tool Shape

Call the MCP tool named ` + "`eval`" + ` with this envelope:

` + "```json" + `
{
  "name": "eval",
  "arguments": {
    "script": "const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers.length};",
    "args": {},
    "timeout_ms": 5000,
    "max_log_entries": 200,
    "max_result_bytes": 1048576
  }
}
` + "```" + `

Scripts run inside a function body. Use ` + "`return`" + ` for the JSON result. Logs written with ` + "`console.log/info/warn/error`" + ` or ` + "`print`" + ` are captured in the eval response.

## Eval Runtime

Available globals:

- ` + "`args`" + `: caller-provided JSON object.
- ` + "`console`" + ` and ` + "`print`" + `: captured logging.
- ` + "`sys`" + `: synchronous Linux sys/unix scripting API.
- ` + "`uapi`" + `: alias for ` + "`sys`" + ` for older scripts.
- ` + "`os`" + `: synchronous Go package os style wrappers over managed handles, roots, processes, env, and filesystem helpers.
- ` + "`io`" + `: synchronous Go package io style copy/read/write helpers over managed handles, buffers, paths, data, and discard endpoints.

Not available in eval: ` + "`uapi.request`" + `, ` + "`sys.request`" + `, ` + "`fetch`" + `, ` + "`XMLHttpRequest`" + `, ` + "`require`" + `, ` + "`import`" + `, Node.js modules, direct network clients, direct MCP resource reads, and server-terminating helpers such as ` + "`os.Exit`" + `.

## Discovery Probe

Use this as the first read-only eval script:

` + "```javascript" + `
const caps = sys.capabilities();
return {
  name: caps.name,
  publicTools: caps.tools.map(t => t.name),
  resources: caps.resources,
  wrappers: caps.scripting_api.uapi_wrappers,
  osWrappers: caps.scripting_api.os_wrappers,
  ioWrappers: caps.scripting_api.io_wrappers,
  constants: Object.keys(sys.constants().constants),
  uname: sys.uname()
};
` + "```" + `

Expected public tools: only ` + "`eval`" + `. Expected scripting objects: ` + "`sys`" + `, with ` + "`uapi`" + ` as the same object, plus ` + "`os`" + ` and ` + "`io`" + ` standard-library wrappers.

## Result Model

Eval responses have ` + "`ok`" + `, ` + "`result`" + `, ` + "`logs`" + `, ` + "`operations`" + `, timing fields, and optional ` + "`error`" + `. Malformed script inputs, unknown handles, invalid ranges, bad constants, and result-size violations are eval errors. Linux errno failures are data returned by syscall wrappers:

` + "```json" + `
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
` + "```" + `

Treat ` + "`ok:false`" + ` errno values as observations during probing rather than crashes.

## Handle Discipline

Helpers that create FDs, buffers, and mappings return managed names. Reuse those names within later eval calls, and read ` + "`uapi://state`" + ` through MCP resources when you need a live inventory. Close what you create:

- FDs: ` + "`sys.close({handle})`" + ` or ` + "`os.fileClose({handle})`" + `.
- Roots: ` + "`os.rootClose({root})`" + `.
- Mappings: ` + "`sys.munmap({mapping})`" + `.
- Buffers: ` + "`sys.bufferFree({name})`" + `.

Raw integer FDs require the server to be started with ` + "`--allow-raw-fd`" + `. Prefer managed handles.

## Common Patterns

File read:

` + "```javascript" + `
const fd = sys.open({path: args.path, flags: "O_RDONLY|O_CLOEXEC"});
try {
  return sys.read({handle: fd.handle, length: args.length || 4096, encoding: "utf8"});
} finally {
  sys.close({handle: fd.handle});
}
` + "```" + `

Socketpair round trip:

` + "```javascript" + `
const pair = sys.socketpair({type: "SOCK_STREAM|SOCK_CLOEXEC", handles: ["left", "right"]});
try {
  sys.write({handle: "left", data_utf8: "ping"});
  const ready = sys.poll({fds: [{handle: "right", events: "POLLIN"}], timeout_ms: 100});
  const got = sys.read({handle: "right", length: 4, encoding: "utf8"});
  return {ready, got};
} finally {
  sys.close({handle: "left"});
  sys.close({handle: "right"});
}
` + "```" + `

Ioctl with a managed buffer:

` + "```javascript" + `
sys.bufferAlloc({name: "argp", size: 8, replace_existing: true});
const ioctl = sys.ioctl({handle: args.handle, request: "FIONREAD", buffer: "argp", buffer_length: 4});
const argp = sys.bufferRead({name: "argp", length: 4, encoding: "hex"});
return {ioctl, argp};
` + "```" + `

Use ` + "`sys.constants({group: 'open_flags'})`" + `, ` + "`sys.constant('O_CLOEXEC')`" + `, and ` + "`sys.errno({name:'ENOENT'})`" + ` when constructing portable scripts.

Go os/io file copy:

` + "```javascript" + `
os.writeFile({name: args.path, data_utf8: "hello", perm: "0600"});
const src = os.open({name: args.path, handle: "copySrc"});
const dst = os.create({name: args.copy, handle: "copyDst"});
try {
  const copied = io.copy({dst: {handle: "copyDst"}, src: {handle: "copySrc"}});
  const got = os.readFile({name: args.copy, encoding: "utf8"});
  return {copied, got};
} finally {
  os.fileClose({handle: "copySrc"});
  os.fileClose({handle: "copyDst"});
}
` + "```" + `
`
}

func apiReferenceMarkdown() string {
	return `# Linux UAPI API Reference

Agents should begin by reading MCP resources ` + "`uapi://agent-guide`" + `, ` + "`uapi://capabilities`" + `, and ` + "`uapi://scripting-api`" + ` through the MCP client resource API. The only public MCP tool is ` + "`eval`" + `; all Linux UAPI operations are available inside eval through the ` + "`sys`" + ` object, with ` + "`uapi`" + ` kept as an alias for older scripts. Go standard-library style filesystem and stream workflows are available through the ` + "`os`" + ` and ` + "`io`" + ` globals. Numeric fields accept JSON numbers, decimal strings, hex strings, or constant expressions such as ` + "`O_RDWR|O_CREAT|O_CLOEXEC`" + `.

MCP resources are not readable from JavaScript. Do not call ` + "`uapi.request('GET', 'uapi://capabilities')`" + `, ` + "`sys.request`" + `, or ` + "`fetch`" + ` inside eval. Use ` + "`sys.capabilities()`" + ` inside eval when a script needs the capability document.

## Result Model

Malformed script arguments, unknown handles, oversized reads, and invalid buffer ranges are eval errors. Linux syscall failures are normal observations and return structured JSON like:

` + "```json" + `
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
` + "```" + `

Successful syscall wrappers return ` + "`ok: true`" + ` plus syscall-specific fields. Prefer managed handles over raw FDs. Raw integer FDs require ` + "`--allow-raw-fd`" + `.

Go ` + "`os`" + `/` + "`io`" + ` wrappers also return ` + "`ok: true`" + ` on success. Package errors return ` + "`ok: false`" + ` with ` + "`error`" + `, ` + "`error_type`" + `, and where available ` + "`error_name`" + `, ` + "`path`" + `, ` + "`op`" + `, ` + "`errno`" + `, and ` + "`errno_name`" + `.

## Core Workflows

- Reconnaissance: ` + "`sys.uname()`" + `, ` + "`sys.stat()`" + `, ` + "`sys.statx()`" + `, ` + "`sys.readlink()`" + `, ` + "`sys.open()`" + `, ` + "`sys.read()`" + `, and ` + "`sys.close()`" + `.
- Filesystem mutation: ` + "`sys.openat()`" + `, ` + "`sys.fstatat()`" + `, ` + "`sys.mkdirat()`" + `, ` + "`sys.renameat2()`" + `, ` + "`sys.fchmodat()`" + `, and ` + "`sys.unlinkat()`" + `.
- Socket clients: ` + "`sys.socket()`" + ` or ` + "`sys.socketpair()`" + `, then ` + "`sys.connect()`" + `, ` + "`sys.sendto()`" + `, ` + "`sys.recvfrom()`" + `, ` + "`sys.poll()`" + ` or ` + "`sys.epollWait()`" + `.
- ioctl probing: allocate a buffer with ` + "`sys.bufferAlloc()`" + `, initialize it with ` + "`sys.bufferWrite()`" + `, call ` + "`sys.ioctl()`" + ` with ` + "`buffer`" + `, then inspect with ` + "`sys.bufferRead()`" + `.
- ptrace memory reads: ` + "`sys.ptraceAttach()`" + ` with wait enabled, ` + "`sys.ptraceRead()`" + ` bounded ranges, then ` + "`sys.ptraceDetach()`" + `.
- mmap experiments: ` + "`sys.mmap()`" + ` anonymous or file-backed memory, mutate with ` + "`sys.memWrite()`" + `, inspect with ` + "`sys.memRead()`" + `, and clean up with ` + "`sys.munmap()`" + `.
- Event and metadata helpers: ` + "`sys.eventfd()`" + `, ` + "`sys.memfdCreate()`" + `, ` + "`sys.inotifyInit1()`" + `, ` + "`sys.getxattr()`" + `, ` + "`sys.setxattr()`" + `, ` + "`sys.sendfile()`" + `, and ` + "`sys.copyFileRange()`" + `.
- Go os/io workflows: ` + "`os.readFile()`" + `, ` + "`os.writeFile()`" + `, ` + "`os.open()`" + `, ` + "`os.openFile()`" + `, ` + "`os.openRoot()`" + `, ` + "`os.rootReadFile()`" + `, ` + "`os.fileRead()`" + `, ` + "`os.fileWrite()`" + `, ` + "`io.copy()`" + `, ` + "`io.copyN()`" + `, ` + "`io.readAll()`" + `, ` + "`io.readFull()`" + `, and ` + "`io.writeString()`" + `.

## Safety Notes

This server intentionally exposes primitives useful for embedded systems testing and low-level research. Eval scripts can modify the filesystem, signal processes, attach to processes permitted by Linux ptrace policy, and issue arbitrary ioctls. Run it in an isolated lab environment with a trusted MCP client.
`
}

func scriptingAPIMarkdown() string {
	return `# Linux UAPI Scripting API

The ` + "`eval`" + ` tool executes JavaScript with Goja. Scripts run inside a function body, so use ` + "`return`" + ` to produce JSON. ` + "`console.log/info/warn/error`" + ` output is captured in the response.

Before calling eval, read MCP resources ` + "`uapi://agent-guide`" + `, ` + "`uapi://scripting-api`" + `, and ` + "`uapi://api-reference`" + ` with the MCP client resource API. Do not try to read those resources from JavaScript: ` + "`uapi.request`" + `, ` + "`sys.request`" + `, ` + "`fetch`" + `, ` + "`require`" + `, and ` + "`import`" + ` are not available in the eval runtime.

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
- ` + "`os`" + `: synchronous Go package os style wrappers for files, dirs, env, roots, processes, and File methods over managed handles.
- ` + "`io`" + `: synchronous Go package io style copy/read/write helpers over managed handle, buffer, path, data, and discard endpoints.

Not globals: ` + "`uapi.request`" + `, ` + "`sys.request`" + `, ` + "`fetch`" + `, ` + "`XMLHttpRequest`" + `, ` + "`require`" + `, ` + "`import`" + `, Node.js modules, or server-terminating helpers such as ` + "`os.Exit`" + `. Resource reading happens at the MCP client layer, not inside eval.

Safe bootstrap:

` + "```javascript" + `
const caps = sys.capabilities();
return {
  name: caps.name,
  wrappers: caps.scripting_api.uapi_wrappers,
  osWrappers: caps.scripting_api.os_wrappers,
  ioWrappers: caps.scripting_api.io_wrappers,
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

The ` + "`os`" + ` and ` + "`io`" + ` objects expose lower camel-case names such as ` + "`os.readFile()`" + ` and ` + "`io.copy()`" + ` plus Go-style aliases such as ` + "`os.ReadFile()`" + ` and ` + "`io.Copy()`" + `. File-returning helpers return managed FD handles. Use ` + "`os.fileClose({handle})`" + ` or ` + "`sys.close({handle})`" + ` to release them.
`
}
