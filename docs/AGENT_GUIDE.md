# MCP-UAPI Agent Guide

This server is intentionally eval-first for Linux UAPI work, with managed-tool lifecycle MCP tools for saving reusable eval scripts. Use `eval` for one-off workflows, and use `tool_register`, `tool_execute`, `tool_list`, `tool_read`, `tool_export`, `tool_import`, `tool_update`, and `tool_delete` when a script should become a reusable tool. Discovery documents, reusable example scripts, references, and prompts are exposed as MCP resources and prompts so a new agent can learn the API before it writes a script.

## Correct Bootstrap

Use the MCP client's resource APIs before calling `eval`:

1. Read MCP resource `uapi://agent-guide` for this orientation.
2. Read MCP resource `uapi://tools-guide` for managed eval tool registration, execution, export/import, and persistence.
3. Read MCP resource `uapi://scripting-api` for JavaScript globals, wrapper groups, and examples.
4. Read MCP resource `uapi://api-reference` for result conventions, handles, constants, and workflow notes.
5. Read MCP resource `uapi://api` for API-specific documents, and `uapi://api/index.json` when a machine-readable index is easier.
6. Read MCP resource `uapi://examples` for reusable eval scripts, and `uapi://examples/index.json` when a machine-readable index is easier.
7. Read MCP resource `uapi://capabilities` when you need machine-readable wrapper names, constants, prompts, resources, docs, and example-script metadata.
8. Call MCP tool `tool_list` to discover runtime-registered eval tools.
9. Call MCP tool `eval` for one-off syscall workflows, or `tool_execute` when an existing managed tool fits.

Do not try to fetch MCP resources from inside JavaScript. These are wrong and will fail because they are not part of the eval runtime:

```javascript
uapi.request('GET', 'uapi://capabilities')
sys.request('GET', 'uapi://capabilities')
fetch('uapi://capabilities')
require('fs')
```

Inside eval, use `sys.capabilities()` for the same machine-readable capability document after the resource-reading phase.

## Eval Tool Shape

Call the MCP tool named `eval` with this envelope:

```json
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
```

Scripts run inside a function body. Use `return` for the JSON result. Logs written with `console.log/info/warn/error` or `print` are captured in the eval response.

## Eval Runtime

Available globals:

- `args`: caller-provided JSON object.
- `console` and `print`: captured logging.
- `sys`: synchronous Linux sys/unix scripting API.
- `uapi`: alias for `sys` for older scripts.
- `os`: synchronous Go package os style wrappers over managed handles, roots, processes, env, and filesystem helpers.
- `io`: synchronous Go package io style copy/read/write helpers over managed handle, net connection, buffer, path, data, and discard endpoints.
- `net`: synchronous Go package net style wrappers over TCP/IP, UDP, Unix domain sockets, DNS resolution, interfaces, and managed network handles.

Not available in eval: `uapi.request`, `sys.request`, `fetch`, `XMLHttpRequest`, `require`, `import`, Node.js modules, direct MCP resource reads, and server-terminating helpers such as `os.Exit`.

## Discovery Probe

Use this as the first read-only eval script:

```javascript
const caps = sys.capabilities();
return {
  name: caps.name,
  publicTools: caps.tools.map(t => t.name),
  resources: caps.resources,
  examples: caps.example_scripts,
  wrappers: caps.scripting_api.uapi_wrappers,
  osWrappers: caps.scripting_api.os_wrappers,
  ioWrappers: caps.scripting_api.io_wrappers,
  netWrappers: caps.scripting_api.net_wrappers,
  constants: Object.keys(sys.constants().constants),
  uname: sys.uname()
};
```

Expected public tools include `eval` and managed-tool lifecycle tools. Expected scripting objects inside eval are `sys`, with `uapi` as the same object, plus `os` and `io` standard-library wrappers.

## Managed Tools

Use `tool_register` when a script is worth saving for later. Registered tools have a stable name, optional input schema, tags, metadata, read-only/destructive annotations, and optional eval defaults. Use `tool_execute` to run the saved script with caller `args`; it returns the same result shape as `eval`.

Managed tools live in memory by default. If the server starts with `--tool-db`, mutations are persisted to a JSON database on the device. Use `tool_export` and `tool_import` to share a toolbox across agents, projects, or devices. Read `uapi://tools-guide` for the full lifecycle and bundle format.

## Result Model

Eval responses have `ok`, `result`, `logs`, `operations`, timing fields, and optional `error`. Malformed script inputs, unknown handles, invalid ranges, bad constants, and result-size violations are eval errors. Linux errno failures are data returned by syscall wrappers:

```json
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
```

Treat `ok:false` errno values as observations during probing rather than crashes.

## Handle Discipline

Helpers that create FDs, buffers, and mappings return managed names. Reuse those names within later eval calls, and read `uapi://state` through MCP resources when you need a live inventory. Close what you create:

- FDs: `sys.close({handle})` or `os.fileClose({handle})`.
- Network connections/listeners/packet sockets: `net.connClose({conn})`, `net.listenerClose({listener})`, or `net.packetClose({packet})`.
- Roots: `os.rootClose({root})`.
- Mappings: `sys.munmap({mapping})`.
- Buffers: `sys.bufferFree({name})`.

Raw integer FDs require the server to be started with `--allow-raw-fd`. Prefer managed handles.

## Reusable Examples

Reusable eval scripts live in the repository under `examples/*.js`, are embedded into the binary at build time, and are exposed as MCP resources under `uapi://examples/<file>.js`. Start with `uapi://examples` for the human-readable index or `uapi://examples/index.json` for metadata.

## API Documents

API-specific documentation lives under `uapi://api`. Start with `uapi://api` for the index, then read resources such as `uapi://api/sys-unix`, `uapi://api/sys-unix-vectored-io`, `uapi://api/sys-unix-process-memory`, and `uapi://api/ebpf` for wrapper parameters, relevant constants, and copy-ready examples.

For eBPF workflows, prefer the self-contained program kinds documented in `uapi://api/ebpf`. They are compiled inside the MCP binary and do not require clang, bpftool, a C compiler, raw assembly, or ELF loading on the target device.