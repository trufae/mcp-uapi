# MCP-UAPI Agent Guide

This server is intentionally eval-first. The only public MCP tool to call is `eval`. Discovery documents, reusable example scripts, references, and prompts are exposed as MCP resources and prompts so a new agent can learn the API before it writes a script.

## Correct Bootstrap

Use the MCP client's resource APIs before calling `eval`:

1. Read MCP resource `uapi://agent-guide` for this orientation.
2. Read MCP resource `uapi://scripting-api` for JavaScript globals, wrapper groups, and examples.
3. Read MCP resource `uapi://api-reference` for result conventions, handles, constants, and workflow notes.
4. Read MCP resource `uapi://api` for API-specific documents, and `uapi://api/index.json` when a machine-readable index is easier.
5. Read MCP resource `uapi://examples` for reusable eval scripts, and `uapi://examples/index.json` when a machine-readable index is easier.
6. Read MCP resource `uapi://capabilities` when you need machine-readable wrapper names, constants, prompts, resources, docs, and example-script metadata.
7. Call MCP tool `eval` for syscall workflows.

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
- `io`: synchronous Go package io style copy/read/write helpers over managed handle, buffer, path, data, and discard endpoints.

Not available in eval: `uapi.request`, `sys.request`, `fetch`, `XMLHttpRequest`, `require`, `import`, Node.js modules, direct network clients, direct MCP resource reads, and server-terminating helpers such as `os.Exit`.

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
  constants: Object.keys(sys.constants().constants),
  uname: sys.uname()
};
```

Expected public tools: only `eval`. Expected scripting objects: `sys`, with `uapi` as the same object, plus `os` and `io` standard-library wrappers.

## Result Model

Eval responses have `ok`, `result`, `logs`, `operations`, timing fields, and optional `error`. Malformed script inputs, unknown handles, invalid ranges, bad constants, and result-size violations are eval errors. Linux errno failures are data returned by syscall wrappers:

```json
{"ok": false, "errno": 2, "errno_name": "ENOENT", "error": "no such file or directory"}
```

Treat `ok:false` errno values as observations during probing rather than crashes.

## Handle Discipline

Helpers that create FDs, buffers, and mappings return managed names. Reuse those names within later eval calls, and read `uapi://state` through MCP resources when you need a live inventory. Close what you create:

- FDs: `sys.close({handle})` or `os.fileClose({handle})`.
- Roots: `os.rootClose({root})`.
- Mappings: `sys.munmap({mapping})`.
- Buffers: `sys.bufferFree({name})`.

Raw integer FDs require the server to be started with `--allow-raw-fd`. Prefer managed handles.

## Reusable Examples

Reusable eval scripts live in the repository under `examples/*.js`, are embedded into the binary at build time, and are exposed as MCP resources under `uapi://examples/<file>.js`. Start with `uapi://examples` for the human-readable index or `uapi://examples/index.json` for metadata.

## API Documents

API-specific documentation lives under `uapi://api`. Start with `uapi://api` for the index, then read resources such as `uapi://api/sys-unix`, `uapi://api/sys-unix-vectored-io`, and `uapi://api/sys-unix-process-memory` for wrapper parameters, relevant constants, and copy-ready examples.