# Managed Eval Tools

Managed eval tools are reusable JavaScript scripts stored by the MCP server. They use the same runtime as `eval`: scripts run inside a function body with `args`, `console`, `print`, `sys`, `uapi`, `os`, and `io` globals, and they return the same eval response shape.

Use managed tools when an agent has learned a workflow that should be reused later, shared with another agent, or moved between projects as a small toolbox.

## Storage

By default, registered tools live only in server memory and disappear when the MCP process exits.

Start the server with `--tool-db /path/to/tools.json` to back the registry with an on-device JSON database. Mutations are validated first and then written with an atomic replace. If the file does not exist, the server starts with an empty registry and creates it on the first mutation.

## Tool Lifecycle

Register a tool:

```json
{
  "name": "tool_register",
  "arguments": {
    "name": "proc.version.read",
    "description": "Read /proc/version with managed FD cleanup.",
    "tags": ["linux", "proc"],
    "read_only": true,
    "destructive": false,
    "input_schema": {
      "type": "object",
      "properties": {
        "path": {"type": "string", "default": "/proc/version"}
      }
    },
    "script": "const path = args.path || '/proc/version'; const fd = sys.open({path, flags:'O_RDONLY|O_CLOEXEC'}); try { return sys.read({handle: fd.handle, length:4096, encoding:'utf8'}); } finally { sys.close({handle: fd.handle}); }"
  }
}
```

Execute it:

```json
{
  "name": "tool_execute",
  "arguments": {
    "name": "proc.version.read",
    "args": {"path": "/proc/version"}
  }
}
```

List registered tools without script bodies:

```json
{"name": "tool_list", "arguments": {}}
```

Read one full tool, including its script:

```json
{"name": "tool_read", "arguments": {"name": "proc.version.read"}}
```

Update a tool. Omitted fields keep their current values. Use `input_schema: null` to clear a schema.

```json
{
  "name": "tool_update",
  "arguments": {
    "name": "proc.version.read",
    "description": "Read a small text file from procfs.",
    "timeout_ms": 2000
  }
}
```

Delete a tool:

```json
{"name": "tool_delete", "arguments": {"name": "proc.version.read"}}
```

## Export And Import

Export all tools:

```json
{"name": "tool_export", "arguments": {}}
```

Export selected tools:

```json
{"name": "tool_export", "arguments": {"names": ["proc.version.read"]}}
```

The result is a portable bundle:

```json
{
  "schema": "mcp-uapi.tools.v1",
  "exported_at": "2026-05-31T00:00:00Z",
  "tools": [
    {
      "name": "proc.version.read",
      "description": "Read /proc/version with managed FD cleanup.",
      "script": "...",
      "read_only": true,
      "destructive": false,
      "revision": 1,
      "created_at": "2026-05-31T00:00:00Z",
      "updated_at": "2026-05-31T00:00:00Z"
    }
  ]
}
```

Import a bundle:

```json
{
  "name": "tool_import",
  "arguments": {
    "bundle": {
      "schema": "mcp-uapi.tools.v1",
      "tools": [
        {
          "name": "proc.version.read",
          "script": "return sys.uname();",
          "read_only": true,
          "destructive": false
        }
      ]
    },
    "replace_existing": true
  }
}
```

Imports are validated before they are applied. Duplicate names in a bundle, reserved built-in MCP tool names, invalid scripts, invalid metadata, or existing tools without `replace_existing` fail the import without changing the current registry.

## Conventions

- Use names such as `stack.workflow.action` or `target:workflow:action`; names accept `A-Za-z0-9_.:-` and are limited to 128 characters.
- Mark read-only tools with `read_only: true` and `destructive: false` when they only inspect state.
- Keep scripts self-contained and close handles in `finally` blocks.
- Put caller inputs under `args`; describe them with `input_schema` so another agent can execute the tool without rereading the script.
- Use `tool_export` and `tool_import` to share a toolbelt across agents, projects, or devices.