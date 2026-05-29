# Security And Safety

`mcp-uapi` is a direct Linux syscall tool. It is intended for isolated test systems, emulators, lab devices, and controlled embedded systems research.

Risks include:

- Filesystem mutation through open/write/truncate/unlink-like future extensions.
- Socket traffic to local or remote services.
- Process signaling and waiting.
- Ptrace reads/writes of processes permitted by kernel policy.
- Arbitrary ioctl requests against device files or sockets.
- Memory mapping and protection changes inside the MCP server process.

Recommended deployment:

- Run in a VM, container, or lab host where the MCP client is trusted.
- Use the default managed-handle mode; avoid `--allow-raw-fd` unless needed.
- Keep `--listen` bound to localhost unless remote access is intentionally required and protected by the surrounding environment.
- Prefer nonblocking sockets and bounded `poll`/`epoll_wait` timeouts in automated loops.
- Keep `--max-read-bytes` and `--max-buffer-bytes` conservative for remote agents.