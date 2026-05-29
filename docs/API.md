# API Reference

Start with `uapi_capabilities`, `uapi_constants`, and `uapi://state`. The server exposes process-local handles for FDs, buffers, and mappings so agents do not need to juggle raw integer FDs.

## Result Model

Syscall errno is data:

```json
{"ok": false, "errno": 111, "errno_name": "ECONNREFUSED", "error": "connection refused"}
```

Invalid MCP inputs are tool errors: unknown handles, unsupported encodings, invalid ranges, malformed constants, or oversized reads.

## Constant Expressions

Fields typed as integer or string accept numeric values, hex strings, or constant expressions:

```json
{"flags":"O_RDWR|O_CREAT|O_CLOEXEC"}
```

Use `uapi_constants` for supported groups: `open_flags`, `socket`, `mmap`, `poll`, `epoll`, `signal`, `wait`, `ioctl`, `prctl`, and `errno`.

## Handles

Managed handles are returned by tools that create resources. Use `handle` for normal FD tools, `mapping` for memory mappings, and `name` for buffers. Raw FDs require `--allow-raw-fd`.

## Tool Groups

- Metadata: `uapi_capabilities`, `uapi_constants`, `uapi_errno`, `uapi_uname`, `uapi_getpid`.
- Files: `uapi_open`, `uapi_close`, `uapi_read`, `uapi_write`, `uapi_pread`, `uapi_pwrite`, `uapi_lseek`, `uapi_fstat`, `uapi_stat`, `uapi_readlink`.
- Buffers: `uapi_buffer_alloc`, `uapi_buffer_write`, `uapi_buffer_read`, `uapi_buffer_info`, `uapi_buffer_free`.
- Memory: `uapi_mmap`, `uapi_mem_write`, `uapi_mem_read`, `uapi_mprotect`, `uapi_msync`, `uapi_madvise`, `uapi_munmap`.
- Network: `uapi_socket`, `uapi_socketpair`, `uapi_bind`, `uapi_connect`, `uapi_listen`, `uapi_accept`, `uapi_sendto`, `uapi_recvfrom`, `uapi_getsockname`, `uapi_getpeername`, `uapi_setsockopt_int`, `uapi_getsockopt_int`, `uapi_shutdown`.
- Readiness: `uapi_poll`, `uapi_epoll_create`, `uapi_epoll_ctl`, `uapi_epoll_wait`.
- Process: `uapi_kill`, `uapi_wait4`, `uapi_prctl`, `uapi_ptrace_attach`, `uapi_ptrace_read`, `uapi_ptrace_write`, `uapi_ptrace_cont`, `uapi_ptrace_syscall`, `uapi_ptrace_detach`.
- Ioctl: `uapi_ioctl` with `arg` or `buffer`/`buffer_offset`/`buffer_length`.
- Scripting: `eval`.

## Ptrace Workflow

1. Attach with `uapi_ptrace_attach({pid, wait:true})`.
2. Read or write bounded ranges with `uapi_ptrace_read` and `uapi_ptrace_write`.
3. Continue or syscall-step with `uapi_ptrace_cont` or `uapi_ptrace_syscall` when needed.
4. Detach with `uapi_ptrace_detach`.

Linux Yama and capability policy still applies. For non-child targets, the server process may need `CAP_SYS_PTRACE` or a permissive `ptrace_scope`.