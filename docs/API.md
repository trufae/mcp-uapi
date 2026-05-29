# API Reference

Start by reading MCP resources `uapi://agent-guide`, `uapi://capabilities`, `uapi://scripting-api`, and `uapi://api-reference` with the MCP client resource-read operation. The only public MCP tool is `eval`; the server exposes process-local handles for FDs, buffers, and mappings inside the JavaScript `sys`/`uapi` scripting API so agents do not need to juggle raw integer FDs.

MCP resources are documentation and discovery surfaces outside the eval runtime. Do not call `uapi.request('GET', 'uapi://capabilities')`, `sys.request`, `fetch`, `require`, or `import` inside eval. Use `sys.capabilities()` inside eval when a script needs the machine-readable capability document.

Correct eval tool envelope:

```json
{
	"name": "eval",
	"arguments": {
		"script": "const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers.length};",
		"args": {}
	}
}
```

## Result Model

Syscall errno is data:

```json
{"ok": false, "errno": 111, "errno_name": "ECONNREFUSED", "error": "connection refused"}
```

Invalid script inputs are eval errors: unknown handles, unsupported encodings, invalid ranges, malformed constants, or oversized reads.

## Constant Expressions

Fields typed as integer or string accept numeric values, hex strings, or constant expressions:

```json
{"flags":"O_RDWR|O_CREAT|O_CLOEXEC"}
```

Use `sys.constants({group})` or `sys.constant("NAME")` for supported groups: `open_flags`, `socket`, `access`, `at`, `fcntl`, `file_type`, `mmap`, `poll`, `epoll`, `eventfd`, `memfd`, `close_range`, `inotify`, `statx`, `rename`, `signal`, `wait`, `rlimit`, `ioctl`, `prctl`, and `errno`.

## Handles

Managed handles are returned by script helpers that create resources. Use `handle` for normal FD helpers, `mapping` for memory mappings, and `name` for buffers. Raw FDs require `--allow-raw-fd`.

## Scripting Groups

- Metadata: `sys.capabilities`, `sys.constants`, `sys.constant`, `sys.errno`, `sys.uname`, `sys.getpid`, `sys.getids`, `sys.state`.
- Files: `sys.open`, `sys.openat`, `sys.close`, `sys.read`, `sys.write`, `sys.pread`, `sys.pwrite`, `sys.lseek`, `sys.fstat`, `sys.fstatat`, `sys.stat`, `sys.statfs`, `sys.fstatfs`, `sys.statx`, `sys.readlink`, `sys.readlinkat`, `sys.truncate`, `sys.ftruncate`, `sys.fsync`, `sys.fdatasync`, `sys.sync`, `sys.syncfs`.
- Descriptor controls: `sys.dup`, `sys.dup2`, `sys.dup3`, `sys.pipe`, `sys.pipe2`, `sys.closeRange`, `sys.setNonblock`, `sys.fcntlInt`.
- Filesystem mutation: `sys.access`, `sys.faccessat`, `sys.chmod`, `sys.fchmod`, `sys.fchmodat`, `sys.chown`, `sys.fchown`, `sys.fchownat`, `sys.lchown`, `sys.mkdir`, `sys.mkdirat`, `sys.mkfifo`, `sys.mkfifoat`, `sys.mknod`, `sys.mknodat`, `sys.link`, `sys.linkat`, `sys.symlink`, `sys.symlinkat`, `sys.unlink`, `sys.unlinkat`, `sys.rmdir`, `sys.rename`, `sys.renameat`, `sys.renameat2`.
- Buffers: `sys.bufferAlloc`, `sys.bufferWrite`, `sys.bufferRead`, `sys.bufferInfo`, `sys.bufferFree`.
- Memory: `sys.mmap`, `sys.memWrite`, `sys.memRead`, `sys.mprotect`, `sys.msync`, `sys.madvise`, `sys.munmap`.
- Network: `sys.socket`, `sys.socketpair`, `sys.bind`, `sys.connect`, `sys.listen`, `sys.accept`, `sys.sendto`, `sys.recvfrom`, `sys.getsockname`, `sys.getpeername`, `sys.setsockoptInt`, `sys.getsockoptInt`, `sys.shutdown`.
- Readiness and event sources: `sys.poll`, `sys.epollCreate`, `sys.epollCtl`, `sys.epollWait`, `sys.eventfd`, `sys.inotifyInit`, `sys.inotifyInit1`, `sys.inotifyAddWatch`, `sys.inotifyRmWatch`, `sys.memfdCreate`.
- Process and resources: `sys.kill`, `sys.wait4`, `sys.prctl`, `sys.ptraceAttach`, `sys.ptraceRead`, `sys.ptraceWrite`, `sys.ptraceCont`, `sys.ptraceSyscall`, `sys.ptraceDetach`, `sys.getgroups`, `sys.getresuid`, `sys.getresgid`, `sys.getrlimit`, `sys.setrlimit`, `sys.getrusage`.
- Extended attributes and transfer: `sys.getxattr`, `sys.lgetxattr`, `sys.fgetxattr`, `sys.listxattr`, `sys.llistxattr`, `sys.flistxattr`, `sys.setxattr`, `sys.lsetxattr`, `sys.fsetxattr`, `sys.removexattr`, `sys.lremovexattr`, `sys.fremovexattr`, `sys.sendfile`, `sys.copyFileRange`.
- Ioctl: `sys.ioctl` with `arg` or `buffer`/`buffer_offset`/`buffer_length`.

## Ptrace Workflow

1. Attach with `sys.ptraceAttach({pid, wait:true})`.
2. Read or write bounded ranges with `sys.ptraceRead` and `sys.ptraceWrite`.
3. Continue or syscall-step with `sys.ptraceCont` or `sys.ptraceSyscall` when needed.
4. Detach with `sys.ptraceDetach`.

Linux Yama and capability policy still applies. For non-child targets, the server process may need `CAP_SYS_PTRACE` or a permissive `ptrace_scope`.