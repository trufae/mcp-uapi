# API Reference

Start by reading MCP resources `uapi://agent-guide`, `uapi://tools-guide`, `uapi://capabilities`, `uapi://scripting-api`, `uapi://api-reference`, and `uapi://api` with the MCP client resource-read operation. Use public MCP tool `eval` for one-off scripts, and managed-tool MCP operations such as `tool_register`, `tool_execute`, `tool_list`, `tool_read`, `tool_export`, `tool_import`, `tool_update`, and `tool_delete` for reusable eval scripts. The server exposes process-local handles for FDs, buffers, mappings, roots, and processes inside the JavaScript `sys`/`uapi`, `os`, and `io` scripting APIs so agents do not need to juggle raw integer FDs.

Documentation resources are backed by the files in `docs/` and `docs/api/`, then embedded into the binary at build time. Use `uapi://docs` for the human-readable documentation index, `uapi://docs/index.json` for the machine-readable index, `uapi://api` for API-specific documentation, `uapi://api/index.json` for a machine-readable API-doc index, and the stable aliases `uapi://agent-guide`, `uapi://tools-guide`, `uapi://api-reference`, `uapi://scripting-api`, `uapi://examples-guide`, and `uapi://security` for specific documents.

Reusable eval scripts are backed by individual files in `examples/` and embedded at build time. Use `uapi://examples` for the script index, `uapi://examples/index.json` for metadata, and `uapi://examples/<file>.js` for the script text to pass to `eval`.

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

Use `sys.constants({group})` or `sys.constant("NAME")` for supported groups: `open_flags`, `socket`, `access`, `at`, `fcntl`, `file_type`, `mmap`, `poll`, `epoll`, `eventfd`, `timerfd`, `signalfd`, `memfd`, `pidfd`, `close_range`, `inotify`, `statx`, `rename`, `signal`, `wait`, `rlimit`, `priority`, `clock`, `random`, `fadvise`, `fallocate`, `sync_file_range`, `splice`, `rwf`, `openat2`, `flock`, `syscall`, `ioctl`, `prctl`, `ebpf`, `go_os`, `go_io`, and `errno`.

## Handles

Managed handles are returned by script helpers that create resources. Use `handle` for normal FD helpers, `mapping` for memory mappings, `name` for buffers, `root` or `handle` for `os.Root` wrappers, and process handles for `os.Process` wrappers. Raw FDs require `--allow-raw-fd`.

## Scripting Groups

- Metadata: `sys.capabilities`, `sys.constants`, `sys.constant`, `sys.errno`, `sys.uname`, `sys.getpid`, `sys.getids`, `sys.state`.
- Files: `sys.open`, `sys.creat`, `sys.openat`, `sys.openat2`, `sys.close`, `sys.read`, `sys.write`, `sys.pread`, `sys.pwrite`, `sys.readv`, `sys.writev`, `sys.preadv`, `sys.pwritev`, `sys.preadv2`, `sys.pwritev2`, `sys.lseek`, `sys.fstat`, `sys.fstatat`, `sys.stat`, `sys.statfs`, `sys.fstatfs`, `sys.statx`, `sys.readlink`, `sys.readlinkat`, `sys.getdents`, `sys.readDirent`, `sys.truncate`, `sys.ftruncate`, `sys.fallocate`, `sys.fadvise`, `sys.syncFileRange`, `sys.flock`, `sys.fsync`, `sys.fdatasync`, `sys.sync`, `sys.syncfs`.
- Descriptor controls: `sys.dup`, `sys.dup2`, `sys.dup3`, `sys.pipe`, `sys.pipe2`, `sys.closeRange`, `sys.setNonblock`, `sys.fcntlInt`.
- Filesystem mutation: `sys.access`, `sys.faccessat`, `sys.chmod`, `sys.fchmod`, `sys.fchmodat`, `sys.chown`, `sys.fchown`, `sys.fchownat`, `sys.lchown`, `sys.mkdir`, `sys.mkdirat`, `sys.mkfifo`, `sys.mkfifoat`, `sys.mknod`, `sys.mknodat`, `sys.link`, `sys.linkat`, `sys.symlink`, `sys.symlinkat`, `sys.unlink`, `sys.unlinkat`, `sys.rmdir`, `sys.rename`, `sys.renameat`, `sys.renameat2`.
- Buffers: `sys.bufferAlloc`, `sys.bufferWrite`, `sys.bufferRead`, `sys.bufferInfo`, `sys.bufferFree`.
- Memory: `sys.mmap`, `sys.memWrite`, `sys.memRead`, `sys.mprotect`, `sys.msync`, `sys.madvise`, `sys.munmap`.
- Network: `sys.socket`, `sys.socketpair`, `sys.bind`, `sys.connect`, `sys.listen`, `sys.accept`, `sys.sendto`, `sys.recvfrom`, `sys.getsockname`, `sys.getpeername`, `sys.setsockoptInt`, `sys.getsockoptInt`, `sys.shutdown`.
- Readiness and event sources: `sys.poll`, `sys.epollCreate`, `sys.epollCtl`, `sys.epollWait`, `sys.eventfd`, `sys.timerfdCreate`, `sys.timerfdGettime`, `sys.timerfdSettime`, `sys.inotifyInit`, `sys.inotifyInit1`, `sys.inotifyAddWatch`, `sys.inotifyRmWatch`, `sys.memfdCreate`.
- Process and resources: `sys.kill`, `sys.tgkill`, `sys.wait4`, `sys.prctl`, `sys.prctlRetInt`, `sys.pidfdOpen`, `sys.pidfdGetfd`, `sys.pidfdSendSignal`, `sys.ptraceAttach`, `sys.ptraceRead`, `sys.ptraceWrite`, `sys.ptraceCont`, `sys.ptraceSyscall`, `sys.ptraceGetRegs`, `sys.ptraceSetOptions`, `sys.ptraceDetach`, `sys.getpgid`, `sys.getpgrp`, `sys.getsid`, `sys.setpgid`, `sys.setsid`, `sys.getpriority`, `sys.setpriority`, `sys.getgroups`, `sys.getresuid`, `sys.getresgid`, `sys.getrlimit`, `sys.setrlimit`, `sys.prlimit`, `sys.getrusage`, `sys.clockGettime`, `sys.clockGetres`, `sys.gettimeofday`, `sys.nanosleep`, `sys.getrandom`, `sys.sysinfo`.
- Extended attributes and transfer: `sys.getxattr`, `sys.lgetxattr`, `sys.fgetxattr`, `sys.listxattr`, `sys.llistxattr`, `sys.flistxattr`, `sys.setxattr`, `sys.lsetxattr`, `sys.fsetxattr`, `sys.removexattr`, `sys.lremovexattr`, `sys.fremovexattr`, `sys.send`, `sys.sendmsg`, `sys.recvmsg`, `sys.sendfile`, `sys.copyFileRange`, `sys.splice`, `sys.tee`, `sys.vmsplice`, `sys.processVMReadv`, `sys.processVMWritev`.
- Ioctl: `sys.ioctl` with `arg` or `buffer`/`buffer_offset`/`buffer_length`.
- eBPF: `sys.ebpfInfo`, `sys.ebpfRemoveMemlock`, `sys.ebpfFeatureProbe`, `sys.ebpfBTFKernelInfo`, `sys.ebpfMapCreate`, `sys.ebpfMapLoadPinned`, `sys.ebpfMapLookup`, `sys.ebpfMapUpdate`, `sys.ebpfMapEntries`, `sys.ebpfMapPin`, `sys.ebpfProgramLoad`, `sys.ebpfProgramLoadPinned`, `sys.ebpfProgramTest`, `sys.ebpfAttachSocketFilter`, `sys.ebpfAttachKprobe`, `sys.ebpfAttachKretprobe`, `sys.ebpfAttachTracepoint`, `sys.ebpfAttachRawTracepoint`, `sys.ebpfAttachXDP`, `sys.ebpfLinkInfo`, `sys.ebpfLinkClose`, `sys.ebpfRingbufReaderCreate`, `sys.ebpfRingbufRead`, `sys.ebpfPerfReaderCreate`, and `sys.ebpfPerfRead`. Program loading uses built-in self-contained kinds, not target-side C compilation or raw assembly input.
- Go os package: `os.readFile`, `os.writeFile`, `os.open`, `os.openFile`, `os.create`, `os.openRoot`, `os.rootReadFile`, `os.rootWriteFile`, `os.fileRead`, `os.fileWrite`, `os.fileSeek`, `os.fileStat`, `os.fileClose`, env helpers, directory/stat helpers, and process helpers.
- Go io package: `io.copy`, `io.copyBuffer`, `io.copyN`, `io.readAll`, `io.readAtLeast`, `io.readFull`, `io.writeString`, `io.limitReader`, `io.multiReader`, `io.teeReader`, `io.multiWriter`, `io.newSectionReader`, `io.newOffsetWriter`, and `io.pipe`.

The `os` and `io` globals use lower camel-case names and also expose Go-style aliases such as `os.ReadFile` and `io.Copy`. File-returning `os` helpers return managed FD handles. Release them with `os.fileClose({handle})` or `sys.close({handle})`; release roots with `os.rootClose({root})`.

API-specific docs are available under `uapi://api`, including `uapi://api/sys-unix`, `uapi://api/sys-unix-vectored-io`, `uapi://api/sys-unix-process-memory`, `uapi://api/sys-unix-coverage`, and `uapi://api/ebpf`.

## Ptrace Workflow

1. Attach with `sys.ptraceAttach({pid, wait:true})`.
2. Read or write bounded ranges with `sys.ptraceRead` and `sys.ptraceWrite`.
3. For syscall tracing, set `PTRACE_O_TRACESYSGOOD` with `sys.ptraceSetOptions`, step with `sys.ptraceSyscall`, and inspect `sys.ptraceGetRegs`; normalized syscall metadata includes a build-time generated `name` when known.
4. Continue with `sys.ptraceCont` when needed.
5. Detach with `sys.ptraceDetach` from a ptrace-stop.

Linux Yama and capability policy still applies. For non-child targets, the server process may need `CAP_SYS_PTRACE` or a permissive `ptrace_scope`.