# Scripting API

`eval` is the only public MCP tool. It runs JavaScript in a fresh Goja runtime for each call. Scripts execute inside a function body, so use `return` for the JSON result. Console output is captured and returned with the eval response.

```json
{
  "script": "const caps = sys.capabilities(); return {name: caps.name, uname: sys.uname()};",
  "args": {},
  "timeout_ms": 5000,
  "max_log_entries": 200,
  "max_result_bytes": 1048576
}
```

Globals:

- `args`: caller JSON.
- `console.log/info/warn/error` and `print`: captured logs.
- `sys`: synchronous Linux `golang.org/x/sys/unix` scripting API plus managed handle helpers.
- `uapi`: alias for `sys` for compatibility with older scripts.

Safe discovery probe:

```javascript
const caps = sys.capabilities();
return {
  wrappers: caps.scripting_api.uapi_wrappers,
  uname: sys.uname(),
  openFlags: sys.constants({group: "open_flags"}).constants,
  atConstants: sys.constants({group: "at"}).constants
};
```

Every syscall-style helper returns `ok: true` on success. Linux errno failures are structured observations with `ok: false`, `errno`, `errno_name`, and `error`; malformed arguments throw eval errors.

Common script groups:

- Metadata: `sys.capabilities`, `sys.constants`, `sys.constant`, `sys.errno`, `sys.uname`, `sys.getpid`, `sys.getids`, `sys.state`, `sys.hex`.
- Files and descriptors: `sys.open`, `sys.openat`, `sys.close`, `sys.read`, `sys.write`, `sys.pread`, `sys.pwrite`, `sys.lseek`, `sys.fstat`, `sys.fstatat`, `sys.stat`, `sys.statfs`, `sys.fstatfs`, `sys.statx`, `sys.readlink`, `sys.readlinkat`, `sys.truncate`, `sys.ftruncate`, `sys.fsync`, `sys.fdatasync`, `sys.syncfs`, `sys.dup`, `sys.dup2`, `sys.dup3`, `sys.pipe`, `sys.pipe2`, `sys.closeRange`, `sys.setNonblock`, `sys.fcntlInt`.
- Filesystem mutation: `sys.access`, `sys.faccessat`, `sys.chmod`, `sys.fchmod`, `sys.fchmodat`, `sys.chown`, `sys.fchown`, `sys.fchownat`, `sys.lchown`, `sys.mkdir`, `sys.mkdirat`, `sys.mkfifo`, `sys.mkfifoat`, `sys.mknod`, `sys.mknodat`, `sys.link`, `sys.linkat`, `sys.symlink`, `sys.symlinkat`, `sys.unlink`, `sys.unlinkat`, `sys.rmdir`, `sys.rename`, `sys.renameat`, `sys.renameat2`.
- Buffers and mappings: `sys.bufferAlloc`, `sys.bufferWrite`, `sys.bufferRead`, `sys.bufferInfo`, `sys.bufferFree`, `sys.mmap`, `sys.munmap`, `sys.mprotect`, `sys.msync`, `sys.madvise`, `sys.memRead`, `sys.memWrite`.
- Networking and readiness: `sys.socket`, `sys.socketpair`, `sys.bind`, `sys.connect`, `sys.listen`, `sys.accept`, `sys.sendto`, `sys.recvfrom`, `sys.getsockname`, `sys.getpeername`, `sys.setsockoptInt`, `sys.getsockoptInt`, `sys.shutdown`, `sys.poll`, `sys.epollCreate`, `sys.epollCtl`, `sys.epollWait`, `sys.eventfd`, `sys.inotifyInit1`, `sys.inotifyAddWatch`, `sys.inotifyRmWatch`.
- Process, xattr, and transfer: `sys.kill`, `sys.wait4`, `sys.prctl`, `sys.ptraceAttach`, `sys.ptraceDetach`, `sys.ptraceRead`, `sys.ptraceWrite`, `sys.ptraceCont`, `sys.ptraceSyscall`, `sys.getgroups`, `sys.getresuid`, `sys.getresgid`, `sys.getrlimit`, `sys.setrlimit`, `sys.getrusage`, `sys.getxattr`, `sys.listxattr`, `sys.setxattr`, `sys.removexattr`, `sys.memfdCreate`, `sys.sendfile`, `sys.copyFileRange`.

Socketpair example:

```javascript
const pair = sys.socketpair({handles: ["left", "right"]});
sys.write({handle: "left", data_utf8: "ping"});
const ready = sys.poll({fds: [{handle: "right", events: "POLLIN"}], timeout_ms: 100});
const got = sys.read({handle: "right", length: 4, encoding: "utf8"});
sys.close({handle: "left"});
sys.close({handle: "right"});
return {ready, got};
```

At-family file example:

```javascript
const file = sys.openat({path: args.path, flags: "O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC", mode: "0600"});
sys.write({handle: file.handle, data_utf8: args.payload || "hello"});
sys.fsync({handle: file.handle});
const stat = sys.fstatat({path: args.path});
sys.close({handle: file.handle});
return stat;
```