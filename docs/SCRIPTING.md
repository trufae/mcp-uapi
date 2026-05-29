# Scripting API

`eval` is the only public MCP tool. It runs JavaScript in a fresh Goja runtime for each call. Scripts execute inside a function body, so use `return` for the JSON result. Console output is captured and returned with the eval response.

Before eval, agents should read MCP resources `uapi://agent-guide`, `uapi://scripting-api`, `uapi://api-reference`, `uapi://api`, and `uapi://capabilities` through the MCP client resource API. Those resources are not JavaScript URLs. Do not call `uapi.request('GET', 'uapi://capabilities')`, `sys.request`, `fetch`, `require`, or `import` inside eval.

Reusable scripts live as individual files in `examples/`, are embedded into the binary at build time, and are exposed as `uapi://examples/<file>.js`. Read `uapi://examples` for a human-readable index or `uapi://examples/index.json` for metadata before choosing a script.

API-specific docs live in `docs/api/`, are embedded into the binary at build time, and are exposed under `uapi://api/<name>`. Start with `uapi://api` or `uapi://api/index.json`, then read resources such as `uapi://api/sys-unix`, `uapi://api/sys-unix-vectored-io`, and `uapi://api/sys-unix-process-memory` for parameters, constants, and examples.

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
- `os`: synchronous Go package `os` style wrappers for files, directories, env, roots, processes, and File methods over managed handles.
- `io`: synchronous Go package `io` style copy/read/write helpers over managed handle, buffer, path, data, and discard endpoints.

Not globals: `uapi.request`, `sys.request`, `fetch`, `XMLHttpRequest`, `require`, `import`, Node.js modules, or server-terminating helpers such as `os.Exit`. Inside eval, use `sys.capabilities()` for the same machine-readable capability data that is served as `uapi://capabilities`.

Safe discovery probe:

```javascript
const caps = sys.capabilities();
return {
  wrappers: caps.scripting_api.uapi_wrappers,
  osWrappers: caps.scripting_api.os_wrappers,
  ioWrappers: caps.scripting_api.io_wrappers,
  uname: sys.uname(),
  openFlags: sys.constants({group: "open_flags"}).constants,
  atConstants: sys.constants({group: "at"}).constants
};
```

Every syscall-style helper returns `ok: true` on success. Linux errno failures are structured observations with `ok: false`, `errno`, `errno_name`, and `error`; malformed arguments throw eval errors.

Go `os`/`io` helpers also return `ok: true` on success. Package errors return `ok: false` with `error`, `error_type`, and when available `error_name`, `op`, `path`, `errno`, and `errno_name`.

Common script groups:

- Metadata: `sys.capabilities`, `sys.constants`, `sys.constant`, `sys.errno`, `sys.uname`, `sys.getpid`, `sys.getids`, `sys.state`, `sys.hex`.
- Files and descriptors: `sys.open`, `sys.creat`, `sys.openat`, `sys.openat2`, `sys.close`, `sys.read`, `sys.write`, `sys.pread`, `sys.pwrite`, `sys.readv`, `sys.writev`, `sys.preadv`, `sys.pwritev`, `sys.preadv2`, `sys.pwritev2`, `sys.lseek`, `sys.fstat`, `sys.fstatat`, `sys.stat`, `sys.statfs`, `sys.fstatfs`, `sys.statx`, `sys.readlink`, `sys.readlinkat`, `sys.getdents`, `sys.readDirent`, `sys.truncate`, `sys.ftruncate`, `sys.fallocate`, `sys.fadvise`, `sys.syncFileRange`, `sys.flock`, `sys.fsync`, `sys.fdatasync`, `sys.syncfs`, `sys.dup`, `sys.dup2`, `sys.dup3`, `sys.pipe`, `sys.pipe2`, `sys.closeRange`, `sys.setNonblock`, `sys.fcntlInt`.
- Filesystem mutation: `sys.access`, `sys.faccessat`, `sys.chmod`, `sys.fchmod`, `sys.fchmodat`, `sys.chown`, `sys.fchown`, `sys.fchownat`, `sys.lchown`, `sys.mkdir`, `sys.mkdirat`, `sys.mkfifo`, `sys.mkfifoat`, `sys.mknod`, `sys.mknodat`, `sys.link`, `sys.linkat`, `sys.symlink`, `sys.symlinkat`, `sys.unlink`, `sys.unlinkat`, `sys.rmdir`, `sys.rename`, `sys.renameat`, `sys.renameat2`.
- Buffers and mappings: `sys.bufferAlloc`, `sys.bufferWrite`, `sys.bufferRead`, `sys.bufferInfo`, `sys.bufferFree`, `sys.mmap`, `sys.munmap`, `sys.mprotect`, `sys.msync`, `sys.madvise`, `sys.memRead`, `sys.memWrite`.
- Networking and readiness: `sys.socket`, `sys.socketpair`, `sys.bind`, `sys.connect`, `sys.listen`, `sys.accept`, `sys.send`, `sys.sendto`, `sys.recvfrom`, `sys.sendmsg`, `sys.recvmsg`, `sys.getsockname`, `sys.getpeername`, `sys.setsockoptInt`, `sys.getsockoptInt`, `sys.setsockoptString`, `sys.getsockoptString`, `sys.setsockoptByte`, `sys.getsockoptByte`, `sys.setsockoptUint64`, `sys.getsockoptUint64`, `sys.bindToDevice`, `sys.shutdown`, `sys.poll`, `sys.epollCreate`, `sys.epollCtl`, `sys.epollWait`, `sys.eventfd`, `sys.timerfdCreate`, `sys.timerfdGettime`, `sys.timerfdSettime`, `sys.inotifyInit1`, `sys.inotifyAddWatch`, `sys.inotifyRmWatch`.
- Process, xattr, and transfer: `sys.kill`, `sys.tgkill`, `sys.wait4`, `sys.prctl`, `sys.prctlRetInt`, `sys.pidfdOpen`, `sys.pidfdGetfd`, `sys.pidfdSendSignal`, `sys.ptraceAttach`, `sys.ptraceDetach`, `sys.ptraceRead`, `sys.ptraceWrite`, `sys.ptraceCont`, `sys.ptraceSyscall`, `sys.processVMReadv`, `sys.processVMWritev`, `sys.getpgid`, `sys.getpgrp`, `sys.getsid`, `sys.setpgid`, `sys.setsid`, `sys.getpriority`, `sys.setpriority`, `sys.getgroups`, `sys.getresuid`, `sys.getresgid`, `sys.getrlimit`, `sys.setrlimit`, `sys.prlimit`, `sys.getrusage`, `sys.clockGettime`, `sys.clockGetres`, `sys.gettimeofday`, `sys.nanosleep`, `sys.getrandom`, `sys.getxattr`, `sys.listxattr`, `sys.setxattr`, `sys.removexattr`, `sys.memfdCreate`, `sys.sendfile`, `sys.copyFileRange`, `sys.splice`, `sys.tee`, `sys.vmsplice`.
- Go os package: `os.readFile`, `os.writeFile`, `os.open`, `os.openFile`, `os.create`, `os.openRoot`, `os.rootReadFile`, `os.rootWriteFile`, `os.fileRead`, `os.fileWrite`, `os.fileSeek`, `os.fileStat`, `os.fileClose`, `os.getenv`, `os.setenv`, `os.getwd`, `os.readDir`, `os.stat`, `os.findProcess`, `os.startProcess`.
- Go io package: `io.copy`, `io.copyBuffer`, `io.copyN`, `io.readAll`, `io.readAtLeast`, `io.readFull`, `io.writeString`, `io.limitReader`, `io.multiReader`, `io.teeReader`, `io.multiWriter`, `io.newSectionReader`, `io.newOffsetWriter`, `io.pipe`.

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

Go os/io file copy example:

```javascript
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
```