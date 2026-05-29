# sys/unix Scripting API

This resource is the subsystem map for the JavaScript `sys` and `uapi` globals. They expose Linux `golang.org/x/sys/unix` through synchronous JSON wrappers that use managed handles, bounded buffers, explicit encodings, and structured errno results.

Use `uapi://api/index.json` to discover all API-specific resources. Use `sys.capabilities().scripting_api.uapi_wrappers` inside eval for the machine-readable wrapper list.

## Calling Convention

Every helper accepts one object argument and returns JSON. Successful syscall helpers return `ok: true`. Linux errno failures return `ok: false`, `errno`, `errno_name`, and `error`. Bad JSON arguments, unknown handles, oversized reads, invalid encodings, and malformed constants are eval errors.

Integer fields accept numbers, hex strings, octal strings, or constant expressions such as `"O_RDWR|O_CREAT|O_CLOEXEC"`. Constants are discoverable with `sys.constants()` and `sys.constant("NAME")`.

Managed FDs are returned as `handle` names. Prefer handles over raw integer FDs; raw FDs require the server to start with `--allow-raw-fd`.

## Wrapper Groups

Metadata and raw escape hatches:

- `sys.capabilities`, `sys.constants`, `sys.constant`, `sys.errno`, `sys.uname`, `sys.getpid`, `sys.getids`, `sys.state`, `sys.hex`
- `sys.auxv`, `sys.getpagesize`, `sys.sysinfo`, `sys.major`, `sys.minor`, `sys.mkdev`, `sys.umask`
- `sys.syscall`, `sys.syscall6`, `sys.rawSyscall`, `sys.rawSyscall6`

Files, descriptors, and at-family helpers:

- `sys.open`, `sys.creat`, `sys.openat`, `sys.openat2`, `sys.close`, `sys.closeRange`
- `sys.read`, `sys.write`, `sys.pread`, `sys.pwrite`, `sys.readv`, `sys.writev`, `sys.preadv`, `sys.pwritev`, `sys.preadv2`, `sys.pwritev2`
- `sys.lseek`, `sys.dup`, `sys.dup2`, `sys.dup3`, `sys.pipe`, `sys.pipe2`, `sys.setNonblock`, `sys.fcntlInt`
- `sys.stat`, `sys.fstat`, `sys.fstatat`, `sys.statfs`, `sys.fstatfs`, `sys.statx`, `sys.readlink`, `sys.readlinkat`, `sys.getdents`, `sys.readDirent`
- `sys.truncate`, `sys.ftruncate`, `sys.fallocate`, `sys.fadvise`, `sys.syncFileRange`, `sys.flock`, `sys.fsync`, `sys.fdatasync`, `sys.sync`, `sys.syncfs`

Filesystem mutation:

- `sys.access`, `sys.faccessat`, `sys.faccessat2`, `sys.chmod`, `sys.fchmod`, `sys.fchmodat`, `sys.chown`, `sys.fchown`, `sys.fchownat`, `sys.lchown`
- `sys.mkdir`, `sys.mkdirat`, `sys.mkfifo`, `sys.mkfifoat`, `sys.mknod`, `sys.mknodat`
- `sys.link`, `sys.linkat`, `sys.symlink`, `sys.symlinkat`, `sys.unlink`, `sys.unlinkat`, `sys.rmdir`, `sys.rename`, `sys.renameat`, `sys.renameat2`

Memory, buffers, and kernel transfer:

- `sys.bufferAlloc`, `sys.bufferWrite`, `sys.bufferRead`, `sys.bufferInfo`, `sys.bufferFree`
- `sys.mmap`, `sys.munmap`, `sys.mprotect`, `sys.msync`, `sys.madvise`, `sys.memRead`, `sys.memWrite`
- `sys.memfdCreate`, `sys.sendfile`, `sys.copyFileRange`, `sys.splice`, `sys.tee`, `sys.vmsplice`
- `sys.processVMReadv`, `sys.processVMWritev`

Networking, messages, readiness, and socket options:

- `sys.socket`, `sys.socketpair`, `sys.bind`, `sys.connect`, `sys.listen`, `sys.accept`, `sys.shutdown`, `sys.bindToDevice`
- `sys.send`, `sys.sendto`, `sys.recvfrom`, `sys.sendmsg`, `sys.recvmsg`, `sys.getsockname`, `sys.getpeername`
- `sys.setsockoptInt`, `sys.getsockoptInt`, `sys.setsockoptString`, `sys.getsockoptString`, `sys.setsockoptByte`, `sys.getsockoptByte`, `sys.setsockoptUint64`, `sys.getsockoptUint64`
- `sys.poll`, `sys.epollCreate`, `sys.epollCtl`, `sys.epollWait`

Processes, clocks, event sources, and resources:

- `sys.kill`, `sys.tgkill`, `sys.wait4`, `sys.prctl`, `sys.prctlRetInt`, `sys.pidfdOpen`, `sys.pidfdGetfd`, `sys.pidfdSendSignal`
- `sys.ptraceAttach`, `sys.ptraceDetach`, `sys.ptraceRead`, `sys.ptraceWrite`, `sys.ptraceCont`, `sys.ptraceSyscall`
- `sys.getpgid`, `sys.getpgrp`, `sys.getsid`, `sys.setpgid`, `sys.setsid`, `sys.getpriority`, `sys.setpriority`
- `sys.getgroups`, `sys.getresuid`, `sys.getresgid`, `sys.getrlimit`, `sys.setrlimit`, `sys.prlimit`, `sys.getrusage`
- `sys.clockGettime`, `sys.clockGetres`, `sys.gettimeofday`, `sys.nanosleep`, `sys.getrandom`
- `sys.eventfd`, `sys.timerfdCreate`, `sys.timerfdGettime`, `sys.timerfdSettime`, `sys.inotifyInit`, `sys.inotifyInit1`, `sys.inotifyAddWatch`, `sys.inotifyRmWatch`

Extended attributes and ioctl:

- `sys.getxattr`, `sys.lgetxattr`, `sys.fgetxattr`, `sys.listxattr`, `sys.llistxattr`, `sys.flistxattr`
- `sys.setxattr`, `sys.lsetxattr`, `sys.fsetxattr`, `sys.removexattr`, `sys.lremovexattr`, `sys.fremovexattr`
- `sys.ioctl` with either an integer `arg` or a managed `buffer` pointer window

## Examples

Vector file write and read:

```javascript
const fd = sys.memfdCreate({name: "vec", flags: "MFD_CLOEXEC", handle: "vec"});
sys.writev({handle: "vec", iovecs: [{data_utf8: "hello "}, {data_hex: "776f726c64"}]});
const got = sys.preadv({handle: "vec", offset: 0, iovecs: [{length: 6}, {length: 5}], encoding: "utf8"});
sys.close({handle: "vec"});
return got.data_utf8;
```

Resource and clock probe:

```javascript
return {
  ids: sys.getids(),
  nofile: sys.prlimit({pid: 0, resource: "RLIMIT_NOFILE"}),
  monotonic: sys.clockGettime({clockid: "CLOCK_MONOTONIC"}),
  page: sys.getpagesize()
};
```

Raw syscall fallback:

```javascript
return sys.syscall({trap: "SYS_GETPID"});
```

Raw syscall helpers are last-resort integer escape hatches. Prefer managed wrappers when a wrapper exists, because wrappers can keep Go memory alive, bound reads, register returned FDs, and encode bytes safely.