# sys/unix Coverage

The scripting layer is built from `go doc golang.org/x/sys/unix` on Linux and exposes the functions that can be represented safely and usefully as JSON. The implementation favors managed handles and byte encodings over raw pointers.

## Implemented Directly

Most commonly used Linux sys/unix calls now have direct wrappers:

- File, path, descriptor, stat, xattr, and at-family calls.
- Buffer, mmap, memfd, transfer, vector I/O, and `process_vm_readv/writev` calls.
- Socket, socketpair, sockaddr, message, socket-option, poll, and epoll calls.
- Process, wait, ptrace, pidfd, prlimit, priority, rlimit, rusage, clock, timerfd, eventfd, inotify, random, and sysinfo calls.
- `ioctl` with integer arguments or managed pointer buffers.

The full active wrapper list is available at runtime:

```javascript
return sys.capabilities().scripting_api.uapi_wrappers;
```

## Covered By Generic Helpers

Some `x/sys/unix` calls are better represented as a lower-level operation plus managed buffers:

- Pointer-shaped ioctls use `sys.ioctl` with `sys.bufferAlloc`, `sys.bufferWrite`, and `sys.bufferRead`.
- Syscalls not yet modeled as JSON wrappers can be probed with `sys.syscall`, `sys.syscall6`, `sys.rawSyscall`, and `sys.rawSyscall6` when all arguments are integers or caller-controlled addresses.

Prefer direct wrappers when available. Direct wrappers keep buffers alive across the syscall, register returned FDs, apply read limits, and encode byte results.

## Intentionally Not One-To-One

The Go package includes helpers whose public signatures expose Go pointers, architecture-specific structs, or process-terminating behavior. Those are intentionally not mirrored as plain JavaScript calls unless there is a managed JSON shape for them.

Examples:

- `Exec`, `Exit`, mount/module/keyring namespace mutations, and other process- or host-disruptive calls are not first-class eval helpers.
- Struct-heavy ioctl conveniences are covered by generic `sys.ioctl` and managed buffers instead of a separate wrapper for every device-specific structure.
- Architecture-specific ptrace register structures are better handled through `/proc/<pid>/syscall`, `sys.ptraceRead`, or future arch-gated wrappers.

## How To Audit Coverage

Run this from the repository with the local Go toolchain:

```sh
GOROOT="$PWD/.tools/go" PATH="$PWD/.tools/go/bin:$PATH" go doc -all golang.org/x/sys/unix | awk '/^func /{print}'
```

Then compare with:

```javascript
return sys.capabilities().scripting_api.uapi_wrappers;
```

When adding wrappers, prefer JSON object arguments, managed FD handles, bounded reads, explicit encodings, structured errno returns, and a short API resource under `docs/api/` when the behavior needs examples.