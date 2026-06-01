//go:build !linux

package mcpserver

import (
	"crypto/rand"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func platformUnameDomainname(uts unix.Utsname) string { return "" }

func platformProcessVMReadv(pid int, local []unix.Iovec, remote []scriptRemoteIovec, flags uint) (int, error) {
	return 0, unix.ENOSYS
}

func platformProcessVMWritev(pid int, local []unix.Iovec, remote []scriptRemoteIovec, flags uint) (int, error) {
	return 0, unix.ENOSYS
}

func platformTimerfdGettime(fd int) (scriptItimerSpec, error) {
	return scriptItimerSpec{}, unix.ENOSYS
}

func platformTimerfdSettime(fd int, flags int, newSpec scriptItimerSpec) (scriptItimerSpec, error) {
	return scriptItimerSpec{}, unix.ENOSYS
}

func platformCopyFileRange(readFD int, readOffset *int64, writeFD int, writeOffset *int64, length int, flags int) (int, error) {
	return 0, unix.ENOSYS
}

func platformPreadv2(fd int, iovs [][]byte, offset int64, flags int) (int, error) {
	if flags != 0 {
		return 0, unix.ENOSYS
	}
	return unix.Preadv(fd, iovs, offset)
}

func platformPwritev2(fd int, iovs [][]byte, offset int64, flags int) (int, error) {
	if flags != 0 {
		return 0, unix.ENOSYS
	}
	return unix.Pwritev(fd, iovs, offset)
}

func platformSplice(inFD int, inOffset *int64, outFD int, outOffset *int64, length int, flags int) (int64, error) {
	return 0, unix.ENOSYS
}

func platformTee(inFD int, outFD int, length int, flags int) (int64, error) {
	return 0, unix.ENOSYS
}

func platformVmsplice(fd int, iovecs []unix.Iovec, flags int) (int, error) {
	return 0, unix.ENOSYS
}

func platformCreat(path string, mode uint32) (int, error) {
	return unix.Open(path, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, mode)
}

func platformFaccessat2(dirfd int, path string, mode uint32, flags int) error {
	return unix.Faccessat(dirfd, path, mode, flags)
}

func platformOpenat2(dirfd int, path string, flags uint64, mode uint64, resolve uint64) (int, error) {
	if resolve != 0 {
		return -1, unix.ENOSYS
	}
	return unix.Openat(dirfd, path, int(flags), uint32(mode))
}

func platformFadvise(fd int, offset int64, length int64, advice int) error {
	return unix.ENOSYS
}

func platformFallocate(fd int, mode uint32, offset int64, length int64) error {
	return unix.ENOSYS
}

func platformSyncFileRange(fd int, offset int64, length int64, flags int) error {
	return unix.ENOSYS
}

func platformGetdents(fd int, buf []byte) (int, error) {
	return unix.ReadDirent(fd, buf)
}

func platformGetrandom(buf []byte, flags int) (int, error) {
	if flags != 0 {
		return 0, unix.ENOSYS
	}
	return rand.Read(buf)
}

func platformPidfdOpen(pid int, flags int) (int, error) {
	return -1, unix.ENOSYS
}

func platformPidfdGetfd(pidfd int, targetfd int, flags int) (int, error) {
	return -1, unix.ENOSYS
}

func platformPidfdSendSignal(pidfd int, sig unix.Signal, flags int) error {
	return unix.ENOSYS
}

func platformClockGettime(clockid int32, ts *unix.Timespec) error {
	return unix.ClockGettime(clockid, ts)
}

func platformClockGetres(clockid int32, ts *unix.Timespec) error {
	return unix.ENOSYS
}

func platformNanosleep(req *unix.Timespec, rem *unix.Timespec) error {
	if req == nil {
		return unix.EINVAL
	}
	time.Sleep(time.Duration(req.Sec)*time.Second + time.Duration(req.Nsec)*time.Nanosecond)
	if rem != nil {
		*rem = unix.Timespec{}
	}
	return nil
}

func platformTimerfdCreate(clockid int, flags int) (int, error) {
	return -1, unix.ENOSYS
}

func platformTimerfdCloexec() int { return 0 }

func platformTgkill(tgid int, tid int, sig unix.Signal) error {
	return unix.ENOSYS
}

func platformPrlimit(pid int, resource int, newLimit *unix.Rlimit, old *unix.Rlimit) error {
	if pid != 0 {
		return unix.ENOSYS
	}
	if old != nil {
		if err := unix.Getrlimit(resource, old); err != nil {
			return err
		}
	}
	if newLimit != nil {
		return unix.Setrlimit(resource, newLimit)
	}
	return nil
}

func platformBindToDevice(fd int, device string) error {
	return unix.ENOSYS
}

func platformSysinfo() (map[string]any, error) {
	return nil, unix.ENOSYS
}

func platformCloseRangeCloexec() uint { return 0 }

func platformMkfifoat(dirfd int, path string, mode uint32) error {
	if dirfd == unix.AT_FDCWD {
		return unix.Mkfifo(path, mode)
	}
	return unix.ENOSYS
}

func platformMknodat(dirfd int, path string, mode uint32, dev int) error {
	if dirfd == unix.AT_FDCWD {
		return unix.Mknod(path, mode, dev)
	}
	return unix.ENOSYS
}

func platformRenameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
	if flags != 0 {
		return unix.ENOSYS
	}
	return unix.Renameat(olddirfd, oldpath, newdirfd, newpath)
}

func platformFdatasync(fd int) error { return unix.Fsync(fd) }

func platformSyncfs(fd int) error { return unix.ENOSYS }

func platformDup3(oldfd int, newfd int, flags int) error {
	if flags != 0 {
		return unix.ENOSYS
	}
	return unix.Dup2(oldfd, newfd)
}

func platformPipe2(fds []int, flags int) error {
	if flags != 0 {
		return unix.ENOSYS
	}
	return unix.Pipe(fds)
}

func platformCloseRange(first uint, last uint, flags uint) error { return unix.ENOSYS }

func platformGettid() int { return 0 }

func platformGetresuid() (int, int, int) { return unix.Getuid(), unix.Geteuid(), -1 }

func platformGetresgid() (int, int, int) { return unix.Getgid(), unix.Getegid(), -1 }

func platformEventfd(init uint, flags int) (int, error) { return -1, unix.ENOSYS }

func platformMemfdCreate(name string, flags int) (int, error) { return -1, unix.ENOSYS }

func platformInotifyInit() (int, error) { return -1, unix.ENOSYS }

func platformInotifyInit1(flags int) (int, error) { return -1, unix.ENOSYS }

func platformInotifyAddWatch(fd int, path string, mask uint32) (int, error) {
	return -1, unix.ENOSYS
}

func platformInotifyRmWatch(fd int, wd uint32) (int, error) { return -1, unix.ENOSYS }

func platformSyscallStatAtime(st syscall.Stat_t) int64 { return st.Atimespec.Sec }

func platformSyscallStatMtime(st syscall.Stat_t) int64 { return st.Mtimespec.Sec }

func platformSyscallStatCtime(st syscall.Stat_t) int64 { return st.Ctimespec.Sec }
