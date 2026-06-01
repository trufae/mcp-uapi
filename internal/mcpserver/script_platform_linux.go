//go:build linux

package mcpserver

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func platformUnameDomainname(uts unix.Utsname) string {
	return unix.ByteSliceToString(uts.Domainname[:])
}

func platformProcessVMReadv(pid int, local []unix.Iovec, remote []scriptRemoteIovec, flags uint) (int, error) {
	iovecs := make([]unix.RemoteIovec, len(remote))
	for i, iov := range remote {
		iovecs[i] = unix.RemoteIovec{Base: iov.Base, Len: iov.Len}
	}
	return unix.ProcessVMReadv(pid, local, iovecs, flags)
}

func platformProcessVMWritev(pid int, local []unix.Iovec, remote []scriptRemoteIovec, flags uint) (int, error) {
	iovecs := make([]unix.RemoteIovec, len(remote))
	for i, iov := range remote {
		iovecs[i] = unix.RemoteIovec{Base: iov.Base, Len: iov.Len}
	}
	return unix.ProcessVMWritev(pid, local, iovecs, flags)
}

func platformTimerfdGettime(fd int) (scriptItimerSpec, error) {
	var spec unix.ItimerSpec
	err := unix.TimerfdGettime(fd, &spec)
	return scriptItimerSpec{Value: spec.Value, Interval: spec.Interval}, err
}

func platformTimerfdSettime(fd int, flags int, newSpec scriptItimerSpec) (scriptItimerSpec, error) {
	newTimer := unix.ItimerSpec{Value: newSpec.Value, Interval: newSpec.Interval}
	var oldTimer unix.ItimerSpec
	err := unix.TimerfdSettime(fd, flags, &newTimer, &oldTimer)
	return scriptItimerSpec{Value: oldTimer.Value, Interval: oldTimer.Interval}, err
}

func platformCopyFileRange(readFD int, readOffset *int64, writeFD int, writeOffset *int64, length int, flags int) (int, error) {
	return unix.CopyFileRange(readFD, readOffset, writeFD, writeOffset, length, flags)
}

func platformPreadv2(fd int, iovs [][]byte, offset int64, flags int) (int, error) {
	return unix.Preadv2(fd, iovs, offset, flags)
}

func platformPwritev2(fd int, iovs [][]byte, offset int64, flags int) (int, error) {
	return unix.Pwritev2(fd, iovs, offset, flags)
}

func platformSplice(inFD int, inOffset *int64, outFD int, outOffset *int64, length int, flags int) (int64, error) {
	n, err := unix.Splice(inFD, inOffset, outFD, outOffset, length, flags)
	return int64(n), err
}

func platformTee(inFD int, outFD int, length int, flags int) (int64, error) {
	n, err := unix.Tee(inFD, outFD, length, flags)
	return int64(n), err
}

func platformVmsplice(fd int, iovecs []unix.Iovec, flags int) (int, error) {
	return unix.Vmsplice(fd, iovecs, flags)
}

func platformCreat(path string, mode uint32) (int, error) {
	return unix.Creat(path, mode)
}

func platformFaccessat2(dirfd int, path string, mode uint32, flags int) error {
	return unix.Faccessat2(dirfd, path, mode, flags)
}

func platformOpenat2(dirfd int, path string, flags uint64, mode uint64, resolve uint64) (int, error) {
	how := &unix.OpenHow{Flags: flags, Mode: mode, Resolve: resolve}
	return unix.Openat2(dirfd, path, how)
}

func platformFadvise(fd int, offset int64, length int64, advice int) error {
	return unix.Fadvise(fd, offset, length, advice)
}

func platformFallocate(fd int, mode uint32, offset int64, length int64) error {
	return unix.Fallocate(fd, mode, offset, length)
}

func platformSyncFileRange(fd int, offset int64, length int64, flags int) error {
	return unix.SyncFileRange(fd, offset, length, flags)
}

func platformGetdents(fd int, buf []byte) (int, error) {
	return unix.Getdents(fd, buf)
}

func platformGetrandom(buf []byte, flags int) (int, error) {
	return unix.Getrandom(buf, flags)
}

func platformPidfdOpen(pid int, flags int) (int, error) {
	return unix.PidfdOpen(pid, flags)
}

func platformPidfdGetfd(pidfd int, targetfd int, flags int) (int, error) {
	return unix.PidfdGetfd(pidfd, targetfd, flags)
}

func platformPidfdSendSignal(pidfd int, sig unix.Signal, flags int) error {
	return unix.PidfdSendSignal(pidfd, sig, nil, flags)
}

func platformClockGettime(clockid int32, ts *unix.Timespec) error {
	return unix.ClockGettime(clockid, ts)
}

func platformClockGetres(clockid int32, ts *unix.Timespec) error {
	return unix.ClockGetres(clockid, ts)
}

func platformNanosleep(req *unix.Timespec, rem *unix.Timespec) error {
	return unix.Nanosleep(req, rem)
}

func platformTimerfdCreate(clockid int, flags int) (int, error) {
	return unix.TimerfdCreate(clockid, flags)
}

func platformTimerfdCloexec() int { return unix.TFD_CLOEXEC }

func platformTgkill(tgid int, tid int, sig unix.Signal) error {
	return unix.Tgkill(tgid, tid, sig)
}

func platformPrlimit(pid int, resource int, newLimit *unix.Rlimit, old *unix.Rlimit) error {
	return unix.Prlimit(pid, resource, newLimit, old)
}

func platformBindToDevice(fd int, device string) error {
	return unix.BindToDevice(fd, device)
}

func platformSysinfo() (map[string]any, error) {
	var info unix.Sysinfo_t
	err := unix.Sysinfo(&info)
	if err != nil {
		return nil, err
	}
	return map[string]any{"uptime": info.Uptime, "loads": []uint64{uint64(info.Loads[0]), uint64(info.Loads[1]), uint64(info.Loads[2])}, "totalram": info.Totalram, "freeram": info.Freeram, "sharedram": info.Sharedram, "bufferram": info.Bufferram, "totalswap": info.Totalswap, "freeswap": info.Freeswap, "procs": info.Procs, "totalhigh": info.Totalhigh, "freehigh": info.Freehigh, "unit": info.Unit}, nil
}

func platformCloseRangeCloexec() uint { return unix.CLOSE_RANGE_CLOEXEC }

func platformMkfifoat(dirfd int, path string, mode uint32) error {
	return unix.Mkfifoat(dirfd, path, mode)
}

func platformMknodat(dirfd int, path string, mode uint32, dev int) error {
	return unix.Mknodat(dirfd, path, mode, dev)
}

func platformRenameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) error {
	return unix.Renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
}

func platformFdatasync(fd int) error { return unix.Fdatasync(fd) }

func platformSyncfs(fd int) error { return unix.Syncfs(fd) }

func platformDup3(oldfd int, newfd int, flags int) error { return unix.Dup3(oldfd, newfd, flags) }

func platformPipe2(fds []int, flags int) error { return unix.Pipe2(fds, flags) }

func platformCloseRange(first uint, last uint, flags uint) error {
	return unix.CloseRange(first, last, flags)
}

func platformGettid() int { return unix.Gettid() }

func platformGetresuid() (int, int, int) { return unix.Getresuid() }

func platformGetresgid() (int, int, int) { return unix.Getresgid() }

func platformEventfd(init uint, flags int) (int, error) { return unix.Eventfd(init, flags) }

func platformMemfdCreate(name string, flags int) (int, error) {
	return unix.MemfdCreate(name, flags)
}

func platformInotifyInit() (int, error) { return unix.InotifyInit() }

func platformInotifyInit1(flags int) (int, error) { return unix.InotifyInit1(flags) }

func platformInotifyAddWatch(fd int, path string, mask uint32) (int, error) {
	return unix.InotifyAddWatch(fd, path, mask)
}

func platformInotifyRmWatch(fd int, wd uint32) (int, error) {
	return unix.InotifyRmWatch(fd, wd)
}

func platformSyscallStatAtime(st syscall.Stat_t) int64 { return int64(st.Atim.Sec) }

func platformSyscallStatMtime(st syscall.Stat_t) int64 { return int64(st.Mtim.Sec) }

func platformSyscallStatCtime(st syscall.Stat_t) int64 { return int64(st.Ctim.Sec) }
