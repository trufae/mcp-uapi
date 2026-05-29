package mcpserver

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type Uint8 uint8
type Uint16 uint16
type Uint32 uint32
type Uint64 uint64
type ConstUint64 uint64
type ConstUint32 uint32

const linuxFIONREAD = 0x541b

func (u *Uint8) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 8)
	if err != nil {
		return err
	}
	*u = Uint8(value)
	return nil
}

func (u *Uint16) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 16)
	if err != nil {
		return err
	}
	*u = Uint16(value)
	return nil
}

func (u *Uint32) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 32)
	if err != nil {
		return err
	}
	*u = Uint32(value)
	return nil
}

func (u *Uint64) UnmarshalJSON(data []byte) error {
	value, err := parseUnsigned(data, 64)
	if err != nil {
		return err
	}
	*u = Uint64(value)
	return nil
}

func (u *ConstUint64) UnmarshalJSON(data []byte) error {
	value, err := parseConstOrUnsigned(data, 64)
	if err != nil {
		return err
	}
	*u = ConstUint64(value)
	return nil
}

func (u *ConstUint32) UnmarshalJSON(data []byte) error {
	value, err := parseConstOrUnsigned(data, 32)
	if err != nil {
		return err
	}
	*u = ConstUint32(value)
	return nil
}

func parseUnsigned(data []byte, bits int) (uint64, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return 0, nil
	}
	if strings.HasPrefix(s, "\"") {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return 0, err
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return 0, nil
		}
		value, err := strconv.ParseUint(text, 0, bits)
		if err != nil {
			return 0, fmt.Errorf("parse unsigned integer %q: %w", text, err)
		}
		return value, nil
	}
	value, err := strconv.ParseUint(s, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("parse unsigned integer %q: %w", s, err)
	}
	return value, nil
}

func parseConstOrUnsigned(data []byte, bits int) (uint64, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return 0, nil
	}
	if strings.HasPrefix(s, "\"") {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return 0, err
		}
		return parseConstExpression(text, bits)
	}
	return parseUnsigned(data, bits)
}

func parseConstExpression(text string, bits int) (uint64, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, nil
	}
	if value, err := strconv.ParseUint(text, 0, bits); err == nil {
		return value, nil
	}
	var value uint64
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == '|' || r == ',' || r == ' ' || r == '\t' || r == '\n' })
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		constant, ok := lookupConstant(part)
		if !ok {
			return 0, fmt.Errorf("unknown constant %q", part)
		}
		value |= constant
	}
	if bits < 64 && value >= 1<<bits {
		return 0, fmt.Errorf("constant expression %q overflows uint%d", text, bits)
	}
	return value, nil
}

func lookupConstant(name string) (uint64, bool) {
	key := normalizeConstantName(name)
	value, ok := namedConstants()[key]
	return value, ok
}

func normalizeConstantName(name string) string {
	name = strings.TrimSpace(strings.ToUpper(name))
	name = strings.TrimPrefix(name, "UNIX.")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

func hex8(v uint8) string     { return fmt.Sprintf("0x%02x", v) }
func hex16(v uint16) string   { return fmt.Sprintf("0x%04x", v) }
func hex32(v uint32) string   { return fmt.Sprintf("0x%08x", v) }
func hex64(v uint64) string   { return fmt.Sprintf("0x%016x", v) }
func hexPtr(v uintptr) string { return fmt.Sprintf("0x%016x", uint64(v)) }

func signedConst(value int) uint64 { return uint64(int64(value)) }

func checksum64(data []byte) string {
	var sum uint64 = 1469598103934665603
	for _, b := range data {
		sum ^= uint64(b)
		sum *= 1099511628211
	}
	return hex64(sum)
}

func namedConstants() map[string]uint64 {
	return map[string]uint64{
		"AF_UNSPEC": unix.AF_UNSPEC, "AF_UNIX": unix.AF_UNIX, "AF_LOCAL": unix.AF_LOCAL, "AF_INET": unix.AF_INET, "AF_INET6": unix.AF_INET6, "AF_NETLINK": unix.AF_NETLINK, "AF_PACKET": unix.AF_PACKET,
		"SOCK_STREAM": unix.SOCK_STREAM, "SOCK_DGRAM": unix.SOCK_DGRAM, "SOCK_RAW": unix.SOCK_RAW, "SOCK_SEQPACKET": unix.SOCK_SEQPACKET, "SOCK_NONBLOCK": unix.SOCK_NONBLOCK, "SOCK_CLOEXEC": unix.SOCK_CLOEXEC,
		"IPPROTO_IP": unix.IPPROTO_IP, "IPPROTO_TCP": unix.IPPROTO_TCP, "IPPROTO_UDP": unix.IPPROTO_UDP, "IPPROTO_ICMP": unix.IPPROTO_ICMP, "IPPROTO_ICMPV6": unix.IPPROTO_ICMPV6,
		"SOL_SOCKET": unix.SOL_SOCKET, "SO_REUSEADDR": unix.SO_REUSEADDR, "SO_REUSEPORT": unix.SO_REUSEPORT, "SO_KEEPALIVE": unix.SO_KEEPALIVE, "SO_BROADCAST": unix.SO_BROADCAST, "SO_ERROR": unix.SO_ERROR, "SO_RCVBUF": unix.SO_RCVBUF, "SO_SNDBUF": unix.SO_SNDBUF, "SO_BINDTODEVICE": unix.SO_BINDTODEVICE, "SO_PASSCRED": unix.SO_PASSCRED, "SCM_RIGHTS": unix.SCM_RIGHTS, "SCM_CREDENTIALS": unix.SCM_CREDENTIALS, "TCP_CONGESTION": unix.TCP_CONGESTION,
		"F_OK": unix.F_OK, "R_OK": unix.R_OK, "W_OK": unix.W_OK, "X_OK": unix.X_OK,
		"O_RDONLY": unix.O_RDONLY, "O_WRONLY": unix.O_WRONLY, "O_RDWR": unix.O_RDWR, "O_CREATE": unix.O_CREAT, "O_CREAT": unix.O_CREAT, "O_EXCL": unix.O_EXCL, "O_TRUNC": unix.O_TRUNC, "O_APPEND": unix.O_APPEND, "O_NONBLOCK": unix.O_NONBLOCK, "O_CLOEXEC": unix.O_CLOEXEC, "O_DIRECTORY": unix.O_DIRECTORY, "O_NOFOLLOW": unix.O_NOFOLLOW, "O_SYNC": unix.O_SYNC,
		"AT_FDCWD": signedConst(unix.AT_FDCWD), "AT_SYMLINK_NOFOLLOW": unix.AT_SYMLINK_NOFOLLOW, "AT_REMOVEDIR": unix.AT_REMOVEDIR, "AT_EMPTY_PATH": unix.AT_EMPTY_PATH, "AT_NO_AUTOMOUNT": unix.AT_NO_AUTOMOUNT, "AT_EACCESS": unix.AT_EACCESS,
		"F_DUPFD": unix.F_DUPFD, "F_DUPFD_CLOEXEC": unix.F_DUPFD_CLOEXEC, "F_GETFD": unix.F_GETFD, "F_SETFD": unix.F_SETFD, "F_GETFL": unix.F_GETFL, "F_SETFL": unix.F_SETFL, "F_GETLK": unix.F_GETLK, "F_SETLK": unix.F_SETLK, "F_SETLKW": unix.F_SETLKW, "F_RDLCK": unix.F_RDLCK, "F_WRLCK": unix.F_WRLCK, "F_UNLCK": unix.F_UNLCK,
		"SEEK_SET": 0, "SEEK_CUR": 1, "SEEK_END": 2, "SEEK_START": 0, "SEEK_CURRENT": 1, "SEEKSTART": 0, "SEEKCURRENT": 1, "SEEKEND": 2,
		"MODE_DIR": uint64(unix.S_IFDIR), "MODE_PERM": 0o777, "MODEDIR": uint64(unix.S_IFDIR), "MODEPERM": 0o777,
		"S_IFIFO": unix.S_IFIFO, "S_IFCHR": unix.S_IFCHR, "S_IFBLK": unix.S_IFBLK, "S_IFREG": unix.S_IFREG, "S_IFSOCK": unix.S_IFSOCK,
		"PROT_NONE": unix.PROT_NONE, "PROT_READ": unix.PROT_READ, "PROT_WRITE": unix.PROT_WRITE, "PROT_EXEC": unix.PROT_EXEC,
		"MAP_SHARED": unix.MAP_SHARED, "MAP_PRIVATE": unix.MAP_PRIVATE, "MAP_ANON": unix.MAP_ANON, "MAP_ANONYMOUS": unix.MAP_ANONYMOUS, "MAP_FIXED": unix.MAP_FIXED, "MAP_POPULATE": unix.MAP_POPULATE,
		"MS_ASYNC": unix.MS_ASYNC, "MS_SYNC": unix.MS_SYNC, "MS_INVALIDATE": unix.MS_INVALIDATE,
		"MREMAP_MAYMOVE": unix.MREMAP_MAYMOVE, "MREMAP_FIXED": unix.MREMAP_FIXED, "MREMAP_DONTUNMAP": unix.MREMAP_DONTUNMAP,
		"MADV_NORMAL": unix.MADV_NORMAL, "MADV_RANDOM": unix.MADV_RANDOM, "MADV_SEQUENTIAL": unix.MADV_SEQUENTIAL, "MADV_WILLNEED": unix.MADV_WILLNEED, "MADV_DONTNEED": unix.MADV_DONTNEED,
		"POLLIN": unix.POLLIN, "POLLOUT": unix.POLLOUT, "POLLERR": unix.POLLERR, "POLLHUP": unix.POLLHUP, "POLLNVAL": unix.POLLNVAL,
		"EPOLLIN": unix.EPOLLIN, "EPOLLOUT": unix.EPOLLOUT, "EPOLLERR": unix.EPOLLERR, "EPOLLHUP": unix.EPOLLHUP, "EPOLLRDHUP": unix.EPOLLRDHUP, "EPOLLET": unix.EPOLLET, "EPOLLONESHOT": unix.EPOLLONESHOT, "EPOLL_CLOEXEC": unix.EPOLL_CLOEXEC, "EPOLL_CTL_ADD": unix.EPOLL_CTL_ADD, "EPOLL_CTL_MOD": unix.EPOLL_CTL_MOD, "EPOLL_CTL_DEL": unix.EPOLL_CTL_DEL,
		"EFD_CLOEXEC": unix.EFD_CLOEXEC, "EFD_NONBLOCK": unix.EFD_NONBLOCK,
		"TFD_CLOEXEC": unix.TFD_CLOEXEC, "TFD_NONBLOCK": unix.TFD_NONBLOCK, "TFD_TIMER_ABSTIME": unix.TFD_TIMER_ABSTIME, "TFD_TIMER_CANCEL_ON_SET": unix.TFD_TIMER_CANCEL_ON_SET,
		"SFD_CLOEXEC": unix.SFD_CLOEXEC, "SFD_NONBLOCK": unix.SFD_NONBLOCK,
		"MFD_CLOEXEC": unix.MFD_CLOEXEC, "MFD_ALLOW_SEALING": unix.MFD_ALLOW_SEALING,
		"PIDFD_NONBLOCK":      unix.PIDFD_NONBLOCK,
		"CLOSE_RANGE_UNSHARE": unix.CLOSE_RANGE_UNSHARE, "CLOSE_RANGE_CLOEXEC": unix.CLOSE_RANGE_CLOEXEC,
		"IN_ACCESS": unix.IN_ACCESS, "IN_ATTRIB": unix.IN_ATTRIB, "IN_CLOSE_WRITE": unix.IN_CLOSE_WRITE, "IN_CLOSE_NOWRITE": unix.IN_CLOSE_NOWRITE, "IN_CREATE": unix.IN_CREATE, "IN_DELETE": unix.IN_DELETE, "IN_DELETE_SELF": unix.IN_DELETE_SELF, "IN_MODIFY": unix.IN_MODIFY, "IN_MOVED_FROM": unix.IN_MOVED_FROM, "IN_MOVED_TO": unix.IN_MOVED_TO, "IN_MOVE_SELF": unix.IN_MOVE_SELF, "IN_OPEN": unix.IN_OPEN,
		"STATX_BASIC_STATS": unix.STATX_BASIC_STATS, "STATX_ALL": unix.STATX_ALL,
		"RENAME_NOREPLACE": unix.RENAME_NOREPLACE, "RENAME_EXCHANGE": unix.RENAME_EXCHANGE,
		"SHUT_RD": unix.SHUT_RD, "SHUT_WR": unix.SHUT_WR, "SHUT_RDWR": unix.SHUT_RDWR,
		"SIGSTOP": uint64(unix.SIGSTOP), "SIGCONT": uint64(unix.SIGCONT), "SIGTERM": uint64(unix.SIGTERM), "SIGKILL": uint64(unix.SIGKILL), "SIGCHLD": uint64(unix.SIGCHLD), "SIGTRAP": uint64(unix.SIGTRAP),
		"PTRACE_O_TRACESYSGOOD": unix.PTRACE_O_TRACESYSGOOD, "PTRACE_O_TRACEFORK": unix.PTRACE_O_TRACEFORK, "PTRACE_O_TRACEVFORK": unix.PTRACE_O_TRACEVFORK, "PTRACE_O_TRACECLONE": unix.PTRACE_O_TRACECLONE, "PTRACE_O_TRACEEXEC": unix.PTRACE_O_TRACEEXEC, "PTRACE_O_TRACEVFORKDONE": unix.PTRACE_O_TRACEVFORKDONE, "PTRACE_O_TRACEEXIT": unix.PTRACE_O_TRACEEXIT, "PTRACE_O_TRACESECCOMP": unix.PTRACE_O_TRACESECCOMP,
		"WNOHANG": unix.WNOHANG, "WUNTRACED": unix.WUNTRACED, "WCONTINUED": unix.WCONTINUED,
		"RUSAGE_SELF": unix.RUSAGE_SELF, "RUSAGE_CHILDREN": signedConst(unix.RUSAGE_CHILDREN), "RLIMIT_NOFILE": unix.RLIMIT_NOFILE, "RLIMIT_CORE": unix.RLIMIT_CORE, "RLIMIT_CPU": unix.RLIMIT_CPU, "RLIMIT_FSIZE": unix.RLIMIT_FSIZE, "RLIMIT_AS": unix.RLIMIT_AS, "RLIMIT_DATA": unix.RLIMIT_DATA, "RLIMIT_STACK": unix.RLIMIT_STACK, "RLIMIT_MEMLOCK": unix.RLIMIT_MEMLOCK, "RLIMIT_NPROC": unix.RLIMIT_NPROC, "RLIMIT_RSS": unix.RLIMIT_RSS, "RLIMIT_LOCKS": unix.RLIMIT_LOCKS, "RLIMIT_SIGPENDING": unix.RLIMIT_SIGPENDING, "RLIMIT_MSGQUEUE": unix.RLIMIT_MSGQUEUE, "RLIMIT_NICE": unix.RLIMIT_NICE, "RLIMIT_RTPRIO": unix.RLIMIT_RTPRIO, "RLIMIT_RTTIME": unix.RLIMIT_RTTIME,
		"FIONREAD":    linuxFIONREAD,
		"PR_SET_NAME": unix.PR_SET_NAME, "PR_GET_NAME": unix.PR_GET_NAME, "PR_SET_PDEATHSIG": unix.PR_SET_PDEATHSIG, "PR_GET_PDEATHSIG": unix.PR_GET_PDEATHSIG, "PR_SET_DUMPABLE": unix.PR_SET_DUMPABLE, "PR_GET_DUMPABLE": unix.PR_GET_DUMPABLE,
		"PRIO_PROCESS": unix.PRIO_PROCESS, "PRIO_PGRP": unix.PRIO_PGRP, "PRIO_USER": unix.PRIO_USER,
		"CLOCK_REALTIME": unix.CLOCK_REALTIME, "CLOCK_MONOTONIC": unix.CLOCK_MONOTONIC, "CLOCK_PROCESS_CPUTIME_ID": unix.CLOCK_PROCESS_CPUTIME_ID, "CLOCK_THREAD_CPUTIME_ID": unix.CLOCK_THREAD_CPUTIME_ID, "CLOCK_MONOTONIC_RAW": unix.CLOCK_MONOTONIC_RAW, "CLOCK_REALTIME_COARSE": unix.CLOCK_REALTIME_COARSE, "CLOCK_MONOTONIC_COARSE": unix.CLOCK_MONOTONIC_COARSE, "CLOCK_BOOTTIME": unix.CLOCK_BOOTTIME, "CLOCK_REALTIME_ALARM": unix.CLOCK_REALTIME_ALARM, "CLOCK_BOOTTIME_ALARM": unix.CLOCK_BOOTTIME_ALARM, "CLOCK_TAI": unix.CLOCK_TAI,
		"GRND_NONBLOCK": unix.GRND_NONBLOCK, "GRND_RANDOM": unix.GRND_RANDOM, "GRND_INSECURE": unix.GRND_INSECURE,
		"FADV_NORMAL": unix.FADV_NORMAL, "FADV_RANDOM": unix.FADV_RANDOM, "FADV_SEQUENTIAL": unix.FADV_SEQUENTIAL, "FADV_WILLNEED": unix.FADV_WILLNEED, "FADV_DONTNEED": unix.FADV_DONTNEED, "FADV_NOREUSE": unix.FADV_NOREUSE,
		"FALLOC_FL_KEEP_SIZE": unix.FALLOC_FL_KEEP_SIZE, "FALLOC_FL_PUNCH_HOLE": unix.FALLOC_FL_PUNCH_HOLE, "FALLOC_FL_NO_HIDE_STALE": unix.FALLOC_FL_NO_HIDE_STALE, "FALLOC_FL_COLLAPSE_RANGE": unix.FALLOC_FL_COLLAPSE_RANGE, "FALLOC_FL_ZERO_RANGE": unix.FALLOC_FL_ZERO_RANGE, "FALLOC_FL_INSERT_RANGE": unix.FALLOC_FL_INSERT_RANGE, "FALLOC_FL_UNSHARE_RANGE": unix.FALLOC_FL_UNSHARE_RANGE,
		"SYNC_FILE_RANGE_WAIT_BEFORE": unix.SYNC_FILE_RANGE_WAIT_BEFORE, "SYNC_FILE_RANGE_WRITE": unix.SYNC_FILE_RANGE_WRITE, "SYNC_FILE_RANGE_WAIT_AFTER": unix.SYNC_FILE_RANGE_WAIT_AFTER, "SYNC_FILE_RANGE_WRITE_AND_WAIT": unix.SYNC_FILE_RANGE_WRITE_AND_WAIT,
		"SPLICE_F_MOVE": unix.SPLICE_F_MOVE, "SPLICE_F_NONBLOCK": unix.SPLICE_F_NONBLOCK, "SPLICE_F_MORE": unix.SPLICE_F_MORE, "SPLICE_F_GIFT": unix.SPLICE_F_GIFT,
		"RWF_HIPRI": unix.RWF_HIPRI, "RWF_DSYNC": unix.RWF_DSYNC, "RWF_SYNC": unix.RWF_SYNC, "RWF_NOWAIT": unix.RWF_NOWAIT, "RWF_APPEND": unix.RWF_APPEND,
		"RESOLVE_NO_XDEV": unix.RESOLVE_NO_XDEV, "RESOLVE_NO_MAGICLINKS": unix.RESOLVE_NO_MAGICLINKS, "RESOLVE_NO_SYMLINKS": unix.RESOLVE_NO_SYMLINKS, "RESOLVE_BENEATH": unix.RESOLVE_BENEATH, "RESOLVE_IN_ROOT": unix.RESOLVE_IN_ROOT,
		"LOCK_SH": unix.LOCK_SH, "LOCK_EX": unix.LOCK_EX, "LOCK_NB": unix.LOCK_NB, "LOCK_UN": unix.LOCK_UN,
		"SYS_GETPID": unix.SYS_GETPID, "SYS_PROCESS_VM_READV": unix.SYS_PROCESS_VM_READV, "SYS_PROCESS_VM_WRITEV": unix.SYS_PROCESS_VM_WRITEV, "SYS_PIDFD_OPEN": unix.SYS_PIDFD_OPEN, "SYS_PIDFD_GETFD": unix.SYS_PIDFD_GETFD, "SYS_PIDFD_SEND_SIGNAL": unix.SYS_PIDFD_SEND_SIGNAL, "SYS_OPENAT2": unix.SYS_OPENAT2, "SYS_FACCESSAT2": unix.SYS_FACCESSAT2, "SYS_SPLICE": unix.SYS_SPLICE, "SYS_TEE": unix.SYS_TEE, "SYS_VMSPLICE": unix.SYS_VMSPLICE, "SYS_GETRANDOM": unix.SYS_GETRANDOM, "SYS_PREADV": unix.SYS_PREADV, "SYS_PWRITEV": unix.SYS_PWRITEV, "SYS_PREADV2": unix.SYS_PREADV2, "SYS_PWRITEV2": unix.SYS_PWRITEV2, "SYS_TIMERFD_CREATE": unix.SYS_TIMERFD_CREATE, "SYS_TIMERFD_SETTIME": unix.SYS_TIMERFD_SETTIME, "SYS_TIMERFD_GETTIME": unix.SYS_TIMERFD_GETTIME, "SYS_SENDMSG": unix.SYS_SENDMSG, "SYS_RECVMSG": unix.SYS_RECVMSG, "SYS_GETDENTS64": unix.SYS_GETDENTS64, "SYS_FALLOCATE": unix.SYS_FALLOCATE,
	}
}
