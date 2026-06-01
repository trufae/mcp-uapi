//go:build linux

package mcpserver

import "golang.org/x/sys/unix"

func platformSocketCloexec() int { return unix.SOCK_CLOEXEC }

func platformSockaddrNetlink(spec sockaddrSpec) (unix.Sockaddr, error) {
	return &unix.SockaddrNetlink{Pid: uint32(spec.PID), Groups: uint32(spec.Groups)}, nil
}

func platformSockaddrInfo(sa unix.Sockaddr) map[string]any {
	if addr, ok := sa.(*unix.SockaddrNetlink); ok {
		return map[string]any{"family": "netlink", "pid": addr.Pid, "groups": addr.Groups}
	}
	return nil
}

func platformAccept(fd int, flags int) (int, unix.Sockaddr, error) {
	return unix.Accept4(fd, flags)
}
