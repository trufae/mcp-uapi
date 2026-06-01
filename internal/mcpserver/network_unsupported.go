//go:build !linux

package mcpserver

import "golang.org/x/sys/unix"

func platformSocketCloexec() int { return 0 }

func platformSockaddrNetlink(spec sockaddrSpec) (unix.Sockaddr, error) {
	return nil, unix.ENOSYS
}

func platformSockaddrInfo(sa unix.Sockaddr) map[string]any { return nil }

func platformAccept(fd int, flags int) (int, unix.Sockaddr, error) {
	if flags != 0 {
		return -1, nil, unix.ENOSYS
	}
	return unix.Accept(fd)
}
