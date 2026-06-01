//go:build !linux

package mcpserver

import "golang.org/x/sys/unix"

type platformEpollEvent struct {
	Events uint32
	FD     int32
}

func platformEpollCloexec() int { return 0 }

func platformEpollCreate1(flags int) (int, error) { return -1, unix.ENOSYS }

func platformEpollCtl(epfd int, op int, fd int, event *platformEpollEvent) error {
	return unix.ENOSYS
}

func platformEpollWait(epfd int, events []platformEpollEvent, timeout int) (int, error) {
	return 0, unix.ENOSYS
}
