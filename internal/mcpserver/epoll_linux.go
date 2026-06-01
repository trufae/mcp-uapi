//go:build linux

package mcpserver

import "golang.org/x/sys/unix"

type platformEpollEvent struct {
	Events uint32
	FD     int32
}

func platformEpollCloexec() int { return unix.EPOLL_CLOEXEC }

func platformEpollCreate1(flags int) (int, error) { return unix.EpollCreate1(flags) }

func platformEpollCtl(epfd int, op int, fd int, event *platformEpollEvent) error {
	return unix.EpollCtl(epfd, op, fd, &unix.EpollEvent{Events: event.Events, Fd: event.FD})
}

func platformEpollWait(epfd int, events []platformEpollEvent, timeout int) (int, error) {
	unixEvents := make([]unix.EpollEvent, len(events))
	n, err := unix.EpollWait(epfd, unixEvents, timeout)
	for i := 0; i < n; i++ {
		events[i] = platformEpollEvent{Events: unixEvents[i].Events, FD: unixEvents[i].Fd}
	}
	return n, err
}
