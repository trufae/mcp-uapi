package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type pollFDArg struct {
	Handle string      `json:"handle"`
	FD     *int        `json:"fd"`
	Events ConstUint64 `json:"events"`
}

type pollArgs struct {
	FDs       []pollFDArg `json:"fds"`
	TimeoutMS Uint32      `json:"timeout_ms"`
}

func (a *App) handlePoll(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args pollArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if len(args.FDs) == 0 {
		return toolError(fmt.Errorf("fds must not be empty"))
	}
	pollfds := make([]unix.PollFd, len(args.FDs))
	handles := make([]string, len(args.FDs))
	a.mu.Lock()
	for i, item := range args.FDs {
		fd, handle, _, err := a.resolveFDLocked(item.Handle, item.FD)
		if err != nil {
			a.mu.Unlock()
			return toolError(fmt.Errorf("fds[%d]: %w", i, err))
		}
		pollfds[i] = unix.PollFd{Fd: int32(fd), Events: int16(item.Events)}
		handles[i] = handle
	}
	a.mu.Unlock()
	n, err := unix.Poll(pollfds, int(args.TimeoutMS))
	fields := map[string]any{"ready": n, "timeout_ms": uint32(args.TimeoutMS)}
	if err == nil {
		events := make([]map[string]any, len(pollfds))
		for i, pfd := range pollfds {
			events[i] = map[string]any{"index": i, "handle": handles[i], "fd": int(pfd.Fd), "events": int(pfd.Events), "revents": int(pfd.Revents)}
		}
		fields["fds"] = events
	}
	return syscallResult(fields, err)
}

type epollCreateArgs struct {
	Flags  ConstUint64 `json:"flags"`
	Handle string      `json:"handle"`
}

func (a *App) handleEpollCreate(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args epollCreateArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.EPOLL_CLOEXEC
	}
	fd, err := unix.EpollCreate1(flags)
	if err != nil {
		return syscallResult(map[string]any{"flags": flags}, err)
	}
	a.mu.Lock()
	entry, regErr := a.registerFDLocked(fd, "epoll", "", args.Handle, map[string]any{"flags": flags})
	a.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(fd)
		return toolError(regErr)
	}
	return syscallResult(map[string]any{"handle": entry.Handle, "fd": fd, "flags": flags}, nil)
}

type epollCtlArgs struct {
	EpollHandle  string      `json:"epoll_handle"`
	EpollFD      *int        `json:"epoll_fd"`
	Op           ConstUint64 `json:"op"`
	TargetHandle string      `json:"target_handle"`
	TargetFD     *int        `json:"target_fd"`
	Events       ConstUint64 `json:"events"`
	Data         *Uint64     `json:"data"`
}

func (a *App) handleEpollCtl(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args epollCtlArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	epfd, epHandle, _, err := a.resolveFDLocked(args.EpollHandle, args.EpollFD)
	if err != nil {
		a.mu.Unlock()
		return toolError(fmt.Errorf("epoll fd: %w", err))
	}
	targetFD, targetHandle, _, err := a.resolveFDLocked(args.TargetHandle, args.TargetFD)
	if err != nil {
		a.mu.Unlock()
		return toolError(fmt.Errorf("target fd: %w", err))
	}
	a.mu.Unlock()
	eventData := targetFD
	if args.Data != nil {
		eventData = int(*args.Data)
	}
	event := &unix.EpollEvent{Events: uint32(args.Events), Fd: int32(eventData)}
	err = unix.EpollCtl(epfd, int(args.Op), targetFD, event)
	return syscallResult(map[string]any{"epoll_handle": epHandle, "epoll_fd": epfd, "target_handle": targetHandle, "target_fd": targetFD, "op": int(args.Op), "events": uint32(args.Events), "data": eventData}, err)
}

type epollWaitArgs struct {
	EpollHandle string `json:"epoll_handle"`
	EpollFD     *int   `json:"epoll_fd"`
	MaxEvents   Uint32 `json:"max_events"`
	TimeoutMS   Uint32 `json:"timeout_ms"`
}

func (a *App) handleEpollWait(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args epollWaitArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	maxEvents := int(args.MaxEvents)
	if maxEvents == 0 {
		maxEvents = 16
	}
	a.mu.Lock()
	epfd, handle, _, err := a.resolveFDLocked(args.EpollHandle, args.EpollFD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	events := make([]unix.EpollEvent, maxEvents)
	n, waitErr := unix.EpollWait(epfd, events, int(args.TimeoutMS))
	fields := map[string]any{"epoll_handle": handle, "epoll_fd": epfd, "ready": n, "timeout_ms": uint32(args.TimeoutMS)}
	if waitErr == nil {
		out := make([]map[string]any, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, map[string]any{"events": events[i].Events, "data": events[i].Fd})
		}
		fields["events"] = out
	}
	return syscallResult(fields, waitErr)
}
