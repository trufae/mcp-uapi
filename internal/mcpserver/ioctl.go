package mcpserver

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type ioctlArgs struct {
	fdRefArgs
	Request      ConstUint64 `json:"request"`
	Arg          Uint64      `json:"arg"`
	Buffer       string      `json:"buffer"`
	BufferOffset Uint64      `json:"buffer_offset"`
	BufferLength Uint64      `json:"buffer_length"`
}

func (a *App) handleIoctl(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ioctlArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	argp := uintptr(args.Arg)
	var data []byte
	if args.Buffer != "" {
		buffer, err := a.bufferLocked(args.Buffer)
		if err != nil {
			a.mu.Unlock()
			return toolError(err)
		}
		data, err = sliceRange(buffer.Data, uint64(args.BufferOffset), uint64(args.BufferLength), true)
		if err != nil {
			a.mu.Unlock()
			return toolError(err)
		}
		if len(data) == 0 {
			a.mu.Unlock()
			return toolError(fmt.Errorf("ioctl buffer range must not be empty"))
		}
		argp = uintptr(unsafe.Pointer(&data[0]))
	}
	r1, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(args.Request), argp)
	runtime.KeepAlive(data)
	fields := map[string]any{"handle": handle, "fd": fd, "request": hex64(uint64(args.Request)), "return": r1, "arg": hex64(uint64(args.Arg))}
	if args.Buffer != "" {
		fields["buffer"] = args.Buffer
		fields["buffer_offset"] = hex64(uint64(args.BufferOffset))
		fields["buffer_length"] = len(data)
		fields["buffer_checksum64"] = checksum64(data)
	}
	a.mu.Unlock()
	if errno != 0 {
		return syscallResult(fields, errno)
	}
	return syscallResult(fields, nil)
}
