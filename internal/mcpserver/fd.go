package mcpserver

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type fdRefArgs struct {
	Handle string `json:"handle"`
	FD     *int   `json:"fd"`
}

func (a *App) registerFDLocked(fd int, kind, path, requestedHandle string, meta map[string]any) (*fdEntry, error) {
	if requestedHandle != "" {
		if err := validateName("fd handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.fds[requestedHandle]; exists {
			return nil, fmt.Errorf("fd handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextFDHandle++
			requestedHandle = fmt.Sprintf("fd%d", a.nextFDHandle)
			if _, exists := a.fds[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &fdEntry{Handle: requestedHandle, FD: fd, Kind: kind, Path: path, Meta: meta}
	a.fds[requestedHandle] = entry
	return entry, nil
}

func (a *App) resolveFDLocked(handle string, rawFD *int) (int, string, bool, error) {
	if handle != "" {
		entry, ok := a.fds[handle]
		if !ok {
			return -1, "", false, fmt.Errorf("fd handle %q not found", handle)
		}
		return entry.FD, entry.Handle, true, nil
	}
	if rawFD == nil {
		return -1, "", false, fmt.Errorf("handle or fd is required")
	}
	for _, entry := range a.fds {
		if entry.FD == *rawFD {
			return entry.FD, entry.Handle, true, nil
		}
	}
	if !a.config.AllowRawFD {
		return -1, "", false, fmt.Errorf("raw fd %d is not managed by this server; restart with --allow-raw-fd to permit raw FDs", *rawFD)
	}
	return *rawFD, "", false, nil
}

func statInfo(st unix.Stat_t) map[string]any {
	return map[string]any{
		"dev":        uint64(st.Dev),
		"ino":        uint64(st.Ino),
		"mode":       hex32(uint32(st.Mode)),
		"mode_octal": fmt.Sprintf("0%o", st.Mode),
		"nlink":      uint64(st.Nlink),
		"uid":        uint32(st.Uid),
		"gid":        uint32(st.Gid),
		"rdev":       uint64(st.Rdev),
		"size":       st.Size,
		"blksize":    st.Blksize,
		"blocks":     st.Blocks,
		"atime_sec":  st.Atim.Sec,
		"mtime_sec":  st.Mtim.Sec,
		"ctime_sec":  st.Ctim.Sec,
	}
}

type openArgs struct {
	Path   string      `json:"path"`
	Flags  ConstUint64 `json:"flags"`
	Mode   Uint32      `json:"mode"`
	Handle string      `json:"handle"`
}

func (a *App) handleOpen(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args openArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Path == "" {
		return toolError(fmt.Errorf("path is required"))
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.O_RDONLY | unix.O_CLOEXEC
	}
	mode := uint32(args.Mode)
	if mode == 0 {
		mode = 0o600
	}
	fd, err := unix.Open(args.Path, flags, mode)
	if err != nil {
		return syscallResult(map[string]any{"path": args.Path, "flags": flags}, err)
	}
	a.mu.Lock()
	entry, regErr := a.registerFDLocked(fd, "file", args.Path, args.Handle, map[string]any{"flags": flags})
	a.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(fd)
		return toolError(regErr)
	}
	return syscallResult(map[string]any{"handle": entry.Handle, "fd": entry.FD, "path": entry.Path, "flags": flags}, nil)
}

func (a *App) handleClose(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args fdRefArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, managed, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	closeErr := unix.Close(fd)
	if closeErr == nil && managed {
		a.mu.Lock()
		delete(a.fds, handle)
		a.mu.Unlock()
	}
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "closed": closeErr == nil}, closeErr)
}

type readArgs struct {
	fdRefArgs
	Length   Uint64 `json:"length"`
	Encoding string `json:"encoding"`
}

func (a *App) handleRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args readArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length > Uint64(a.config.MaxReadBytes) {
		return toolError(fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, a.config.MaxReadBytes))
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	buf := make([]byte, int(args.Length))
	n, readErr := unix.Read(fd, buf)
	fields := map[string]any{"handle": handle, "fd": fd, "bytes_read": n}
	if readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return toolError(err)
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return syscallResult(fields, readErr)
}

type writeArgs struct {
	fdRefArgs
	DataBase64   string `json:"data_base64"`
	DataHex      string `json:"data_hex"`
	DataUTF8     string `json:"data_utf8"`
	Buffer       string `json:"buffer"`
	BufferOffset Uint64 `json:"buffer_offset"`
	Length       Uint64 `json:"length"`
}

func (a *App) handleWrite(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args writeArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := a.inputBytesLocked(args.DataBase64, args.DataHex, args.DataUTF8, args.Buffer, uint64(args.BufferOffset), uint64(args.Length))
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	n, writeErr := unix.Write(fd, data)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

type preadArgs struct {
	readArgs
	Offset Uint64 `json:"offset"`
}

func (a *App) handlePRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args preadArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length > Uint64(a.config.MaxReadBytes) {
		return toolError(fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, a.config.MaxReadBytes))
	}
	if uint64(args.Offset) > math.MaxInt64 {
		return toolError(fmt.Errorf("offset %d exceeds int64", args.Offset))
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	buf := make([]byte, int(args.Length))
	n, readErr := unix.Pread(fd, buf, int64(args.Offset))
	fields := map[string]any{"handle": handle, "fd": fd, "offset": hex64(uint64(args.Offset)), "bytes_read": n}
	if readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return toolError(err)
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return syscallResult(fields, readErr)
}

type pwriteArgs struct {
	writeArgs
	Offset Uint64 `json:"offset"`
}

func (a *App) handlePWrite(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args pwriteArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if uint64(args.Offset) > math.MaxInt64 {
		return toolError(fmt.Errorf("offset %d exceeds int64", args.Offset))
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := a.inputBytesLocked(args.DataBase64, args.DataHex, args.DataUTF8, args.Buffer, uint64(args.BufferOffset), uint64(args.Length))
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	n, writeErr := unix.Pwrite(fd, data, int64(args.Offset))
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "offset": hex64(uint64(args.Offset)), "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

type lseekArgs struct {
	fdRefArgs
	Offset Uint64      `json:"offset"`
	Whence ConstUint64 `json:"whence"`
}

func (a *App) handleLseek(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args lseekArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if uint64(args.Offset) > math.MaxInt64 {
		return toolError(fmt.Errorf("offset %d exceeds int64", args.Offset))
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	newOffset, seekErr := unix.Seek(fd, int64(args.Offset), int(args.Whence))
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "offset": newOffset}, seekErr)
}

func (a *App) handleFstat(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args fdRefArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	var st unix.Stat_t
	statErr := unix.Fstat(fd, &st)
	fields := map[string]any{"handle": handle, "fd": fd}
	if statErr == nil {
		fields["stat"] = statInfo(st)
	}
	return syscallResult(fields, statErr)
}

type statArgs struct {
	Path     string `json:"path"`
	NoFollow bool   `json:"nofollow"`
}

func (a *App) handleStat(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args statArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Path == "" {
		return toolError(fmt.Errorf("path is required"))
	}
	var st unix.Stat_t
	var err error
	if args.NoFollow {
		err = unix.Lstat(args.Path, &st)
	} else {
		err = unix.Stat(args.Path, &st)
	}
	fields := map[string]any{"path": args.Path, "nofollow": args.NoFollow}
	if err == nil {
		fields["stat"] = statInfo(st)
	}
	return syscallResult(fields, err)
}

type readlinkArgs struct {
	Path string `json:"path"`
	Size Uint64 `json:"size"`
}

func (a *App) handleReadlink(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args readlinkArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Path == "" {
		return toolError(fmt.Errorf("path is required"))
	}
	size := uint64(args.Size)
	if size == 0 {
		size = 4096
	}
	if size > a.config.MaxReadBytes {
		return toolError(fmt.Errorf("size %d exceeds max_read_bytes %d", size, a.config.MaxReadBytes))
	}
	buf := make([]byte, int(size))
	n, err := unix.Readlink(args.Path, buf)
	fields := map[string]any{"path": args.Path, "bytes_read": n}
	if err == nil {
		fields["target"] = string(buf[:n])
	}
	return syscallResult(fields, err)
}

func sleepBriefly(ctx context.Context) bool {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
