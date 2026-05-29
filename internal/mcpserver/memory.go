package mcpserver

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"unsafe"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type mmapArgs struct {
	FDHandle string      `json:"fd_handle"`
	FD       *int        `json:"fd"`
	Length   Uint64      `json:"length"`
	Prot     ConstUint64 `json:"prot"`
	Flags    ConstUint64 `json:"flags"`
	Offset   Uint64      `json:"offset"`
	Handle   string      `json:"handle"`
}

func (a *App) handleMmap(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mmapArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length == 0 {
		return toolError(fmt.Errorf("length must be greater than zero"))
	}
	if uint64(args.Length) > a.config.MaxBufferBytes {
		return toolError(fmt.Errorf("length %d exceeds max_buffer_bytes %d", args.Length, a.config.MaxBufferBytes))
	}
	if uint64(args.Offset) > math.MaxInt64 {
		return toolError(fmt.Errorf("offset %d exceeds int64", args.Offset))
	}
	prot := int(args.Prot)
	if prot == 0 {
		prot = unix.PROT_READ | unix.PROT_WRITE
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.MAP_PRIVATE | unix.MAP_ANONYMOUS
	}
	fd := -1
	if flags&unix.MAP_ANONYMOUS == 0 && flags&unix.MAP_ANON == 0 {
		a.mu.Lock()
		resolved, _, _, err := a.resolveFDLocked(args.FDHandle, args.FD)
		a.mu.Unlock()
		if err != nil {
			return toolError(err)
		}
		fd = resolved
	} else if args.FDHandle != "" || args.FD != nil {
		a.mu.Lock()
		resolved, _, _, err := a.resolveFDLocked(args.FDHandle, args.FD)
		a.mu.Unlock()
		if err != nil {
			return toolError(err)
		}
		fd = resolved
	}
	data, err := unix.Mmap(fd, int64(args.Offset), int(args.Length), prot, flags)
	if err != nil {
		return syscallResult(map[string]any{"fd": fd, "length": uint64(args.Length), "prot": prot, "flags": flags}, err)
	}
	a.mu.Lock()
	handle, regErr := a.registerMappingLocked(data, fd, int64(args.Offset), prot, flags, args.Handle)
	a.mu.Unlock()
	if regErr != nil {
		_ = unix.Munmap(data)
		return toolError(regErr)
	}
	return syscallResult(map[string]any{"mapping": mappingInfo(handle)}, nil)
}

func (a *App) registerMappingLocked(data []byte, fd int, offset int64, prot int, flags int, requestedHandle string) (*mmapEntry, error) {
	if requestedHandle != "" {
		if err := validateName("mapping handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.mappings[requestedHandle]; exists {
			return nil, fmt.Errorf("mapping handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextMapHandle++
			requestedHandle = fmt.Sprintf("map%d", a.nextMapHandle)
			if _, exists := a.mappings[requestedHandle]; !exists {
				break
			}
		}
	}
	mapping := &mmapEntry{Handle: requestedHandle, Data: data, FD: fd, Offset: offset, Prot: prot, Flags: flags}
	a.mappings[requestedHandle] = mapping
	return mapping, nil
}

type mappingArgs struct {
	Mapping string `json:"mapping"`
}

func (a *App) handleMunmap(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mappingArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data := mapping.Data
	a.mu.Unlock()
	unmapErr := unix.Munmap(data)
	if unmapErr == nil {
		a.mu.Lock()
		delete(a.mappings, args.Mapping)
		a.mu.Unlock()
	}
	return syscallResult(map[string]any{"mapping": args.Mapping, "unmapped": unmapErr == nil}, unmapErr)
}

type mprotectArgs struct {
	Mapping string      `json:"mapping"`
	Offset  Uint64      `json:"offset"`
	Length  Uint64      `json:"length"`
	Prot    ConstUint64 `json:"prot"`
}

func (a *App) handleMprotect(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args mprotectArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := sliceRange(mapping.Data, uint64(args.Offset), uint64(args.Length), true)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	protErr := unix.Mprotect(data, int(args.Prot))
	if protErr == nil {
		a.mu.Lock()
		mapping.Prot = int(args.Prot)
		a.mu.Unlock()
	}
	return syscallResult(map[string]any{"mapping": args.Mapping, "offset": hex64(uint64(args.Offset)), "length": len(data), "prot": int(args.Prot)}, protErr)
}

type msyncArgs struct {
	Mapping string      `json:"mapping"`
	Offset  Uint64      `json:"offset"`
	Length  Uint64      `json:"length"`
	Flags   ConstUint64 `json:"flags"`
}

func (a *App) handleMsync(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args msyncArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.MS_SYNC
	}
	a.mu.Lock()
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := sliceRange(mapping.Data, uint64(args.Offset), uint64(args.Length), true)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	msyncErr := msync(data, flags)
	return syscallResult(map[string]any{"mapping": args.Mapping, "offset": hex64(uint64(args.Offset)), "length": len(data), "flags": flags}, msyncErr)
}

type madviseArgs struct {
	Mapping string      `json:"mapping"`
	Offset  Uint64      `json:"offset"`
	Length  Uint64      `json:"length"`
	Advice  ConstUint64 `json:"advice"`
}

func (a *App) handleMadvise(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args madviseArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := sliceRange(mapping.Data, uint64(args.Offset), uint64(args.Length), true)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	adviseErr := unix.Madvise(data, int(args.Advice))
	return syscallResult(map[string]any{"mapping": args.Mapping, "offset": hex64(uint64(args.Offset)), "length": len(data), "advice": int(args.Advice)}, adviseErr)
}

type memReadArgs struct {
	Mapping  string `json:"mapping"`
	Offset   Uint64 `json:"offset"`
	Length   Uint64 `json:"length"`
	Encoding string `json:"encoding"`
}

func (a *App) handleMemRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args memReadArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length > Uint64(a.config.MaxReadBytes) {
		return toolError(fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, a.config.MaxReadBytes))
	}
	a.mu.Lock()
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	data, err := sliceRange(mapping.Data, uint64(args.Offset), uint64(args.Length), false)
	if err == nil {
		data = append([]byte(nil), data...)
	}
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	encoded, err := encodeBytes(data, args.Encoding)
	if err != nil {
		return toolError(err)
	}
	encoded["ok"] = true
	encoded["mapping"] = args.Mapping
	encoded["offset"] = hex64(uint64(args.Offset))
	return jsonResult(encoded)
}

type memWriteArgs struct {
	Mapping      string `json:"mapping"`
	Offset       Uint64 `json:"offset"`
	DataBase64   string `json:"data_base64"`
	DataHex      string `json:"data_hex"`
	DataUTF8     string `json:"data_utf8"`
	Buffer       string `json:"buffer"`
	BufferOffset Uint64 `json:"buffer_offset"`
	Length       Uint64 `json:"length"`
}

func (a *App) handleMemWrite(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args memWriteArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	data, err := a.inputBytesLocked(args.DataBase64, args.DataHex, args.DataUTF8, args.Buffer, uint64(args.BufferOffset), uint64(args.Length))
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	mapping, err := a.mappingLocked(args.Mapping)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	target, err := sliceRange(mapping.Data, uint64(args.Offset), uint64(len(data)), false)
	if err != nil {
		a.mu.Unlock()
		return toolError(err)
	}
	copy(target, data)
	a.mu.Unlock()
	return jsonResult(map[string]any{"ok": true, "mapping": args.Mapping, "offset": hex64(uint64(args.Offset)), "bytes_written": len(data), "checksum64": checksum64(data)})
}

func (a *App) mappingLocked(handle string) (*mmapEntry, error) {
	if handle == "" {
		return nil, fmt.Errorf("mapping handle is required")
	}
	mapping, ok := a.mappings[handle]
	if !ok {
		return nil, fmt.Errorf("mapping %q not found", handle)
	}
	return mapping, nil
}

func mappingInfo(mapping *mmapEntry) map[string]any {
	info := map[string]any{"handle": mapping.Handle, "length": len(mapping.Data), "fd": mapping.FD, "offset": mapping.Offset, "prot": mapping.Prot, "flags": mapping.Flags}
	if len(mapping.Data) > 0 {
		info["address"] = hexPtr(uintptr(unsafe.Pointer(&mapping.Data[0])))
	}
	info["checksum64"] = checksum64(mapping.Data)
	return info
}

func msync(data []byte, flags int) error {
	if len(data) == 0 {
		return nil
	}
	_, _, errno := unix.Syscall(unix.SYS_MSYNC, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(flags))
	runtime.KeepAlive(data)
	if errno != 0 {
		return errno
	}
	return nil
}
