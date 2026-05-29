package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

type bufferAllocArgs struct {
	Name            string `json:"name"`
	Size            Uint64 `json:"size"`
	ReplaceExisting bool   `json:"replace_existing"`
}

func (a *App) handleBufferAlloc(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bufferAllocArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if err := validateName("buffer", args.Name); err != nil {
		return toolError(err)
	}
	if args.Size == 0 {
		return toolError(fmt.Errorf("size must be greater than zero"))
	}
	if uint64(args.Size) > a.config.MaxBufferBytes {
		return toolError(fmt.Errorf("size %d exceeds max_buffer_bytes %d", args.Size, a.config.MaxBufferBytes))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.buffers[args.Name]; exists && !args.ReplaceExisting {
		return toolError(fmt.Errorf("buffer %q already exists", args.Name))
	}
	buffer := &bufferEntry{Name: args.Name, Data: make([]byte, int(args.Size))}
	a.buffers[args.Name] = buffer
	return jsonResult(map[string]any{"ok": true, "buffer": bufferInfo(buffer)})
}

type bufferFreeArgs struct {
	Name string `json:"name"`
}

func (a *App) handleBufferFree(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bufferFreeArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.buffers[args.Name]; !exists {
		return toolError(fmt.Errorf("buffer %q not found", args.Name))
	}
	delete(a.buffers, args.Name)
	return jsonResult(map[string]any{"ok": true, "freed": args.Name})
}

type bufferInfoArgs struct {
	Name string `json:"name"`
}

func (a *App) handleBufferInfo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bufferInfoArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if args.Name != "" {
		buffer, err := a.bufferLocked(args.Name)
		if err != nil {
			return toolError(err)
		}
		return jsonResult(map[string]any{"ok": true, "buffer": bufferInfo(buffer)})
	}
	return jsonResult(map[string]any{"ok": true, "buffers": a.bufferInfosLocked()})
}

type bufferWriteArgs struct {
	Name       string    `json:"name"`
	Offset     Uint64    `json:"offset"`
	DataBase64 string    `json:"data_base64"`
	DataHex    string    `json:"data_hex"`
	DataUTF8   string    `json:"data_utf8"`
	Fill       *fillSpec `json:"fill"`
}

func (a *App) handleBufferWrite(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bufferWriteArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	data, err := decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, args.Fill)
	if err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	buffer, err := a.bufferLocked(args.Name)
	if err != nil {
		return toolError(err)
	}
	target, err := sliceRange(buffer.Data, uint64(args.Offset), uint64(len(data)), false)
	if err != nil {
		return toolError(err)
	}
	copy(target, data)
	return jsonResult(map[string]any{"ok": true, "buffer": args.Name, "offset": hex64(uint64(args.Offset)), "bytes_written": len(data), "checksum64": checksum64(data)})
}

type bufferReadArgs struct {
	Name     string `json:"name"`
	Offset   Uint64 `json:"offset"`
	Length   Uint64 `json:"length"`
	Encoding string `json:"encoding"`
}

func (a *App) handleBufferRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bufferReadArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length > Uint64(a.config.MaxReadBytes) {
		return toolError(fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, a.config.MaxReadBytes))
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	buffer, err := a.bufferLocked(args.Name)
	if err != nil {
		return toolError(err)
	}
	data, err := sliceRange(buffer.Data, uint64(args.Offset), uint64(args.Length), false)
	if err != nil {
		return toolError(err)
	}
	encoded, err := encodeBytes(data, args.Encoding)
	if err != nil {
		return toolError(err)
	}
	encoded["ok"] = true
	encoded["buffer"] = args.Name
	encoded["offset"] = hex64(uint64(args.Offset))
	return jsonResult(encoded)
}

func (a *App) bufferLocked(name string) (*bufferEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("buffer name is required")
	}
	buffer, ok := a.buffers[name]
	if !ok {
		return nil, fmt.Errorf("buffer %q not found", name)
	}
	return buffer, nil
}

func bufferInfo(buffer *bufferEntry) map[string]any {
	return map[string]any{"name": buffer.Name, "size": len(buffer.Data), "checksum64": checksum64(buffer.Data)}
}
