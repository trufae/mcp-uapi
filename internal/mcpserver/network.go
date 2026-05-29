package mcpserver

import (
	"context"
	"fmt"
	"net"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type sockaddrSpec struct {
	Family string `json:"family"`
	Path   string `json:"path"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	ZoneID int    `json:"zone_id"`
	PID    int    `json:"pid"`
	Groups Uint32 `json:"groups"`
}

func parseSockaddr(spec sockaddrSpec) (unix.Sockaddr, error) {
	switch spec.Family {
	case "unix":
		if spec.Path == "" {
			return nil, fmt.Errorf("unix sockaddr requires path")
		}
		return &unix.SockaddrUnix{Name: spec.Path}, nil
	case "inet4":
		ip := net.ParseIP(spec.IP).To4()
		if ip == nil {
			return nil, fmt.Errorf("inet4 sockaddr requires IPv4 address")
		}
		addr := &unix.SockaddrInet4{Port: spec.Port}
		copy(addr.Addr[:], ip)
		return addr, nil
	case "inet6":
		ip := net.ParseIP(spec.IP).To16()
		if ip == nil {
			return nil, fmt.Errorf("inet6 sockaddr requires IPv6 address")
		}
		addr := &unix.SockaddrInet6{Port: spec.Port, ZoneId: uint32(spec.ZoneID)}
		copy(addr.Addr[:], ip)
		return addr, nil
	case "netlink":
		return &unix.SockaddrNetlink{Pid: uint32(spec.PID), Groups: uint32(spec.Groups)}, nil
	default:
		return nil, fmt.Errorf("unsupported sockaddr family %q", spec.Family)
	}
}

func sockaddrInfo(sa unix.Sockaddr) map[string]any {
	switch addr := sa.(type) {
	case *unix.SockaddrUnix:
		return map[string]any{"family": "unix", "path": addr.Name}
	case *unix.SockaddrInet4:
		return map[string]any{"family": "inet4", "ip": net.IP(addr.Addr[:]).String(), "port": addr.Port}
	case *unix.SockaddrInet6:
		return map[string]any{"family": "inet6", "ip": net.IP(addr.Addr[:]).String(), "port": addr.Port, "zone_id": addr.ZoneId}
	case *unix.SockaddrNetlink:
		return map[string]any{"family": "netlink", "pid": addr.Pid, "groups": addr.Groups}
	case nil:
		return nil
	default:
		return map[string]any{"family": fmt.Sprintf("%T", sa)}
	}
}

type socketArgs struct {
	Domain   ConstUint64 `json:"domain"`
	Type     ConstUint64 `json:"type"`
	Protocol ConstUint64 `json:"protocol"`
	Handle   string      `json:"handle"`
}

func (a *App) handleSocket(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args socketArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	fd, err := unix.Socket(int(args.Domain), int(args.Type), int(args.Protocol))
	if err != nil {
		return syscallResult(map[string]any{"domain": int(args.Domain), "type": int(args.Type), "protocol": int(args.Protocol)}, err)
	}
	a.mu.Lock()
	entry, regErr := a.registerFDLocked(fd, "socket", "", args.Handle, map[string]any{"domain": int(args.Domain), "type": int(args.Type), "protocol": int(args.Protocol)})
	a.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(fd)
		return toolError(regErr)
	}
	return syscallResult(map[string]any{"handle": entry.Handle, "fd": fd, "domain": int(args.Domain), "type": int(args.Type), "protocol": int(args.Protocol)}, nil)
}

type socketpairArgs struct {
	Domain   ConstUint64 `json:"domain"`
	Type     ConstUint64 `json:"type"`
	Protocol ConstUint64 `json:"protocol"`
	Handles  []string    `json:"handles"`
}

func (a *App) handleSocketpair(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args socketpairArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	domain := int(args.Domain)
	if domain == 0 {
		domain = unix.AF_UNIX
	}
	typ := int(args.Type)
	if typ == 0 {
		typ = unix.SOCK_STREAM | unix.SOCK_CLOEXEC
	}
	if len(args.Handles) != 0 && len(args.Handles) != 2 {
		return toolError(fmt.Errorf("handles must contain exactly two names when provided"))
	}
	fds, err := unix.Socketpair(domain, typ, int(args.Protocol))
	if err != nil {
		return syscallResult(map[string]any{"domain": domain, "type": typ, "protocol": int(args.Protocol)}, err)
	}
	a.mu.Lock()
	handle0, handle1 := "", ""
	if len(args.Handles) == 2 {
		handle0, handle1 = args.Handles[0], args.Handles[1]
	}
	entry0, err0 := a.registerFDLocked(fds[0], "socketpair", "", handle0, map[string]any{"peer_index": 1, "domain": domain, "type": typ})
	entry1, err1 := a.registerFDLocked(fds[1], "socketpair", "", handle1, map[string]any{"peer_index": 0, "domain": domain, "type": typ})
	a.mu.Unlock()
	if err0 != nil || err1 != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		if err0 != nil {
			return toolError(err0)
		}
		return toolError(err1)
	}
	return syscallResult(map[string]any{"handles": []string{entry0.Handle, entry1.Handle}, "fds": []int{fds[0], fds[1]}, "domain": domain, "type": typ, "protocol": int(args.Protocol)}, nil)
}

type bindConnectArgs struct {
	fdRefArgs
	Sockaddr sockaddrSpec `json:"sockaddr"`
}

func (a *App) handleBind(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bindConnectArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	sa, err := parseSockaddr(args.Sockaddr)
	if err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	bindErr := unix.Bind(fd, sa)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "sockaddr": sockaddrInfo(sa)}, bindErr)
}

func (a *App) handleConnect(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args bindConnectArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	sa, err := parseSockaddr(args.Sockaddr)
	if err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	connectErr := unix.Connect(fd, sa)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "sockaddr": sockaddrInfo(sa)}, connectErr)
}

type listenArgs struct {
	fdRefArgs
	Backlog Uint32 `json:"backlog"`
}

func (a *App) handleListen(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args listenArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	backlog := int(args.Backlog)
	if backlog == 0 {
		backlog = 128
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	listenErr := unix.Listen(fd, backlog)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "backlog": backlog}, listenErr)
}

type acceptArgs struct {
	ListenerHandle string      `json:"listener_handle"`
	ListenerFD     *int        `json:"listener_fd"`
	Flags          ConstUint64 `json:"flags"`
	Handle         string      `json:"handle"`
}

func (a *App) handleAccept(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args acceptArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.SOCK_CLOEXEC
	}
	a.mu.Lock()
	fd, parentHandle, _, err := a.resolveFDLocked(args.ListenerHandle, args.ListenerFD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	nfd, sa, acceptErr := unix.Accept4(fd, flags)
	fields := map[string]any{"listener_handle": parentHandle, "listener_fd": fd, "flags": flags}
	if acceptErr == nil {
		a.mu.Lock()
		entry, regErr := a.registerFDLocked(nfd, "accepted_socket", "", args.Handle, map[string]any{"listener": parentHandle})
		a.mu.Unlock()
		if regErr != nil {
			_ = unix.Close(nfd)
			return toolError(regErr)
		}
		fields["handle"] = entry.Handle
		fields["fd"] = nfd
		fields["sockaddr"] = sockaddrInfo(sa)
	}
	return syscallResult(fields, acceptErr)
}

type sendtoArgs struct {
	writeArgs
	Flags    ConstUint64   `json:"flags"`
	Sockaddr *sockaddrSpec `json:"sockaddr"`
}

func (a *App) handleSendto(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args sendtoArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	var sa unix.Sockaddr
	var err error
	if args.Sockaddr != nil {
		sa, err = parseSockaddr(*args.Sockaddr)
		if err != nil {
			return toolError(err)
		}
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
	sendErr := unix.Sendto(fd, data, int(args.Flags), sa)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(data), "bytes_sent": len(data), "flags": int(args.Flags), "checksum64": checksum64(data), "sockaddr": sockaddrInfo(sa)}, sendErr)
}

type recvfromArgs struct {
	fdRefArgs
	Length   Uint64      `json:"length"`
	Flags    ConstUint64 `json:"flags"`
	Encoding string      `json:"encoding"`
}

func (a *App) handleRecvfrom(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args recvfromArgs
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
	n, sa, recvErr := unix.Recvfrom(fd, buf, int(args.Flags))
	fields := map[string]any{"handle": handle, "fd": fd, "bytes_received": n, "flags": int(args.Flags), "sockaddr": sockaddrInfo(sa)}
	if recvErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return toolError(err)
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return syscallResult(fields, recvErr)
}

func (a *App) handleGetsockname(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return a.sockName(ctx, request, unix.Getsockname, "getsockname")
}

func (a *App) handleGetpeername(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return a.sockName(ctx, request, unix.Getpeername, "getpeername")
}

func (a *App) sockName(ctx context.Context, request mcp.CallToolRequest, fn func(int) (unix.Sockaddr, error), name string) (*mcp.CallToolResult, error) {
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
	sa, sockErr := fn(fd)
	return syscallResult(map[string]any{"operation": name, "handle": handle, "fd": fd, "sockaddr": sockaddrInfo(sa)}, sockErr)
}

type sockoptIntArgs struct {
	fdRefArgs
	Level ConstUint64 `json:"level"`
	Opt   ConstUint64 `json:"opt"`
	Value ConstUint64 `json:"value"`
}

func (a *App) handleSetsockoptInt(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args sockoptIntArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	err = unix.SetsockoptInt(fd, int(args.Level), int(args.Opt), int(args.Value))
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": int(args.Value)}, err)
}

func (a *App) handleGetsockoptInt(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args sockoptIntArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	value, optErr := unix.GetsockoptInt(fd, int(args.Level), int(args.Opt))
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": value}, optErr)
}

type shutdownArgs struct {
	fdRefArgs
	How ConstUint64 `json:"how"`
}

func (a *App) handleShutdown(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args shutdownArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	how := int(args.How)
	if how == 0 {
		how = unix.SHUT_RDWR
	}
	a.mu.Lock()
	fd, handle, _, err := a.resolveFDLocked(args.Handle, args.FD)
	a.mu.Unlock()
	if err != nil {
		return toolError(err)
	}
	shutdownErr := unix.Shutdown(fd, how)
	return syscallResult(map[string]any{"handle": handle, "fd": fd, "how": how}, shutdownErr)
}
