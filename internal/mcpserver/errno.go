package mcpserver

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

type constantsArgs struct {
	Group string `json:"group"`
}

func (a *App) handleCapabilities(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return jsonResult(Capabilities())
}

func (a *App) handleConstants(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args constantsArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	catalog := constantCatalog()
	if args.Group != "" {
		group, ok := catalog[args.Group]
		if !ok {
			return toolError(fmt.Errorf("unknown constants group %q", args.Group))
		}
		return jsonResult(map[string]any{"group": args.Group, "constants": group})
	}
	return jsonResult(map[string]any{"constants": catalog})
}

type errnoArgs struct {
	Errno Uint64 `json:"errno"`
	Name  string `json:"name"`
}

func (a *App) handleErrno(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args errnoArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Name != "" {
		value, ok := errnoByName()[normalizeConstantName(args.Name)]
		if !ok {
			return toolError(fmt.Errorf("unknown errno name %q", args.Name))
		}
		return jsonResult(errnoInfo(value))
	}
	return jsonResult(errnoInfo(unix.Errno(args.Errno)))
}

func errnoInfo(errno unix.Errno) map[string]any {
	return map[string]any{"errno": int(errno), "errno_name": errnoName(errno), "error": errno.Error()}
}

func errnoName(errno unix.Errno) string {
	if name, ok := errnoNames()[errno]; ok {
		return name
	}
	return fmt.Sprintf("ERRNO_%d", errno)
}

func errnoCatalog() map[string]any {
	names := errnoByName()
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	result := map[string]any{}
	for _, name := range keys {
		result[name] = int(names[name])
	}
	return result
}

func errnoByName() map[string]unix.Errno {
	result := map[string]unix.Errno{}
	for errno, name := range errnoNames() {
		result[normalizeConstantName(name)] = errno
	}
	return result
}

func errnoNames() map[unix.Errno]string {
	return map[unix.Errno]string{
		unix.EPERM: "EPERM", unix.ENOENT: "ENOENT", unix.ESRCH: "ESRCH", unix.EINTR: "EINTR", unix.EIO: "EIO", unix.ENXIO: "ENXIO", unix.E2BIG: "E2BIG", unix.ENOEXEC: "ENOEXEC", unix.EBADF: "EBADF", unix.ECHILD: "ECHILD",
		unix.EAGAIN: "EAGAIN", unix.ENOMEM: "ENOMEM", unix.EACCES: "EACCES", unix.EFAULT: "EFAULT", unix.ENOTBLK: "ENOTBLK", unix.EBUSY: "EBUSY", unix.EEXIST: "EEXIST", unix.EXDEV: "EXDEV", unix.ENODEV: "ENODEV", unix.ENOTDIR: "ENOTDIR",
		unix.EISDIR: "EISDIR", unix.EINVAL: "EINVAL", unix.ENFILE: "ENFILE", unix.EMFILE: "EMFILE", unix.ENOTTY: "ENOTTY", unix.ETXTBSY: "ETXTBSY", unix.EFBIG: "EFBIG", unix.ENOSPC: "ENOSPC", unix.ESPIPE: "ESPIPE", unix.EROFS: "EROFS",
		unix.EMLINK: "EMLINK", unix.EPIPE: "EPIPE", unix.EDOM: "EDOM", unix.ERANGE: "ERANGE", unix.EDEADLK: "EDEADLK", unix.ENAMETOOLONG: "ENAMETOOLONG", unix.ENOLCK: "ENOLCK", unix.ENOSYS: "ENOSYS", unix.ENOTEMPTY: "ENOTEMPTY", unix.ELOOP: "ELOOP",
		unix.ENOMSG: "ENOMSG", unix.EIDRM: "EIDRM", unix.ENOSTR: "ENOSTR", unix.ENODATA: "ENODATA", unix.ETIME: "ETIME", unix.ENOSR: "ENOSR", unix.ENOLINK: "ENOLINK", unix.EPROTO: "EPROTO", unix.EMULTIHOP: "EMULTIHOP", unix.EBADMSG: "EBADMSG",
		unix.EOVERFLOW: "EOVERFLOW", unix.EILSEQ: "EILSEQ", unix.ENOTSOCK: "ENOTSOCK", unix.EDESTADDRREQ: "EDESTADDRREQ", unix.EMSGSIZE: "EMSGSIZE", unix.EPROTOTYPE: "EPROTOTYPE", unix.ENOPROTOOPT: "ENOPROTOOPT", unix.EPROTONOSUPPORT: "EPROTONOSUPPORT", unix.ESOCKTNOSUPPORT: "ESOCKTNOSUPPORT", unix.EOPNOTSUPP: "EOPNOTSUPP",
		unix.EPFNOSUPPORT: "EPFNOSUPPORT", unix.EAFNOSUPPORT: "EAFNOSUPPORT", unix.EADDRINUSE: "EADDRINUSE", unix.EADDRNOTAVAIL: "EADDRNOTAVAIL", unix.ENETDOWN: "ENETDOWN", unix.ENETUNREACH: "ENETUNREACH", unix.ENETRESET: "ENETRESET", unix.ECONNABORTED: "ECONNABORTED", unix.ECONNRESET: "ECONNRESET", unix.ENOBUFS: "ENOBUFS",
		unix.EISCONN: "EISCONN", unix.ENOTCONN: "ENOTCONN", unix.ESHUTDOWN: "ESHUTDOWN", unix.ETOOMANYREFS: "ETOOMANYREFS", unix.ETIMEDOUT: "ETIMEDOUT", unix.ECONNREFUSED: "ECONNREFUSED", unix.EHOSTDOWN: "EHOSTDOWN", unix.EHOSTUNREACH: "EHOSTUNREACH", unix.EALREADY: "EALREADY", unix.EINPROGRESS: "EINPROGRESS",
		unix.ESTALE: "ESTALE", unix.EDQUOT: "EDQUOT", unix.ECANCELED: "ECANCELED", unix.EOWNERDEAD: "EOWNERDEAD", unix.ENOTRECOVERABLE: "ENOTRECOVERABLE", unix.ERFKILL: "ERFKILL", unix.EHWPOISON: "EHWPOISON",
	}
}

func errnoFromString(name string) (unix.Errno, bool) {
	value, ok := errnoByName()[strings.ToUpper(strings.TrimSpace(name))]
	return value, ok
}
