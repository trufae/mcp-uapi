package mcpserver

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func toolSummaryRegistry() []toolSpec {
	return []toolSpec{
		{"uapi_capabilities", "Return the complete server capability document, including client bootstrap hints and scripting metadata.", schemaCapabilities, true, false, nil},
		{"uapi_constants", "Return Linux constants accepted by schemas, optionally filtered by group.", schemaConstants, true, false, nil},
		{"uapi_errno", "Decode an errno number or name.", schemaErrno, true, false, nil},
		{"uapi_uname", "Return unix.Uname kernel identity fields.", schemaNoArgs, true, false, nil},
		{"uapi_getpid", "Return this MCP server process PID, PPID, UID, EUID, GID, and EGID.", schemaNoArgs, true, false, nil},
		{"uapi_open", "Open a path with unix.Open and register a managed FD handle.", schemaOpen, false, true, nil},
		{"uapi_close", "Close a managed or permitted raw FD.", schemaClose, false, true, nil},
		{"uapi_read", "Read bytes from an FD and return base64, hex, or UTF-8 text with checksum metadata.", schemaRead, true, false, nil},
		{"uapi_write", "Write bytes or a managed buffer to an FD.", schemaWrite, false, true, nil},
		{"uapi_pread", "Read bytes from an FD at an explicit offset.", schemaPRead, true, false, nil},
		{"uapi_pwrite", "Write bytes or a managed buffer to an FD at an explicit offset.", schemaPWrite, false, true, nil},
		{"uapi_lseek", "Move an FD offset with unix.Seek.", schemaLseek, false, true, nil},
		{"uapi_fstat", "Return unix.Fstat metadata for an FD.", schemaFstat, true, false, nil},
		{"uapi_stat", "Return unix.Stat or unix.Lstat metadata for a path.", schemaStat, true, false, nil},
		{"uapi_readlink", "Read a symlink target with unix.Readlink.", schemaReadlink, true, false, nil},
		{"uapi_buffer_alloc", "Allocate a bounded managed user-space byte buffer.", schemaBufferAlloc, false, true, nil},
		{"uapi_buffer_free", "Free a managed user-space byte buffer.", schemaBufferFree, false, true, nil},
		{"uapi_buffer_info", "Describe one or all managed buffers.", schemaBufferInfo, true, false, nil},
		{"uapi_buffer_write", "Write base64/hex/UTF-8 data or deterministic fill bytes into a managed buffer.", schemaBufferWrite, false, true, nil},
		{"uapi_buffer_read", "Read managed buffer bytes as base64, hex, or UTF-8 text.", schemaBufferRead, true, false, nil},
		{"uapi_mmap", "Create an anonymous or file-backed mapping with unix.Mmap and register a mapping handle.", schemaMmap, false, true, nil},
		{"uapi_munmap", "Unmap and unregister a managed mapping.", schemaMunmap, false, true, nil},
		{"uapi_mprotect", "Change protection on a managed mapping range.", schemaMprotect, false, true, nil},
		{"uapi_msync", "Synchronize a managed mapping range with msync.", schemaMsync, false, true, nil},
		{"uapi_madvise", "Apply madvise to a managed mapping range.", schemaMadvise, false, true, nil},
		{"uapi_mem_read", "Read bytes from a managed mapping.", schemaMemRead, true, false, nil},
		{"uapi_mem_write", "Write bytes or a managed buffer into a managed mapping.", schemaMemWrite, false, true, nil},
		{"uapi_socket", "Create a socket with unix.Socket and register a managed FD handle.", schemaSocket, false, true, nil},
		{"uapi_socketpair", "Create a socket pair and register both managed FD handles.", schemaSocketpair, false, true, nil},
		{"uapi_bind", "Bind a socket to a unix/inet/netlink sockaddr.", schemaBindConnect, false, true, nil},
		{"uapi_connect", "Connect a socket to a unix/inet/netlink sockaddr.", schemaBindConnect, false, true, nil},
		{"uapi_listen", "Listen on a socket FD.", schemaListen, false, true, nil},
		{"uapi_accept", "Accept a socket connection with unix.Accept4 and register the accepted FD.", schemaAccept, false, true, nil},
		{"uapi_sendto", "Send bytes or a managed buffer through a socket, optionally with a destination sockaddr.", schemaSendto, false, true, nil},
		{"uapi_recvfrom", "Receive bytes from a socket and return source sockaddr metadata.", schemaRecvfrom, false, true, nil},
		{"uapi_getsockname", "Return the local sockaddr for a socket.", schemaSockName, true, false, nil},
		{"uapi_getpeername", "Return the peer sockaddr for a connected socket.", schemaSockName, true, false, nil},
		{"uapi_setsockopt_int", "Set an integer socket option.", schemaSockOptInt, false, true, nil},
		{"uapi_getsockopt_int", "Get an integer socket option.", schemaSockOptInt, true, false, nil},
		{"uapi_shutdown", "Shut down socket reads, writes, or both.", schemaShutdown, false, true, nil},
		{"uapi_poll", "Poll managed or permitted raw FDs for readiness.", schemaPoll, true, false, nil},
		{"uapi_epoll_create", "Create an epoll instance and register a managed FD handle.", schemaEpollCreate, false, true, nil},
		{"uapi_epoll_ctl", "Add, modify, or delete an FD in an epoll instance.", schemaEpollCtl, false, true, nil},
		{"uapi_epoll_wait", "Wait for epoll events and return ready event metadata.", schemaEpollWait, true, false, nil},
		{"uapi_kill", "Send a signal to a process with unix.Kill.", schemaKill, false, true, nil},
		{"uapi_wait4", "Wait for child or traced process state with unix.Wait4.", schemaWait4, false, true, nil},
		{"uapi_ptrace_attach", "Attach to a process with ptrace and optionally wait for its stop.", schemaPtraceAttach, false, true, nil},
		{"uapi_ptrace_detach", "Detach from a traced process.", schemaPtraceDetach, false, true, nil},
		{"uapi_ptrace_read", "Read traced process memory with PtracePeekData.", schemaPtraceRead, true, false, nil},
		{"uapi_ptrace_write", "Write traced process memory with PtracePokeData.", schemaPtraceWrite, false, true, nil},
		{"uapi_ptrace_cont", "Continue a traced process, optionally delivering a signal.", schemaPtraceSignal, false, true, nil},
		{"uapi_ptrace_syscall", "Continue a traced process until the next syscall-stop.", schemaPtraceSignal, false, true, nil},
		{"uapi_ioctl", "Invoke ioctl with either an integer argument or a pointer to a managed buffer range.", schemaIoctl, false, true, nil},
		{"uapi_prctl", "Invoke unix.Prctl with explicit uintptr arguments.", schemaPrctl, false, true, nil},
		{"eval", "Execute JavaScript with uapi/sys wrappers, captured logs, deterministic RNG helpers, timeout enforcement, and JSON return values.", schemaEval, false, true, nil},
	}
}

func toolRegistry(a *App) []toolSpec {
	specs := toolSummaryRegistry()
	for i := range specs {
		specs[i].handler = a.handlerForTool(specs[i].name)
	}
	return specs
}

func (a *App) handlerForTool(name string) server.ToolHandlerFunc {
	switch name {
	case "uapi_capabilities":
		return a.handleCapabilities
	case "uapi_constants":
		return a.handleConstants
	case "uapi_errno":
		return a.handleErrno
	case "uapi_uname":
		return a.handleUname
	case "uapi_getpid":
		return a.handleGetpid
	case "uapi_open":
		return a.handleOpen
	case "uapi_close":
		return a.handleClose
	case "uapi_read":
		return a.handleRead
	case "uapi_write":
		return a.handleWrite
	case "uapi_pread":
		return a.handlePRead
	case "uapi_pwrite":
		return a.handlePWrite
	case "uapi_lseek":
		return a.handleLseek
	case "uapi_fstat":
		return a.handleFstat
	case "uapi_stat":
		return a.handleStat
	case "uapi_readlink":
		return a.handleReadlink
	case "uapi_buffer_alloc":
		return a.handleBufferAlloc
	case "uapi_buffer_free":
		return a.handleBufferFree
	case "uapi_buffer_info":
		return a.handleBufferInfo
	case "uapi_buffer_write":
		return a.handleBufferWrite
	case "uapi_buffer_read":
		return a.handleBufferRead
	case "uapi_mmap":
		return a.handleMmap
	case "uapi_munmap":
		return a.handleMunmap
	case "uapi_mprotect":
		return a.handleMprotect
	case "uapi_msync":
		return a.handleMsync
	case "uapi_madvise":
		return a.handleMadvise
	case "uapi_mem_read":
		return a.handleMemRead
	case "uapi_mem_write":
		return a.handleMemWrite
	case "uapi_socket":
		return a.handleSocket
	case "uapi_socketpair":
		return a.handleSocketpair
	case "uapi_bind":
		return a.handleBind
	case "uapi_connect":
		return a.handleConnect
	case "uapi_listen":
		return a.handleListen
	case "uapi_accept":
		return a.handleAccept
	case "uapi_sendto":
		return a.handleSendto
	case "uapi_recvfrom":
		return a.handleRecvfrom
	case "uapi_getsockname":
		return a.handleGetsockname
	case "uapi_getpeername":
		return a.handleGetpeername
	case "uapi_setsockopt_int":
		return a.handleSetsockoptInt
	case "uapi_getsockopt_int":
		return a.handleGetsockoptInt
	case "uapi_shutdown":
		return a.handleShutdown
	case "uapi_poll":
		return a.handlePoll
	case "uapi_epoll_create":
		return a.handleEpollCreate
	case "uapi_epoll_ctl":
		return a.handleEpollCtl
	case "uapi_epoll_wait":
		return a.handleEpollWait
	case "uapi_kill":
		return a.handleKill
	case "uapi_wait4":
		return a.handleWait4
	case "uapi_ptrace_attach":
		return a.handlePtraceAttach
	case "uapi_ptrace_detach":
		return a.handlePtraceDetach
	case "uapi_ptrace_read":
		return a.handlePtraceRead
	case "uapi_ptrace_write":
		return a.handlePtraceWrite
	case "uapi_ptrace_cont":
		return a.handlePtraceCont
	case "uapi_ptrace_syscall":
		return a.handlePtraceSyscall
	case "uapi_ioctl":
		return a.handleIoctl
	case "uapi_prctl":
		return a.handlePrctl
	case "eval":
		return a.handleEval
	default:
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return toolError(&unknownToolError{name: name})
		}
	}
}

type unknownToolError struct{ name string }

func (e *unknownToolError) Error() string { return "unknown tool " + e.name }
