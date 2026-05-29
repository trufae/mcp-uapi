package mcpserver

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func toolSummaryRegistry() []toolSpec {
	return []toolSpec{
		{"eval", "Execute JavaScript with the sys/uapi scripting layer. Read MCP resources outside eval; inside scripts use sys.* or uapi.* only, with no uapi.request/fetch helper.", schemaEval, false, true, nil},
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
