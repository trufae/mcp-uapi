package mcpserver

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sys/unix"
)

func (a *App) handleUname(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return syscallResult(nil, err)
	}
	return syscallResult(map[string]any{
		"sysname":    unix.ByteSliceToString(uts.Sysname[:]),
		"nodename":   unix.ByteSliceToString(uts.Nodename[:]),
		"release":    unix.ByteSliceToString(uts.Release[:]),
		"version":    unix.ByteSliceToString(uts.Version[:]),
		"machine":    unix.ByteSliceToString(uts.Machine[:]),
		"domainname": unix.ByteSliceToString(uts.Domainname[:]),
	}, nil)
}

func (a *App) handleGetpid(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return jsonResult(map[string]any{"ok": true, "pid": unix.Getpid(), "ppid": unix.Getppid(), "uid": unix.Getuid(), "euid": unix.Geteuid(), "gid": unix.Getgid(), "egid": unix.Getegid()})
}

type killArgs struct {
	PID    int         `json:"pid"`
	Signal ConstUint64 `json:"signal"`
}

func (a *App) handleKill(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args killArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := unix.Kill(args.PID, syscall.Signal(args.Signal))
	return syscallResult(map[string]any{"pid": args.PID, "signal": int(args.Signal)}, err)
}

type wait4Args struct {
	PID       int         `json:"pid"`
	Options   ConstUint64 `json:"options"`
	TimeoutMS Uint32      `json:"timeout_ms"`
}

func (a *App) handleWait4(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args wait4Args
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	pid := args.PID
	if pid == 0 {
		pid = -1
	}
	status, rusage, waitedPID, err := wait4WithTimeout(ctx, pid, int(args.Options), time.Duration(args.TimeoutMS)*time.Millisecond)
	fields := map[string]any{"pid": pid, "waited_pid": waitedPID, "options": int(args.Options)}
	if err == nil && waitedPID != 0 {
		fields["status"] = waitStatusInfo(status)
		fields["rusage"] = rusageInfo(rusage)
	}
	return syscallResult(fields, err)
}

type ptraceAttachArgs struct {
	PID       int    `json:"pid"`
	Wait      *bool  `json:"wait"`
	TimeoutMS Uint32 `json:"timeout_ms"`
}

func (a *App) handlePtraceAttach(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceAttachArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.PID <= 0 {
		return toolError(fmt.Errorf("pid must be greater than zero"))
	}
	err := unix.PtraceAttach(args.PID)
	fields := map[string]any{"pid": args.PID, "attached": err == nil}
	if err != nil {
		return syscallResult(fields, err)
	}
	wait := true
	if args.Wait != nil {
		wait = *args.Wait
	}
	if wait {
		timeout := time.Duration(args.TimeoutMS) * time.Millisecond
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		status, rusage, waitedPID, waitErr := wait4WithTimeout(ctx, args.PID, unix.WUNTRACED, timeout)
		fields["waited_pid"] = waitedPID
		if waitedPID != 0 {
			fields["status"] = waitStatusInfo(status)
			fields["rusage"] = rusageInfo(rusage)
		}
		if waitErr != nil {
			return syscallResult(fields, waitErr)
		}
	}
	return syscallResult(fields, nil)
}

type ptracePIDArgs struct {
	PID int `json:"pid"`
}

func (a *App) handlePtraceDetach(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptracePIDArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := unix.PtraceDetach(args.PID)
	return syscallResult(map[string]any{"pid": args.PID, "detached": err == nil}, err)
}

type ptraceReadArgs struct {
	PID      int    `json:"pid"`
	Address  Uint64 `json:"address"`
	Length   Uint64 `json:"length"`
	Encoding string `json:"encoding"`
}

func (a *App) handlePtraceRead(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceReadArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	if args.Length > Uint64(a.config.MaxReadBytes) {
		return toolError(fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, a.config.MaxReadBytes))
	}
	data := make([]byte, int(args.Length))
	n, err := unix.PtracePeekData(args.PID, uintptr(args.Address), data)
	fields := map[string]any{"pid": args.PID, "address": hex64(uint64(args.Address)), "bytes_read": n}
	if err == nil {
		encoded, encErr := encodeBytes(data[:n], args.Encoding)
		if encErr != nil {
			return toolError(encErr)
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return syscallResult(fields, err)
}

type ptraceWriteArgs struct {
	PID        int    `json:"pid"`
	Address    Uint64 `json:"address"`
	DataBase64 string `json:"data_base64"`
	DataHex    string `json:"data_hex"`
	DataUTF8   string `json:"data_utf8"`
}

func (a *App) handlePtraceWrite(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceWriteArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	data, err := decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, nil)
	if err != nil {
		return toolError(err)
	}
	n, pokeErr := unix.PtracePokeData(args.PID, uintptr(args.Address), data)
	return syscallResult(map[string]any{"pid": args.PID, "address": hex64(uint64(args.Address)), "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, pokeErr)
}

type ptraceSignalArgs struct {
	PID    int         `json:"pid"`
	Signal ConstUint64 `json:"signal"`
}

func (a *App) handlePtraceCont(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceSignalArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := unix.PtraceCont(args.PID, int(args.Signal))
	return syscallResult(map[string]any{"pid": args.PID, "signal": int(args.Signal)}, err)
}

func (a *App) handlePtraceSyscall(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceSignalArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := unix.PtraceSyscall(args.PID, int(args.Signal))
	return syscallResult(map[string]any{"pid": args.PID, "signal": int(args.Signal)}, err)
}

type prctlArgs struct {
	Option ConstUint64 `json:"option"`
	Arg2   Uint64      `json:"arg2"`
	Arg3   Uint64      `json:"arg3"`
	Arg4   Uint64      `json:"arg4"`
	Arg5   Uint64      `json:"arg5"`
}

func (a *App) handlePrctl(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args prctlArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := unix.Prctl(int(args.Option), uintptr(args.Arg2), uintptr(args.Arg3), uintptr(args.Arg4), uintptr(args.Arg5))
	return syscallResult(map[string]any{"option": int(args.Option), "arg2": hex64(uint64(args.Arg2)), "arg3": hex64(uint64(args.Arg3)), "arg4": hex64(uint64(args.Arg4)), "arg5": hex64(uint64(args.Arg5))}, err)
}

func wait4WithTimeout(ctx context.Context, pid int, options int, timeout time.Duration) (unix.WaitStatus, unix.Rusage, int, error) {
	var status unix.WaitStatus
	var rusage unix.Rusage
	if timeout <= 0 {
		waitedPID, err := unix.Wait4(pid, &status, options, &rusage)
		return status, rusage, waitedPID, err
	}
	deadline := time.Now().Add(timeout)
	loopOptions := options | unix.WNOHANG
	for {
		waitedPID, err := unix.Wait4(pid, &status, loopOptions, &rusage)
		if err != nil || waitedPID != 0 {
			return status, rusage, waitedPID, err
		}
		if time.Now().After(deadline) {
			return status, rusage, 0, unix.EAGAIN
		}
		if !sleepBriefly(ctx) {
			return status, rusage, 0, ctx.Err()
		}
	}
}

func waitStatusInfo(status unix.WaitStatus) map[string]any {
	return map[string]any{
		"raw":         int(status),
		"exited":      status.Exited(),
		"exit_status": status.ExitStatus(),
		"signaled":    status.Signaled(),
		"signal":      int(status.Signal()),
		"stopped":     status.Stopped(),
		"stop_signal": int(status.StopSignal()),
		"continued":   status.Continued(),
		"core_dump":   status.CoreDump(),
	}
}

func rusageInfo(rusage unix.Rusage) map[string]any {
	return map[string]any{
		"utime_usec": rusage.Utime.Sec*1_000_000 + int64(rusage.Utime.Usec),
		"stime_usec": rusage.Stime.Sec*1_000_000 + int64(rusage.Stime.Usec),
		"maxrss":     rusage.Maxrss,
		"minflt":     rusage.Minflt,
		"majflt":     rusage.Majflt,
		"inblock":    rusage.Inblock,
		"oublock":    rusage.Oublock,
		"nvcsw":      rusage.Nvcsw,
		"nivcsw":     rusage.Nivcsw,
	}
}

func runPtraceHelper() {
	if os.Getenv("MCP_UAPI_PTRACE_HELPER") == "" {
		return
	}
	buf := []byte("mcp-uapi-ptrace-test")
	fmt.Printf("%d %p\n", os.Getpid(), &buf[0])
	_, _ = os.Stdout.WriteString("ready\n")
	select {}
}
