package mcpserver

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
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
	fields := map[string]any{
		"sysname":  unix.ByteSliceToString(uts.Sysname[:]),
		"nodename": unix.ByteSliceToString(uts.Nodename[:]),
		"release":  unix.ByteSliceToString(uts.Release[:]),
		"version":  unix.ByteSliceToString(uts.Version[:]),
		"machine":  unix.ByteSliceToString(uts.Machine[:]),
	}
	if domainname := platformUnameDomainname(uts); domainname != "" {
		fields["domainname"] = domainname
	}
	return syscallResult(fields, nil)
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
	err := platformPtraceAttach(args.PID)
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
	err := platformPtraceDetach(args.PID)
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
	n, err := platformPtracePeekData(args.PID, uintptr(args.Address), data)
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
	n, pokeErr := platformPtracePokeData(args.PID, uintptr(args.Address), data)
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
	err := platformPtraceCont(args.PID, int(args.Signal))
	return syscallResult(map[string]any{"pid": args.PID, "signal": int(args.Signal)}, err)
}

func (a *App) handlePtraceSyscall(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceSignalArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := platformPtraceSyscall(args.PID, int(args.Signal))
	return syscallResult(map[string]any{"pid": args.PID, "signal": int(args.Signal)}, err)
}

func (a *App) handlePtraceGetRegs(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptracePIDArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	regs, err := platformPtraceGetRegs(args.PID)
	fields := map[string]any{"pid": args.PID, "arch": runtime.GOARCH}
	if err == nil {
		raw, scalars, arrays := ptraceRegsInfo(regs)
		fields["registers"] = raw
		if syscallInfo := ptraceSyscallRegisterInfo(runtime.GOARCH, scalars, arrays); len(syscallInfo) != 0 {
			fields["syscall"] = syscallInfo
		}
	}
	return syscallResult(fields, err)
}

type ptraceOptionsArgs struct {
	PID     int         `json:"pid"`
	Options ConstUint64 `json:"options"`
}

func (a *App) handlePtraceSetOptions(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args ptraceOptionsArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	err := platformPtraceSetOptions(args.PID, int(args.Options))
	return syscallResult(map[string]any{"pid": args.PID, "options": int(args.Options)}, err)
}

func ptraceRegsInfo(regs any) (map[string]any, map[string]uint64, map[string][]uint64) {
	value := reflect.ValueOf(regs)
	typ := value.Type()
	raw := map[string]any{}
	scalars := map[string]uint64{}
	arrays := map[string][]uint64{}
	for i := 0; i < value.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		key := normalizeRegisterName(field.Name)
		fieldValue := value.Field(i)
		switch fieldValue.Kind() {
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			v := fieldValue.Uint()
			scalars[key] = v
			raw[key] = hex64(v)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v := uint64(fieldValue.Int())
			scalars[key] = v
			raw[key] = hex64(v)
		case reflect.Array:
			items := make([]string, 0, fieldValue.Len())
			values := make([]uint64, 0, fieldValue.Len())
			for j := 0; j < fieldValue.Len(); j++ {
				item := fieldValue.Index(j)
				var v uint64
				switch item.Kind() {
				case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
					v = item.Uint()
				case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
					v = uint64(item.Int())
				default:
					continue
				}
				values = append(values, v)
				items = append(items, hex64(v))
			}
			arrays[key] = values
			raw[key] = items
		}
	}
	return raw, scalars, arrays
}

func normalizeRegisterName(name string) string {
	return strings.ToLower(name)
}

func ptraceSyscallRegisterInfo(arch string, scalars map[string]uint64, arrays map[string][]uint64) map[string]any {
	info := map[string]any{}
	var nr uint64
	var nrOK bool
	var retval uint64
	var retvalOK bool
	var args []uint64
	var pc, sp uint64
	var pcOK, spOK bool

	scalar := func(name string) (uint64, bool) { v, ok := scalars[name]; return v, ok }
	array := func(name string, idx int) (uint64, bool) {
		values, ok := arrays[name]
		if !ok || idx < 0 || idx >= len(values) {
			return 0, false
		}
		return values[idx], true
	}

	switch arch {
	case "amd64":
		nr, nrOK = scalar("orig_rax")
		retval, retvalOK = scalar("rax")
		args = registerArgs(scalars, "rdi", "rsi", "rdx", "r10", "r8", "r9")
		pc, pcOK = scalar("rip")
		sp, spOK = scalar("rsp")
	case "386":
		nr, nrOK = scalar("orig_eax")
		retval, retvalOK = scalar("eax")
		args = registerArgs(scalars, "ebx", "ecx", "edx", "esi", "edi", "ebp")
		pc, pcOK = scalar("eip")
		sp, spOK = scalar("esp")
	case "arm64":
		nr, nrOK = array("regs", 8)
		retval, retvalOK = array("regs", 0)
		for i := 0; i < 6; i++ {
			if v, ok := array("regs", i); ok {
				args = append(args, v)
			}
		}
		pc, pcOK = scalar("pc")
		sp, spOK = scalar("sp")
	case "arm":
		nr, nrOK = array("uregs", 7)
		retval, retvalOK = array("uregs", 0)
		for i := 0; i < 6; i++ {
			if v, ok := array("uregs", i); ok {
				args = append(args, v)
			}
		}
		pc, pcOK = array("uregs", 15)
		sp, spOK = array("uregs", 13)
	case "riscv64":
		nr, nrOK = scalar("a7")
		retval, retvalOK = scalar("a0")
		args = registerArgs(scalars, "a0", "a1", "a2", "a3", "a4", "a5")
		pc, pcOK = scalar("pc")
		sp, spOK = scalar("sp")
	}

	if nrOK {
		info["nr"] = nr
		info["nr_hex"] = hex64(nr)
		if name, ok := linuxSyscallName(arch, nr); ok {
			info["name"] = name
		} else {
			info["name"] = fmt.Sprintf("sys_%d", nr)
		}
	}
	if retvalOK {
		info["retval"] = hex64(retval)
		info["retval_signed"] = fmt.Sprintf("%d", int64(retval))
		if name, ok := negativeErrno(retval); ok {
			info["retval_errno"] = name
		}
	}
	if len(args) != 0 {
		encoded := make([]string, 0, len(args))
		for _, arg := range args {
			encoded = append(encoded, hex64(arg))
		}
		info["args"] = encoded
	}
	if pcOK {
		info["pc"] = hex64(pc)
	}
	if spOK {
		info["sp"] = hex64(sp)
	}
	return info
}

func registerArgs(scalars map[string]uint64, names ...string) []uint64 {
	args := make([]uint64, 0, len(names))
	for _, name := range names {
		if v, ok := scalars[name]; ok {
			args = append(args, v)
		}
	}
	return args
}

func negativeErrno(retval uint64) (string, bool) {
	if retval < ^uint64(0)-4094 {
		return "", false
	}
	errno := unix.Errno(-int64(retval))
	return errnoName(errno), true
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
	err := platformPrctl(int(args.Option), uintptr(args.Arg2), uintptr(args.Arg3), uintptr(args.Arg4), uintptr(args.Arg5))
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
		"utime_usec": int64(rusage.Utime.Sec)*1_000_000 + int64(rusage.Utime.Usec),
		"stime_usec": int64(rusage.Stime.Sec)*1_000_000 + int64(rusage.Stime.Usec),
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
