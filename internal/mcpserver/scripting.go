package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultEvalTimeoutMS  = 5000
	maxEvalTimeoutMS      = 12 * 60 * 60 * 1000
	defaultEvalLogEntries = 200
	maxEvalLogEntries     = 1000
	defaultMaxResultBytes = 1 << 20
)

type evalArgs struct {
	Script         string         `json:"script"`
	Args           map[string]any `json:"args"`
	TimeoutMS      Uint32         `json:"timeout_ms"`
	MaxLogEntries  Uint32         `json:"max_log_entries"`
	MaxResultBytes Uint64         `json:"max_result_bytes"`
}

type scriptLogEntry struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type evalResponse struct {
	OK             bool             `json:"ok"`
	Result         any              `json:"result,omitempty"`
	Logs           []scriptLogEntry `json:"logs,omitempty"`
	DroppedLogs    int              `json:"dropped_logs,omitempty"`
	Operations     int              `json:"operations"`
	DurationMS     int64            `json:"duration_ms"`
	TimeoutMS      uint32           `json:"timeout_ms"`
	MaxResultBytes uint64           `json:"max_result_bytes"`
	Error          string           `json:"error,omitempty"`
}

type scriptLogSink struct {
	entries []scriptLogEntry
	limit   int
	dropped int
}

type scriptEnv struct {
	app            *App
	ctx            context.Context
	vm             *goja.Runtime
	logs           *scriptLogSink
	ops            int
	lockedOSThread bool
}

func (a *App) handleEval(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args evalArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
	return a.runEval(ctx, args)
}

func (a *App) runEval(ctx context.Context, args evalArgs) (*mcp.CallToolResult, error) {
	if strings.TrimSpace(args.Script) == "" {
		return toolError(errors.New("script is required"))
	}
	timeoutMS := uint32(args.TimeoutMS)
	if timeoutMS == 0 {
		timeoutMS = defaultEvalTimeoutMS
	}
	if timeoutMS > maxEvalTimeoutMS {
		return toolError(fmt.Errorf("timeout_ms %d exceeds maximum %d", timeoutMS, maxEvalTimeoutMS))
	}
	logLimit := uint32(args.MaxLogEntries)
	if logLimit == 0 {
		logLimit = defaultEvalLogEntries
	}
	if logLimit > maxEvalLogEntries {
		return toolError(fmt.Errorf("max_log_entries %d exceeds maximum %d", logLimit, maxEvalLogEntries))
	}
	maxResultBytes := uint64(args.MaxResultBytes)
	if maxResultBytes == 0 {
		maxResultBytes = a.config.MaxReadBytes
		if maxResultBytes == 0 {
			maxResultBytes = defaultMaxResultBytes
		}
	}

	vm := goja.New()
	vm.SetMaxCallStackSize(2048)
	logs := &scriptLogSink{limit: int(logLimit)}
	env := &scriptEnv{app: a, ctx: ctx, vm: vm, logs: logs}
	defer env.unlockOSThread()

	if err := vm.Set("args", jsonSafeValue(args.Args)); err != nil {
		return toolError(err)
	}
	if err := vm.Set("console", env.consoleObject()); err != nil {
		return toolError(err)
	}
	if err := vm.Set("print", env.logFunc("log")); err != nil {
		return toolError(err)
	}
	uapi := env.uapiObject()
	if err := vm.Set("uapi", uapi); err != nil {
		return toolError(err)
	}
	if err := vm.Set("sys", uapi); err != nil {
		return toolError(err)
	}
	if err := vm.Set("os", env.osObject()); err != nil {
		return toolError(err)
	}
	if err := vm.Set("io", env.ioObject()); err != nil {
		return toolError(err)
	}
	timeoutErr := fmt.Errorf("script exceeded timeout_ms=%d", timeoutMS)
	timer := time.AfterFunc(time.Duration(timeoutMS)*time.Millisecond, func() { vm.Interrupt(timeoutErr) })
	stopContextInterrupt := context.AfterFunc(ctx, func() { vm.Interrupt(ctx.Err()) })
	defer stopContextInterrupt()
	defer timer.Stop()

	started := time.Now()
	value, runErr := vm.RunScript("mcp-uapi-eval.js", wrapEvalScript(args.Script))
	durationMS := time.Since(started).Milliseconds()

	if runErr != nil {
		return evalToolResult(evalResponse{OK: false, Logs: logs.entries, DroppedLogs: logs.dropped, Operations: env.ops, DurationMS: durationMS, TimeoutMS: timeoutMS, MaxResultBytes: maxResultBytes, Error: scriptErrorString(runErr)}, true)
	}

	result := normalizeJSValue(value)
	if err := ensureJSONSize(result, maxResultBytes); err != nil {
		return evalToolResult(evalResponse{OK: false, Logs: logs.entries, DroppedLogs: logs.dropped, Operations: env.ops, DurationMS: durationMS, TimeoutMS: timeoutMS, MaxResultBytes: maxResultBytes, Error: err.Error()}, true)
	}
	return evalToolResult(evalResponse{OK: true, Result: result, Logs: logs.entries, DroppedLogs: logs.dropped, Operations: env.ops, DurationMS: durationMS, TimeoutMS: timeoutMS, MaxResultBytes: maxResultBytes}, false)
}

func wrapEvalScript(script string) string {
	return "(function(){\n\"use strict\";\n" + script + "\n})()"
}

func evalToolResult(response evalResponse, isError bool) (*mcp.CallToolResult, error) {
	result, err := jsonResult(response)
	if err != nil {
		return nil, err
	}
	result.IsError = isError
	return result, nil
}

func (s *scriptLogSink) add(level string, text string) {
	if len(s.entries) >= s.limit {
		s.dropped++
		return
	}
	s.entries = append(s.entries, scriptLogEntry{Level: level, Text: text})
}

func (e *scriptEnv) consoleObject() *goja.Object {
	obj := e.vm.NewObject()
	_ = obj.Set("log", e.logFunc("log"))
	_ = obj.Set("info", e.logFunc("info"))
	_ = obj.Set("warn", e.logFunc("warn"))
	_ = obj.Set("error", e.logFunc("error"))
	return obj
}

func (e *scriptEnv) logFunc(level string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, arg := range call.Arguments {
			parts = append(parts, stringifyJSValue(e.vm, arg))
		}
		e.logs.add(level, strings.Join(parts, " "))
		return goja.Undefined()
	}
}

func (e *scriptEnv) uapiObject() *goja.Object {
	obj := e.vm.NewObject()
	_ = obj.Set("state", func() any { return e.app.stateSnapshot() })
	_ = obj.Set("hex", func(call goja.FunctionCall) goja.Value {
		value, err := jsUint64(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		width := 0
		if !goja.IsUndefined(call.Argument(1)) {
			parsed, err := jsUint64(call.Argument(1))
			if err != nil {
				panic(e.vm.NewGoError(err))
			}
			width = int(parsed)
		}
		if width <= 0 {
			return e.vm.ToValue(fmt.Sprintf("0x%x", value))
		}
		return e.vm.ToValue(fmt.Sprintf("0x%0*x", width, value))
	})
	for jsName, toolName := range scriptToolAliases() {
		_ = obj.Set(jsName, e.toolFunc(toolName))
	}
	e.addScriptUnixExtensions(obj)
	e.addScriptEBPFExtensions(obj)
	return obj
}

func (e *scriptEnv) toolFunc(toolName string) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		value, err := e.callTool(toolName, exportArgument(call.Argument(0)))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return e.vm.ToValue(value)
	}
}

func (e *scriptEnv) callTool(toolName string, args any) (any, error) {
	handler := e.app.handlerForTool(toolName)
	if handler == nil {
		return nil, fmt.Errorf("tool %q is not available inside eval", toolName)
	}
	if isPtraceTool(toolName) {
		e.lockOSThread()
	}
	e.ops++
	request := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: toolName, Arguments: jsonSafeValue(args)}}
	result, err := handler(e.ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	if result.IsError {
		return nil, errors.New(toolResultText(result))
	}
	if result.StructuredContent != nil {
		return jsonSafeValue(result.StructuredContent), nil
	}
	text := toolResultText(result)
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err == nil {
		return decoded, nil
	}
	return text, nil
}

func isPtraceTool(toolName string) bool {
	switch toolName {
	case "uapi_ptrace_attach", "uapi_ptrace_detach", "uapi_ptrace_read", "uapi_ptrace_write", "uapi_ptrace_cont", "uapi_ptrace_syscall", "uapi_ptrace_get_regs", "uapi_ptrace_set_options":
		return true
	default:
		return false
	}
}

func (e *scriptEnv) lockOSThread() {
	if e.lockedOSThread {
		return
	}
	runtime.LockOSThread()
	e.lockedOSThread = true
}

func (e *scriptEnv) unlockOSThread() {
	if !e.lockedOSThread {
		return
	}
	runtime.UnlockOSThread()
	e.lockedOSThread = false
}

func scriptToolAliases() map[string]string {
	return map[string]string{
		"capabilities":     "uapi_capabilities",
		"constants":        "uapi_constants",
		"errno":            "uapi_errno",
		"uname":            "uapi_uname",
		"getpid":           "uapi_getpid",
		"open":             "uapi_open",
		"close":            "uapi_close",
		"read":             "uapi_read",
		"write":            "uapi_write",
		"pread":            "uapi_pread",
		"pwrite":           "uapi_pwrite",
		"lseek":            "uapi_lseek",
		"fstat":            "uapi_fstat",
		"stat":             "uapi_stat",
		"readlink":         "uapi_readlink",
		"bufferAlloc":      "uapi_buffer_alloc",
		"bufferFree":       "uapi_buffer_free",
		"bufferInfo":       "uapi_buffer_info",
		"bufferWrite":      "uapi_buffer_write",
		"bufferRead":       "uapi_buffer_read",
		"mmap":             "uapi_mmap",
		"munmap":           "uapi_munmap",
		"mprotect":         "uapi_mprotect",
		"msync":            "uapi_msync",
		"madvise":          "uapi_madvise",
		"memRead":          "uapi_mem_read",
		"memWrite":         "uapi_mem_write",
		"socket":           "uapi_socket",
		"socketpair":       "uapi_socketpair",
		"bind":             "uapi_bind",
		"connect":          "uapi_connect",
		"listen":           "uapi_listen",
		"accept":           "uapi_accept",
		"sendto":           "uapi_sendto",
		"recvfrom":         "uapi_recvfrom",
		"getsockname":      "uapi_getsockname",
		"getpeername":      "uapi_getpeername",
		"setsockoptInt":    "uapi_setsockopt_int",
		"getsockoptInt":    "uapi_getsockopt_int",
		"shutdown":         "uapi_shutdown",
		"poll":             "uapi_poll",
		"epollCreate":      "uapi_epoll_create",
		"epollCtl":         "uapi_epoll_ctl",
		"epollWait":        "uapi_epoll_wait",
		"kill":             "uapi_kill",
		"wait4":            "uapi_wait4",
		"ptraceAttach":     "uapi_ptrace_attach",
		"ptraceDetach":     "uapi_ptrace_detach",
		"ptraceRead":       "uapi_ptrace_read",
		"ptraceWrite":      "uapi_ptrace_write",
		"ptraceCont":       "uapi_ptrace_cont",
		"ptraceSyscall":    "uapi_ptrace_syscall",
		"ptraceGetRegs":    "uapi_ptrace_get_regs",
		"ptraceSetOptions": "uapi_ptrace_set_options",
		"ioctl":            "uapi_ioctl",
		"prctl":            "uapi_prctl",
	}
}

func scriptWrapperNames() []string {
	aliases := scriptToolAliases()
	names := make([]string, 0, len(aliases)+2+len(scriptUnixExtensionNames()))
	for name := range aliases {
		names = append(names, name)
	}
	names = append(names, "state", "hex")
	names = append(names, scriptUnixExtensionNames()...)
	names = append(names, scriptEBPFExtensionNames()...)
	sort.Strings(names)
	return names
}

func isMissingJSValue(value goja.Value) bool {
	return value == nil || goja.IsUndefined(value) || goja.IsNull(value)
}

func toolResultText(result *mcp.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := content.(mcp.TextContent); ok {
			return text.Text
		}
	}
	return "tool returned an error"
}

func stringifyJSValue(vm *goja.Runtime, value goja.Value) string {
	if goja.IsUndefined(value) {
		return "undefined"
	}
	if goja.IsNull(value) {
		return "null"
	}
	if goja.IsString(value) {
		return value.String()
	}
	if object, ok := value.(*goja.Object); ok {
		jsonObject := vm.Get("JSON").ToObject(vm)
		stringify, ok := goja.AssertFunction(jsonObject.Get("stringify"))
		if ok {
			if encoded, err := stringify(jsonObject, object); err == nil && !goja.IsUndefined(encoded) {
				return encoded.String()
			}
		}
	}
	return value.String()
}

func exportArgument(value goja.Value) any {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return map[string]any{}
	}
	return jsonSafeValue(value.Export())
}

func normalizeJSValue(value goja.Value) any {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return nil
	}
	return jsonSafeValue(value.Export())
}

func jsonSafeValue(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case bool, string, float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return value
	case *big.Int:
		if v == nil {
			return nil
		}
		return v.String()
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = jsonSafeValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = jsonSafeValue(item)
		}
		return out
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	default:
		data, err := json.Marshal(value)
		if err != nil {
			return value
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return value
		}
		return jsonSafeValue(decoded)
	}
}

func ensureJSONSize(value any, maxBytes uint64) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("script result is not JSON-serializable: %w", err)
	}
	if uint64(len(data)) > maxBytes {
		return fmt.Errorf("script result is %d bytes, exceeding max_result_bytes %d", len(data), maxBytes)
	}
	return nil
}

func scriptErrorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func jsUint64(value goja.Value) (uint64, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return 0, errors.New("value is required")
	}
	if goja.IsString(value) {
		return strconv.ParseUint(strings.TrimSpace(value.String()), 0, 64)
	}
	exported := value.Export()
	switch v := exported.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	case float64:
		if v < 0 || math.Trunc(v) != v || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, fmt.Errorf("invalid unsigned integer %v", v)
		}
		return uint64(v), nil
	case *big.Int:
		if v == nil || v.Sign() < 0 || v.BitLen() > 64 {
			return 0, fmt.Errorf("invalid unsigned integer %v", v)
		}
		return v.Uint64(), nil
	default:
		return strconv.ParseUint(strings.TrimSpace(fmt.Sprint(v)), 0, 64)
	}
}
