package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/mark3labs/mcp-go/mcp"
)

const (
	defaultEvalTimeoutMS    = 5000
	maxEvalTimeoutMS        = 12 * 60 * 60 * 1000
	defaultEvalLogEntries   = 200
	maxEvalLogEntries       = 1000
	defaultMaxResultBytes   = 1 << 20
	maxScriptGeneratedBytes = 1 << 20
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
	app  *App
	ctx  context.Context
	vm   *goja.Runtime
	logs *scriptLogSink
	ops  int
}

func (a *App) handleEval(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args evalArgs
	if err := bind(request, &args); err != nil {
		return toolError(err)
	}
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
	if err := vm.Set("rng", env.rngNamespace()); err != nil {
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
	_ = obj.Set("callTool", func(call goja.FunctionCall) goja.Value {
		toolName := call.Argument(0).String()
		args := exportArgument(call.Argument(1))
		value, err := e.callTool(toolName, args)
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return e.vm.ToValue(value)
	})
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

func scriptToolAliases() map[string]string {
	return map[string]string{
		"capabilities":  "uapi_capabilities",
		"constants":     "uapi_constants",
		"errno":         "uapi_errno",
		"uname":         "uapi_uname",
		"getpid":        "uapi_getpid",
		"open":          "uapi_open",
		"close":         "uapi_close",
		"read":          "uapi_read",
		"write":         "uapi_write",
		"pread":         "uapi_pread",
		"pwrite":        "uapi_pwrite",
		"lseek":         "uapi_lseek",
		"fstat":         "uapi_fstat",
		"stat":          "uapi_stat",
		"readlink":      "uapi_readlink",
		"bufferAlloc":   "uapi_buffer_alloc",
		"bufferFree":    "uapi_buffer_free",
		"bufferInfo":    "uapi_buffer_info",
		"bufferWrite":   "uapi_buffer_write",
		"bufferRead":    "uapi_buffer_read",
		"mmap":          "uapi_mmap",
		"munmap":        "uapi_munmap",
		"mprotect":      "uapi_mprotect",
		"msync":         "uapi_msync",
		"madvise":       "uapi_madvise",
		"memRead":       "uapi_mem_read",
		"memWrite":      "uapi_mem_write",
		"socket":        "uapi_socket",
		"socketpair":    "uapi_socketpair",
		"bind":          "uapi_bind",
		"connect":       "uapi_connect",
		"listen":        "uapi_listen",
		"accept":        "uapi_accept",
		"sendto":        "uapi_sendto",
		"recvfrom":      "uapi_recvfrom",
		"getsockname":   "uapi_getsockname",
		"getpeername":   "uapi_getpeername",
		"setsockoptInt": "uapi_setsockopt_int",
		"getsockoptInt": "uapi_getsockopt_int",
		"shutdown":      "uapi_shutdown",
		"poll":          "uapi_poll",
		"epollCreate":   "uapi_epoll_create",
		"epollCtl":      "uapi_epoll_ctl",
		"epollWait":     "uapi_epoll_wait",
		"kill":          "uapi_kill",
		"wait4":         "uapi_wait4",
		"ptraceAttach":  "uapi_ptrace_attach",
		"ptraceDetach":  "uapi_ptrace_detach",
		"ptraceRead":    "uapi_ptrace_read",
		"ptraceWrite":   "uapi_ptrace_write",
		"ptraceCont":    "uapi_ptrace_cont",
		"ptraceSyscall": "uapi_ptrace_syscall",
		"ioctl":         "uapi_ioctl",
		"prctl":         "uapi_prctl",
	}
}

func scriptWrapperNames() []string {
	aliases := scriptToolAliases()
	names := make([]string, 0, len(aliases)+3)
	for name := range aliases {
		names = append(names, name)
	}
	names = append(names, "callTool", "state", "hex")
	return names
}

type scriptRNG struct {
	seed          string
	originalSeed  string
	iterationMode bool
	iteration     uint64
	state         uint64
}

func (e *scriptEnv) rngNamespace() *goja.Object {
	obj := e.vm.NewObject()
	_ = obj.Set("create", func(call goja.FunctionCall) goja.Value {
		rngObj, err := e.createRNG(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return rngObj
	})
	_ = obj.Set("local", func(call goja.FunctionCall) goja.Value {
		seed := ""
		if !goja.IsUndefined(call.Argument(0)) {
			seed = call.Argument(0).String()
		}
		rngObj, err := e.rngObject(newScriptRNG(seed, "", 0, false))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return rngObj
	})
	_ = obj.Set("deriveIterationSeed", func(call goja.FunctionCall) goja.Value {
		iteration, err := jsUint64(call.Argument(1))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return e.vm.ToValue(deriveIterationSeed(call.Argument(0).String(), iteration))
	})
	return obj
}

func (e *scriptEnv) createRNG(value goja.Value) (*goja.Object, error) {
	seed := ""
	originalSeed := ""
	var iteration uint64
	iterationMode := false
	if !goja.IsUndefined(value) && !goja.IsNull(value) {
		if goja.IsString(value) {
			seed = value.String()
		} else if object := value.ToObject(e.vm); object != nil {
			if v := object.Get("seed"); !isMissingJSValue(v) {
				seed = v.String()
			}
			if v := object.Get("originalSeed"); !isMissingJSValue(v) {
				originalSeed = v.String()
			}
			if v := object.Get("original_seed"); !isMissingJSValue(v) {
				originalSeed = v.String()
			}
			if v := object.Get("iteration"); !isMissingJSValue(v) {
				parsed, err := jsUint64(v)
				if err != nil {
					return nil, err
				}
				iteration = parsed
				iterationMode = true
			}
		}
	}
	if iterationMode {
		base := originalSeed
		if base == "" {
			base = seed
		}
		if base == "" {
			return nil, errors.New("rng.create iteration mode requires seed or originalSeed")
		}
		seed = deriveIterationSeed(base, iteration)
		originalSeed = base
	}
	return e.rngObject(newScriptRNG(seed, originalSeed, iteration, iterationMode))
}

func newScriptRNG(seed, originalSeed string, iteration uint64, iterationMode bool) *scriptRNG {
	if seed == "" {
		seed = "00000000-0000-4000-8000-000000000000"
	}
	hash := sha256.Sum256([]byte(seed))
	state := binary.LittleEndian.Uint64(hash[:8])
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	return &scriptRNG{seed: seed, originalSeed: originalSeed, iteration: iteration, iterationMode: iterationMode, state: state}
}

func (r *scriptRNG) next() uint64 {
	x := r.state
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	r.state = x
	return x * 2685821657736338717
}

func (e *scriptEnv) rngObject(r *scriptRNG) (*goja.Object, error) {
	obj := e.vm.NewObject()
	_ = obj.Set("info", func() map[string]any { return r.info() })
	_ = obj.Set("seed", func(seed string) map[string]any {
		*r = *newScriptRNG(seed, "", 0, false)
		return r.info()
	})
	_ = obj.Set("seedForIteration", func(call goja.FunctionCall) goja.Value {
		iteration, err := jsUint64(call.Argument(1))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		base := call.Argument(0).String()
		*r = *newScriptRNG(deriveIterationSeed(base, iteration), base, iteration, true)
		return e.vm.ToValue(r.info())
	})
	_ = obj.Set("seekIteration", func(call goja.FunctionCall) goja.Value {
		iteration, err := jsUint64(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		base := r.originalSeed
		if base == "" {
			base = r.seed
		}
		*r = *newScriptRNG(deriveIterationSeed(base, iteration), base, iteration, true)
		return e.vm.ToValue(r.info())
	})
	_ = obj.Set("uint32", func() uint32 { return uint32(r.next() >> 32) })
	_ = obj.Set("int32", func() int32 { return int32(r.next() >> 32) })
	_ = obj.Set("double", func() float64 { return float64(r.next()>>11) * (1.0 / (1 << 53)) })
	_ = obj.Set("float", func() float32 { return float32(float64(r.next()>>40) * (1.0 / (1 << 24))) })
	_ = obj.Set("uint64", func() string { return hex64(r.next()) })
	_ = obj.Set("uint64Decimal", func() string { return strconv.FormatUint(r.next(), 10) })
	_ = obj.Set("int64", func() string { return strconv.FormatInt(int64(r.next()), 10) })
	_ = obj.Set("bytes", func(call goja.FunctionCall) goja.Value {
		length, err := jsUint64(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		if length > maxScriptGeneratedBytes {
			panic(e.vm.NewGoError(fmt.Errorf("length %d exceeds maximum %d", length, maxScriptGeneratedBytes)))
		}
		encoding := "hex"
		if !goja.IsUndefined(call.Argument(1)) {
			encoding = call.Argument(1).String()
		}
		data := make([]byte, int(length))
		for i := 0; i < len(data); i += 8 {
			value := r.next()
			for j := 0; j < 8 && i+j < len(data); j++ {
				data[i+j] = byte(value >> (8 * j))
			}
		}
		switch encoding {
		case "hex":
			return e.vm.ToValue(hex.EncodeToString(data))
		case "base64":
			return e.vm.ToValue(base64.StdEncoding.EncodeToString(data))
		case "array":
			values := make([]int, len(data))
			for i, b := range data {
				values[i] = int(b)
			}
			return e.vm.ToValue(values)
		default:
			panic(e.vm.NewGoError(fmt.Errorf("unsupported bytes encoding %q", encoding)))
		}
	})
	_ = obj.Set("range", func(call goja.FunctionCall) goja.Value {
		min, err := jsUint64(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		max, err := jsUint64(call.Argument(1))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		if max <= min {
			panic(e.vm.NewGoError(errors.New("range max must be greater than min")))
		}
		return e.vm.ToValue(float64(min + r.next()%(max-min)))
	})
	_ = obj.Set("bool", func(call goja.FunctionCall) goja.Value {
		probability := 0.5
		if !goja.IsUndefined(call.Argument(0)) {
			probability = call.Argument(0).ToFloat()
		}
		if probability < 0 || probability > 1 || math.IsNaN(probability) {
			panic(e.vm.NewGoError(errors.New("probability must be between 0 and 1")))
		}
		return e.vm.ToValue((float64(r.next()>>11) * (1.0 / (1 << 53))) < probability)
	})
	_ = obj.Set("choice", func(call goja.FunctionCall) goja.Value {
		array := call.Argument(0).ToObject(e.vm)
		length := int(array.Get("length").ToInteger())
		if length <= 0 {
			panic(e.vm.NewGoError(errors.New("choice requires a non-empty array")))
		}
		return array.Get(strconv.Itoa(int(r.next() % uint64(length))))
	})
	return obj, nil
}

func (r *scriptRNG) info() map[string]any {
	info := map[string]any{"backend": "local", "seed": r.seed, "iteration_mode": r.iterationMode, "iteration": r.iteration}
	if r.originalSeed != "" {
		info["original_seed"] = r.originalSeed
	}
	return info
}

func deriveIterationSeed(seed string, iteration uint64) string {
	h := sha256.New()
	_, _ = h.Write([]byte(seed))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], iteration)
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
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
