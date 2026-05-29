package mcpserver

const Version = "0.1.0"

type CapabilityDocument struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Purpose         string              `json:"purpose"`
	Transports      []string            `json:"transports"`
	ClientBootstrap ClientBootstrapInfo `json:"client_bootstrap"`
	SafetyModel     []string            `json:"safety_model"`
	PrimitiveGroups []PrimitiveGroup    `json:"primitive_groups"`
	Constants       map[string]any      `json:"constants"`
	Tools           []ToolSummary       `json:"tools"`
	Resources       []string            `json:"resources"`
	Prompts         []string            `json:"prompts"`
	ScriptingAPI    ScriptingAPIInfo    `json:"scripting_api"`
	Implementation  []string            `json:"implementation_notes"`
}

type ClientBootstrapInfo struct {
	RecommendedFirstCalls []string `json:"recommended_first_calls"`
	ScriptingAPIResource  string   `json:"scripting_api_resource"`
	ScriptingPrompt       string   `json:"scripting_prompt"`
	SafeEvalProbe         string   `json:"safe_eval_probe"`
	Notes                 []string `json:"notes"`
}

type PrimitiveGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Primitives  []string `json:"primitives"`
}

type ToolSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ReadOnly    bool   `json:"read_only"`
	Destructive bool   `json:"destructive"`
}

type ScriptingAPIInfo struct {
	Tool           string             `json:"tool"`
	Resource       string             `json:"resource"`
	Engine         string             `json:"engine"`
	ExecutionModel string             `json:"execution_model"`
	Globals        []ScriptGlobalInfo `json:"globals"`
	UAPIWrappers   []string           `json:"uapi_wrappers"`
	RNG            ScriptingRNGInfo   `json:"rng"`
	Limits         map[string]any     `json:"limits"`
	ResultShape    map[string]string  `json:"result_shape"`
	Examples       []ScriptingExample `json:"examples"`
}

type ScriptGlobalInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ScriptingRNGInfo struct {
	Source       string   `json:"source"`
	Default      string   `json:"default_backend"`
	Factories    []string `json:"factories"`
	Methods      []string `json:"methods"`
	Uint64Policy string   `json:"uint64_policy"`
}

type ScriptingExample struct {
	Name   string `json:"name"`
	Script string `json:"script"`
}

func Capabilities() CapabilityDocument {
	return CapabilityDocument{
		Name:       "mcp-uapi",
		Version:    Version,
		Purpose:    "Expose Linux user-mode APIs from golang.org/x/sys/unix as agent-friendly MCP primitives for embedded testing, reconnaissance, fuzzing, and proof-of-concept development.",
		Transports: []string{"stdio", "streamable-http"},
		ClientBootstrap: ClientBootstrapInfo{
			RecommendedFirstCalls: []string{"uapi_capabilities", "uapi_constants", "read resource uapi://scripting-api before eval", "read resource uapi://state when reusing handles"},
			ScriptingAPIResource:  "uapi://scripting-api",
			ScriptingPrompt:       "uapi_eval_quickstart",
			SafeEvalProbe:         `const caps = uapi.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, uname: uapi.uname(), openFlags: uapi.constants({group:"open_flags"}).constants};`,
			Notes: []string{
				"All handles returned by tools are process-local to this MCP server instance.",
				"Syscall errno results are returned as structured data with ok=false instead of MCP tool errors.",
				"Use string constants such as O_RDWR|O_CREAT, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, PROT_READ|PROT_WRITE, and EPOLLIN where schemas accept integer|string.",
			},
		},
		SafetyModel: []string{
			"The server exposes direct Linux syscalls. Run it only where the MCP client is trusted to create files, open sockets, signal processes, ptrace child/allowed processes, and invoke ioctls.",
			"Raw integer FD access is disabled by default; use managed handles unless the server is started with --allow-raw-fd.",
			"ptrace, ioctl, prctl, kill, writes, mmap mutations, socket sends, and FD close operations are marked destructive.",
			"Most APIs are synchronous. Use nonblocking flags, poll/epoll tools, and eval timeouts for robust agent loops.",
		},
		PrimitiveGroups: []PrimitiveGroup{
			{"metadata", "Discover server capabilities, constants, errno names, kernel identity, and live managed state.", []string{"uapi_capabilities", "uapi_constants", "uapi_errno", "uapi_uname", "uapi_getpid", "uapi://state"}},
			{"files and descriptors", "Open, close, read, write, seek, stat, and inspect Linux file descriptors through managed handles.", []string{"open", "close", "read", "write", "pread", "pwrite", "lseek", "fstat", "stat", "readlink"}},
			{"buffers and pointers", "Create bounded user-space buffers for ioctl payloads, send/write sources, and deterministic data shaping.", []string{"buffer_alloc", "buffer_write", "buffer_read", "buffer_info", "buffer_free"}},
			{"memory mappings", "Create anonymous or file-backed mappings and mutate or synchronize them with mmap-family APIs.", []string{"mmap", "munmap", "mprotect", "msync", "madvise", "mem_read", "mem_write"}},
			{"networking", "Create sockets, socketpairs, bind/connect/listen/accept, exchange datagrams/streams, and tune integer socket options.", []string{"socket", "socketpair", "bind", "connect", "listen", "accept", "sendto", "recvfrom", "getsockname", "getpeername", "setsockopt_int", "getsockopt_int", "shutdown"}},
			{"readiness", "Drive blocking-sensitive clients with poll and epoll primitives.", []string{"poll", "epoll_create", "epoll_ctl", "epoll_wait"}},
			{"process control", "Signal, wait, prctl, ptrace attach/detach, and read/write traced process memory.", []string{"kill", "wait4", "prctl", "ptrace_attach", "ptrace_read", "ptrace_write", "ptrace_cont", "ptrace_syscall", "ptrace_detach"}},
			{"ioctl", "Invoke arbitrary ioctl requests with either integer arguments or managed buffer pointers.", []string{"ioctl", "buffer_alloc", "buffer_read", "buffer_write"}},
			{"JavaScript scripting", "Compose multi-step syscall workflows in one eval call with captured logs and deterministic RNG.", []string{"eval", "uapi.* wrappers", "rng.local"}},
		},
		Constants:      constantCatalog(),
		Tools:          toolSummaries(),
		Resources:      []string{"uapi://capabilities", "uapi://api-reference", "uapi://scripting-api", "uapi://state"},
		Prompts:        []string{"uapi_recon_quickstart", "uapi_eval_quickstart", "uapi_ptrace_memory_probe", "uapi_socket_fuzzing"},
		ScriptingAPI:   scriptingAPIInfo(),
		Implementation: []string{"The MCP layer keeps FD, buffer, and mmap lifetime in process-local registries guarded by a mutex.", "The syscall layer uses golang.org/x/sys/unix directly and treats Unix errno as normal structured results.", "Goja eval creates a fresh runtime per call and invokes the same MCP handlers used by remote clients.", "The project is organized so additional syscall families can be added by registering schemas, handlers, constants, and scripting aliases without changing transport code."},
	}
}

func scriptingAPIInfo() ScriptingAPIInfo {
	return ScriptingAPIInfo{
		Tool:           "eval",
		Resource:       "uapi://scripting-api",
		Engine:         "Goja (github.com/dop251/goja)",
		ExecutionModel: "Each eval call runs a fresh synchronous JavaScript runtime inside a function body; use return for JSON results and console.* for captured logs.",
		Globals:        []ScriptGlobalInfo{{"args", "Caller-provided JSON object."}, {"console", "Captured log/info/warn/error functions returned in the eval response."}, {"print", "Alias for console.log."}, {"uapi", "Synchronous wrappers around MCP tools plus state() and hex()."}, {"sys", "Alias for uapi."}, {"rng", "Deterministic local RNG for repeatable payload generation."}},
		UAPIWrappers:   scriptWrapperNames(),
		RNG: ScriptingRNGInfo{
			Source:       "Local xorshift64* stream seeded from SHA-256 of a string or derived iteration UUID.",
			Default:      "local",
			Factories:    []string{"rng.local(seed)", "rng.create({seed, originalSeed, iteration})", "rng.deriveIterationSeed(seed, iteration)"},
			Methods:      []string{"info", "seed", "seedForIteration", "seekIteration", "uint32", "uint64", "uint64Decimal", "int32", "int64", "float", "double", "bytes", "range", "bool", "choice"},
			Uint64Policy: "uint64() returns a hex string and uint64Decimal() returns a decimal string to avoid JavaScript number precision loss.",
		},
		Limits:      map[string]any{"default_timeout_ms": defaultEvalTimeoutMS, "max_timeout_ms": maxEvalTimeoutMS, "default_max_log_entries": defaultEvalLogEntries, "max_log_entries": maxEvalLogEntries, "max_generated_bytes": maxScriptGeneratedBytes},
		ResultShape: map[string]string{"ok": "true on successful script execution", "result": "JSON value returned by the script", "logs": "captured console entries", "operations": "number of uapi tool wrapper calls", "error": "script/tool error string when ok=false"},
		Examples: []ScriptingExample{
			{"safe_bootstrap", `const caps = uapi.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, uname: uapi.uname()};`},
			{"socketpair_roundtrip", `const pair = uapi.socketpair({type:"SOCK_STREAM|SOCK_CLOEXEC"}); uapi.write({handle: pair.handles[0], data_utf8:"ping"}); return uapi.read({handle: pair.handles[1], length:4, encoding:"utf8"});`},
			{"deterministic_payload", `const r = rng.local("550e8400-e29b-41d4-a716-446655440000"); return {u64: r.uint64(), payload: r.bytes(16, "hex")};`},
		},
	}
}

func constantCatalog() map[string]any {
	return map[string]any{
		"socket":     groupConstants("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET", "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_SEQPACKET", "SOCK_NONBLOCK", "SOCK_CLOEXEC", "IPPROTO_TCP", "IPPROTO_UDP", "SOL_SOCKET", "SO_REUSEADDR", "SO_REUSEPORT", "SO_ERROR"),
		"open_flags": groupConstants("O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_SYNC"),
		"seek":       groupConstants("SEEK_SET", "SEEK_CUR", "SEEK_END"),
		"mmap":       groupConstants("PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC", "MAP_SHARED", "MAP_PRIVATE", "MAP_ANON", "MAP_ANONYMOUS", "MS_SYNC", "MS_ASYNC", "MADV_NORMAL", "MADV_RANDOM", "MADV_DONTNEED"),
		"poll":       groupConstants("POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL"),
		"epoll":      groupConstants("EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP", "EPOLLRDHUP", "EPOLLET", "EPOLLONESHOT", "EPOLL_CLOEXEC", "EPOLL_CTL_ADD", "EPOLL_CTL_MOD", "EPOLL_CTL_DEL"),
		"signal":     groupConstants("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL", "SIGCHLD", "SIGTRAP"),
		"wait":       groupConstants("WNOHANG", "WUNTRACED", "WCONTINUED"),
		"ioctl":      groupConstants("FIONREAD"),
		"prctl":      groupConstants("PR_SET_NAME", "PR_GET_NAME", "PR_SET_PDEATHSIG", "PR_GET_PDEATHSIG", "PR_SET_DUMPABLE", "PR_GET_DUMPABLE"),
		"errno":      errnoCatalog(),
	}
}

func groupConstants(names ...string) map[string]any {
	constants := namedConstants()
	group := map[string]any{}
	for _, name := range names {
		group[name] = constants[name]
	}
	return group
}

func toolSummaries() []ToolSummary {
	registry := toolSummaryRegistry()
	summaries := make([]ToolSummary, 0, len(registry))
	for _, spec := range registry {
		summaries = append(summaries, ToolSummary{spec.name, spec.description, spec.readOnly, spec.destructive})
	}
	return summaries
}
