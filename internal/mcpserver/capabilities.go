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
	RecommendedFirstCalls []string       `json:"recommended_first_calls"`
	AgentGuideResource    string         `json:"agent_guide_resource"`
	ScriptingAPIResource  string         `json:"scripting_api_resource"`
	APIReferenceResource  string         `json:"api_reference_resource"`
	ResourceAccess        string         `json:"resource_access"`
	ScriptingPrompt       string         `json:"scripting_prompt"`
	SafeEvalProbe         string         `json:"safe_eval_probe"`
	EvalToolExample       map[string]any `json:"eval_tool_example"`
	DoNotUse              []string       `json:"do_not_use"`
	Notes                 []string       `json:"notes"`
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
	NotAvailable   []string           `json:"not_available"`
	Conventions    []string           `json:"conventions"`
	UAPIWrappers   []string           `json:"uapi_wrappers"`
	Limits         map[string]any     `json:"limits"`
	ResultShape    map[string]string  `json:"result_shape"`
	Examples       []ScriptingExample `json:"examples"`
}

type ScriptGlobalInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ScriptingExample struct {
	Name   string `json:"name"`
	Script string `json:"script"`
}

func Capabilities() CapabilityDocument {
	return CapabilityDocument{
		Name:       "mcp-uapi",
		Version:    Version,
		Purpose:    "Expose Linux user-mode APIs from golang.org/x/sys/unix through a single JavaScript eval scripting layer for embedded testing, reconnaissance, and proof-of-concept development.",
		Transports: []string{"stdio", "streamable-http"},
		ClientBootstrap: ClientBootstrapInfo{
			RecommendedFirstCalls: []string{"MCP resources/read uapi://agent-guide", "MCP resources/read uapi://scripting-api", "MCP resources/read uapi://api-reference", "MCP resources/read uapi://capabilities", "MCP tools/call eval for all syscall workflows", "MCP resources/read uapi://state when reusing handles"},
			AgentGuideResource:    "uapi://agent-guide",
			ScriptingAPIResource:  "uapi://scripting-api",
			APIReferenceResource:  "uapi://api-reference",
			ResourceAccess:        "Resources are MCP resources read by the client with the MCP resources/read operation. They are not available from JavaScript eval; there is no uapi.request, sys.request, fetch, HTTP client, require, or import inside the eval runtime.",
			ScriptingPrompt:       "uapi_eval_quickstart",
			SafeEvalProbe:         `const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, uname: sys.uname(), openFlags: sys.constants({group:"open_flags"}).constants};`,
			EvalToolExample: map[string]any{
				"name": "eval",
				"arguments": map[string]any{
					"script": `const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers.length, uname: sys.uname()};`,
				},
			},
			DoNotUse: []string{"uapi.request('GET', 'uapi://capabilities')", "sys.request('GET', 'uapi://capabilities')", "fetch('uapi://capabilities')", "calling uapi_* as public MCP tools"},
			Notes: []string{
				"The only public MCP tool is eval; syscall functionality is available inside the JavaScript sys/uapi object.",
				"Read uapi://agent-guide, uapi://scripting-api, and uapi://api-reference through MCP resource APIs before composing nontrivial eval scripts.",
				"Inside eval, use sys.capabilities() for the same machine-readable capability document; do not try to read MCP resources from JavaScript.",
				"All handles returned by scripts are process-local to this MCP server instance.",
				"Syscall errno results are returned as structured data with ok=false instead of MCP tool errors.",
				"Use string constants such as O_RDWR|O_CREAT, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, PROT_READ|PROT_WRITE, AT_FDCWD, and EPOLLIN where schemas accept integer|string.",
			},
		},
		SafetyModel: []string{
			"The server exposes direct Linux syscalls. Run it only where the MCP client is trusted to create files, open sockets, signal processes, ptrace child/allowed processes, and invoke ioctls.",
			"Raw integer FD access is disabled by default; use managed handles unless the server is started with --allow-raw-fd.",
			"ptrace, ioctl, prctl, kill, writes, chmod/chown, mount-like primitives exposed by sys/unix wrappers, mmap mutations, socket sends, and FD close operations can be destructive.",
			"Most APIs are synchronous. Use nonblocking flags, poll/epoll, and eval timeouts for robust script loops.",
		},
		PrimitiveGroups: []PrimitiveGroup{
			{"metadata", "Discover capabilities, constants, errno names, kernel identity, process IDs, and live managed state from scripts.", []string{"eval", "sys.capabilities", "sys.constants", "sys.constant", "sys.errno", "sys.uname", "sys.getpid", "sys.getids", "sys.state"}},
			{"files and descriptors", "Open, duplicate, close, read, write, seek, stat, truncate, sync, and inspect Linux file descriptors through managed handles.", []string{"sys.open", "sys.openat", "sys.close", "sys.read", "sys.write", "sys.pread", "sys.pwrite", "sys.lseek", "sys.dup", "sys.dup2", "sys.dup3", "sys.pipe2", "sys.fstat", "sys.fstatat", "sys.stat", "sys.statfs", "sys.fstatfs", "sys.statx", "sys.readlink", "sys.readlinkat", "sys.truncate", "sys.ftruncate", "sys.fsync", "sys.fdatasync", "sys.syncfs"}},
			{"filesystem mutation", "Create, rename, link, unlink, chmod, chown, and test paths with at-family variants.", []string{"sys.access", "sys.faccessat", "sys.mkdir", "sys.mkdirat", "sys.mkfifo", "sys.mkfifoat", "sys.mknod", "sys.mknodat", "sys.link", "sys.linkat", "sys.symlink", "sys.symlinkat", "sys.unlink", "sys.unlinkat", "sys.rename", "sys.renameat", "sys.renameat2", "sys.rmdir", "sys.chmod", "sys.fchmod", "sys.fchmodat", "sys.chown", "sys.fchown", "sys.fchownat", "sys.lchown"}},
			{"buffers and pointers", "Create bounded user-space buffers for ioctl payloads, socket sends, file writes, and explicit data shaping.", []string{"sys.bufferAlloc", "sys.bufferWrite", "sys.bufferRead", "sys.bufferInfo", "sys.bufferFree"}},
			{"memory mappings", "Create anonymous or file-backed mappings and mutate or synchronize them with mmap-family APIs.", []string{"sys.mmap", "sys.munmap", "sys.mprotect", "sys.msync", "sys.madvise", "sys.memRead", "sys.memWrite"}},
			{"networking", "Create sockets, socketpairs, bind/connect/listen/accept, exchange datagrams/streams, and tune integer socket options.", []string{"sys.socket", "sys.socketpair", "sys.bind", "sys.connect", "sys.listen", "sys.accept", "sys.sendto", "sys.recvfrom", "sys.getsockname", "sys.getpeername", "sys.setsockoptInt", "sys.getsockoptInt", "sys.shutdown"}},
			{"readiness and event fds", "Drive blocking-sensitive clients with poll, epoll, eventfd, inotify, and nonblocking controls.", []string{"sys.poll", "sys.epollCreate", "sys.epollCtl", "sys.epollWait", "sys.eventfd", "sys.inotifyInit1", "sys.inotifyAddWatch", "sys.inotifyRmWatch", "sys.setNonblock", "sys.fcntlInt"}},
			{"process and resources", "Signal, wait, prctl, ptrace, query groups/resource usage, and adjust rlimits.", []string{"sys.kill", "sys.wait4", "sys.prctl", "sys.ptraceAttach", "sys.ptraceRead", "sys.ptraceWrite", "sys.ptraceCont", "sys.ptraceSyscall", "sys.ptraceDetach", "sys.getgroups", "sys.getresuid", "sys.getresgid", "sys.getrlimit", "sys.setrlimit", "sys.getrusage"}},
			{"extended attributes and transfer", "Inspect and mutate xattrs, create anonymous memfd files, and move bytes between descriptors with kernel helpers.", []string{"sys.getxattr", "sys.lgetxattr", "sys.fgetxattr", "sys.listxattr", "sys.llistxattr", "sys.flistxattr", "sys.setxattr", "sys.lsetxattr", "sys.fsetxattr", "sys.removexattr", "sys.lremovexattr", "sys.fremovexattr", "sys.memfdCreate", "sys.sendfile", "sys.copyFileRange"}},
			{"ioctl", "Invoke arbitrary ioctl requests with either integer arguments or managed buffer pointers.", []string{"sys.ioctl", "sys.bufferAlloc", "sys.bufferRead", "sys.bufferWrite"}},
			{"JavaScript scripting", "Compose multi-step syscall workflows in one eval call with captured logs, args, timeouts, and JSON results.", []string{"eval", "sys.*", "uapi.*"}},
		},
		Constants:      constantCatalog(),
		Tools:          toolSummaries(),
		Resources:      []string{"uapi://agent-guide", "uapi://capabilities", "uapi://api-reference", "uapi://scripting-api", "uapi://state"},
		Prompts:        []string{"uapi_recon_quickstart", "uapi_eval_quickstart", "uapi_ptrace_memory_probe", "uapi_socket_fuzzing"},
		ScriptingAPI:   scriptingAPIInfo(),
		Implementation: []string{"The public MCP tool surface registers only eval; MCP resources and prompts remain available for discovery and documentation.", "MCP resource reads happen outside eval through the client; the JavaScript runtime intentionally has no uapi.request, sys.request, fetch, require, or import helpers.", "The scripting layer keeps FD, buffer, and mmap lifetime in process-local registries guarded by a mutex.", "The syscall layer uses golang.org/x/sys/unix directly and treats Unix errno as normal structured results.", "Goja eval creates a fresh runtime per call and exposes sys and uapi aliases for synchronous Unix workflows."},
	}
}

func scriptingAPIInfo() ScriptingAPIInfo {
	return ScriptingAPIInfo{
		Tool:           "eval",
		Resource:       "uapi://scripting-api",
		Engine:         "Goja (github.com/dop251/goja)",
		ExecutionModel: "Each eval call runs a fresh synchronous JavaScript runtime inside a function body; use return for JSON results and console.* for captured logs.",
		Globals:        []ScriptGlobalInfo{{"args", "Caller-provided JSON object."}, {"console", "Captured log/info/warn/error functions returned in the eval response."}, {"print", "Alias for console.log."}, {"sys", "Synchronous Linux sys/unix scripting API with managed FD, buffer, mmap, socket, process, xattr, and event helpers."}, {"uapi", "Alias for sys for compatibility with older scripts."}},
		NotAvailable:   []string{"uapi.request", "sys.request", "fetch", "XMLHttpRequest", "require", "import", "Node.js fs/net modules", "direct MCP resource reads from inside eval", "public uapi_* MCP tool calls"},
		Conventions:    []string{"Call MCP resources/read outside eval for uapi://agent-guide, uapi://scripting-api, and uapi://api-reference.", "Call the MCP tool named eval with an object containing script, optional args, timeout_ms, max_log_entries, and max_result_bytes.", "Inside scripts, use sys.* or uapi.* only; sys and uapi are the same object.", "Every syscall-style helper returns ok=true on success or ok=false with errno fields for Linux errno failures.", "Close managed FDs and mappings explicitly with sys.close and sys.munmap when a script creates them."},
		UAPIWrappers:   scriptWrapperNames(),
		Limits:         map[string]any{"default_timeout_ms": defaultEvalTimeoutMS, "max_timeout_ms": maxEvalTimeoutMS, "default_max_log_entries": defaultEvalLogEntries, "max_log_entries": maxEvalLogEntries},
		ResultShape:    map[string]string{"ok": "true on successful script execution", "result": "JSON value returned by the script", "logs": "captured console entries", "operations": "number of sys/uapi wrapper calls", "error": "script or argument error string when ok=false"},
		Examples: []ScriptingExample{
			{"safe_bootstrap", `const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, uname: sys.uname()};`},
			{"socketpair_roundtrip", `const pair = sys.socketpair({type:"SOCK_STREAM|SOCK_CLOEXEC"}); sys.write({handle: pair.handles[0], data_utf8:"ping"}); return sys.read({handle: pair.handles[1], length:4, encoding:"utf8"});`},
			{"at_family_file", `const fd = sys.openat({path: args.path, flags:"O_RDWR|O_CREAT|O_CLOEXEC", mode:"0600"}); sys.write({handle: fd.handle, data_utf8:"hello"}); return sys.fstatat({path: args.path});`},
		},
	}
}

func constantCatalog() map[string]any {
	return map[string]any{
		"socket":      groupConstants("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET", "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_SEQPACKET", "SOCK_NONBLOCK", "SOCK_CLOEXEC", "IPPROTO_TCP", "IPPROTO_UDP", "SOL_SOCKET", "SO_REUSEADDR", "SO_REUSEPORT", "SO_ERROR"),
		"open_flags":  groupConstants("O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_SYNC"),
		"access":      groupConstants("F_OK", "R_OK", "W_OK", "X_OK", "AT_FDCWD", "AT_EACCESS", "AT_SYMLINK_NOFOLLOW", "AT_EMPTY_PATH"),
		"at":          groupConstants("AT_FDCWD", "AT_SYMLINK_NOFOLLOW", "AT_REMOVEDIR", "AT_EMPTY_PATH", "AT_NO_AUTOMOUNT", "AT_EACCESS"),
		"fcntl":       groupConstants("F_DUPFD", "F_DUPFD_CLOEXEC", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL"),
		"file_type":   groupConstants("S_IFIFO", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFSOCK"),
		"seek":        groupConstants("SEEK_SET", "SEEK_CUR", "SEEK_END"),
		"mmap":        groupConstants("PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC", "MAP_SHARED", "MAP_PRIVATE", "MAP_ANON", "MAP_ANONYMOUS", "MS_SYNC", "MS_ASYNC", "MADV_NORMAL", "MADV_RANDOM", "MADV_DONTNEED"),
		"poll":        groupConstants("POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL"),
		"epoll":       groupConstants("EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP", "EPOLLRDHUP", "EPOLLET", "EPOLLONESHOT", "EPOLL_CLOEXEC", "EPOLL_CTL_ADD", "EPOLL_CTL_MOD", "EPOLL_CTL_DEL"),
		"eventfd":     groupConstants("EFD_CLOEXEC", "EFD_NONBLOCK"),
		"memfd":       groupConstants("MFD_CLOEXEC", "MFD_ALLOW_SEALING"),
		"close_range": groupConstants("CLOSE_RANGE_UNSHARE", "CLOSE_RANGE_CLOEXEC"),
		"inotify":     groupConstants("IN_ACCESS", "IN_ATTRIB", "IN_CLOSE_WRITE", "IN_CLOSE_NOWRITE", "IN_CREATE", "IN_DELETE", "IN_DELETE_SELF", "IN_MODIFY", "IN_MOVED_FROM", "IN_MOVED_TO", "IN_MOVE_SELF", "IN_OPEN"),
		"statx":       groupConstants("STATX_BASIC_STATS", "STATX_ALL"),
		"rename":      groupConstants("RENAME_NOREPLACE", "RENAME_EXCHANGE"),
		"signal":      groupConstants("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL", "SIGCHLD", "SIGTRAP"),
		"wait":        groupConstants("WNOHANG", "WUNTRACED", "WCONTINUED", "RUSAGE_SELF", "RUSAGE_CHILDREN"),
		"rlimit":      groupConstants("RLIMIT_NOFILE", "RLIMIT_CORE", "RLIMIT_CPU", "RLIMIT_FSIZE"),
		"ioctl":       groupConstants("FIONREAD"),
		"prctl":       groupConstants("PR_SET_NAME", "PR_GET_NAME", "PR_SET_PDEATHSIG", "PR_GET_PDEATHSIG", "PR_SET_DUMPABLE", "PR_GET_DUMPABLE"),
		"errno":       errnoCatalog(),
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
