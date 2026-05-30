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
	Documentation   []ResourceSummary   `json:"documentation"`
	ExampleScripts  []ScriptingExample  `json:"example_scripts"`
	Prompts         []string            `json:"prompts"`
	ScriptingAPI    ScriptingAPIInfo    `json:"scripting_api"`
	Implementation  []string            `json:"implementation_notes"`
}

type ClientBootstrapInfo struct {
	RecommendedFirstCalls []string       `json:"recommended_first_calls"`
	AgentGuideResource    string         `json:"agent_guide_resource"`
	ScriptingAPIResource  string         `json:"scripting_api_resource"`
	APIReferenceResource  string         `json:"api_reference_resource"`
	DocsIndexResource     string         `json:"docs_index_resource"`
	ExamplesIndexResource string         `json:"examples_index_resource"`
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

type ResourceSummary struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mime_type"`
	SourcePath  string `json:"source_path,omitempty"`
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
	OSWrappers     []string           `json:"os_wrappers"`
	IOWrappers     []string           `json:"io_wrappers"`
	Limits         map[string]any     `json:"limits"`
	ResultShape    map[string]string  `json:"result_shape"`
	Examples       []ScriptingExample `json:"examples"`
}

type ScriptGlobalInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ScriptingExample struct {
	Name        string   `json:"name"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	URI         string   `json:"uri,omitempty"`
	SourcePath  string   `json:"source_path,omitempty"`
	MIMEType    string   `json:"mime_type,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Script      string   `json:"script,omitempty"`
}

func Capabilities() CapabilityDocument {
	return CapabilityDocument{
		Name:       "mcp-uapi",
		Version:    Version,
		Purpose:    "Expose Linux user-mode APIs from golang.org/x/sys/unix and self-contained eBPF monitoring helpers through a single JavaScript eval scripting layer for embedded testing, reconnaissance, and proof-of-concept development.",
		Transports: []string{"stdio", "streamable-http"},
		ClientBootstrap: ClientBootstrapInfo{
			RecommendedFirstCalls: []string{"MCP resources/read uapi://agent-guide", "MCP resources/read uapi://scripting-api", "MCP resources/read uapi://api-reference", "MCP resources/read uapi://api", "MCP resources/read uapi://examples", "MCP resources/read uapi://capabilities", "MCP tools/call eval for all syscall workflows", "MCP resources/read uapi://state when reusing handles"},
			AgentGuideResource:    "uapi://agent-guide",
			ScriptingAPIResource:  "uapi://scripting-api",
			APIReferenceResource:  "uapi://api-reference",
			DocsIndexResource:     "uapi://docs",
			ExamplesIndexResource: "uapi://examples",
			ResourceAccess:        "Resources are MCP resources read by the client with the MCP resources/read operation. Documentation is embedded from docs/*.md and reusable scripts are embedded from examples/*.js at build time. They are not available from JavaScript eval; there is no uapi.request, sys.request, fetch, HTTP client, require, or import inside the eval runtime.",
			ScriptingPrompt:       "uapi_eval_quickstart",
			SafeEvalProbe:         `const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, os: caps.scripting_api.os_wrappers, io: caps.scripting_api.io_wrappers, examples: caps.example_scripts, uname: sys.uname(), openFlags: sys.constants({group:"open_flags"}).constants};`,
			EvalToolExample: map[string]any{
				"name": "eval",
				"arguments": map[string]any{
					"script": `const caps = sys.capabilities(); return {name: caps.name, sys: caps.scripting_api.uapi_wrappers.length, os: caps.scripting_api.os_wrappers.length, io: caps.scripting_api.io_wrappers.length, uname: sys.uname()};`,
				},
			},
			DoNotUse: []string{"uapi.request('GET', 'uapi://capabilities')", "sys.request('GET', 'uapi://capabilities')", "fetch('uapi://capabilities')", "require('fs')", "import('node:fs')", "os.exit/os.Exit", "calling uapi_* as public MCP tools"},
			Notes: []string{
				"The only public MCP tool is eval; syscall functionality is available inside the JavaScript sys/uapi object.",
				"The JavaScript os and io globals provide Go standard-library style wrappers over managed handles and explicit byte encodings; they are not Node.js modules.",
				"Read uapi://agent-guide, uapi://scripting-api, uapi://api-reference, uapi://api, and uapi://examples through MCP resource APIs before composing nontrivial eval scripts.",
				"Documentation resources are backed by docs/*.md and docs/api/*.md, and example script resources are backed by examples/*.js, then embedded into the binary by Go at build time.",
				"Inside eval, use sys.capabilities() for the same machine-readable capability document; do not try to read MCP resources from JavaScript.",
				"All handles returned by scripts are process-local to this MCP server instance.",
				"Syscall errno results are returned as structured data with ok=false instead of MCP tool errors.",
				"eBPF programs are authored from JavaScript by selecting built-in program kinds; no C compiler, clang, bpftool, external assembler, or ELF loader is required on the target.",
				"Inside eval, ptrace wrapper calls automatically pin the eval goroutine to one OS thread until the script returns, which Linux ptrace requires for multi-step tracing.",
				"Use string constants such as O_RDWR|O_CREAT, AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, PROT_READ|PROT_WRITE, AT_FDCWD, and EPOLLIN where schemas accept integer|string.",
			},
		},
		SafetyModel: []string{
			"The server exposes direct Linux syscalls. Run it only where the MCP client is trusted to create files, open sockets, signal processes, ptrace child/allowed processes, and invoke ioctls.",
			"Raw integer FD access is disabled by default; use managed handles unless the server is started with --allow-raw-fd.",
			"ptrace, ioctl, prctl, kill, writes, chmod/chown, mount-like primitives exposed by sys/unix wrappers, mmap mutations, socket sends, and FD close operations can be destructive.",
			"eBPF program loading and attachment can observe or affect kernel execution depending on the program type, return value, and hook. Use least-privilege capabilities and detach or close links when finished.",
			"Most APIs are synchronous. Use nonblocking flags, poll/epoll, and eval timeouts for robust script loops.",
		},
		PrimitiveGroups: []PrimitiveGroup{
			{"metadata", "Discover capabilities, constants, errno names, kernel identity, process IDs, and live managed state from scripts.", []string{"eval", "sys.capabilities", "sys.constants", "sys.constant", "sys.errno", "sys.uname", "sys.getpid", "sys.getids", "sys.state"}},
			{"files and descriptors", "Open, duplicate, close, vector-read/write, seek, stat, truncate, sync, and inspect Linux file descriptors through managed handles.", []string{"sys.open", "sys.creat", "sys.openat", "sys.openat2", "sys.close", "sys.read", "sys.write", "sys.pread", "sys.pwrite", "sys.readv", "sys.writev", "sys.preadv", "sys.pwritev", "sys.preadv2", "sys.pwritev2", "sys.lseek", "sys.dup", "sys.dup2", "sys.dup3", "sys.pipe2", "sys.fstat", "sys.fstatat", "sys.stat", "sys.statfs", "sys.fstatfs", "sys.statx", "sys.readlink", "sys.readlinkat", "sys.getdents", "sys.readDirent", "sys.truncate", "sys.ftruncate", "sys.fallocate", "sys.fadvise", "sys.syncFileRange", "sys.flock", "sys.fsync", "sys.fdatasync", "sys.syncfs"}},
			{"filesystem mutation", "Create, rename, link, unlink, chmod, chown, and test paths with at-family variants.", []string{"sys.access", "sys.faccessat", "sys.mkdir", "sys.mkdirat", "sys.mkfifo", "sys.mkfifoat", "sys.mknod", "sys.mknodat", "sys.link", "sys.linkat", "sys.symlink", "sys.symlinkat", "sys.unlink", "sys.unlinkat", "sys.rename", "sys.renameat", "sys.renameat2", "sys.rmdir", "sys.chmod", "sys.fchmod", "sys.fchmodat", "sys.chown", "sys.fchown", "sys.fchownat", "sys.lchown"}},
			{"buffers and pointers", "Create bounded user-space buffers for ioctl payloads, socket sends, file writes, and explicit data shaping.", []string{"sys.bufferAlloc", "sys.bufferWrite", "sys.bufferRead", "sys.bufferInfo", "sys.bufferFree"}},
			{"memory mappings", "Create anonymous or file-backed mappings and mutate or synchronize them with mmap-family APIs.", []string{"sys.mmap", "sys.munmap", "sys.mprotect", "sys.msync", "sys.madvise", "sys.memRead", "sys.memWrite"}},
			{"networking", "Create sockets, socketpairs, bind/connect/listen/accept, exchange datagrams/streams, and tune integer socket options.", []string{"sys.socket", "sys.socketpair", "sys.bind", "sys.connect", "sys.listen", "sys.accept", "sys.sendto", "sys.recvfrom", "sys.getsockname", "sys.getpeername", "sys.setsockoptInt", "sys.getsockoptInt", "sys.shutdown"}},
			{"readiness and event fds", "Drive blocking-sensitive clients with poll, epoll, eventfd, timerfd, inotify, pidfd, and nonblocking controls.", []string{"sys.poll", "sys.epollCreate", "sys.epollCtl", "sys.epollWait", "sys.eventfd", "sys.timerfdCreate", "sys.timerfdGettime", "sys.timerfdSettime", "sys.pidfdOpen", "sys.pidfdGetfd", "sys.pidfdSendSignal", "sys.inotifyInit1", "sys.inotifyAddWatch", "sys.inotifyRmWatch", "sys.setNonblock", "sys.fcntlInt"}},
			{"process and resources", "Signal, wait, prctl, ptrace, process_vm memory-copy, query groups/resource usage, and adjust rlimits.", []string{"sys.kill", "sys.tgkill", "sys.wait4", "sys.prctl", "sys.prctlRetInt", "sys.ptraceAttach", "sys.ptraceRead", "sys.ptraceWrite", "sys.ptraceCont", "sys.ptraceSyscall", "sys.ptraceGetRegs", "sys.ptraceSetOptions", "sys.ptraceDetach", "sys.processVMReadv", "sys.processVMWritev", "sys.getgroups", "sys.getresuid", "sys.getresgid", "sys.getrlimit", "sys.setrlimit", "sys.prlimit", "sys.getrusage", "sys.clockGettime", "sys.clockGetres", "sys.gettimeofday", "sys.getrandom"}},
			{"extended attributes and transfer", "Inspect and mutate xattrs, create anonymous memfd files, and move bytes between descriptors with kernel helpers.", []string{"sys.getxattr", "sys.lgetxattr", "sys.fgetxattr", "sys.listxattr", "sys.llistxattr", "sys.flistxattr", "sys.setxattr", "sys.lsetxattr", "sys.fsetxattr", "sys.removexattr", "sys.lremovexattr", "sys.fremovexattr", "sys.memfdCreate", "sys.send", "sys.sendmsg", "sys.recvmsg", "sys.sendfile", "sys.copyFileRange", "sys.splice", "sys.tee", "sys.vmsplice"}},
			{"ioctl", "Invoke arbitrary ioctl requests with either integer arguments or managed buffer pointers.", []string{"sys.ioctl", "sys.bufferAlloc", "sys.bufferRead", "sys.bufferWrite"}},
			{"eBPF", "Create maps, load self-contained built-in eBPF program kinds, attach them to kernel hooks, pin/load objects, probe features, and read ringbuf/perf event streams without a target-side C toolchain.", []string{"sys.ebpfInfo", "sys.ebpfRemoveMemlock", "sys.ebpfFeatureProbe", "sys.ebpfBTFKernelInfo", "sys.ebpfMapCreate", "sys.ebpfMapLookup", "sys.ebpfMapUpdate", "sys.ebpfProgramLoad", "sys.ebpfProgramTest", "sys.ebpfAttachKprobe", "sys.ebpfAttachKretprobe", "sys.ebpfAttachTracepoint", "sys.ebpfAttachRawTracepoint", "sys.ebpfAttachXDP", "sys.ebpfLinkInfo", "sys.ebpfLinkClose", "sys.ebpfRingbufReaderCreate", "sys.ebpfRingbufRead", "sys.ebpfPerfReaderCreate", "sys.ebpfPerfRead"}},
			{"Go standard library scripting", "Use package-os and package-io style helpers for portable filesystem, environment, root, process, and stream workflows over the same managed handles.", []string{"os.readFile", "os.writeFile", "os.open", "os.openFile", "os.openRoot", "os.rootReadFile", "os.fileRead", "os.fileWrite", "io.copy", "io.copyN", "io.readAll", "io.readFull", "io.writeString"}},
			{"JavaScript scripting", "Compose multi-step syscall and standard-library workflows in one eval call with captured logs, args, timeouts, and JSON results.", []string{"eval", "sys.*", "uapi.*", "os.*", "io.*"}},
		},
		Constants:      constantCatalog(),
		Tools:          toolSummaries(),
		Resources:      resourceURIs(),
		Documentation:  documentationResourceSummaries(),
		ExampleScripts: exampleScriptSummaries(),
		Prompts:        []string{"uapi_recon_quickstart", "uapi_eval_quickstart", "uapi_ptrace_memory_probe", "uapi_socket_fuzzing"},
		ScriptingAPI:   scriptingAPIInfo(),
		Implementation: []string{"The public MCP tool surface registers only eval; MCP resources and prompts remain available for discovery and documentation.", "Documentation resources are sourced from docs/*.md and docs/api/*.md, and example script resources from examples/*.js, via Go embed at build time.", "MCP resource reads happen outside eval through the client; the JavaScript runtime intentionally has no uapi.request, sys.request, fetch, require, or import helpers.", "The scripting layer keeps FD, buffer, mmap, os.Root, os.Process, eBPF map, eBPF program, eBPF link, ringbuf reader, and perf reader lifetimes in process-local registries guarded by a mutex.", "The syscall layer uses golang.org/x/sys/unix directly and treats Unix errno as normal structured results.", "The eBPF layer uses github.com/cilium/ebpf internally; scripts select built-in program kinds instead of supplying raw assembly or compiling C on the target.", "Perf event readers are unavailable on linux/mips and return ErrNotSupported there; use ring buffers or map polling on that target.", "Goja eval creates a fresh runtime per call and exposes sys/uapi plus os/io globals for synchronous Unix and Go standard-library workflows."},
	}
}

func scriptingAPIInfo() ScriptingAPIInfo {
	return ScriptingAPIInfo{
		Tool:           "eval",
		Resource:       "uapi://scripting-api",
		Engine:         "Goja (github.com/dop251/goja)",
		ExecutionModel: "Each eval call runs a fresh synchronous JavaScript runtime inside a function body; use return for JSON results and console.* for captured logs.",
		Globals:        []ScriptGlobalInfo{{"args", "Caller-provided JSON object."}, {"console", "Captured log/info/warn/error functions returned in the eval response."}, {"print", "Alias for console.log."}, {"sys", "Synchronous Linux sys/unix and self-contained eBPF scripting API with managed FD, buffer, mmap, socket, process, xattr, event, map, program, link, and reader helpers."}, {"uapi", "Alias for sys for compatibility with older scripts."}, {"os", "Synchronous Go package os style wrappers for files, dirs, env, roots, processes, and File methods over managed handles."}, {"io", "Synchronous Go package io style wrappers for copy/read/write helpers over managed handle, buffer, path, data, and discard endpoints."}},
		NotAvailable:   []string{"uapi.request", "sys.request", "fetch", "XMLHttpRequest", "require", "import", "Node.js fs/net modules", "direct MCP resource reads from inside eval", "public uapi_* MCP tool calls", "os.Exit/os.exit", "os.DirFS", "os.CopyFS", "File.SyscallConn", "persistent io.Reader interface objects"},
		Conventions:    []string{"Call MCP resources/read outside eval for uapi://agent-guide, uapi://scripting-api, uapi://api-reference, uapi://api, and uapi://examples.", "Call the MCP tool named eval with an object containing script, optional args, timeout_ms, max_log_entries, and max_result_bytes.", "Read API-specific docs from uapi://api/<name> and reusable scripts from uapi://examples/<file>.js before composing a subsystem-specific workflow.", "Inside scripts, use sys.* or uapi.* for Linux syscalls and eBPF helpers, os.* for Go package os style workflows, and io.* for Go package io style copy/read/write workflows.", "eBPF program loading accepts built-in kinds such as return, counter, perf_event, ringbuf_event, socket_filter_pass, and socket_filter_drop; scripts do not need target-side C compilation, raw assembly, or ELF loading.", "Every syscall-style helper returns ok=true on success or ok=false with errno fields for Linux errno failures; os/io package errors return ok=false with error_name/error_type/path metadata when available.", "Ptrace helpers pin the eval goroutine to one OS thread from the first ptrace wrapper call through script completion.", "sys.ptraceGetRegs returns normalized syscall metadata with a generated name when the syscall number is known for the architecture.", "Close managed FDs, roots, mappings, eBPF links, eBPF programs, eBPF maps, and eBPF readers explicitly when a script creates them."},
		UAPIWrappers:   scriptWrapperNames(),
		OSWrappers:     scriptOSWrapperNames(),
		IOWrappers:     scriptIOWrapperNames(),
		Limits:         map[string]any{"default_timeout_ms": defaultEvalTimeoutMS, "max_timeout_ms": maxEvalTimeoutMS, "default_max_log_entries": defaultEvalLogEntries, "max_log_entries": maxEvalLogEntries},
		ResultShape:    map[string]string{"ok": "true on successful script execution", "result": "JSON value returned by the script", "logs": "captured console entries", "operations": "number of sys/uapi wrapper calls", "error": "script or argument error string when ok=false"},
		Examples: []ScriptingExample{
			{Name: "safe_bootstrap", Script: `const caps = sys.capabilities(); return {name: caps.name, sys: caps.scripting_api.uapi_wrappers, os: caps.scripting_api.os_wrappers, io: caps.scripting_api.io_wrappers, examples: caps.example_scripts, uname: sys.uname()};`},
			{Name: "socketpair_roundtrip", Script: `const pair = sys.socketpair({type:"SOCK_STREAM|SOCK_CLOEXEC"}); sys.write({handle: pair.handles[0], data_utf8:"ping"}); return sys.read({handle: pair.handles[1], length:4, encoding:"utf8"});`},
			{Name: "at_family_file", Script: `const fd = sys.openat({path: args.path, flags:"O_RDWR|O_CREAT|O_CLOEXEC", mode:"0600"}); sys.write({handle: fd.handle, data_utf8:"hello"}); return sys.fstatat({path: args.path});`},
			{Name: "stdlib_copy", Script: `os.writeFile({name: args.path, data_utf8:"hello", perm:"0600"}); const src = os.open({name: args.path}); const dst = os.create({name: args.copy}); try { return io.copy({dst:{handle: dst.handle}, src:{handle: src.handle}}); } finally { os.fileClose({handle: src.handle}); os.fileClose({handle: dst.handle}); }`},
			{Name: "ebpf_socket_filter", Script: `const prog = sys.ebpfProgramLoad({kind:"socket_filter_pass", handle:"passAll"}); if (!prog.ok) return prog; const pair = sys.socketpair({type:"SOCK_DGRAM|SOCK_CLOEXEC", handles:["left","right"]}); const attach = sys.ebpfAttachSocketFilter({program:"passAll", handle:"left"}); return {prog, attach};`},
		},
	}
}

func constantCatalog() map[string]any {
	return map[string]any{
		"socket":          groupConstants("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET", "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_SEQPACKET", "SOCK_NONBLOCK", "SOCK_CLOEXEC", "IPPROTO_TCP", "IPPROTO_UDP", "SOL_SOCKET", "SO_REUSEADDR", "SO_REUSEPORT", "SO_ERROR", "SO_PASSCRED", "SO_BINDTODEVICE", "SCM_RIGHTS", "TCP_CONGESTION"),
		"open_flags":      groupConstants("O_RDONLY", "O_WRONLY", "O_RDWR", "O_CREATE", "O_CREAT", "O_EXCL", "O_TRUNC", "O_APPEND", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_SYNC"),
		"go_os":           osConstants(),
		"go_io":           ioConstants(),
		"access":          groupConstants("F_OK", "R_OK", "W_OK", "X_OK", "AT_FDCWD", "AT_EACCESS", "AT_SYMLINK_NOFOLLOW", "AT_EMPTY_PATH"),
		"at":              groupConstants("AT_FDCWD", "AT_SYMLINK_NOFOLLOW", "AT_REMOVEDIR", "AT_EMPTY_PATH", "AT_NO_AUTOMOUNT", "AT_EACCESS"),
		"fcntl":           groupConstants("F_DUPFD", "F_DUPFD_CLOEXEC", "F_GETFD", "F_SETFD", "F_GETFL", "F_SETFL", "F_GETLK", "F_SETLK", "F_SETLKW", "F_RDLCK", "F_WRLCK", "F_UNLCK"),
		"file_type":       groupConstants("S_IFIFO", "S_IFCHR", "S_IFBLK", "S_IFREG", "S_IFSOCK"),
		"seek":            groupConstants("SEEK_SET", "SEEK_CUR", "SEEK_END"),
		"mmap":            groupConstants("PROT_NONE", "PROT_READ", "PROT_WRITE", "PROT_EXEC", "MAP_SHARED", "MAP_PRIVATE", "MAP_ANON", "MAP_ANONYMOUS", "MS_SYNC", "MS_ASYNC", "MADV_NORMAL", "MADV_RANDOM", "MADV_DONTNEED"),
		"poll":            groupConstants("POLLIN", "POLLOUT", "POLLERR", "POLLHUP", "POLLNVAL"),
		"epoll":           groupConstants("EPOLLIN", "EPOLLOUT", "EPOLLERR", "EPOLLHUP", "EPOLLRDHUP", "EPOLLET", "EPOLLONESHOT", "EPOLL_CLOEXEC", "EPOLL_CTL_ADD", "EPOLL_CTL_MOD", "EPOLL_CTL_DEL"),
		"eventfd":         groupConstants("EFD_CLOEXEC", "EFD_NONBLOCK"),
		"timerfd":         groupConstants("TFD_CLOEXEC", "TFD_NONBLOCK", "TFD_TIMER_ABSTIME", "TFD_TIMER_CANCEL_ON_SET"),
		"signalfd":        groupConstants("SFD_CLOEXEC", "SFD_NONBLOCK"),
		"memfd":           groupConstants("MFD_CLOEXEC", "MFD_ALLOW_SEALING"),
		"pidfd":           groupConstants("PIDFD_NONBLOCK"),
		"close_range":     groupConstants("CLOSE_RANGE_UNSHARE", "CLOSE_RANGE_CLOEXEC"),
		"inotify":         groupConstants("IN_ACCESS", "IN_ATTRIB", "IN_CLOSE_WRITE", "IN_CLOSE_NOWRITE", "IN_CREATE", "IN_DELETE", "IN_DELETE_SELF", "IN_MODIFY", "IN_MOVED_FROM", "IN_MOVED_TO", "IN_MOVE_SELF", "IN_OPEN"),
		"statx":           groupConstants("STATX_BASIC_STATS", "STATX_ALL"),
		"rename":          groupConstants("RENAME_NOREPLACE", "RENAME_EXCHANGE"),
		"signal":          groupConstants("SIGSTOP", "SIGCONT", "SIGTERM", "SIGKILL", "SIGCHLD", "SIGTRAP"),
		"ptrace":          groupConstants("PTRACE_O_TRACESYSGOOD", "PTRACE_O_TRACEFORK", "PTRACE_O_TRACEVFORK", "PTRACE_O_TRACECLONE", "PTRACE_O_TRACEEXEC", "PTRACE_O_TRACEVFORKDONE", "PTRACE_O_TRACEEXIT", "PTRACE_O_TRACESECCOMP"),
		"wait":            groupConstants("WNOHANG", "WUNTRACED", "WCONTINUED", "RUSAGE_SELF", "RUSAGE_CHILDREN"),
		"rlimit":          groupConstants("RLIMIT_NOFILE", "RLIMIT_CORE", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_MEMLOCK", "RLIMIT_NPROC", "RLIMIT_RSS", "RLIMIT_LOCKS", "RLIMIT_SIGPENDING", "RLIMIT_MSGQUEUE", "RLIMIT_NICE", "RLIMIT_RTPRIO", "RLIMIT_RTTIME"),
		"ioctl":           groupConstants("FIONREAD"),
		"prctl":           groupConstants("PR_SET_NAME", "PR_GET_NAME", "PR_SET_PDEATHSIG", "PR_GET_PDEATHSIG", "PR_SET_DUMPABLE", "PR_GET_DUMPABLE"),
		"priority":        groupConstants("PRIO_PROCESS", "PRIO_PGRP", "PRIO_USER"),
		"clock":           groupConstants("CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_PROCESS_CPUTIME_ID", "CLOCK_THREAD_CPUTIME_ID", "CLOCK_MONOTONIC_RAW", "CLOCK_REALTIME_COARSE", "CLOCK_MONOTONIC_COARSE", "CLOCK_BOOTTIME", "CLOCK_REALTIME_ALARM", "CLOCK_BOOTTIME_ALARM", "CLOCK_TAI"),
		"random":          groupConstants("GRND_NONBLOCK", "GRND_RANDOM", "GRND_INSECURE"),
		"fadvise":         groupConstants("FADV_NORMAL", "FADV_RANDOM", "FADV_SEQUENTIAL", "FADV_WILLNEED", "FADV_DONTNEED", "FADV_NOREUSE"),
		"fallocate":       groupConstants("FALLOC_FL_KEEP_SIZE", "FALLOC_FL_PUNCH_HOLE", "FALLOC_FL_NO_HIDE_STALE", "FALLOC_FL_COLLAPSE_RANGE", "FALLOC_FL_ZERO_RANGE", "FALLOC_FL_INSERT_RANGE", "FALLOC_FL_UNSHARE_RANGE"),
		"sync_file_range": groupConstants("SYNC_FILE_RANGE_WAIT_BEFORE", "SYNC_FILE_RANGE_WRITE", "SYNC_FILE_RANGE_WAIT_AFTER", "SYNC_FILE_RANGE_WRITE_AND_WAIT"),
		"splice":          groupConstants("SPLICE_F_MOVE", "SPLICE_F_NONBLOCK", "SPLICE_F_MORE", "SPLICE_F_GIFT"),
		"rwf":             groupConstants("RWF_HIPRI", "RWF_DSYNC", "RWF_SYNC", "RWF_NOWAIT", "RWF_APPEND"),
		"openat2":         groupConstants("RESOLVE_NO_XDEV", "RESOLVE_NO_MAGICLINKS", "RESOLVE_NO_SYMLINKS", "RESOLVE_BENEATH", "RESOLVE_IN_ROOT"),
		"flock":           groupConstants("LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"),
		"syscall":         groupConstants("SYS_GETPID", "SYS_PROCESS_VM_READV", "SYS_PROCESS_VM_WRITEV", "SYS_PIDFD_OPEN", "SYS_PIDFD_GETFD", "SYS_PIDFD_SEND_SIGNAL", "SYS_OPENAT2", "SYS_FACCESSAT2", "SYS_SPLICE", "SYS_TEE", "SYS_VMSPLICE", "SYS_GETRANDOM", "SYS_PREADV", "SYS_PWRITEV", "SYS_PREADV2", "SYS_PWRITEV2", "SYS_TIMERFD_CREATE", "SYS_TIMERFD_SETTIME", "SYS_TIMERFD_GETTIME", "SYS_SENDMSG", "SYS_RECVMSG", "SYS_GETDENTS64", "SYS_FALLOCATE"),
		"ebpf":            groupConstants("BPF_MAP_TYPE_HASH", "BPF_MAP_TYPE_ARRAY", "BPF_MAP_TYPE_PROG_ARRAY", "BPF_MAP_TYPE_PERF_EVENT_ARRAY", "BPF_MAP_TYPE_LRU_HASH", "BPF_MAP_TYPE_PERCPU_HASH", "BPF_MAP_TYPE_RINGBUF", "BPF_PROG_TYPE_SOCKET_FILTER", "BPF_PROG_TYPE_KPROBE", "BPF_PROG_TYPE_TRACEPOINT", "BPF_PROG_TYPE_RAW_TRACEPOINT", "BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_SCHED_CLS", "BPF_PROG_TYPE_CGROUP_SKB", "BPF_ATTACH_TYPE_XDP", "BPF_ANY", "BPF_NOEXIST", "BPF_EXIST", "BPF_F_LOCK", "BPF_F_NO_PREALLOC", "BPF_F_RDONLY", "BPF_F_WRONLY", "BPF_F_RDONLY_PROG", "BPF_F_WRONLY_PROG", "BPF_F_NUMA_NODE", "BPF_F_MMAPABLE", "BPF_F_PRESERVE_ELEMS", "BPF_F_CURRENT_CPU", "XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT", "XDP_GENERIC_MODE", "XDP_DRIVER_MODE", "XDP_OFFLOAD_MODE", "BPF_LOG_LEVEL1", "BPF_LOG_LEVEL2", "BPF_LOG_STATS"),
		"errno":           errnoCatalog(),
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
