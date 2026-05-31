package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/sys/unix"
)

const defaultMaxReadBytes = 1 << 20
const defaultMaxBufferBytes = 16 << 20

type Config struct {
	AllowRawFD       bool
	MaxReadBytes     uint64
	MaxBufferBytes   uint64
	ToolDatabasePath string
}

type App struct {
	config Config
	mu     sync.Mutex

	nextFDHandle uint64
	fds          map[string]*fdEntry

	buffers map[string]*bufferEntry

	nextMapHandle uint64
	mappings      map[string]*mmapEntry

	nextRootHandle    uint64
	roots             map[string]*rootEntry
	nextProcessHandle uint64
	processes         map[string]*processEntry

	nextEBPFMapHandle     uint64
	ebpfMaps              map[string]*ebpfMapEntry
	nextEBPFProgramHandle uint64
	ebpfPrograms          map[string]*ebpfProgramEntry
	nextEBPFLinkHandle    uint64
	ebpfLinks             map[string]*ebpfLinkEntry
	nextRingReaderHandle  uint64
	ringReaders           map[string]*ebpfRingReaderEntry
	nextPerfReaderHandle  uint64
	perfReaders           map[string]*ebpfPerfReaderEntry

	tools map[string]*managedTool
}

type fdEntry struct {
	Handle string         `json:"handle"`
	FD     int            `json:"fd"`
	Kind   string         `json:"kind"`
	Path   string         `json:"path,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

type bufferEntry struct {
	Name string
	Data []byte
}

type mmapEntry struct {
	Handle string
	Data   []byte
	FD     int
	Offset int64
	Prot   int
	Flags  int
}

func New(config Config) (*App, *server.MCPServer) {
	app, srv, err := NewWithError(config)
	if err != nil {
		panic(err)
	}
	return app, srv
}

func NewWithError(config Config) (*App, *server.MCPServer, error) {
	if config.MaxReadBytes == 0 {
		config.MaxReadBytes = defaultMaxReadBytes
	}
	if config.MaxBufferBytes == 0 {
		config.MaxBufferBytes = defaultMaxBufferBytes
	}
	app := &App{
		config:       config,
		fds:          map[string]*fdEntry{},
		buffers:      map[string]*bufferEntry{},
		mappings:     map[string]*mmapEntry{},
		roots:        map[string]*rootEntry{},
		processes:    map[string]*processEntry{},
		ebpfMaps:     map[string]*ebpfMapEntry{},
		ebpfPrograms: map[string]*ebpfProgramEntry{},
		ebpfLinks:    map[string]*ebpfLinkEntry{},
		ringReaders:  map[string]*ebpfRingReaderEntry{},
		perfReaders:  map[string]*ebpfPerfReaderEntry{},
		tools:        map[string]*managedTool{},
	}
	if err := app.initManagedTools(); err != nil {
		return nil, nil, err
	}
	srv := server.NewMCPServer(
		"mcp-uapi",
		Version,
		server.WithToolCapabilities(false),
		server.WithResourceCapabilities(false, false),
		server.WithPromptCapabilities(false),
		server.WithRecovery(),
		server.WithResourceRecovery(),
		server.WithInputSchemaValidation(),
		server.WithInstructions(serverInstructions()),
	)
	app.registerResources(srv)
	app.registerPrompts(srv)
	app.registerTools(srv)
	return app, srv, nil
}

func serverInstructions() string {
	return "Start by reading MCP resources uapi://agent-guide, uapi://tools-guide, uapi://scripting-api, uapi://api-reference, uapi://api, uapi://examples, and uapi://capabilities using the MCP client resource-read operation. Documentation is embedded from docs/*.md and docs/api/*.md, and reusable eval examples from examples/*.js, at build time. Public MCP tools are eval plus tool_register, tool_update, tool_execute, tool_list, tool_read, tool_export, tool_import, and tool_delete for managing reusable eval scripts. MCP resources are not readable from JavaScript eval: do not call uapi.request, sys.request, fetch, require, or import. eval runs JavaScript inside a function body with globals args, console, print, sys, uapi, os, and io. Registered managed tools are stored in memory by default, or in a JSON database when the server starts with --tool-db. Use tool_register to save a script and its metadata, tool_execute to run it with args, tool_export/tool_import to share toolboxes, and tool_delete to remove tools. Inside eval and registered tool scripts, use sys.capabilities() for the machine-readable capability document. Syscall and eBPF kernel errno returns are data with ok=false, errno, errno_name, and error; malformed script arguments are eval errors. Prefer managed handles returned by sys.open, os.open, os.create, os.openRoot, sys.socket, sys.socketpair, sys.epollCreate, sys.bufferAlloc, sys.mmap, sys.memfdCreate, sys.timerfdCreate, sys.pidfdOpen, sys.eventfd, sys.ebpfMapCreate, sys.ebpfProgramLoad, and related helpers. Close managed FDs, roots, mappings, eBPF links/programs/maps/readers, and buffers when finished."
}

func (a *App) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for handle, reader := range a.perfReaders {
		_ = reader.Reader.Close()
		delete(a.perfReaders, handle)
	}
	for handle, reader := range a.ringReaders {
		_ = reader.Reader.Close()
		delete(a.ringReaders, handle)
	}
	for handle, ebpfLink := range a.ebpfLinks {
		_ = ebpfLink.Link.Close()
		delete(a.ebpfLinks, handle)
	}
	for handle, program := range a.ebpfPrograms {
		_ = program.Program.Close()
		delete(a.ebpfPrograms, handle)
	}
	for handle, ebpfMap := range a.ebpfMaps {
		_ = ebpfMap.Map.Close()
		delete(a.ebpfMaps, handle)
	}
	for handle, mapping := range a.mappings {
		_ = unix.Munmap(mapping.Data)
		delete(a.mappings, handle)
	}
	for handle, fd := range a.fds {
		_ = unix.Close(fd.FD)
		delete(a.fds, handle)
	}
	for handle, root := range a.roots {
		_ = root.Root.Close()
		delete(a.roots, handle)
	}
	for handle, process := range a.processes {
		_ = process.Process.Release()
		delete(a.processes, handle)
	}
	for name := range a.buffers {
		delete(a.buffers, name)
	}
	for name := range a.tools {
		delete(a.tools, name)
	}
}

func (a *App) registerResources(srv *server.MCPServer) {
	for _, resource := range documentResources() {
		resource := resource
		srv.AddResource(mcp.NewResource(resource.URI, resource.Name, mcp.WithResourceDescription(resource.Description), mcp.WithMIMEType(resource.MIMEType)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: resource.MIMEType, Text: mustEmbeddedText(resource.Path)}}, nil
		})
	}
	srv.AddResource(mcp.NewResource("uapi://docs", "MCP-UAPI documentation index", mcp.WithResourceDescription("Human-readable index of embedded documentation resources."), mcp.WithMIMEType(mimeMarkdown)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeMarkdown, Text: docsIndexMarkdown()}}, nil
	})
	srv.AddResource(mcp.NewResource("uapi://docs/index.json", "MCP-UAPI documentation index JSON", mcp.WithResourceDescription("Machine-readable index of embedded documentation resources."), mcp.WithMIMEType(mimeJSON)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeJSON, Text: docsIndexJSON()}}, nil
	})
	srv.AddResource(mcp.NewResource("uapi://api", "MCP-UAPI API documents", mcp.WithResourceDescription("Human-readable index of embedded per-API documentation resources."), mcp.WithMIMEType(mimeMarkdown)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeMarkdown, Text: apiDocsIndexMarkdown()}}, nil
	})
	srv.AddResource(mcp.NewResource("uapi://api/index.json", "MCP-UAPI API document index JSON", mcp.WithResourceDescription("Machine-readable index of embedded per-API documentation resources."), mcp.WithMIMEType(mimeJSON)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeJSON, Text: apiDocsIndexJSON()}}, nil
	})
	for _, resource := range apiDocResources() {
		resource := resource
		srv.AddResource(mcp.NewResource(resource.URI, resource.Name, mcp.WithResourceDescription(resource.Description), mcp.WithMIMEType(resource.MIMEType)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: resource.MIMEType, Text: mustEmbeddedText(resource.Path)}}, nil
		})
	}
	srv.AddResource(mcp.NewResource("uapi://examples", "MCP-UAPI example scripts", mcp.WithResourceDescription("Human-readable index of reusable eval scripts embedded from examples/*.js."), mcp.WithMIMEType(mimeMarkdown)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeMarkdown, Text: examplesIndexMarkdown()}}, nil
	})
	srv.AddResource(mcp.NewResource("uapi://examples/index.json", "MCP-UAPI example script index JSON", mcp.WithResourceDescription("Machine-readable index of reusable eval scripts embedded from examples/*.js."), mcp.WithMIMEType(mimeJSON)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: mimeJSON, Text: examplesIndexJSON()}}, nil
	})
	for _, resource := range exampleScriptResources() {
		resource := resource
		srv.AddResource(mcp.NewResource(resource.URI, resource.Name, mcp.WithResourceDescription(resource.Description), mcp.WithMIMEType(resource.MIMEType)), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: resource.MIMEType, Text: mustEmbeddedText(resource.Path)}}, nil
		})
	}
	srv.AddResource(mcp.NewResource("uapi://capabilities", "Linux UAPI capabilities", mcp.WithResourceDescription("Machine-readable primitive inventory, constants, tool summaries, and scripting metadata."), mcp.WithMIMEType("application/json")), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		data, err := json.MarshalIndent(Capabilities(), "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: "application/json", Text: string(data)}}, nil
	})
	srv.AddResource(mcp.NewResource("uapi://state", "Linux UAPI live state", mcp.WithResourceDescription("Current managed FDs, buffers, and mmap regions."), mcp.WithMIMEType("application/json")), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		data, err := json.MarshalIndent(a.stateSnapshot(), "", "  ")
		if err != nil {
			return nil, err
		}
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: request.Params.URI, MIMEType: "application/json", Text: string(data)}}, nil
	})
}

func (a *App) registerPrompts(srv *server.MCPServer) {
	srv.AddPrompt(mcp.NewPrompt("uapi_recon_quickstart", mcp.WithPromptDescription("Plan a Linux user-mode attack-surface reconnaissance workflow."), mcp.WithArgument("target", mcp.ArgumentDescription("Optional process, path, socket, or subsystem to inspect."))), func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		target := request.Params.Arguments["target"]
		text := "Read MCP resources uapi://agent-guide, uapi://capabilities, and uapi://scripting-api before eval. Resource reads happen outside JavaScript; do not use uapi.request/sys.request/fetch inside eval. Use eval with sys.uname(), sys.constants(), relevant sys.stat/sys.readlink/sys.statx data, then managed handles for files, sockets, poll/epoll, ioctl buffers, or ptrace. Treat ok=false errno results as observations and reserve eval errors for malformed script arguments."
		if target != "" {
			text += "\n\nTarget:\n" + target
		}
		return &mcp.GetPromptResult{Description: "Linux UAPI reconnaissance workflow", Messages: []mcp.PromptMessage{mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(text))}}, nil
	})
	srv.AddPrompt(mcp.NewPrompt("uapi_eval_quickstart", mcp.WithPromptDescription("Discover and safely probe the JavaScript eval API."), mcp.WithArgument("goal", mcp.ArgumentDescription("Optional task to accomplish with eval."))), func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		goal := request.Params.Arguments["goal"]
		text := "Read MCP resources uapi://agent-guide, uapi://scripting-api, and uapi://capabilities. Do not call uapi.request, sys.request, fetch, require, or import from eval. Then run a read-only eval probe: const caps = sys.capabilities(); return {name: caps.name, wrappers: caps.scripting_api.uapi_wrappers, constants: Object.keys(sys.constants().constants), uname: sys.uname()}; Use args for caller JSON, console.* for captured logs, and sys.* or uapi.* for synchronous Unix wrappers."
		if goal != "" {
			text += "\n\nGoal:\n" + goal
		}
		return &mcp.GetPromptResult{Description: "Linux UAPI eval quickstart", Messages: []mcp.PromptMessage{mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(text))}}, nil
	})
	srv.AddPrompt(mcp.NewPrompt("uapi_ptrace_memory_probe", mcp.WithPromptDescription("Use eval ptrace helpers to attach to a process and read memory safely."), mcp.WithArgument("pid", mcp.ArgumentDescription("Target PID and any known address/range context."))), func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		pid := request.Params.Arguments["pid"]
		text := "Read MCP resources uapi://agent-guide and uapi://scripting-api first. In eval, ptrace helpers pin the OS thread automatically. Attach with sys.ptraceAttach({pid, wait:true}), optionally call sys.ptraceSetOptions({pid, options:'PTRACE_O_TRACESYSGOOD'}), use sys.ptraceGetRegs({pid}) or bounded sys.ptraceRead({pid,address,length,encoding:'hex'}), then always detach with sys.ptraceDetach. Keep addresses as hex strings."
		if pid != "" {
			text += "\n\nPID/address context:\n" + pid
		}
		return &mcp.GetPromptResult{Description: "ptrace memory probing workflow", Messages: []mcp.PromptMessage{mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(text))}}, nil
	})
	srv.AddPrompt(mcp.NewPrompt("uapi_socket_fuzzing", mcp.WithPromptDescription("Build deterministic socket/client experiments with eval."), mcp.WithArgument("service", mcp.ArgumentDescription("Socket family, address, protocol, or service under test."))), func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		service := request.Params.Arguments["service"]
		text := "Read MCP resources uapi://agent-guide and uapi://scripting-api first. Use eval with sys.socket({type:'SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC'}) or sys.socketpair for local experiments, sys.poll/sys.epollWait for readiness, and sys.sendto/sys.recvfrom for payload exchange. Provide payload bytes explicitly through args, buffers, data_hex, data_base64, or data_utf8 and return per-iteration errno/result metadata."
		if service != "" {
			text += "\n\nService:\n" + service
		}
		return &mcp.GetPromptResult{Description: "socket fuzzing workflow", Messages: []mcp.PromptMessage{mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(text))}}, nil
	})
}

func (a *App) registerTools(srv *server.MCPServer) {
	for _, spec := range toolRegistry(a) {
		addTool(srv, spec.name, spec.description, spec.schema, spec.readOnly, spec.destructive, spec.handler)
	}
}

type toolSpec struct {
	name        string
	description string
	schema      string
	readOnly    bool
	destructive bool
	handler     server.ToolHandlerFunc
}

func addTool(srv *server.MCPServer, name, desc, schema string, readOnly, destructive bool, handler server.ToolHandlerFunc) {
	tool := mcp.NewToolWithRawSchema(name, desc, json.RawMessage(schema))
	tool.Annotations = mcp.ToolAnnotation{
		ReadOnlyHint:    mcp.ToBoolPtr(readOnly),
		DestructiveHint: mcp.ToBoolPtr(destructive),
		IdempotentHint:  mcp.ToBoolPtr(false),
		OpenWorldHint:   mcp.ToBoolPtr(true),
	}
	srv.AddTool(tool, handler)
}

func bind[T any](request mcp.CallToolRequest, target *T) error {
	if request.Params.Arguments == nil {
		return nil
	}
	return request.BindArguments(target)
}

func jsonResult(value any) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultJSON(value)
}

func toolError(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(err.Error()), nil
}

func syscallResult(fields map[string]any, err error) (*mcp.CallToolResult, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err == nil {
		fields["ok"] = true
		return jsonResult(fields)
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		fields["ok"] = false
		fields["errno"] = int(errno)
		fields["errno_name"] = errnoName(errno)
		fields["error"] = errno.Error()
		return jsonResult(fields)
	}
	return toolError(err)
}

func (a *App) stateSnapshot() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]any{
		"allow_raw_fd":      a.config.AllowRawFD,
		"max_read_bytes":    a.config.MaxReadBytes,
		"max_buffer_bytes":  a.config.MaxBufferBytes,
		"fds":               a.fdInfosLocked(),
		"buffers":           a.bufferInfosLocked(),
		"mappings":          a.mappingInfosLocked(),
		"roots":             rootInfosLocked(a.roots),
		"processes":         processInfosLocked(a.processes),
		"ebpf_maps":         a.ebpfMapInfosLocked(),
		"ebpf_programs":     a.ebpfProgramInfosLocked(),
		"ebpf_links":        a.ebpfLinkInfosLocked(),
		"ebpf_ring_readers": a.ebpfRingReaderInfosLocked(),
		"ebpf_perf_readers": a.ebpfPerfReaderInfosLocked(),
		"tool_storage":      a.managedToolStorageLocked(),
		"tools":             a.managedToolSummariesLocked(nil),
	}
}

func (a *App) fdInfosLocked() []fdEntry {
	infos := make([]fdEntry, 0, len(a.fds))
	for _, entry := range a.fds {
		copyEntry := *entry
		infos = append(infos, copyEntry)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Handle < infos[j].Handle })
	return infos
}

func (a *App) bufferInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.buffers))
	for _, buffer := range a.buffers {
		infos = append(infos, bufferInfo(buffer))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["name"]) < fmt.Sprint(infos[j]["name"]) })
	return infos
}

func (a *App) mappingInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.mappings))
	for _, mapping := range a.mappings {
		infos = append(infos, mappingInfo(mapping))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

func validateName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s name is required", kind)
	}
	if len(name) > 128 || !namePattern.MatchString(name) {
		return fmt.Errorf("invalid %s name %q; use 1-128 characters from A-Za-z0-9_.:-", kind, name)
	}
	return nil
}
