package mcpserver

import (
	"runtime"
	"strings"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestCapabilitiesExposeRequiredSurface(t *testing.T) {
	doc := Capabilities()
	if doc.Name != "mcp-uapi" {
		t.Fatalf("Name = %q", doc.Name)
	}
	if doc.ClientBootstrap.ScriptingAPIResource != "uapi://scripting-api" {
		t.Fatalf("scripting resource = %q", doc.ClientBootstrap.ScriptingAPIResource)
	}
	if doc.ClientBootstrap.ToolsGuideResource != "uapi://tools-guide" {
		t.Fatalf("tools guide resource = %q", doc.ClientBootstrap.ToolsGuideResource)
	}
	if doc.ClientBootstrap.AgentGuideResource != "uapi://agent-guide" {
		t.Fatalf("agent guide resource = %q", doc.ClientBootstrap.AgentGuideResource)
	}
	if !containsString(doc.Resources, "uapi://agent-guide") {
		t.Fatalf("capabilities missing agent guide resource: %#v", doc.Resources)
	}
	for _, uri := range []string{"uapi://docs", "uapi://docs/index.json", "uapi://tools-guide", "uapi://examples", "uapi://examples/index.json", "uapi://examples/001-network-interfaces-ioctl.js"} {
		if !containsString(doc.Resources, uri) {
			t.Fatalf("capabilities missing resource %s: %#v", uri, doc.Resources)
		}
	}
	if doc.ClientBootstrap.DocsIndexResource != "uapi://docs" || doc.ClientBootstrap.ExamplesIndexResource != "uapi://examples" {
		t.Fatalf("unexpected docs/examples bootstrap resources: %#v", doc.ClientBootstrap)
	}
	if len(doc.Documentation) == 0 || len(doc.ExampleScripts) == 0 {
		t.Fatalf("capabilities should include documentation and example script inventories: %#v %#v", doc.Documentation, doc.ExampleScripts)
	}
	if doc.ExampleScripts[0].Name != "network_interfaces_ioctl" || doc.ExampleScripts[0].URI != "uapi://examples/001-network-interfaces-ioctl.js" || doc.ExampleScripts[0].Script != "" {
		t.Fatalf("unexpected first example summary: %#v", doc.ExampleScripts[0])
	}
	if !strings.Contains(doc.ClientBootstrap.ResourceAccess, "no uapi.request") {
		t.Fatalf("resource access guidance should reject uapi.request: %q", doc.ClientBootstrap.ResourceAccess)
	}
	if !containsString(doc.ClientBootstrap.DoNotUse, "uapi.request('GET', 'uapi://capabilities')") {
		t.Fatalf("do_not_use should include uapi.request pattern: %#v", doc.ClientBootstrap.DoNotUse)
	}
	for _, tool := range []string{"eval", "tool_register", "tool_update", "tool_execute", "tool_list", "tool_read", "tool_export", "tool_import", "tool_delete"} {
		if !containsToolSummary(doc.Tools, tool) {
			t.Fatalf("public tools missing %s: %#v", tool, doc.Tools)
		}
	}
	if !containsString(toolSpecNames(toolSummaryRegistry()), "tool_execute") {
		t.Fatalf("tool registry missing managed tool execution: %#v", toolSummaryRegistry())
	}
	if !containsString(doc.ScriptingAPI.UAPIWrappers, "socketpair") || !containsString(doc.ScriptingAPI.UAPIWrappers, "ptraceRead") {
		t.Fatalf("legacy scripting wrappers missing expected entries: %#v", doc.ScriptingAPI.UAPIWrappers)
	}
	for _, name := range []string{"readFile", "writeFile", "openRoot", "fileRead", "fileWrite", "rootReadFile"} {
		if !containsString(doc.ScriptingAPI.OSWrappers, name) {
			t.Fatalf("os scripting wrappers missing %s: %#v", name, doc.ScriptingAPI.OSWrappers)
		}
	}
	for _, name := range []string{"copy", "copyN", "readAll", "readFull", "writeString"} {
		if !containsString(doc.ScriptingAPI.IOWrappers, name) {
			t.Fatalf("io scripting wrappers missing %s: %#v", name, doc.ScriptingAPI.IOWrappers)
		}
	}
	for _, name := range []string{"dial", "listen", "listenPacket", "lookupHost", "connRead", "packetReadFrom"} {
		if !containsString(doc.ScriptingAPI.NetWrappers, name) {
			t.Fatalf("net scripting wrappers missing %s: %#v", name, doc.ScriptingAPI.NetWrappers)
		}
	}
	for _, name := range []string{"openat", "fstatat", "statx", "eventfd", "memfdCreate", "getxattr", "copyFileRange"} {
		if !containsString(doc.ScriptingAPI.UAPIWrappers, name) {
			t.Fatalf("scripting wrappers missing %s: %#v", name, doc.ScriptingAPI.UAPIWrappers)
		}
	}
	for _, global := range doc.ScriptingAPI.Globals {
		if global.Name == "rng" {
			t.Fatalf("rng global should not be documented: %#v", doc.ScriptingAPI.Globals)
		}
	}
	if !containsString(doc.ScriptingAPI.NotAvailable, "uapi.request") || !containsString(doc.ScriptingAPI.NotAvailable, "fetch") || !containsString(doc.ScriptingAPI.NotAvailable, "os.Exit/os.exit") {
		t.Fatalf("scripting API should document unavailable request/fetch helpers: %#v", doc.ScriptingAPI.NotAvailable)
	}
	for _, group := range []string{"open_flags", "at", "eventfd", "inotify", "statx", "rlimit", "go_os", "go_io", "go_net"} {
		if _, ok := doc.Constants[group]; !ok {
			t.Fatalf("capabilities missing %s constants", group)
		}
	}
}

func TestEmbeddedDocsAndExamples(t *testing.T) {
	if !strings.Contains(agentGuideMarkdown(), "uapi://examples") {
		t.Fatalf("agent guide should mention embedded examples")
	}
	if !strings.Contains(agentGuideMarkdown(), "uapi://tools-guide") || !strings.Contains(mustEmbeddedText("docs/TOOLS.md"), "tool_register") {
		t.Fatalf("managed tool documentation should be embedded and linked")
	}
	if !strings.Contains(apiReferenceMarkdown(), "# API Reference") {
		t.Fatalf("api reference should come from docs/API.md")
	}
	if !strings.Contains(scriptingAPIMarkdown(), "# Scripting API") {
		t.Fatalf("scripting API should come from docs/SCRIPTING.md")
	}

	examples := exampleScripts()
	if len(examples) == 0 {
		t.Fatalf("expected embedded example scripts")
	}
	first := examples[0]
	if first.Name != "network_interfaces_ioctl" || first.URI != "uapi://examples/001-network-interfaces-ioctl.js" {
		t.Fatalf("unexpected first example: %#v", first)
	}
	if !strings.Contains(first.Script, "SIOCGIFINDEX") || !strings.Contains(first.Script, "sys.ioctl") {
		t.Fatalf("network ioctl example missing expected ioctl code")
	}
	if !strings.Contains(examplesIndexMarkdown(), first.URI) {
		t.Fatalf("examples index should list first example")
	}
	if !strings.Contains(docsIndexMarkdown(), "uapi://api-reference") {
		t.Fatalf("docs index should list API reference")
	}
	if !strings.Contains(apiDocsIndexMarkdown(), "uapi://api/sys-unix") {
		t.Fatalf("API docs index should list sys/unix reference")
	}
}

func TestEmbeddedNetworkInterfaceExampleExecutes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("network interface example reads /proc/net/dev")
	}

	app, _ := New(Config{})
	defer app.Close()

	first := exampleScripts()[0]
	resp, result := callEvalForTest(t, app, map[string]any{"script": first.Script, "timeout_ms": 5000})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	interfaces, ok := resp.Result.([]any)
	if !ok || len(interfaces) == 0 {
		t.Fatalf("expected interface list, got %#v", resp.Result)
	}
	iface, ok := interfaces[0].(map[string]any)
	if !ok || iface["name"] == "" {
		t.Fatalf("unexpected first interface entry: %#v", interfaces[0])
	}
}

func TestEmbeddedResourcesAreReadableThroughMCP(t *testing.T) {
	app, srv := New(Config{})
	defer app.Close()

	client, err := mcpclient.NewInProcessClient(srv)
	if err != nil {
		t.Fatalf("new in-process client: %v", err)
	}
	defer client.Close()

	if err := client.Start(t.Context()); err != nil {
		t.Fatalf("start client: %v", err)
	}
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = mcp.Implementation{Name: "mcp-uapi-test", Version: "1.0.0"}
	if _, err := client.Initialize(t.Context(), initRequest); err != nil {
		t.Fatalf("initialize client: %v", err)
	}

	listedTools, err := client.ListTools(t.Context(), mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	toolNames := make([]string, 0, len(listedTools.Tools))
	for _, tool := range listedTools.Tools {
		toolNames = append(toolNames, tool.Name)
	}
	for _, name := range []string{"eval", "tool_register", "tool_execute", "tool_export", "tool_import", "tool_delete"} {
		if !containsString(toolNames, name) {
			t.Fatalf("listed tools missing %s: %#v", name, toolNames)
		}
	}

	listed, err := client.ListResources(t.Context(), mcp.ListResourcesRequest{})
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	resourceURIs := make([]string, 0, len(listed.Resources))
	for _, resource := range listed.Resources {
		resourceURIs = append(resourceURIs, resource.URI)
	}
	for _, uri := range []string{"uapi://docs", "uapi://tools-guide", "uapi://api", "uapi://api/sys-unix", "uapi://api/go-net", "uapi://examples", "uapi://examples/001-network-interfaces-ioctl.js", "uapi://examples/010-net-tcp-port-scanner.js", "uapi://examples/011-net-unix-domain-socket-echo.js"} {
		if !containsString(resourceURIs, uri) {
			t.Fatalf("listed resources missing %s: %#v", uri, resourceURIs)
		}
	}

	readRequest := mcp.ReadResourceRequest{}
	readRequest.Params.URI = "uapi://examples/001-network-interfaces-ioctl.js"
	read, err := client.ReadResource(t.Context(), readRequest)
	if err != nil {
		t.Fatalf("read example resource: %v", err)
	}
	if len(read.Contents) != 1 {
		t.Fatalf("example resource contents = %d", len(read.Contents))
	}
	text, ok := read.Contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("example resource content type = %T", read.Contents[0])
	}
	if text.MIMEType != mimeJavaScript || !strings.Contains(text.Text, "SIOCGIFINDEX") {
		t.Fatalf("unexpected example resource contents: %#v", text)
	}

	readRequest.Params.URI = "uapi://api/sys-unix"
	read, err = client.ReadResource(t.Context(), readRequest)
	if err != nil {
		t.Fatalf("read API resource: %v", err)
	}
	if len(read.Contents) != 1 {
		t.Fatalf("API resource contents = %d", len(read.Contents))
	}
	text, ok = read.Contents[0].(mcp.TextResourceContents)
	if !ok {
		t.Fatalf("API resource content type = %T", read.Contents[0])
	}
	if text.MIMEType != mimeMarkdown || !strings.Contains(text.Text, "processVMReadv") {
		t.Fatalf("unexpected API resource contents: %#v", text)
	}
}

func TestBuiltInDocsGuideAgentsAwayFromRequestHelpers(t *testing.T) {
	for name, text := range map[string]string{
		"instructions":  serverInstructions(),
		"agent guide":   agentGuideMarkdown(),
		"api reference": apiReferenceMarkdown(),
		"scripting api": scriptingAPIMarkdown(),
	} {
		if !strings.Contains(text, "uapi.request") {
			t.Fatalf("%s should mention that uapi.request is unavailable", name)
		}
		if !strings.Contains(text, "MCP resource") {
			t.Fatalf("%s should tell agents to use MCP resources outside eval", name)
		}
	}
}

func containsToolSummary(values []ToolSummary, want string) bool {
	for _, value := range values {
		if value.Name == want {
			return true
		}
	}
	return false
}

func toolSpecNames(values []toolSpec) []string {
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, value.name)
	}
	return names
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
