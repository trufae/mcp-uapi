package mcpserver

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func TestManagedToolLifecycleExecutesEvalScripts(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	registered := callToolForTest(t, app, "tool_register", map[string]any{
		"name":        "math.add",
		"description": "Add two numbers through a reusable eval script.",
		"script":      `console.info("adding", args.a, args.b); return {sum: args.a + args.b, caps: sys.capabilities().name};`,
		"input_schema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"a": map[string]any{"type": "number"}, "b": map[string]any{"type": "number"}},
		},
		"tags":        []string{"math", "demo", "math"},
		"read_only":   true,
		"destructive": false,
		"metadata":    map[string]any{"owner": "test"},
	})
	requireOK(t, registered)
	registeredTool := nestedMap(t, registered, "tool")
	if registeredTool["name"] != "math.add" || registeredTool["read_only"] != true || registeredTool["destructive"] != false {
		t.Fatalf("unexpected registered tool summary: %#v", registeredTool)
	}
	if !containsAnyString(registeredTool["tags"], "math") || len(registeredTool["tags"].([]any)) != 2 {
		t.Fatalf("tags should be normalized and deduplicated: %#v", registeredTool["tags"])
	}

	list := callToolForTest(t, app, "tool_list", map[string]any{"tags": []string{"math"}})
	requireOK(t, list)
	if list["count"] != float64(1) {
		t.Fatalf("tool_list count = %#v", list)
	}

	read := callToolForTest(t, app, "tool_read", map[string]any{"name": "math.add"})
	requireOK(t, read)
	readTool := nestedMap(t, read, "tool")
	if !strings.Contains(stringField(t, readTool, "script"), "args.a + args.b") {
		t.Fatalf("tool_read did not return script: %#v", readTool)
	}

	resp, result := callManagedToolForTest(t, app, "math.add", map[string]any{"a": 4, "b": 7})
	if result.IsError || !resp.OK {
		t.Fatalf("tool_execute failed: result=%#v resp=%#v", result, resp)
	}
	executed := resp.Result.(map[string]any)
	if executed["sum"] != float64(11) || executed["caps"] != "mcp-uapi" || len(resp.Logs) != 1 {
		t.Fatalf("unexpected execution response: %#v logs=%#v", executed, resp.Logs)
	}

	updated := callToolForTest(t, app, "tool_update", map[string]any{
		"name":        "math.add",
		"description": "Multiply two numbers through a reusable eval script.",
		"script":      `return {product: args.a * args.b};`,
		"tags":        []string{"math", "multiply"},
	})
	requireOK(t, updated)
	updatedTool := nestedMap(t, updated, "tool")
	if updatedTool["revision"] != float64(2) || !containsAnyString(updatedTool["tags"], "multiply") {
		t.Fatalf("unexpected updated summary: %#v", updatedTool)
	}

	resp, result = callManagedToolForTest(t, app, "math.add", map[string]any{"a": 4, "b": 7})
	if result.IsError || !resp.OK {
		t.Fatalf("updated tool_execute failed: result=%#v resp=%#v", result, resp)
	}
	executed = resp.Result.(map[string]any)
	if executed["product"] != float64(28) {
		t.Fatalf("unexpected updated execution response: %#v", executed)
	}

	deleted := callToolForTest(t, app, "tool_delete", map[string]any{"name": "math.add"})
	requireOK(t, deleted)
	list = callToolForTest(t, app, "tool_list", nil)
	if list["count"] != float64(0) {
		t.Fatalf("tool should be deleted: %#v", list)
	}
}

func TestManagedToolRejectsReservedAndDuplicateNames(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	result := callToolResultForTest(t, app, "tool_register", map[string]any{"name": "eval", "script": "return 1;"})
	if !result.IsError || !strings.Contains(toolResultText(result), "reserved") {
		t.Fatalf("reserved name should fail: %#v", result)
	}

	callToolForTest(t, app, "tool_register", map[string]any{"name": "demo.once", "script": "return 1;"})
	result = callToolResultForTest(t, app, "tool_register", map[string]any{"name": "demo.once", "script": "return 2;"})
	if !result.IsError || !strings.Contains(toolResultText(result), "already exists") {
		t.Fatalf("duplicate name should fail: %#v", result)
	}
}

func TestManagedToolExportImportAndTransactionalFailure(t *testing.T) {
	source, _ := New(Config{})
	defer source.Close()

	callToolForTest(t, source, "tool_register", map[string]any{"name": "tool.one", "script": "return {value: 1};", "read_only": true, "destructive": false})
	callToolForTest(t, source, "tool_register", map[string]any{"name": "tool.two", "script": "return {value: 2};"})
	exported := callToolForTest(t, source, "tool_export", map[string]any{"names": []string{"tool.two", "tool.one"}})
	if exported["schema"] != toolBundleSchema {
		t.Fatalf("unexpected export bundle: %#v", exported)
	}

	target, _ := New(Config{})
	defer target.Close()
	imported := callToolForTest(t, target, "tool_import", map[string]any{"bundle": exported})
	requireOK(t, imported)
	if imported["count"] != float64(2) {
		t.Fatalf("unexpected import result: %#v", imported)
	}
	resp, result := callManagedToolForTest(t, target, "tool.two", nil)
	if result.IsError || !resp.OK || resp.Result.(map[string]any)["value"] != float64(2) {
		t.Fatalf("imported tool did not execute: result=%#v resp=%#v", result, resp)
	}
	rawImported := callToolForTest(t, target, "tool_import", map[string]any{"tools": []map[string]any{{"name": "tool.raw", "script": "return 3;"}}})
	requireOK(t, rawImported)
	rawRead := callToolForTest(t, target, "tool_read", map[string]any{"name": "tool.raw"})
	if nestedMap(t, rawRead, "tool")["destructive"] != true {
		t.Fatalf("raw imported tools should default to destructive=true: %#v", rawRead)
	}

	failure := callToolResultForTest(t, target, "tool_import", map[string]any{"tools": []map[string]any{
		{"name": "tool.three", "script": "return 3;"},
		{"name": "tool.one", "script": "return 99;"},
	}})
	if !failure.IsError || !strings.Contains(toolResultText(failure), "already exists") {
		t.Fatalf("conflicting import should fail: %#v", failure)
	}
	list := callToolForTest(t, target, "tool_list", nil)
	if list["count"] != float64(3) {
		t.Fatalf("failed import should not mutate registry: %#v", list)
	}
	missing := callToolResultForTest(t, target, "tool_read", map[string]any{"name": "tool.three"})
	if !missing.IsError {
		t.Fatalf("transactional import should not add tool.three: %#v", missing)
	}
}

func TestManagedToolJSONDatabasePersistsAcrossRestarts(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tools.json")
	app, _, err := NewWithError(Config{ToolDatabasePath: dbPath})
	if err != nil {
		t.Fatalf("new persistent app: %v", err)
	}
	callToolForTest(t, app, "tool_register", map[string]any{"name": "persist.echo", "script": "return {message: args.message};", "timeout_ms": 1000})
	app.Close()

	restarted, _, err := NewWithError(Config{ToolDatabasePath: dbPath})
	if err != nil {
		t.Fatalf("restart persistent app: %v", err)
	}
	defer restarted.Close()

	list := callToolForTest(t, restarted, "tool_list", nil)
	requireOK(t, list)
	if list["count"] != float64(1) {
		t.Fatalf("persisted registry not loaded: %#v", list)
	}
	resp, result := callManagedToolForTest(t, restarted, "persist.echo", map[string]any{"message": "still here"})
	if result.IsError || !resp.OK || resp.Result.(map[string]any)["message"] != "still here" {
		t.Fatalf("persisted tool did not execute: result=%#v resp=%#v", result, resp)
	}
}

func TestManagedToolsThroughMCPClient(t *testing.T) {
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
	initRequest.Params.ClientInfo = mcp.Implementation{Name: "mcp-uapi-tool-test", Version: "1.0.0"}
	if _, err := client.Initialize(t.Context(), initRequest); err != nil {
		t.Fatalf("initialize client: %v", err)
	}

	registerRequest := mcp.CallToolRequest{}
	registerRequest.Params.Name = "tool_register"
	registerRequest.Params.Arguments = map[string]any{
		"name":        "client.echo",
		"script":      "return {echo: args.echo};",
		"read_only":   true,
		"destructive": false,
	}
	registered, err := client.CallTool(t.Context(), registerRequest)
	if err != nil {
		t.Fatalf("client tool_register protocol error: %v", err)
	}
	if registered.IsError {
		t.Fatalf("client tool_register tool error: %s", toolResultText(registered))
	}

	executeRequest := mcp.CallToolRequest{}
	executeRequest.Params.Name = "tool_execute"
	executeRequest.Params.Arguments = map[string]any{"name": "client.echo", "args": map[string]any{"echo": "ok"}}
	executed, err := client.CallTool(t.Context(), executeRequest)
	if err != nil {
		t.Fatalf("client tool_execute protocol error: %v", err)
	}
	data, err := json.Marshal(executed.StructuredContent)
	if err != nil {
		t.Fatalf("marshal client execution response: %v", err)
	}
	var resp evalResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal client execution response: %v", err)
	}
	if executed.IsError || !resp.OK || resp.Result.(map[string]any)["echo"] != "ok" {
		t.Fatalf("client tool_execute failed: result=%#v resp=%#v", executed, resp)
	}
}

func callManagedToolForTest(t *testing.T, app *App, name string, arguments map[string]any) (evalResponse, *mcp.CallToolResult) {
	t.Helper()
	result := callToolResultForTest(t, app, "tool_execute", map[string]any{"name": name, "args": arguments})
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal tool execution response: %v", err)
	}
	var resp evalResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal tool execution response: %v", err)
	}
	return resp, result
}
