package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestMain(m *testing.M) {
	if os.Getenv("MCP_UAPI_PTRACE_HELPER") == "1" {
		runPtraceHelper()
		return
	}
	os.Exit(m.Run())
}

func callToolForTest(t *testing.T, app *App, name string, arguments map[string]any) map[string]any {
	t.Helper()
	handler := app.handlerForTool(name)
	if handler == nil {
		t.Fatalf("handler %s not found", name)
	}
	result, err := handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: arguments}})
	if err != nil {
		t.Fatalf("%s returned protocol error: %v", name, err)
	}
	if result.IsError {
		t.Fatalf("%s returned tool error: %s", name, toolResultText(result))
	}
	return structuredMapForTest(t, result)
}

func callToolResultForTest(t *testing.T, app *App, name string, arguments map[string]any) *mcp.CallToolResult {
	t.Helper()
	handler := app.handlerForTool(name)
	result, err := handler(context.Background(), mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: arguments}})
	if err != nil {
		t.Fatalf("%s returned protocol error: %v", name, err)
	}
	return result
}

func structuredMapForTest(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("unmarshal structured content: %v", err)
	}
	return value
}

func requireOK(t *testing.T, value map[string]any) {
	t.Helper()
	if value["ok"] != true {
		t.Fatalf("result ok=false: %#v", value)
	}
}

func stringField(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	text, ok := value[key].(string)
	if !ok {
		t.Fatalf("%s = %#v, want string", key, value[key])
	}
	return text
}
