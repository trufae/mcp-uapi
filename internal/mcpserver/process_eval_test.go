package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestProcessAndEvalPrimitives(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	uname := callToolForTest(t, app, "uapi_uname", nil)
	requireOK(t, uname)
	if stringField(t, uname, "sysname") == "" {
		t.Fatalf("empty uname: %#v", uname)
	}
	pid := callToolForTest(t, app, "uapi_getpid", nil)
	requireOK(t, pid)
	errno := callToolForTest(t, app, "uapi_errno", map[string]any{"name": "ENOENT"})
	if errno["errno_name"] != "ENOENT" {
		t.Fatalf("errno decode = %#v", errno)
	}

	cmd := exec.Command("sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	wait := callToolForTest(t, app, "uapi_wait4", map[string]any{"pid": cmd.Process.Pid, "timeout_ms": 1000})
	requireOK(t, wait)
	_ = cmd.Process.Release()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
console.log("probe", args.name);
const pair = uapi.socketpair({handles:["evalA","evalB"]});
uapi.write({handle:"evalA", data_utf8:"ok"});
const read = uapi.read({handle:"evalB", length:2, encoding:"utf8"});
uapi.close({handle:"evalA"});
uapi.close({handle:"evalB"});
const r1 = rng.local("550e8400-e29b-41d4-a716-446655440000");
const r2 = rng.local("550e8400-e29b-41d4-a716-446655440000");
return {name:uapi.capabilities().name, read:read.data_utf8, same:r1.uint64() === r2.uint64(), fixed:uapi.hex(255,4)};
`, "args": map[string]any{"name": "eval"}})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	if value["name"] != "mcp-uapi" || value["read"] != "ok" || value["same"] != true || value["fixed"] != "0x00ff" {
		t.Fatalf("unexpected eval result: %#v", value)
	}
}

func TestEvalTimeoutReturnsToolError(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()
	resp, result := callEvalForTest(t, app, map[string]any{"script": `for (;;) {}`, "timeout_ms": 10})
	if !result.IsError || resp.OK || !strings.Contains(resp.Error, "timeout_ms=10") {
		t.Fatalf("timeout result=%#v resp=%#v", result, resp)
	}
}

func TestPtraceAttachAndReadChildMemory(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(cmd.Environ(), "MCP_UAPI_PTRACE_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatalf("helper did not print pid/address: %v", scanner.Err())
	}
	parts := strings.Fields(scanner.Text())
	if len(parts) != 2 {
		t.Fatalf("helper line = %q", scanner.Text())
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatalf("parse pid: %v", err)
	}
	addr, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 64)
	if err != nil {
		t.Fatalf("parse address: %v", err)
	}
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("helper not ready")
	}

	attach := callToolForTest(t, app, "uapi_ptrace_attach", map[string]any{"pid": pid, "wait": true, "timeout_ms": 1000})
	if attach["ok"] != true {
		if attach["errno_name"] == "EPERM" || attach["errno_name"] == "EACCES" {
			t.Skipf("ptrace denied by kernel policy: %#v", attach)
		}
		t.Fatalf("ptrace attach failed: %#v", attach)
	}
	read := callToolForTest(t, app, "uapi_ptrace_read", map[string]any{"pid": pid, "address": fmt.Sprintf("0x%x", addr), "length": 20, "encoding": "utf8"})
	requireOK(t, read)
	if got := stringField(t, read, "data_utf8"); got != "mcp-uapi-ptrace-test" {
		t.Fatalf("ptrace read = %q", got)
	}
	detach := callToolForTest(t, app, "uapi_ptrace_detach", map[string]any{"pid": pid})
	requireOK(t, detach)
}

func callEvalForTest(t *testing.T, app *App, arguments map[string]any) (evalResponse, *mcp.CallToolResult) {
	t.Helper()
	result := callToolResultForTest(t, app, "eval", arguments)
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal eval response: %v", err)
	}
	var resp evalResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("unmarshal eval response: %v", err)
	}
	return resp, result
}
