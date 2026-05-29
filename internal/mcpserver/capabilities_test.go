package mcpserver

import (
	"strings"
	"testing"
)

func TestCapabilitiesExposeRequiredSurface(t *testing.T) {
	doc := Capabilities()
	if doc.Name != "mcp-uapi" {
		t.Fatalf("Name = %q", doc.Name)
	}
	if doc.ClientBootstrap.ScriptingAPIResource != "uapi://scripting-api" {
		t.Fatalf("scripting resource = %q", doc.ClientBootstrap.ScriptingAPIResource)
	}
	if doc.ClientBootstrap.AgentGuideResource != "uapi://agent-guide" {
		t.Fatalf("agent guide resource = %q", doc.ClientBootstrap.AgentGuideResource)
	}
	if !containsString(doc.Resources, "uapi://agent-guide") {
		t.Fatalf("capabilities missing agent guide resource: %#v", doc.Resources)
	}
	if !strings.Contains(doc.ClientBootstrap.ResourceAccess, "no uapi.request") {
		t.Fatalf("resource access guidance should reject uapi.request: %q", doc.ClientBootstrap.ResourceAccess)
	}
	if !containsString(doc.ClientBootstrap.DoNotUse, "uapi.request('GET', 'uapi://capabilities')") {
		t.Fatalf("do_not_use should include uapi.request pattern: %#v", doc.ClientBootstrap.DoNotUse)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].Name != "eval" {
		t.Fatalf("public tools = %#v, want eval only", doc.Tools)
	}
	if len(toolSummaryRegistry()) != 1 || toolSummaryRegistry()[0].name != "eval" {
		t.Fatalf("tool registry should expose only eval: %#v", toolSummaryRegistry())
	}
	if !containsString(doc.ScriptingAPI.UAPIWrappers, "socketpair") || !containsString(doc.ScriptingAPI.UAPIWrappers, "ptraceRead") {
		t.Fatalf("legacy scripting wrappers missing expected entries: %#v", doc.ScriptingAPI.UAPIWrappers)
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
	if !containsString(doc.ScriptingAPI.NotAvailable, "uapi.request") || !containsString(doc.ScriptingAPI.NotAvailable, "fetch") {
		t.Fatalf("scripting API should document unavailable request/fetch helpers: %#v", doc.ScriptingAPI.NotAvailable)
	}
	for _, group := range []string{"open_flags", "at", "eventfd", "inotify", "statx", "rlimit"} {
		if _, ok := doc.Constants[group]; !ok {
			t.Fatalf("capabilities missing %s constants", group)
		}
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
