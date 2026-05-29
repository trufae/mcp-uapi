package mcpserver

import "testing"

func TestCapabilitiesExposeRequiredSurface(t *testing.T) {
	doc := Capabilities()
	if doc.Name != "mcp-uapi" {
		t.Fatalf("Name = %q", doc.Name)
	}
	if doc.ClientBootstrap.ScriptingAPIResource != "uapi://scripting-api" {
		t.Fatalf("scripting resource = %q", doc.ClientBootstrap.ScriptingAPIResource)
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
	for _, group := range []string{"open_flags", "at", "eventfd", "inotify", "statx", "rlimit"} {
		if _, ok := doc.Constants[group]; !ok {
			t.Fatalf("capabilities missing %s constants", group)
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
