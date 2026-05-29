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
	wantTools := map[string]bool{
		"uapi_capabilities": false,
		"uapi_open":         false,
		"uapi_socketpair":   false,
		"uapi_mmap":         false,
		"uapi_ioctl":        false,
		"uapi_ptrace_read":  false,
		"eval":              false,
	}
	for _, tool := range doc.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, found := range wantTools {
		if !found {
			t.Fatalf("capabilities missing tool %s", name)
		}
	}
	if !containsString(doc.ScriptingAPI.UAPIWrappers, "socketpair") || !containsString(doc.ScriptingAPI.UAPIWrappers, "ptraceRead") {
		t.Fatalf("scripting wrappers missing expected entries: %#v", doc.ScriptingAPI.UAPIWrappers)
	}
	if _, ok := doc.Constants["open_flags"]; !ok {
		t.Fatalf("capabilities missing open_flags constants")
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
