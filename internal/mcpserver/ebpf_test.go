package mcpserver

import (
	"strings"
	"testing"
)

func TestEBPFCapabilitiesAndEmbeddedDocs(t *testing.T) {
	doc := Capabilities()
	for _, name := range []string{"ebpfInfo", "ebpfProgramLoad", "ebpfAttachKprobe", "ebpfRingbufRead", "ebpfPerfRead", "ebpfFeatureProbe"} {
		if !containsString(doc.ScriptingAPI.UAPIWrappers, name) {
			t.Fatalf("eBPF wrapper %s missing from capabilities", name)
		}
	}
	if !containsString(doc.Resources, "uapi://api/ebpf") {
		t.Fatalf("capabilities missing eBPF API resource")
	}
	if !containsString(doc.Resources, "uapi://examples/007-ebpf-socket-filter.js") {
		t.Fatalf("capabilities missing eBPF example resource")
	}
	ebpfConstants, ok := doc.Constants["ebpf"].(map[string]any)
	if !ok {
		t.Fatalf("eBPF constants missing or wrong type: %#v", doc.Constants["ebpf"])
	}
	for _, name := range []string{"BPF_F_CURRENT_CPU", "XDP_PASS", "XDP_GENERIC_MODE"} {
		if _, ok := ebpfConstants[name]; !ok {
			t.Fatalf("eBPF constants missing %s: %#v", name, ebpfConstants)
		}
	}
	if !strings.Contains(apiDocsIndexMarkdown(), "uapi://api/ebpf") {
		t.Fatalf("API docs index should list eBPF doc")
	}
	if !strings.Contains(mustEmbeddedText("docs/api/ebpf.md"), "self-contained") {
		t.Fatalf("eBPF API doc should describe self-contained authoring")
	}
	foundExample := false
	for _, example := range exampleScripts() {
		if example.URI == "uapi://examples/007-ebpf-socket-filter.js" {
			foundExample = true
			if example.Name != "ebpf_socket_filter_self_contained" || !strings.Contains(example.Script, "ebpfProgramLoad") {
				t.Fatalf("unexpected eBPF example summary: %#v", example)
			}
		}
	}
	if !foundExample {
		t.Fatalf("eBPF example script not embedded")
	}
}

func TestEBPFInfoAndDiscoveryEval(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const info = sys.ebpfInfo();
const caps = sys.capabilities();
const constants = sys.constants({group: "ebpf"}).constants;
return {
  info,
  wrappers: {
    programLoad: caps.scripting_api.uapi_wrappers.indexOf("ebpfProgramLoad") >= 0,
    attachKprobe: caps.scripting_api.uapi_wrappers.indexOf("ebpfAttachKprobe") >= 0,
    ringRead: caps.scripting_api.uapi_wrappers.indexOf("ebpfRingbufRead") >= 0,
    perfRead: caps.scripting_api.uapi_wrappers.indexOf("ebpfPerfRead") >= 0
  },
  constants: {xdpPass: constants.XDP_PASS, currentCPU: constants.BPF_F_CURRENT_CPU},
  state: sys.state()
};
`})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	info := nestedMap(t, value, "info")
	if info["ok"] != true || info["authoring_model"] == "" {
		t.Fatalf("unexpected eBPF info: %#v", info)
	}
	wrappers := nestedMap(t, value, "wrappers")
	for key, got := range wrappers {
		if got != true {
			t.Fatalf("wrapper %s missing: %#v", key, wrappers)
		}
	}
	constants := nestedMap(t, value, "constants")
	if constants["xdpPass"] != float64(2) || constants["currentCPU"] == nil {
		t.Fatalf("unexpected eBPF constants: %#v", constants)
	}
}

func TestEBPFMapWorkflowWhenPermitted(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const created = sys.ebpfMapCreate({handle: "counts", type: "array", key_size: 4, value_size: 8, max_entries: 1});
if (!created.ok) return {created, skipped: true};
let updated = null;
let looked = null;
let closed = null;
try {
  updated = sys.ebpfMapUpdate({map: "counts", key: 0, value: 42});
  looked = sys.ebpfMapLookup({map: "counts", key: 0});
} finally {
  closed = sys.ebpfMapClose({map: "counts"});
}
return {created, updated, looked, closed, state: sys.state()};
`, "timeout_ms": 5000})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	created := nestedMap(t, value, "created")
	if value["skipped"] == true || created["ok"] != true {
		if isEBPFUnavailable(created) {
			t.Skipf("eBPF map creation unavailable: %#v", created)
		}
		t.Fatalf("map create failed unexpectedly: %#v", created)
	}
	requireNestedOK(t, value, "updated")
	looked := nestedMap(t, value, "looked")
	if looked["ok"] != true || looked["value_uint"] != float64(42) {
		t.Fatalf("lookup = %#v, want value_uint 42", looked)
	}
	requireNestedOK(t, value, "closed")
	state := nestedMap(t, value, "state")
	if maps, ok := state["ebpf_maps"].([]any); ok && len(maps) != 0 {
		t.Fatalf("expected no leaked eBPF maps, state=%#v", state)
	}
}

func TestEBPFProgramKindWorkflowWhenPermitted(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const loaded = sys.ebpfProgramLoad({handle: "passAll", kind: "socket_filter_pass", log_level: "BPF_LOG_LEVEL1", log_size_start: 65536});
if (!loaded.ok) return {loaded, skipped: true};
let tested = null;
let closed = null;
try {
  tested = sys.ebpfProgramTest({program: "passAll", data_utf8: "abc", encoding: "utf8"});
} finally {
  closed = sys.ebpfProgramClose({program: "passAll"});
}
return {loaded, tested, closed, state: sys.state()};
`, "timeout_ms": 5000})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	loaded := nestedMap(t, value, "loaded")
	if value["skipped"] == true || loaded["ok"] != true {
		if isEBPFUnavailable(loaded) {
			t.Skipf("eBPF program loading unavailable: %#v", loaded)
		}
		t.Fatalf("program load failed unexpectedly: %#v", loaded)
	}
	if loaded["kind"] != "socket_filter_pass" {
		t.Fatalf("loaded kind = %#v", loaded)
	}
	requireNestedOK(t, value, "tested")
	requireNestedOK(t, value, "closed")
	state := nestedMap(t, value, "state")
	if programs, ok := state["ebpf_programs"].([]any); ok && len(programs) != 0 {
		t.Fatalf("expected no leaked eBPF programs, state=%#v", state)
	}
}

func isEBPFUnavailable(result map[string]any) bool {
	name, _ := result["errno_name"].(string)
	if name == "EPERM" || name == "EACCES" || name == "ENOSYS" {
		return true
	}
	errorName, _ := result["error_name"].(string)
	if errorName == "ErrNotSupported" || errorName == "ErrRestrictedKernel" {
		return true
	}
	errorText, _ := result["error"].(string)
	return strings.Contains(errorText, "operation not permitted") || strings.Contains(errorText, "permission denied") || strings.Contains(errorText, "not supported")
}
