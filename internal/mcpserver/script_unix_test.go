package mcpserver

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEvalExpandedUnixFileAndXattrAPI(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "target.link")
	renamed := filepath.Join(dir, "renamed.txt")

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const fd = sys.openat({path: args.path, flags: "O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC", mode: "0600", handle: "scriptFile"});
sys.write({handle: "scriptFile", data_utf8: "hello unix"});
const fstatat = sys.fstatat({path: args.path});
const statx = sys.statx({path: args.path, mask: "STATX_BASIC_STATS"});
const access = sys.access({path: args.path, mode: "R_OK|W_OK"});
const dup = sys.dup({handle: "scriptFile", new_handle: "scriptDup"});
const flags = sys.fcntlInt({handle: "scriptDup", cmd: "F_GETFL"});
sys.close({handle: "scriptDup"});
const symlink = sys.symlink({oldpath: args.path, newpath: args.link});
const target = sys.readlinkat({path: args.link});
const setxattr = sys.setxattr({path: args.path, name: "user.mcp_uapi", data_utf8: "ok"});
let getxattr = null;
let listxattr = null;
if (setxattr.ok) {
  getxattr = sys.getxattr({path: args.path, name: "user.mcp_uapi", encoding: "utf8"});
  listxattr = sys.listxattr({path: args.path});
}
const rename = sys.renameat2({oldpath: args.path, newpath: args.renamed});
const renamedStat = sys.fstatat({path: args.renamed});
sys.close({handle: "scriptFile"});
return {fd, fstatat, statx, access, dup, flags, symlink, target, setxattr, getxattr, listxattr, rename, renamedStat};
`, "args": map[string]any{"path": path, "link": link, "renamed": renamed}})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	for _, key := range []string{"fd", "fstatat", "statx", "access", "dup", "flags", "symlink", "target", "rename", "renamedStat"} {
		requireNestedOK(t, value, key)
	}
	if target := nestedMap(t, value, "target")["target"]; target != path {
		t.Fatalf("readlinkat target = %#v, want %q", target, path)
	}
	setxattr := nestedMap(t, value, "setxattr")
	if setxattr["ok"] == true {
		getxattr := nestedMap(t, value, "getxattr")
		if getxattr["data_utf8"] != "ok" {
			t.Fatalf("getxattr = %#v", getxattr)
		}
		listxattr := nestedMap(t, value, "listxattr")
		if !containsAnyString(listxattr["names"], "user.mcp_uapi") {
			t.Fatalf("listxattr names = %#v", listxattr["names"])
		}
	} else if !containsString([]string{"ENOTSUP", "EOPNOTSUPP", "EPERM", "EACCES"}, stringField(t, setxattr, "errno_name")) {
		t.Fatalf("setxattr failed unexpectedly: %#v", setxattr)
	}
}

func TestEvalExpandedUnixEventTransferAndPipeAPI(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const eventfd = sys.eventfd({init: 1, flags: "EFD_CLOEXEC|EFD_NONBLOCK", handle: "evt"});
const pipe = sys.pipe2({flags: "O_CLOEXEC|O_NONBLOCK", handles: ["pipeR", "pipeW"]});
sys.write({handle: "pipeW", data_utf8: "pipe"});
const pipeRead = sys.read({handle: "pipeR", length: 4, encoding: "utf8"});
const nonblock = sys.setNonblock({handle: "pipeR", nonblocking: true});
sys.close({handle: "pipeR"});
sys.close({handle: "pipeW"});

const src = sys.memfdCreate({name: "src", flags: "MFD_CLOEXEC", handle: "src"});
const dst = sys.memfdCreate({name: "dst", flags: "MFD_CLOEXEC", handle: "dst"});
let copied = null;
let copiedRead = null;
if (src.ok && dst.ok) {
  sys.write({handle: "src", data_utf8: "copy!"});
  copied = sys.copyFileRange({read_handle: "src", write_handle: "dst", read_offset: 0, write_offset: 0, length: 5});
  copiedRead = sys.pread({handle: "dst", offset: 0, length: 5, encoding: "utf8"});
  sys.close({handle: "src"});
  sys.close({handle: "dst"});
} else {
	if (src.ok) sys.close({handle: "src"});
	if (dst.ok) sys.close({handle: "dst"});
}
if (eventfd.ok) sys.close({handle: "evt"});
return {eventfd, pipe, pipeRead, nonblock, src, dst, copied, copiedRead, state: sys.state()};
`})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	for _, key := range []string{"eventfd", "pipe", "pipeRead", "nonblock"} {
		requireNestedOK(t, value, key)
	}
	if got := nestedMap(t, value, "pipeRead")["data_utf8"]; got != "pipe" {
		t.Fatalf("pipe read = %#v", got)
	}
	src := nestedMap(t, value, "src")
	dst := nestedMap(t, value, "dst")
	if src["ok"] == true && dst["ok"] == true {
		requireNestedOK(t, value, "copied")
		requireNestedOK(t, value, "copiedRead")
		if got := nestedMap(t, value, "copiedRead")["data_utf8"]; got != "copy!" {
			t.Fatalf("copyFileRange read = %#v", got)
		}
	} else if !knownUnsupportedSyscall(src) && !knownUnsupportedSyscall(dst) {
		t.Fatalf("memfdCreate failed unexpectedly: src=%#v dst=%#v", src, dst)
	}
	state := nestedMap(t, value, "state")
	if fds, ok := state["fds"].([]any); ok && len(fds) != 0 {
		t.Fatalf("expected eval script to close managed fds, state=%#v", state)
	}
}

func TestEvalRejectsRNGAndRandomFill(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
if (typeof rng !== "undefined") {
  throw new Error("rng should not be exposed");
}
sys.bufferAlloc({name: "payload", size: 4});
sys.bufferWrite({name: "payload", fill: {mode: "random", length: 4}});
`})
	if !result.IsError || resp.OK || !strings.Contains(resp.Error, "unsupported fill mode") {
		t.Fatalf("random fill should fail without RNG support: result=%#v resp=%#v", result, resp)
	}
}

func requireNestedOK(t *testing.T, value map[string]any, key string) {
	t.Helper()
	nested := nestedMap(t, value, key)
	if nested["ok"] != true {
		t.Fatalf("%s ok=false: %#v", key, nested)
	}
}

func nestedMap(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	nested, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, value[key])
	}
	return nested
}

func containsAnyString(value any, want string) bool {
	switch values := value.(type) {
	case []any:
		for _, item := range values {
			if item == want {
				return true
			}
		}
	case []string:
		return containsString(values, want)
	}
	return false
}

func knownUnsupportedSyscall(value map[string]any) bool {
	if value["ok"] == true {
		return false
	}
	errno, _ := value["errno_name"].(string)
	return containsString([]string{"ENOSYS", "EINVAL", "EPERM", "EACCES"}, errno)
}
