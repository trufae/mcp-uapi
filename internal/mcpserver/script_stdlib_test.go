package mcpserver

import (
	"path/filepath"
	"testing"
)

func TestEvalStdlibOSAndIOAPI(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "source.txt")
	copyPath := filepath.Join(dir, "copy.txt")
	missingPath := filepath.Join(dir, "missing.txt")

	resp, result := callEvalForTest(t, app, map[string]any{"script": `
const missing = os.readFile({name: args.missing, encoding: "utf8"});
const wrote = os.writeFile({name: args.path, data_utf8: "hello", perm: "0600"});
const read = os.ReadFile({name: args.path, encoding: "utf8"});

const file = os.openFile({name: args.path, flag: "O_RDWR|O_APPEND", perm: "0600", handle: "stdFile"});
const appended = os.fileWriteString({handle: "stdFile", data: "!"});
const seek = os.fileSeek({handle: "stdFile", offset: 0, whence: io.SeekStart});
const all = io.readAll({src: {handle: "stdFile"}, encoding: "utf8"});
const stat = os.fileStat({handle: "stdFile"});
os.fileClose({handle: "stdFile"});

const src = os.open({name: args.path, handle: "copySrc"});
const dst = os.create({name: args.copy, handle: "copyDst"});
const copied = io.Copy({dst: {handle: "copyDst"}, src: {handle: "copySrc"}});
os.fileClose({handle: "copySrc"});
os.fileClose({handle: "copyDst"});
const copiedRead = os.readFile({name: args.copy, encoding: "utf8"});

const root = os.openRoot({name: args.dir, handle: "rooted"});
const rootWrite = os.rootWriteFile({root: "rooted", name: "inside.txt", data_utf8: "root ok", perm: "0600"});
const rootRead = os.rootReadFile({root: "rooted", name: "inside.txt", encoding: "utf8"});
const rootClose = os.rootClose({root: "rooted"});

const caps = sys.capabilities().scripting_api;
return {
  types: {os: typeof os.readFile, osAlias: typeof os.ReadFile, io: typeof io.copy, ioAlias: typeof io.Copy},
  constants: {create: os.O_CREATE, seek: io.SeekStart},
  missing, wrote, read, file, appended, seek, all, stat, copied, copiedRead, root, rootWrite, rootRead, rootClose,
  wrappers: {os: caps.os_wrappers.indexOf("readFile") >= 0, io: caps.io_wrappers.indexOf("copy") >= 0},
  state: sys.state()
};
`, "args": map[string]any{"dir": dir, "path": path, "copy": copyPath, "missing": missingPath}})
	if result.IsError || !resp.OK {
		t.Fatalf("eval failed: result=%#v resp=%#v", result, resp)
	}
	value := resp.Result.(map[string]any)
	types := nestedMap(t, value, "types")
	if types["os"] != "function" || types["osAlias"] != "function" || types["io"] != "function" || types["ioAlias"] != "function" {
		t.Fatalf("stdlib wrapper types = %#v", types)
	}
	missing := nestedMap(t, value, "missing")
	if missing["ok"] != false || missing["error_name"] != "ErrNotExist" {
		t.Fatalf("missing read should be structured ErrNotExist: %#v", missing)
	}
	for _, key := range []string{"wrote", "read", "file", "appended", "seek", "all", "stat", "copied", "copiedRead", "root", "rootWrite", "rootRead", "rootClose"} {
		requireNestedOK(t, value, key)
	}
	if got := nestedMap(t, value, "read")["data_utf8"]; got != "hello" {
		t.Fatalf("read = %#v", got)
	}
	if got := nestedMap(t, value, "all")["data_utf8"]; got != "hello!" {
		t.Fatalf("io.readAll = %#v", got)
	}
	if got := nestedMap(t, value, "copiedRead")["data_utf8"]; got != "hello!" {
		t.Fatalf("copiedRead = %#v", got)
	}
	if got := nestedMap(t, value, "rootRead")["data_utf8"]; got != "root ok" {
		t.Fatalf("rootRead = %#v", got)
	}
	wrappers := nestedMap(t, value, "wrappers")
	if wrappers["os"] != true || wrappers["io"] != true {
		t.Fatalf("capabilities missing stdlib wrappers: %#v", wrappers)
	}
	state := nestedMap(t, value, "state")
	if fds, ok := state["fds"].([]any); ok && len(fds) != 0 {
		t.Fatalf("expected script to close stdlib fds, state=%#v", state)
	}
	if roots, ok := state["roots"].([]any); ok && len(roots) != 0 {
		t.Fatalf("expected script to close stdlib roots, state=%#v", state)
	}
}
