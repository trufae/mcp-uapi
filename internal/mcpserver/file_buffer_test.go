package mcpserver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileAndBufferPrimitives(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	buffer := callToolForTest(t, app, "uapi_buffer_alloc", map[string]any{"name": "payload", "size": 32})
	requireOK(t, buffer)
	writeBuffer := callToolForTest(t, app, "uapi_buffer_write", map[string]any{"name": "payload", "data_utf8": "hello-uapi"})
	requireOK(t, writeBuffer)
	readBuffer := callToolForTest(t, app, "uapi_buffer_read", map[string]any{"name": "payload", "length": 10, "encoding": "utf8"})
	requireOK(t, readBuffer)
	if got := stringField(t, readBuffer, "data_utf8"); got != "hello-uapi" {
		t.Fatalf("buffer read = %q", got)
	}

	path := filepath.Join(t.TempDir(), "sample.bin")
	opened := callToolForTest(t, app, "uapi_open", map[string]any{"path": path, "flags": "O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC", "mode": "0600", "handle": "file"})
	requireOK(t, opened)
	written := callToolForTest(t, app, "uapi_write", map[string]any{"handle": "file", "buffer": "payload", "length": 10})
	requireOK(t, written)
	if written["bytes_written"] != float64(10) {
		t.Fatalf("bytes_written = %#v", written["bytes_written"])
	}
	seek := callToolForTest(t, app, "uapi_lseek", map[string]any{"handle": "file", "offset": 0, "whence": "SEEK_SET"})
	requireOK(t, seek)
	read := callToolForTest(t, app, "uapi_read", map[string]any{"handle": "file", "length": 10, "encoding": "utf8"})
	requireOK(t, read)
	if got := stringField(t, read, "data_utf8"); got != "hello-uapi" {
		t.Fatalf("file read = %q", got)
	}
	pwrite := callToolForTest(t, app, "uapi_pwrite", map[string]any{"handle": "file", "offset": 6, "data_utf8": "unix"})
	requireOK(t, pwrite)
	pread := callToolForTest(t, app, "uapi_pread", map[string]any{"handle": "file", "offset": 0, "length": 10, "encoding": "utf8"})
	requireOK(t, pread)
	if got := stringField(t, pread, "data_utf8"); got != "hello-unix" {
		t.Fatalf("pread = %q", got)
	}
	fstat := callToolForTest(t, app, "uapi_fstat", map[string]any{"handle": "file"})
	requireOK(t, fstat)
	stat := callToolForTest(t, app, "uapi_stat", map[string]any{"path": path})
	requireOK(t, stat)
	closed := callToolForTest(t, app, "uapi_close", map[string]any{"handle": "file"})
	requireOK(t, closed)

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	readlink := callToolForTest(t, app, "uapi_readlink", map[string]any{"path": link})
	requireOK(t, readlink)
	if got := stringField(t, readlink, "target"); got != path {
		t.Fatalf("readlink = %q, want %q", got, path)
	}
	freed := callToolForTest(t, app, "uapi_buffer_free", map[string]any{"name": "payload"})
	requireOK(t, freed)
}
