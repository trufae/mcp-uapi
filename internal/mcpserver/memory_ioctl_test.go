package mcpserver

import "testing"

func TestMemoryAndIoctlPrimitives(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	mapped := callToolForTest(t, app, "uapi_mmap", map[string]any{"length": 4096, "handle": "mem"})
	requireOK(t, mapped)
	memWrite := callToolForTest(t, app, "uapi_mem_write", map[string]any{"mapping": "mem", "offset": 8, "data_utf8": "mapped"})
	requireOK(t, memWrite)
	memRead := callToolForTest(t, app, "uapi_mem_read", map[string]any{"mapping": "mem", "offset": 8, "length": 6, "encoding": "utf8"})
	requireOK(t, memRead)
	if got := stringField(t, memRead, "data_utf8"); got != "mapped" {
		t.Fatalf("mem read = %q", got)
	}
	advise := callToolForTest(t, app, "uapi_madvise", map[string]any{"mapping": "mem", "advice": "MADV_NORMAL"})
	requireOK(t, advise)
	protect := callToolForTest(t, app, "uapi_mprotect", map[string]any{"mapping": "mem", "prot": "PROT_READ|PROT_WRITE"})
	requireOK(t, protect)
	sync := callToolForTest(t, app, "uapi_msync", map[string]any{"mapping": "mem", "flags": "MS_ASYNC"})
	requireOK(t, sync)
	unmap := callToolForTest(t, app, "uapi_munmap", map[string]any{"mapping": "mem"})
	requireOK(t, unmap)

	pair := callToolForTest(t, app, "uapi_socketpair", map[string]any{"handles": []string{"w", "r"}})
	requireOK(t, pair)
	write := callToolForTest(t, app, "uapi_write", map[string]any{"handle": "w", "data_utf8": "abc"})
	requireOK(t, write)
	buf := callToolForTest(t, app, "uapi_buffer_alloc", map[string]any{"name": "ioctl", "size": 8})
	requireOK(t, buf)
	ioctl := callToolForTest(t, app, "uapi_ioctl", map[string]any{"handle": "r", "request": "FIONREAD", "buffer": "ioctl", "buffer_length": 4})
	requireOK(t, ioctl)
	read := callToolForTest(t, app, "uapi_buffer_read", map[string]any{"name": "ioctl", "length": 4, "encoding": "hex"})
	requireOK(t, read)
	if got := stringField(t, read, "data_hex"); got != "03000000" {
		t.Fatalf("FIONREAD buffer = %q", got)
	}
}
