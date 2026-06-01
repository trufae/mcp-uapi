package mcpserver

import (
	"runtime"
	"testing"
)

func TestSocketPollAndEpollPrimitives(t *testing.T) {
	app, _ := New(Config{})
	defer app.Close()

	pair := callToolForTest(t, app, "uapi_socketpair", map[string]any{"handles": []string{"left", "right"}})
	requireOK(t, pair)
	write := callToolForTest(t, app, "uapi_write", map[string]any{"handle": "left", "data_utf8": "ping"})
	requireOK(t, write)
	poll := callToolForTest(t, app, "uapi_poll", map[string]any{"fds": []map[string]any{{"handle": "right", "events": "POLLIN"}}, "timeout_ms": 100})
	requireOK(t, poll)
	if poll["ready"] != float64(1) {
		t.Fatalf("poll ready = %#v", poll["ready"])
	}
	read := callToolForTest(t, app, "uapi_read", map[string]any{"handle": "right", "length": 4, "encoding": "utf8"})
	requireOK(t, read)
	if got := stringField(t, read, "data_utf8"); got != "ping" {
		t.Fatalf("socket read = %q", got)
	}

	setsockopt := callToolForTest(t, app, "uapi_setsockopt_int", map[string]any{"handle": "left", "level": "SOL_SOCKET", "opt": "SO_REUSEADDR", "value": 1})
	requireOK(t, setsockopt)
	getsockopt := callToolForTest(t, app, "uapi_getsockopt_int", map[string]any{"handle": "left", "level": "SOL_SOCKET", "opt": "SO_REUSEADDR"})
	requireOK(t, getsockopt)

	if runtime.GOOS != "linux" {
		for _, handle := range []string{"left", "right"} {
			closed := callToolForTest(t, app, "uapi_close", map[string]any{"handle": handle})
			requireOK(t, closed)
		}
		return
	}

	epoll := callToolForTest(t, app, "uapi_epoll_create", map[string]any{"handle": "ep"})
	requireOK(t, epoll)
	ctl := callToolForTest(t, app, "uapi_epoll_ctl", map[string]any{"epoll_handle": "ep", "op": "EPOLL_CTL_ADD", "target_handle": "right", "events": "EPOLLIN"})
	requireOK(t, ctl)
	send := callToolForTest(t, app, "uapi_sendto", map[string]any{"handle": "left", "data_utf8": "pong"})
	requireOK(t, send)
	wait := callToolForTest(t, app, "uapi_epoll_wait", map[string]any{"epoll_handle": "ep", "max_events": 4, "timeout_ms": 100})
	requireOK(t, wait)
	if wait["ready"] != float64(1) {
		t.Fatalf("epoll ready = %#v", wait["ready"])
	}
	recv := callToolForTest(t, app, "uapi_recvfrom", map[string]any{"handle": "right", "length": 4, "encoding": "utf8"})
	requireOK(t, recv)
	if got := stringField(t, recv, "data_utf8"); got != "pong" {
		t.Fatalf("recv = %q", got)
	}

	for _, handle := range []string{"ep", "left", "right"} {
		closed := callToolForTest(t, app, "uapi_close", map[string]any{"handle": handle})
		requireOK(t, closed)
	}
}
