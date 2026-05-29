package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/server"

	"github.com/nullsub/mcp-uapi/internal/mcpserver"
)

func main() {
	var (
		transport      = flag.String("transport", "stdio", "MCP transport: stdio or http")
		listenAddr     = flag.String("listen", "127.0.0.1:8080", "Streamable HTTP listen address")
		endpoint       = flag.String("endpoint", "/mcp", "Streamable HTTP MCP endpoint path")
		allowRawFD     = flag.Bool("allow-raw-fd", false, "Allow tools to operate on integer FDs not opened by this server")
		maxReadBytes   = flag.Uint64("max-read-bytes", 1<<20, "Maximum bytes returned by read-like tool calls")
		maxBufferBytes = flag.Uint64("max-buffer-bytes", 16<<20, "Maximum size of a managed user-space buffer or mmap region")
		showVersion    = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("mcp-uapi %s\n", mcpserver.Version)
		return
	}

	app, srv := mcpserver.New(mcpserver.Config{
		AllowRawFD:     *allowRawFD,
		MaxReadBytes:   *maxReadBytes,
		MaxBufferBytes: *maxBufferBytes,
	})
	defer app.Close()

	switch *transport {
	case "stdio":
		if err := server.ServeStdio(srv); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-uapi stdio error: %v\n", err)
			os.Exit(1)
		}
	case "http", "streamable-http":
		httpSrv := server.NewStreamableHTTPServer(
			srv,
			server.WithEndpointPath(*endpoint),
			server.WithStateful(true),
			server.WithHeartbeatInterval(30*time.Second),
			server.WithSessionIdleTTL(30*time.Minute),
		)
		log.Printf("mcp-uapi listening on http://%s%s", *listenAddr, *endpoint)
		if err := httpSrv.Start(*listenAddr); err != nil {
			log.Fatalf("mcp-uapi http error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unsupported transport %q; use stdio or http\n", *transport)
		os.Exit(2)
	}
}
