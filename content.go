package mcpuapi

import "embed"

// Content contains documentation and example assets embedded at build time.
//
//go:embed docs/*.md examples/*.js
var Content embed.FS
