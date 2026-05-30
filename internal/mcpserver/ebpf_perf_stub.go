//go:build !linux || mips

package mcpserver

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func newEBPFPerfReader(eventMap *ebpf.Map, perCPUBuffer int, wakeupEvents int, watermark int, overwritable bool) (ebpfPerfReader, error) {
	return nil, fmt.Errorf("perf readers are unavailable on this target: %w", ebpf.ErrNotSupported)
}
