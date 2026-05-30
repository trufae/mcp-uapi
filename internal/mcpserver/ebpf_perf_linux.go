//go:build linux && !mips

package mcpserver

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type ciliumPerfReader struct {
	reader *perf.Reader
}

func newEBPFPerfReader(eventMap *ebpf.Map, perCPUBuffer int, wakeupEvents int, watermark int, overwritable bool) (ebpfPerfReader, error) {
	reader, err := perf.NewReaderWithOptions(eventMap, perCPUBuffer, perf.ReaderOptions{
		WakeupEvents: wakeupEvents,
		Watermark:    watermark,
		Overwritable: overwritable,
	})
	if err != nil {
		return nil, err
	}
	return &ciliumPerfReader{reader: reader}, nil
}

func (r *ciliumPerfReader) Close() error {
	return r.reader.Close()
}

func (r *ciliumPerfReader) SetDeadline(t time.Time) {
	r.reader.SetDeadline(t)
}

func (r *ciliumPerfReader) Read() (ebpfPerfRecord, error) {
	record, err := r.reader.Read()
	return ebpfPerfRecord{
		CPU:         record.CPU,
		RawSample:   record.RawSample,
		LostSamples: record.LostSamples,
		Remaining:   record.Remaining,
	}, err
}

func (r *ciliumPerfReader) Pause() error {
	return r.reader.Pause()
}

func (r *ciliumPerfReader) Resume() error {
	return r.reader.Resume()
}

func (r *ciliumPerfReader) Flush() error {
	return r.reader.Flush()
}

func (r *ciliumPerfReader) BufferSize() int {
	return r.reader.BufferSize()
}
