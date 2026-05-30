package mcpserver

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dop251/goja"
	"golang.org/x/sys/unix"
)

type ebpfMapEntry struct {
	Handle     string
	Name       string
	Map        *cebpf.Map
	PinnedPath string
}

type ebpfProgramEntry struct {
	Handle      string
	Name        string
	Kind        string
	Program     *cebpf.Program
	PinnedPath  string
	VerifierLog string
}

type ebpfLinkEntry struct {
	Handle     string
	Kind       string
	Link       link.Link
	PinnedPath string
	Meta       map[string]any
}

type ebpfRingReaderEntry struct {
	Handle string
	Map    string
	Reader *ringbuf.Reader
}

type ebpfPerfReaderEntry struct {
	Handle string
	Map    string
	Reader ebpfPerfReader
}

type ebpfPerfRecord struct {
	CPU         int
	RawSample   []byte
	LostSamples uint64
	Remaining   int
}

type ebpfPerfReader interface {
	Close() error
	SetDeadline(time.Time)
	Read() (ebpfPerfRecord, error)
	Pause() error
	Resume() error
	Flush() error
	BufferSize() int
}

type ebpfMapCreateArgs struct {
	Handle     string      `json:"handle"`
	Name       string      `json:"name"`
	Type       any         `json:"type"`
	KeySize    Uint32      `json:"key_size"`
	ValueSize  Uint32      `json:"value_size"`
	MaxEntries Uint32      `json:"max_entries"`
	Flags      ConstUint64 `json:"flags"`
	NumaNode   Uint32      `json:"numa_node"`
	PinPath    string      `json:"pin_path"`
}

type ebpfPinnedArgs struct {
	Path      string      `json:"path"`
	Handle    string      `json:"handle"`
	ReadOnly  bool        `json:"read_only"`
	WriteOnly bool        `json:"write_only"`
	Flags     ConstUint64 `json:"flags"`
}

type ebpfMapRefArgs struct {
	Map string `json:"map"`
}

type ebpfMapInfoArgs struct {
	Map string `json:"map"`
}

type ebpfMapPinArgs struct {
	Map  string `json:"map"`
	Path string `json:"path"`
}

type ebpfMapKeyArgs struct {
	Map       string `json:"map"`
	Key       any    `json:"key"`
	KeyBase64 string `json:"key_base64"`
	KeyHex    string `json:"key_hex"`
	KeyUTF8   string `json:"key_utf8"`
	Encoding  string `json:"encoding"`
}

type ebpfMapUpdateArgs struct {
	Map          string      `json:"map"`
	Key          any         `json:"key"`
	KeyBase64    string      `json:"key_base64"`
	KeyHex       string      `json:"key_hex"`
	KeyUTF8      string      `json:"key_utf8"`
	Value        any         `json:"value"`
	ValueBase64  string      `json:"value_base64"`
	ValueHex     string      `json:"value_hex"`
	ValueUTF8    string      `json:"value_utf8"`
	ValueBuffer  string      `json:"value_buffer"`
	Buffer       string      `json:"buffer"`
	BufferOffset Uint64      `json:"buffer_offset"`
	Length       Uint64      `json:"length"`
	ValueMap     string      `json:"value_map"`
	ValueProgram string      `json:"value_program"`
	Flags        ConstUint64 `json:"flags"`
}

type ebpfMapEntriesArgs struct {
	Map        string `json:"map"`
	MaxEntries Uint64 `json:"max_entries"`
	Encoding   string `json:"encoding"`
}

type ebpfProgramLoadArgs struct {
	Handle       string      `json:"handle"`
	Name         string      `json:"name"`
	Kind         string      `json:"kind"`
	Type         any         `json:"type"`
	AttachType   any         `json:"attach_type"`
	AttachTo     string      `json:"attach_to"`
	Ifindex      Uint32      `json:"ifindex"`
	Flags        ConstUint64 `json:"flags"`
	License      string      `json:"license"`
	ReturnValue  any         `json:"return_value"`
	CounterMap   string      `json:"counter_map"`
	CounterKey   any         `json:"counter_key"`
	EventMap     string      `json:"event_map"`
	PidNSDev     Uint64      `json:"pidns_dev"`
	PidNSIno     Uint64      `json:"pidns_ino"`
	LogLevel     ConstUint64 `json:"log_level"`
	LogSizeStart Uint32      `json:"log_size_start"`
	LogDisabled  bool        `json:"log_disabled"`
}

type ebpfProgramRefArgs struct {
	Program string `json:"program"`
}

type ebpfProgramInfoArgs struct {
	Program string `json:"program"`
}

type ebpfProgramPinArgs struct {
	Program string `json:"program"`
	Path    string `json:"path"`
}

type ebpfProgramTestArgs struct {
	Program    string `json:"program"`
	DataBase64 string `json:"data_base64"`
	DataHex    string `json:"data_hex"`
	DataUTF8   string `json:"data_utf8"`
	Encoding   string `json:"encoding"`
}

type ebpfSocketFilterArgs struct {
	Program string `json:"program"`
	ScriptFDRefArgs
}

type ebpfLinkPinnedArgs struct {
	Path      string      `json:"path"`
	Handle    string      `json:"handle"`
	ReadOnly  bool        `json:"read_only"`
	WriteOnly bool        `json:"write_only"`
	Flags     ConstUint64 `json:"flags"`
}

type ebpfLinkRefArgs struct {
	Link string `json:"link"`
}

type ebpfLinkInfoArgs struct {
	Link string `json:"link"`
}

type ebpfLinkPinArgs struct {
	Link string `json:"link"`
	Path string `json:"path"`
}

type ebpfLinkUpdateArgs struct {
	Link    string      `json:"link"`
	Program string      `json:"program"`
	Flags   ConstUint64 `json:"flags"`
}

type ebpfAttachKprobeArgs struct {
	Handle            string `json:"handle"`
	Program           string `json:"program"`
	Symbol            string `json:"symbol"`
	Cookie            Uint64 `json:"cookie"`
	Offset            Uint64 `json:"offset"`
	RetprobeMaxActive Uint32 `json:"retprobe_max_active"`
	TraceFSPrefix     string `json:"tracefs_prefix"`
}

type ebpfAttachTracepointArgs struct {
	Handle  string `json:"handle"`
	Program string `json:"program"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Cookie  Uint64 `json:"cookie"`
}

type ebpfAttachRawTracepointArgs struct {
	Handle  string `json:"handle"`
	Program string `json:"program"`
	Name    string `json:"name"`
}

type ebpfAttachXDPArgs struct {
	Handle    string      `json:"handle"`
	Program   string      `json:"program"`
	Interface Uint32      `json:"interface"`
	Ifindex   Uint32      `json:"ifindex"`
	Flags     ConstUint64 `json:"flags"`
}

type ebpfReaderCreateArgs struct {
	Handle string `json:"handle"`
	Map    string `json:"map"`
}

type ebpfRingReaderRefArgs struct {
	Reader string `json:"reader"`
}

type ebpfPerfReaderRefArgs struct {
	Reader string `json:"reader"`
}

type ebpfReaderReadArgs struct {
	Reader    string `json:"reader"`
	TimeoutMS Uint32 `json:"timeout_ms"`
	Encoding  string `json:"encoding"`
}

type ebpfPerfReaderCreateArgs struct {
	Handle       string `json:"handle"`
	Map          string `json:"map"`
	PerCPUBuffer Uint32 `json:"per_cpu_buffer"`
	WakeupEvents Uint32 `json:"wakeup_events"`
	Watermark    Uint32 `json:"watermark"`
	Overwritable bool   `json:"overwritable"`
}

type ebpfFeatureProbeArgs struct {
	Kind        string `json:"kind"`
	Type        any    `json:"type"`
	ProgramType any    `json:"program_type"`
	Helper      any    `json:"helper"`
	Name        string `json:"name"`
}

type ebpfBTFKernelArgs struct {
	Module string `json:"module"`
	Name   string `json:"name"`
	Limit  Uint32 `json:"limit"`
}

func (e *scriptEnv) addScriptEBPFExtensions(obj *goja.Object) {
	methods := map[string]scriptMethod{
		"ebpfInfo":                      e.scriptEBPFInfo,
		"ebpfRemoveMemlock":             e.scriptEBPFRemoveMemlock,
		"ebpfFeatureProbe":              e.scriptEBPFFeatureProbe,
		"ebpfBTFKernelInfo":             e.scriptEBPFBTFKernelInfo,
		"ebpfMapCreate":                 e.scriptEBPFMapCreate,
		"ebpfMapLoadPinned":             e.scriptEBPFMapLoadPinned,
		"ebpfMapClose":                  e.scriptEBPFMapClose,
		"ebpfMapInfo":                   e.scriptEBPFMapInfo,
		"ebpfMapLookup":                 e.scriptEBPFMapLookup,
		"ebpfMapUpdate":                 e.scriptEBPFMapUpdate,
		"ebpfMapDelete":                 e.scriptEBPFMapDelete,
		"ebpfMapNextKey":                e.scriptEBPFMapNextKey,
		"ebpfMapEntries":                e.scriptEBPFMapEntries,
		"ebpfMapPin":                    e.scriptEBPFMapPin,
		"ebpfMapUnpin":                  e.scriptEBPFMapUnpin,
		"ebpfMapFreeze":                 e.scriptEBPFMapFreeze,
		"ebpfProgramLoad":               e.scriptEBPFProgramLoad,
		"ebpfProgramLoadPinned":         e.scriptEBPFProgramLoadPinned,
		"ebpfProgramClose":              e.scriptEBPFProgramClose,
		"ebpfProgramInfo":               e.scriptEBPFProgramInfo,
		"ebpfProgramTest":               e.scriptEBPFProgramTest,
		"ebpfProgramPin":                e.scriptEBPFProgramPin,
		"ebpfProgramUnpin":              e.scriptEBPFProgramUnpin,
		"ebpfProgramAttachSocketFilter": e.scriptEBPFProgramAttachSocketFilter,
		"ebpfAttachSocketFilter":        e.scriptEBPFProgramAttachSocketFilter,
		"ebpfSocketFilterDetach":        e.scriptEBPFSocketFilterDetach,
		"ebpfLinkLoadPinned":            e.scriptEBPFLinkLoadPinned,
		"ebpfLinkClose":                 e.scriptEBPFLinkClose,
		"ebpfLinkInfo":                  e.scriptEBPFLinkInfo,
		"ebpfLinkPin":                   e.scriptEBPFLinkPin,
		"ebpfLinkUnpin":                 e.scriptEBPFLinkUnpin,
		"ebpfLinkDetach":                e.scriptEBPFLinkDetach,
		"ebpfLinkUpdate":                e.scriptEBPFLinkUpdate,
		"ebpfAttachKprobe":              e.scriptEBPFAttachKprobe,
		"ebpfAttachKretprobe":           e.scriptEBPFAttachKretprobe,
		"ebpfAttachTracepoint":          e.scriptEBPFAttachTracepoint,
		"ebpfAttachRawTracepoint":       e.scriptEBPFAttachRawTracepoint,
		"ebpfAttachXDP":                 e.scriptEBPFAttachXDP,
		"ebpfRingbufReaderCreate":       e.scriptEBPFRingReaderCreate,
		"ebpfRingbufRead":               e.scriptEBPFRingRead,
		"ebpfRingbufInfo":               e.scriptEBPFRingReaderInfo,
		"ebpfRingbufFlush":              e.scriptEBPFRingReaderFlush,
		"ebpfRingbufClose":              e.scriptEBPFRingReaderClose,
		"ebpfPerfReaderCreate":          e.scriptEBPFPerfReaderCreate,
		"ebpfPerfRead":                  e.scriptEBPFPerfRead,
		"ebpfPerfReaderInfo":            e.scriptEBPFPerfReaderInfo,
		"ebpfPerfReaderPause":           e.scriptEBPFPerfReaderPause,
		"ebpfPerfReaderResume":          e.scriptEBPFPerfReaderResume,
		"ebpfPerfReaderFlush":           e.scriptEBPFPerfReaderFlush,
		"ebpfPerfReaderClose":           e.scriptEBPFPerfReaderClose,
	}
	for name, method := range methods {
		e.setScriptMethod(obj, name, method)
	}
}

func scriptEBPFExtensionNames() []string {
	return []string{
		"ebpfInfo", "ebpfRemoveMemlock", "ebpfFeatureProbe", "ebpfBTFKernelInfo",
		"ebpfMapCreate", "ebpfMapLoadPinned", "ebpfMapClose", "ebpfMapInfo", "ebpfMapLookup", "ebpfMapUpdate", "ebpfMapDelete", "ebpfMapNextKey", "ebpfMapEntries", "ebpfMapPin", "ebpfMapUnpin", "ebpfMapFreeze",
		"ebpfProgramLoad", "ebpfProgramLoadPinned", "ebpfProgramClose", "ebpfProgramInfo", "ebpfProgramTest", "ebpfProgramPin", "ebpfProgramUnpin", "ebpfProgramAttachSocketFilter", "ebpfAttachSocketFilter", "ebpfSocketFilterDetach",
		"ebpfLinkLoadPinned", "ebpfLinkClose", "ebpfLinkInfo", "ebpfLinkPin", "ebpfLinkUnpin", "ebpfLinkDetach", "ebpfLinkUpdate", "ebpfAttachKprobe", "ebpfAttachKretprobe", "ebpfAttachTracepoint", "ebpfAttachRawTracepoint", "ebpfAttachXDP",
		"ebpfRingbufReaderCreate", "ebpfRingbufRead", "ebpfRingbufInfo", "ebpfRingbufFlush", "ebpfRingbufClose", "ebpfPerfReaderCreate", "ebpfPerfRead", "ebpfPerfReaderInfo", "ebpfPerfReaderPause", "ebpfPerfReaderResume", "ebpfPerfReaderFlush", "ebpfPerfReaderClose",
	}
}

func (e *scriptEnv) scriptEBPFInfo(value goja.Value) (any, error) {
	fields := map[string]any{
		"ok":                  true,
		"library":             "github.com/cilium/ebpf",
		"runtime":             runtime.GOOS + "/" + runtime.GOARCH,
		"supported_goos":      []string{"linux"},
		"supported_targets":   supportedEBPFTargets(),
		"program_kinds":       []string{"return", "counter", "perf_event", "ringbuf_event", "socket_filter_pass", "socket_filter_drop"},
		"authoring_model":     "self-contained JavaScript program kinds compiled to eBPF instructions inside the MCP binary; no C compiler, clang, bpftool, external assembler, or ELF loader is required",
		"map_wrappers":        []string{"ebpfMapCreate", "ebpfMapLoadPinned", "ebpfMapLookup", "ebpfMapUpdate", "ebpfMapDelete", "ebpfMapNextKey", "ebpfMapEntries", "ebpfMapPin", "ebpfMapUnpin", "ebpfMapFreeze", "ebpfMapClose"},
		"program_wrappers":    []string{"ebpfProgramLoad", "ebpfProgramLoadPinned", "ebpfProgramTest", "ebpfAttachSocketFilter", "ebpfSocketFilterDetach", "ebpfProgramPin", "ebpfProgramUnpin", "ebpfProgramClose"},
		"link_wrappers":       []string{"ebpfAttachKprobe", "ebpfAttachKretprobe", "ebpfAttachTracepoint", "ebpfAttachRawTracepoint", "ebpfAttachXDP", "ebpfLinkLoadPinned", "ebpfLinkInfo", "ebpfLinkUpdate", "ebpfLinkPin", "ebpfLinkUnpin", "ebpfLinkDetach", "ebpfLinkClose"},
		"monitor_wrappers":    []string{"ebpfRingbufReaderCreate", "ebpfRingbufRead", "ebpfRingbufFlush", "ebpfRingbufClose", "ebpfPerfReaderCreate", "ebpfPerfRead", "ebpfPerfReaderPause", "ebpfPerfReaderResume", "ebpfPerfReaderFlush", "ebpfPerfReaderClose"},
		"kernel_requirements": []string{"Linux kernel with the bpf syscall and enabled eBPF support", "CAP_BPF/CAP_SYS_ADMIN or unprivileged eBPF policy allowing the requested operation", "sufficient RLIMIT_MEMLOCK on kernels that account BPF objects against memlock", "bpffs mounted when using pin or load-pinned helpers"},
	}
	if cpus, err := cebpf.PossibleCPU(); err == nil {
		fields["possible_cpus"] = cpus
	} else {
		fields["possible_cpus_error"] = err.Error()
	}
	return fields, nil
}

func (e *scriptEnv) scriptEBPFMapCreate(value goja.Value) (any, error) {
	var args ebpfMapCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	typ, err := parseEBPFMapType(args.Type)
	if err != nil {
		return nil, err
	}
	if args.KeySize == 0 && !ebpfMapTypeAllowsZeroKey(typ) {
		return nil, fmt.Errorf("key_size must be greater than zero for %s", typ)
	}
	if args.ValueSize == 0 && ebpfMapTypeRequiresValueSize(typ) {
		return nil, fmt.Errorf("value_size must be greater than zero for %s", typ)
	}
	if args.MaxEntries == 0 {
		return nil, fmt.Errorf("max_entries must be greater than zero")
	}
	spec := &cebpf.MapSpec{Name: args.Name, Type: typ, KeySize: uint32(args.KeySize), ValueSize: uint32(args.ValueSize), MaxEntries: uint32(args.MaxEntries), Flags: uint32(args.Flags), NumaNode: uint32(args.NumaNode)}
	var opts cebpf.MapOptions
	if args.PinPath != "" {
		spec.Pinning = cebpf.PinByName
		opts.PinPath = args.PinPath
	}
	m, err := cebpf.NewMapWithOptions(spec, opts)
	fields := map[string]any{"name": args.Name, "type": typ.String(), "type_value": uint32(typ), "key_size": uint32(args.KeySize), "value_size": uint32(args.ValueSize), "max_entries": uint32(args.MaxEntries), "flags": uint32(args.Flags)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFMap(m, args.Handle, args.Name, pinnedPathForName(args.PinPath, args.Name))
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	fields["map"] = ebpfMapInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFMapLoadPinned(value goja.Value) (any, error) {
	var args ebpfPinnedArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	m, err := cebpf.LoadPinnedMap(args.Path, &cebpf.LoadPinOptions{ReadOnly: args.ReadOnly, WriteOnly: args.WriteOnly, Flags: uint32(args.Flags)})
	fields := map[string]any{"path": args.Path, "read_only": args.ReadOnly, "write_only": args.WriteOnly, "flags": uint32(args.Flags)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFMap(m, args.Handle, "", args.Path)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	fields["map"] = ebpfMapInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFMapClose(value goja.Value) (any, error) {
	var args ebpfMapRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	closeErr := entry.Map.Close()
	if closeErr == nil {
		e.app.removeEBPFMap(args.Map)
	}
	return ebpfScriptResult(map[string]any{"map": args.Map, "fd": entry.Map.FD(), "closed": closeErr == nil}, closeErr)
}

func (e *scriptEnv) scriptEBPFMapInfo(value goja.Value) (any, error) {
	var args ebpfMapInfoArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Map == "" {
		return map[string]any{"ok": true, "maps": e.app.ebpfMapInfos()}, nil
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	info := ebpfMapInfo(entry)
	if err := addKernelMapInfo(info, entry.Map); err != nil {
		return ebpfScriptResult(info, err)
	}
	info["ok"] = true
	return info, nil
}

func (e *scriptEnv) scriptEBPFMapLookup(value goja.Value) (any, error) {
	var args ebpfMapKeyArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	key, keyBytes, err := e.ebpfKeyBytes(entry.Map, args.Key, args.KeyBase64, args.KeyHex, args.KeyUTF8, false)
	if err != nil {
		return nil, err
	}
	data, err := entry.Map.LookupBytes(key)
	fields := map[string]any{"map": args.Map, "fd": entry.Map.FD(), "key_hex": hex.EncodeToString(keyBytes)}
	addNativeUintField(fields, "key", keyBytes)
	if err == nil && data == nil {
		err = cebpf.ErrKeyNotExist
	}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	if err := addEBPFEncodedBytes(fields, data, args.Encoding); err != nil {
		return nil, err
	}
	addNativeUintField(fields, "value", data)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFMapUpdate(value goja.Value) (any, error) {
	var args ebpfMapUpdateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	key, keyBytes, err := e.ebpfKeyBytes(entry.Map, args.Key, args.KeyBase64, args.KeyHex, args.KeyUTF8, false)
	if err != nil {
		return nil, err
	}
	valueArg, valueBytes, valueRef, err := e.ebpfUpdateValue(entry.Map, args)
	if err != nil {
		return nil, err
	}
	flags := cebpf.MapUpdateFlags(uint64(args.Flags))
	err = entry.Map.Update(key, valueArg, flags)
	fields := map[string]any{"map": args.Map, "fd": entry.Map.FD(), "flags": uint64(args.Flags), "key_hex": hex.EncodeToString(keyBytes)}
	addNativeUintField(fields, "key", keyBytes)
	if valueBytes != nil {
		fields["value_hex"] = hex.EncodeToString(valueBytes)
		fields["bytes_written"] = len(valueBytes)
		fields["checksum64"] = checksum64(valueBytes)
		addNativeUintField(fields, "value", valueBytes)
	}
	if valueRef != "" {
		fields["value_ref"] = valueRef
	}
	return ebpfScriptResult(fields, err)
}

func (e *scriptEnv) scriptEBPFMapDelete(value goja.Value) (any, error) {
	var args ebpfMapKeyArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	key, keyBytes, err := e.ebpfKeyBytes(entry.Map, args.Key, args.KeyBase64, args.KeyHex, args.KeyUTF8, false)
	if err != nil {
		return nil, err
	}
	deleteErr := entry.Map.Delete(key)
	fields := map[string]any{"map": args.Map, "fd": entry.Map.FD(), "key_hex": hex.EncodeToString(keyBytes), "deleted": deleteErr == nil}
	addNativeUintField(fields, "key", keyBytes)
	return ebpfScriptResult(fields, deleteErr)
}

func (e *scriptEnv) scriptEBPFMapNextKey(value goja.Value) (any, error) {
	var args ebpfMapKeyArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	key, keyBytes, err := e.ebpfKeyBytes(entry.Map, args.Key, args.KeyBase64, args.KeyHex, args.KeyUTF8, true)
	if err != nil {
		return nil, err
	}
	next, err := entry.Map.NextKeyBytes(key)
	fields := map[string]any{"map": args.Map, "fd": entry.Map.FD()}
	if keyBytes != nil {
		fields["key_hex"] = hex.EncodeToString(keyBytes)
		addNativeUintField(fields, "key", keyBytes)
	}
	if err == nil && next == nil {
		err = cebpf.ErrKeyNotExist
	}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	fields["next_key_hex"] = hex.EncodeToString(next)
	addNativeUintField(fields, "next_key", next)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFMapEntries(value goja.Value) (any, error) {
	var args ebpfMapEntriesArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	limit := uint64(args.MaxEntries)
	if limit == 0 {
		limit = 64
	}
	if limit > uint64(math.MaxInt32) {
		return nil, fmt.Errorf("max_entries %d is too large", limit)
	}
	entryBytes := uint64(entry.Map.KeySize()) + uint64(entry.Map.ValueSize())
	if entryBytes > 0 && limit > e.app.config.MaxReadBytes/entryBytes {
		return nil, fmt.Errorf("requested entries exceed max_read_bytes %d", e.app.config.MaxReadBytes)
	}
	items := make([]map[string]any, 0, int(limit))
	var previous []byte
	for uint64(len(items)) < limit {
		next, nextErr := entry.Map.NextKeyBytes(previous)
		if nextErr != nil {
			return ebpfScriptResult(map[string]any{"map": args.Map, "fd": entry.Map.FD(), "entries": items}, nextErr)
		}
		if next == nil {
			return ebpfScriptResult(map[string]any{"map": args.Map, "fd": entry.Map.FD(), "entries": items, "truncated": false}, nil)
		}
		data, lookupErr := entry.Map.LookupBytes(next)
		if lookupErr != nil {
			return ebpfScriptResult(map[string]any{"map": args.Map, "fd": entry.Map.FD(), "entries": items, "key_hex": hex.EncodeToString(next)}, lookupErr)
		}
		item := map[string]any{"key_hex": hex.EncodeToString(next)}
		addNativeUintField(item, "key", next)
		if data != nil {
			if err := addEBPFEncodedBytes(item, data, args.Encoding); err != nil {
				return nil, err
			}
			addNativeUintField(item, "value", data)
		}
		items = append(items, item)
		previous = next
	}
	next, nextErr := entry.Map.NextKeyBytes(previous)
	truncated := nextErr == nil && next != nil
	return ebpfScriptResult(map[string]any{"map": args.Map, "fd": entry.Map.FD(), "entries": items, "truncated": truncated}, nil)
}

func (e *scriptEnv) scriptEBPFMapPin(value goja.Value) (any, error) {
	var args ebpfMapPinArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	err = entry.Map.Pin(args.Path)
	if err == nil {
		e.app.setEBPFMapPinnedPath(args.Map, args.Path)
	}
	return ebpfScriptResult(map[string]any{"map": args.Map, "path": args.Path, "pinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFMapUnpin(value goja.Value) (any, error) {
	var args ebpfMapRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	err = entry.Map.Unpin()
	if err == nil {
		e.app.setEBPFMapPinnedPath(args.Map, "")
	}
	return ebpfScriptResult(map[string]any{"map": args.Map, "unpinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFMapFreeze(value goja.Value) (any, error) {
	var args ebpfMapRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	err = entry.Map.Freeze()
	return ebpfScriptResult(map[string]any{"map": args.Map, "frozen": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFProgramLoad(value goja.Value) (any, error) {
	var args ebpfProgramLoadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	kind := normalizeEBPFProgramKind(args.Kind)
	typ, err := e.ebpfProgramTypeForLoad(args.Type, kind)
	if err != nil {
		return nil, err
	}
	if kind == "" {
		kind = defaultEBPFProgramKind(typ)
	}
	returnValue, err := parseEBPFReturnValue(args.ReturnValue, defaultEBPFReturnValue(typ, kind))
	if err != nil {
		return nil, err
	}
	insns, buildMeta, err := e.ebpfProgramKindInstructions(args, typ, kind, returnValue)
	if err != nil {
		return nil, err
	}
	license := args.License
	if license == "" {
		license = "MIT"
	}
	attachType, err := parseEBPFAttachType(args.AttachType)
	if err != nil {
		return nil, err
	}
	spec := &cebpf.ProgramSpec{Name: args.Name, Type: typ, AttachType: attachType, AttachTo: args.AttachTo, Ifindex: uint32(args.Ifindex), Flags: uint32(args.Flags), License: license, Instructions: insns}
	opts := cebpf.ProgramOptions{LogLevel: cebpf.LogLevel(uint32(args.LogLevel)), LogSizeStart: uint32(args.LogSizeStart), LogDisabled: args.LogDisabled}
	program, err := cebpf.NewProgramWithOptions(spec, opts)
	fields := map[string]any{"name": args.Name, "kind": kind, "type": typ.String(), "type_value": uint32(typ), "attach_type": uint32(attachType), "license": license, "instruction_count": len(insns), "flags": uint32(args.Flags), "return_value": returnValue}
	for key, value := range buildMeta {
		fields[key] = value
	}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFProgram(program, args.Handle, args.Name, kind, "")
	if err != nil {
		_ = program.Close()
		return nil, err
	}
	entry.VerifierLog = program.VerifierLog
	fields["program"] = ebpfProgramInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFProgramLoadPinned(value goja.Value) (any, error) {
	var args ebpfPinnedArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	program, err := cebpf.LoadPinnedProgram(args.Path, &cebpf.LoadPinOptions{ReadOnly: args.ReadOnly, WriteOnly: args.WriteOnly, Flags: uint32(args.Flags)})
	fields := map[string]any{"path": args.Path, "read_only": args.ReadOnly, "write_only": args.WriteOnly, "flags": uint32(args.Flags)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFProgram(program, args.Handle, "", "pinned", args.Path)
	if err != nil {
		_ = program.Close()
		return nil, err
	}
	fields["program"] = ebpfProgramInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFProgramClose(value goja.Value) (any, error) {
	var args ebpfProgramRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	closeErr := entry.Program.Close()
	if closeErr == nil {
		e.app.removeEBPFProgram(args.Program)
	}
	return ebpfScriptResult(map[string]any{"program": args.Program, "fd": entry.Program.FD(), "closed": closeErr == nil}, closeErr)
}

func (e *scriptEnv) scriptEBPFProgramInfo(value goja.Value) (any, error) {
	var args ebpfProgramInfoArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Program == "" {
		return map[string]any{"ok": true, "programs": e.app.ebpfProgramInfos()}, nil
	}
	entry, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	info := ebpfProgramInfo(entry)
	if err := addKernelProgramInfo(info, entry.Program); err != nil {
		return ebpfScriptResult(info, err)
	}
	info["ok"] = true
	return info, nil
}

func (e *scriptEnv) scriptEBPFProgramTest(value goja.Value) (any, error) {
	var args ebpfProgramTestArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	data, err := decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, nil)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > e.app.config.MaxBufferBytes {
		return nil, fmt.Errorf("data length %d exceeds max_buffer_bytes %d", len(data), e.app.config.MaxBufferBytes)
	}
	ret, out, runErr := entry.Program.Test(data)
	fields := map[string]any{"program": args.Program, "fd": entry.Program.FD(), "return_value": ret, "input_length": len(data)}
	if runErr == nil {
		if uint64(len(out)) > e.app.config.MaxReadBytes {
			return nil, fmt.Errorf("output length %d exceeds max_read_bytes %d", len(out), e.app.config.MaxReadBytes)
		}
		if err := addEBPFEncodedBytes(fields, out, args.Encoding); err != nil {
			return nil, err
		}
	}
	return ebpfScriptResult(fields, runErr)
}

func (e *scriptEnv) scriptEBPFProgramPin(value goja.Value) (any, error) {
	var args ebpfProgramPinArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	entry, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	err = entry.Program.Pin(args.Path)
	if err == nil {
		e.app.setEBPFProgramPinnedPath(args.Program, args.Path)
	}
	return ebpfScriptResult(map[string]any{"program": args.Program, "path": args.Path, "pinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFProgramUnpin(value goja.Value) (any, error) {
	var args ebpfProgramRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	err = entry.Program.Unpin()
	if err == nil {
		e.app.setEBPFProgramPinnedPath(args.Program, "")
	}
	return ebpfScriptResult(map[string]any{"program": args.Program, "unpinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFProgramAttachSocketFilter(value goja.Value) (any, error) {
	var args ebpfSocketFilterArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return ebpfScriptResult(map[string]any{"program": args.Program, "handle": handle, "fd": fd}, err)
	}
	file := os.NewFile(uintptr(dup), "mcp-uapi-ebpf-socket")
	attachErr := link.AttachSocketFilter(file, program.Program)
	closeErr := file.Close()
	if attachErr == nil {
		attachErr = closeErr
	}
	return ebpfScriptResult(map[string]any{"program": args.Program, "handle": handle, "fd": fd, "attached": attachErr == nil}, attachErr)
}

func (e *scriptEnv) scriptEBPFSocketFilterDetach(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return ebpfScriptResult(map[string]any{"handle": handle, "fd": fd}, err)
	}
	file := os.NewFile(uintptr(dup), "mcp-uapi-ebpf-socket")
	detachErr := link.DetachSocketFilter(file)
	closeErr := file.Close()
	if detachErr == nil {
		detachErr = closeErr
	}
	return ebpfScriptResult(map[string]any{"handle": handle, "fd": fd, "detached": detachErr == nil}, detachErr)
}

func (e *scriptEnv) scriptEBPFLinkLoadPinned(value goja.Value) (any, error) {
	var args ebpfLinkPinnedArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	loaded, err := link.LoadPinnedLink(args.Path, &cebpf.LoadPinOptions{ReadOnly: args.ReadOnly, WriteOnly: args.WriteOnly, Flags: uint32(args.Flags)})
	fields := map[string]any{"path": args.Path, "read_only": args.ReadOnly, "write_only": args.WriteOnly, "flags": uint32(args.Flags)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFLink(loaded, args.Handle, "pinned", args.Path, nil)
	if err != nil {
		_ = loaded.Close()
		return nil, err
	}
	fields["link"] = ebpfLinkInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFLinkClose(value goja.Value) (any, error) {
	var args ebpfLinkRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	closeErr := entry.Link.Close()
	if closeErr == nil {
		e.app.removeEBPFLink(args.Link)
	}
	return ebpfScriptResult(map[string]any{"link": args.Link, "closed": closeErr == nil}, closeErr)
}

func (e *scriptEnv) scriptEBPFLinkInfo(value goja.Value) (any, error) {
	var args ebpfLinkInfoArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Link == "" {
		return map[string]any{"ok": true, "links": e.app.ebpfLinkInfos()}, nil
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	info := ebpfLinkInfo(entry)
	if err := addKernelLinkInfo(info, entry.Link); err != nil {
		return ebpfScriptResult(info, err)
	}
	info["ok"] = true
	return info, nil
}

func (e *scriptEnv) scriptEBPFLinkPin(value goja.Value) (any, error) {
	var args ebpfLinkPinArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	err = entry.Link.Pin(args.Path)
	if err == nil {
		e.app.setEBPFLinkPinnedPath(args.Link, args.Path)
	}
	return ebpfScriptResult(map[string]any{"link": args.Link, "path": args.Path, "pinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFLinkUnpin(value goja.Value) (any, error) {
	var args ebpfLinkRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	err = entry.Link.Unpin()
	if err == nil {
		e.app.setEBPFLinkPinnedPath(args.Link, "")
	}
	return ebpfScriptResult(map[string]any{"link": args.Link, "unpinned": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFLinkDetach(value goja.Value) (any, error) {
	var args ebpfLinkRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	detachErr := entry.Link.Detach()
	return ebpfScriptResult(map[string]any{"link": args.Link, "detached": detachErr == nil}, detachErr)
}

func (e *scriptEnv) scriptEBPFLinkUpdate(value goja.Value) (any, error) {
	var args ebpfLinkUpdateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfLink(args.Link)
	if err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	err = entry.Link.Update(program.Program)
	return ebpfScriptResult(map[string]any{"link": args.Link, "program": args.Program, "updated": err == nil, "flags": uint32(args.Flags)}, err)
}

func (e *scriptEnv) scriptEBPFAttachKprobe(value goja.Value) (any, error) {
	return e.scriptEBPFAttachKprobeCommon(value, false)
}

func (e *scriptEnv) scriptEBPFAttachKretprobe(value goja.Value) (any, error) {
	return e.scriptEBPFAttachKprobeCommon(value, true)
}

func (e *scriptEnv) scriptEBPFAttachKprobeCommon(value goja.Value, retprobe bool) (any, error) {
	var args ebpfAttachKprobeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	opts := &link.KprobeOptions{Cookie: uint64(args.Cookie), Offset: uint64(args.Offset), RetprobeMaxActive: int(args.RetprobeMaxActive), TraceFSPrefix: args.TraceFSPrefix}
	var lnk link.Link
	if retprobe {
		lnk, err = link.Kretprobe(args.Symbol, program.Program, opts)
	} else {
		lnk, err = link.Kprobe(args.Symbol, program.Program, opts)
	}
	kind := "kprobe"
	if retprobe {
		kind = "kretprobe"
	}
	fields := map[string]any{"kind": kind, "program": args.Program, "symbol": args.Symbol, "cookie": uint64(args.Cookie), "offset": uint64(args.Offset)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFLink(lnk, args.Handle, kind, "", fields)
	if err != nil {
		_ = lnk.Close()
		return nil, err
	}
	fields["link"] = ebpfLinkInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFAttachTracepoint(value goja.Value) (any, error) {
	var args ebpfAttachTracepointArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	lnk, err := link.Tracepoint(args.Group, args.Name, program.Program, &link.TracepointOptions{Cookie: uint64(args.Cookie)})
	fields := map[string]any{"kind": "tracepoint", "program": args.Program, "group": args.Group, "name": args.Name, "cookie": uint64(args.Cookie)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFLink(lnk, args.Handle, "tracepoint", "", fields)
	if err != nil {
		_ = lnk.Close()
		return nil, err
	}
	fields["link"] = ebpfLinkInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFAttachRawTracepoint(value goja.Value) (any, error) {
	var args ebpfAttachRawTracepointArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: args.Name, Program: program.Program})
	fields := map[string]any{"kind": "raw_tracepoint", "program": args.Program, "name": args.Name}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFLink(lnk, args.Handle, "raw_tracepoint", "", fields)
	if err != nil {
		_ = lnk.Close()
		return nil, err
	}
	fields["link"] = ebpfLinkInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFAttachXDP(value goja.Value) (any, error) {
	var args ebpfAttachXDPArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	program, err := e.app.ebpfProgram(args.Program)
	if err != nil {
		return nil, err
	}
	ifindex := uint32(args.Ifindex)
	if ifindex == 0 {
		ifindex = uint32(args.Interface)
	}
	lnk, err := link.AttachXDP(link.XDPOptions{Program: program.Program, Interface: int(ifindex), Flags: link.XDPAttachFlags(uint32(args.Flags))})
	fields := map[string]any{"kind": "xdp", "program": args.Program, "ifindex": ifindex, "flags": uint32(args.Flags)}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	entry, err := e.app.registerEBPFLink(lnk, args.Handle, "xdp", "", fields)
	if err != nil {
		_ = lnk.Close()
		return nil, err
	}
	fields["link"] = ebpfLinkInfo(entry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFRingReaderCreate(value goja.Value) (any, error) {
	var args ebpfReaderCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	reader, err := ringbuf.NewReader(entry.Map)
	fields := map[string]any{"map": args.Map}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	readerEntry, err := e.app.registerEBPFRingReader(reader, args.Handle, args.Map)
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	fields["reader"] = ebpfRingReaderInfo(readerEntry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFRingRead(value goja.Value) (any, error) {
	var args ebpfReaderReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfRingReader(args.Reader)
	if err != nil {
		return nil, err
	}
	entry.Reader.SetDeadline(readerDeadline(uint32(args.TimeoutMS)))
	record, readErr := entry.Reader.Read()
	fields := map[string]any{"reader": args.Reader, "map": entry.Map, "remaining": record.Remaining}
	if readErr == nil {
		if uint64(len(record.RawSample)) > e.app.config.MaxReadBytes {
			return nil, fmt.Errorf("sample length %d exceeds max_read_bytes %d", len(record.RawSample), e.app.config.MaxReadBytes)
		}
		if err := addEBPFEncodedBytes(fields, record.RawSample, args.Encoding); err != nil {
			return nil, err
		}
		addEBPFEventFields(fields, record.RawSample)
	}
	return ebpfScriptResult(fields, readErr)
}

func (e *scriptEnv) scriptEBPFRingReaderInfo(value goja.Value) (any, error) {
	var args ebpfRingReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Reader == "" {
		return map[string]any{"ok": true, "readers": e.app.ebpfRingReaderInfos()}, nil
	}
	entry, err := e.app.ebpfRingReader(args.Reader)
	if err != nil {
		return nil, err
	}
	info := ebpfRingReaderInfo(entry)
	info["ok"] = true
	return info, nil
}

func (e *scriptEnv) scriptEBPFRingReaderFlush(value goja.Value) (any, error) {
	var args ebpfRingReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfRingReader(args.Reader)
	if err != nil {
		return nil, err
	}
	err = entry.Reader.Flush()
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "flushed": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFRingReaderClose(value goja.Value) (any, error) {
	var args ebpfRingReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfRingReader(args.Reader)
	if err != nil {
		return nil, err
	}
	closeErr := entry.Reader.Close()
	if closeErr == nil {
		e.app.removeEBPFRingReader(args.Reader)
	}
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "closed": closeErr == nil}, closeErr)
}

func (e *scriptEnv) scriptEBPFPerfReaderCreate(value goja.Value) (any, error) {
	var args ebpfPerfReaderCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfMap(args.Map)
	if err != nil {
		return nil, err
	}
	perCPUBuffer := int(args.PerCPUBuffer)
	if perCPUBuffer == 0 {
		perCPUBuffer = os.Getpagesize()
	}
	reader, err := newEBPFPerfReader(entry.Map, perCPUBuffer, int(args.WakeupEvents), int(args.Watermark), args.Overwritable)
	fields := map[string]any{"map": args.Map, "per_cpu_buffer": perCPUBuffer, "wakeup_events": uint32(args.WakeupEvents), "watermark": uint32(args.Watermark), "overwritable": args.Overwritable}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	readerEntry, err := e.app.registerEBPFPerfReader(reader, args.Handle, args.Map)
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	fields["reader"] = ebpfPerfReaderInfo(readerEntry)
	return ebpfScriptResult(fields, nil)
}

func (e *scriptEnv) scriptEBPFPerfRead(value goja.Value) (any, error) {
	var args ebpfReaderReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	entry.Reader.SetDeadline(readerDeadline(uint32(args.TimeoutMS)))
	record, readErr := entry.Reader.Read()
	fields := map[string]any{"reader": args.Reader, "map": entry.Map, "cpu": record.CPU, "lost_samples": record.LostSamples, "remaining": record.Remaining}
	if readErr == nil {
		if uint64(len(record.RawSample)) > e.app.config.MaxReadBytes {
			return nil, fmt.Errorf("sample length %d exceeds max_read_bytes %d", len(record.RawSample), e.app.config.MaxReadBytes)
		}
		if err := addEBPFEncodedBytes(fields, record.RawSample, args.Encoding); err != nil {
			return nil, err
		}
		addEBPFEventFields(fields, record.RawSample)
	}
	return ebpfScriptResult(fields, readErr)
}

func (e *scriptEnv) scriptEBPFPerfReaderInfo(value goja.Value) (any, error) {
	var args ebpfPerfReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Reader == "" {
		return map[string]any{"ok": true, "readers": e.app.ebpfPerfReaderInfos()}, nil
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	info := ebpfPerfReaderInfo(entry)
	info["ok"] = true
	return info, nil
}

func (e *scriptEnv) scriptEBPFPerfReaderPause(value goja.Value) (any, error) {
	var args ebpfPerfReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	err = entry.Reader.Pause()
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "paused": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFPerfReaderResume(value goja.Value) (any, error) {
	var args ebpfPerfReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	err = entry.Reader.Resume()
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "resumed": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFPerfReaderFlush(value goja.Value) (any, error) {
	var args ebpfPerfReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	err = entry.Reader.Flush()
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "flushed": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFPerfReaderClose(value goja.Value) (any, error) {
	var args ebpfPerfReaderRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.app.ebpfPerfReader(args.Reader)
	if err != nil {
		return nil, err
	}
	closeErr := entry.Reader.Close()
	if closeErr == nil {
		e.app.removeEBPFPerfReader(args.Reader)
	}
	return ebpfScriptResult(map[string]any{"reader": args.Reader, "closed": closeErr == nil}, closeErr)
}

func readerDeadline(timeoutMS uint32) time.Time {
	if timeoutMS == 0 {
		return time.Now()
	}
	return time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
}

func addEBPFEventFields(fields map[string]any, data []byte) {
	if len(data) < 16 {
		return
	}
	ktimeNS := binary.NativeEndian.Uint64(data[:8])
	pidTGID := binary.NativeEndian.Uint64(data[8:16])
	fields["ktime_ns"] = ktimeNS
	fields["pid_tgid"] = pidTGID
	fields["pid"] = uint32(pidTGID >> 32)
	fields["tid"] = uint32(pidTGID)
	if len(data) >= 24 {
		nsPidTGID := binary.NativeEndian.Uint64(data[16:24])
		fields["ns_pid_tgid"] = nsPidTGID
		fields["ns_pid"] = uint32(nsPidTGID >> 32)
		fields["ns_tid"] = uint32(nsPidTGID)
	}
}

func (e *scriptEnv) scriptEBPFRemoveMemlock(value goja.Value) (any, error) {
	err := rlimit.RemoveMemlock()
	return ebpfScriptResult(map[string]any{"process_global": true, "removed": err == nil}, err)
}

func (e *scriptEnv) scriptEBPFFeatureProbe(value goja.Value) (any, error) {
	var args ebpfFeatureProbeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	kind := normalizeEBPFName(args.Kind)
	if kind == "" {
		kind = normalizeEBPFName(args.Name)
	}
	fields := map[string]any{"kind": kind}
	var err error
	switch kind {
	case "map", "map_type":
		typ, parseErr := parseEBPFMapType(args.Type)
		if parseErr != nil {
			return nil, parseErr
		}
		fields["type"] = typ.String()
		fields["type_value"] = uint32(typ)
		err = features.HaveMapType(typ)
	case "program", "program_type", "prog", "prog_type":
		typ, parseErr := parseEBPFProgramType(args.Type)
		if parseErr != nil {
			return nil, parseErr
		}
		fields["type"] = typ.String()
		fields["type_value"] = uint32(typ)
		err = features.HaveProgramType(typ)
	case "helper", "program_helper", "prog_helper":
		typ, parseErr := parseEBPFProgramType(args.ProgramType)
		if parseErr != nil {
			return nil, parseErr
		}
		helper, parseErr := parseASMHelper(args.Helper)
		if parseErr != nil {
			return nil, parseErr
		}
		fields["program_type"] = typ.String()
		fields["program_type_value"] = uint32(typ)
		fields["helper"] = helper.String()
		fields["helper_value"] = uint32(helper)
		err = features.HaveProgramHelper(typ, helper)
	case "large_instructions", "largeinstructions":
		err = features.HaveLargeInstructions()
	case "bounded_loops", "boundedloops":
		err = features.HaveBoundedLoops()
	case "v2_isa", "v2isa", "isa_v2":
		err = features.HaveV2ISA()
	case "v3_isa", "v3isa", "isa_v3":
		err = features.HaveV3ISA()
	case "v4_isa", "v4isa", "isa_v4":
		err = features.HaveV4ISA()
	case "kprobe_multi", "bpf_link_kprobe_multi":
		err = features.HaveBPFLinkKprobeMulti()
	case "uprobe_multi", "bpf_link_uprobe_multi":
		err = features.HaveBPFLinkUprobeMulti()
	case "kprobe_session", "bpf_link_kprobe_session":
		err = features.HaveBPFLinkKprobeSession()
	default:
		return nil, fmt.Errorf("unsupported feature probe kind %q", args.Kind)
	}
	return ebpfFeatureResult(fields, err), nil
}

func ebpfFeatureResult(fields map[string]any, err error) map[string]any {
	if err == nil {
		fields["ok"] = true
		fields["supported"] = true
		return fields
	}
	if errors.Is(err, cebpf.ErrNotSupported) {
		fields["ok"] = true
		fields["supported"] = false
		fields["error_name"] = "ErrNotSupported"
		fields["error"] = err.Error()
		return fields
	}
	fields["supported"] = false
	result, _ := ebpfScriptResult(fields, err)
	return result
}

func parseASMHelper(value any) (asm.BuiltinFunc, error) {
	if text, ok := value.(string); ok {
		name := normalizeEBPFName(text)
		if helper, ok := asmHelpersByName()[name]; ok {
			return helper, nil
		}
	}
	parsed, err := parseFlexibleUint(value, 32, "helper")
	if err != nil {
		return 0, err
	}
	return asm.BuiltinFunc(parsed), nil
}

func asmHelpersByName() map[string]asm.BuiltinFunc {
	return map[string]asm.BuiltinFunc{
		"map_lookup_elem": asm.FnMapLookupElem, "map_update_elem": asm.FnMapUpdateElem, "map_delete_elem": asm.FnMapDeleteElem,
		"ktime_get_ns": asm.FnKtimeGetNs, "get_current_pid_tgid": asm.FnGetCurrentPidTgid, "get_ns_current_pid_tgid": asm.FnGetNsCurrentPidTgid, "get_current_uid_gid": asm.FnGetCurrentUidGid, "get_current_comm": asm.FnGetCurrentComm,
		"perf_event_output": asm.FnPerfEventOutput, "ringbuf_output": asm.FnRingbufOutput, "ringbuf_reserve": asm.FnRingbufReserve, "ringbuf_submit": asm.FnRingbufSubmit, "ringbuf_discard": asm.FnRingbufDiscard,
		"get_smp_processor_id": asm.FnGetSmpProcessorId, "get_prandom_u32": asm.FnGetPrandomU32, "probe_read_kernel": asm.FnProbeReadKernel, "probe_read_user": asm.FnProbeReadUser,
	}
}

func (e *scriptEnv) scriptEBPFBTFKernelInfo(value goja.Value) (any, error) {
	var args ebpfBTFKernelArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var spec *btf.Spec
	var err error
	fields := map[string]any{"module": args.Module}
	if args.Module != "" {
		spec, err = btf.LoadKernelModuleSpec(args.Module)
	} else {
		spec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		return ebpfScriptResult(fields, err)
	}
	limit := int(args.Limit)
	if limit == 0 {
		limit = 32
	}
	if args.Name != "" {
		types, err := spec.AnyTypesByName(args.Name)
		fields["name"] = args.Name
		if err != nil {
			return ebpfScriptResult(fields, err)
		}
		fields["matches"] = btfTypeSummaries(types, limit)
		fields["truncated"] = len(types) > limit
		fields["ok"] = true
		return fields, nil
	}
	items := make([]map[string]any, 0, limit)
	for typ, err := range spec.All() {
		if err != nil {
			return ebpfScriptResult(fields, err)
		}
		items = append(items, btfTypeSummary(typ))
		if len(items) >= limit {
			break
		}
	}
	fields["types"] = items
	fields["limit"] = limit
	fields["ok"] = true
	return fields, nil
}

func btfTypeSummaries(types []btf.Type, limit int) []map[string]any {
	if limit > len(types) {
		limit = len(types)
	}
	items := make([]map[string]any, 0, limit)
	for _, typ := range types[:limit] {
		items = append(items, btfTypeSummary(typ))
	}
	return items
}

func btfTypeSummary(typ btf.Type) map[string]any {
	return map[string]any{"name": typ.TypeName(), "type": fmt.Sprintf("%T", typ), "detail": fmt.Sprintf("%v", typ)}
}

func (a *App) registerEBPFMap(m *cebpf.Map, requestedHandle, name, pinnedPath string) (*ebpfMapEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("eBPF map handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.ebpfMaps[requestedHandle]; exists {
			return nil, fmt.Errorf("eBPF map handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextEBPFMapHandle++
			requestedHandle = fmt.Sprintf("bpfMap%d", a.nextEBPFMapHandle)
			if _, exists := a.ebpfMaps[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &ebpfMapEntry{Handle: requestedHandle, Name: name, Map: m, PinnedPath: pinnedPath}
	a.ebpfMaps[requestedHandle] = entry
	return entry, nil
}

func (a *App) ebpfMap(handle string) (*ebpfMapEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfMapLocked(handle)
}

func (a *App) ebpfMapLocked(handle string) (*ebpfMapEntry, error) {
	if handle == "" {
		return nil, fmt.Errorf("map is required")
	}
	entry, ok := a.ebpfMaps[handle]
	if !ok {
		return nil, fmt.Errorf("eBPF map handle %q not found", handle)
	}
	return entry, nil
}

func (a *App) removeEBPFMap(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ebpfMaps, handle)
}

func (a *App) setEBPFMapPinnedPath(handle, path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if entry := a.ebpfMaps[handle]; entry != nil {
		entry.PinnedPath = path
	}
}

func (a *App) registerEBPFProgram(program *cebpf.Program, requestedHandle, name, kind, pinnedPath string) (*ebpfProgramEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("eBPF program handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.ebpfPrograms[requestedHandle]; exists {
			return nil, fmt.Errorf("eBPF program handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextEBPFProgramHandle++
			requestedHandle = fmt.Sprintf("bpfProg%d", a.nextEBPFProgramHandle)
			if _, exists := a.ebpfPrograms[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &ebpfProgramEntry{Handle: requestedHandle, Name: name, Kind: kind, Program: program, PinnedPath: pinnedPath}
	a.ebpfPrograms[requestedHandle] = entry
	return entry, nil
}

func (a *App) ebpfProgram(handle string) (*ebpfProgramEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if handle == "" {
		return nil, fmt.Errorf("program is required")
	}
	entry, ok := a.ebpfPrograms[handle]
	if !ok {
		return nil, fmt.Errorf("eBPF program handle %q not found", handle)
	}
	return entry, nil
}

func (a *App) removeEBPFProgram(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ebpfPrograms, handle)
}

func (a *App) setEBPFProgramPinnedPath(handle, path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if entry := a.ebpfPrograms[handle]; entry != nil {
		entry.PinnedPath = path
	}
}

func (a *App) registerEBPFLink(lnk link.Link, requestedHandle, kind, pinnedPath string, meta map[string]any) (*ebpfLinkEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("eBPF link handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.ebpfLinks[requestedHandle]; exists {
			return nil, fmt.Errorf("eBPF link handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextEBPFLinkHandle++
			requestedHandle = fmt.Sprintf("bpfLink%d", a.nextEBPFLinkHandle)
			if _, exists := a.ebpfLinks[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &ebpfLinkEntry{Handle: requestedHandle, Kind: kind, Link: lnk, PinnedPath: pinnedPath, Meta: meta}
	a.ebpfLinks[requestedHandle] = entry
	return entry, nil
}

func (a *App) ebpfLink(handle string) (*ebpfLinkEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if handle == "" {
		return nil, fmt.Errorf("link is required")
	}
	entry, ok := a.ebpfLinks[handle]
	if !ok {
		return nil, fmt.Errorf("eBPF link handle %q not found", handle)
	}
	return entry, nil
}

func (a *App) removeEBPFLink(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ebpfLinks, handle)
}

func (a *App) setEBPFLinkPinnedPath(handle, path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if entry := a.ebpfLinks[handle]; entry != nil {
		entry.PinnedPath = path
	}
}

func (a *App) registerEBPFRingReader(reader *ringbuf.Reader, requestedHandle, mapHandle string) (*ebpfRingReaderEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("eBPF ringbuf reader handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.ringReaders[requestedHandle]; exists {
			return nil, fmt.Errorf("eBPF ringbuf reader handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextRingReaderHandle++
			requestedHandle = fmt.Sprintf("bpfRingReader%d", a.nextRingReaderHandle)
			if _, exists := a.ringReaders[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &ebpfRingReaderEntry{Handle: requestedHandle, Map: mapHandle, Reader: reader}
	a.ringReaders[requestedHandle] = entry
	return entry, nil
}

func (a *App) ebpfRingReader(handle string) (*ebpfRingReaderEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if handle == "" {
		return nil, fmt.Errorf("reader is required")
	}
	entry, ok := a.ringReaders[handle]
	if !ok {
		return nil, fmt.Errorf("eBPF ringbuf reader handle %q not found", handle)
	}
	return entry, nil
}

func (a *App) removeEBPFRingReader(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ringReaders, handle)
}

func (a *App) registerEBPFPerfReader(reader ebpfPerfReader, requestedHandle, mapHandle string) (*ebpfPerfReaderEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("eBPF perf reader handle", requestedHandle); err != nil {
			return nil, err
		}
		if _, exists := a.perfReaders[requestedHandle]; exists {
			return nil, fmt.Errorf("eBPF perf reader handle %q already exists", requestedHandle)
		}
	} else {
		for {
			a.nextPerfReaderHandle++
			requestedHandle = fmt.Sprintf("bpfPerfReader%d", a.nextPerfReaderHandle)
			if _, exists := a.perfReaders[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &ebpfPerfReaderEntry{Handle: requestedHandle, Map: mapHandle, Reader: reader}
	a.perfReaders[requestedHandle] = entry
	return entry, nil
}

func (a *App) ebpfPerfReader(handle string) (*ebpfPerfReaderEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if handle == "" {
		return nil, fmt.Errorf("reader is required")
	}
	entry, ok := a.perfReaders[handle]
	if !ok {
		return nil, fmt.Errorf("eBPF perf reader handle %q not found", handle)
	}
	return entry, nil
}

func (a *App) removeEBPFPerfReader(handle string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.perfReaders, handle)
}

func (a *App) ebpfMapInfos() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfMapInfosLocked()
}

func (a *App) ebpfMapInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.ebpfMaps))
	for _, entry := range a.ebpfMaps {
		infos = append(infos, ebpfMapInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func (a *App) ebpfProgramInfos() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfProgramInfosLocked()
}

func (a *App) ebpfProgramInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.ebpfPrograms))
	for _, entry := range a.ebpfPrograms {
		infos = append(infos, ebpfProgramInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func (a *App) ebpfLinkInfos() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfLinkInfosLocked()
}

func (a *App) ebpfLinkInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.ebpfLinks))
	for _, entry := range a.ebpfLinks {
		infos = append(infos, ebpfLinkInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func (a *App) ebpfRingReaderInfos() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfRingReaderInfosLocked()
}

func (a *App) ebpfRingReaderInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.ringReaders))
	for _, entry := range a.ringReaders {
		infos = append(infos, ebpfRingReaderInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func (a *App) ebpfPerfReaderInfos() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ebpfPerfReaderInfosLocked()
}

func (a *App) ebpfPerfReaderInfosLocked() []map[string]any {
	infos := make([]map[string]any, 0, len(a.perfReaders))
	for _, entry := range a.perfReaders {
		infos = append(infos, ebpfPerfReaderInfo(entry))
	}
	sort.Slice(infos, func(i, j int) bool { return fmt.Sprint(infos[i]["handle"]) < fmt.Sprint(infos[j]["handle"]) })
	return infos
}

func ebpfMapInfo(entry *ebpfMapEntry) map[string]any {
	info := map[string]any{"handle": entry.Handle, "fd": entry.Map.FD(), "type": entry.Map.Type().String(), "type_value": uint32(entry.Map.Type()), "key_size": entry.Map.KeySize(), "value_size": entry.Map.ValueSize(), "max_entries": entry.Map.MaxEntries(), "flags": entry.Map.Flags()}
	if entry.Name != "" {
		info["name"] = entry.Name
	}
	if entry.PinnedPath != "" {
		info["pinned_path"] = entry.PinnedPath
	}
	return info
}

func addKernelMapInfo(fields map[string]any, m *cebpf.Map) error {
	info, err := m.Info()
	if err != nil {
		return err
	}
	fields["type"] = fmt.Sprint(info.Type)
	fields["type_value"] = uint32(info.Type)
	fields["key_size"] = info.KeySize
	fields["value_size"] = info.ValueSize
	fields["max_entries"] = info.MaxEntries
	fields["flags"] = info.Flags
	fields["name"] = info.Name
	if id, ok := info.ID(); ok {
		fields["id"] = uint32(id)
	}
	if btfID, ok := info.BTFID(); ok {
		fields["btf_id"] = uint32(btfID)
	}
	if extra, ok := info.MapExtra(); ok {
		fields["map_extra"] = extra
	}
	if memlock, ok := info.Memlock(); ok {
		fields["memlock"] = memlock
	}
	fields["frozen"] = info.Frozen()
	return nil
}

func ebpfProgramInfo(entry *ebpfProgramEntry) map[string]any {
	info := map[string]any{"handle": entry.Handle, "fd": entry.Program.FD(), "type": entry.Program.Type().String(), "type_value": uint32(entry.Program.Type())}
	if entry.Name != "" {
		info["name"] = entry.Name
	}
	if entry.Kind != "" {
		info["kind"] = entry.Kind
	}
	if entry.PinnedPath != "" {
		info["pinned_path"] = entry.PinnedPath
	}
	if entry.VerifierLog != "" {
		info["verifier_log"] = entry.VerifierLog
	}
	return info
}

func addKernelProgramInfo(fields map[string]any, program *cebpf.Program) error {
	info, err := program.Info()
	if err != nil {
		return err
	}
	fields["type"] = info.Type.String()
	fields["type_value"] = uint32(info.Type)
	fields["name"] = info.Name
	fields["tag"] = info.Tag
	if id, ok := info.ID(); ok {
		fields["id"] = uint32(id)
	}
	if uid, ok := info.CreatedByUID(); ok {
		fields["created_by_uid"] = uid
	}
	if btfID, ok := info.BTFID(); ok {
		fields["btf_id"] = uint32(btfID)
	}
	if maps, ok := info.MapIDs(); ok {
		ids := make([]uint32, 0, len(maps))
		for _, id := range maps {
			ids = append(ids, uint32(id))
		}
		fields["map_ids"] = ids
	}
	if loadTime, ok := info.LoadTime(); ok {
		fields["load_time_ns"] = loadTime.Nanoseconds()
	}
	if count, ok := info.VerifiedInstructions(); ok {
		fields["verified_instructions"] = count
	}
	if translatedSize, err := info.TranslatedSize(); err == nil {
		fields["translated_size"] = translatedSize
	}
	if jitedSize, err := info.JitedSize(); err == nil {
		fields["jited_size"] = jitedSize
	}
	if memlock, ok := info.Memlock(); ok {
		fields["memlock"] = memlock
	}
	return nil
}

func ebpfLinkInfo(entry *ebpfLinkEntry) map[string]any {
	info := map[string]any{"handle": entry.Handle, "kind": entry.Kind}
	if entry.PinnedPath != "" {
		info["pinned_path"] = entry.PinnedPath
	}
	for key, value := range entry.Meta {
		switch key {
		case "link", "ok":
			continue
		default:
			info[key] = value
		}
	}
	return info
}

func addKernelLinkInfo(fields map[string]any, lnk link.Link) error {
	info, err := lnk.Info()
	if err != nil {
		return err
	}
	fields["type"] = fmt.Sprint(info.Type)
	fields["type_value"] = uint32(info.Type)
	fields["id"] = uint32(info.ID)
	fields["program_id"] = uint32(info.Program)
	if raw := info.RawTracepoint(); raw != nil {
		fields["raw_tracepoint"] = raw.Name
	}
	if xdp := info.XDP(); xdp != nil {
		fields["ifindex"] = xdp.Ifindex
	}
	if cg := info.Cgroup(); cg != nil {
		fields["cgroup_id"] = cg.CgroupId
		fields["attach_type"] = uint32(cg.AttachType)
	}
	if tracing := info.Tracing(); tracing != nil {
		fields["attach_type"] = uint32(tracing.AttachType)
		fields["target_object_id"] = tracing.TargetObjectId
		fields["target_btf_id"] = uint32(tracing.TargetBtfId)
	}
	if perfEvent := info.PerfEvent(); perfEvent != nil {
		fields["perf_event_type"] = uint32(perfEvent.Type)
		if kprobe := perfEvent.Kprobe(); kprobe != nil {
			fields["symbol"] = kprobe.Function
			fields["offset"] = kprobe.Offset
			fields["missed"] = kprobe.Missed
		}
		if tracepoint := perfEvent.Tracepoint(); tracepoint != nil {
			fields["tracepoint"] = tracepoint.Tracepoint
			fields["cookie"] = tracepoint.Cookie
		}
	}
	return nil
}

func ebpfRingReaderInfo(entry *ebpfRingReaderEntry) map[string]any {
	info := map[string]any{"handle": entry.Handle, "map": entry.Map, "buffer_size": entry.Reader.BufferSize(), "available_bytes": entry.Reader.AvailableBytes()}
	return info
}

func ebpfPerfReaderInfo(entry *ebpfPerfReaderEntry) map[string]any {
	return map[string]any{"handle": entry.Handle, "map": entry.Map, "buffer_size": entry.Reader.BufferSize()}
}

func (e *scriptEnv) ebpfKeyBytes(m *cebpf.Map, value any, dataBase64, dataHex, dataUTF8 string, allowMissing bool) (any, []byte, error) {
	if m.KeySize() == 0 && value == nil && dataBase64 == "" && dataHex == "" && dataUTF8 == "" {
		return nil, nil, nil
	}
	data, present, err := e.ebpfInputBytes(value, dataBase64, dataHex, dataUTF8, "", 0, 0, m.KeySize(), "key", allowMissing)
	if err != nil || !present {
		return nil, nil, err
	}
	return data, data, nil
}

func (e *scriptEnv) ebpfUpdateValue(m *cebpf.Map, args ebpfMapUpdateArgs) (any, []byte, string, error) {
	valueSources := 0
	if args.Value != nil {
		valueSources++
	}
	if args.ValueBase64 != "" {
		valueSources++
	}
	if args.ValueHex != "" {
		valueSources++
	}
	if args.ValueUTF8 != "" {
		valueSources++
	}
	bufferName := args.ValueBuffer
	if bufferName == "" {
		bufferName = args.Buffer
	}
	if bufferName != "" {
		valueSources++
	}
	if args.ValueMap != "" {
		valueSources++
	}
	if args.ValueProgram != "" {
		valueSources++
	}
	if valueSources == 0 {
		return nil, nil, "", fmt.Errorf("value, value_hex, value_base64, value_utf8, value_buffer, value_map, or value_program is required")
	}
	if valueSources > 1 {
		return nil, nil, "", fmt.Errorf("provide only one value source")
	}
	if args.ValueMap != "" {
		entry, err := e.app.ebpfMap(args.ValueMap)
		if err != nil {
			return nil, nil, "", err
		}
		return entry.Map, nil, args.ValueMap, nil
	}
	if args.ValueProgram != "" {
		entry, err := e.app.ebpfProgram(args.ValueProgram)
		if err != nil {
			return nil, nil, "", err
		}
		return entry.Program, nil, args.ValueProgram, nil
	}
	data, _, err := e.ebpfInputBytes(args.Value, args.ValueBase64, args.ValueHex, args.ValueUTF8, bufferName, uint64(args.BufferOffset), uint64(args.Length), m.ValueSize(), "value", false)
	if err != nil {
		return nil, nil, "", err
	}
	return data, data, "", nil
}

func (e *scriptEnv) ebpfInputBytes(value any, dataBase64, dataHex, dataUTF8, bufferName string, bufferOffset, length uint64, size uint32, field string, allowMissing bool) ([]byte, bool, error) {
	sources := 0
	if value != nil {
		sources++
	}
	if dataBase64 != "" {
		sources++
	}
	if dataHex != "" {
		sources++
	}
	if dataUTF8 != "" {
		sources++
	}
	if bufferName != "" {
		sources++
	}
	if sources == 0 {
		if allowMissing {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("%s is required", field)
	}
	if sources > 1 {
		return nil, false, fmt.Errorf("provide only one %s source", field)
	}
	var data []byte
	var err error
	if value != nil {
		data, err = scalarBytes(value, size, field)
	} else if bufferName != "" {
		readLength := length
		if readLength == 0 {
			readLength = uint64(size)
		}
		e.app.mu.Lock()
		buffer, bufferErr := e.app.bufferLocked(bufferName)
		if bufferErr == nil {
			data, bufferErr = sliceRange(buffer.Data, bufferOffset, readLength, false)
			if bufferErr == nil {
				data = append([]byte(nil), data...)
			}
		}
		e.app.mu.Unlock()
		err = bufferErr
	} else {
		data, err = decodeDirectData(dataBase64, dataHex, dataUTF8, nil)
	}
	if err != nil {
		return nil, true, err
	}
	if len(data) != int(size) {
		return nil, true, fmt.Errorf("%s length %d does not match required size %d", field, len(data), size)
	}
	return data, true, nil
}

func scalarBytes(value any, size uint32, field string) ([]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("%s cannot be scalar when size is zero", field)
	}
	if size > 8 {
		return nil, fmt.Errorf("%s scalar encoding supports sizes up to 8 bytes; use %s_hex or %s_base64 for size %d", field, field, field, size)
	}
	parsed, err := parseFlexibleUint(value, int(size)*8, field)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(size))
	switch size {
	case 1:
		data[0] = byte(parsed)
	case 2:
		binary.NativeEndian.PutUint16(data, uint16(parsed))
	case 4:
		binary.NativeEndian.PutUint32(data, uint32(parsed))
	case 8:
		binary.NativeEndian.PutUint64(data, parsed)
	default:
		return nil, fmt.Errorf("%s scalar size %d is not supported; use explicit bytes", field, size)
	}
	return data, nil
}

func addEBPFEncodedBytes(fields map[string]any, data []byte, encoding string) error {
	encoded, err := encodeBytes(data, encoding)
	if err != nil {
		return err
	}
	for key, value := range encoded {
		fields[key] = value
	}
	return nil
}

func addNativeUintField(fields map[string]any, prefix string, data []byte) {
	value, ok := nativeUint(data)
	if !ok {
		return
	}
	fields[prefix+"_uint"] = value
	fields[prefix+"_hex"] = hex64(value)
}

func nativeUint(data []byte) (uint64, bool) {
	switch len(data) {
	case 1:
		return uint64(data[0]), true
	case 2:
		return uint64(binary.NativeEndian.Uint16(data)), true
	case 4:
		return uint64(binary.NativeEndian.Uint32(data)), true
	case 8:
		return binary.NativeEndian.Uint64(data), true
	default:
		return 0, false
	}
}

func (e *scriptEnv) ebpfProgramTypeForLoad(value any, kind string) (cebpf.ProgramType, error) {
	if value != nil {
		return parseEBPFProgramType(value)
	}
	switch kind {
	case "socket_filter_pass", "socket_filter_drop":
		return cebpf.SocketFilter, nil
	default:
		return cebpf.UnspecifiedProgram, fmt.Errorf("type is required for eBPF program kind %q", kind)
	}
}

func normalizeEBPFProgramKind(kind string) string {
	switch normalizeEBPFName(kind) {
	case "":
		return ""
	case "return", "constant", "constant_return":
		return "return"
	case "counter", "count", "event_counter":
		return "counter"
	case "perf", "perf_event", "perf_event_output":
		return "perf_event"
	case "ringbuf", "ringbuf_event", "ring_buffer", "ring_buffer_event":
		return "ringbuf_event"
	case "socket_filter", "socket_filter_pass", "pass":
		return "socket_filter_pass"
	case "socket_filter_drop", "drop":
		return "socket_filter_drop"
	default:
		return normalizeEBPFName(kind)
	}
}

func defaultEBPFProgramKind(typ cebpf.ProgramType) string {
	if typ == cebpf.SocketFilter {
		return "socket_filter_pass"
	}
	return "return"
}

func defaultEBPFReturnValue(typ cebpf.ProgramType, kind string) int32 {
	switch kind {
	case "socket_filter_drop":
		return 0
	case "socket_filter_pass":
		return 0xffff
	}
	if typ == cebpf.SocketFilter {
		return 0xffff
	}
	if typ == cebpf.XDP {
		return 2
	}
	return 0
}

func parseEBPFReturnValue(value any, fallback int32) (int32, error) {
	if value == nil {
		return fallback, nil
	}
	parsed, err := parseOptionalInt64(value, "return_value")
	if err != nil {
		return 0, err
	}
	if parsed < math.MinInt32 || parsed > math.MaxInt32 {
		return 0, fmt.Errorf("return_value %d overflows int32", parsed)
	}
	return int32(parsed), nil
}

func (e *scriptEnv) ebpfProgramKindInstructions(args ebpfProgramLoadArgs, typ cebpf.ProgramType, kind string, returnValue int32) (asm.Instructions, map[string]any, error) {
	switch kind {
	case "return", "socket_filter_pass", "socket_filter_drop":
		return ebpfReturnInstructions(returnValue), nil, nil
	case "counter":
		return e.ebpfCounterInstructions(args, returnValue)
	case "perf_event":
		return e.ebpfPerfEventInstructions(args, returnValue)
	case "ringbuf_event":
		return e.ebpfRingbufEventInstructions(args, returnValue)
	default:
		return nil, nil, fmt.Errorf("unsupported eBPF program kind %q", kind)
	}
}

func ebpfReturnInstructions(returnValue int32) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R0, returnValue),
		asm.Return(),
	}
}

func (e *scriptEnv) ebpfCounterInstructions(args ebpfProgramLoadArgs, returnValue int32) (asm.Instructions, map[string]any, error) {
	entry, err := e.app.ebpfMap(args.CounterMap)
	if err != nil {
		return nil, nil, err
	}
	if entry.Map.KeySize() != 4 {
		return nil, nil, fmt.Errorf("counter_map %q must have key_size 4", args.CounterMap)
	}
	if entry.Map.ValueSize() != 8 {
		return nil, nil, fmt.Errorf("counter_map %q must have value_size 8", args.CounterMap)
	}
	key, err := e.ebpfCounterKey(args)
	if err != nil {
		return nil, nil, err
	}
	insns := asm.Instructions{
		asm.StoreImm(asm.R10, -4, int64(key), asm.Word),
		asm.LoadMapPtr(asm.R1, entry.Map.FD()),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 0),
		asm.Mov.Imm(asm.R0, returnValue).WithSymbol("exit"),
		asm.Return(),
	}
	return insns, map[string]any{"counter_map": args.CounterMap, "counter_key": key}, nil
}

func (e *scriptEnv) ebpfCounterKey(args ebpfProgramLoadArgs) (uint32, error) {
	data, present, err := e.ebpfInputBytes(args.CounterKey, "", "", "", "", 0, 0, 4, "counter_key", true)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, nil
	}
	return binary.NativeEndian.Uint32(data), nil
}

func (e *scriptEnv) ebpfPerfEventInstructions(args ebpfProgramLoadArgs, returnValue int32) (asm.Instructions, map[string]any, error) {
	entry, err := e.app.ebpfMap(args.EventMap)
	if err != nil {
		return nil, nil, err
	}
	if entry.Map.Type() != cebpf.PerfEventArray {
		return nil, nil, fmt.Errorf("event_map %q must be a PerfEventArray", args.EventMap)
	}
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R10, -16, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.R10, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, entry.Map.FD()),
		asm.LoadImm(asm.R3, int64(uint32(unix.BPF_F_CURRENT_CPU)), asm.DWord),
		asm.Mov.Reg(asm.R4, asm.R10),
		asm.Add.Imm(asm.R4, -16),
		asm.Mov.Imm(asm.R5, 16),
		asm.FnPerfEventOutput.Call(),
		asm.Mov.Imm(asm.R0, returnValue),
		asm.Return(),
	}
	return insns, map[string]any{"event_map": args.EventMap, "event_format": "u64 ktime_ns; u64 pid_tgid"}, nil
}

func (e *scriptEnv) ebpfRingbufEventInstructions(args ebpfProgramLoadArgs, returnValue int32) (asm.Instructions, map[string]any, error) {
	entry, err := e.app.ebpfMap(args.EventMap)
	if err != nil {
		return nil, nil, err
	}
	if entry.Map.Type() != cebpf.RingBuf {
		return nil, nil, fmt.Errorf("event_map %q must be a RingBuf", args.EventMap)
	}
	pidNSDev := uint64(args.PidNSDev)
	pidNSIno := uint64(args.PidNSIno)
	usePidNS := pidNSDev != 0 && pidNSIno != 0
	eventSize := int32(16)
	eventFormat := "u64 ktime_ns; u64 pid_tgid"
	if usePidNS {
		eventSize = 24
		eventFormat = "u64 ktime_ns; u64 pid_tgid; u64 ns_pid_tgid"
	}
	insns := asm.Instructions{
		asm.LoadMapPtr(asm.R1, entry.Map.FD()),
		asm.Mov.Imm(asm.R2, eventSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R6, 0, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.R6, 8, asm.R0, asm.DWord),
	}
	if usePidNS {
		insns = append(insns,
			asm.Mov.Imm(asm.R7, 0),
			asm.StoreMem(asm.R6, 16, asm.R7, asm.DWord),
			asm.StoreMem(asm.R10, -8, asm.R7, asm.DWord),
			asm.LoadImm(asm.R1, int64(pidNSDev), asm.DWord),
			asm.LoadImm(asm.R2, int64(pidNSIno), asm.DWord),
			asm.Mov.Reg(asm.R3, asm.R10),
			asm.Add.Imm(asm.R3, -8),
			asm.Mov.Imm(asm.R4, 8),
			asm.FnGetNsCurrentPidTgid.Call(),
			asm.JNE.Imm(asm.R0, 0, "submit"),
			asm.LoadMem(asm.R7, asm.R10, -4, asm.Word),
			asm.LSh.Imm(asm.R7, 32),
			asm.LoadMem(asm.R8, asm.R10, -8, asm.Word),
			asm.Or.Reg(asm.R7, asm.R8),
			asm.StoreMem(asm.R6, 16, asm.R7, asm.DWord),
		)
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("submit"),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
		asm.Mov.Imm(asm.R0, returnValue).WithSymbol("exit"),
		asm.Return(),
	)
	meta := map[string]any{"event_map": args.EventMap, "event_format": eventFormat}
	if usePidNS {
		meta["pidns_dev"] = pidNSDev
		meta["pidns_ino"] = pidNSIno
	}
	return insns, meta, nil
}

func ebpfScriptResult(fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err == nil {
		fields["ok"] = true
		return fields, nil
	}
	if errors.Is(err, cebpf.ErrKeyNotExist) {
		fields["ok"] = false
		fields["errno"] = int(unix.ENOENT)
		fields["errno_name"] = errnoName(unix.ENOENT)
		fields["error"] = err.Error()
		return fields, nil
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		fields["ok"] = false
		fields["errno"] = int(errno)
		fields["errno_name"] = errnoName(errno)
		fields["error"] = err.Error()
		return fields, nil
	}
	var verifier *cebpf.VerifierError
	if errors.As(err, &verifier) {
		fields["verifier_log"] = verifier.Log
		fields["error_name"] = "VerifierError"
		fields["ok"] = false
		fields["error"] = err.Error()
		return fields, nil
	}
	for _, known := range []struct {
		err  error
		name string
	}{
		{cebpf.ErrNotSupported, "ErrNotSupported"},
		{cebpf.ErrRestrictedKernel, "ErrRestrictedKernel"},
		{cebpf.ErrInvalidType, "ErrInvalidType"},
		{cebpf.ErrMapIncompatible, "ErrMapIncompatible"},
		{cebpf.ErrProgIncompatible, "ErrProgIncompatible"},
		{cebpf.ErrReadOnly, "ErrReadOnly"},
		{cebpf.ErrKeyExist, "ErrKeyExist"},
	} {
		if errors.Is(err, known.err) {
			fields["ok"] = false
			fields["error_name"] = known.name
			fields["error"] = err.Error()
			return fields, nil
		}
	}
	fields["ok"] = false
	fields["error"] = err.Error()
	return fields, nil
}

func parseEBPFMapType(value any) (cebpf.MapType, error) {
	if value == nil {
		return cebpf.UnspecifiedMap, fmt.Errorf("type is required")
	}
	if text, ok := value.(string); ok {
		name := normalizeEBPFName(text)
		if parsed, err := strconv.ParseUint(strings.TrimSpace(text), 0, 32); err == nil {
			return cebpf.MapType(parsed), nil
		}
		if constant, ok := lookupConstant(text); ok {
			return cebpf.MapType(uint32(constant)), nil
		}
		if typ, ok := ebpfMapTypesByName()[name]; ok {
			return typ, nil
		}
		return cebpf.UnspecifiedMap, fmt.Errorf("unknown eBPF map type %q", text)
	}
	parsed, err := parseFlexibleUint(value, 32, "type")
	return cebpf.MapType(uint32(parsed)), err
}

func parseEBPFProgramType(value any) (cebpf.ProgramType, error) {
	if value == nil {
		return cebpf.UnspecifiedProgram, fmt.Errorf("type is required")
	}
	if text, ok := value.(string); ok {
		name := normalizeEBPFName(text)
		if parsed, err := strconv.ParseUint(strings.TrimSpace(text), 0, 32); err == nil {
			return cebpf.ProgramType(parsed), nil
		}
		if constant, ok := lookupConstant(text); ok {
			return cebpf.ProgramType(uint32(constant)), nil
		}
		if typ, ok := ebpfProgramTypesByName()[name]; ok {
			return typ, nil
		}
		return cebpf.UnspecifiedProgram, fmt.Errorf("unknown eBPF program type %q", text)
	}
	parsed, err := parseFlexibleUint(value, 32, "type")
	return cebpf.ProgramType(uint32(parsed)), err
}

func parseEBPFAttachType(value any) (cebpf.AttachType, error) {
	if value == nil {
		return cebpf.AttachNone, nil
	}
	if text, ok := value.(string); ok {
		if strings.TrimSpace(text) == "" {
			return cebpf.AttachNone, nil
		}
		name := normalizeEBPFName(text)
		if parsed, err := strconv.ParseUint(strings.TrimSpace(text), 0, 32); err == nil {
			return cebpf.AttachType(parsed), nil
		}
		if constant, ok := lookupConstant(text); ok {
			return cebpf.AttachType(uint32(constant)), nil
		}
		if attachType, ok := ebpfAttachTypesByName()[name]; ok {
			return attachType, nil
		}
		return cebpf.AttachNone, fmt.Errorf("unknown eBPF attach type %q", text)
	}
	parsed, err := parseFlexibleUint(value, 32, "attach_type")
	return cebpf.AttachType(uint32(parsed)), err
}

func ebpfMapTypesByName() map[string]cebpf.MapType {
	return map[string]cebpf.MapType{
		"hash": cebpf.Hash, "array": cebpf.Array, "programarray": cebpf.ProgramArray, "program_array": cebpf.ProgramArray, "progarray": cebpf.ProgramArray, "prog_array": cebpf.ProgramArray,
		"perfeventarray": cebpf.PerfEventArray, "perf_event_array": cebpf.PerfEventArray, "percpuhash": cebpf.PerCPUHash, "per_cpu_hash": cebpf.PerCPUHash, "percpu_hash": cebpf.PerCPUHash,
		"percpuarray": cebpf.PerCPUArray, "per_cpu_array": cebpf.PerCPUArray, "percpu_array": cebpf.PerCPUArray, "stacktrace": cebpf.StackTrace, "stack_trace": cebpf.StackTrace,
		"cgrouparray": cebpf.CGroupArray, "cgroup_array": cebpf.CGroupArray, "lruhash": cebpf.LRUHash, "lru_hash": cebpf.LRUHash, "lrucpuhash": cebpf.LRUCPUHash, "lru_cpu_hash": cebpf.LRUCPUHash,
		"lpmtrie": cebpf.LPMTrie, "lpm_trie": cebpf.LPMTrie, "arrayofmaps": cebpf.ArrayOfMaps, "array_of_maps": cebpf.ArrayOfMaps, "hashofmaps": cebpf.HashOfMaps, "hash_of_maps": cebpf.HashOfMaps,
		"devmap": cebpf.DevMap, "dev_map": cebpf.DevMap, "sockmap": cebpf.SockMap, "sock_map": cebpf.SockMap, "cpumap": cebpf.CPUMap, "cpu_map": cebpf.CPUMap, "xskmap": cebpf.XSKMap, "xsk_map": cebpf.XSKMap,
		"sockhash": cebpf.SockHash, "sock_hash": cebpf.SockHash, "queue": cebpf.Queue, "stack": cebpf.Stack, "ringbuf": cebpf.RingBuf, "ring_buf": cebpf.RingBuf,
		"bloomfilter": cebpf.BloomFilter, "bloom_filter": cebpf.BloomFilter, "userringbuf": cebpf.UserRingbuf, "user_ringbuf": cebpf.UserRingbuf, "arena": cebpf.Arena,
	}
}

func ebpfProgramTypesByName() map[string]cebpf.ProgramType {
	return map[string]cebpf.ProgramType{
		"socketfilter": cebpf.SocketFilter, "socket_filter": cebpf.SocketFilter, "kprobe": cebpf.Kprobe, "schedcls": cebpf.SchedCLS, "sched_cls": cebpf.SchedCLS, "schedact": cebpf.SchedACT, "sched_act": cebpf.SchedACT,
		"tracepoint": cebpf.TracePoint, "trace_point": cebpf.TracePoint, "xdp": cebpf.XDP, "perfevent": cebpf.PerfEvent, "perf_event": cebpf.PerfEvent, "cgroupskb": cebpf.CGroupSKB, "cgroup_skb": cebpf.CGroupSKB,
		"cgroupsock": cebpf.CGroupSock, "cgroup_sock": cebpf.CGroupSock, "sockops": cebpf.SockOps, "sock_ops": cebpf.SockOps, "skskb": cebpf.SkSKB, "sk_skb": cebpf.SkSKB, "skmsg": cebpf.SkMsg, "sk_msg": cebpf.SkMsg,
		"rawtracepoint": cebpf.RawTracepoint, "raw_tracepoint": cebpf.RawTracepoint, "cgroupsockaddr": cebpf.CGroupSockAddr, "cgroup_sock_addr": cebpf.CGroupSockAddr, "skreuseport": cebpf.SkReuseport, "sk_reuseport": cebpf.SkReuseport,
		"flowdissector": cebpf.FlowDissector, "flow_dissector": cebpf.FlowDissector, "cgroupsysctl": cebpf.CGroupSysctl, "cgroup_sysctl": cebpf.CGroupSysctl, "tracing": cebpf.Tracing, "structops": cebpf.StructOps, "struct_ops": cebpf.StructOps,
		"extension": cebpf.Extension, "lsm": cebpf.LSM, "sklookup": cebpf.SkLookup, "sk_lookup": cebpf.SkLookup, "syscall": cebpf.Syscall, "netfilter": cebpf.Netfilter,
	}
}

func ebpfAttachTypesByName() map[string]cebpf.AttachType {
	return map[string]cebpf.AttachType{
		"none": cebpf.AttachNone, "cgroupinetingress": cebpf.AttachCGroupInetIngress, "cgroup_inet_ingress": cebpf.AttachCGroupInetIngress, "cgroupinetegress": cebpf.AttachCGroupInetEgress, "cgroup_inet_egress": cebpf.AttachCGroupInetEgress,
		"tracefentry": cebpf.AttachTraceFEntry, "trace_fentry": cebpf.AttachTraceFEntry, "tracefexit": cebpf.AttachTraceFExit, "trace_fexit": cebpf.AttachTraceFExit, "tracerawtp": cebpf.AttachTraceRawTp, "trace_raw_tp": cebpf.AttachTraceRawTp,
		"xdp": cebpf.AttachXDP, "sklookup": cebpf.AttachSkLookup, "sk_lookup": cebpf.AttachSkLookup, "netfilter": cebpf.AttachNetfilter, "tcxingress": cebpf.AttachTCXIngress, "tcx_ingress": cebpf.AttachTCXIngress, "tcxegress": cebpf.AttachTCXEgress, "tcx_egress": cebpf.AttachTCXEgress,
	}
}

func ebpfMapTypeAllowsZeroKey(typ cebpf.MapType) bool {
	return typ == cebpf.Queue || typ == cebpf.Stack || typ == cebpf.RingBuf || typ == cebpf.UserRingbuf || typ == cebpf.Arena
}

func ebpfMapTypeRequiresValueSize(typ cebpf.MapType) bool {
	switch typ {
	case cebpf.RingBuf, cebpf.UserRingbuf, cebpf.Arena:
		return false
	default:
		return true
	}
}

func normalizeEBPFName(text string) string {
	text = strings.TrimSpace(strings.ToLower(text))
	text = strings.TrimPrefix(text, "bpf_map_type_")
	text = strings.TrimPrefix(text, "bpf_prog_type_")
	text = strings.TrimPrefix(text, "bpf_attach_type_")
	text = strings.TrimPrefix(text, "ebpf.")
	text = strings.TrimPrefix(text, "ebpf_")
	text = strings.ReplaceAll(text, "-", "_")
	return text
}

func parseFlexibleUint(value any, bits int, field string) (uint64, error) {
	if value == nil {
		return 0, fmt.Errorf("%s is required", field)
	}
	max := uint64(math.MaxUint64)
	if bits < 64 {
		max = (uint64(1) << bits) - 1
	}
	var parsed uint64
	switch v := value.(type) {
	case uint64:
		parsed = v
	case uint32:
		parsed = uint64(v)
	case uint:
		parsed = uint64(v)
	case int:
		if v < 0 {
			return 0, fmt.Errorf("%s must be non-negative", field)
		}
		parsed = uint64(v)
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("%s must be non-negative", field)
		}
		parsed = uint64(v)
	case int32:
		if v < 0 {
			return 0, fmt.Errorf("%s must be non-negative", field)
		}
		parsed = uint64(v)
	case float64:
		if v < 0 || math.Trunc(v) != v {
			return 0, fmt.Errorf("%s must be a non-negative integer", field)
		}
		parsed = uint64(v)
	case float32:
		if v < 0 || math.Trunc(float64(v)) != float64(v) {
			return 0, fmt.Errorf("%s must be a non-negative integer", field)
		}
		parsed = uint64(v)
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, fmt.Errorf("%s is required", field)
		}
		if constant, ok := lookupConstant(text); ok {
			parsed = constant
		} else {
			value, err := strconv.ParseUint(text, 0, bits)
			if err != nil {
				return 0, fmt.Errorf("parse %s %q: %w", field, text, err)
			}
			parsed = value
		}
	default:
		return 0, fmt.Errorf("%s has unsupported type %T", field, value)
	}
	if parsed > max {
		return 0, fmt.Errorf("%s %d overflows uint%d", field, parsed, bits)
	}
	return parsed, nil
}

func parseOptionalInt64(value any, field string) (int64, error) {
	if value == nil {
		return 0, nil
	}
	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("%s overflows int64", field)
		}
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, fmt.Errorf("%s overflows int64", field)
		}
		return int64(v), nil
	case float64:
		if math.Trunc(v) != v || v < math.MinInt64 || v > math.MaxInt64 {
			return 0, fmt.Errorf("%s must be an int64", field)
		}
		return int64(v), nil
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, nil
		}
		if constant, ok := lookupConstant(text); ok {
			return int64(constant), nil
		}
		if parsed, err := strconv.ParseInt(text, 0, 64); err == nil {
			return parsed, nil
		}
		parsed, err := strconv.ParseUint(text, 0, 64)
		if err != nil || parsed > math.MaxInt64 {
			if err == nil {
				err = fmt.Errorf("overflows int64")
			}
			return 0, fmt.Errorf("parse %s %q: %w", field, text, err)
		}
		return int64(parsed), nil
	default:
		return 0, fmt.Errorf("%s has unsupported type %T", field, value)
	}
}

func pinnedPathForName(pinPath, name string) string {
	if pinPath == "" || name == "" {
		return ""
	}
	return strings.TrimRight(pinPath, "/") + "/" + name
}

func supportedEBPFTargets() []string {
	return []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "linux/loong64", "linux/mips", "linux/mips64", "linux/mips64le", "linux/mipsle", "linux/ppc64", "linux/ppc64le", "linux/riscv64", "linux/s390x"}
}

func _keepBase64ImportForEBPF() {
	_ = base64.StdEncoding
}
