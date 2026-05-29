package mcpserver

import (
	"fmt"
	"runtime"
	"time"

	"github.com/dop251/goja"
	"golang.org/x/sys/unix"
)

type scriptDataArg struct {
	DataBase64   string `json:"data_base64"`
	DataHex      string `json:"data_hex"`
	DataUTF8     string `json:"data_utf8"`
	Buffer       string `json:"buffer"`
	BufferOffset Uint64 `json:"buffer_offset"`
	Length       Uint64 `json:"length"`
}

type scriptReadIovecArg struct {
	Length Uint64 `json:"length"`
}

type scriptRemoteIovecArg struct {
	Address Uint64 `json:"address"`
	Length  Uint64 `json:"length"`
}

type scriptVectoredReadArgs struct {
	ScriptFDRefArgs
	Iovecs   []scriptReadIovecArg `json:"iovecs"`
	Offset   *Uint64              `json:"offset"`
	Flags    ConstUint64          `json:"flags"`
	Encoding string               `json:"encoding"`
}

type scriptVectoredWriteArgs struct {
	ScriptFDRefArgs
	Iovecs []scriptDataArg `json:"iovecs"`
	Offset *Uint64         `json:"offset"`
	Flags  ConstUint64     `json:"flags"`
}

type scriptProcessVMReadvArgs struct {
	PID        int                    `json:"pid"`
	Address    Uint64                 `json:"address"`
	Length     Uint64                 `json:"length"`
	LocalIovs  []scriptReadIovecArg   `json:"local_iovs"`
	RemoteIovs []scriptRemoteIovecArg `json:"remote_iovs"`
	Flags      ConstUint64            `json:"flags"`
	Encoding   string                 `json:"encoding"`
}

type scriptProcessVMWritevArgs struct {
	PID        int                    `json:"pid"`
	Address    Uint64                 `json:"address"`
	LocalIovs  []scriptDataArg        `json:"local_iovs"`
	RemoteIovs []scriptRemoteIovecArg `json:"remote_iovs"`
	Flags      ConstUint64            `json:"flags"`
	scriptDataArg
}

type scriptSpliceArgs struct {
	InHandle  string      `json:"in_handle"`
	InFD      *int        `json:"in_fd"`
	OutHandle string      `json:"out_handle"`
	OutFD     *int        `json:"out_fd"`
	InOffset  *Uint64     `json:"in_offset"`
	OutOffset *Uint64     `json:"out_offset"`
	Length    Uint64      `json:"length"`
	Flags     ConstUint64 `json:"flags"`
}

type scriptOpenat2Args struct {
	DirFD   *ConstUint64 `json:"dirfd"`
	Path    string       `json:"path"`
	Flags   ConstUint64  `json:"flags"`
	Mode    Uint64       `json:"mode"`
	Resolve ConstUint64  `json:"resolve"`
	Handle  string       `json:"handle"`
}

type scriptFDRangeArgs struct {
	ScriptFDRefArgs
	Offset Uint64      `json:"offset"`
	Length Uint64      `json:"length"`
	Mode   ConstUint64 `json:"mode"`
	Advice ConstUint64 `json:"advice"`
	Flags  ConstUint64 `json:"flags"`
}

type scriptGetdentsArgs struct {
	ScriptFDRefArgs
	Size     Uint64 `json:"size"`
	MaxNames int    `json:"max_names"`
	Encoding string `json:"encoding"`
}

type scriptPidfdOpenArgs struct {
	PID    int         `json:"pid"`
	Flags  ConstUint64 `json:"flags"`
	Handle string      `json:"handle"`
}

type scriptPidfdGetfdArgs struct {
	ScriptFDRefArgs
	TargetFD  int         `json:"target_fd"`
	Flags     ConstUint64 `json:"flags"`
	NewHandle string      `json:"new_handle"`
}

type scriptPidfdSignalArgs struct {
	ScriptFDRefArgs
	Signal ConstUint64 `json:"signal"`
	Flags  ConstUint64 `json:"flags"`
}

type scriptClockArgs struct {
	ClockID ConstUint64 `json:"clockid"`
}

type scriptTimespecArg struct {
	Sec        int64  `json:"sec"`
	Nsec       int64  `json:"nsec"`
	DurationMS Uint64 `json:"duration_ms"`
}

type scriptTimerfdCreateArgs struct {
	ClockID ConstUint64 `json:"clockid"`
	Flags   ConstUint64 `json:"flags"`
	Handle  string      `json:"handle"`
}

type scriptTimerfdSettimeArgs struct {
	ScriptFDRefArgs
	Flags        ConstUint64       `json:"flags"`
	Value        scriptTimespecArg `json:"value"`
	Interval     scriptTimespecArg `json:"interval"`
	ValueSec     int64             `json:"value_sec"`
	ValueNsec    int64             `json:"value_nsec"`
	IntervalSec  int64             `json:"interval_sec"`
	IntervalNsec int64             `json:"interval_nsec"`
	ValueMS      Uint64            `json:"value_ms"`
	IntervalMS   Uint64            `json:"interval_ms"`
}

type scriptPriorityArgs struct {
	Which ConstUint64 `json:"which"`
	Who   int         `json:"who"`
	Prio  int         `json:"prio"`
}

type scriptProcessGroupArgs struct {
	PID  int `json:"pid"`
	PGID int `json:"pgid"`
}

type scriptPrlimitArgs struct {
	PID      int         `json:"pid"`
	Resource ConstUint64 `json:"resource"`
	Cur      *Uint64     `json:"cur"`
	Max      *Uint64     `json:"max"`
}

type scriptSendArgs struct {
	ScriptFDRefArgs
	Flags ConstUint64 `json:"flags"`
	scriptDataArg
}

type scriptMsgArgs struct {
	ScriptFDRefArgs
	Flags         ConstUint64   `json:"flags"`
	Sockaddr      *sockaddrSpec `json:"sockaddr"`
	OOBBase64     string        `json:"oob_base64"`
	OOBHex        string        `json:"oob_hex"`
	OOBUTF8       string        `json:"oob_utf8"`
	RightsHandles []string      `json:"rights_handles"`
	RightsFDs     []int         `json:"rights_fds"`
	scriptDataArg
}

type scriptRecvmsgArgs struct {
	ScriptFDRefArgs
	Length      Uint64      `json:"length"`
	OOBLength   Uint64      `json:"oob_length"`
	Flags       ConstUint64 `json:"flags"`
	Encoding    string      `json:"encoding"`
	OOBEncoding string      `json:"oob_encoding"`
	ParseRights bool        `json:"parse_rights"`
}

type scriptSockoptScalarArgs struct {
	ScriptFDRefArgs
	Level ConstUint64 `json:"level"`
	Opt   ConstUint64 `json:"opt"`
	Value ConstUint64 `json:"value"`
	Text  string      `json:"text"`
}

type scriptRawSyscallArgs struct {
	Trap ConstUint64 `json:"trap"`
	A1   Uint64      `json:"a1"`
	A2   Uint64      `json:"a2"`
	A3   Uint64      `json:"a3"`
	A4   Uint64      `json:"a4"`
	A5   Uint64      `json:"a5"`
	A6   Uint64      `json:"a6"`
}

func (e *scriptEnv) scriptReadv(value goja.Value) (any, error) {
	return e.readv(value, false, false)
}

func (e *scriptEnv) scriptPreadv(value goja.Value) (any, error) {
	return e.readv(value, true, false)
}

func (e *scriptEnv) scriptPreadv2(value goja.Value) (any, error) {
	return e.readv(value, true, true)
}

func (e *scriptEnv) readv(value goja.Value, withOffset, withFlags bool) (any, error) {
	var args scriptVectoredReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	buffers, total, err := e.readIovecBuffers(args.Iovecs)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"handle": handle, "fd": fd, "iovecs_requested": len(buffers), "bytes_requested": total}
	var n int
	if withOffset {
		if args.Offset == nil {
			return nil, fmt.Errorf("offset is required")
		}
		offset, err := checkedInt64("offset", *args.Offset)
		if err != nil {
			return nil, err
		}
		fields["offset"] = offset
		if withFlags {
			fields["flags"] = int(args.Flags)
			n, err = unix.Preadv2(fd, buffers, offset, int(args.Flags))
		} else {
			n, err = unix.Preadv(fd, buffers, offset)
		}
	} else {
		n, err = unix.Readv(fd, buffers)
	}
	fields["bytes_read"] = n
	if err == nil {
		if encErr := addReadvData(fields, buffers, n, args.Encoding); encErr != nil {
			return nil, encErr
		}
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptWritev(value goja.Value) (any, error) {
	return e.writev(value, false, false)
}

func (e *scriptEnv) scriptPwritev(value goja.Value) (any, error) {
	return e.writev(value, true, false)
}

func (e *scriptEnv) scriptPwritev2(value goja.Value) (any, error) {
	return e.writev(value, true, true)
}

func (e *scriptEnv) writev(value goja.Value, withOffset, withFlags bool) (any, error) {
	var args scriptVectoredWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, buffers, checksum, err := e.writeIovecBuffers(args.ScriptFDRefArgs, args.Iovecs)
	if err != nil {
		return nil, err
	}
	total := totalBufferLength(buffers)
	fields := map[string]any{"handle": handle, "fd": fd, "iovecs_requested": len(buffers), "bytes_requested": total, "checksum64": checksum}
	var n int
	if withOffset {
		if args.Offset == nil {
			return nil, fmt.Errorf("offset is required")
		}
		offset, err := checkedInt64("offset", *args.Offset)
		if err != nil {
			return nil, err
		}
		fields["offset"] = offset
		if withFlags {
			fields["flags"] = int(args.Flags)
			n, err = unix.Pwritev2(fd, buffers, offset, int(args.Flags))
		} else {
			n, err = unix.Pwritev(fd, buffers, offset)
		}
	} else {
		n, err = unix.Writev(fd, buffers)
	}
	fields["bytes_written"] = n
	runtime.KeepAlive(buffers)
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptProcessVMReadv(value goja.Value) (any, error) {
	var args scriptProcessVMReadvArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	remote, remoteTotal, err := processRemoteIovecs(args.RemoteIovs, args.Address, args.Length)
	if err != nil {
		return nil, err
	}
	localSpecs := args.LocalIovs
	if len(localSpecs) == 0 {
		localSpecs = []scriptReadIovecArg{{Length: Uint64(remoteTotal)}}
	}
	buffers, localTotal, err := e.readIovecBuffers(localSpecs)
	if err != nil {
		return nil, err
	}
	local, err := unixIovecsForBuffers(buffers)
	if err != nil {
		return nil, err
	}
	n, err := unix.ProcessVMReadv(args.PID, local, remote, uint(args.Flags))
	fields := map[string]any{"pid": args.PID, "local_iovecs": len(local), "remote_iovecs": len(remote), "bytes_requested": localTotal, "remote_bytes": remoteTotal, "flags": uint(args.Flags), "bytes_read": n}
	if err == nil {
		if encErr := addReadvData(fields, buffers, n, args.Encoding); encErr != nil {
			return nil, encErr
		}
	}
	runtime.KeepAlive(buffers)
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptProcessVMWritev(value goja.Value) (any, error) {
	var args scriptProcessVMWritevArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	localSpecs := args.LocalIovs
	if len(localSpecs) == 0 {
		localSpecs = []scriptDataArg{args.scriptDataArg}
	}
	buffers, checksum, err := e.dataIovecBuffers(localSpecs)
	if err != nil {
		return nil, err
	}
	local, err := unixIovecsForBuffers(buffers)
	if err != nil {
		return nil, err
	}
	remote, remoteTotal, err := processRemoteIovecs(args.RemoteIovs, args.Address, Uint64(totalBufferLength(buffers)))
	if err != nil {
		return nil, err
	}
	n, err := unix.ProcessVMWritev(args.PID, local, remote, uint(args.Flags))
	fields := map[string]any{"pid": args.PID, "local_iovecs": len(local), "remote_iovecs": len(remote), "bytes_requested": totalBufferLength(buffers), "remote_bytes": remoteTotal, "flags": uint(args.Flags), "bytes_written": n, "checksum64": checksum}
	runtime.KeepAlive(buffers)
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptSplice(value goja.Value) (any, error) {
	var args scriptSpliceArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	inFD, inHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.InHandle, FD: args.InFD})
	if err != nil {
		return nil, fmt.Errorf("in fd: %w", err)
	}
	outFD, outHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.OutHandle, FD: args.OutFD})
	if err != nil {
		return nil, fmt.Errorf("out fd: %w", err)
	}
	length, err := checkedInt("length", args.Length)
	if err != nil {
		return nil, err
	}
	inOffset, err := optionalInt64(args.InOffset, "in_offset")
	if err != nil {
		return nil, err
	}
	outOffset, err := optionalInt64(args.OutOffset, "out_offset")
	if err != nil {
		return nil, err
	}
	n, err := unix.Splice(inFD, inOffset, outFD, outOffset, length, int(args.Flags))
	fields := map[string]any{"in_handle": inHandle, "in_fd": inFD, "out_handle": outHandle, "out_fd": outFD, "length": length, "flags": int(args.Flags), "bytes_moved": n}
	if inOffset != nil {
		fields["in_offset"] = *inOffset
	}
	if outOffset != nil {
		fields["out_offset"] = *outOffset
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptTee(value goja.Value) (any, error) {
	var args scriptSpliceArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	inFD, inHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.InHandle, FD: args.InFD})
	if err != nil {
		return nil, fmt.Errorf("in fd: %w", err)
	}
	outFD, outHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.OutHandle, FD: args.OutFD})
	if err != nil {
		return nil, fmt.Errorf("out fd: %w", err)
	}
	length, err := checkedInt("length", args.Length)
	if err != nil {
		return nil, err
	}
	n, err := unix.Tee(inFD, outFD, length, int(args.Flags))
	return scriptSyscallResult(map[string]any{"in_handle": inHandle, "in_fd": inFD, "out_handle": outHandle, "out_fd": outFD, "length": length, "flags": int(args.Flags), "bytes_moved": n}, err)
}

func (e *scriptEnv) scriptVmsplice(value goja.Value) (any, error) {
	var args scriptVectoredWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, buffers, checksum, err := e.writeIovecBuffers(args.ScriptFDRefArgs, args.Iovecs)
	if err != nil {
		return nil, err
	}
	iovecs, err := unixIovecsForBuffers(buffers)
	if err != nil {
		return nil, err
	}
	n, err := unix.Vmsplice(fd, iovecs, int(args.Flags))
	runtime.KeepAlive(buffers)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "iovecs_requested": len(iovecs), "bytes_requested": totalBufferLength(buffers), "bytes_written": n, "flags": int(args.Flags), "checksum64": checksum}, err)
}

func (e *scriptEnv) scriptCreat(value goja.Value) (any, error) {
	var args struct {
		scriptPathModeArgs
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.Creat(args.Path, uint32(args.Mode))
	return e.registerScriptFD(fd, "file", args.Path, args.Handle, map[string]any{"mode": uint32(args.Mode)}, map[string]any{"path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptFaccessat2(value goja.Value) (any, error) {
	var args scriptAtPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Faccessat2(dirfd, args.Path, uint32(args.Mode), int(args.Flags))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode), "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptOpenat2(value goja.Value) (any, error) {
	var args scriptOpenat2Args
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	how := &unix.OpenHow{Flags: uint64(args.Flags), Mode: uint64(args.Mode), Resolve: uint64(args.Resolve)}
	fd, err := unix.Openat2(dirfd, args.Path, how)
	return e.registerScriptFD(fd, "file", args.Path, args.Handle, map[string]any{"dirfd": dirfd, "flags": how.Flags, "resolve": how.Resolve}, map[string]any{"dirfd": dirfd, "path": args.Path, "flags": how.Flags, "mode": how.Mode, "resolve": how.Resolve}, err)
}

func (e *scriptEnv) scriptFadvise(value goja.Value) (any, error) {
	var args scriptFDRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	length, err := checkedInt64("length", args.Length)
	if err != nil {
		return nil, err
	}
	err = unix.Fadvise(fd, offset, length, int(args.Advice))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "offset": offset, "length": length, "advice": int(args.Advice)}, err)
}

func (e *scriptEnv) scriptFallocate(value goja.Value) (any, error) {
	var args scriptFDRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	length, err := checkedInt64("length", args.Length)
	if err != nil {
		return nil, err
	}
	err = unix.Fallocate(fd, uint32(args.Mode), offset, length)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "offset": offset, "length": length, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptSyncFileRange(value goja.Value) (any, error) {
	var args scriptFDRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	length, err := checkedInt64("length", args.Length)
	if err != nil {
		return nil, err
	}
	err = unix.SyncFileRange(fd, offset, length, int(args.Flags))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "offset": offset, "length": length, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptFlock(value goja.Value) (any, error) {
	var args scriptFDRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.Flock(fd, int(args.Flags))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "how": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptGetdents(value goja.Value) (any, error) {
	return e.direntRead(value, unix.Getdents, "getdents")
}

func (e *scriptEnv) scriptReadDirent(value goja.Value) (any, error) {
	return e.direntRead(value, unix.ReadDirent, "readDirent")
}

func (e *scriptEnv) direntRead(value goja.Value, fn func(int, []byte) (int, error), operation string) (any, error) {
	var args scriptGetdentsArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	size := uint64(args.Size)
	if size == 0 {
		size = 8192
	}
	if size > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("size %d exceeds max_read_bytes %d", size, e.app.config.MaxReadBytes)
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, int(size))
	n, err := fn(fd, buf)
	fields := map[string]any{"operation": operation, "handle": handle, "fd": fd, "bytes_read": n}
	if err == nil {
		encoded, encErr := encodeBytes(buf[:n], args.Encoding)
		if encErr != nil {
			return nil, encErr
		}
		for key, value := range encoded {
			fields[key] = value
		}
		_, _, names := unix.ParseDirent(buf[:n], args.MaxNames, nil)
		fields["names"] = names
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptGetrandom(value goja.Value) (any, error) {
	var args struct {
		Length   Uint64      `json:"length"`
		Flags    ConstUint64 `json:"flags"`
		Encoding string      `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	buf := make([]byte, int(args.Length))
	n, err := unix.Getrandom(buf, int(args.Flags))
	fields := map[string]any{"length": uint64(args.Length), "flags": int(args.Flags), "bytes_read": n}
	if err == nil {
		encoded, encErr := encodeBytes(buf[:n], args.Encoding)
		if encErr != nil {
			return nil, encErr
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptPidfdOpen(value goja.Value) (any, error) {
	var args scriptPidfdOpenArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.PidfdOpen(args.PID, int(args.Flags))
	return e.registerScriptFD(fd, "pidfd", "", args.Handle, map[string]any{"pid": args.PID, "flags": int(args.Flags)}, map[string]any{"pid": args.PID, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptPidfdGetfd(value goja.Value) (any, error) {
	var args scriptPidfdGetfdArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	pidfd, pidHandle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	newFD, err := unix.PidfdGetfd(pidfd, args.TargetFD, int(args.Flags))
	return e.registerScriptFD(newFD, "pidfd_target", "", args.NewHandle, map[string]any{"pidfd": pidHandle, "target_fd": args.TargetFD}, map[string]any{"pidfd_handle": pidHandle, "pidfd": pidfd, "target_fd": args.TargetFD, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptPidfdSendSignal(value goja.Value) (any, error) {
	var args scriptPidfdSignalArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.PidfdSendSignal(fd, unix.Signal(args.Signal), nil, int(args.Flags))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "signal": int(args.Signal), "flags": uint(args.Flags)}, err)
}

func (e *scriptEnv) scriptClockGettime(value goja.Value) (any, error) {
	var args scriptClockArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	clockid := int32(args.ClockID)
	var ts unix.Timespec
	err := unix.ClockGettime(clockid, &ts)
	return scriptSyscallResult(map[string]any{"clockid": clockid, "time": timespecInfo(ts)}, err)
}

func (e *scriptEnv) scriptClockGetres(value goja.Value) (any, error) {
	var args scriptClockArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	clockid := int32(args.ClockID)
	var ts unix.Timespec
	err := unix.ClockGetres(clockid, &ts)
	return scriptSyscallResult(map[string]any{"clockid": clockid, "resolution": timespecInfo(ts)}, err)
}

func (e *scriptEnv) scriptGettimeofday(value goja.Value) (any, error) {
	var tv unix.Timeval
	err := unix.Gettimeofday(&tv)
	return scriptSyscallResult(map[string]any{"time": timevalInfo(tv)}, err)
}

func (e *scriptEnv) scriptNanosleep(value goja.Value) (any, error) {
	var args scriptTimespecArg
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	req := timespecFromArg(args)
	var rem unix.Timespec
	err := unix.Nanosleep(&req, &rem)
	return scriptSyscallResult(map[string]any{"request": timespecInfo(req), "remain": timespecInfo(rem)}, err)
}

func (e *scriptEnv) scriptTimerfdCreate(value goja.Value) (any, error) {
	var args scriptTimerfdCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	clockid := int(args.ClockID)
	if clockid == 0 {
		clockid = unix.CLOCK_MONOTONIC
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.TFD_CLOEXEC
	}
	fd, err := unix.TimerfdCreate(clockid, flags)
	return e.registerScriptFD(fd, "timerfd", "", args.Handle, map[string]any{"clockid": clockid, "flags": flags}, map[string]any{"clockid": clockid, "flags": flags}, err)
}

func (e *scriptEnv) scriptTimerfdGettime(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	var spec unix.ItimerSpec
	err = unix.TimerfdGettime(fd, &spec)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "timer": itimerSpecInfo(spec)}, err)
}

func (e *scriptEnv) scriptTimerfdSettime(value goja.Value) (any, error) {
	var args scriptTimerfdSettimeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	valueSpec := args.Value
	if valueSpec.Sec == 0 && valueSpec.Nsec == 0 && valueSpec.DurationMS == 0 {
		valueSpec = scriptTimespecArg{Sec: args.ValueSec, Nsec: args.ValueNsec, DurationMS: args.ValueMS}
	}
	intervalSpec := args.Interval
	if intervalSpec.Sec == 0 && intervalSpec.Nsec == 0 && intervalSpec.DurationMS == 0 {
		intervalSpec = scriptTimespecArg{Sec: args.IntervalSec, Nsec: args.IntervalNsec, DurationMS: args.IntervalMS}
	}
	newSpec := unix.ItimerSpec{Value: timespecFromArg(valueSpec), Interval: timespecFromArg(intervalSpec)}
	var oldSpec unix.ItimerSpec
	err = unix.TimerfdSettime(fd, int(args.Flags), &newSpec, &oldSpec)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "flags": int(args.Flags), "timer": itimerSpecInfo(newSpec), "old_timer": itimerSpecInfo(oldSpec)}, err)
}

func (e *scriptEnv) scriptGetpgid(value goja.Value) (any, error) {
	var args ptracePIDArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	pgid, err := unix.Getpgid(args.PID)
	return scriptSyscallResult(map[string]any{"pid": args.PID, "pgid": pgid}, err)
}

func (e *scriptEnv) scriptGetpgrp(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "pgrp": unix.Getpgrp()}, nil
}

func (e *scriptEnv) scriptGetsid(value goja.Value) (any, error) {
	var args ptracePIDArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	sid, err := unix.Getsid(args.PID)
	return scriptSyscallResult(map[string]any{"pid": args.PID, "sid": sid}, err)
}

func (e *scriptEnv) scriptGetpriority(value goja.Value) (any, error) {
	var args scriptPriorityArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	prio, err := unix.Getpriority(int(args.Which), args.Who)
	return scriptSyscallResult(map[string]any{"which": int(args.Which), "who": args.Who, "priority": prio}, err)
}

func (e *scriptEnv) scriptSetpriority(value goja.Value) (any, error) {
	var args scriptPriorityArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Setpriority(int(args.Which), args.Who, args.Prio)
	return scriptSyscallResult(map[string]any{"which": int(args.Which), "who": args.Who, "priority": args.Prio}, err)
}

func (e *scriptEnv) scriptSetpgid(value goja.Value) (any, error) {
	var args scriptProcessGroupArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Setpgid(args.PID, args.PGID)
	return scriptSyscallResult(map[string]any{"pid": args.PID, "pgid": args.PGID}, err)
}

func (e *scriptEnv) scriptSetsid(value goja.Value) (any, error) {
	pid, err := unix.Setsid()
	return scriptSyscallResult(map[string]any{"pid": pid}, err)
}

func (e *scriptEnv) scriptTgkill(value goja.Value) (any, error) {
	var args struct {
		TGID   int         `json:"tgid"`
		TID    int         `json:"tid"`
		Signal ConstUint64 `json:"signal"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Tgkill(args.TGID, args.TID, unix.Signal(args.Signal))
	return scriptSyscallResult(map[string]any{"tgid": args.TGID, "tid": args.TID, "signal": int(args.Signal)}, err)
}

func (e *scriptEnv) scriptPrlimit(value goja.Value) (any, error) {
	var args scriptPrlimitArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var old unix.Rlimit
	var newLimit *unix.Rlimit
	if args.Cur != nil || args.Max != nil {
		if args.Cur == nil || args.Max == nil {
			return nil, fmt.Errorf("cur and max must be provided together")
		}
		newLimit = &unix.Rlimit{Cur: uint64(*args.Cur), Max: uint64(*args.Max)}
	}
	err := unix.Prlimit(args.PID, int(args.Resource), newLimit, &old)
	fields := map[string]any{"pid": args.PID, "resource": int(args.Resource), "old_rlimit": rlimitInfo(old)}
	if newLimit != nil {
		fields["new_rlimit"] = rlimitInfo(*newLimit)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptPrctlRetInt(value goja.Value) (any, error) {
	var args prctlArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r, err := unix.PrctlRetInt(int(args.Option), uintptr(args.Arg2), uintptr(args.Arg3), uintptr(args.Arg4), uintptr(args.Arg5))
	return scriptSyscallResult(map[string]any{"option": int(args.Option), "arg2": hex64(uint64(args.Arg2)), "arg3": hex64(uint64(args.Arg3)), "arg4": hex64(uint64(args.Arg4)), "arg5": hex64(uint64(args.Arg5)), "return": r}, err)
}

func (e *scriptEnv) scriptSend(value goja.Value) (any, error) {
	var args scriptSendArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, data, err := e.dataForFD(args.ScriptFDRefArgs, args.scriptDataArg)
	if err != nil {
		return nil, err
	}
	err = unix.Send(fd, data, int(args.Flags))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(data), "bytes_sent": len(data), "flags": int(args.Flags), "checksum64": checksum64(data)}, err)
}

func (e *scriptEnv) scriptSendmsg(value goja.Value) (any, error) {
	var args scriptMsgArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var sa unix.Sockaddr
	var err error
	if args.Sockaddr != nil {
		sa, err = parseSockaddr(*args.Sockaddr)
		if err != nil {
			return nil, err
		}
	}
	fd, handle, data, err := e.dataForFD(args.ScriptFDRefArgs, args.scriptDataArg)
	if err != nil {
		return nil, err
	}
	oob, err := decodeDirectData(args.OOBBase64, args.OOBHex, args.OOBUTF8, nil)
	if err != nil {
		return nil, err
	}
	rights, err := e.rightsControlMessage(args.RightsHandles, args.RightsFDs)
	if err != nil {
		return nil, err
	}
	oob = append(oob, rights...)
	n, err := unix.SendmsgN(fd, data, oob, sa, int(args.Flags))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(data), "bytes_sent": n, "oob_bytes": len(oob), "rights_count": len(args.RightsHandles) + len(args.RightsFDs), "flags": int(args.Flags), "checksum64": checksum64(data), "sockaddr": sockaddrInfo(sa)}, err)
}

func (e *scriptEnv) scriptRecvmsg(value goja.Value) (any, error) {
	var args scriptRecvmsgArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) || args.OOBLength > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length exceeds max_read_bytes %d", e.app.config.MaxReadBytes)
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(args.Length))
	oobLength := uint64(args.OOBLength)
	if args.ParseRights && oobLength == 0 {
		oobLength = uint64(unix.CmsgSpace(4 * 16))
	}
	oob := make([]byte, int(oobLength))
	n, oobn, recvflags, sa, err := unix.Recvmsg(fd, data, oob, int(args.Flags))
	fields := map[string]any{"handle": handle, "fd": fd, "bytes_received": n, "oob_bytes_received": oobn, "recv_flags": recvflags, "flags": int(args.Flags), "sockaddr": sockaddrInfo(sa)}
	if err == nil {
		encoded, encErr := encodeBytes(data[:n], args.Encoding)
		if encErr != nil {
			return nil, encErr
		}
		for key, value := range encoded {
			fields[key] = value
		}
		if oobn > 0 {
			oobEncoding := args.OOBEncoding
			if oobEncoding == "" {
				oobEncoding = "hex"
			}
			oobEncoded, encErr := encodeBytes(oob[:oobn], oobEncoding)
			if encErr != nil {
				return nil, encErr
			}
			fields["oob"] = oobEncoded
		}
		if args.ParseRights {
			rights, parseErr := e.registerRights(oob[:oobn])
			if parseErr != nil {
				fields["rights_error"] = parseErr.Error()
			} else {
				fields["rights"] = rights
			}
		}
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptBindToDevice(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Device string `json:"device"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.BindToDevice(fd, args.Device)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "device": args.Device}, err)
}

func (e *scriptEnv) scriptSetsockoptString(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.SetsockoptString(fd, int(args.Level), int(args.Opt), args.Text)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": args.Text}, err)
}

func (e *scriptEnv) scriptGetsockoptString(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	text, err := unix.GetsockoptString(fd, int(args.Level), int(args.Opt))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": text}, err)
}

func (e *scriptEnv) scriptSetsockoptByte(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.SetsockoptByte(fd, int(args.Level), int(args.Opt), byte(args.Value))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": uint8(args.Value)}, err)
}

func (e *scriptEnv) scriptGetsockoptByte(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	optValue, err := unix.GetsockoptByte(fd, int(args.Level), int(args.Opt))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": optValue}, err)
}

func (e *scriptEnv) scriptSetsockoptUint64(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.SetsockoptUint64(fd, int(args.Level), int(args.Opt), uint64(args.Value))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": uint64(args.Value)}, err)
}

func (e *scriptEnv) scriptGetsockoptUint64(value goja.Value) (any, error) {
	var args scriptSockoptScalarArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	optValue, err := unix.GetsockoptUint64(fd, int(args.Level), int(args.Opt))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "level": int(args.Level), "opt": int(args.Opt), "value": optValue}, err)
}

func (e *scriptEnv) scriptAuxv(value goja.Value) (any, error) {
	entries, err := unix.Auxv()
	items := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		items = append(items, map[string]any{"key": uint64(entry[0]), "value": hex64(uint64(entry[1]))})
	}
	return scriptSyscallResult(map[string]any{"entries": items}, err)
}

func (e *scriptEnv) scriptGetpagesize(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "pagesize": unix.Getpagesize()}, nil
}

func (e *scriptEnv) scriptSysinfo(value goja.Value) (any, error) {
	var info unix.Sysinfo_t
	err := unix.Sysinfo(&info)
	fields := map[string]any{}
	if err == nil {
		fields["sysinfo"] = map[string]any{"uptime": info.Uptime, "loads": []uint64{uint64(info.Loads[0]), uint64(info.Loads[1]), uint64(info.Loads[2])}, "totalram": info.Totalram, "freeram": info.Freeram, "sharedram": info.Sharedram, "bufferram": info.Bufferram, "totalswap": info.Totalswap, "freeswap": info.Freeswap, "procs": info.Procs, "totalhigh": info.Totalhigh, "freehigh": info.Freehigh, "unit": info.Unit}
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptMajor(value goja.Value) (any, error) {
	dev, err := jsUint64(value)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "dev": dev, "major": unix.Major(dev)}, nil
}

func (e *scriptEnv) scriptMinor(value goja.Value) (any, error) {
	dev, err := jsUint64(value)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "dev": dev, "minor": unix.Minor(dev)}, nil
}

func (e *scriptEnv) scriptMkdev(value goja.Value) (any, error) {
	var args struct {
		Major Uint32 `json:"major"`
		Minor Uint32 `json:"minor"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dev := unix.Mkdev(uint32(args.Major), uint32(args.Minor))
	return map[string]any{"ok": true, "dev": dev, "hex": hex64(dev), "major": uint32(args.Major), "minor": uint32(args.Minor)}, nil
}

func (e *scriptEnv) scriptUmask(value goja.Value) (any, error) {
	var args struct {
		Mask ConstUint64 `json:"mask"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	old := unix.Umask(int(args.Mask))
	return map[string]any{"ok": true, "old_mask": old, "mask": int(args.Mask)}, nil
}

func (e *scriptEnv) scriptSyscall(value goja.Value) (any, error) {
	var args scriptRawSyscallArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r1, r2, errno := unix.Syscall(uintptr(args.Trap), uintptr(args.A1), uintptr(args.A2), uintptr(args.A3))
	return scriptSyscallResult(rawSyscallFields(args, r1, r2), syscallErrno(errno))
}

func (e *scriptEnv) scriptSyscall6(value goja.Value) (any, error) {
	var args scriptRawSyscallArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r1, r2, errno := unix.Syscall6(uintptr(args.Trap), uintptr(args.A1), uintptr(args.A2), uintptr(args.A3), uintptr(args.A4), uintptr(args.A5), uintptr(args.A6))
	return scriptSyscallResult(rawSyscallFields(args, r1, r2), syscallErrno(errno))
}

func (e *scriptEnv) scriptRawSyscall(value goja.Value) (any, error) {
	var args scriptRawSyscallArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r1, r2, errno := unix.RawSyscall(uintptr(args.Trap), uintptr(args.A1), uintptr(args.A2), uintptr(args.A3))
	return scriptSyscallResult(rawSyscallFields(args, r1, r2), syscallErrno(errno))
}

func (e *scriptEnv) scriptRawSyscall6(value goja.Value) (any, error) {
	var args scriptRawSyscallArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r1, r2, errno := unix.RawSyscall6(uintptr(args.Trap), uintptr(args.A1), uintptr(args.A2), uintptr(args.A3), uintptr(args.A4), uintptr(args.A5), uintptr(args.A6))
	return scriptSyscallResult(rawSyscallFields(args, r1, r2), syscallErrno(errno))
}

func syscallErrno(errno unix.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

func (e *scriptEnv) readIovecBuffers(specs []scriptReadIovecArg) ([][]byte, int, error) {
	if len(specs) == 0 {
		return nil, 0, fmt.Errorf("iovecs must not be empty")
	}
	buffers := make([][]byte, len(specs))
	total := 0
	for i, spec := range specs {
		length, err := checkedInt(fmt.Sprintf("iovecs[%d].length", i), spec.Length)
		if err != nil {
			return nil, 0, err
		}
		if length <= 0 {
			return nil, 0, fmt.Errorf("iovecs[%d].length must be greater than zero", i)
		}
		if uint64(total)+uint64(length) > e.app.config.MaxReadBytes {
			return nil, 0, fmt.Errorf("iovecs total length exceeds max_read_bytes %d", e.app.config.MaxReadBytes)
		}
		buffers[i] = make([]byte, length)
		total += length
	}
	return buffers, total, nil
}

func (e *scriptEnv) writeIovecBuffers(ref ScriptFDRefArgs, specs []scriptDataArg) (int, string, [][]byte, string, error) {
	fd, handle, err := e.resolveScriptFD(ref)
	if err != nil {
		return 0, "", nil, "", err
	}
	buffers, checksum, err := e.dataIovecBuffers(specs)
	if err != nil {
		return 0, "", nil, "", err
	}
	return fd, handle, buffers, checksum, nil
}

func (e *scriptEnv) dataIovecBuffers(specs []scriptDataArg) ([][]byte, string, error) {
	if len(specs) == 0 {
		return nil, "", fmt.Errorf("iovecs must not be empty")
	}
	buffers := make([][]byte, len(specs))
	combined := []byte{}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	for i, spec := range specs {
		data, err := e.app.inputBytesLocked(spec.DataBase64, spec.DataHex, spec.DataUTF8, spec.Buffer, uint64(spec.BufferOffset), uint64(spec.Length))
		if err != nil {
			return nil, "", fmt.Errorf("iovecs[%d]: %w", i, err)
		}
		if len(data) == 0 {
			return nil, "", fmt.Errorf("iovecs[%d] is empty", i)
		}
		buffers[i] = data
		combined = append(combined, data...)
	}
	return buffers, checksum64(combined), nil
}

func (e *scriptEnv) dataForFD(ref ScriptFDRefArgs, spec scriptDataArg) (int, string, []byte, error) {
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	fd, handle, _, err := e.app.resolveFDLocked(ref.Handle, ref.FD)
	if err != nil {
		return 0, "", nil, err
	}
	data, err := e.app.inputBytesLocked(spec.DataBase64, spec.DataHex, spec.DataUTF8, spec.Buffer, uint64(spec.BufferOffset), uint64(spec.Length))
	if err != nil {
		return 0, "", nil, err
	}
	return fd, handle, data, nil
}

func addReadvData(fields map[string]any, buffers [][]byte, n int, encoding string) error {
	combined := make([]byte, 0, n)
	segments := make([]map[string]any, 0, len(buffers))
	remaining := n
	for i, buffer := range buffers {
		read := 0
		if remaining > 0 {
			read = len(buffer)
			if read > remaining {
				read = remaining
			}
			remaining -= read
		}
		segment := map[string]any{"index": i, "length": len(buffer), "bytes_read": read}
		if read > 0 {
			encoded, err := encodeBytes(buffer[:read], encoding)
			if err != nil {
				return err
			}
			for key, value := range encoded {
				segment[key] = value
			}
			combined = append(combined, buffer[:read]...)
		}
		segments = append(segments, segment)
	}
	fields["iovecs"] = segments
	encoded, err := encodeBytes(combined, encoding)
	if err != nil {
		return err
	}
	for key, value := range encoded {
		fields[key] = value
	}
	return nil
}

func processRemoteIovecs(specs []scriptRemoteIovecArg, address Uint64, length Uint64) ([]unix.RemoteIovec, int, error) {
	if len(specs) == 0 {
		if address == 0 || length == 0 {
			return nil, 0, fmt.Errorf("remote_iovs or address and length are required")
		}
		specs = []scriptRemoteIovecArg{{Address: address, Length: length}}
	}
	remote := make([]unix.RemoteIovec, len(specs))
	total := 0
	for i, spec := range specs {
		length, err := checkedInt(fmt.Sprintf("remote_iovs[%d].length", i), spec.Length)
		if err != nil {
			return nil, 0, err
		}
		if length <= 0 {
			return nil, 0, fmt.Errorf("remote_iovs[%d].length must be greater than zero", i)
		}
		remote[i] = unix.RemoteIovec{Base: uintptr(spec.Address), Len: length}
		total += length
	}
	return remote, total, nil
}

func unixIovecsForBuffers(buffers [][]byte) ([]unix.Iovec, error) {
	iovecs := make([]unix.Iovec, len(buffers))
	for i, buffer := range buffers {
		if len(buffer) == 0 {
			return nil, fmt.Errorf("iovecs[%d] is empty", i)
		}
		iovecs[i].Base = &buffer[0]
		iovecs[i].SetLen(len(buffer))
	}
	return iovecs, nil
}

func totalBufferLength(buffers [][]byte) int {
	total := 0
	for _, buffer := range buffers {
		total += len(buffer)
	}
	return total
}

func checkedInt(name string, value Uint64) (int, error) {
	maxInt := uint64(int(^uint(0) >> 1))
	if uint64(value) > maxInt {
		return 0, fmt.Errorf("%s %d exceeds int", name, value)
	}
	return int(value), nil
}

func optionalInt64(value *Uint64, name string) (*int64, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := checkedInt64(name, *value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func timespecFromArg(arg scriptTimespecArg) unix.Timespec {
	if arg.DurationMS != 0 {
		return unix.NsecToTimespec(int64(time.Duration(uint64(arg.DurationMS)) * time.Millisecond))
	}
	return unix.NsecToTimespec(arg.Sec*1_000_000_000 + arg.Nsec)
}

func timespecInfo(ts unix.Timespec) map[string]any {
	return map[string]any{"sec": ts.Sec, "nsec": ts.Nsec, "nsec_total": ts.Nano()}
}

func timevalInfo(tv unix.Timeval) map[string]any {
	return map[string]any{"sec": tv.Sec, "usec": tv.Usec, "nsec_total": unix.TimevalToNsec(tv)}
}

func itimerSpecInfo(spec unix.ItimerSpec) map[string]any {
	return map[string]any{"value": timespecInfo(spec.Value), "interval": timespecInfo(spec.Interval)}
}

func (e *scriptEnv) rightsControlMessage(handles []string, rawFDs []int) ([]byte, error) {
	if len(handles) == 0 && len(rawFDs) == 0 {
		return nil, nil
	}
	fds := make([]int, 0, len(handles)+len(rawFDs))
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	for _, handle := range handles {
		fd, _, _, err := e.app.resolveFDLocked(handle, nil)
		if err != nil {
			return nil, err
		}
		fds = append(fds, fd)
	}
	for i := range rawFDs {
		fd := rawFDs[i]
		resolved, _, _, err := e.app.resolveFDLocked("", &fd)
		if err != nil {
			return nil, err
		}
		fds = append(fds, resolved)
	}
	return unix.UnixRights(fds...), nil
}

func (e *scriptEnv) registerRights(oob []byte) ([]map[string]any, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	rights := []map[string]any{}
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			e.app.mu.Lock()
			entry, regErr := e.app.registerFDLocked(fd, "received_fd", "", "", nil)
			e.app.mu.Unlock()
			if regErr != nil {
				_ = unix.Close(fd)
				return rights, regErr
			}
			rights = append(rights, map[string]any{"handle": entry.Handle, "fd": entry.FD})
		}
	}
	return rights, nil
}

func rawSyscallFields(args scriptRawSyscallArgs, r1 uintptr, r2 uintptr) map[string]any {
	return map[string]any{"trap": uint64(args.Trap), "a1": hex64(uint64(args.A1)), "a2": hex64(uint64(args.A2)), "a3": hex64(uint64(args.A3)), "a4": hex64(uint64(args.A4)), "a5": hex64(uint64(args.A5)), "a6": hex64(uint64(args.A6)), "r1": hexPtr(r1), "r2": hexPtr(r2)}
}
