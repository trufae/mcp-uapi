package mcpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/dop251/goja"
	"golang.org/x/sys/unix"
)

type scriptMethod func(goja.Value) (any, error)

func (e *scriptEnv) addScriptUnixExtensions(obj *goja.Object) {
	methods := map[string]scriptMethod{
		"constant":         e.scriptConstant,
		"syscall":          e.scriptSyscall,
		"syscall6":         e.scriptSyscall6,
		"rawSyscall":       e.scriptRawSyscall,
		"rawSyscall6":      e.scriptRawSyscall6,
		"auxv":             e.scriptAuxv,
		"getpagesize":      e.scriptGetpagesize,
		"sysinfo":          e.scriptSysinfo,
		"major":            e.scriptMajor,
		"minor":            e.scriptMinor,
		"mkdev":            e.scriptMkdev,
		"umask":            e.scriptUmask,
		"access":           e.scriptAccess,
		"faccessat":        e.scriptFaccessat,
		"faccessat2":       e.scriptFaccessat2,
		"chmod":            e.scriptChmod,
		"fchmod":           e.scriptFchmod,
		"fchmodat":         e.scriptFchmodat,
		"chown":            e.scriptChown,
		"fchown":           e.scriptFchown,
		"fchownat":         e.scriptFchownat,
		"lchown":           e.scriptLchown,
		"mkdir":            e.scriptMkdir,
		"mkdirat":          e.scriptMkdirat,
		"mkfifo":           e.scriptMkfifo,
		"mkfifoat":         e.scriptMkfifoat,
		"mknod":            e.scriptMknod,
		"mknodat":          e.scriptMknodat,
		"link":             e.scriptLink,
		"linkat":           e.scriptLinkat,
		"symlink":          e.scriptSymlink,
		"symlinkat":        e.scriptSymlinkat,
		"unlink":           e.scriptUnlink,
		"unlinkat":         e.scriptUnlinkat,
		"rmdir":            e.scriptRmdir,
		"rename":           e.scriptRename,
		"renameat":         e.scriptRenameat,
		"renameat2":        e.scriptRenameat2,
		"creat":            e.scriptCreat,
		"openat":           e.scriptOpenat,
		"openat2":          e.scriptOpenat2,
		"fstatat":          e.scriptFstatat,
		"statfs":           e.scriptStatfs,
		"fstatfs":          e.scriptFstatfs,
		"statx":            e.scriptStatx,
		"readlinkat":       e.scriptReadlinkat,
		"readv":            e.scriptReadv,
		"writev":           e.scriptWritev,
		"preadv":           e.scriptPreadv,
		"pwritev":          e.scriptPwritev,
		"preadv2":          e.scriptPreadv2,
		"pwritev2":         e.scriptPwritev2,
		"truncate":         e.scriptTruncate,
		"ftruncate":        e.scriptFtruncate,
		"fallocate":        e.scriptFallocate,
		"fadvise":          e.scriptFadvise,
		"syncFileRange":    e.scriptSyncFileRange,
		"flock":            e.scriptFlock,
		"fsync":            e.scriptFsync,
		"fdatasync":        e.scriptFdatasync,
		"sync":             e.scriptSync,
		"syncfs":           e.scriptSyncfs,
		"getdents":         e.scriptGetdents,
		"readDirent":       e.scriptReadDirent,
		"dup":              e.scriptDup,
		"dup2":             e.scriptDup2,
		"dup3":             e.scriptDup3,
		"pipe":             e.scriptPipe,
		"pipe2":            e.scriptPipe2,
		"closeRange":       e.scriptCloseRange,
		"setNonblock":      e.scriptSetNonblock,
		"fcntlInt":         e.scriptFcntlInt,
		"getcwd":           e.scriptGetcwd,
		"chdir":            e.scriptChdir,
		"fchdir":           e.scriptFchdir,
		"getids":           e.scriptGetids,
		"getpgid":          e.scriptGetpgid,
		"getpgrp":          e.scriptGetpgrp,
		"getsid":           e.scriptGetsid,
		"getpriority":      e.scriptGetpriority,
		"setpriority":      e.scriptSetpriority,
		"setpgid":          e.scriptSetpgid,
		"setsid":           e.scriptSetsid,
		"tgkill":           e.scriptTgkill,
		"getgroups":        e.scriptGetgroups,
		"getresuid":        e.scriptGetresuid,
		"getresgid":        e.scriptGetresgid,
		"getrlimit":        e.scriptGetrlimit,
		"setrlimit":        e.scriptSetrlimit,
		"prlimit":          e.scriptPrlimit,
		"getrusage":        e.scriptGetrusage,
		"clockGettime":     e.scriptClockGettime,
		"clockGetres":      e.scriptClockGetres,
		"gettimeofday":     e.scriptGettimeofday,
		"nanosleep":        e.scriptNanosleep,
		"eventfd":          e.scriptEventfd,
		"timerfdCreate":    e.scriptTimerfdCreate,
		"timerfdGettime":   e.scriptTimerfdGettime,
		"timerfdSettime":   e.scriptTimerfdSettime,
		"memfdCreate":      e.scriptMemfdCreate,
		"inotifyInit":      e.scriptInotifyInit,
		"inotifyInit1":     e.scriptInotifyInit1,
		"inotifyAddWatch":  e.scriptInotifyAddWatch,
		"inotifyRmWatch":   e.scriptInotifyRmWatch,
		"send":             e.scriptSend,
		"sendmsg":          e.scriptSendmsg,
		"recvmsg":          e.scriptRecvmsg,
		"sendfile":         e.scriptSendfile,
		"copyFileRange":    e.scriptCopyFileRange,
		"splice":           e.scriptSplice,
		"tee":              e.scriptTee,
		"vmsplice":         e.scriptVmsplice,
		"processVMReadv":   e.scriptProcessVMReadv,
		"processVMWritev":  e.scriptProcessVMWritev,
		"getrandom":        e.scriptGetrandom,
		"bindToDevice":     e.scriptBindToDevice,
		"setsockoptString": e.scriptSetsockoptString,
		"getsockoptString": e.scriptGetsockoptString,
		"setsockoptByte":   e.scriptSetsockoptByte,
		"getsockoptByte":   e.scriptGetsockoptByte,
		"setsockoptUint64": e.scriptSetsockoptUint64,
		"getsockoptUint64": e.scriptGetsockoptUint64,
		"pidfdOpen":        e.scriptPidfdOpen,
		"pidfdGetfd":       e.scriptPidfdGetfd,
		"pidfdSendSignal":  e.scriptPidfdSendSignal,
		"getxattr":         e.scriptGetxattr,
		"lgetxattr":        e.scriptLgetxattr,
		"fgetxattr":        e.scriptFgetxattr,
		"listxattr":        e.scriptListxattr,
		"llistxattr":       e.scriptLlistxattr,
		"flistxattr":       e.scriptFlistxattr,
		"setxattr":         e.scriptSetxattr,
		"lsetxattr":        e.scriptLsetxattr,
		"fsetxattr":        e.scriptFsetxattr,
		"removexattr":      e.scriptRemovexattr,
		"lremovexattr":     e.scriptLremovexattr,
		"fremovexattr":     e.scriptFremovexattr,
	}
	for name, method := range methods {
		e.setScriptMethod(obj, name, method)
	}
}

func scriptUnixExtensionNames() []string {
	return []string{
		"constant", "syscall", "syscall6", "rawSyscall", "rawSyscall6", "auxv", "getpagesize", "sysinfo", "major", "minor", "mkdev", "umask",
		"access", "faccessat", "faccessat2", "chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown",
		"mkdir", "mkdirat", "mkfifo", "mkfifoat", "mknod", "mknodat", "link", "linkat", "symlink", "symlinkat", "unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2",
		"creat", "openat", "openat2", "fstatat", "statfs", "fstatfs", "statx", "readlinkat", "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2", "truncate", "ftruncate", "fallocate", "fadvise", "syncFileRange", "flock", "fsync", "fdatasync", "sync", "syncfs", "getdents", "readDirent",
		"dup", "dup2", "dup3", "pipe", "pipe2", "closeRange", "setNonblock", "fcntlInt", "getcwd", "chdir", "fchdir",
		"getids", "getpgid", "getpgrp", "getsid", "getpriority", "setpriority", "setpgid", "setsid", "tgkill", "getgroups", "getresuid", "getresgid", "getrlimit", "setrlimit", "prlimit", "getrusage", "clockGettime", "clockGetres", "gettimeofday", "nanosleep",
		"eventfd", "timerfdCreate", "timerfdGettime", "timerfdSettime", "memfdCreate", "inotifyInit", "inotifyInit1", "inotifyAddWatch", "inotifyRmWatch", "send", "sendmsg", "recvmsg", "sendfile", "copyFileRange", "splice", "tee", "vmsplice", "processVMReadv", "processVMWritev", "getrandom", "bindToDevice", "setsockoptString", "getsockoptString", "setsockoptByte", "getsockoptByte", "setsockoptUint64", "getsockoptUint64", "pidfdOpen", "pidfdGetfd", "pidfdSendSignal",
		"getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
	}
}

func (e *scriptEnv) setScriptMethod(obj *goja.Object, name string, method scriptMethod) {
	_ = obj.Set(name, func(call goja.FunctionCall) goja.Value {
		e.ops++
		value, err := method(call.Argument(0))
		if err != nil {
			panic(e.vm.NewGoError(err))
		}
		return e.vm.ToValue(value)
	})
}

func decodeScriptArgs(value goja.Value, target any) error {
	data, err := json.Marshal(exportArgument(value))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func scriptSyscallResult(fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err == nil {
		fields["ok"] = true
		return fields, nil
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		fields["ok"] = false
		fields["errno"] = int(errno)
		fields["errno_name"] = errnoName(errno)
		fields["error"] = errno.Error()
		return fields, nil
	}
	return nil, err
}

func defaultedConstInt(value *ConstUint64, fallback int) int {
	if value == nil {
		return fallback
	}
	return int(uint64(*value))
}

func checkedInt64(name string, value Uint64) (int64, error) {
	if uint64(value) > math.MaxInt64 {
		return 0, fmt.Errorf("%s %d exceeds int64", name, value)
	}
	return int64(value), nil
}

type ScriptFDRefArgs struct {
	Handle string `json:"handle"`
	FD     *int   `json:"fd"`
}

func (e *scriptEnv) resolveScriptFD(ref ScriptFDRefArgs) (int, string, error) {
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	fd, handle, _, err := e.app.resolveFDLocked(ref.Handle, ref.FD)
	return fd, handle, err
}

func (e *scriptEnv) registerScriptFD(fd int, kind, path, handle string, meta map[string]any, fields map[string]any, err error) (map[string]any, error) {
	if err != nil {
		return scriptSyscallResult(fields, err)
	}
	e.app.mu.Lock()
	entry, regErr := e.app.registerFDLocked(fd, kind, path, handle, meta)
	e.app.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(fd)
		return nil, regErr
	}
	fields["handle"] = entry.Handle
	fields["fd"] = entry.FD
	return scriptSyscallResult(fields, nil)
}

func (e *scriptEnv) registerDupedFD(fd int, kind, requestedHandle string, meta map[string]any, fields map[string]any, err error) (map[string]any, error) {
	if err != nil {
		return scriptSyscallResult(fields, err)
	}
	e.app.mu.Lock()
	for handle, entry := range e.app.fds {
		if entry.FD == fd {
			delete(e.app.fds, handle)
		}
	}
	entry, regErr := e.app.registerFDLocked(fd, kind, "", requestedHandle, meta)
	e.app.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(fd)
		return nil, regErr
	}
	fields["handle"] = entry.Handle
	fields["fd"] = entry.FD
	return scriptSyscallResult(fields, nil)
}

func (e *scriptEnv) removeClosedFDs(first, last uint, flags uint) {
	if flags&unix.CLOSE_RANGE_CLOEXEC != 0 {
		return
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	for handle, entry := range e.app.fds {
		fd := uint(entry.FD)
		if fd >= first && fd <= last {
			delete(e.app.fds, handle)
		}
	}
}

type scriptPathModeArgs struct {
	Path string      `json:"path"`
	Mode ConstUint32 `json:"mode"`
}

type scriptAtPathModeArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	Mode  ConstUint32  `json:"mode"`
	Flags ConstUint64  `json:"flags"`
}

type scriptPathOwnerArgs struct {
	Path string `json:"path"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

type scriptAtPathOwnerArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	UID   int          `json:"uid"`
	GID   int          `json:"gid"`
	Flags ConstUint64  `json:"flags"`
}

type scriptTwoPathArgs struct {
	OldPath string `json:"oldpath"`
	NewPath string `json:"newpath"`
}

type scriptLinkatArgs struct {
	OldDirFD *ConstUint64 `json:"olddirfd"`
	OldPath  string       `json:"oldpath"`
	NewDirFD *ConstUint64 `json:"newdirfd"`
	NewPath  string       `json:"newpath"`
	Flags    ConstUint64  `json:"flags"`
}

type scriptSymlinkatArgs struct {
	OldPath  string       `json:"oldpath"`
	NewDirFD *ConstUint64 `json:"newdirfd"`
	NewPath  string       `json:"newpath"`
}

type scriptUnlinkatArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	Flags ConstUint64  `json:"flags"`
}

type scriptRenameatArgs struct {
	OldDirFD *ConstUint64 `json:"olddirfd"`
	OldPath  string       `json:"oldpath"`
	NewDirFD *ConstUint64 `json:"newdirfd"`
	NewPath  string       `json:"newpath"`
	Flags    ConstUint64  `json:"flags"`
}

type scriptOpenatArgs struct {
	DirFD  *ConstUint64 `json:"dirfd"`
	Path   string       `json:"path"`
	Flags  ConstUint64  `json:"flags"`
	Mode   Uint32       `json:"mode"`
	Handle string       `json:"handle"`
}

type scriptFstatatArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	Flags ConstUint64  `json:"flags"`
}

type scriptReadlinkatArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	Size  Uint64       `json:"size"`
}

type scriptStatxArgs struct {
	DirFD *ConstUint64 `json:"dirfd"`
	Path  string       `json:"path"`
	Flags ConstUint64  `json:"flags"`
	Mask  ConstUint64  `json:"mask"`
}

type scriptLengthArgs struct {
	ScriptFDRefArgs
	Path   string `json:"path"`
	Length Uint64 `json:"length"`
}

type scriptDupArgs struct {
	ScriptFDRefArgs
	NewFD     int         `json:"newfd"`
	Flags     ConstUint64 `json:"flags"`
	NewHandle string      `json:"new_handle"`
}

type scriptPipeArgs struct {
	Flags   ConstUint64 `json:"flags"`
	Handles []string    `json:"handles"`
}

type scriptCloseRangeArgs struct {
	First Uint64      `json:"first"`
	Last  Uint64      `json:"last"`
	Flags ConstUint64 `json:"flags"`
}

type scriptSetNonblockArgs struct {
	ScriptFDRefArgs
	Nonblocking bool `json:"nonblocking"`
}

type scriptFcntlIntArgs struct {
	ScriptFDRefArgs
	Cmd ConstUint64 `json:"cmd"`
	Arg ConstUint64 `json:"arg"`
}

type scriptRlimitArgs struct {
	Resource ConstUint64 `json:"resource"`
	Cur      *Uint64     `json:"cur"`
	Max      *Uint64     `json:"max"`
}

type scriptRusageArgs struct {
	Who ConstUint64 `json:"who"`
}

type scriptFDCreateArgs struct {
	Name   string      `json:"name"`
	Init   Uint64      `json:"init"`
	Flags  ConstUint64 `json:"flags"`
	Handle string      `json:"handle"`
}

type scriptInotifyWatchArgs struct {
	ScriptFDRefArgs
	Path string      `json:"path"`
	Mask ConstUint32 `json:"mask"`
	WD   Uint32      `json:"wd"`
}

type scriptSendfileArgs struct {
	OutHandle string  `json:"out_handle"`
	OutFD     *int    `json:"out_fd"`
	InHandle  string  `json:"in_handle"`
	InFD      *int    `json:"in_fd"`
	Offset    *Uint64 `json:"offset"`
	Count     Uint64  `json:"count"`
}

type scriptCopyFileRangeArgs struct {
	ReadHandle  string      `json:"read_handle"`
	ReadFD      *int        `json:"read_fd"`
	WriteHandle string      `json:"write_handle"`
	WriteFD     *int        `json:"write_fd"`
	ReadOffset  *Uint64     `json:"read_offset"`
	WriteOffset *Uint64     `json:"write_offset"`
	Length      Uint64      `json:"length"`
	Flags       ConstUint64 `json:"flags"`
}

type scriptXattrReadArgs struct {
	ScriptFDRefArgs
	Path     string `json:"path"`
	Name     string `json:"name"`
	Size     Uint64 `json:"size"`
	Encoding string `json:"encoding"`
}

type scriptXattrWriteArgs struct {
	ScriptFDRefArgs
	Path       string      `json:"path"`
	Name       string      `json:"name"`
	DataBase64 string      `json:"data_base64"`
	DataHex    string      `json:"data_hex"`
	DataUTF8   string      `json:"data_utf8"`
	Flags      ConstUint64 `json:"flags"`
}

func (e *scriptEnv) scriptConstant(value goja.Value) (any, error) {
	name := value.String()
	constant, ok := lookupConstant(name)
	if !ok {
		return nil, fmt.Errorf("unknown constant %q", name)
	}
	return map[string]any{"ok": true, "name": normalizeConstantName(name), "value": constant, "hex": hex64(constant)}, nil
}

func (e *scriptEnv) scriptAccess(value goja.Value) (any, error) {
	var args struct {
		Path string      `json:"path"`
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Access(args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptFaccessat(value goja.Value) (any, error) {
	var args scriptAtPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Faccessat(dirfd, args.Path, uint32(args.Mode), int(args.Flags))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode), "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptChmod(value goja.Value) (any, error) {
	var args scriptPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Chmod(args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptFchmod(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.Fchmod(fd, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptFchmodat(value goja.Value) (any, error) {
	var args scriptAtPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Fchmodat(dirfd, args.Path, uint32(args.Mode), int(args.Flags))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode), "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptChown(value goja.Value) (any, error) {
	var args scriptPathOwnerArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Chown(args.Path, args.UID, args.GID)
	return scriptSyscallResult(map[string]any{"path": args.Path, "uid": args.UID, "gid": args.GID}, err)
}

func (e *scriptEnv) scriptFchown(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		UID int `json:"uid"`
		GID int `json:"gid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.Fchown(fd, args.UID, args.GID)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "uid": args.UID, "gid": args.GID}, err)
}

func (e *scriptEnv) scriptFchownat(value goja.Value) (any, error) {
	var args scriptAtPathOwnerArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Fchownat(dirfd, args.Path, args.UID, args.GID, int(args.Flags))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "uid": args.UID, "gid": args.GID, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptLchown(value goja.Value) (any, error) {
	var args scriptPathOwnerArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Lchown(args.Path, args.UID, args.GID)
	return scriptSyscallResult(map[string]any{"path": args.Path, "uid": args.UID, "gid": args.GID}, err)
}

func (e *scriptEnv) scriptMkdir(value goja.Value) (any, error) {
	var args scriptPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Mkdir(args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptMkdirat(value goja.Value) (any, error) {
	var args scriptAtPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Mkdirat(dirfd, args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptMkfifo(value goja.Value) (any, error) {
	var args scriptPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Mkfifo(args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptMkfifoat(value goja.Value) (any, error) {
	var args scriptAtPathModeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Mkfifoat(dirfd, args.Path, uint32(args.Mode))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode)}, err)
}

func (e *scriptEnv) scriptMknod(value goja.Value) (any, error) {
	var args struct {
		Path string      `json:"path"`
		Mode ConstUint32 `json:"mode"`
		Dev  int         `json:"dev"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Mknod(args.Path, uint32(args.Mode), args.Dev)
	return scriptSyscallResult(map[string]any{"path": args.Path, "mode": uint32(args.Mode), "dev": args.Dev}, err)
}

func (e *scriptEnv) scriptMknodat(value goja.Value) (any, error) {
	var args struct {
		DirFD *ConstUint64 `json:"dirfd"`
		Path  string       `json:"path"`
		Mode  ConstUint32  `json:"mode"`
		Dev   int          `json:"dev"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Mknodat(dirfd, args.Path, uint32(args.Mode), args.Dev)
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "mode": uint32(args.Mode), "dev": args.Dev}, err)
}

func (e *scriptEnv) scriptLink(value goja.Value) (any, error) {
	var args scriptTwoPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Link(args.OldPath, args.NewPath)
	return scriptSyscallResult(map[string]any{"oldpath": args.OldPath, "newpath": args.NewPath}, err)
}

func (e *scriptEnv) scriptLinkat(value goja.Value) (any, error) {
	var args scriptLinkatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	olddirfd := defaultedConstInt(args.OldDirFD, unix.AT_FDCWD)
	newdirfd := defaultedConstInt(args.NewDirFD, unix.AT_FDCWD)
	err := unix.Linkat(olddirfd, args.OldPath, newdirfd, args.NewPath, int(args.Flags))
	return scriptSyscallResult(map[string]any{"olddirfd": olddirfd, "oldpath": args.OldPath, "newdirfd": newdirfd, "newpath": args.NewPath, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptSymlink(value goja.Value) (any, error) {
	var args scriptTwoPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Symlink(args.OldPath, args.NewPath)
	return scriptSyscallResult(map[string]any{"oldpath": args.OldPath, "newpath": args.NewPath}, err)
}

func (e *scriptEnv) scriptSymlinkat(value goja.Value) (any, error) {
	var args scriptSymlinkatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	newdirfd := defaultedConstInt(args.NewDirFD, unix.AT_FDCWD)
	err := unix.Symlinkat(args.OldPath, newdirfd, args.NewPath)
	return scriptSyscallResult(map[string]any{"oldpath": args.OldPath, "newdirfd": newdirfd, "newpath": args.NewPath}, err)
}

func (e *scriptEnv) scriptUnlink(value goja.Value) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Unlink(args.Path)
	return scriptSyscallResult(map[string]any{"path": args.Path}, err)
}

func (e *scriptEnv) scriptUnlinkat(value goja.Value) (any, error) {
	var args scriptUnlinkatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	err := unix.Unlinkat(dirfd, args.Path, int(args.Flags))
	return scriptSyscallResult(map[string]any{"dirfd": dirfd, "path": args.Path, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptRmdir(value goja.Value) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Rmdir(args.Path)
	return scriptSyscallResult(map[string]any{"path": args.Path}, err)
}

func (e *scriptEnv) scriptRename(value goja.Value) (any, error) {
	var args scriptTwoPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Rename(args.OldPath, args.NewPath)
	return scriptSyscallResult(map[string]any{"oldpath": args.OldPath, "newpath": args.NewPath}, err)
}

func (e *scriptEnv) scriptRenameat(value goja.Value) (any, error) {
	var args scriptRenameatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	olddirfd := defaultedConstInt(args.OldDirFD, unix.AT_FDCWD)
	newdirfd := defaultedConstInt(args.NewDirFD, unix.AT_FDCWD)
	err := unix.Renameat(olddirfd, args.OldPath, newdirfd, args.NewPath)
	return scriptSyscallResult(map[string]any{"olddirfd": olddirfd, "oldpath": args.OldPath, "newdirfd": newdirfd, "newpath": args.NewPath}, err)
}

func (e *scriptEnv) scriptRenameat2(value goja.Value) (any, error) {
	var args scriptRenameatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	olddirfd := defaultedConstInt(args.OldDirFD, unix.AT_FDCWD)
	newdirfd := defaultedConstInt(args.NewDirFD, unix.AT_FDCWD)
	err := unix.Renameat2(olddirfd, args.OldPath, newdirfd, args.NewPath, uint(args.Flags))
	return scriptSyscallResult(map[string]any{"olddirfd": olddirfd, "oldpath": args.OldPath, "newdirfd": newdirfd, "newpath": args.NewPath, "flags": uint(args.Flags)}, err)
}

func (e *scriptEnv) scriptOpenat(value goja.Value) (any, error) {
	var args scriptOpenatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	flags := int(args.Flags)
	if flags == 0 {
		flags = unix.O_RDONLY | unix.O_CLOEXEC
	}
	mode := uint32(args.Mode)
	if mode == 0 {
		mode = 0o600
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	fd, err := unix.Openat(dirfd, args.Path, flags, mode)
	return e.registerScriptFD(fd, "file", args.Path, args.Handle, map[string]any{"dirfd": dirfd, "flags": flags}, map[string]any{"dirfd": dirfd, "path": args.Path, "flags": flags, "mode": mode}, err)
}

func (e *scriptEnv) scriptFstatat(value goja.Value) (any, error) {
	var args scriptFstatatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, args.Path, &st, int(args.Flags))
	fields := map[string]any{"dirfd": dirfd, "path": args.Path, "flags": int(args.Flags)}
	if err == nil {
		fields["stat"] = statInfo(st)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptStatfs(value goja.Value) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var st unix.Statfs_t
	err := unix.Statfs(args.Path, &st)
	fields := map[string]any{"path": args.Path}
	if err == nil {
		fields["statfs"] = statfsInfo(st)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptFstatfs(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	var st unix.Statfs_t
	err = unix.Fstatfs(fd, &st)
	fields := map[string]any{"handle": handle, "fd": fd}
	if err == nil {
		fields["statfs"] = statfsInfo(st)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptStatx(value goja.Value) (any, error) {
	var args scriptStatxArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	mask := int(args.Mask)
	if mask == 0 {
		mask = unix.STATX_BASIC_STATS
	}
	var st unix.Statx_t
	err := unix.Statx(dirfd, args.Path, int(args.Flags), mask, &st)
	fields := map[string]any{"dirfd": dirfd, "path": args.Path, "flags": int(args.Flags), "mask": mask}
	if err == nil {
		fields["statx"] = statxInfo(st)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptReadlinkat(value goja.Value) (any, error) {
	var args scriptReadlinkatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	size := uint64(args.Size)
	if size == 0 {
		size = 4096
	}
	if size > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("size %d exceeds max_read_bytes %d", size, e.app.config.MaxReadBytes)
	}
	dirfd := defaultedConstInt(args.DirFD, unix.AT_FDCWD)
	buf := make([]byte, int(size))
	n, err := unix.Readlinkat(dirfd, args.Path, buf)
	fields := map[string]any{"dirfd": dirfd, "path": args.Path, "bytes_read": n}
	if err == nil {
		fields["target"] = string(buf[:n])
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptTruncate(value goja.Value) (any, error) {
	var args scriptLengthArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	length, err := checkedInt64("length", args.Length)
	if err != nil {
		return nil, err
	}
	err = unix.Truncate(args.Path, length)
	return scriptSyscallResult(map[string]any{"path": args.Path, "length": length}, err)
}

func (e *scriptEnv) scriptFtruncate(value goja.Value) (any, error) {
	var args scriptLengthArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	length, err := checkedInt64("length", args.Length)
	if err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.Ftruncate(fd, length)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "length": length}, err)
}

func (e *scriptEnv) scriptFsync(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	err = unix.Fsync(fd)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd}, err)
}

func (e *scriptEnv) scriptFdatasync(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	err = unix.Fdatasync(fd)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd}, err)
}

func (e *scriptEnv) scriptSync(value goja.Value) (any, error) {
	unix.Sync()
	return map[string]any{"ok": true}, nil
}

func (e *scriptEnv) scriptSyncfs(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	err = unix.Syncfs(fd)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd}, err)
}

func (e *scriptEnv) scriptDup(value goja.Value) (any, error) {
	var args scriptDupArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	newFD, dupErr := unix.Dup(fd)
	return e.registerScriptFD(newFD, "dup", "", args.NewHandle, map[string]any{"source": handle}, map[string]any{"source_handle": handle, "source_fd": fd}, dupErr)
}

func (e *scriptEnv) scriptDup2(value goja.Value) (any, error) {
	var args scriptDupArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	dupErr := unix.Dup2(fd, args.NewFD)
	return e.registerDupedFD(args.NewFD, "dup", args.NewHandle, map[string]any{"source": handle}, map[string]any{"source_handle": handle, "source_fd": fd, "newfd": args.NewFD}, dupErr)
}

func (e *scriptEnv) scriptDup3(value goja.Value) (any, error) {
	var args scriptDupArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	dupErr := unix.Dup3(fd, args.NewFD, int(args.Flags))
	return e.registerDupedFD(args.NewFD, "dup", args.NewHandle, map[string]any{"source": handle, "flags": int(args.Flags)}, map[string]any{"source_handle": handle, "source_fd": fd, "newfd": args.NewFD, "flags": int(args.Flags)}, dupErr)
}

func (e *scriptEnv) scriptPipe(value goja.Value) (any, error) {
	var args scriptPipeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return e.createPipe(args, false)
}

func (e *scriptEnv) scriptPipe2(value goja.Value) (any, error) {
	var args scriptPipeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return e.createPipe(args, true)
}

func (e *scriptEnv) createPipe(args scriptPipeArgs, pipe2 bool) (any, error) {
	if len(args.Handles) != 0 && len(args.Handles) != 2 {
		return nil, fmt.Errorf("handles must contain exactly two names when provided")
	}
	fds := []int{0, 0}
	var err error
	if pipe2 {
		err = unix.Pipe2(fds, int(args.Flags))
	} else {
		err = unix.Pipe(fds)
	}
	fields := map[string]any{"flags": int(args.Flags)}
	if err != nil {
		return scriptSyscallResult(fields, err)
	}
	h0, h1 := "", ""
	if len(args.Handles) == 2 {
		h0, h1 = args.Handles[0], args.Handles[1]
	}
	e.app.mu.Lock()
	entry0, err0 := e.app.registerFDLocked(fds[0], "pipe_read", "", h0, map[string]any{"peer_index": 1})
	entry1, err1 := e.app.registerFDLocked(fds[1], "pipe_write", "", h1, map[string]any{"peer_index": 0})
	e.app.mu.Unlock()
	if err0 != nil || err1 != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		if err0 != nil {
			return nil, err0
		}
		return nil, err1
	}
	fields["handles"] = []string{entry0.Handle, entry1.Handle}
	fields["fds"] = []int{fds[0], fds[1]}
	return scriptSyscallResult(fields, nil)
}

func (e *scriptEnv) scriptCloseRange(value goja.Value) (any, error) {
	var args scriptCloseRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	maxUint := uint64(^uint(0))
	if uint64(args.First) > maxUint || uint64(args.Last) > maxUint {
		return nil, fmt.Errorf("first/last exceed uint")
	}
	first, last, flags := uint(args.First), uint(args.Last), uint(args.Flags)
	err := unix.CloseRange(first, last, flags)
	if err == nil {
		e.removeClosedFDs(first, last, flags)
	}
	return scriptSyscallResult(map[string]any{"first": first, "last": last, "flags": flags}, err)
}

func (e *scriptEnv) scriptSetNonblock(value goja.Value) (any, error) {
	var args scriptSetNonblockArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.SetNonblock(fd, args.Nonblocking)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "nonblocking": args.Nonblocking}, err)
}

func (e *scriptEnv) scriptFcntlInt(value goja.Value) (any, error) {
	var args scriptFcntlIntArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	r, err := unix.FcntlInt(uintptr(fd), int(args.Cmd), int(args.Arg))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "cmd": int(args.Cmd), "arg": int(args.Arg), "return": r}, err)
}

func (e *scriptEnv) scriptGetcwd(value goja.Value) (any, error) {
	wd, err := unix.Getwd()
	return scriptSyscallResult(map[string]any{"path": wd}, err)
}

func (e *scriptEnv) scriptChdir(value goja.Value) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := unix.Chdir(args.Path)
	return scriptSyscallResult(map[string]any{"path": args.Path}, err)
}

func (e *scriptEnv) scriptFchdir(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	err = unix.Fchdir(fd)
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd}, err)
}

func (e *scriptEnv) scriptGetids(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "pid": unix.Getpid(), "ppid": unix.Getppid(), "tid": unix.Gettid(), "uid": unix.Getuid(), "euid": unix.Geteuid(), "gid": unix.Getgid(), "egid": unix.Getegid()}, nil
}

func (e *scriptEnv) scriptGetgroups(value goja.Value) (any, error) {
	groups, err := unix.Getgroups()
	return scriptSyscallResult(map[string]any{"groups": groups}, err)
}

func (e *scriptEnv) scriptGetresuid(value goja.Value) (any, error) {
	ruid, euid, suid := unix.Getresuid()
	return map[string]any{"ok": true, "ruid": ruid, "euid": euid, "suid": suid}, nil
}

func (e *scriptEnv) scriptGetresgid(value goja.Value) (any, error) {
	rgid, egid, sgid := unix.Getresgid()
	return map[string]any{"ok": true, "rgid": rgid, "egid": egid, "sgid": sgid}, nil
}

func (e *scriptEnv) scriptGetrlimit(value goja.Value) (any, error) {
	var args scriptRlimitArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var limit unix.Rlimit
	err := unix.Getrlimit(int(args.Resource), &limit)
	fields := map[string]any{"resource": int(args.Resource)}
	if err == nil {
		fields["rlimit"] = rlimitInfo(limit)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptSetrlimit(value goja.Value) (any, error) {
	var args scriptRlimitArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Cur == nil || args.Max == nil {
		return nil, fmt.Errorf("cur and max are required")
	}
	limit := unix.Rlimit{Cur: uint64(*args.Cur), Max: uint64(*args.Max)}
	err := unix.Setrlimit(int(args.Resource), &limit)
	return scriptSyscallResult(map[string]any{"resource": int(args.Resource), "rlimit": rlimitInfo(limit)}, err)
}

func (e *scriptEnv) scriptGetrusage(value goja.Value) (any, error) {
	var args scriptRusageArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var rusage unix.Rusage
	err := unix.Getrusage(int(args.Who), &rusage)
	fields := map[string]any{"who": int(args.Who)}
	if err == nil {
		fields["rusage"] = rusageInfo(rusage)
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptEventfd(value goja.Value) (any, error) {
	var args scriptFDCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.Eventfd(uint(args.Init), int(args.Flags))
	return e.registerScriptFD(fd, "eventfd", "", args.Handle, map[string]any{"init": uint(args.Init), "flags": int(args.Flags)}, map[string]any{"init": uint(args.Init), "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptMemfdCreate(value goja.Value) (any, error) {
	var args scriptFDCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.MemfdCreate(args.Name, int(args.Flags))
	return e.registerScriptFD(fd, "memfd", args.Name, args.Handle, map[string]any{"flags": int(args.Flags)}, map[string]any{"name": args.Name, "flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptInotifyInit(value goja.Value) (any, error) {
	var args scriptFDCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.InotifyInit()
	return e.registerScriptFD(fd, "inotify", "", args.Handle, nil, map[string]any{}, err)
}

func (e *scriptEnv) scriptInotifyInit1(value goja.Value) (any, error) {
	var args scriptFDCreateArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, err := unix.InotifyInit1(int(args.Flags))
	return e.registerScriptFD(fd, "inotify", "", args.Handle, map[string]any{"flags": int(args.Flags)}, map[string]any{"flags": int(args.Flags)}, err)
}

func (e *scriptEnv) scriptInotifyAddWatch(value goja.Value) (any, error) {
	var args scriptInotifyWatchArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	wd, err := unix.InotifyAddWatch(fd, args.Path, uint32(args.Mask))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "path": args.Path, "mask": uint32(args.Mask), "wd": wd}, err)
}

func (e *scriptEnv) scriptInotifyRmWatch(value goja.Value) (any, error) {
	var args scriptInotifyWatchArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	success, err := unix.InotifyRmWatch(fd, uint32(args.WD))
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "wd": uint32(args.WD), "return": success}, err)
}

func (e *scriptEnv) scriptSendfile(value goja.Value) (any, error) {
	var args scriptSendfileArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	outFD, outHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.OutHandle, FD: args.OutFD})
	if err != nil {
		return nil, fmt.Errorf("out fd: %w", err)
	}
	inFD, inHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.InHandle, FD: args.InFD})
	if err != nil {
		return nil, fmt.Errorf("in fd: %w", err)
	}
	var offset *int64
	if args.Offset != nil {
		parsed, err := checkedInt64("offset", *args.Offset)
		if err != nil {
			return nil, err
		}
		offset = &parsed
	}
	written, err := unix.Sendfile(outFD, inFD, offset, int(args.Count))
	fields := map[string]any{"out_handle": outHandle, "out_fd": outFD, "in_handle": inHandle, "in_fd": inFD, "count": uint64(args.Count), "bytes_written": written}
	if offset != nil {
		fields["offset"] = *offset
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptCopyFileRange(value goja.Value) (any, error) {
	var args scriptCopyFileRangeArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	readFD, readHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.ReadHandle, FD: args.ReadFD})
	if err != nil {
		return nil, fmt.Errorf("read fd: %w", err)
	}
	writeFD, writeHandle, err := e.resolveScriptFD(ScriptFDRefArgs{Handle: args.WriteHandle, FD: args.WriteFD})
	if err != nil {
		return nil, fmt.Errorf("write fd: %w", err)
	}
	var readOffset, writeOffset *int64
	if args.ReadOffset != nil {
		parsed, err := checkedInt64("read_offset", *args.ReadOffset)
		if err != nil {
			return nil, err
		}
		readOffset = &parsed
	}
	if args.WriteOffset != nil {
		parsed, err := checkedInt64("write_offset", *args.WriteOffset)
		if err != nil {
			return nil, err
		}
		writeOffset = &parsed
	}
	n, err := unix.CopyFileRange(readFD, readOffset, writeFD, writeOffset, int(args.Length), int(args.Flags))
	fields := map[string]any{"read_handle": readHandle, "read_fd": readFD, "write_handle": writeHandle, "write_fd": writeFD, "length": uint64(args.Length), "flags": int(args.Flags), "bytes_copied": n}
	if readOffset != nil {
		fields["read_offset"] = *readOffset
	}
	if writeOffset != nil {
		fields["write_offset"] = *writeOffset
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) scriptGetxattr(value goja.Value) (any, error) {
	return e.readPathXattr(value, unix.Getxattr, "getxattr")
}

func (e *scriptEnv) scriptLgetxattr(value goja.Value) (any, error) {
	return e.readPathXattr(value, unix.Lgetxattr, "lgetxattr")
}

func (e *scriptEnv) scriptFgetxattr(value goja.Value) (any, error) {
	var args scriptXattrReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	return e.readFDXattr(fd, handle, args, unix.Fgetxattr, "fgetxattr")
}

func (e *scriptEnv) scriptListxattr(value goja.Value) (any, error) {
	return e.listPathXattr(value, unix.Listxattr, "listxattr")
}

func (e *scriptEnv) scriptLlistxattr(value goja.Value) (any, error) {
	return e.listPathXattr(value, unix.Llistxattr, "llistxattr")
}

func (e *scriptEnv) scriptFlistxattr(value goja.Value) (any, error) {
	var args scriptXattrReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	return e.readXattrList(map[string]any{"operation": "flistxattr", "handle": handle, "fd": fd}, args.Size, args.Encoding, func(dest []byte) (int, error) {
		return unix.Flistxattr(fd, dest)
	})
}

func (e *scriptEnv) scriptSetxattr(value goja.Value) (any, error) {
	return e.writePathXattr(value, unix.Setxattr, "setxattr")
}

func (e *scriptEnv) scriptLsetxattr(value goja.Value) (any, error) {
	return e.writePathXattr(value, unix.Lsetxattr, "lsetxattr")
}

func (e *scriptEnv) scriptFsetxattr(value goja.Value) (any, error) {
	var args scriptXattrWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	data, err := decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, nil)
	if err != nil {
		return nil, err
	}
	err = unix.Fsetxattr(fd, args.Name, data, int(args.Flags))
	return scriptSyscallResult(map[string]any{"operation": "fsetxattr", "handle": handle, "fd": fd, "name": args.Name, "flags": int(args.Flags), "length": len(data), "checksum64": checksum64(data)}, err)
}

func (e *scriptEnv) scriptRemovexattr(value goja.Value) (any, error) {
	return e.removePathXattr(value, unix.Removexattr, "removexattr")
}

func (e *scriptEnv) scriptLremovexattr(value goja.Value) (any, error) {
	return e.removePathXattr(value, unix.Lremovexattr, "lremovexattr")
}

func (e *scriptEnv) scriptFremovexattr(value goja.Value) (any, error) {
	var args scriptXattrWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args.ScriptFDRefArgs)
	if err != nil {
		return nil, err
	}
	err = unix.Fremovexattr(fd, args.Name)
	return scriptSyscallResult(map[string]any{"operation": "fremovexattr", "handle": handle, "fd": fd, "name": args.Name}, err)
}

func (e *scriptEnv) readPathXattr(value goja.Value, fn func(string, string, []byte) (int, error), operation string) (any, error) {
	var args scriptXattrReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return e.readXattr(map[string]any{"operation": operation, "path": args.Path, "name": args.Name}, args.Size, args.Encoding, func(dest []byte) (int, error) {
		return fn(args.Path, args.Name, dest)
	})
}

func (e *scriptEnv) readFDXattr(fd int, handle string, args scriptXattrReadArgs, fn func(int, string, []byte) (int, error), operation string) (any, error) {
	return e.readXattr(map[string]any{"operation": operation, "handle": handle, "fd": fd, "name": args.Name}, args.Size, args.Encoding, func(dest []byte) (int, error) {
		return fn(fd, args.Name, dest)
	})
}

func (e *scriptEnv) readXattr(fields map[string]any, size Uint64, encoding string, fn func([]byte) (int, error)) (any, error) {
	length := uint64(size)
	if length == 0 {
		n, err := fn(nil)
		if err != nil {
			return scriptSyscallResult(fields, err)
		}
		length = uint64(n)
	}
	if length > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("size %d exceeds max_read_bytes %d", length, e.app.config.MaxReadBytes)
	}
	buf := make([]byte, int(length))
	n, err := fn(buf)
	fields["bytes_read"] = n
	if err == nil {
		encoded, encErr := encodeBytes(buf[:n], encoding)
		if encErr != nil {
			return nil, encErr
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptSyscallResult(fields, err)
}

func (e *scriptEnv) listPathXattr(value goja.Value, fn func(string, []byte) (int, error), operation string) (any, error) {
	var args scriptXattrReadArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return e.readXattrList(map[string]any{"operation": operation, "path": args.Path}, args.Size, args.Encoding, func(dest []byte) (int, error) {
		return fn(args.Path, dest)
	})
}

func (e *scriptEnv) readXattrList(fields map[string]any, size Uint64, encoding string, fn func([]byte) (int, error)) (any, error) {
	if encoding == "" {
		encoding = "utf8"
	}
	value, err := e.readXattr(fields, size, encoding, fn)
	if err != nil {
		return nil, err
	}
	fields, ok := value.(map[string]any)
	if !ok || fields["ok"] != true {
		return value, nil
	}
	if text, ok := fields["data_utf8"].(string); ok {
		fields["names"] = splitXattrList([]byte(text))
	} else if hexText, ok := fields["data_hex"].(string); ok && hexText == "" {
		fields["names"] = []string{}
	}
	return fields, nil
}

func (e *scriptEnv) writePathXattr(value goja.Value, fn func(string, string, []byte, int) error, operation string) (any, error) {
	var args scriptXattrWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	data, err := decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, nil)
	if err != nil {
		return nil, err
	}
	err = fn(args.Path, args.Name, data, int(args.Flags))
	return scriptSyscallResult(map[string]any{"operation": operation, "path": args.Path, "name": args.Name, "flags": int(args.Flags), "length": len(data), "checksum64": checksum64(data)}, err)
}

func (e *scriptEnv) removePathXattr(value goja.Value, fn func(string, string) error, operation string) (any, error) {
	var args scriptXattrWriteArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	err := fn(args.Path, args.Name)
	return scriptSyscallResult(map[string]any{"operation": operation, "path": args.Path, "name": args.Name}, err)
}

func splitXattrList(data []byte) []string {
	if len(data) == 0 {
		return []string{}
	}
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	if len(parts) == 1 && parts[0] == "" {
		return []string{}
	}
	return parts
}

func statfsInfo(st unix.Statfs_t) map[string]any {
	return map[string]any{
		"type":    st.Type,
		"bsize":   st.Bsize,
		"blocks":  st.Blocks,
		"bfree":   st.Bfree,
		"bavail":  st.Bavail,
		"files":   st.Files,
		"ffree":   st.Ffree,
		"fsid":    []int32{st.Fsid.Val[0], st.Fsid.Val[1]},
		"namelen": st.Namelen,
		"frsize":  st.Frsize,
		"flags":   st.Flags,
	}
}

func statxInfo(st unix.Statx_t) map[string]any {
	return map[string]any{
		"mask":                st.Mask,
		"blksize":             st.Blksize,
		"attributes":          hex64(st.Attributes),
		"nlink":               st.Nlink,
		"uid":                 st.Uid,
		"gid":                 st.Gid,
		"mode":                hex16(st.Mode),
		"ino":                 st.Ino,
		"size":                st.Size,
		"blocks":              st.Blocks,
		"attributes_mask":     hex64(st.Attributes_mask),
		"atime":               statxTimestampInfo(st.Atime),
		"btime":               statxTimestampInfo(st.Btime),
		"ctime":               statxTimestampInfo(st.Ctime),
		"mtime":               statxTimestampInfo(st.Mtime),
		"rdev_major":          st.Rdev_major,
		"rdev_minor":          st.Rdev_minor,
		"dev_major":           st.Dev_major,
		"dev_minor":           st.Dev_minor,
		"mnt_id":              st.Mnt_id,
		"dio_mem_align":       st.Dio_mem_align,
		"dio_offset_align":    st.Dio_offset_align,
		"subvol":              st.Subvol,
		"atomic_write_min":    st.Atomic_write_unit_min,
		"atomic_write_max":    st.Atomic_write_unit_max,
		"atomic_write_segs":   st.Atomic_write_segments_max,
		"dio_read_offset":     st.Dio_read_offset_align,
		"atomic_write_max_op": st.Atomic_write_unit_max_opt,
	}
}

func statxTimestampInfo(ts unix.StatxTimestamp) map[string]any {
	return map[string]any{"sec": ts.Sec, "nsec": ts.Nsec}
}

func rlimitInfo(limit unix.Rlimit) map[string]any {
	return map[string]any{"cur": limit.Cur, "max": limit.Max}
}
