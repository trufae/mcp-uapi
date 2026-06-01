package mcpserver

import (
	"bytes"
	"errors"
	"fmt"
	stdio "io"
	"io/fs"
	stdnet "net"
	stdos "os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/dop251/goja"
	"golang.org/x/sys/unix"
)

type rootEntry struct {
	Handle string      `json:"handle"`
	Name   string      `json:"name"`
	Root   *stdos.Root `json:"-"`
}

type processEntry struct {
	Handle  string         `json:"handle"`
	Pid     int            `json:"pid"`
	Process *stdos.Process `json:"-"`
}

type scriptNamedMethod struct {
	GoName string
	JSName string
	Method scriptMethod
}

func (e *scriptEnv) osObject() *goja.Object {
	obj := e.vm.NewObject()
	for _, method := range e.osMethods() {
		e.setScriptMethod(obj, method.JSName, method.Method)
		if method.GoName != "" && method.GoName != method.JSName {
			e.setScriptMethod(obj, method.GoName, method.Method)
		}
	}
	for name, value := range osConstants() {
		_ = obj.Set(name, value)
	}
	return obj
}

func (e *scriptEnv) ioObject() *goja.Object {
	obj := e.vm.NewObject()
	for _, method := range e.ioMethods() {
		e.setScriptMethod(obj, method.JSName, method.Method)
		if method.GoName != "" && method.GoName != method.JSName {
			e.setScriptMethod(obj, method.GoName, method.Method)
		}
	}
	for name, value := range ioConstants() {
		_ = obj.Set(name, value)
	}
	return obj
}

func (e *scriptEnv) osMethods() []scriptNamedMethod {
	return []scriptNamedMethod{
		{"Args", "args", e.scriptOSArgs},
		{"Constants", "constants", e.scriptOSConstants},
		{"Chdir", "chdir", e.scriptOSChdir},
		{"Chmod", "chmod", e.scriptOSChmod},
		{"Chown", "chown", e.scriptOSChown},
		{"Chtimes", "chtimes", e.scriptOSChtimes},
		{"Clearenv", "clearenv", e.scriptOSClearenv},
		{"Create", "create", e.scriptOSCreate},
		{"CreateTemp", "createTemp", e.scriptOSCreateTemp},
		{"Environ", "environ", e.scriptOSEnviron},
		{"Executable", "executable", e.scriptOSExecutable},
		{"ExpandEnv", "expandEnv", e.scriptOSExpandEnv},
		{"Getegid", "getegid", e.scriptOSGetegid},
		{"Getenv", "getenv", e.scriptOSGetenv},
		{"Geteuid", "geteuid", e.scriptOSGeteuid},
		{"Getgid", "getgid", e.scriptOSGetgid},
		{"Getgroups", "getgroups", e.scriptOSGetgroups},
		{"Getpagesize", "getpagesize", e.scriptOSGetpagesize},
		{"Getpid", "getpid", e.scriptOSGetpid},
		{"Getppid", "getppid", e.scriptOSGetppid},
		{"Getuid", "getuid", e.scriptOSGetuid},
		{"Getwd", "getwd", e.scriptOSGetwd},
		{"Hostname", "hostname", e.scriptOSHostname},
		{"IsExist", "isExist", e.scriptOSIsExist},
		{"IsNotExist", "isNotExist", e.scriptOSIsNotExist},
		{"IsPathSeparator", "isPathSeparator", e.scriptOSIsPathSeparator},
		{"IsPermission", "isPermission", e.scriptOSIsPermission},
		{"IsTimeout", "isTimeout", e.scriptOSIsTimeout},
		{"Lchown", "lchown", e.scriptOSLchown},
		{"Link", "link", e.scriptOSLink},
		{"LookupEnv", "lookupEnv", e.scriptOSLookupEnv},
		{"Lstat", "lstat", e.scriptOSLstat},
		{"Mkdir", "mkdir", e.scriptOSMkdir},
		{"MkdirAll", "mkdirAll", e.scriptOSMkdirAll},
		{"MkdirTemp", "mkdirTemp", e.scriptOSMkdirTemp},
		{"NewFile", "newFile", e.scriptOSNewFile},
		{"Open", "open", e.scriptOSOpen},
		{"OpenFile", "openFile", e.scriptOSOpenFile},
		{"OpenInRoot", "openInRoot", e.scriptOSOpenInRoot},
		{"OpenRoot", "openRoot", e.scriptOSOpenRoot},
		{"Pipe", "pipe", e.scriptOSPipe},
		{"ReadDir", "readDir", e.scriptOSReadDir},
		{"ReadFile", "readFile", e.scriptOSReadFile},
		{"Readlink", "readlink", e.scriptOSReadlink},
		{"Remove", "remove", e.scriptOSRemove},
		{"RemoveAll", "removeAll", e.scriptOSRemoveAll},
		{"Rename", "rename", e.scriptOSRename},
		{"SameFile", "sameFile", e.scriptOSSameFile},
		{"Setenv", "setenv", e.scriptOSSetenv},
		{"Stat", "stat", e.scriptOSStat},
		{"Symlink", "symlink", e.scriptOSSymlink},
		{"TempDir", "tempDir", e.scriptOSTempDir},
		{"Truncate", "truncate", e.scriptOSTruncate},
		{"Unsetenv", "unsetenv", e.scriptOSUnsetenv},
		{"UserCacheDir", "userCacheDir", e.scriptOSUserCacheDir},
		{"UserConfigDir", "userConfigDir", e.scriptOSUserConfigDir},
		{"UserHomeDir", "userHomeDir", e.scriptOSUserHomeDir},
		{"WriteFile", "writeFile", e.scriptOSWriteFile},
		{"FileChdir", "fileChdir", e.scriptOSFileChdir},
		{"FileChmod", "fileChmod", e.scriptOSFileChmod},
		{"FileChown", "fileChown", e.scriptOSFileChown},
		{"FileClose", "fileClose", e.scriptOSFileClose},
		{"FileFd", "fileFd", e.scriptOSFileFd},
		{"FileName", "fileName", e.scriptOSFileName},
		{"FileRead", "fileRead", e.scriptOSFileRead},
		{"FileReadAt", "fileReadAt", e.scriptOSFileReadAt},
		{"FileReadDir", "fileReadDir", e.scriptOSFileReadDir},
		{"FileReaddir", "fileReaddir", e.scriptOSFileReaddir},
		{"FileReaddirnames", "fileReaddirnames", e.scriptOSFileReaddirnames},
		{"FileReadFrom", "fileReadFrom", e.scriptOSFileReadFrom},
		{"FileSeek", "fileSeek", e.scriptOSFileSeek},
		{"FileSetDeadline", "fileSetDeadline", e.scriptOSFileSetDeadline},
		{"FileSetReadDeadline", "fileSetReadDeadline", e.scriptOSFileSetReadDeadline},
		{"FileSetWriteDeadline", "fileSetWriteDeadline", e.scriptOSFileSetWriteDeadline},
		{"FileStat", "fileStat", e.scriptOSFileStat},
		{"FileSync", "fileSync", e.scriptOSFileSync},
		{"FileTruncate", "fileTruncate", e.scriptOSFileTruncate},
		{"FileWrite", "fileWrite", e.scriptOSFileWrite},
		{"FileWriteAt", "fileWriteAt", e.scriptOSFileWriteAt},
		{"FileWriteString", "fileWriteString", e.scriptOSFileWriteString},
		{"FileWriteTo", "fileWriteTo", e.scriptOSFileWriteTo},
		{"RootChmod", "rootChmod", e.scriptOSRootChmod},
		{"RootChown", "rootChown", e.scriptOSRootChown},
		{"RootChtimes", "rootChtimes", e.scriptOSRootChtimes},
		{"RootClose", "rootClose", e.scriptOSRootClose},
		{"RootCreate", "rootCreate", e.scriptOSRootCreate},
		{"RootLchown", "rootLchown", e.scriptOSRootLchown},
		{"RootLink", "rootLink", e.scriptOSRootLink},
		{"RootLstat", "rootLstat", e.scriptOSRootLstat},
		{"RootMkdir", "rootMkdir", e.scriptOSRootMkdir},
		{"RootMkdirAll", "rootMkdirAll", e.scriptOSRootMkdirAll},
		{"RootName", "rootName", e.scriptOSRootName},
		{"RootOpen", "rootOpen", e.scriptOSRootOpen},
		{"RootOpenFile", "rootOpenFile", e.scriptOSRootOpenFile},
		{"RootOpenRoot", "rootOpenRoot", e.scriptOSRootOpenRoot},
		{"RootReadFile", "rootReadFile", e.scriptOSRootReadFile},
		{"RootReadlink", "rootReadlink", e.scriptOSRootReadlink},
		{"RootRemove", "rootRemove", e.scriptOSRootRemove},
		{"RootRemoveAll", "rootRemoveAll", e.scriptOSRootRemoveAll},
		{"RootRename", "rootRename", e.scriptOSRootRename},
		{"RootStat", "rootStat", e.scriptOSRootStat},
		{"RootSymlink", "rootSymlink", e.scriptOSRootSymlink},
		{"RootWriteFile", "rootWriteFile", e.scriptOSRootWriteFile},
		{"FindProcess", "findProcess", e.scriptOSFindProcess},
		{"StartProcess", "startProcess", e.scriptOSStartProcess},
		{"ProcessKill", "processKill", e.scriptOSProcessKill},
		{"ProcessRelease", "processRelease", e.scriptOSProcessRelease},
		{"ProcessSignal", "processSignal", e.scriptOSProcessSignal},
		{"ProcessWait", "processWait", e.scriptOSProcessWait},
	}
}

func (e *scriptEnv) ioMethods() []scriptNamedMethod {
	return []scriptNamedMethod{
		{"Constants", "constants", e.scriptIOConstants},
		{"Copy", "copy", e.scriptIOCopy},
		{"CopyBuffer", "copyBuffer", e.scriptIOCopyBuffer},
		{"CopyN", "copyN", e.scriptIOCopyN},
		{"ReadAll", "readAll", e.scriptIOReadAll},
		{"ReadAtLeast", "readAtLeast", e.scriptIOReadAtLeast},
		{"ReadFull", "readFull", e.scriptIOReadFull},
		{"WriteString", "writeString", e.scriptIOWriteString},
		{"LimitReader", "limitReader", e.scriptIOLimitReader},
		{"MultiReader", "multiReader", e.scriptIOMultiReader},
		{"TeeReader", "teeReader", e.scriptIOTeeReader},
		{"MultiWriter", "multiWriter", e.scriptIOMultiWriter},
		{"NewSectionReader", "newSectionReader", e.scriptIONewSectionReader},
		{"NewOffsetWriter", "newOffsetWriter", e.scriptIONewOffsetWriter},
		{"Pipe", "pipe", e.scriptIOPipe},
	}
}

func scriptOSWrapperNames() []string {
	return []string{
		"args", "constants", "chdir", "chmod", "chown", "chtimes", "clearenv", "create", "createTemp", "environ", "executable", "expandEnv",
		"getegid", "getenv", "geteuid", "getgid", "getgroups", "getpagesize", "getpid", "getppid", "getuid", "getwd", "hostname",
		"isExist", "isNotExist", "isPathSeparator", "isPermission", "isTimeout", "lchown", "link", "lookupEnv", "lstat", "mkdir", "mkdirAll", "mkdirTemp",
		"newFile", "open", "openFile", "openInRoot", "openRoot", "pipe", "readDir", "readFile", "readlink", "remove", "removeAll", "rename", "sameFile", "setenv", "stat", "symlink", "tempDir", "truncate", "unsetenv", "userCacheDir", "userConfigDir", "userHomeDir", "writeFile",
		"fileChdir", "fileChmod", "fileChown", "fileClose", "fileFd", "fileName", "fileRead", "fileReadAt", "fileReadDir", "fileReaddir", "fileReaddirnames", "fileReadFrom", "fileSeek", "fileSetDeadline", "fileSetReadDeadline", "fileSetWriteDeadline", "fileStat", "fileSync", "fileTruncate", "fileWrite", "fileWriteAt", "fileWriteString", "fileWriteTo",
		"rootChmod", "rootChown", "rootChtimes", "rootClose", "rootCreate", "rootLchown", "rootLink", "rootLstat", "rootMkdir", "rootMkdirAll", "rootName", "rootOpen", "rootOpenFile", "rootOpenRoot", "rootReadFile", "rootReadlink", "rootRemove", "rootRemoveAll", "rootRename", "rootStat", "rootSymlink", "rootWriteFile",
		"findProcess", "startProcess", "processKill", "processRelease", "processSignal", "processWait",
	}
}

func scriptIOWrapperNames() []string {
	return []string{"constants", "copy", "copyBuffer", "copyN", "readAll", "readAtLeast", "readFull", "writeString", "limitReader", "multiReader", "teeReader", "multiWriter", "newSectionReader", "newOffsetWriter", "pipe"}
}

func osConstants() map[string]any {
	return map[string]any{
		"O_RDONLY":          stdos.O_RDONLY,
		"O_WRONLY":          stdos.O_WRONLY,
		"O_RDWR":            stdos.O_RDWR,
		"O_APPEND":          stdos.O_APPEND,
		"O_CREATE":          stdos.O_CREATE,
		"O_CREAT":           stdos.O_CREATE,
		"O_EXCL":            stdos.O_EXCL,
		"O_SYNC":            stdos.O_SYNC,
		"O_TRUNC":           stdos.O_TRUNC,
		"SEEK_SET":          stdos.SEEK_SET,
		"SEEK_CUR":          stdos.SEEK_CUR,
		"SEEK_END":          stdos.SEEK_END,
		"PathSeparator":     string(stdos.PathSeparator),
		"PathListSeparator": string(stdos.PathListSeparator),
		"DevNull":           stdos.DevNull,
		"ModeDir":           uint32(fs.ModeDir),
		"ModeAppend":        uint32(fs.ModeAppend),
		"ModeExclusive":     uint32(fs.ModeExclusive),
		"ModeTemporary":     uint32(fs.ModeTemporary),
		"ModeSymlink":       uint32(fs.ModeSymlink),
		"ModeDevice":        uint32(fs.ModeDevice),
		"ModeNamedPipe":     uint32(fs.ModeNamedPipe),
		"ModeSocket":        uint32(fs.ModeSocket),
		"ModeSetuid":        uint32(fs.ModeSetuid),
		"ModeSetgid":        uint32(fs.ModeSetgid),
		"ModeCharDevice":    uint32(fs.ModeCharDevice),
		"ModeSticky":        uint32(fs.ModeSticky),
		"ModeIrregular":     uint32(fs.ModeIrregular),
		"ModeType":          uint32(fs.ModeType),
		"ModePerm":          uint32(fs.ModePerm),
		"Stdin":             map[string]any{"fd": 0, "name": "/dev/stdin"},
		"Stdout":            map[string]any{"fd": 1, "name": "/dev/stdout"},
		"Stderr":            map[string]any{"fd": 2, "name": "/dev/stderr"},
	}
}

func ioConstants() map[string]any {
	return map[string]any{
		"SeekStart":        stdio.SeekStart,
		"SeekCurrent":      stdio.SeekCurrent,
		"SeekEnd":          stdio.SeekEnd,
		"EOF":              "EOF",
		"ErrClosedPipe":    stdio.ErrClosedPipe.Error(),
		"ErrNoProgress":    stdio.ErrNoProgress.Error(),
		"ErrShortBuffer":   stdio.ErrShortBuffer.Error(),
		"ErrShortWrite":    stdio.ErrShortWrite.Error(),
		"ErrUnexpectedEOF": stdio.ErrUnexpectedEOF.Error(),
		"Discard":          map[string]any{"discard": true},
	}
}

func (e *scriptEnv) scriptOSConstants(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "constants": osConstants()}, nil
}

func (e *scriptEnv) scriptIOConstants(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "constants": ioConstants()}, nil
}

func scriptGoResult(fields map[string]any, err error) (map[string]any, error) {
	if fields == nil {
		fields = map[string]any{}
	}
	if err == nil {
		fields["ok"] = true
		return fields, nil
	}
	fields["ok"] = false
	addGoErrorFields(fields, err)
	return fields, nil
}

func addGoErrorFields(fields map[string]any, err error) {
	fields["error"] = err.Error()
	fields["error_type"] = fmt.Sprintf("%T", err)
	if errors.Is(err, stdio.EOF) {
		fields["error_name"] = "EOF"
	} else if errors.Is(err, stdio.ErrUnexpectedEOF) {
		fields["error_name"] = "ErrUnexpectedEOF"
	} else if errors.Is(err, stdio.ErrShortWrite) {
		fields["error_name"] = "ErrShortWrite"
	} else if errors.Is(err, stdio.ErrShortBuffer) {
		fields["error_name"] = "ErrShortBuffer"
	} else if errors.Is(err, stdio.ErrClosedPipe) {
		fields["error_name"] = "ErrClosedPipe"
	} else if errors.Is(err, stdio.ErrNoProgress) {
		fields["error_name"] = "ErrNoProgress"
	} else if errors.Is(err, fs.ErrInvalid) {
		fields["error_name"] = "ErrInvalid"
	} else if errors.Is(err, fs.ErrPermission) {
		fields["error_name"] = "ErrPermission"
	} else if errors.Is(err, fs.ErrExist) {
		fields["error_name"] = "ErrExist"
	} else if errors.Is(err, fs.ErrNotExist) {
		fields["error_name"] = "ErrNotExist"
	} else if errors.Is(err, fs.ErrClosed) {
		fields["error_name"] = "ErrClosed"
	}
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		fields["op"] = pathErr.Op
		fields["path"] = pathErr.Path
	}
	var linkErr *stdos.LinkError
	if errors.As(err, &linkErr) {
		fields["op"] = linkErr.Op
		fields["old"] = linkErr.Old
		fields["new"] = linkErr.New
	}
	var sysErr *stdos.SyscallError
	if errors.As(err, &sysErr) {
		fields["syscall"] = sysErr.Syscall
	}
	var netErr stdnet.Error
	if errors.As(err, &netErr) {
		fields["timeout"] = netErr.Timeout()
		fields["temporary"] = netErr.Temporary()
	}
	var opErr *stdnet.OpError
	if errors.As(err, &opErr) {
		fields["op"] = opErr.Op
		fields["network"] = opErr.Net
		fields["source_addr"] = netAddrInfo(opErr.Source)
		fields["addr"] = netAddrInfo(opErr.Addr)
	}
	var dnsErr *stdnet.DNSError
	if errors.As(err, &dnsErr) {
		fields["error_name"] = "DNSError"
		fields["dns_name"] = dnsErr.Name
		fields["dns_server"] = dnsErr.Server
		fields["timeout"] = dnsErr.IsTimeout
		fields["temporary"] = dnsErr.IsTemporary
		fields["not_found"] = dnsErr.IsNotFound
	}
	var addrErr *stdnet.AddrError
	if errors.As(err, &addrErr) {
		fields["error_name"] = "AddrError"
		fields["addr"] = addrErr.Addr
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		fields["errno"] = int(errno)
		fields["errno_name"] = errnoName(unix.Errno(errno))
	}
}

func scriptErrorPredicate(value goja.Value, predicate func(error) bool) (any, error) {
	err := scriptErrorFromValue(value)
	return map[string]any{"ok": true, "match": predicate(err)}, nil
}

func scriptErrorFromValue(value goja.Value) error {
	if isMissingJSValue(value) {
		return nil
	}
	exported := exportArgument(value)
	switch v := exported.(type) {
	case string:
		return errors.New(v)
	case map[string]any:
		if name, _ := v["error_name"].(string); name != "" {
			switch name {
			case "ErrInvalid":
				return fs.ErrInvalid
			case "ErrPermission":
				return fs.ErrPermission
			case "ErrExist":
				return fs.ErrExist
			case "ErrNotExist":
				return fs.ErrNotExist
			case "ErrClosed":
				return fs.ErrClosed
			case "EOF":
				return stdio.EOF
			}
		}
		if name, _ := v["errno_name"].(string); name != "" {
			if errno, ok := errnoFromString(name); ok {
				return errno
			}
		}
		if errText, _ := v["error"].(string); errText != "" {
			return errors.New(errText)
		}
	}
	return nil
}

type scriptPathArgs struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func scriptPath(args scriptPathArgs) string {
	if args.Name != "" {
		return args.Name
	}
	return args.Path
}

func requireScriptPath(args scriptPathArgs) (string, error) {
	path := scriptPath(args)
	if path == "" {
		return "", fmt.Errorf("name or path is required")
	}
	return path, nil
}

type scriptDataInputArgs struct {
	DataBase64   string    `json:"data_base64"`
	DataHex      string    `json:"data_hex"`
	DataUTF8     string    `json:"data_utf8"`
	Buffer       string    `json:"buffer"`
	BufferOffset Uint64    `json:"buffer_offset"`
	Length       Uint64    `json:"length"`
	Fill         *fillSpec `json:"fill"`
}

func (e *scriptEnv) scriptInputBytes(args scriptDataInputArgs) ([]byte, error) {
	if args.Buffer != "" {
		directSources := 0
		if args.DataBase64 != "" {
			directSources++
		}
		if args.DataHex != "" {
			directSources++
		}
		if args.DataUTF8 != "" {
			directSources++
		}
		if args.Fill != nil {
			directSources++
		}
		if directSources > 0 {
			return nil, errors.New("provide only one data source")
		}
		e.app.mu.Lock()
		defer e.app.mu.Unlock()
		return e.app.inputBytesLocked("", "", "", args.Buffer, uint64(args.BufferOffset), uint64(args.Length))
	}
	return decodeDirectData(args.DataBase64, args.DataHex, args.DataUTF8, args.Fill)
}

func fileInfoMap(info fs.FileInfo) map[string]any {
	mode := info.Mode()
	fields := map[string]any{
		"name":        info.Name(),
		"size":        info.Size(),
		"mode":        mode.String(),
		"mode_octal":  fmt.Sprintf("0%o", uint32(mode)),
		"mode_type":   fmt.Sprintf("0%o", uint32(mode.Type())),
		"mode_perm":   fmt.Sprintf("0%o", uint32(mode.Perm())),
		"is_dir":      info.IsDir(),
		"mod_time":    info.ModTime().Format(time.RFC3339Nano),
		"mod_time_ns": info.ModTime().UnixNano(),
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		fields["stat"] = syscallStatInfo(*stat)
	}
	return fields
}

func syscallStatInfo(st syscall.Stat_t) map[string]any {
	return map[string]any{
		"dev":        uint64(st.Dev),
		"ino":        uint64(st.Ino),
		"mode":       hex32(uint32(st.Mode)),
		"mode_octal": fmt.Sprintf("0%o", st.Mode),
		"nlink":      uint64(st.Nlink),
		"uid":        uint32(st.Uid),
		"gid":        uint32(st.Gid),
		"rdev":       uint64(st.Rdev),
		"size":       st.Size,
		"blksize":    st.Blksize,
		"blocks":     st.Blocks,
		"atime_sec":  st.Atim.Sec,
		"mtime_sec":  st.Mtim.Sec,
		"ctime_sec":  st.Ctim.Sec,
	}
}

func dirEntryMap(entry fs.DirEntry) map[string]any {
	fields := map[string]any{"name": entry.Name(), "is_dir": entry.IsDir(), "type": entry.Type().String(), "type_octal": fmt.Sprintf("0%o", uint32(entry.Type()))}
	if info, err := entry.Info(); err == nil {
		fields["info"] = fileInfoMap(info)
	} else {
		fields["info_error"] = err.Error()
	}
	return fields
}

func fileInfoList(infos []fs.FileInfo) []map[string]any {
	out := make([]map[string]any, 0, len(infos))
	for _, info := range infos {
		out = append(out, fileInfoMap(info))
	}
	return out
}

func dirEntryList(entries []fs.DirEntry) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, dirEntryMap(entry))
	}
	return out
}

func parseScriptTime(text string, unixSeconds *int64, unixNano *int64, field string) (time.Time, error) {
	if unixNano != nil {
		return time.Unix(0, *unixNano), nil
	}
	if unixSeconds != nil {
		return time.Unix(*unixSeconds, 0), nil
	}
	if strings.TrimSpace(text) == "" {
		return time.Time{}, fmt.Errorf("%s, %s_unix, or %s_unix_nano is required", field, field, field)
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed, nil
}

func parseOptionalDeadline(text string, unixSeconds *int64, unixNano *int64, field string) (time.Time, error) {
	if strings.TrimSpace(text) == "" && unixSeconds == nil && unixNano == nil {
		return time.Time{}, nil
	}
	return parseScriptTime(text, unixSeconds, unixNano, field)
}

func (e *scriptEnv) registerOpenedFD(fd int, kind, path, handle string, meta map[string]any, fields map[string]any, err error) (map[string]any, error) {
	return e.registerScriptFD(fd, kind, path, handle, meta, fields, err)
}

func (e *scriptEnv) registerStdOSFile(file *stdos.File, kind, path, handle string, meta map[string]any, fields map[string]any, err error) (map[string]any, error) {
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if file == nil {
		return nil, errors.New("os file is nil")
	}
	dupFD, dupErr := unix.Dup(int(file.Fd()))
	closeErr := file.Close()
	if dupErr != nil {
		return scriptSyscallResult(fields, dupErr)
	}
	if closeErr != nil {
		_ = unix.Close(dupFD)
		return scriptGoResult(fields, closeErr)
	}
	return e.registerOpenedFD(dupFD, kind, path, handle, meta, fields, nil)
}

func (e *scriptEnv) dupFile(ref ScriptFDRefArgs, label string) (*stdos.File, int, string, func(), error) {
	fd, handle, err := e.resolveScriptFD(ref)
	if err != nil {
		return nil, -1, "", nil, err
	}
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return nil, fd, handle, nil, err
	}
	name := handle
	if name == "" {
		name = label
	}
	file := stdos.NewFile(uintptr(dupFD), name)
	if file == nil {
		_ = unix.Close(dupFD)
		return nil, fd, handle, nil, errors.New("os.NewFile returned nil")
	}
	return file, fd, handle, func() { _ = file.Close() }, nil
}

func (e *scriptEnv) resolveFDInfo(ref ScriptFDRefArgs) (*fdEntry, int, string, error) {
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	fd, handle, managed, err := e.app.resolveFDLocked(ref.Handle, ref.FD)
	if err != nil {
		return nil, -1, "", err
	}
	if managed {
		return e.app.fds[handle], fd, handle, nil
	}
	return nil, fd, handle, nil
}

func (e *scriptEnv) closeManagedFD(ref ScriptFDRefArgs) (map[string]any, error) {
	e.app.mu.Lock()
	fd, handle, managed, err := e.app.resolveFDLocked(ref.Handle, ref.FD)
	e.app.mu.Unlock()
	if err != nil {
		return nil, err
	}
	closeErr := unix.Close(fd)
	if closeErr == nil && managed {
		e.app.mu.Lock()
		delete(e.app.fds, handle)
		e.app.mu.Unlock()
	}
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "closed": closeErr == nil}, closeErr)
}

func (e *scriptEnv) registerRoot(root *stdos.Root, requestedHandle string, fields map[string]any, err error) (map[string]any, error) {
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if root == nil {
		return nil, errors.New("os root is nil")
	}
	if fields == nil {
		fields = map[string]any{}
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("root handle", requestedHandle); err != nil {
			_ = root.Close()
			return nil, err
		}
		if _, exists := e.app.roots[requestedHandle]; exists {
			_ = root.Close()
			return nil, fmt.Errorf("root handle %q already exists", requestedHandle)
		}
	} else {
		for {
			e.app.nextRootHandle++
			requestedHandle = fmt.Sprintf("root%d", e.app.nextRootHandle)
			if _, exists := e.app.roots[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &rootEntry{Handle: requestedHandle, Name: root.Name(), Root: root}
	e.app.roots[requestedHandle] = entry
	fields["handle"] = entry.Handle
	fields["name"] = entry.Name
	return scriptGoResult(fields, nil)
}

func (e *scriptEnv) resolveRoot(handle string) (*rootEntry, error) {
	if handle == "" {
		return nil, errors.New("root handle is required")
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	entry, ok := e.app.roots[handle]
	if !ok {
		return nil, fmt.Errorf("root handle %q not found", handle)
	}
	return entry, nil
}

func (e *scriptEnv) registerProcess(process *stdos.Process, requestedHandle string, fields map[string]any, err error) (map[string]any, error) {
	if err != nil {
		return scriptGoResult(fields, err)
	}
	if process == nil {
		return nil, errors.New("os process is nil")
	}
	if fields == nil {
		fields = map[string]any{}
	}
	e.app.mu.Lock()
	defer e.app.mu.Unlock()
	if requestedHandle != "" {
		if err := validateName("process handle", requestedHandle); err != nil {
			_ = process.Release()
			return nil, err
		}
		if _, exists := e.app.processes[requestedHandle]; exists {
			_ = process.Release()
			return nil, fmt.Errorf("process handle %q already exists", requestedHandle)
		}
	} else {
		for {
			e.app.nextProcessHandle++
			requestedHandle = fmt.Sprintf("proc%d", e.app.nextProcessHandle)
			if _, exists := e.app.processes[requestedHandle]; !exists {
				break
			}
		}
	}
	entry := &processEntry{Handle: requestedHandle, Pid: process.Pid, Process: process}
	e.app.processes[requestedHandle] = entry
	fields["handle"] = entry.Handle
	fields["pid"] = entry.Pid
	return scriptGoResult(fields, nil)
}

func (e *scriptEnv) resolveProcess(handle string, pid *int) (*processEntry, error) {
	if handle != "" {
		e.app.mu.Lock()
		defer e.app.mu.Unlock()
		entry, ok := e.app.processes[handle]
		if !ok {
			return nil, fmt.Errorf("process handle %q not found", handle)
		}
		return entry, nil
	}
	if pid == nil {
		return nil, errors.New("process handle or pid is required")
	}
	process, err := stdos.FindProcess(*pid)
	if err != nil {
		return nil, err
	}
	return &processEntry{Pid: process.Pid, Process: process}, nil
}

func parseSignal(value ConstUint64) syscall.Signal {
	return syscall.Signal(int(value))
}

func statPathResult(path string, nofollow bool) (map[string]any, error) {
	var info fs.FileInfo
	var err error
	if nofollow {
		info, err = stdos.Lstat(path)
	} else {
		info, err = stdos.Stat(path)
	}
	fields := map[string]any{"path": path, "nofollow": nofollow}
	if err == nil {
		fields["info"] = fileInfoMap(info)
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) boundedReadAll(reader stdio.Reader, encoding string) (map[string]any, error) {
	limit := e.app.config.MaxReadBytes
	data, err := stdio.ReadAll(stdio.LimitReader(reader, int64(limit)+1))
	if uint64(len(data)) > limit {
		return nil, fmt.Errorf("read result %d exceeds max_read_bytes %d", len(data), limit)
	}
	fields := map[string]any{"bytes_read": len(data)}
	if len(data) > 0 || err == nil {
		encoded, encodeErr := encodeBytes(data, encoding)
		if encodeErr != nil {
			return nil, encodeErr
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, err)
}

func (e *scriptEnv) scriptOSArgs(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "args": append([]string(nil), stdos.Args...)}, nil
}

func (e *scriptEnv) scriptOSChdir(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"dir": path}, stdos.Chdir(path))
}

func (e *scriptEnv) scriptOSChmod(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path, "mode": uint32(args.Mode)}, stdos.Chmod(path, fs.FileMode(args.Mode)))
}

func (e *scriptEnv) scriptOSChown(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		UID int `json:"uid"`
		GID int `json:"gid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path, "uid": args.UID, "gid": args.GID}, stdos.Chown(path, args.UID, args.GID))
}

func (e *scriptEnv) scriptOSChtimes(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		ATime         string `json:"atime"`
		MTime         string `json:"mtime"`
		ATimeUnix     *int64 `json:"atime_unix"`
		MTimeUnix     *int64 `json:"mtime_unix"`
		ATimeUnixNano *int64 `json:"atime_unix_nano"`
		MTimeUnixNano *int64 `json:"mtime_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	atime, err := parseScriptTime(args.ATime, args.ATimeUnix, args.ATimeUnixNano, "atime")
	if err != nil {
		return nil, err
	}
	mtime, err := parseScriptTime(args.MTime, args.MTimeUnix, args.MTimeUnixNano, "mtime")
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path, "atime": atime.Format(time.RFC3339Nano), "mtime": mtime.Format(time.RFC3339Nano)}, stdos.Chtimes(path, atime, mtime))
}

func (e *scriptEnv) scriptOSClearenv(value goja.Value) (any, error) {
	stdos.Clearenv()
	return map[string]any{"ok": true}, nil
}

func (e *scriptEnv) scriptOSCreate(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	fd, openErr := unix.Open(path, stdos.O_RDWR|stdos.O_CREATE|stdos.O_TRUNC|unix.O_CLOEXEC, 0o666)
	return e.registerOpenedFD(fd, "os.File", path, args.Handle, map[string]any{"package": "os", "function": "Create"}, map[string]any{"name": path}, openErr)
}

func (e *scriptEnv) scriptOSCreateTemp(value goja.Value) (any, error) {
	var args struct {
		Dir     string `json:"dir"`
		Pattern string `json:"pattern"`
		Handle  string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, err := stdos.CreateTemp(args.Dir, args.Pattern)
	fields := map[string]any{"dir": args.Dir, "pattern": args.Pattern}
	if file != nil {
		fields["name"] = file.Name()
	}
	return e.registerStdOSFile(file, "os.File", "", args.Handle, map[string]any{"package": "os", "function": "CreateTemp"}, fields, err)
}

func (e *scriptEnv) scriptOSEnviron(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "env": stdos.Environ()}, nil
}

func (e *scriptEnv) scriptOSExecutable(value goja.Value) (any, error) {
	name, err := stdos.Executable()
	return scriptGoResult(map[string]any{"name": name}, err)
}

func (e *scriptEnv) scriptOSExpandEnv(value goja.Value) (any, error) {
	var args struct {
		Text string `json:"text"`
		S    string `json:"s"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	text := args.Text
	if text == "" {
		text = args.S
	}
	return map[string]any{"ok": true, "text": stdos.ExpandEnv(text)}, nil
}

func (e *scriptEnv) scriptOSGetegid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "egid": stdos.Getegid()}, nil
}

func (e *scriptEnv) scriptOSGetenv(value goja.Value) (any, error) {
	var args struct {
		Key string `json:"key"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "key": args.Key, "value": stdos.Getenv(args.Key)}, nil
}

func (e *scriptEnv) scriptOSGeteuid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "euid": stdos.Geteuid()}, nil
}

func (e *scriptEnv) scriptOSGetgid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "gid": stdos.Getgid()}, nil
}

func (e *scriptEnv) scriptOSGetgroups(value goja.Value) (any, error) {
	groups, err := stdos.Getgroups()
	return scriptGoResult(map[string]any{"groups": groups}, err)
}

func (e *scriptEnv) scriptOSGetpagesize(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "pagesize": stdos.Getpagesize()}, nil
}

func (e *scriptEnv) scriptOSGetpid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "pid": stdos.Getpid()}, nil
}

func (e *scriptEnv) scriptOSGetppid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "ppid": stdos.Getppid()}, nil
}

func (e *scriptEnv) scriptOSGetuid(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "uid": stdos.Getuid()}, nil
}

func (e *scriptEnv) scriptOSGetwd(value goja.Value) (any, error) {
	dir, err := stdos.Getwd()
	return scriptGoResult(map[string]any{"dir": dir}, err)
}

func (e *scriptEnv) scriptOSHostname(value goja.Value) (any, error) {
	name, err := stdos.Hostname()
	return scriptGoResult(map[string]any{"name": name}, err)
}

func (e *scriptEnv) scriptOSIsExist(value goja.Value) (any, error) {
	return scriptErrorPredicate(value, stdos.IsExist)
}

func (e *scriptEnv) scriptOSIsNotExist(value goja.Value) (any, error) {
	return scriptErrorPredicate(value, stdos.IsNotExist)
}

func (e *scriptEnv) scriptOSIsPathSeparator(value goja.Value) (any, error) {
	var args struct {
		Char string `json:"char"`
		Code *int   `json:"code"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	var b byte
	if args.Code != nil {
		if *args.Code < 0 || *args.Code > 255 {
			return nil, fmt.Errorf("code %d is outside byte range", *args.Code)
		}
		b = byte(*args.Code)
	} else if args.Char != "" {
		b = args.Char[0]
	} else {
		return nil, errors.New("char or code is required")
	}
	return map[string]any{"ok": true, "match": stdos.IsPathSeparator(b)}, nil
}

func (e *scriptEnv) scriptOSIsPermission(value goja.Value) (any, error) {
	return scriptErrorPredicate(value, stdos.IsPermission)
}

func (e *scriptEnv) scriptOSIsTimeout(value goja.Value) (any, error) {
	return scriptErrorPredicate(value, stdos.IsTimeout)
}

func (e *scriptEnv) scriptOSLchown(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		UID int `json:"uid"`
		GID int `json:"gid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path, "uid": args.UID, "gid": args.GID}, stdos.Lchown(path, args.UID, args.GID))
}

func (e *scriptEnv) scriptOSLink(value goja.Value) (any, error) {
	var args scriptTwoPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"oldname": args.OldPath, "newname": args.NewPath}, stdos.Link(args.OldPath, args.NewPath))
}

func (e *scriptEnv) scriptOSLookupEnv(value goja.Value) (any, error) {
	var args struct {
		Key string `json:"key"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	valueText, found := stdos.LookupEnv(args.Key)
	return map[string]any{"ok": true, "key": args.Key, "value": valueText, "found": found}, nil
}

func (e *scriptEnv) scriptOSLstat(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	return statPathResult(path, true)
}

func (e *scriptEnv) scriptOSMkdir(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Perm ConstUint32 `json:"perm"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = 0o777
	}
	return scriptGoResult(map[string]any{"name": path, "perm": uint32(perm)}, stdos.Mkdir(path, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSMkdirAll(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Perm ConstUint32 `json:"perm"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = 0o777
	}
	return scriptGoResult(map[string]any{"path": path, "perm": uint32(perm)}, stdos.MkdirAll(path, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSMkdirTemp(value goja.Value) (any, error) {
	var args struct {
		Dir     string `json:"dir"`
		Pattern string `json:"pattern"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	name, err := stdos.MkdirTemp(args.Dir, args.Pattern)
	return scriptGoResult(map[string]any{"dir": args.Dir, "pattern": args.Pattern, "name": name}, err)
}

func (e *scriptEnv) scriptOSNewFile(value goja.Value) (any, error) {
	var args struct {
		FD     *int   `json:"fd"`
		Name   string `json:"name"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.FD == nil {
		return nil, errors.New("fd is required")
	}
	e.app.mu.Lock()
	for _, entry := range e.app.fds {
		if entry.FD == *args.FD {
			e.app.mu.Unlock()
			return map[string]any{"ok": true, "handle": entry.Handle, "fd": entry.FD, "name": entry.Path, "already_managed": true}, nil
		}
	}
	if !e.app.config.AllowRawFD {
		e.app.mu.Unlock()
		return nil, fmt.Errorf("raw fd %d is not managed by this server; restart with --allow-raw-fd to permit os.newFile", *args.FD)
	}
	entry, err := e.app.registerFDLocked(*args.FD, "os.File", args.Name, args.Handle, map[string]any{"package": "os", "function": "NewFile"})
	e.app.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "handle": entry.Handle, "fd": entry.FD, "name": entry.Path}, nil
}

func (e *scriptEnv) scriptOSOpen(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	fd, openErr := unix.Open(path, stdos.O_RDONLY|unix.O_CLOEXEC, 0)
	return e.registerOpenedFD(fd, "os.File", path, args.Handle, map[string]any{"package": "os", "function": "Open"}, map[string]any{"name": path, "flag": stdos.O_RDONLY}, openErr)
}

func (e *scriptEnv) scriptOSOpenFile(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Flag   ConstUint64 `json:"flag"`
		Flags  ConstUint64 `json:"flags"`
		Perm   ConstUint32 `json:"perm"`
		Mode   ConstUint32 `json:"mode"`
		Handle string      `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	flag := int(args.Flag)
	if flag == 0 && args.Flags != 0 {
		flag = int(args.Flags)
	}
	perm := args.Perm
	if perm == 0 {
		perm = args.Mode
	}
	fd, openErr := unix.Open(path, flag|unix.O_CLOEXEC, uint32(perm))
	return e.registerOpenedFD(fd, "os.File", path, args.Handle, map[string]any{"package": "os", "function": "OpenFile"}, map[string]any{"name": path, "flag": flag, "perm": uint32(perm)}, openErr)
}

func (e *scriptEnv) scriptOSOpenInRoot(value goja.Value) (any, error) {
	var args struct {
		Dir    string `json:"dir"`
		Name   string `json:"name"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, err := stdos.OpenInRoot(args.Dir, args.Name)
	fields := map[string]any{"dir": args.Dir, "name": args.Name}
	return e.registerStdOSFile(file, "os.File", args.Name, args.Handle, map[string]any{"package": "os", "function": "OpenInRoot", "dir": args.Dir}, fields, err)
}

func (e *scriptEnv) scriptOSOpenRoot(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	root, openErr := stdos.OpenRoot(path)
	return e.registerRoot(root, args.Handle, map[string]any{"name": path}, openErr)
}

func (e *scriptEnv) scriptOSPipe(value goja.Value) (any, error) {
	var args struct {
		Handles []string `json:"handles"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	r, w, err := stdos.Pipe()
	if err != nil {
		return scriptGoResult(nil, err)
	}
	readHandle := ""
	writeHandle := ""
	if len(args.Handles) > 0 {
		readHandle = args.Handles[0]
	}
	if len(args.Handles) > 1 {
		writeHandle = args.Handles[1]
	}
	rdup, rerr := unix.Dup(int(r.Fd()))
	wdup, werr := unix.Dup(int(w.Fd()))
	_ = r.Close()
	_ = w.Close()
	if rerr != nil {
		return scriptSyscallResult(nil, rerr)
	}
	if werr != nil {
		_ = unix.Close(rdup)
		return scriptSyscallResult(nil, werr)
	}
	e.app.mu.Lock()
	rEntry, regErr := e.app.registerFDLocked(rdup, "os.File", "pipe-read", readHandle, map[string]any{"package": "os", "function": "Pipe", "end": "read"})
	var wEntry *fdEntry
	if regErr == nil {
		wEntry, regErr = e.app.registerFDLocked(wdup, "os.File", "pipe-write", writeHandle, map[string]any{"package": "os", "function": "Pipe", "end": "write"})
	}
	if regErr != nil && rEntry != nil {
		delete(e.app.fds, rEntry.Handle)
	}
	e.app.mu.Unlock()
	if regErr != nil {
		_ = unix.Close(rdup)
		_ = unix.Close(wdup)
		return nil, regErr
	}
	return map[string]any{"ok": true, "handles": []string{rEntry.Handle, wEntry.Handle}, "fds": []int{rEntry.FD, wEntry.FD}}, nil
}

func (e *scriptEnv) scriptOSReadDir(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	entries, readErr := stdos.ReadDir(path)
	fields := map[string]any{"name": path}
	if readErr == nil {
		fields["entries"] = dirEntryList(entries)
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSReadFile(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Encoding string `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	data, readErr := stdos.ReadFile(path)
	if uint64(len(data)) > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("read result %d exceeds max_read_bytes %d", len(data), e.app.config.MaxReadBytes)
	}
	fields := map[string]any{"name": path, "bytes_read": len(data)}
	if readErr == nil {
		encoded, err := encodeBytes(data, args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSReadlink(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	target, readErr := stdos.Readlink(path)
	return scriptGoResult(map[string]any{"name": path, "target": target}, readErr)
}

func (e *scriptEnv) scriptOSRemove(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path}, stdos.Remove(path))
}

func (e *scriptEnv) scriptOSRemoveAll(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"path": path}, stdos.RemoveAll(path))
}

func (e *scriptEnv) scriptOSRename(value goja.Value) (any, error) {
	var args scriptRenameatArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"oldpath": args.OldPath, "newpath": args.NewPath}, stdos.Rename(args.OldPath, args.NewPath))
}

func (e *scriptEnv) scriptOSSameFile(value goja.Value) (any, error) {
	var args struct {
		Path1 string `json:"path1"`
		Path2 string `json:"path2"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	info1, err := stdos.Stat(args.Path1)
	if err != nil {
		return scriptGoResult(map[string]any{"path1": args.Path1, "path2": args.Path2}, err)
	}
	info2, err := stdos.Stat(args.Path2)
	if err != nil {
		return scriptGoResult(map[string]any{"path1": args.Path1, "path2": args.Path2}, err)
	}
	return map[string]any{"ok": true, "same": stdos.SameFile(info1, info2), "path1": args.Path1, "path2": args.Path2}, nil
}

func (e *scriptEnv) scriptOSSetenv(value goja.Value) (any, error) {
	var args struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"key": args.Key}, stdos.Setenv(args.Key, args.Value))
}

func (e *scriptEnv) scriptOSStat(value goja.Value) (any, error) {
	var args scriptPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args)
	if err != nil {
		return nil, err
	}
	return statPathResult(path, false)
}

func (e *scriptEnv) scriptOSSymlink(value goja.Value) (any, error) {
	var args scriptTwoPathArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"oldname": args.OldPath, "newname": args.NewPath}, stdos.Symlink(args.OldPath, args.NewPath))
}

func (e *scriptEnv) scriptOSTempDir(value goja.Value) (any, error) {
	return map[string]any{"ok": true, "dir": stdos.TempDir()}, nil
}

func (e *scriptEnv) scriptOSTruncate(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		Size Uint64 `json:"size"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	size, err := checkedInt64("size", args.Size)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"name": path, "size": size}, stdos.Truncate(path, size))
}

func (e *scriptEnv) scriptOSUnsetenv(value goja.Value) (any, error) {
	var args struct {
		Key string `json:"key"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"key": args.Key}, stdos.Unsetenv(args.Key))
}

func (e *scriptEnv) scriptOSUserCacheDir(value goja.Value) (any, error) {
	dir, err := stdos.UserCacheDir()
	return scriptGoResult(map[string]any{"dir": dir}, err)
}

func (e *scriptEnv) scriptOSUserConfigDir(value goja.Value) (any, error) {
	dir, err := stdos.UserConfigDir()
	return scriptGoResult(map[string]any{"dir": dir}, err)
}

func (e *scriptEnv) scriptOSUserHomeDir(value goja.Value) (any, error) {
	dir, err := stdos.UserHomeDir()
	return scriptGoResult(map[string]any{"dir": dir}, err)
}

func (e *scriptEnv) scriptOSWriteFile(value goja.Value) (any, error) {
	var args struct {
		scriptPathArgs
		scriptDataInputArgs
		Perm ConstUint32 `json:"perm"`
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	path, err := requireScriptPath(args.scriptPathArgs)
	if err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = args.Mode
	}
	if perm == 0 {
		perm = 0o666
	}
	return scriptGoResult(map[string]any{"name": path, "bytes_written": len(data), "checksum64": checksum64(data), "perm": uint32(perm)}, stdos.WriteFile(path, data, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSFileChdir(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	fd, handle, err := e.resolveScriptFD(args)
	if err != nil {
		return nil, err
	}
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd}, unix.Fchdir(fd))
}

func (e *scriptEnv) scriptOSFileChmod(value goja.Value) (any, error) {
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
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "mode": uint32(args.Mode)}, unix.Fchmod(fd, uint32(args.Mode)))
}

func (e *scriptEnv) scriptOSFileChown(value goja.Value) (any, error) {
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
	return scriptSyscallResult(map[string]any{"handle": handle, "fd": fd, "uid": args.UID, "gid": args.GID}, unix.Fchown(fd, args.UID, args.GID))
}

func (e *scriptEnv) scriptOSFileClose(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	return e.closeManagedFD(args)
}

func (e *scriptEnv) scriptOSFileFd(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, fd, handle, err := e.resolveFDInfo(args)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"ok": true, "handle": handle, "fd": fd}
	if entry != nil {
		fields["name"] = entry.Path
		fields["kind"] = entry.Kind
	}
	return fields, nil
}

func (e *scriptEnv) scriptOSFileName(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, fd, handle, err := e.resolveFDInfo(args)
	if err != nil {
		return nil, err
	}
	name := handle
	if entry != nil && entry.Path != "" {
		name = entry.Path
	}
	return map[string]any{"ok": true, "handle": handle, "fd": fd, "name": name}, nil
}

func (e *scriptEnv) scriptOSFileRead(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Length   Uint64 `json:"length"`
		Encoding string `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileRead")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	buf := make([]byte, int(args.Length))
	n, readErr := file.Read(buf)
	fields := map[string]any{"handle": handle, "fd": fd, "bytes_read": n}
	if n > 0 || readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSFileReadAt(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Offset   Uint64 `json:"offset"`
		Length   Uint64 `json:"length"`
		Encoding string `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileReadAt")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	buf := make([]byte, int(args.Length))
	n, readErr := file.ReadAt(buf, offset)
	fields := map[string]any{"handle": handle, "fd": fd, "offset": offset, "bytes_read": n}
	if n > 0 || readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSFileReadDir(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		N int `json:"n"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileReadDir")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	entries, readErr := file.ReadDir(args.N)
	fields := map[string]any{"handle": handle, "fd": fd}
	if readErr == nil || len(entries) > 0 {
		fields["entries"] = dirEntryList(entries)
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSFileReaddir(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		N int `json:"n"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileReaddir")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	infos, readErr := file.Readdir(args.N)
	fields := map[string]any{"handle": handle, "fd": fd}
	if readErr == nil || len(infos) > 0 {
		fields["infos"] = fileInfoList(infos)
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSFileReaddirnames(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		N int `json:"n"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileReaddirnames")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	names, readErr := file.Readdirnames(args.N)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "names": names}, readErr)
}

func (e *scriptEnv) scriptOSFileReadFrom(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Src scriptIOEndpoint `json:"src"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileReadFrom")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	src, cleanupSrc, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanupSrc()
	n, copyErr := file.ReadFrom(src)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "bytes_written": n}, copyErr)
}

func (e *scriptEnv) scriptOSFileSeek(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Offset Uint64      `json:"offset"`
		Whence ConstUint64 `json:"whence"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileSeek")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	newOffset, seekErr := file.Seek(offset, int(args.Whence))
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "offset": newOffset}, seekErr)
}

func (e *scriptEnv) scriptOSFileSetDeadline(value goja.Value) (any, error) {
	return e.scriptOSFileDeadline(value, "deadline")
}

func (e *scriptEnv) scriptOSFileSetReadDeadline(value goja.Value) (any, error) {
	return e.scriptOSFileDeadline(value, "read_deadline")
}

func (e *scriptEnv) scriptOSFileSetWriteDeadline(value goja.Value) (any, error) {
	return e.scriptOSFileDeadline(value, "write_deadline")
}

func (e *scriptEnv) scriptOSFileDeadline(value goja.Value, kind string) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Time         string `json:"time"`
		Unix         *int64 `json:"unix"`
		UnixNano     *int64 `json:"unix_nano"`
		Deadline     string `json:"deadline"`
		DeadlineUnix *int64 `json:"deadline_unix"`
		DeadlineNano *int64 `json:"deadline_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	text := args.Time
	unixSeconds := args.Unix
	unixNano := args.UnixNano
	if text == "" && args.Deadline != "" {
		text = args.Deadline
	}
	if unixSeconds == nil && args.DeadlineUnix != nil {
		unixSeconds = args.DeadlineUnix
	}
	if unixNano == nil && args.DeadlineNano != nil {
		unixNano = args.DeadlineNano
	}
	deadline, err := parseOptionalDeadline(text, unixSeconds, unixNano, "deadline")
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileDeadline")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	switch kind {
	case "read_deadline":
		err = file.SetReadDeadline(deadline)
	case "write_deadline":
		err = file.SetWriteDeadline(deadline)
	default:
		err = file.SetDeadline(deadline)
	}
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "deadline": deadline.Format(time.RFC3339Nano)}, err)
}

func (e *scriptEnv) scriptOSFileStat(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args, "fileStat")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	info, statErr := file.Stat()
	fields := map[string]any{"handle": handle, "fd": fd}
	if statErr == nil {
		fields["info"] = fileInfoMap(info)
	}
	return scriptGoResult(fields, statErr)
}

func (e *scriptEnv) scriptOSFileSync(value goja.Value) (any, error) {
	var args ScriptFDRefArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args, "fileSync")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd}, file.Sync())
}

func (e *scriptEnv) scriptOSFileTruncate(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Size Uint64 `json:"size"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	size, err := checkedInt64("size", args.Size)
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileTruncate")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "size": size}, file.Truncate(size))
}

func (e *scriptEnv) scriptOSFileWrite(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		scriptDataInputArgs
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileWrite")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	n, writeErr := file.Write(data)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

func (e *scriptEnv) scriptOSFileWriteAt(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		scriptDataInputArgs
		Offset Uint64 `json:"offset"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileWriteAt")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	n, writeErr := file.WriteAt(data, offset)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "offset": offset, "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

func (e *scriptEnv) scriptOSFileWriteString(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Data string `json:"data"`
		Text string `json:"text"`
		S    string `json:"s"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	text := args.Data
	if text == "" {
		text = args.Text
	}
	if text == "" {
		text = args.S
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileWriteString")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	n, writeErr := file.WriteString(text)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "bytes_requested": len(text), "bytes_written": n, "checksum64": checksum64([]byte(text))}, writeErr)
}

func (e *scriptEnv) scriptOSFileWriteTo(value goja.Value) (any, error) {
	var args struct {
		ScriptFDRefArgs
		Dst scriptIOEndpoint `json:"dst"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	file, fd, handle, cleanup, err := e.dupFile(args.ScriptFDRefArgs, "fileWriteTo")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	dst, cleanupDst, err := e.writerFromEndpoint(args.Dst)
	if err != nil {
		return nil, err
	}
	defer cleanupDst()
	n, copyErr := file.WriteTo(dst)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "bytes_written": n}, copyErr)
}

type scriptRootArgs struct {
	Root string `json:"root"`
}

func (e *scriptEnv) scriptOSRootChmod(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string      `json:"name"`
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "mode": uint32(args.Mode)}, root.Root.Chmod(args.Name, fs.FileMode(args.Mode)))
}

func (e *scriptEnv) scriptOSRootChown(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
		UID  int    `json:"uid"`
		GID  int    `json:"gid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "uid": args.UID, "gid": args.GID}, root.Root.Chown(args.Name, args.UID, args.GID))
}

func (e *scriptEnv) scriptOSRootChtimes(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name          string `json:"name"`
		ATime         string `json:"atime"`
		MTime         string `json:"mtime"`
		ATimeUnix     *int64 `json:"atime_unix"`
		MTimeUnix     *int64 `json:"mtime_unix"`
		ATimeUnixNano *int64 `json:"atime_unix_nano"`
		MTimeUnixNano *int64 `json:"mtime_unix_nano"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	atime, err := parseScriptTime(args.ATime, args.ATimeUnix, args.ATimeUnixNano, "atime")
	if err != nil {
		return nil, err
	}
	mtime, err := parseScriptTime(args.MTime, args.MTimeUnix, args.MTimeUnixNano, "mtime")
	if err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name}, root.Root.Chtimes(args.Name, atime, mtime))
}

func (e *scriptEnv) scriptOSRootClose(value goja.Value) (any, error) {
	var args scriptRootArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	e.app.mu.Lock()
	entry, ok := e.app.roots[args.Root]
	if ok {
		delete(e.app.roots, args.Root)
	}
	e.app.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("root handle %q not found", args.Root)
	}
	return scriptGoResult(map[string]any{"root": entry.Handle, "name": entry.Name, "closed": true}, entry.Root.Close())
}

func (e *scriptEnv) scriptOSRootCreate(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name   string `json:"name"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	file, createErr := root.Root.Create(args.Name)
	return e.registerStdOSFile(file, "os.File", args.Name, args.Handle, map[string]any{"package": "os", "root": root.Handle}, map[string]any{"root": root.Handle, "name": args.Name}, createErr)
}

func (e *scriptEnv) scriptOSRootLchown(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
		UID  int    `json:"uid"`
		GID  int    `json:"gid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "uid": args.UID, "gid": args.GID}, root.Root.Lchown(args.Name, args.UID, args.GID))
}

func (e *scriptEnv) scriptOSRootLink(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		OldName string `json:"oldname"`
		NewName string `json:"newname"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "oldname": args.OldName, "newname": args.NewName}, root.Root.Link(args.OldName, args.NewName))
}

func (e *scriptEnv) scriptOSRootLstat(value goja.Value) (any, error) {
	return e.scriptRootStatLike(value, true)
}

func (e *scriptEnv) scriptOSRootMkdir(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string      `json:"name"`
		Perm ConstUint32 `json:"perm"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = 0o777
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "perm": uint32(perm)}, root.Root.Mkdir(args.Name, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSRootMkdirAll(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string      `json:"name"`
		Perm ConstUint32 `json:"perm"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = 0o777
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "perm": uint32(perm)}, root.Root.MkdirAll(args.Name, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSRootName(value goja.Value) (any, error) {
	var args scriptRootArgs
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "root": root.Handle, "name": root.Root.Name()}, nil
}

func (e *scriptEnv) scriptOSRootOpen(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name   string `json:"name"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	file, openErr := root.Root.Open(args.Name)
	return e.registerStdOSFile(file, "os.File", args.Name, args.Handle, map[string]any{"package": "os", "root": root.Handle}, map[string]any{"root": root.Handle, "name": args.Name}, openErr)
}

func (e *scriptEnv) scriptOSRootOpenFile(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name   string      `json:"name"`
		Flag   ConstUint64 `json:"flag"`
		Flags  ConstUint64 `json:"flags"`
		Perm   ConstUint32 `json:"perm"`
		Mode   ConstUint32 `json:"mode"`
		Handle string      `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	flag := int(args.Flag)
	if flag == 0 && args.Flags != 0 {
		flag = int(args.Flags)
	}
	perm := args.Perm
	if perm == 0 {
		perm = args.Mode
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	file, openErr := root.Root.OpenFile(args.Name, flag, fs.FileMode(perm))
	return e.registerStdOSFile(file, "os.File", args.Name, args.Handle, map[string]any{"package": "os", "root": root.Handle, "flag": flag}, map[string]any{"root": root.Handle, "name": args.Name, "flag": flag, "perm": uint32(perm)}, openErr)
}

func (e *scriptEnv) scriptOSRootOpenRoot(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name   string `json:"name"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	child, openErr := root.Root.OpenRoot(args.Name)
	return e.registerRoot(child, args.Handle, map[string]any{"parent": root.Handle, "name": args.Name}, openErr)
}

func (e *scriptEnv) scriptOSRootReadFile(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name     string `json:"name"`
		Encoding string `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	data, readErr := root.Root.ReadFile(args.Name)
	if uint64(len(data)) > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("read result %d exceeds max_read_bytes %d", len(data), e.app.config.MaxReadBytes)
	}
	fields := map[string]any{"root": root.Handle, "name": args.Name, "bytes_read": len(data)}
	if readErr == nil {
		encoded, err := encodeBytes(data, args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptOSRootReadlink(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	target, readErr := root.Root.Readlink(args.Name)
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "target": target}, readErr)
}

func (e *scriptEnv) scriptOSRootRemove(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name}, root.Root.Remove(args.Name))
}

func (e *scriptEnv) scriptOSRootRemoveAll(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name}, root.Root.RemoveAll(args.Name))
}

func (e *scriptEnv) scriptOSRootRename(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		OldName string `json:"oldname"`
		NewName string `json:"newname"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "oldname": args.OldName, "newname": args.NewName}, root.Root.Rename(args.OldName, args.NewName))
}

func (e *scriptEnv) scriptOSRootStat(value goja.Value) (any, error) {
	return e.scriptRootStatLike(value, false)
}

func (e *scriptEnv) scriptRootStatLike(value goja.Value, nofollow bool) (any, error) {
	var args struct {
		scriptRootArgs
		Name string `json:"name"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	var info fs.FileInfo
	var statErr error
	if nofollow {
		info, statErr = root.Root.Lstat(args.Name)
	} else {
		info, statErr = root.Root.Stat(args.Name)
	}
	fields := map[string]any{"root": root.Handle, "name": args.Name, "nofollow": nofollow}
	if statErr == nil {
		fields["info"] = fileInfoMap(info)
	}
	return scriptGoResult(fields, statErr)
}

func (e *scriptEnv) scriptOSRootSymlink(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		OldName string `json:"oldname"`
		NewName string `json:"newname"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "oldname": args.OldName, "newname": args.NewName}, root.Root.Symlink(args.OldName, args.NewName))
}

func (e *scriptEnv) scriptOSRootWriteFile(value goja.Value) (any, error) {
	var args struct {
		scriptRootArgs
		scriptDataInputArgs
		Name string      `json:"name"`
		Perm ConstUint32 `json:"perm"`
		Mode ConstUint32 `json:"mode"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	root, err := e.resolveRoot(args.Root)
	if err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	perm := args.Perm
	if perm == 0 {
		perm = args.Mode
	}
	if perm == 0 {
		perm = 0o666
	}
	return scriptGoResult(map[string]any{"root": root.Handle, "name": args.Name, "bytes_written": len(data), "checksum64": checksum64(data), "perm": uint32(perm)}, root.Root.WriteFile(args.Name, data, fs.FileMode(perm)))
}

func (e *scriptEnv) scriptOSFindProcess(value goja.Value) (any, error) {
	var args struct {
		PID    int    `json:"pid"`
		Handle string `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	process, err := stdos.FindProcess(args.PID)
	return e.registerProcess(process, args.Handle, map[string]any{"pid": args.PID}, err)
}

func (e *scriptEnv) scriptOSStartProcess(value goja.Value) (any, error) {
	var args struct {
		Name   string            `json:"name"`
		Argv   []string          `json:"argv"`
		Dir    string            `json:"dir"`
		Env    []string          `json:"env"`
		Files  []ScriptFDRefArgs `json:"files"`
		Handle string            `json:"handle"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Name == "" {
		return nil, errors.New("name is required")
	}
	argv := args.Argv
	if len(argv) == 0 {
		argv = []string{args.Name}
	}
	files := make([]*stdos.File, 0, len(args.Files))
	for i, ref := range args.Files {
		file, _, _, cleanup, err := e.dupFile(ref, fmt.Sprintf("startProcessFile%d", i))
		if err != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return nil, err
		}
		files = append(files, file)
		defer cleanup()
	}
	attr := &stdos.ProcAttr{Dir: args.Dir, Env: args.Env, Files: files}
	process, err := stdos.StartProcess(args.Name, argv, attr)
	return e.registerProcess(process, args.Handle, map[string]any{"name": args.Name, "argv": argv}, err)
}

func (e *scriptEnv) scriptOSProcessKill(value goja.Value) (any, error) {
	var args struct {
		Handle string `json:"handle"`
		PID    *int   `json:"pid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveProcess(args.Handle, args.PID)
	if err != nil {
		return nil, err
	}
	return scriptGoResult(map[string]any{"handle": entry.Handle, "pid": entry.Pid}, entry.Process.Kill())
}

func (e *scriptEnv) scriptOSProcessRelease(value goja.Value) (any, error) {
	var args struct {
		Handle string `json:"handle"`
		PID    *int   `json:"pid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveProcess(args.Handle, args.PID)
	if err != nil {
		return nil, err
	}
	releaseErr := entry.Process.Release()
	if releaseErr == nil && entry.Handle != "" {
		e.app.mu.Lock()
		delete(e.app.processes, entry.Handle)
		e.app.mu.Unlock()
	}
	return scriptGoResult(map[string]any{"handle": entry.Handle, "pid": entry.Pid}, releaseErr)
}

func (e *scriptEnv) scriptOSProcessSignal(value goja.Value) (any, error) {
	var args struct {
		Handle string      `json:"handle"`
		PID    *int        `json:"pid"`
		Signal ConstUint64 `json:"signal"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveProcess(args.Handle, args.PID)
	if err != nil {
		return nil, err
	}
	sig := parseSignal(args.Signal)
	return scriptGoResult(map[string]any{"handle": entry.Handle, "pid": entry.Pid, "signal": sig.String()}, entry.Process.Signal(sig))
}

func (e *scriptEnv) scriptOSProcessWait(value goja.Value) (any, error) {
	var args struct {
		Handle string `json:"handle"`
		PID    *int   `json:"pid"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	entry, err := e.resolveProcess(args.Handle, args.PID)
	if err != nil {
		return nil, err
	}
	state, waitErr := entry.Process.Wait()
	fields := map[string]any{"handle": entry.Handle, "pid": entry.Pid}
	if state != nil {
		fields["state"] = map[string]any{"pid": state.Pid(), "exited": state.Exited(), "success": state.Success(), "user_time_ms": state.UserTime().Milliseconds(), "system_time_ms": state.SystemTime().Milliseconds(), "string": state.String()}
	}
	if waitErr == nil && entry.Handle != "" {
		e.app.mu.Lock()
		delete(e.app.processes, entry.Handle)
		e.app.mu.Unlock()
	}
	return scriptGoResult(fields, waitErr)
}

type scriptIOEndpoint struct {
	Handle       string `json:"handle"`
	Conn         string `json:"conn"`
	FD           *int   `json:"fd"`
	Path         string `json:"path"`
	Name         string `json:"name"`
	Buffer       string `json:"buffer"`
	BufferOffset Uint64 `json:"buffer_offset"`
	Length       Uint64 `json:"length"`
	DataBase64   string `json:"data_base64"`
	DataHex      string `json:"data_hex"`
	DataUTF8     string `json:"data_utf8"`
	Discard      bool   `json:"discard"`
	Append       bool   `json:"append"`
}

type managedBufferWriter struct {
	app    *App
	name   string
	offset uint64
}

func (w *managedBufferWriter) Write(data []byte) (int, error) {
	w.app.mu.Lock()
	defer w.app.mu.Unlock()
	buffer, err := w.app.bufferLocked(w.name)
	if err != nil {
		return 0, err
	}
	target, err := sliceRange(buffer.Data, w.offset, uint64(len(data)), false)
	if err != nil {
		return 0, err
	}
	copy(target, data)
	w.offset += uint64(len(data))
	return len(data), nil
}

func endpointFDRef(endpoint scriptIOEndpoint) ScriptFDRefArgs {
	return ScriptFDRefArgs{Handle: endpoint.Handle, FD: endpoint.FD}
}

func endpointDataSources(endpoint scriptIOEndpoint) int {
	sources := 0
	if endpoint.Handle != "" || endpoint.FD != nil {
		sources++
	}
	if endpoint.Conn != "" {
		sources++
	}
	if endpoint.Path != "" || endpoint.Name != "" {
		sources++
	}
	if endpoint.Buffer != "" {
		sources++
	}
	if endpoint.DataBase64 != "" {
		sources++
	}
	if endpoint.DataHex != "" {
		sources++
	}
	if endpoint.DataUTF8 != "" {
		sources++
	}
	if endpoint.Discard {
		sources++
	}
	return sources
}

func (e *scriptEnv) readerFromEndpoint(endpoint scriptIOEndpoint) (stdio.Reader, func(), error) {
	if endpointDataSources(endpoint) == 0 {
		return nil, nil, errors.New("reader endpoint is required")
	}
	if endpointDataSources(endpoint) > 1 {
		return nil, nil, errors.New("provide only one reader endpoint source")
	}
	if endpoint.Handle != "" || endpoint.FD != nil {
		file, _, _, cleanup, err := e.dupFile(endpointFDRef(endpoint), "ioReader")
		if err != nil {
			return nil, nil, err
		}
		return file, cleanup, nil
	}
	if endpoint.Conn != "" {
		return netReaderFromConn(e, endpoint.Conn)
	}
	if endpoint.Path != "" || endpoint.Name != "" {
		path := endpoint.Path
		if path == "" {
			path = endpoint.Name
		}
		file, err := stdos.Open(path)
		if err != nil {
			return nil, nil, err
		}
		return file, func() { _ = file.Close() }, nil
	}
	if endpoint.Buffer != "" {
		e.app.mu.Lock()
		buffer, err := e.app.bufferLocked(endpoint.Buffer)
		if err != nil {
			e.app.mu.Unlock()
			return nil, nil, err
		}
		data, err := sliceRange(buffer.Data, uint64(endpoint.BufferOffset), uint64(endpoint.Length), true)
		if err != nil {
			e.app.mu.Unlock()
			return nil, nil, err
		}
		copyData := append([]byte(nil), data...)
		e.app.mu.Unlock()
		return bytes.NewReader(copyData), func() {}, nil
	}
	data, err := decodeDirectData(endpoint.DataBase64, endpoint.DataHex, endpoint.DataUTF8, nil)
	if err != nil {
		return nil, nil, err
	}
	return bytes.NewReader(data), func() {}, nil
}

func (e *scriptEnv) writerFromEndpoint(endpoint scriptIOEndpoint) (stdio.Writer, func(), error) {
	if endpoint.Discard {
		if endpointDataSources(endpoint) != 1 {
			return nil, nil, errors.New("discard writer cannot be combined with another writer endpoint")
		}
		return stdio.Discard, func() {}, nil
	}
	if endpointDataSources(endpoint) == 0 {
		return nil, nil, errors.New("writer endpoint is required")
	}
	if endpointDataSources(endpoint) > 1 {
		return nil, nil, errors.New("provide only one writer endpoint source")
	}
	if endpoint.Handle != "" || endpoint.FD != nil {
		file, _, _, cleanup, err := e.dupFile(endpointFDRef(endpoint), "ioWriter")
		if err != nil {
			return nil, nil, err
		}
		return file, cleanup, nil
	}
	if endpoint.Conn != "" {
		return netWriterFromConn(e, endpoint.Conn)
	}
	if endpoint.Path != "" || endpoint.Name != "" {
		path := endpoint.Path
		if path == "" {
			path = endpoint.Name
		}
		flag := stdos.O_WRONLY | stdos.O_CREATE
		if endpoint.Append {
			flag |= stdos.O_APPEND
		} else {
			flag |= stdos.O_TRUNC
		}
		file, err := stdos.OpenFile(path, flag, 0o666)
		if err != nil {
			return nil, nil, err
		}
		return file, func() { _ = file.Close() }, nil
	}
	if endpoint.Buffer != "" {
		return &managedBufferWriter{app: e.app, name: endpoint.Buffer, offset: uint64(endpoint.BufferOffset)}, func() {}, nil
	}
	return nil, nil, errors.New("unsupported writer endpoint")
}

type scriptIOCopyArgs struct {
	Dst       scriptIOEndpoint
	Src       scriptIOEndpoint
	DstHandle string
	SrcHandle string
	N         Uint64
	Buffer    string
}

func copyArgsFromValue(value goja.Value) (scriptIOCopyArgs, error) {
	var args struct {
		Dst       scriptIOEndpoint `json:"dst"`
		Src       scriptIOEndpoint `json:"src"`
		DstHandle string           `json:"dst_handle"`
		SrcHandle string           `json:"src_handle"`
		N         Uint64           `json:"n"`
		Buffer    string           `json:"buffer"`
	}
	err := decodeScriptArgs(value, &args)
	return scriptIOCopyArgs{Dst: args.Dst, Src: args.Src, DstHandle: args.DstHandle, SrcHandle: args.SrcHandle, N: args.N, Buffer: args.Buffer}, err
}

func normalizeCopyEndpoints(dst, src scriptIOEndpoint, dstHandle, srcHandle string) (scriptIOEndpoint, scriptIOEndpoint) {
	if dst.Handle == "" && dst.FD == nil && dstHandle != "" {
		dst.Handle = dstHandle
	}
	if src.Handle == "" && src.FD == nil && srcHandle != "" {
		src.Handle = srcHandle
	}
	return dst, src
}

func (e *scriptEnv) scriptIOCopy(value goja.Value) (any, error) {
	args, err := copyArgsFromValue(value)
	if err != nil {
		return nil, err
	}
	dstEndpoint, srcEndpoint := normalizeCopyEndpoints(args.Dst, args.Src, args.DstHandle, args.SrcHandle)
	dst, cleanupDst, err := e.writerFromEndpoint(dstEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupDst()
	src, cleanupSrc, err := e.readerFromEndpoint(srcEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupSrc()
	n, copyErr := stdio.Copy(dst, src)
	return scriptGoResult(map[string]any{"written": n, "bytes_written": n}, copyErr)
}

func (e *scriptEnv) scriptIOCopyBuffer(value goja.Value) (any, error) {
	args, err := copyArgsFromValue(value)
	if err != nil {
		return nil, err
	}
	if args.Buffer == "" {
		return nil, errors.New("buffer is required")
	}
	dstEndpoint, srcEndpoint := normalizeCopyEndpoints(args.Dst, args.Src, args.DstHandle, args.SrcHandle)
	dst, cleanupDst, err := e.writerFromEndpoint(dstEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupDst()
	src, cleanupSrc, err := e.readerFromEndpoint(srcEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupSrc()
	e.app.mu.Lock()
	buffer, err := e.app.bufferLocked(args.Buffer)
	if err != nil {
		e.app.mu.Unlock()
		return nil, err
	}
	scratch := append([]byte(nil), buffer.Data...)
	e.app.mu.Unlock()
	n, copyErr := stdio.CopyBuffer(dst, src, scratch)
	return scriptGoResult(map[string]any{"written": n, "bytes_written": n, "buffer": args.Buffer}, copyErr)
}

func (e *scriptEnv) scriptIOCopyN(value goja.Value) (any, error) {
	args, err := copyArgsFromValue(value)
	if err != nil {
		return nil, err
	}
	dstEndpoint, srcEndpoint := normalizeCopyEndpoints(args.Dst, args.Src, args.DstHandle, args.SrcHandle)
	dst, cleanupDst, err := e.writerFromEndpoint(dstEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupDst()
	src, cleanupSrc, err := e.readerFromEndpoint(srcEndpoint)
	if err != nil {
		return nil, err
	}
	defer cleanupSrc()
	nValue, err := checkedInt64("n", args.N)
	if err != nil {
		return nil, err
	}
	n, copyErr := stdio.CopyN(dst, src, nValue)
	return scriptGoResult(map[string]any{"written": n, "bytes_written": n, "n": nValue}, copyErr)
}

func (e *scriptEnv) scriptIOReadAll(value goja.Value) (any, error) {
	var args struct {
		Src      scriptIOEndpoint `json:"src"`
		Encoding string           `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	src, cleanup, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return e.boundedReadAll(src, args.Encoding)
}

func (e *scriptEnv) scriptIOReadAtLeast(value goja.Value) (any, error) {
	return e.scriptIOReadMinimum(value, false)
}

func (e *scriptEnv) scriptIOReadFull(value goja.Value) (any, error) {
	return e.scriptIOReadMinimum(value, true)
}

func (e *scriptEnv) scriptIOReadMinimum(value goja.Value, full bool) (any, error) {
	var args struct {
		Src      scriptIOEndpoint `json:"src"`
		Length   Uint64           `json:"length"`
		Min      Uint64           `json:"min"`
		Encoding string           `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	if args.Length > Uint64(e.app.config.MaxReadBytes) {
		return nil, fmt.Errorf("length %d exceeds max_read_bytes %d", args.Length, e.app.config.MaxReadBytes)
	}
	src, cleanup, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	buf := make([]byte, int(args.Length))
	var n int
	var readErr error
	if full {
		n, readErr = stdio.ReadFull(src, buf)
	} else {
		minValue := int(args.Min)
		if minValue == 0 {
			return nil, errors.New("min is required")
		}
		n, readErr = stdio.ReadAtLeast(src, buf, minValue)
	}
	fields := map[string]any{"bytes_read": n}
	if n > 0 || readErr == nil {
		encoded, err := encodeBytes(buf[:n], args.Encoding)
		if err != nil {
			return nil, err
		}
		for key, value := range encoded {
			fields[key] = value
		}
	}
	return scriptGoResult(fields, readErr)
}

func (e *scriptEnv) scriptIOWriteString(value goja.Value) (any, error) {
	var args struct {
		Dst  scriptIOEndpoint `json:"dst"`
		Data string           `json:"data"`
		Text string           `json:"text"`
		S    string           `json:"s"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	text := args.Data
	if text == "" {
		text = args.Text
	}
	if text == "" {
		text = args.S
	}
	dst, cleanup, err := e.writerFromEndpoint(args.Dst)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	n, writeErr := stdio.WriteString(dst, text)
	return scriptGoResult(map[string]any{"bytes_requested": len(text), "bytes_written": n, "checksum64": checksum64([]byte(text))}, writeErr)
}

func (e *scriptEnv) scriptIOLimitReader(value goja.Value) (any, error) {
	var args struct {
		Src      scriptIOEndpoint `json:"src"`
		N        Uint64           `json:"n"`
		Encoding string           `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	src, cleanup, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	n, err := checkedInt64("n", args.N)
	if err != nil {
		return nil, err
	}
	return e.boundedReadAll(stdio.LimitReader(src, n), args.Encoding)
}

func (e *scriptEnv) scriptIOMultiReader(value goja.Value) (any, error) {
	var args struct {
		Readers  []scriptIOEndpoint `json:"readers"`
		Encoding string             `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	readers := make([]stdio.Reader, 0, len(args.Readers))
	cleanups := make([]func(), 0, len(args.Readers))
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()
	for _, endpoint := range args.Readers {
		reader, cleanup, err := e.readerFromEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		readers = append(readers, reader)
		cleanups = append(cleanups, cleanup)
	}
	return e.boundedReadAll(stdio.MultiReader(readers...), args.Encoding)
}

func (e *scriptEnv) scriptIOTeeReader(value goja.Value) (any, error) {
	var args struct {
		Src      scriptIOEndpoint `json:"src"`
		Dst      scriptIOEndpoint `json:"dst"`
		Encoding string           `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	src, cleanupSrc, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanupSrc()
	dst, cleanupDst, err := e.writerFromEndpoint(args.Dst)
	if err != nil {
		return nil, err
	}
	defer cleanupDst()
	return e.boundedReadAll(stdio.TeeReader(src, dst), args.Encoding)
}

func (e *scriptEnv) scriptIOMultiWriter(value goja.Value) (any, error) {
	var args struct {
		Writers []scriptIOEndpoint `json:"writers"`
		scriptDataInputArgs
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	writers := make([]stdio.Writer, 0, len(args.Writers))
	cleanups := make([]func(), 0, len(args.Writers))
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()
	for _, endpoint := range args.Writers {
		writer, cleanup, err := e.writerFromEndpoint(endpoint)
		if err != nil {
			return nil, err
		}
		writers = append(writers, writer)
		cleanups = append(cleanups, cleanup)
	}
	n, writeErr := stdio.MultiWriter(writers...).Write(data)
	return scriptGoResult(map[string]any{"bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

func (e *scriptEnv) scriptIONewSectionReader(value goja.Value) (any, error) {
	var args struct {
		Src      scriptIOEndpoint `json:"src"`
		Offset   Uint64           `json:"offset"`
		N        Uint64           `json:"n"`
		Encoding string           `json:"encoding"`
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	src, cleanup, err := e.readerFromEndpoint(args.Src)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	data, err := stdio.ReadAll(stdio.LimitReader(src, int64(e.app.config.MaxReadBytes)+1))
	if err != nil {
		return scriptGoResult(nil, err)
	}
	if uint64(len(data)) > e.app.config.MaxReadBytes {
		return nil, fmt.Errorf("read result %d exceeds max_read_bytes %d", len(data), e.app.config.MaxReadBytes)
	}
	offset, err := checkedInt64("offset", args.Offset)
	if err != nil {
		return nil, err
	}
	n, err := checkedInt64("n", args.N)
	if err != nil {
		return nil, err
	}
	reader := stdio.NewSectionReader(bytes.NewReader(data), offset, n)
	return e.boundedReadAll(reader, args.Encoding)
}

func (e *scriptEnv) scriptIONewOffsetWriter(value goja.Value) (any, error) {
	var args struct {
		Dst scriptIOEndpoint `json:"dst"`
		Off Uint64           `json:"off"`
		scriptDataInputArgs
	}
	if err := decodeScriptArgs(value, &args); err != nil {
		return nil, err
	}
	data, err := e.scriptInputBytes(args.scriptDataInputArgs)
	if err != nil {
		return nil, err
	}
	if args.Dst.Handle == "" && args.Dst.FD == nil {
		return nil, errors.New("newOffsetWriter currently requires a file descriptor writer endpoint")
	}
	file, fd, handle, cleanup, err := e.dupFile(endpointFDRef(args.Dst), "offsetWriter")
	if err != nil {
		return nil, err
	}
	defer cleanup()
	off, err := checkedInt64("off", args.Off)
	if err != nil {
		return nil, err
	}
	writer := stdio.NewOffsetWriter(file, off)
	n, writeErr := writer.Write(data)
	return scriptGoResult(map[string]any{"handle": handle, "fd": fd, "off": off, "bytes_requested": len(data), "bytes_written": n, "checksum64": checksum64(data)}, writeErr)
}

func (e *scriptEnv) scriptIOPipe(value goja.Value) (any, error) {
	return e.scriptOSPipe(value)
}

func rootInfosLocked(roots map[string]*rootEntry) []rootEntry {
	infos := make([]rootEntry, 0, len(roots))
	for _, entry := range roots {
		infos = append(infos, rootEntry{Handle: entry.Handle, Name: entry.Name})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Handle < infos[j].Handle })
	return infos
}

func processInfosLocked(processes map[string]*processEntry) []processEntry {
	infos := make([]processEntry, 0, len(processes))
	for _, entry := range processes {
		infos = append(infos, processEntry{Handle: entry.Handle, Pid: entry.Pid})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Handle < infos[j].Handle })
	return infos
}
