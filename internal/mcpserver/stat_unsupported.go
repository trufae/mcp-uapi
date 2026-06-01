//go:build !linux

package mcpserver

import "golang.org/x/sys/unix"

func platformStatfsInfo(st unix.Statfs_t) map[string]any {
	return map[string]any{
		"type":       st.Type,
		"bsize":      st.Bsize,
		"iosize":     st.Iosize,
		"blocks":     st.Blocks,
		"bfree":      st.Bfree,
		"bavail":     st.Bavail,
		"files":      st.Files,
		"ffree":      st.Ffree,
		"fsid":       []int32{st.Fsid.Val[0], st.Fsid.Val[1]},
		"owner":      st.Owner,
		"fssubtype":  st.Fssubtype,
		"fstypename": unix.ByteSliceToString(st.Fstypename[:]),
		"mntonname":  unix.ByteSliceToString(st.Mntonname[:]),
		"mntfrom":    unix.ByteSliceToString(st.Mntfromname[:]),
		"flags":      st.Flags,
	}
}

func platformStatxBasicStats() int {
	return 0
}

func platformStatxInfo(dirfd int, path string, flags int, mask int) (map[string]any, error) {
	return nil, unix.ENOSYS
}
