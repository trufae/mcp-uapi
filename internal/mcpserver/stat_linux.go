//go:build linux

package mcpserver

import "golang.org/x/sys/unix"

func platformStatfsInfo(st unix.Statfs_t) map[string]any {
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

func platformStatxBasicStats() int {
	return unix.STATX_BASIC_STATS
}

func platformStatxInfo(dirfd int, path string, flags int, mask int) (map[string]any, error) {
	var st unix.Statx_t
	if err := unix.Statx(dirfd, path, flags, mask, &st); err != nil {
		return nil, err
	}
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
	}, nil
}

func statxTimestampInfo(ts unix.StatxTimestamp) map[string]any {
	return map[string]any{"sec": ts.Sec, "nsec": ts.Nsec}
}
