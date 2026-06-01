//go:build linux

package mcpserver

import "golang.org/x/sys/unix"

func platformErrnoNames() map[unix.Errno]string {
	return map[unix.Errno]string{
		unix.ERFKILL:   "ERFKILL",
		unix.EHWPOISON: "EHWPOISON",
	}
}
