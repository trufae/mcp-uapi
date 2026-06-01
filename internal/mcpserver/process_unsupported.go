//go:build !linux

package mcpserver

import "golang.org/x/sys/unix"

func platformPtraceAttach(pid int) error { return unix.PtraceAttach(pid) }

func platformPtraceDetach(pid int) error { return unix.PtraceDetach(pid) }

func platformPtracePeekData(pid int, addr uintptr, out []byte) (int, error) {
	return 0, unix.ENOSYS
}

func platformPtracePokeData(pid int, addr uintptr, data []byte) (int, error) {
	return 0, unix.ENOSYS
}

func platformPtraceCont(pid int, signal int) error { return unix.ENOSYS }

func platformPtraceSyscall(pid int, signal int) error { return unix.ENOSYS }

func platformPtraceGetRegs(pid int) (any, error) { return nil, unix.ENOSYS }

func platformPtraceSetOptions(pid int, options int) error { return unix.ENOSYS }

func platformPrctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	return unix.ENOSYS
}

func platformPrctlRetInt(option int, arg2, arg3, arg4, arg5 uintptr) (int, error) {
	return 0, unix.ENOSYS
}
