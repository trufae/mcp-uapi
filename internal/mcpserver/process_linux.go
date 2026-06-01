//go:build linux

package mcpserver

import "golang.org/x/sys/unix"

func platformPtraceAttach(pid int) error { return unix.PtraceAttach(pid) }

func platformPtraceDetach(pid int) error { return unix.PtraceDetach(pid) }

func platformPtracePeekData(pid int, addr uintptr, out []byte) (int, error) {
	return unix.PtracePeekData(pid, addr, out)
}

func platformPtracePokeData(pid int, addr uintptr, data []byte) (int, error) {
	return unix.PtracePokeData(pid, addr, data)
}

func platformPtraceCont(pid int, signal int) error { return unix.PtraceCont(pid, signal) }

func platformPtraceSyscall(pid int, signal int) error { return unix.PtraceSyscall(pid, signal) }

func platformPtraceGetRegs(pid int) (any, error) {
	var regs unix.PtraceRegs
	err := unix.PtraceGetRegs(pid, &regs)
	return regs, err
}

func platformPtraceSetOptions(pid int, options int) error {
	return unix.PtraceSetOptions(pid, options)
}

func platformPrctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	return unix.Prctl(option, arg2, arg3, arg4, arg5)
}

func platformPrctlRetInt(option int, arg2, arg3, arg4, arg5 uintptr) (int, error) {
	return unix.PrctlRetInt(option, arg2, arg3, arg4, arg5)
}
