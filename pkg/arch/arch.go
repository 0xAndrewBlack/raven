package arch

import "github.com/mirkobrombin/Raven/pkg/mmu"

// Arch identifies the guest architecture.
type Arch int

const (
	ArchRISCV64 Arch = iota
	ArchAMD64
	ArchI386 // PE32 (32-bit x86)
)

// ExitError signals a guest exit(2) syscall.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return "guest exit"
}

// SyscallHandler is called when the guest executes a syscall instruction.
type SyscallHandler func(CPU)

// CPU is the interface all guest CPU implementations must satisfy.
type CPU interface {
	Run() error
	Stop()
	// Resume resets the stopped state so the CPU can be Run() again.
	// Must be called after a nested Run() inside a vmcall handler to restore
	// the outer Run() loop's ability to continue executing.
	Resume()

	GetPC() uint64
	SetPC(uint64)
	GetSP() uint64
	SetSP(uint64)
	GetTLS() uint64
	SetTLS(uint64)

	// Syscall calling convention (arch-neutral).
	SyscallNum() uint64
	SyscallArgs() [6]uint64
	SetSyscallReturn(uint64)
	// SyscallReturnPC returns the address where execution resumes after the
	// current syscall (used by clone to set the child's starting PC).
	SyscallReturnPC() uint64

	GetMem() *mmu.MMU
	GetInstret() uint64
	GetArch() Arch

	// Threading support.
	CloneForThread() CPU
	SetSyscallHandler(SyscallHandler)
}
