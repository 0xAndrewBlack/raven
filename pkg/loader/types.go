package loader

import "github.com/mirkobrombin/Raven/pkg/arch"

const (
	DefaultStackSize = 64 * 1024 * 1024   // 64 MiB
	StackTop         = uint64(0x700000000000)  // top of guest stack
)

// LoadResult holds the state produced by loading an executable.
type LoadResult struct {
	EntryPoint uint64
	StackPtr   uint64
	BrkAddr    uint64
	TLSAddr    uint64    // Thread-Local Storage base (0 if none)
	Arch       arch.Arch // detected architecture
}
