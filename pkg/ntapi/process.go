//go:build guest_windows

package ntapi

import (
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// ProcessManager handles NtAllocateVirtualMemory, NtProtectVirtualMemory,
// and other process/thread related operations that need MMU access.
type ProcessManager struct {
	Mem       *mmu.MMU
	Handles   *HandleTable
	State     *ProcessState
	ProcessID uint32
	ThreadID  uint32
}

// NewProcessManager creates a process manager.
func NewProcessManager(mem *mmu.MMU, handles *HandleTable, state *ProcessState) *ProcessManager {
	return &ProcessManager{
		Mem:       mem,
		Handles:   handles,
		State:     state,
		ProcessID: 1000,
		ThreadID:  1004,
	}
}

// AllocateTEB allocates a new TEB for a child thread.
func (pm *ProcessManager) AllocateTEB(threadID uint32, stackBase, stackLimit uint64) (uint64, error) {
	tebAddr := pm.Mem.Mmap(0, TebSize, mmu.PermRead|mmu.PermWrite)

	pm.Mem.Write64(tebAddr+TebSelf, tebAddr)
	pm.Mem.Write64(tebAddr+TebPEB, pm.State.PEBAddr)
	pm.Mem.Write64(tebAddr+TebStackBase, stackBase)
	pm.Mem.Write64(tebAddr+TebStackLimit, stackLimit)
	pm.Mem.Write32(tebAddr+TebProcessId, pm.ProcessID)
	pm.Mem.Write32(tebAddr+TebThreadId, threadID)
	pm.Mem.Write64(tebAddr+TebExceptionList, 0xFFFFFFFFFFFFFFFF)

	return tebAddr, nil
}

// NtMemProtectToMMU converts Windows memory protection constants to MMU permissions.
func NtMemProtectToMMU(protect uint32) uint8 {
	var perms uint8
	switch protect {
	case 0x01: // PAGE_NOACCESS
		perms = 0
	case 0x02: // PAGE_READONLY
		perms = mmu.PermRead
	case 0x04: // PAGE_READWRITE
		perms = mmu.PermRead | mmu.PermWrite
	case 0x08: // PAGE_WRITECOPY
		perms = mmu.PermRead | mmu.PermWrite
	case 0x10: // PAGE_EXECUTE
		perms = mmu.PermExecute
	case 0x20: // PAGE_EXECUTE_READ
		perms = mmu.PermRead | mmu.PermExecute
	case 0x40: // PAGE_EXECUTE_READWRITE
		perms = mmu.PermRead | mmu.PermWrite | mmu.PermExecute
	case 0x80: // PAGE_EXECUTE_WRITECOPY
		perms = mmu.PermRead | mmu.PermWrite | mmu.PermExecute
	default:
		perms = mmu.PermRead | mmu.PermWrite
	}
	return perms
}

// MMUPermsToNtProtect converts MMU permissions to Windows memory protection.
func MMUPermsToNtProtect(perms uint8) uint32 {
	hasR := perms&mmu.PermRead != 0
	hasW := perms&mmu.PermWrite != 0
	hasX := perms&mmu.PermExecute != 0

	switch {
	case hasR && hasW && hasX:
		return 0x40 // PAGE_EXECUTE_READWRITE
	case hasR && hasX:
		return 0x20 // PAGE_EXECUTE_READ
	case hasX:
		return 0x10 // PAGE_EXECUTE
	case hasR && hasW:
		return 0x04 // PAGE_READWRITE
	case hasR:
		return 0x02 // PAGE_READONLY
	default:
		return 0x01 // PAGE_NOACCESS
	}
}
