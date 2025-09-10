package ntapi

import (
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// DllMain reason codes.
const (
	DllProcessDetach = 0
	DllProcessAttach = 1
	DllThreadAttach  = 2
	DllThreadDetach  = 3
)

// DllMainTrampoline holds the guest address of a small code region used as
// a return address when calling DllMain. The trampoline executes:
//
//	mov eax, DllMainReturnID  ; B8 DE FF 00 00
//	vmcall                    ; 0F 01 C1
//	hlt                       ; F4
type DllMainTrampoline struct {
	Addr uint64
}

// AllocTrampoline creates the DllMain return trampoline in guest memory.
func AllocTrampoline(mem *mmu.MMU) *DllMainTrampoline {
	size := uint64(16) // more than enough for the stub
	addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermExecute|mmu.PermWrite)

	// mov eax, DllMainReturnID (B8 xx xx xx xx)
	mem.Write8(addr+0, 0xB8)
	mem.Write32(addr+1, DllMainReturnID)
	// vmcall (0F 01 C1)
	mem.Write8(addr+5, 0x0F)
	mem.Write8(addr+6, 0x01)
	mem.Write8(addr+7, 0xC1)
	// hlt (F4) - safety net
	mem.Write8(addr+8, 0xF4)

	// Make the page read+execute only after writing
	mem.Mprotect(addr, size, mmu.PermRead|mmu.PermExecute)

	return &DllMainTrampoline{Addr: addr}
}

// CallDllMain invokes a DLL's entry point (DllMain) with DLL_PROCESS_ATTACH.
// It saves the CPU state, sets up the Windows x64 ABI arguments, runs the CPU
// until the trampoline fires the return sentinel, then restores the CPU state.
//
// Windows x64 ABI for DllMain:
//
//	RCX = hinstDLL (DLL base address)
//	RDX = fdwReason (DLL_PROCESS_ATTACH = 1)
//	R8  = lpvReserved (0 for dynamic loads)
func CallDllMain(cpu arch.CPU, mem *mmu.MMU, trampoline *DllMainTrampoline, dllBase, entryPoint uint64, trace bool) error {
	if entryPoint == 0 || entryPoint == dllBase {
		return nil // no entry point
	}

	rw, ok := cpu.(RegisterWriter)
	if !ok {
		return fmt.Errorf("CPU does not support RegisterWriter for DllMain calls")
	}
	rr, ok := cpu.(RegisterReader)
	if !ok {
		return fmt.Errorf("CPU does not support RegisterReader for DllMain calls")
	}

	// Save all general-purpose registers + RIP
	var savedRegs [16]uint64
	for i := 0; i < 16; i++ {
		savedRegs[i] = rr.ReadReg(i)
	}
	savedRIP := cpu.GetPC()

	// Set up Windows x64 calling convention
	rw.WriteReg(regRCX, dllBase)       // hinstDLL
	rw.WriteReg(regRDX, DllProcessAttach) // fdwReason
	rw.WriteReg(regR8, 0)              // lpvReserved

	// Simulate a CALL to entryPoint: allocate shadow space, then push return addr.
	// Windows x64 ABI: caller's RSP is 16-byte aligned, caller allocates 32-byte
	// shadow space, then CALL pushes the return address (RSP becomes aligned-8).
	sp := cpu.GetSP()
	sp &= ^uint64(0xF) // ensure 16-byte aligned before "call"
	sp -= 32            // shadow space (32 bytes for 4 register args)
	sp -= 8             // CALL pushes return address
	mem.Write64(sp, trampoline.Addr)
	cpu.SetSP(sp)

	// Set RIP to DllMain entry
	cpu.SetPC(entryPoint)

	if trace {
		fmt.Printf("[dllmain] calling entry 0x%x (base=0x%x)\n", entryPoint, dllBase)
	}

	// Run the CPU until the trampoline sentinel fires Stop()
	err := cpu.Run()
	if err != nil {
		// ExitError means the DllMain called NtTerminateProcess - that's fatal
		if _, isExit := err.(*arch.ExitError); isExit {
			return err
		}
		if trace {
			fmt.Printf("[dllmain] entry 0x%x returned with error: %v\n", entryPoint, err)
		}
	}

	// Restore CPU state
	for i := 0; i < 16; i++ {
		rw.WriteReg(i, savedRegs[i])
	}
	cpu.SetPC(savedRIP)

	if trace {
		fmt.Printf("[dllmain] entry 0x%x completed\n", entryPoint)
	}

	return nil
}
