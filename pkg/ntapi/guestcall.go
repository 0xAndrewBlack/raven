package ntapi

import (
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

const amd64ContextSize = 1232

// ContextMarshaler is implemented by CPUs that can save and restore a Windows
// x64 CONTEXT structure in guest memory.
type ContextMarshaler interface {
	SaveContext(mem *mmu.MMU, ctxAddr uint64) error
	RestoreContext(mem *mmu.MMU, ctxAddr uint64) error
}

// GuestCallFunc invokes guest code synchronously and returns the guest's RAX.
type GuestCallFunc func(addr uint64, args []uint64) (uint64, error)

func saveCPUContextToGuest(cpu arch.CPU, mem *mmu.MMU, ctxAddr uint64) error {
	if ctxAddr == 0 {
		return fmt.Errorf("nil CONTEXT address")
	}
	if cm, ok := cpu.(ContextMarshaler); ok {
		return cm.SaveContext(mem, ctxAddr)
	}
	rr, ok := cpu.(RegisterReader)
	if !ok {
		return fmt.Errorf("CPU does not support RegisterReader")
	}
	mem.Write32(ctxAddr+0x00, 0x10000B)
	mem.Write64(ctxAddr+0x78, rr.ReadReg(regRAX))
	mem.Write64(ctxAddr+0x80, rr.ReadReg(regRCX))
	mem.Write64(ctxAddr+0x88, rr.ReadReg(regRDX))
	mem.Write64(ctxAddr+0x90, rr.ReadReg(regRBX))
	mem.Write64(ctxAddr+0x98, rr.ReadReg(regRSP))
	mem.Write64(ctxAddr+0xA0, rr.ReadReg(regRBP))
	mem.Write64(ctxAddr+0xA8, rr.ReadReg(regRSI))
	mem.Write64(ctxAddr+0xB0, rr.ReadReg(regRDI))
	mem.Write64(ctxAddr+0xB8, rr.ReadReg(regR8))
	mem.Write64(ctxAddr+0xC0, rr.ReadReg(regR9))
	mem.Write64(ctxAddr+0xC8, rr.ReadReg(regR10))
	mem.Write64(ctxAddr+0xD0, rr.ReadReg(regR11))
	mem.Write64(ctxAddr+0xD8, rr.ReadReg(regR12))
	mem.Write64(ctxAddr+0xE0, rr.ReadReg(regR13))
	mem.Write64(ctxAddr+0xE8, rr.ReadReg(regR14))
	mem.Write64(ctxAddr+0xF0, rr.ReadReg(regR15))
	mem.Write64(ctxAddr+0xF8, cpu.GetPC())
	return nil
}

func restoreCPUContextFromGuest(cpu arch.CPU, mem *mmu.MMU, ctxAddr uint64) error {
	if ctxAddr == 0 {
		return fmt.Errorf("nil CONTEXT address")
	}
	if cm, ok := cpu.(ContextMarshaler); ok {
		return cm.RestoreContext(mem, ctxAddr)
	}
	rw, ok := cpu.(RegisterWriter)
	if !ok {
		return fmt.Errorf("CPU does not support RegisterWriter")
	}
	read64 := func(off uint64) uint64 {
		v, _ := mem.Read64(ctxAddr + off)
		return v
	}
	rw.WriteReg(regRAX, read64(0x78))
	rw.WriteReg(regRCX, read64(0x80))
	rw.WriteReg(regRDX, read64(0x88))
	rw.WriteReg(regRBX, read64(0x90))
	rw.WriteReg(regRSP, read64(0x98))
	rw.WriteReg(regRBP, read64(0xA0))
	rw.WriteReg(regRSI, read64(0xA8))
	rw.WriteReg(regRDI, read64(0xB0))
	rw.WriteReg(regR8, read64(0xB8))
	rw.WriteReg(regR9, read64(0xC0))
	rw.WriteReg(regR10, read64(0xC8))
	rw.WriteReg(regR11, read64(0xD0))
	rw.WriteReg(regR12, read64(0xD8))
	rw.WriteReg(regR13, read64(0xE0))
	rw.WriteReg(regR14, read64(0xE8))
	rw.WriteReg(regR15, read64(0xF0))
	cpu.SetSP(read64(0x98))
	cpu.SetPC(read64(0xF8))
	return nil
}

// CallGuestFunction performs a synchronous call into guest code using the
// existing vmcall return trampoline.
func CallGuestFunction(cpu arch.CPU, mem *mmu.MMU, trampoline *DllMainTrampoline, addr uint64, args []uint64, trace bool) (uint64, error) {
	_ = trace
	if addr == 0 {
		return 0, nil
	}
	if trampoline == nil || trampoline.Addr == 0 {
		return 0, fmt.Errorf("nil guest-call trampoline")
	}
	rw, ok := cpu.(RegisterWriter)
	if !ok {
		return 0, fmt.Errorf("CPU does not support RegisterWriter")
	}
	rr, ok := cpu.(RegisterReader)
	if !ok {
		return 0, fmt.Errorf("CPU does not support RegisterReader")
	}

	savedCtx := mem.Mmap(0, amd64ContextSize, mmu.PermRead|mmu.PermWrite)
	if err := saveCPUContextToGuest(cpu, mem, savedCtx); err != nil {
		return 0, err
	}

	sp := cpu.GetSP() &^ uint64(0xF)
	extraCount := 0
	if len(args) > 4 {
		extraCount = len(args) - 4
	}
	stackBytes := uint64(32 + extraCount*8)
	if stackBytes%16 != 0 {
		stackBytes += 8
	}
	sp -= stackBytes
	sp -= 8
	mem.Write64(sp, trampoline.Addr)
	for i := 4; i < len(args); i++ {
		mem.Write64(sp+0x28+uint64(i-4)*8, args[i])
	}
	cpu.SetSP(sp)

	if len(args) > 0 {
		rw.WriteReg(regRCX, args[0])
	}
	if len(args) > 1 {
		rw.WriteReg(regRDX, args[1])
	}
	if len(args) > 2 {
		rw.WriteReg(regR8, args[2])
	}
	if len(args) > 3 {
		rw.WriteReg(regR9, args[3])
	}
	cpu.SetPC(addr)

	err := cpu.Run()
	ret := rr.ReadReg(regRAX)
	restoreErr := restoreCPUContextFromGuest(cpu, mem, savedCtx)
	if err != nil {
		return ret, err
	}
	if restoreErr != nil {
		return ret, restoreErr
	}
	return ret, nil
}
