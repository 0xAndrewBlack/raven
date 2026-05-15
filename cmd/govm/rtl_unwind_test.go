//go:build guest_windows

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestNormalizeRtlUnwindCallerContext(t *testing.T) {
	mem := mmu.New()
	stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	const returnAddress = uint64(0x140001234)
	mem.Write64(stack, returnAddress)
	context := &ntapi.AMD64Context{Rip: 0x400000100000}
	context.Regs[4] = stack
	context.XMM[8] = [2]uint64{0x1122, 0x3344}
	if err := ntapi.WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	if err := normalizeRtlUnwindCallerContext(mem, contextAddress); err != nil {
		t.Fatal(err)
	}
	got, err := ntapi.ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rip != returnAddress || got.Regs[4] != stack+8 ||
		got.XMM[8] != [2]uint64{0x1122, 0x3344} {
		t.Fatalf("normalized caller context = %#v", got)
	}
}

func TestRtlUnwindExUsesSuppliedContextWithoutRecapture(t *testing.T) {
	mem := mmu.New()
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	context := &ntapi.AMD64Context{
		Rip: 0x140001234,
		XMM: [16][2]uint64{
			6: {0x11223344, 0x55667788},
		},
	}
	context.Regs[4] = 0x7fff00102000
	if err := ntapi.WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	before, err := mem.ReadBytes(contextAddress, 1232)
	if err != nil {
		t.Fatal(err)
	}
	cpu := x64.New(mem)
	cpu.SetPC(0x140009999)
	cpu.SetSP(0x7fff00999000)
	prepared, err := prepareRtlUnwindContext(mem, cpu, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if prepared != contextAddress {
		t.Fatalf("prepared context = %#x, want %#x", prepared, contextAddress)
	}
	after, err := mem.ReadBytes(contextAddress, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("supplied RtlUnwindEx context was modified before phase two")
	}
}

func TestRtlRestoreContextConsolidatesReentrantUnwind(t *testing.T) {
	mem := mmu.New()
	trampoline, err := allocRtlConsolidateTrampoline(mem)
	if err != nil {
		t.Fatal(err)
	}
	code := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	const continuation = uint64(0x140007000)
	callback := code + 0x100
	callbackCode := []byte{0x48, 0xB8}
	callbackCode = binary.LittleEndian.AppendUint64(callbackCode, continuation)
	callbackCode = append(callbackCode, 0xC3)
	if err := mem.WriteBytes(callback, callbackCode); err != nil {
		t.Fatal(err)
	}

	targetStack := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	targetRSP := targetStack + 0x8000
	targetRIP := uint64(0x140004000)
	mem.Write64(targetRSP, 0)
	contextRecord := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	targetContext := &ntapi.AMD64Context{Rip: targetRIP, Rflags: 0x202}
	targetContext.Regs[4] = targetRSP
	targetContext.Regs[3] = 0x1122334455667788
	if err := ntapi.WriteAMD64Context(mem, contextRecord, targetContext); err != nil {
		t.Fatal(err)
	}
	exceptionRecord := mem.Mmap(0, 0x100, mmu.PermRead|mmu.PermWrite)
	mem.Write32(exceptionRecord, ntapi.StatusUnwindConsolidate)
	mem.Write32(exceptionRecord+0x18, 1)
	mem.Write64(exceptionRecord+0x20, callback)

	nestedContextRecord := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	nestedExceptionRecord := mem.Mmap(0, 0x100, mmu.PermRead|mmu.PermWrite)
	mem.Write32(nestedExceptionRecord, ntapi.StatusUnwind)
	originalStack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	originalRSP := originalStack + 0x800
	originalRIP := uint64(0x140009000)

	cpu := x64.New(mem)
	cpu.SetPC(originalRIP)
	cpu.SetSP(originalRSP)
	cpu.WriteReg(3, 0x8877665544332211)
	cpu.SetSyscallHandler(func(trapped arch.CPU) {
		if uint32(trapped.SyscallNum()) == ntapi.DllMainReturnID {
			trapped.Stop()
		}
	})

	var nestedErr error
	callbackEntered := false
	cpu.PreStep = func(current *x64.CPU) bool {
		if current.GetPC() != callback || callbackEntered {
			return false
		}
		callbackEntered = true
		if current.ReadReg(1) != exceptionRecord {
			nestedErr = errors.New("consolidation callback received the wrong exception record")
			return false
		}
		if err := current.SaveContext(mem, nestedContextRecord); err != nil {
			nestedErr = err
			return false
		}
		nestedErr = ntapi.UnwindStack(
			mem,
			nestedExceptionRecord,
			nestedContextRecord,
			targetRSP,
			targetRIP+0x40,
			0,
			0,
			func(address uint64, args []uint64) (uint64, error) {
				return 0, errors.New("reentrant unwind exposed a hidden restore frame")
			},
			false,
		)
		return false
	}

	result, err := callRtlConsolidateCallback(
		&ntapi.TrapContext{CPU: cpu, Mem: mem},
		trampoline,
		contextRecord,
		exceptionRecord,
		callback,
	)
	if err != nil {
		t.Fatal(err)
	}
	if nestedErr != nil {
		t.Fatal(nestedErr)
	}
	if !callbackEntered {
		t.Fatal("consolidation callback was not entered")
	}
	if result != continuation {
		t.Fatalf("consolidation callback result = %#x, want %#x", result, continuation)
	}
	nestedContext, err := ntapi.ReadAMD64Context(mem, nestedContextRecord)
	if err != nil {
		t.Fatal(err)
	}
	if nestedContext.Rip != targetRIP+0x40 || nestedContext.Regs[4] != targetRSP {
		t.Fatalf("reentrant unwind context = %#v", nestedContext)
	}
	if cpu.GetPC() != originalRIP || cpu.GetSP() != originalRSP ||
		cpu.ReadReg(3) != 0x8877665544332211 {
		t.Fatalf("restore frame context leaked: RIP=%#x RSP=%#x RBX=%#x",
			cpu.GetPC(), cpu.GetSP(), cpu.ReadReg(3))
	}
}

func TestTerminateRtlUnwindDoesNotReturn(t *testing.T) {
	if os.Getenv("RAVEN_TEST_RTL_UNWIND_FAILURE") == "1" {
		terminateRtlUnwind(errors.New("forced unwind failure"))
		t.Fatal("terminateRtlUnwind returned")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestTerminateRtlUnwindDoesNotReturn$")
	command.Env = append(os.Environ(), "RAVEN_TEST_RTL_UNWIND_FAILURE=1")
	err := command.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unwind failure process error = %v", err)
	}
	if exitError.ExitCode() != 3 {
		t.Fatalf("unwind failure exit code = %d, want 3", exitError.ExitCode())
	}
}
