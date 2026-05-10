//go:build guest_windows

package ntapi

import (
	"fmt"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestUserCallbackRuntimeWindowProcPE32AndPE64(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE32=%t", mode32), func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			pebSize := uint64(PebSize)
			if mode32 {
				pebSize = Peb32Size
			}
			peb := mem.Mmap(0, pebSize, mmu.PermRead|mmu.PermWrite)
			state := &ProcessState{PEBAddr: peb, Is32: mode32}
			ntdll := GenerateNtdll(mem)
			d := NewDispatcher(mem, vfs.New(), NewHandleTable(), nil, state, ntdll, GenerateWin32u(mem))

			runtime, err := InstallUserCallbackRuntime(mem, state, ntdll.Exports["NtCallbackReturn"])
			if err != nil {
				t.Fatal(err)
			}
			assertInstalledCallbackRuntime(t, mem, state, runtime)

			wndProc := installTestWindowProc(t, mem, mode32, 0x12345678)
			stack := mem.Mmap(0, 4*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			stop := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			if err := mem.WriteBytes(stop, []byte{0x0F, 0x01, 0xC1}); err != nil {
				t.Fatal(err)
			}

			cpu := x64.New(mem)
			cpu.Mode32 = mode32
			cpu.SetSP(stack + 3*mmu.PageSize)
			cpu.SetPC(stop)
			cpu.Regs[x64.RAX] = 0xA5A5
			cpu.SetVmcallHandler(func(trapped arch.CPU) {
				if trapped.GetPC() == stop+3 {
					trapped.Stop()
					return
				}
				d.Handle(trapped)
			})
			before := cpu.Snapshot()

			input := EncodeWindowProcCallbackArguments(mode32, WindowProcCallbackArguments{
				Proc:   wndProc,
				Wnd:    0x10203,
				Msg:    0x401,
				WParam: 0x11223344,
				LParam: 0x55667788,
			})
			var completed UserCallbackReturn
			if _, err := d.BeginUserCallbackWithCompletion(cpu, runtime.Dispatcher, User32CallbackWindowProc, input,
				func(cpu *x64.CPU, callbackReturn UserCallbackReturn) {
					completed = callbackReturn
					result, readErr := ReadWindowProcCallbackResult(mem, mode32, callbackReturn)
					if readErr != nil {
						t.Error(readErr)
						return
					}
					cpu.SetSyscallReturn(result)
				}); err != nil {
				t.Fatal(err)
			}

			if err := cpu.Run(); err != nil {
				t.Fatal(err)
			}
			if completed.Status != StatusSuccess || completed.Length != uint32(len(input)) {
				t.Fatalf("callback return = %+v", completed)
			}
			if callbackReturn, ok := d.TakeUserCallbackReturn(cpu); ok {
				t.Fatalf("completion callback also queued return %+v", callbackReturn)
			}
			if result := cpu.Regs[x64.RAX]; result != 0x12345678 {
				t.Fatalf("WndProc result = 0x%x, want 0x12345678", result)
			}
			cpu.Regs[x64.RAX] = 0xA5A5
			cpu.SetPC(stop)
			after := cpu.Snapshot()
			if after != before {
				t.Fatal("callback runtime did not restore CPU state")
			}
		})
	}
}

func TestInstallUserCallbackRuntimePreservesExistingTable(t *testing.T) {
	for _, mode32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE32=%t", mode32), func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = mode32
			peb := mem.Mmap(0, PebSize, mmu.PermRead|mmu.PermWrite)
			state := &ProcessState{PEBAddr: peb, Is32: mode32}
			existing := mem.Mmap(0, mmu.PageSize, mmu.PermRead)
			if mode32 {
				if err := mem.Write32(peb+Peb32KernelCallbackTable, uint32(existing)); err != nil {
					t.Fatal(err)
				}
			} else if err := mem.Write64(peb+PebKernelCallbackTable, existing); err != nil {
				t.Fatal(err)
			}

			runtime, err := InstallUserCallbackRuntime(mem, state, 0x123400)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.CallbackTable != existing {
				t.Fatalf("callback table = 0x%x, want existing 0x%x", runtime.CallbackTable, existing)
			}
		})
	}
}

func assertInstalledCallbackRuntime(t *testing.T, mem *mmu.MMU, state *ProcessState, runtime UserCallbackRuntime) {
	t.Helper()
	tableAddress := state.PEBAddr + PebKernelCallbackTable
	if state.Is32 {
		tableAddress = state.PEBAddr + Peb32KernelCallbackTable
	}
	table, err := readCallbackPointer(mem, tableAddress, state.Is32)
	if err != nil {
		t.Fatal(err)
	}
	if table != runtime.CallbackTable {
		t.Fatalf("PEB callback table = 0x%x, want 0x%x", table, runtime.CallbackTable)
	}
	entry, err := readCallbackPointer(mem, table, state.Is32)
	if err != nil {
		t.Fatal(err)
	}
	if entry != runtime.WindowProc {
		t.Fatalf("callback[0] = 0x%x, want 0x%x", entry, runtime.WindowProc)
	}
}

func installTestWindowProc(t *testing.T, mem *mmu.MMU, mode32 bool, result uint32) uint64 {
	t.Helper()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	code := []byte{0xB8, byte(result), byte(result >> 8), byte(result >> 16), byte(result >> 24)}
	if mode32 {
		code = append(code, 0xC2, 0x10, 0x00)
	} else {
		code = append(code, 0xC3)
	}
	if err := mem.WriteBytes(address, code); err != nil {
		t.Fatal(err)
	}
	return address
}
