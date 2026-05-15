//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestGetWindowSubclassMissPreservesOutput(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		mem := mmu.New()
		mem.Mode32 = is32
		state := &ntapi.ProcessState{Is32: is32}
		dispatcher := ntapi.NewDispatcher(
			mem,
			vfs.New(),
			ntapi.NewHandleTable(),
			nil,
			state,
			ntapi.GenerateNtdll(mem),
			ntapi.GenerateWin32u(mem),
		)
		comctl := ntapi.GenerateComctl32(mem)
		registerComctl32Handlers(&HandlerCtx{
			Mem:          mem,
			Disp:         dispatcher,
			ProcState:    state,
			SynthByName:  map[string]*ntapi.SynthPE{"comctl32.dll": comctl},
			HwndWndProc:  make(map[uint64]uint64),
			HwndChildren: make(map[uint64]*controlState),
		})

		output := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
		const sentinel = uint64(0x1122334455667788)
		const sentinel32 = uint32(0x55667788)
		if is32 {
			mem.Write32(output, sentinel32)
		} else {
			mem.Write64(output, sentinel)
		}
		if got := callSubclassTestExport(t, dispatcher, comctl, mem, is32,
			"GetWindowSubclass", 0x1234, 0x5678, 9, output); got != 0 {
			t.Fatalf("is32=%v GetWindowSubclass miss = %d", is32, got)
		}
		if is32 {
			got, _ := mem.Read32(output)
			if got != sentinel32 {
				t.Fatalf("PE32 output = %#x", got)
			}
		} else {
			got, _ := mem.Read64(output)
			if got != sentinel {
				t.Fatalf("PE64 output = %#x", got)
			}
		}
	}
}
