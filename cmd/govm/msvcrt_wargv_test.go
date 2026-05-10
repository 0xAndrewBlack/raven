//go:build guest_windows

package main

import (
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestMsvcrtWideArgvPointerContract(t *testing.T) {
	args := []string{
		`C:\Program Files\Raven\sample.exe`,
		"unicode-\U0001f600-\u65e5\u672c\u8a9e.txt",
		"",
	}
	for _, tc := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = tc.is32
			state := &ntapi.ProcessState{Is32: tc.is32}
			dispatcher := ntapi.NewDispatcher(
				mem,
				vfs.New(),
				ntapi.NewHandleTable(),
				nil,
				state,
				ntapi.GenerateNtdll(mem),
				ntapi.GenerateWin32u(mem),
			)
			msvcrt := ntapi.GenerateSynthDLL(mem, "msvcrt.dll", []string{"__p___wargv"}, ntapi.AutoSynthIDBase)
			registerMsvcrtHandlers(&HandlerCtx{
				Argv:        args,
				Disp:        dispatcher,
				Mem:         mem,
				SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": msvcrt},
			})

			const callers = 8
			cpus := make([]*x64.CPU, callers)
			stacks := make([]uint64, callers)
			slots := make([]uint64, callers)
			stub := msvcrt.Exports["__p___wargv"]
			stubID := uint64(msvcrt.StubIDs[stub])
			for i := range cpus {
				cpus[i] = x64.New(mem)
				cpus[i].Mode32 = tc.is32
				stacks[i] = mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				cpus[i].SetSP(stacks[i])
				if tc.is32 {
					if err := mem.Write32(stacks[i], 0); err != nil {
						t.Fatal(err)
					}
				} else if err := mem.Write64(stacks[i], 0); err != nil {
					t.Fatal(err)
				}
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range cpus {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					cpus[i].Regs[0] = stubID
					dispatcher.Handle(cpus[i])
					slots[i] = cpus[i].Regs[0]
				}(i)
			}
			close(start)
			wg.Wait()

			slot := slots[0]
			if slot == 0 {
				t.Fatal("handler returned NULL")
			}
			for i, got := range slots[1:] {
				if got != slot {
					t.Fatalf("concurrent slot %d = %#x, want %#x", i+1, got, slot)
				}
			}
			vector := readWideArgvPointer(t, mem, slot, tc.is32)
			if tc.is32 && (slot > uint64(^uint32(0)) || vector > uint64(^uint32(0))) {
				t.Fatalf("PE32 pointers exceed 32 bits: slot=%#x vector=%#x", slot, vector)
			}
			for i, want := range args {
				argAddr := readWideArgvPointer(t, mem, vector+uint64(i)*pointerSize(tc.is32), tc.is32)
				if got := readUTF16(mem, argAddr, -1); got != want {
					t.Fatalf("argv[%d] = %q, want %q", i, got, want)
				}
			}
			if terminator := readWideArgvPointer(t, mem, vector+uint64(len(args))*pointerSize(tc.is32), tc.is32); terminator != 0 {
				t.Fatalf("argv terminator = %#x, want NULL", terminator)
			}

			writeWideArgvPointer(t, mem, slot, 0, tc.is32)
			if second := invokeWideArgv(t, dispatcher, msvcrt, cpus[0], stacks[0], tc.is32); second != slot {
				t.Fatalf("second slot = %#x, want stable %#x", second, slot)
			}
			if got := readWideArgvPointer(t, mem, slot, tc.is32); got != 0 {
				t.Fatalf("global slot was rewritten to %#x", got)
			}
		})
	}
}

func invokeWideArgv(
	t *testing.T,
	dispatcher *ntapi.Dispatcher,
	msvcrt *ntapi.SynthPE,
	cpu *x64.CPU,
	stack uint64,
	is32 bool,
) uint64 {
	t.Helper()
	cpu.SetSP(stack)
	if is32 {
		if err := cpu.GetMem().Write32(stack, 0); err != nil {
			t.Fatal(err)
		}
	} else if err := cpu.GetMem().Write64(stack, 0); err != nil {
		t.Fatal(err)
	}
	stub := msvcrt.Exports["__p___wargv"]
	cpu.Regs[0] = uint64(msvcrt.StubIDs[stub])
	dispatcher.Handle(cpu)
	return cpu.Regs[0]
}

func pointerSize(is32 bool) uint64 {
	if is32 {
		return 4
	}
	return 8
}

func readWideArgvPointer(t *testing.T, mem *mmu.MMU, addr uint64, is32 bool) uint64 {
	t.Helper()
	if is32 {
		value, err := mem.Read32(addr)
		if err != nil {
			t.Fatal(err)
		}
		return uint64(value)
	}
	value, err := mem.Read64(addr)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func writeWideArgvPointer(t *testing.T, mem *mmu.MMU, addr, value uint64, is32 bool) {
	t.Helper()
	var err error
	if is32 {
		err = mem.Write32(addr, uint32(value))
	} else {
		err = mem.Write64(addr, value)
	}
	if err != nil {
		t.Fatal(err)
	}
}
