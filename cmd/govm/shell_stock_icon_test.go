//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestFillStockIconInfoGuestLayouts(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := stockIconInfoLayoutFor(test.is32)
			mem := mmu.New()
			addr := mem.Mmap(0, uint64(layout.size)+4, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr, layout.size); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write32(addr+uint64(layout.size), 0xa5a5a5a5); err != nil {
				t.Fatal(err)
			}

			flags := shgsiIcon | shgsiSysIconIndex | shgsiSmallIcon | shgsiLinkOverlay | shgsiSelected
			if hr := fillStockIconInfo(mem, addr, test.is32, 77, flags); hr != S_OK {
				t.Fatalf("SHGetStockIconInfo returned %#x", hr)
			}

			if got, err := mem.Read32(addr); err != nil || got != layout.size {
				t.Fatalf("cbSize = %d, err = %v", got, err)
			}
			if got := readStockIconHandle(t, mem, addr+layout.hIconOffset, test.is32); got != stockIconHandle(77, flags) {
				t.Fatalf("hIcon = %#x, want %#x", got, stockIconHandle(77, flags))
			}
			if got, err := mem.Read32(addr + layout.sysIndexOffset); err != nil || got != 77 {
				t.Fatalf("iSysImageIndex = %d, err = %v", got, err)
			}
			if got, err := mem.Read32(addr + layout.iconOffset); err != nil || int32(got) != -194 {
				t.Fatalf("iIcon = %d, err = %v", int32(got), err)
			}
			if got := readGuestUTF16String(mem, addr+layout.pathOffset); got != stockIconPath {
				t.Fatalf("szPath = %q, want %q", got, stockIconPath)
			}
			if got, err := mem.Read32(addr + uint64(layout.size)); err != nil || got != 0xa5a5a5a5 {
				t.Fatalf("adjacent memory = %#x, err = %v", got, err)
			}
		})
	}
}

func TestFillStockIconInfoHonorsFlags(t *testing.T) {
	layout := stockIconInfoLayoutFor(true)
	mem := mmu.New()
	addr := mem.Mmap(0, uint64(layout.size)*4, mmu.PermRead|mmu.PermWrite)

	writeSize := func(target uint64) {
		t.Helper()
		if err := mem.Write32(target, layout.size); err != nil {
			t.Fatal(err)
		}
	}

	writeSize(addr)
	if hr := fillStockIconInfo(mem, addr, true, 3, 0); hr != S_OK {
		t.Fatalf("location-only call returned %#x", hr)
	}
	if got := readStockIconHandle(t, mem, addr+layout.hIconOffset, true); got != 0 {
		t.Fatalf("location-only hIcon = %#x, want NULL", got)
	}
	if got, err := mem.Read32(addr + layout.sysIndexOffset); err != nil || got != ^uint32(0) {
		t.Fatalf("location-only iSysImageIndex = %#x, err = %v", got, err)
	}
	if got, err := mem.Read32(addr + layout.iconOffset); err != nil || int32(got) != -4 {
		t.Fatalf("location-only iIcon = %d, err = %v", int32(got), err)
	}

	iconFlags := shgsiIcon | shgsiSmallIcon | shgsiShellIconSize | shgsiLinkOverlay | shgsiSelected
	first := addr + uint64(layout.size)
	second := first + uint64(layout.size)
	large := second + uint64(layout.size)
	for _, target := range []uint64{first, second, large} {
		writeSize(target)
	}
	if hr := fillStockIconInfo(mem, first, true, 3, iconFlags); hr != S_OK {
		t.Fatalf("first icon call returned %#x", hr)
	}
	if hr := fillStockIconInfo(mem, second, true, 3, iconFlags|0x80000000); hr != S_OK {
		t.Fatalf("icon call with unknown flag returned %#x", hr)
	}
	if hr := fillStockIconInfo(mem, large, true, 3, shgsiIcon); hr != S_OK {
		t.Fatalf("large icon call returned %#x", hr)
	}
	firstHandle := readStockIconHandle(t, mem, first+layout.hIconOffset, true)
	secondHandle := readStockIconHandle(t, mem, second+layout.hIconOffset, true)
	largeHandle := readStockIconHandle(t, mem, large+layout.hIconOffset, true)
	if firstHandle == 0 || firstHandle != secondHandle {
		t.Fatalf("deterministic handles = %#x and %#x", firstHandle, secondHandle)
	}
	if largeHandle == firstHandle {
		t.Fatalf("large and modified icon handles both equal %#x", largeHandle)
	}
	otherID := mem.Mmap(0, uint64(layout.size), mmu.PermRead|mmu.PermWrite)
	writeSize(otherID)
	if hr := fillStockIconInfo(mem, otherID, true, 4, iconFlags); hr != S_OK {
		t.Fatalf("other SIID call returned %#x", hr)
	}
	if otherHandle := readStockIconHandle(t, mem, otherID+layout.hIconOffset, true); otherHandle == firstHandle {
		t.Fatalf("SIID 3 and 4 handles both equal %#x", otherHandle)
	}
}

func TestFillStockIconInfoRejectsInvalidInputs(t *testing.T) {
	if hr := fillStockIconInfo(nil, 0x1000, true, 0, 0); hr != E_INVALIDARG {
		t.Fatalf("nil memory returned %#x", hr)
	}
	mem := mmu.New()
	if hr := fillStockIconInfo(mem, 0, true, 0, 0); hr != E_INVALIDARG {
		t.Fatalf("NULL structure returned %#x", hr)
	}
	if hr := fillStockIconInfo(mem, 0x4000, true, 0, 0); hr != E_INVALIDARG {
		t.Fatalf("unmapped structure returned %#x", hr)
	}

	for _, is32 := range []bool{true, false} {
		layout := stockIconInfoLayoutFor(is32)
		for _, size := range []uint32{layout.size - 1, layout.size + 1} {
			addr := mem.Mmap(0, uint64(layout.size)+4, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr, size); err != nil {
				t.Fatal(err)
			}
			if hr := fillStockIconInfo(mem, addr, is32, 0, 0); hr != E_INVALIDARG {
				t.Fatalf("is32=%v cbSize %d returned %#x", is32, size, hr)
			}
		}
	}

	addr := mem.Mmap(0, uint64(shStockIconInfo32Size), mmu.PermRead|mmu.PermWrite)
	if err := mem.Write32(addr, shStockIconInfo32Size); err != nil {
		t.Fatal(err)
	}
	if hr := fillStockIconInfo(mem, addr, true, ^uint32(0), 0); hr != E_INVALIDARG {
		t.Fatalf("SIID_INVALID returned %#x", hr)
	}
	if hr := fillStockIconInfo(mem, addr, true, stockIconIDLimit, 0); hr != E_INVALIDARG {
		t.Fatalf("SIID_MAX_ICONS returned %#x", hr)
	}
	if hr := fillStockIconInfo(mem, addr, true, stockIconIDLimit-1, 0); hr != S_OK {
		t.Fatalf("highest valid SIID returned %#x", hr)
	}

	readonly := mem.Mmap(0, uint64(shStockIconInfo32Size), mmu.PermRead|mmu.PermWrite)
	if err := mem.Write32(readonly, shStockIconInfo32Size); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(readonly, uint64(shStockIconInfo32Size), mmu.PermRead); err != nil {
		t.Fatal(err)
	}
	if hr := fillStockIconInfo(mem, readonly, true, 0, 0); hr != E_INVALIDARG {
		t.Fatalf("read-only structure returned %#x", hr)
	}

	partialMem := mmu.New()
	const partialPage = uint64(0x4000)
	partialMem.MapRange(partialPage, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	partial := partialPage + mmu.PageSize - 8
	if err := partialMem.Write32(partial, shStockIconInfo64Size); err != nil {
		t.Fatal(err)
	}
	if hr := fillStockIconInfo(partialMem, partial, false, 0, 0); hr != E_INVALIDARG {
		t.Fatalf("partially mapped structure returned %#x", hr)
	}
}

func TestSHGetStockIconInfoHandlerPE32AndPE64(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = test.is32
			state := &ntapi.ProcessState{Is32: test.is32}
			dispatcher := ntapi.NewDispatcher(
				mem,
				vfs.New(),
				ntapi.NewHandleTable(),
				nil,
				state,
				ntapi.GenerateNtdll(mem),
				ntapi.GenerateWin32u(mem),
			)
			shell32 := ntapi.GenerateSynthDLL(mem, "shell32.dll", []string{"SHGetStockIconInfo"}, ntapi.AutoSynthIDBase)
			registerShell32Handlers(&HandlerCtx{
				Disp:        dispatcher,
				Mem:         mem,
				SynthByName: map[string]*ntapi.SynthPE{"shell32.dll": shell32},
			})

			layout := stockIconInfoLayoutFor(test.is32)
			info := mem.Mmap(0, uint64(layout.size), mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(info, layout.size); err != nil {
				t.Fatal(err)
			}
			stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			cpu := x64.New(mem)
			cpu.Mode32 = test.is32
			cpu.SetSP(stack)
			if test.is32 {
				for index, value := range []uint32{0, 3, shgsiIcon, uint32(info)} {
					if err := mem.Write32(stack+uint64(index*4), value); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				if err := mem.Write64(stack, 0); err != nil {
					t.Fatal(err)
				}
				cpu.Regs[1] = 3
				cpu.Regs[2] = uint64(shgsiIcon)
				cpu.Regs[8] = info
			}
			stub := shell32.Exports["SHGetStockIconInfo"]
			cpu.Regs[0] = uint64(shell32.StubIDs[stub])
			dispatcher.Handle(cpu)

			if got := uint32(cpu.Regs[0]); got != S_OK {
				t.Fatalf("handler returned %#x", got)
			}
			if got := readStockIconHandle(t, mem, info+layout.hIconOffset, test.is32); got == 0 {
				t.Fatal("handler did not populate hIcon")
			}
		})
	}
}

func readStockIconHandle(t *testing.T, mem *mmu.MMU, addr uint64, is32 bool) uint64 {
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
