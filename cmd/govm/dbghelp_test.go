//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestVersionQueryPointerUsesGuestPointerWidth(t *testing.T) {
	const (
		addr     = uint64(0x4000)
		value    = uint64(0x1122334455667788)
		sentinel = uint32(0xa5a5a5a5)
	)

	for _, tc := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64", is32: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := mmu.New()
			mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr+4, sentinel); err != nil {
				t.Fatal(err)
			}
			ctx := &ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{Is32: tc.is32}}

			writeGuestPtr(ctx, addr, value)

			if tc.is32 {
				got, err := mem.Read32(addr)
				if err != nil || got != uint32(value&0xffffffff) {
					t.Fatalf("pointer = %#x, err = %v", got, err)
				}
				gotSentinel, err := mem.Read32(addr + 4)
				if err != nil || gotSentinel != sentinel {
					t.Fatalf("adjacent memory = %#x, err = %v", gotSentinel, err)
				}
				return
			}

			got, err := mem.Read64(addr)
			if err != nil || got != value {
				t.Fatalf("pointer = %#x, err = %v", got, err)
			}
		})
	}
}

func TestVerQueryValueHandlersPreservePE32AdjacentMemory(t *testing.T) {
	for _, funcName := range []string{"VerQueryValueA", "VerQueryValueW"} {
		t.Run(funcName, func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = true
			const (
				stack       = uint64(0x8000)
				versionData = uint64(0x9000)
				subBlock    = uint64(0xa000)
				resultOut   = uint64(0xb000)
				lengthOut   = uint64(0xb010)
				sentinel    = uint32(0xa5a5a5a5)
			)
			mem.MapRange(stack, mmu.PageSize*4, mmu.PermRead|mmu.PermWrite)
			if funcName == "VerQueryValueW" {
				if err := mem.Write16(subBlock, '\\'); err != nil {
					t.Fatal(err)
				}
				if err := mem.Write16(subBlock+2, 0); err != nil {
					t.Fatal(err)
				}
			} else if err := mem.WriteBytes(subBlock, []byte{'\\', 0}); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write32(resultOut+4, sentinel); err != nil {
				t.Fatal(err)
			}

			state := &ntapi.ProcessState{Is32: true}
			dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, ntapi.GenerateNtdll(mem), ntapi.GenerateWin32u(mem))
			version := ntapi.GenerateSynthDLL(mem, "version.dll", []string{funcName}, ntapi.AutoSynthIDBase)
			hctx := &HandlerCtx{
				Mem:         mem,
				Disp:        dispatcher,
				SynthByName: map[string]*ntapi.SynthPE{"version.dll": version},
				ReadGuestString: func(addr uint64) string {
					data, _ := mem.ReadBytes(addr, 2)
					return string(data[:1])
				},
				ReadGuestUTF16: func(addr uint64) string {
					value, _ := mem.Read16(addr)
					return string(rune(value))
				},
			}
			registerVersionDLLHandlers(hctx)

			cpu := x64.New(mem)
			cpu.Mode32 = true
			cpu.SetSP(stack)
			for index, arg := range []uint32{uint32(versionData), uint32(subBlock), uint32(resultOut), uint32(lengthOut)} {
				if err := mem.Write32(stack+4+uint64(index*4), arg); err != nil {
					t.Fatal(err)
				}
			}
			stubAddr := version.Exports[funcName]
			cpu.Regs[0] = uint64(version.StubIDs[stubAddr])
			dispatcher.Handle(cpu)

			gotResult, err := mem.Read32(resultOut)
			if err != nil || uint64(gotResult) != versionData {
				t.Fatalf("result pointer = %#x, err = %v", gotResult, err)
			}
			gotLength, err := mem.Read32(lengthOut)
			if err != nil || gotLength != 52 {
				t.Fatalf("result length = %d, err = %v", gotLength, err)
			}
			gotSentinel, err := mem.Read32(resultOut + 4)
			if err != nil || gotSentinel != sentinel {
				t.Fatalf("adjacent memory = %#x, err = %v", gotSentinel, err)
			}
		})
	}
}

func TestImageNtHeader(t *testing.T) {
	tests := []struct {
		name        string
		base        uint64
		dos         uint16
		lfanew      uint32
		pe          uint32
		mapHeader   bool
		wantAddress uint64
	}{
		{name: "null base"},
		{name: "valid PE64 image", base: 0x10000, dos: 0x5A4D, lfanew: 0x180, pe: 0x00004550, mapHeader: true, wantAddress: 0x10180},
		{name: "invalid DOS signature", base: 0x20000, dos: 0x1234, lfanew: 0x80, pe: 0x00004550, mapHeader: true},
		{name: "invalid PE signature", base: 0x30000, dos: 0x5A4D, lfanew: 0x80, pe: 0x12345678, mapHeader: true},
		{name: "unmapped NT header", base: 0x40000, dos: 0x5A4D, lfanew: 0x2000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := mmu.New()
			cpu := x64.New(mem)
			if tt.base != 0 {
				mem.MapRange(tt.base, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				mem.Write16(tt.base, tt.dos)
				mem.Write32(tt.base+0x3C, tt.lfanew)
				if tt.mapHeader {
					mem.Write32(tt.base+uint64(tt.lfanew), tt.pe)
				}
			}
			cpu.Regs[1] = tt.base
			ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}

			if got := handleImageNtHeader(ctx); got != 0 {
				t.Fatalf("handler status = %#x, want 0", got)
			}
			if got := cpu.Regs[0]; got != tt.wantAddress {
				t.Fatalf("ImageNtHeader returned %#x, want %#x", got, tt.wantAddress)
			}
		})
	}
}
