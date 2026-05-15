package jit_test

import (
	"bytes"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/jit"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

type memoryDifferentialResult struct {
	regs    [16]uint64
	flags   uint64
	rip     uint64
	instret uint64
	data    []byte
}

func newMemoryDifferentialMMU(t *testing.T, mode32 bool, codeAddr, dataAddr uint64, code, data []byte) *mmu.MMU {
	t.Helper()
	mem := mmu.New()
	if mode32 {
		if err := mem.EnableFlatBacking(); err != nil {
			t.Skipf("flat backing unavailable: %v", err)
		}
		mem.Mode32 = true
	}
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	for page, last := dataAddr&mmu.PageMask, (dataAddr+uint64(len(data)-1))&mmu.PageMask; ; page += mmu.PageSize {
		if err := mem.MapPage(page, mmu.PermRead|mmu.PermWrite); err != nil {
			t.Fatal(err)
		}
		if page == last {
			break
		}
	}
	if err := mem.WriteBytes(codeAddr, code); err != nil {
		t.Fatal(err)
	}
	if err := mem.WriteBytes(dataAddr, data); err != nil {
		t.Fatal(err)
	}
	return mem
}

func runMemoryInterpreter(t *testing.T, mode32 bool, codeAddr, dataAddr uint64, code, data []byte, regs [16]uint64, flags uint64, instructions int) memoryDifferentialResult {
	t.Helper()
	mem := newMemoryDifferentialMMU(t, mode32, codeAddr, dataAddr, code, data)
	cpu := x64.New(mem)
	cpu.Mode32 = mode32
	cpu.Regs = regs
	cpu.Rflags = flags
	cpu.RIP = codeAddr
	if err := cpu.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := mem.ReadBytes(dataAddr, len(data))
	if err != nil {
		t.Fatal(err)
	}
	return memoryDifferentialResult{
		regs: cpu.Regs, flags: cpu.Rflags, rip: cpu.RIP,
		instret: cpu.GetInstret(), data: got,
	}
}

func runMemoryJIT(t *testing.T, native, mode32 bool, codeAddr, dataAddr uint64, code, data []byte, regs [16]uint64, flags uint64, instructions int) memoryDifferentialResult {
	t.Helper()
	mem := newMemoryDifferentialMMU(t, mode32, codeAddr, dataAddr, code, data)
	cache := jit.NewCacheMode(mem, mode32)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil {
		t.Fatal("memory differential block did not compile")
	}
	rip, instret := codeAddr, uint64(0)
	state := &jit.State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: mode32, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || instret != uint64(instructions) {
		t.Fatalf("native=%v fallback=%v instret=%d", native, state.Fallback, instret)
	}
	remainder := x64.New(mem)
	remainder.Mode32 = mode32
	remainder.Regs = regs
	remainder.Rflags = flags
	remainder.RIP = rip
	if err := remainder.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := mem.ReadBytes(dataAddr, len(data))
	if err != nil {
		t.Fatal(err)
	}
	return memoryDifferentialResult{
		regs: remainder.Regs, flags: remainder.Rflags, rip: remainder.RIP,
		instret: instret + remainder.GetInstret(), data: got,
	}
}

func TestNativeMemoryMatchesClosureAndInterpreter(t *testing.T) {
	tests := []struct {
		name     string
		mode32   bool
		codeAddr uint64
		dataAddr uint64
		code     []byte
		regs     [16]uint64
	}{
		{
			name:     "PE32",
			mode32:   true,
			codeAddr: 0x3000,
			dataAddr: 0x12340,
			code: []byte{
				0x8B, 0x03,
				0x03, 0x43, 0x04,
				0x89, 0x43, 0x08,
				0x0F, 0xB6, 0x4B, 0x0C,
				0x0F, 0xBF, 0x53, 0x0E,
				0xF4,
			},
			regs: [16]uint64{3: 0x12340},
		},
		{
			name:     "PE64 high canonical",
			codeAddr: 0x3000,
			dataAddr: 0xffff923456790120,
			code: []byte{
				0x48, 0x8B, 0x03,
				0x48, 0x03, 0x43, 0x08,
				0x48, 0x89, 0x43, 0x10,
				0x4C, 0x0F, 0xB6, 0x53, 0x18,
				0x48, 0x0F, 0xBF, 0x4B, 0x1A,
				0xF4,
			},
			regs: [16]uint64{3: 0xffff923456790120},
		},
	}
	data := []byte{
		0x78, 0x56, 0x34, 0x12, 0x10, 0x32, 0x54, 0x76,
		0x11, 0x22, 0x33, 0x44, 0xFE, 0x00, 0x01, 0x80,
		0, 0, 0, 0, 0, 0, 0, 0,
		0xA5, 0, 0x01, 0x80, 0, 0, 0, 0,
	}
	const (
		flags        = uint64(0xA53)
		instructions = 5
	)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interpreter := runMemoryInterpreter(t, test.mode32, test.codeAddr, test.dataAddr, test.code, data, test.regs, flags, instructions)
			closure := runMemoryJIT(t, false, test.mode32, test.codeAddr, test.dataAddr, test.code, data, test.regs, flags, instructions)
			native := runMemoryJIT(t, true, test.mode32, test.codeAddr, test.dataAddr, test.code, data, test.regs, flags, instructions)
			for name, got := range map[string]memoryDifferentialResult{"closure": closure, "native": native} {
				if got.regs != interpreter.regs || got.flags != interpreter.flags ||
					got.rip != interpreter.rip || got.instret != interpreter.instret ||
					!bytes.Equal(got.data, interpreter.data) {
					t.Fatalf("%s=%+v interpreter=%+v", name, got, interpreter)
				}
			}
		})
	}
}
