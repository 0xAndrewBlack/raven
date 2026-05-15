package jit

import (
	"sync/atomic"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func runNativeDivision(
	t *testing.T,
	native, mode32 bool,
	code []byte,
	regs [16]uint64,
	flags uint64,
) nativeIntegerResult {
	t.Helper()

	mem := mmu.New()
	mem.Mode32 = mode32
	mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	program := append(append([]byte(nil), code...), 0xEB, 0xFE)
	for i, opcode := range program {
		if err := mem.Write8(0x1000+uint64(i), opcode); err != nil {
			t.Fatal(err)
		}
	}

	cache := NewCacheMode(mem, mode32)
	if native && !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(0x1000)
	if block == nil {
		t.Fatal("division fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatalf("native backend rejected division fixture % x", code)
	}

	rip := uint64(0x1000)
	instret := uint64(0)
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &flags, Mem: mem,
		Mode32: mode32, Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	return nativeIntegerResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback,
	}
}

func TestNativeDivisionMatchesClosure(t *testing.T) {
	const flags = uint64(0xA53)
	tests := []struct {
		name   string
		mode32 bool
		code   []byte
		regs   [16]uint64
	}{
		{
			name: "PE64 DIV byte partial registers",
			code: []byte{0xF6, 0xF1},
			regs: [16]uint64{
				0: 0x1122334455660321,
				1: 10,
			},
		},
		{
			name:   "PE32 DIV word partial registers",
			mode32: true,
			code:   []byte{0x66, 0xF7, 0xF1},
			regs: [16]uint64{
				0: 0x1122334455660000,
				1: 3,
				2: 0x8877665544330001,
			},
		},
		{
			name:   "PE32 DIV dword zero extension",
			mode32: true,
			code:   []byte{0xF7, 0xF1},
			regs: [16]uint64{
				0: 0xFFFFFFFF00000000,
				1: 3,
				2: 0xAAAAAAAA00000001,
			},
		},
		{
			name: "PE64 DIV qword extended source",
			code: []byte{0x49, 0xF7, 0xF1},
			regs: [16]uint64{
				0: 0,
				2: 1,
				9: 3,
			},
		},
		{
			name: "PE64 DIV source aliases accumulator",
			code: []byte{0xF7, 0xF0},
			regs: [16]uint64{
				0: 7,
				2: 0,
			},
		},
		{
			name: "PE64 IDIV source aliases accumulator",
			code: []byte{0xF6, 0xF8},
			regs: [16]uint64{0: 3},
		},
		{
			name: "PE64 IDIV source aliases high dividend",
			code: []byte{0x66, 0xF7, 0xFA},
			regs: [16]uint64{
				0: 0x112233445566FFF6,
				2: 0x887766554433FFFF,
			},
		},
		{
			name: "PE64 IDIV byte negative remainder",
			code: []byte{0xF6, 0xF9},
			regs: [16]uint64{
				0: 0x112233445566FD41,
				1: 7,
			},
		},
		{
			name:   "PE32 IDIV word negative quotient",
			mode32: true,
			code:   []byte{0x66, 0xF7, 0xF9},
			regs: [16]uint64{
				0: 0x1122334455667960,
				1: 300,
				2: 0x887766554433FFFE,
			},
		},
		{
			name:   "PE32 IDIV dword signed dividend",
			mode32: true,
			code:   []byte{0xF7, 0xF9},
			regs: [16]uint64{
				0: 0xAAAAAAAAD5FA0E00,
				1: 0xFFFFFFFD,
				2: 0xBBBBBBBBFFFFFFFE,
			},
		},
		{
			name: "PE64 IDIV qword signed dividend",
			code: []byte{0x48, 0xF7, 0xF9},
			regs: [16]uint64{
				0: ^uint64(98),
				1: 7,
				2: ^uint64(0),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure := runNativeDivision(t, false, test.mode32, test.code, test.regs, flags)
			native := runNativeDivision(t, true, test.mode32, test.code, test.regs, flags)
			if native != closure {
				t.Fatalf("native=%+v closure=%+v", native, closure)
			}
			if native.fallback || native.flags != flags || native.instret != 2 {
				t.Fatalf("division state=%+v", native)
			}
		})
	}
}

func TestNativeDivisionFaultsBeforeHostDivide(t *testing.T) {
	const flags = uint64(0xA53)
	tests := []struct {
		name string
		code []byte
		regs [16]uint64
	}{
		{
			name: "DIV zero",
			code: []byte{0x48, 0xF7, 0xF1},
			regs: [16]uint64{0: 1},
		},
		{
			name: "DIV quotient overflow",
			code: []byte{0x48, 0xF7, 0xF1},
			regs: [16]uint64{0: 0, 1: 3, 2: 3},
		},
		{
			name: "IDIV positive overflow",
			code: []byte{0x48, 0xF7, 0xF9},
			regs: [16]uint64{0: 0, 1: 1, 2: 1},
		},
		{
			name: "IDIV minimum divided by negative one",
			code: []byte{0x48, 0xF7, 0xF9},
			regs: [16]uint64{0: 0x8000000000000000, 1: ^uint64(0), 2: ^uint64(0)},
		},
		{
			name: "IDIV byte overflow",
			code: []byte{0xF6, 0xF9},
			regs: [16]uint64{0: 0x0100, 1: 1},
		},
		{
			name: "IDIV word overflow",
			code: []byte{0x66, 0xF7, 0xF9},
			regs: [16]uint64{0: 0, 1: 1, 2: 1},
		},
		{
			name: "IDIV dword overflow",
			code: []byte{0xF7, 0xF9},
			regs: [16]uint64{0: 0, 1: 1, 2: 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := runNativeDivision(t, true, false, test.code, test.regs, flags)
			if !got.fallback || got.instret != 0 || got.rip != 0x1000 ||
				got.regs != test.regs || got.flags != flags {
				t.Fatalf("fault state=%+v", got)
			}
		})
	}
}

func TestNativeDivisionFaultReleasesSparseMemoryPin(t *testing.T) {
	const (
		codeAddr = uint64(0x1000)
		dataAddr = uint64(0x123456789000)
		flags    = uint64(0xA53)
	)
	mem := mmu.New()
	if err := mem.MapPage(codeAddr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := mem.MapPage(dataAddr, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatal(err)
	}
	program := []byte{0x48, 0x8B, 0x03, 0x48, 0xF7, 0xF1, 0xEB, 0xFE}
	if err := mem.WriteBytes(codeAddr, program); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write64(dataAddr, 0x1122334455667788); err != nil {
		t.Fatal(err)
	}

	cache := NewCacheMode(mem, false)
	if !cache.EnableNativeCodegen() {
		t.Skip("native codegen unavailable")
	}
	block := cache.Compile(codeAddr)
	if block == nil || block.native == 0 || !block.nativeMem {
		t.Fatal("native backend rejected sparse-memory division fixture")
	}

	regs := [16]uint64{0: 0xAAAAAAAAAAAAAAAA, 3: dataAddr}
	rip, instret, gotFlags := codeAddr, uint64(0), flags
	state := &State{
		Regs: &regs, RIP: &rip, Rflags: &gotFlags, Mem: mem,
		Instret: &instret,
	}
	if err := block.Run(state); err != nil {
		t.Fatal(err)
	}
	if !state.Fallback || rip != codeAddr+3 || instret != 1 ||
		regs[0] != 0x1122334455667788 || gotFlags != flags {
		t.Fatalf("fault state regs=%#v flags=%#x RIP=%#x instret=%d fallback=%v",
			regs, gotFlags, rip, instret, state.Fallback)
	}
	desc := mem.NativeTable()
	if users := (*atomic.Uint64)(desc.ActiveUsers).Load(); users != 0 {
		t.Fatalf("active sparse-memory users=%d", users)
	}
}
