package jit

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

type nativePartialMOVResult struct {
	regs     [16]uint64
	flags    uint64
	rip      uint64
	instret  uint64
	fallback bool
}

func runNativePartialMOV(
	t *testing.T,
	native bool,
	mode32 bool,
	code []byte,
	regs [16]uint64,
	flags uint64,
) nativePartialMOVResult {
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
		t.Fatal("partial MOV fixture did not compile")
	}
	if native && block.native == 0 {
		t.Fatalf("native backend rejected partial MOV fixture % x", code)
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
	return nativePartialMOVResult{
		regs: regs, flags: flags, rip: rip, instret: instret,
		fallback: state.Fallback,
	}
}

func TestNativePartialMOVMatchesClosure(t *testing.T) {
	const initialFlags = uint64(0xA53)
	tests := []struct {
		name   string
		mode32 bool
		code   []byte
		regs   [16]uint64
		dst    int
		want   uint64
	}{
		{
			name: "PE64 byte opcode immediate",
			code: []byte{0xB0, 0x5A},
			regs: [16]uint64{0: 0x1122334455667788},
			dst:  0,
			want: 0x112233445566775A,
		},
		{
			name: "PE64 byte ModRM immediate",
			code: []byte{0xC6, 0xC1, 0xA5},
			regs: [16]uint64{1: 0x8877665544332211},
			dst:  1,
			want: 0x88776655443322A5,
		},
		{
			name: "PE64 word ModRM immediate",
			code: []byte{0x66, 0xC7, 0xC1, 0xEF, 0xBE},
			regs: [16]uint64{1: 0x8877665544332211},
			dst:  1,
			want: 0x887766554433BEEF,
		},
		{
			name: "PE64 byte source first",
			code: []byte{0x88, 0xC8},
			regs: [16]uint64{
				0: 0x1122334455667788,
				1: 0x88776655443322A5,
			},
			dst:  0,
			want: 0x11223344556677A5,
		},
		{
			name: "PE64 byte destination first",
			code: []byte{0x8A, 0xC1},
			regs: [16]uint64{
				0: 0x1122334455667788,
				1: 0x88776655443322A5,
			},
			dst:  0,
			want: 0x11223344556677A5,
		},
		{
			name: "PE64 word source first",
			code: []byte{0x66, 0x89, 0xC8},
			regs: [16]uint64{
				0: 0x1122334455667788,
				1: 0x887766554433A5B6,
			},
			dst:  0,
			want: 0x112233445566A5B6,
		},
		{
			name: "PE64 word destination first",
			code: []byte{0x66, 0x8B, 0xC1},
			regs: [16]uint64{
				0: 0x1122334455667788,
				1: 0x887766554433A5B6,
			},
			dst:  0,
			want: 0x112233445566A5B6,
		},
		{
			name: "PE64 byte same register",
			code: []byte{0x88, 0xC0},
			regs: [16]uint64{0: 0x1122334455667788},
			dst:  0,
			want: 0x1122334455667788,
		},
		{
			name: "PE64 word same register",
			code: []byte{0x66, 0x89, 0xC0},
			regs: [16]uint64{0: 0x1122334455667788},
			dst:  0,
			want: 0x1122334455667788,
		},
		{
			name: "PE64 REX byte immediate SPL",
			code: []byte{0x40, 0xB4, 0x7E},
			regs: [16]uint64{4: 0x1020304050607080},
			dst:  4,
			want: 0x102030405060707E,
		},
		{
			name: "PE64 extended byte immediate",
			code: []byte{0x41, 0xB0, 0xE1},
			regs: [16]uint64{8: 0x1020304050607080},
			dst:  8,
			want: 0x10203040506070E1,
		},
		{
			name: "PE64 extended word immediate",
			code: []byte{0x66, 0x41, 0xC7, 0xC0, 0x57, 0x13},
			regs: [16]uint64{8: 0x1020304050607080},
			dst:  8,
			want: 0x1020304050601357,
		},
		{
			name: "PE64 extended byte register",
			code: []byte{0x45, 0x88, 0xC8},
			regs: [16]uint64{
				8: 0x1020304050607080,
				9: 0x90807060504030E1,
			},
			dst:  8,
			want: 0x10203040506070E1,
		},
		{
			name: "PE64 extended word register",
			code: []byte{0x66, 0x45, 0x8B, 0xC1},
			regs: [16]uint64{
				8: 0x1020304050607080,
				9: 0x9080706050401357,
			},
			dst:  8,
			want: 0x1020304050601357,
		},
		{
			name:   "PE32 byte immediate",
			mode32: true,
			code:   []byte{0xB0, 0x5A},
			regs:   [16]uint64{0: 0x1122334455667788},
			dst:    0,
			want:   0x112233445566775A,
		},
		{
			name:   "PE32 word register",
			mode32: true,
			code:   []byte{0x66, 0x8B, 0xC1},
			regs: [16]uint64{
				0: 0x1122334455667788,
				1: 0x887766554433A5B6,
			},
			dst:  0,
			want: 0x112233445566A5B6,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			closure := runNativePartialMOV(t, false, test.mode32, test.code, test.regs, initialFlags)
			native := runNativePartialMOV(t, true, test.mode32, test.code, test.regs, initialFlags)
			if native != closure {
				t.Fatalf("native=%+v closure=%+v", native, closure)
			}
			if native.regs[test.dst] != test.want {
				t.Fatalf("register %d=%#x, want %#x", test.dst, native.regs[test.dst], test.want)
			}
			if native.flags != initialFlags || native.instret != 2 || native.fallback {
				t.Fatalf("partial MOV state=%+v", native)
			}
		})
	}
}
