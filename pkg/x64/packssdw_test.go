package x64

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestPACKSSDWMMXSaturatesSignedDwords(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0x6b, 0xc1})
	cpu.writeMMX(0, uint64(uint32(40000))|uint64(uint32(0xffff63c0))<<32)
	cpu.writeMMX(1, uint64(uint32(1234))|uint64(uint32(0xfffffb2e))<<32)
	cpu.XMM[0] = [2]uint64{0x1111222233334444, 0x5555666677778888}

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, want := cpu.readMMX(0), uint64(0xfb2e04d280007fff); got != want {
		t.Fatalf("PACKSSDW mm result = %#x, want %#x", got, want)
	}
	if got, want := cpu.XMM[0], [2]uint64{0x1111222233334444, 0x5555666677778888}; got != want {
		t.Fatalf("PACKSSDW changed XMM0 to %#x", got)
	}
}

func TestPACKSSDWXMMPacksBothOperands(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x66, 0x0f, 0x6b, 0xc1})
	cpu.XMM[0] = [2]uint64{uint64(uint32(1)) | uint64(uint32(2))<<32, uint64(uint32(3)) | uint64(uint32(4))<<32}
	cpu.XMM[1] = [2]uint64{uint64(uint32(5)) | uint64(uint32(6))<<32, uint64(uint32(7)) | uint64(uint32(8))<<32}

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, want := cpu.XMM[0], [2]uint64{0x0004000300020001, 0x0008000700060005}; got != want {
		t.Fatalf("PACKSSDW xmm result = %#x, want %#x", got, want)
	}
}

func TestMMXPackByteInstructionsDoNotUseXMM(t *testing.T) {
	tests := []struct {
		name string
		op   byte
		want uint64
	}{
		{name: "PACKSSWB", op: 0x63, want: 0x807f807f807f807f},
		{name: "PACKUSWB", op: 0x67, want: 0x00ff00ff00ff00ff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, []byte{0x0f, tt.op, 0xc1})
			cpu.writeMMX(0, 0x80007fff80007fff)
			cpu.writeMMX(1, 0x80007fff80007fff)
			cpu.XMM[0] = [2]uint64{1, 2}
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if got := cpu.readMMX(0); got != tt.want {
				t.Fatalf("result = %#x, want %#x", got, tt.want)
			}
			if got := cpu.XMM[0]; got != [2]uint64{1, 2} {
				t.Fatalf("XMM0 changed to %#x", got)
			}
		})
	}
}

func TestMMXPMOVMSKBProducesEightBitMask(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0xd7, 0xc1})
	cpu.writeMMX(1, 0x80ff007f800100ff)
	cpu.XMM[1] = [2]uint64{0, ^uint64(0)}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, want := uint32(cpu.Regs[RAX]), uint32(0xc9); got != want {
		t.Fatalf("mask = %#x, want %#x", got, want)
	}
}

func TestPACKSSDWReturnsMemoryFault(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0x6b, 0x00})
	cpu.Regs[RAX] = 0x90000000
	if err := cpu.step(); err == nil {
		t.Fatal("PACKSSDW accepted an unmapped memory operand")
	}
}

func TestMMXMOVQStoreDoesNotOverwriteFollowingQword(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0x7f, 0x00})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RAX] = 0x2000
	cpu.writeMMX(0, 0x1122334455667788)
	cpu.XMM[0] = [2]uint64{0xaabbccddeeff0011, 0x2233445566778899}
	if err := cpu.mem.Write64(0x2008, 0xdeadbeefcafebabe); err != nil {
		t.Fatal(err)
	}

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, _ := cpu.mem.Read64(0x2000); got != 0x1122334455667788 {
		t.Fatalf("MOVQ stored %#x", got)
	}
	if got, _ := cpu.mem.Read64(0x2008); got != 0xdeadbeefcafebabe {
		t.Fatalf("MOVQ overwrote following qword with %#x", got)
	}
	if got, want := cpu.XMM[0], [2]uint64{0xaabbccddeeff0011, 0x2233445566778899}; got != want {
		t.Fatalf("MOVQ changed XMM0 to %#x", got)
	}
}

func TestMMXMOVQRegisterDoesNotChangeXMM(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0x6f, 0xc1})
	cpu.writeMMX(1, 0x123456789abcdef0)
	cpu.XMM[0] = [2]uint64{1, 2}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := cpu.readMMX(0); got != 0x123456789abcdef0 {
		t.Fatalf("MM0 = %#x", got)
	}
	if got, want := cpu.XMM[0], [2]uint64{1, 2}; got != want {
		t.Fatalf("MOVQ changed XMM0 to %#x", got)
	}
}

func TestMMXInstructionEntersAndEMMSLeavesMMXState(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0x6f, 0xc1, 0x0f, 0x77})
	cpu.fpuTop = 5
	cpu.fpuTW = 0xffff
	cpu.fpuST[1] = math.Float64frombits(0x123456789abcdef0)

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuTop != 0 || cpu.fpuTW != 0 {
		t.Fatalf("MMX state top=%d tag=%#x", cpu.fpuTop, cpu.fpuTW)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.fpuTW != 0xffff {
		t.Fatalf("EMMS tag=%#x", cpu.fpuTW)
	}
}

func TestMMXPINSRWAndPEXTRWUseMMXState(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0xc4, 0xc0, 0x02, 0x0f, 0xc5, 0xc0, 0x02})
	cpu.writeMMX(0, 0x1111222233334444)
	cpu.XMM[0] = [2]uint64{0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb}
	cpu.Regs[RAX] = 0xbeef
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := cpu.readMMX(0); got != 0x1111beef33334444 {
		t.Fatalf("PINSRW MM0 = %#x", got)
	}
	cpu.Regs[RAX] = 0
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := uint32(cpu.Regs[RAX]); got != 0xbeef {
		t.Fatalf("PEXTRW EAX = %#x", got)
	}
	if got, want := cpu.XMM[0], [2]uint64{0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb}; got != want {
		t.Fatalf("MMX instructions changed XMM0 to %#x", got)
	}
}

func TestSSEMOVDQAStoreWritesFullXMM(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x66, 0x0f, 0x7f, 0x00})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RAX] = 0x2000
	cpu.XMM[0] = [2]uint64{0x1122334455667788, 0xaabbccddeeff0011}

	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, _ := cpu.mem.Read64(0x2008); got != 0xaabbccddeeff0011 {
		t.Fatalf("MOVDQA high qword = %#x", got)
	}
}

func TestLegacyMMXPackedOpcodesUseMMX(t *testing.T) {
	tests := []struct {
		name     string
		op       byte
		dst      uint64
		src      uint64
		expected uint64
	}{
		{name: "PUNPCKLBW", op: 0x60, dst: 0x8877665544332211, src: 0x00ffeeddccbbaa99, expected: 0xcc44bb33aa229911},
		{name: "PCMPGTB", op: 0x64, dst: 0x0807060504030201, src: 0x0108070205040300, expected: 0xff0000ff000000ff},
		{name: "PCMPEQW", op: 0x75, dst: 0x4444333322221111, src: 0x4444000022220000, expected: 0xffff0000ffff0000},
		{name: "PADDQ", op: 0xd4, dst: 0xfffffffffffffff0, src: 0x20, expected: 0x10},
		{name: "PMULLW", op: 0xd5, dst: 0x0004000300020001, src: 0x0008000700060005, expected: 0x00200015000c0005},
		{name: "PAND", op: 0xdb, dst: 0xff00ff00aa55aa55, src: 0x0ff00ff0ffff0000, expected: 0x0f000f00aa550000},
		{name: "PANDN", op: 0xdf, dst: 0xff00ff00aa55aa55, src: 0x0ff00ff0ffff0000, expected: 0x00f000f055aa0000},
		{name: "PAVGB", op: 0xe0, dst: 0x00020406080a0c0e, src: 0x020406080a0c0e10, expected: 0x01030507090b0d0f},
		{name: "PMULHUW", op: 0xe4, dst: 0x8000800080008000, src: 0x0002000400080010, expected: 0x0001000200040008},
		{name: "POR", op: 0xeb, dst: 0xf000f00000ff00ff, src: 0x0f000f00ff00ff00, expected: 0xff00ff00ffffffff},
		{name: "PXOR", op: 0xef, dst: 0xffff0000aaaa5555, src: 0x0f0f0f0f33333333, expected: 0xf0f00f0f99996666},
		{name: "PSADBW", op: 0xf6, dst: 0x0807060504030201, src: 0x0102030405060708, expected: 32},
		{name: "PSUBB", op: 0xf8, dst: 0x100f0e0d0c0b0a09, src: 0x0102030405060708, expected: 0x0f0d0b0907050301},
		{name: "PADDW", op: 0xfd, dst: 0xffff000300020001, src: 0x0002000300040005, expected: 0x0001000600060006},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, []byte{0x0f, tt.op, 0xc1})
			cpu.writeMMX(0, tt.dst)
			cpu.writeMMX(1, tt.src)
			before := [2]uint64{0x1122334455667788, 0x99aabbccddeeff00}
			cpu.XMM[0] = before
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if got := cpu.readMMX(0); got != tt.expected {
				t.Fatalf("result = %#x, want %#x", got, tt.expected)
			}
			if got := cpu.XMM[0]; got != before {
				t.Fatalf("XMM0 changed to %#x", got)
			}
		})
	}
}

func TestLegacyMMXImmediateOpcodesUseMMX(t *testing.T) {
	tests := []struct {
		name     string
		code     []byte
		dstReg   int
		value    uint64
		expected uint64
	}{
		{name: "PSHUFW", code: []byte{0x0f, 0x70, 0xc1, 0x1b}, dstReg: 0, value: 0x4444333322221111, expected: 0x1111222233334444},
		{name: "PSRLW", code: []byte{0x0f, 0x71, 0xd1, 0x04}, dstReg: 1, value: 0x8000400020001000, expected: 0x0800040002000100},
		{name: "PSRAD", code: []byte{0x0f, 0x72, 0xe1, 0x04}, dstReg: 1, value: 0x800000007fffffff, expected: 0xf800000007ffffff},
		{name: "PSLLQ", code: []byte{0x0f, 0x73, 0xf1, 0x08}, dstReg: 1, value: 0x0011223344556677, expected: 0x1122334455667700},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, tt.code)
			cpu.writeMMX(1, tt.value)
			before0 := [2]uint64{0x1111111111111111, 0x2222222222222222}
			before1 := [2]uint64{0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb}
			cpu.XMM[0], cpu.XMM[1] = before0, before1
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if got := cpu.readMMX(tt.dstReg); got != tt.expected {
				t.Fatalf("result = %#x, want %#x", got, tt.expected)
			}
			if got := cpu.XMM[0]; got != before0 {
				t.Fatalf("XMM0 changed to %#x", got)
			}
			if got := cpu.XMM[1]; got != before1 {
				t.Fatalf("XMM1 changed to %#x", got)
			}
		})
	}
}

func TestLegacyMMXMemoryOperandReadsOnlyEightBytes(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x0f, 0xdb, 0x08})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RAX] = 0x2ff8
	cpu.writeMMX(1, 0xffff0000ffff0000)
	if err := cpu.mem.Write64(0x2ff8, 0x00ffff0000ffff00); err != nil {
		t.Fatal(err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, want := cpu.readMMX(1), uint64(0x00ff000000ff0000); got != want {
		t.Fatalf("PAND result = %#x, want %#x", got, want)
	}
}

func TestSSE2PackedOpcodeUsesXMMAndPreservesMMX(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x66, 0x0f, 0xfc, 0xc1})
	cpu.writeMMX(0, 0xdeadbeefcafebabe)
	cpu.XMM[0] = [2]uint64{0x0101010101010101, 0x1010101010101010}
	cpu.XMM[1] = [2]uint64{0x0202020202020202, 0x2020202020202020}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got, want := cpu.XMM[0], [2]uint64{0x0303030303030303, 0x3030303030303030}; got != want {
		t.Fatalf("PADDB XMM result = %#x, want %#x", got, want)
	}
	if got, want := cpu.readMMX(0), uint64(0xdeadbeefcafebabe); got != want {
		t.Fatalf("PADDB changed MM0 to %#x", got)
	}
}
