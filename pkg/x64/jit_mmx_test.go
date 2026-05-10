package x64

import (
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestJITMMXMatchesInterpreter(t *testing.T) {
	tests := []struct {
		name string
		code []byte
	}{
		{"punpcklwd", []byte{0x0F, 0x61, 0xC0}},
		{"packssdw", []byte{0x0F, 0x6B, 0xC0}},
		{"movd", []byte{0x0F, 0x6E, 0xC0}},
		{"movq-load-mm2", []byte{0x0F, 0x6F, 0x13}},
		{"movq-load-mm3", []byte{0x0F, 0x6F, 0x1B}},
		{"psllw", []byte{0x0F, 0x71, 0xF2, 3}},
		{"emms", []byte{0x0F, 0x77}},
		{"movq-store", []byte{0x0F, 0x7F, 0x13}},
		{"pmulhw-mm2", []byte{0x0F, 0xE5, 0xD0}},
		{"pmulhw-mm3", []byte{0x0F, 0xE5, 0xD8}},
		{"paddw", []byte{0x0F, 0xFD, 0xD3}},
		{"punpcklbw", []byte{0x0F, 0x60, 0xC3}},
		{"punpckldq", []byte{0x0F, 0x62, 0xC3}},
		{"packsswb", []byte{0x0F, 0x63, 0xC3}},
		{"pcmpgtb", []byte{0x0F, 0x64, 0xC3}},
		{"pcmpgtw", []byte{0x0F, 0x65, 0xC3}},
		{"pcmpgtd", []byte{0x0F, 0x66, 0xC3}},
		{"packuswb", []byte{0x0F, 0x67, 0xC3}},
		{"punpckhbw", []byte{0x0F, 0x68, 0xC3}},
		{"punpckhwd", []byte{0x0F, 0x69, 0xC3}},
		{"punpckhdq", []byte{0x0F, 0x6A, 0xC3}},
		{"pshufw", []byte{0x0F, 0x70, 0xC3, 0x1B}},
		{"psrlw-imm", []byte{0x0F, 0x71, 0xD3, 3}},
		{"psraw-imm", []byte{0x0F, 0x71, 0xE3, 3}},
		{"psrld-imm", []byte{0x0F, 0x72, 0xD3, 5}},
		{"pslld-imm", []byte{0x0F, 0x72, 0xF3, 5}},
		{"psrlq-imm", []byte{0x0F, 0x73, 0xD3, 7}},
		{"psllq-imm", []byte{0x0F, 0x73, 0xF3, 7}},
		{"pcmpeqb", []byte{0x0F, 0x74, 0xC3}},
		{"pcmpeqw", []byte{0x0F, 0x75, 0xC3}},
		{"pcmpeqd", []byte{0x0F, 0x76, 0xC3}},
		{"psrlw-mm", []byte{0x0F, 0xD1, 0xC1}},
		{"psrlw-mm-large", []byte{0x0F, 0xD1, 0xC3}},
		{"psrld-mm", []byte{0x0F, 0xD2, 0xC1}},
		{"psrlq-mm", []byte{0x0F, 0xD3, 0xC1}},
		{"paddq", []byte{0x0F, 0xD4, 0xC3}},
		{"pmullw", []byte{0x0F, 0xD5, 0xC3}},
		{"psubusb", []byte{0x0F, 0xD8, 0xC3}},
		{"psubusw", []byte{0x0F, 0xD9, 0xC3}},
		{"psubusw-mem", []byte{0x0F, 0xD9, 0x13}},
		{"pminub", []byte{0x0F, 0xDA, 0xC3}},
		{"pand", []byte{0x0F, 0xDB, 0xC3}},
		{"paddusb", []byte{0x0F, 0xDC, 0xC3}},
		{"paddusw", []byte{0x0F, 0xDD, 0xC3}},
		{"pmaxub", []byte{0x0F, 0xDE, 0xC3}},
		{"pandn", []byte{0x0F, 0xDF, 0xC3}},
		{"pavgb", []byte{0x0F, 0xE0, 0xC3}},
		{"psraw-mm", []byte{0x0F, 0xE1, 0xC1}},
		{"psrad-mm", []byte{0x0F, 0xE2, 0xC1}},
		{"pavgw", []byte{0x0F, 0xE3, 0xC3}},
		{"pmulhuw", []byte{0x0F, 0xE4, 0xC3}},
		{"movntq", []byte{0x0F, 0xE7, 0x13}},
		{"psubsb", []byte{0x0F, 0xE8, 0xC3}},
		{"psubsw", []byte{0x0F, 0xE9, 0xC3}},
		{"pminsw", []byte{0x0F, 0xEA, 0xC3}},
		{"por", []byte{0x0F, 0xEB, 0xC3}},
		{"paddsb", []byte{0x0F, 0xEC, 0xC3}},
		{"paddsw", []byte{0x0F, 0xED, 0xC3}},
		{"pmaxsw", []byte{0x0F, 0xEE, 0xC3}},
		{"pxor", []byte{0x0F, 0xEF, 0xC3}},
		{"psllw-mm", []byte{0x0F, 0xF1, 0xC1}},
		{"pslld-mm", []byte{0x0F, 0xF2, 0xC1}},
		{"psllq-mm", []byte{0x0F, 0xF3, 0xC1}},
		{"pmuludq", []byte{0x0F, 0xF4, 0xC3}},
		{"pmaddwd", []byte{0x0F, 0xF5, 0xC3}},
		{"psadbw", []byte{0x0F, 0xF6, 0xC3}},
		{"psubb", []byte{0x0F, 0xF8, 0xC3}},
		{"psubw", []byte{0x0F, 0xF9, 0xC3}},
		{"psubd", []byte{0x0F, 0xFA, 0xC3}},
		{"paddb", []byte{0x0F, 0xFC, 0xC3}},
		{"paddd", []byte{0x0F, 0xFE, 0xC3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			interpreted, interpretedMem := newMMXTestCPU(t, test.code)
			compiled, compiledMem := newMMXTestCPU(t, test.code)
			if err := interpreted.step(); err != nil {
				t.Fatal(err)
			}
			compiler := NewJITCompiler(compiled, compiledMem)
			block := compiler.cache.Compile(compiled.RIP)
			if block == nil {
				t.Fatal("MMX block was not compiled")
			}
			if err := block.Run(&compiler.state); err != nil {
				t.Fatal(err)
			}
			if mmxBits(compiled.fpuST) != mmxBits(interpreted.fpuST) || compiled.fpuTop != interpreted.fpuTop || compiled.fpuTW != interpreted.fpuTW {
				t.Fatalf("compiled MMX state differs: ST=%x top=%d tag=%#x, want ST=%x top=%d tag=%#x",
					mmxBits(compiled.fpuST), compiled.fpuTop, compiled.fpuTW,
					mmxBits(interpreted.fpuST), interpreted.fpuTop, interpreted.fpuTW)
			}
			got, err := compiledMem.Read64(0x9000)
			if err != nil {
				t.Fatal(err)
			}
			want, err := interpretedMem.Read64(0x9000)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("memory=%#x, want %#x", got, want)
			}
		})
	}
}

func newMMXTestCPU(t *testing.T, instruction []byte) (*CPU, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	mem.MapPage(0x8000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.MapPage(0x9000, mmu.PermRead|mmu.PermWrite)
	code := append(append([]byte{}, instruction...), 0xEB, 0xFE)
	for i, value := range code {
		if err := mem.Write8(0x8000+uint64(i), value); err != nil {
			t.Fatal(err)
		}
	}
	if err := mem.Write64(0x9000, 0x123456789ABCDEF0); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.Mode32 = true
	cpu.RIP = 0x8000
	cpu.Regs[RAX] = 0x89ABCDEF
	cpu.Regs[RBX] = 0x9000
	values := [8]uint64{0x000180007FFF0002, 0, 0x1000200030004000, 0xFFFF00010002FFFE}
	for i, value := range values {
		cpu.fpuST[i] = math.Float64frombits(value)
	}
	cpu.fpuTop = 0
	cpu.fpuTW = 0
	return cpu, mem
}

func mmxBits(values [8]float64) [8]uint64 {
	var result [8]uint64
	for i, value := range values {
		result[i] = math.Float64bits(value)
	}
	return result
}
