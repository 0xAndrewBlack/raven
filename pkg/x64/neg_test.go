package x64

import "testing"

func TestNEGUpdatesCarryAndOverflow(t *testing.T) {
	tests := []struct {
		name    string
		code    []byte
		operand uint64
		want    uint64
		wantCF  bool
		wantOF  bool
		wantAF  bool
	}{
		{name: "byte zero", code: []byte{0x40, 0xF6, 0xDF}},
		{name: "byte nonzero", code: []byte{0x40, 0xF6, 0xDF}, operand: 1, want: 0xFF, wantCF: true, wantAF: true},
		{name: "byte minimum", code: []byte{0x40, 0xF6, 0xDF}, operand: 0x80, want: 0x80, wantCF: true, wantOF: true},
		{name: "word zero", code: []byte{0x66, 0xF7, 0xDF}},
		{name: "word nonzero", code: []byte{0x66, 0xF7, 0xDF}, operand: 1, want: 0xFFFF, wantCF: true, wantAF: true},
		{name: "word minimum", code: []byte{0x66, 0xF7, 0xDF}, operand: 0x8000, want: 0x8000, wantCF: true, wantOF: true},
		{name: "dword zero", code: []byte{0xF7, 0xDF}},
		{name: "dword nonzero", code: []byte{0xF7, 0xDF}, operand: 1, want: 0xFFFFFFFF, wantCF: true, wantAF: true},
		{name: "dword minimum", code: []byte{0xF7, 0xDF}, operand: 0x80000000, want: 0x80000000, wantCF: true, wantOF: true},
		{name: "qword zero", code: []byte{0x48, 0xF7, 0xDF}},
		{name: "qword nonzero", code: []byte{0x48, 0xF7, 0xDF}, operand: 1, want: ^uint64(0), wantCF: true, wantAF: true},
		{name: "qword minimum", code: []byte{0x48, 0xF7, 0xDF}, operand: uint64(1) << 63, want: uint64(1) << 63, wantCF: true, wantOF: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialFlags := uint64(0)
			if !tt.wantCF {
				initialFlags |= flagCF
			}
			if !tt.wantOF {
				initialFlags |= flagOF
			}
			if !tt.wantAF {
				initialFlags |= flagAF
			}
			cpu := runGroup3Multiply(t, tt.code, 0, tt.operand, initialFlags)
			if cpu.Regs[RDI] != tt.want {
				t.Fatalf("result = 0x%x, want 0x%x", cpu.Regs[RDI], tt.want)
			}
			if got := cpu.Rflags&flagCF != 0; got != tt.wantCF {
				t.Fatalf("CF set = %v, want %v", got, tt.wantCF)
			}
			if got := cpu.Rflags&flagOF != 0; got != tt.wantOF {
				t.Fatalf("OF set = %v, want %v", got, tt.wantOF)
			}
			if got := cpu.Rflags&flagAF != 0; got != tt.wantAF {
				t.Fatalf("AF set = %v, want %v", got, tt.wantAF)
			}
		})
	}
}
