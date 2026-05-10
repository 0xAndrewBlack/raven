package x64

import "testing"

func TestMMXPackedAddSubtractKeepLaneBoundaries(t *testing.T) {
	tests := []struct {
		name string
		op   byte
		dst  uint64
		src  uint64
		want uint64
	}{
		{name: "paddb", op: 0xFC, dst: 0xFFFFFFFFFFFFFFFF, src: 0x0101010101010101, want: 0},
		{name: "paddw", op: 0xFD, dst: 0xFFFFFFFFFFFFFFFF, src: 0x0001000100010001, want: 0},
		{name: "paddd", op: 0xFE, dst: 0xFFFFFFFFFFFFFFFF, src: 0x0000000100000001, want: 0},
		{name: "psubb", op: 0xF8, dst: 0, src: 0x0101010101010101, want: 0xFFFFFFFFFFFFFFFF},
		{name: "psubw", op: 0xF9, dst: 0, src: 0x0001000100010001, want: 0xFFFFFFFFFFFFFFFF},
		{name: "psubd", op: 0xFA, dst: 0, src: 0x0000000100000001, want: 0xFFFFFFFFFFFFFFFF},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, []byte{0x0F, test.op, 0xC1})
			cpu.writeMMX(0, test.dst)
			cpu.writeMMX(1, test.src)
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if got := cpu.readMMX(0); got != test.want {
				t.Fatalf("MM0=%#x, want %#x", got, test.want)
			}
		})
	}
}
