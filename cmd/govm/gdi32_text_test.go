//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestOutlineTextMetricSize(t *testing.T) {
	if got := outlineTextMetricSize(true); got != 216 {
		t.Fatalf("PE32 OUTLINETEXTMETRICW size = %d", got)
	}
	if got := outlineTextMetricSize(false); got != 232 {
		t.Fatalf("PE32+ OUTLINETEXTMETRICW size = %d", got)
	}
}

func TestReadExtTextAdvances(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	for i, value := range []int32{8, 1, 12, -2} {
		if err := mem.Write32(addr+uint64(i*4), uint32(value)); err != nil {
			t.Fatal(err)
		}
	}

	x, y, ok := readExtTextAdvances(mem, addr, 2, true)
	if !ok || len(x) != 2 || x[0] != 8 || x[1] != 12 || y[0] != 1 || y[1] != -2 {
		t.Fatalf("advances = x:%v y:%v ok:%v", x, y, ok)
	}
	if _, _, ok := readExtTextAdvances(mem, addr+mmu.PageSize, 1, false); ok {
		t.Fatal("accepted an unmapped advance array")
	}
	if err := mem.Write32(addr+mmu.PageSize-4, 7); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readExtTextAdvances(mem, addr+mmu.PageSize-4, 2, false); ok {
		t.Fatal("accepted a partially mapped advance array")
	}
}

func TestCollapseUTF16Advances(t *testing.T) {
	chars := []uint16{'A', 0xD83D, 0xDE00, 'B'}
	x, y := collapseUTF16Advances(chars, []int32{5, 7, 3, 9}, []int32{1, 2, 4, 8})
	if len(x) != 3 || x[0] != 5 || x[1] != 10 || x[2] != 9 {
		t.Fatalf("horizontal advances = %v", x)
	}
	if len(y) != 3 || y[0] != 1 || y[1] != 6 || y[2] != 8 {
		t.Fatalf("vertical advances = %v", y)
	}
}

func TestDecodeExtTextANSIUsesWindows1252CodeUnits(t *testing.T) {
	got := decodeExtTextANSI([]byte{0xC3, 0xA9})
	if got != "\u00C3\u00A9" || len([]rune(got)) != 2 {
		t.Fatalf("decoded text = %q", got)
	}
}

func TestReadExtTextANSIRejectsPartialMapping(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x8000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write8(addr+mmu.PageSize-1, 0x80); err != nil {
		t.Fatal(err)
	}
	if got, ok := readExtTextANSI(mem, addr+mmu.PageSize-1, 1); !ok || len(got) != 1 || got[0] != 0x80 {
		t.Fatalf("mapped bytes = %x, ok=%v", got, ok)
	}
	if _, ok := readExtTextANSI(mem, addr+mmu.PageSize-1, 2); ok {
		t.Fatal("accepted a partially mapped ANSI string")
	}
	if _, ok := readExtTextANSI(mem, 0, 1); ok {
		t.Fatal("accepted a null ANSI string")
	}
}

func TestReadExtTextUTF16RejectsPartialMapping(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0xC000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write16(addr+mmu.PageSize-2, 'A'); err != nil {
		t.Fatal(err)
	}
	if got, ok := readExtTextUTF16(mem, addr+mmu.PageSize-2, 1); !ok || len(got) != 1 || got[0] != 'A' {
		t.Fatalf("mapped UTF-16 = %x, ok=%v", got, ok)
	}
	if _, ok := readExtTextUTF16(mem, addr+mmu.PageSize-2, 2); ok {
		t.Fatal("accepted a partially mapped UTF-16 string")
	}
	if _, ok := readExtTextUTF16(mem, 0, 1); ok {
		t.Fatal("accepted a null UTF-16 string")
	}
}

func TestExtTextANSITextPreservesRawBytesWithoutAdvances(t *testing.T) {
	raw := []byte{0xC3, 0xA9}
	if got := []byte(extTextANSIText(raw, false)); string(got) != string(raw) {
		t.Fatalf("raw text bytes = %x", got)
	}
	if got := extTextANSIText(raw, true); got != "\u00C3\u00A9" {
		t.Fatalf("explicit-advance text = %q", got)
	}
}
