package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestWindowsContextSaveUsesLiteralAMD64Offsets(t *testing.T) {
	mem := mmu.New()
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	mem.Write32(contextAddress+0x34, 0xa1b2c3d4)
	mem.Write64(contextAddress+0x48, 0x1020304050607080)
	cpu := New(mem)
	cpu.Rflags = 0x246
	cpu.Regs[RAX] = 0x1111222233334444
	cpu.Regs[RSP] = 0x5555666677778888
	cpu.RIP = 0x9999aaaabbbbcccc
	cpu.XMM[6] = [2]uint64{0x610, 0x618}
	cpu.XMM[15] = [2]uint64{0xf10, 0xf18}

	if err := cpu.SaveContext(mem, contextAddress); err != nil {
		t.Fatal(err)
	}
	check32 := func(offset uint64, want uint32) {
		t.Helper()
		got, err := mem.Read32(contextAddress + offset)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("CONTEXT +%#x = %#x, want %#x", offset, got, want)
		}
	}
	check64 := func(offset, want uint64) {
		t.Helper()
		got, err := mem.Read64(contextAddress + offset)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("CONTEXT +%#x = %#x, want %#x", offset, got, want)
		}
	}

	check32(0x00, 0)
	check32(0x30, 0x10000b)
	check32(0x34, 0xa1b2c3d4)
	check32(0x44, 0x246)
	check64(0x48, 0x1020304050607080)
	check64(0x78, cpu.Regs[RAX])
	check64(0x98, cpu.Regs[RSP])
	check64(0xf8, cpu.RIP)
	check64(0x200, cpu.XMM[6][0])
	check64(0x208, cpu.XMM[6][1])
	check64(0x290, cpu.XMM[15][0])
	check64(0x298, cpu.XMM[15][1])
}

func TestWindowsContextRestoreUsesLiteralAMD64Offsets(t *testing.T) {
	mem := mmu.New()
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	mem.Write32(contextAddress+0x30, 0x10000b)
	mem.Write32(contextAddress+0x34, 0xa1b2c3d4)
	mem.Write32(contextAddress+0x44, 0x202)
	mem.Write64(contextAddress+0x48, 0x1020304050607080)
	mem.Write64(contextAddress+0x78, 0x1111222233334444)
	mem.Write64(contextAddress+0x98, 0x5555666677778888)
	mem.Write64(contextAddress+0xf8, 0x9999aaaabbbbcccc)
	mem.Write64(contextAddress+0x200, 0x610)
	mem.Write64(contextAddress+0x208, 0x618)
	mem.Write64(contextAddress+0x290, 0xf10)
	mem.Write64(contextAddress+0x298, 0xf18)

	cpu := New(mem)
	if err := cpu.RestoreContext(mem, contextAddress); err != nil {
		t.Fatal(err)
	}
	if cpu.Rflags != 0x202 ||
		cpu.Regs[RAX] != 0x1111222233334444 ||
		cpu.Regs[RSP] != 0x5555666677778888 ||
		cpu.RIP != 0x9999aaaabbbbcccc {
		t.Fatalf("restored integer context = %#v", cpu)
	}
	if cpu.XMM[6] != [2]uint64{0x610, 0x618} ||
		cpu.XMM[15] != [2]uint64{0xf10, 0xf18} {
		t.Fatalf("restored XMM6=%#v XMM15=%#v", cpu.XMM[6], cpu.XMM[15])
	}
}

func TestWindowsContextRoundTripPreservesNonvolatileXMM(t *testing.T) {
	mem := mmu.New()
	contextAddress := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
	cpu := New(mem)
	for index := range cpu.XMM {
		cpu.XMM[index] = [2]uint64{
			0x1000000000000000 + uint64(index),
			0x2000000000000000 + uint64(index),
		}
	}
	if err := cpu.SaveContext(mem, contextAddress); err != nil {
		t.Fatal(err)
	}
	cpu.XMM = [16][2]uint64{}
	if err := cpu.RestoreContext(mem, contextAddress); err != nil {
		t.Fatal(err)
	}
	for index := 6; index <= 15; index++ {
		want := [2]uint64{
			0x1000000000000000 + uint64(index),
			0x2000000000000000 + uint64(index),
		}
		if cpu.XMM[index] != want {
			t.Fatalf("XMM%d = %#v, want %#v", index, cpu.XMM[index], want)
		}
	}
}
