package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func newLegacy32CPU(t *testing.T, code []byte) *CPU {
	t.Helper()
	mem := mmu.New()
	mem.MapRange(0x1000, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
	if err := mem.WriteBytesRaw(0x1000, code); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.Mode32 = true
	cpu.RIP = 0x1000
	return cpu
}

func TestCloneForThreadPreservesModeWithoutReturnSentinel(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x90})
	cpu.ExpectedReturnPC = 0xFFFFFFF0
	cpu.ExpectedReturnSP = 0x2000

	clone, ok := cpu.CloneForThread().(*CPU)
	if !ok {
		t.Fatal("thread clone has unexpected CPU type")
	}
	if !clone.Mode32 {
		t.Fatal("thread clone lost 32-bit execution mode")
	}
	if clone.ExpectedReturnPC != 0 {
		t.Fatalf("thread clone inherited return sentinel 0x%x", clone.ExpectedReturnPC)
	}
	if clone.ExpectedReturnSP != 0 {
		t.Fatalf("thread clone inherited return stack pointer 0x%x", clone.ExpectedReturnSP)
	}
}

func TestLegacyIncDecPreserveCarry(t *testing.T) {
	for _, tt := range []struct {
		name string
		op   byte
	}{
		{name: "inc", op: 0x40},
		{name: "dec", op: 0x48},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, []byte{tt.op})
			cpu.Rflags = flagCF
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if cpu.Rflags&flagCF == 0 {
				t.Fatal("carry flag was cleared")
			}
		})
	}
}

func TestLegacyXchgUsesDwordOperands(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x92})
	cpu.Regs[RAX] = 0xAAAAAAAA11223344
	cpu.Regs[RDX] = 0xBBBBBBBB55667788
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RAX] != 0x55667788 || cpu.Regs[RDX] != 0x11223344 {
		t.Fatalf("EAX=0x%x EDX=0x%x", cpu.Regs[RAX], cpu.Regs[RDX])
	}
}

func TestLegacyXLATWrapsAddress(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0xD7})
	cpu.mem.MapRange(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RBX] = 0xffffffff
	cpu.Regs[RAX] = 1
	if err := cpu.mem.Write8(0, 0x7a); err != nil {
		t.Fatal(err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if got := byte(cpu.Regs[RAX]); got != 0x7a {
		t.Fatalf("AL=0x%x, want 0x7a", got)
	}
}

func TestLegacyOperandSizeOverride(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x66, 0x40, 0x66, 0x92})
	cpu.Regs[RAX] = 0xAAAAFFFF
	cpu.Regs[RDX] = 0xBBBB1234
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RAX] != 0xAAAA0000 {
		t.Fatalf("INC AX produced RAX=0x%x", cpu.Regs[RAX])
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RAX] != 0xAAAA1234 || cpu.Regs[RDX] != 0xBBBB0000 {
		t.Fatalf("XCHG AX,DX produced RAX=0x%x RDX=0x%x", cpu.Regs[RAX], cpu.Regs[RDX])
	}
}

func TestLegacyPushPopESUsesDwordStackSlots(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x06, 0x07})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RSP] = 0x2800
	if err := cpu.mem.Write32(0x27FC, 0xAABBCCDD); err != nil {
		t.Fatal(err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RSP] != 0x27FC {
		t.Fatalf("ESP after PUSH ES = %#x", cpu.Regs[RSP])
	}
	if value, err := cpu.mem.Read32(0x27FC); err != nil || value != 0xAABB0000 {
		t.Fatalf("saved ES selector = %#x, err=%v", value, err)
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RSP] != 0x2800 {
		t.Fatalf("ESP after POP ES = %#x", cpu.Regs[RSP])
	}
}

func TestLegacyPushPopESHonorsOperandSizeOverride(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x66, 0x06, 0x66, 0x07})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu.Regs[RSP] = 0x2800
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RSP] != 0x27FE {
		t.Fatalf("ESP after PUSH ES = %#x", cpu.Regs[RSP])
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RSP] != 0x2800 {
		t.Fatalf("ESP after POP ES = %#x", cpu.Regs[RSP])
	}
}

func TestLegacyIncSetsOverflowAndAuxiliaryCarry(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0x40})
	cpu.Regs[RAX] = 0x7FFFFFFF
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Rflags&flagOF == 0 || cpu.Rflags&flagAF == 0 {
		t.Fatalf("RFLAGS=0x%x, want OF and AF", cpu.Rflags)
	}
}

func TestLegacyJecxzConsumesDisplacement(t *testing.T) {
	for _, tt := range []struct {
		name    string
		ecx     uint64
		wantRIP uint64
	}{
		{name: "not taken", ecx: 1, wantRIP: 0x1002},
		{name: "taken", wantRIP: 0x1007},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cpu := newLegacy32CPU(t, []byte{0xE3, 0x05})
			cpu.Regs[RCX] = tt.ecx
			if err := cpu.step(); err != nil {
				t.Fatal(err)
			}
			if cpu.RIP != tt.wantRIP {
				t.Fatalf("RIP=0x%x, want 0x%x", cpu.RIP, tt.wantRIP)
			}
		})
	}
}

func TestLegacyLoopUpdatesCounterAndBranches(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0xE2, 0xFE})
	cpu.Regs[RCX] = 2
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RCX] != 1 || cpu.RIP != 0x1000 {
		t.Fatalf("ECX=0x%x RIP=0x%x", cpu.Regs[RCX], cpu.RIP)
	}
}

func TestLegacyShrFeedsCarryToAdc(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0xD1, 0xE8, 0x11, 0xC9})
	cpu.Regs[RAX] = 3
	cpu.Regs[RCX] = 2
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Rflags&flagCF == 0 {
		t.Fatal("SHR did not retain the shifted-out bit")
	}
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RCX] != 5 {
		t.Fatalf("ECX=0x%x, want 0x5", cpu.Regs[RCX])
	}
}

func TestLegacyXlatLoadsByteFromTable(t *testing.T) {
	cpu := newLegacy32CPU(t, []byte{0xD7})
	cpu.mem.MapRange(0x2000, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := cpu.mem.Write8(0x202A, 0x7F); err != nil {
		t.Fatal(err)
	}
	cpu.Regs[RBX] = 0x2000
	cpu.Regs[RAX] = 0x1122332A
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if cpu.Regs[RAX] != 0x1122337F {
		t.Fatalf("EAX=0x%x, want 0x1122337f", cpu.Regs[RAX])
	}
}
