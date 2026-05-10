//go:build guest_windows

package ntapi

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestPrepareGuestCallStackI386(t *testing.T) {
	mem := mmu.New()
	stack := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	top := stack + 4096
	ret := uint64(0x12345678)
	args := []uint64{0x11, 0x22, 0x33, 0x44}

	sp := prepareGuestCallStack(mem, arch.ArchI386, top, ret, args)
	want := []uint32{uint32(ret), 0x11, 0x22, 0x33, 0x44}
	for i, expected := range want {
		got, err := mem.Read32(sp + uint64(i*4))
		if err != nil || got != expected {
			t.Fatalf("stack[%d] = %#x, %v; want %#x, nil", i, got, err, expected)
		}
	}
}

func TestPrepareGuestCallStackAMD64(t *testing.T) {
	mem := mmu.New()
	stack := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
	top := stack + 4096
	ret := uint64(0x123456789ABCDEF0)
	args := []uint64{1, 2, 3, 4, 0x55, 0x66}

	sp := prepareGuestCallStack(mem, arch.ArchAMD64, top, ret, args)
	if got, err := mem.Read64(sp); err != nil || got != ret {
		t.Fatalf("return address = %#x, %v; want %#x, nil", got, err, ret)
	}
	for i, expected := range args[4:] {
		got, err := mem.Read64(sp + 0x28 + uint64(i*8))
		if err != nil || got != expected {
			t.Fatalf("stack arg %d = %#x, %v; want %#x, nil", i+4, got, err, expected)
		}
	}
}
