package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestFetchCacheObservesExecutePermissionRevocation(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapPage(addr, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if err := mem.Write8(addr, 0x90); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.RIP = addr
	if err := cpu.step(); err != nil {
		t.Fatal(err)
	}
	if err := mem.Mprotect(addr, mmu.PageSize, mmu.PermRead); err != nil {
		t.Fatal(err)
	}
	cpu.RIP = addr
	if err := cpu.step(); err == nil {
		t.Fatal("instruction fetch succeeded after execute permission was revoked")
	}
}

func TestFetch8CrossesPageBoundary(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapRange(addr, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if err := mem.Write8(addr+mmu.PageSize-1, 0x12); err != nil {
		t.Fatal(err)
	}
	if err := mem.Write8(addr+mmu.PageSize, 0x34); err != nil {
		t.Fatal(err)
	}
	cpu := New(mem)
	cpu.RIP = addr + mmu.PageSize - 1
	for _, want := range []byte{0x12, 0x34} {
		got, err := cpu.fetch8()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("fetch8() = %#x, want %#x", got, want)
		}
	}
}

func BenchmarkFetch8CachedPage(b *testing.B) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapPage(addr, mmu.PermRead|mmu.PermExecute)
	cpu := New(mem)
	if _, err := cpu.fetch8Slow(addr); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cpu.RIP = addr
		if _, err := cpu.fetch8(); err != nil {
			b.Fatal(err)
		}
	}
}
