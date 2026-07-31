//go:build linux

package mmu

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSharedBackingAliasesSparseGuestPages(t *testing.T) {
	m := New()
	if err := m.EnableSharedBacking(); err != nil {
		t.Fatal(err)
	}
	defer m.CloseSharedBacking()
	const base = 0x400000000000
	for _, addr := range []uint64{base, base + PageSize, 0x10000} {
		if err := m.MapPage(addr, PermRead|PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	m.Write64(base, 0x123456789)
	mappings, err := m.SharedMappings()
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[1].Address != base || mappings[1].Size != 2*PageSize || mappings[1].Offset != 0 {
		t.Fatalf("unexpected sparse mappings: %+v", mappings)
	}
	fd, err := m.SharedFD()
	if err != nil {
		t.Fatal(err)
	}
	alias, err := unix.Mmap(fd, 0, PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(alias)
	if alias[0] != 0x89 || alias[4] != 1 {
		t.Fatalf("guest writes not visible through file mapping: %x", alias[:8])
	}
	alias[7] = 0xAB
	got, err := m.Read8(base + 7)
	if err != nil || got != 0xAB {
		t.Fatalf("external write not visible: got %x, error %v", got, err)
	}
	if err := m.Mprotect(base, PageSize, PermRead); err != nil {
		t.Fatal(err)
	}
	mappings, _ = m.SharedMappings()
	if len(mappings) != 3 || mappings[1].Perms != PermRead {
		t.Fatalf("protection change absent: %+v", mappings)
	}
	m.Munmap(base, PageSize)
	if err := m.MapPage(base, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	got, _ = m.Read8(base + 7)
	if got != 0 || alias[7] != 0 {
		t.Fatal("remapped shared page retained old data")
	}
}

func TestSharedBackingRejectsExistingAndExternalMappings(t *testing.T) {
	m := New()
	m.MapPage(0x10000, PermRead)
	if err := m.EnableSharedBacking(); err == nil {
		t.Fatal("enabled shared backing after mapping pages")
	}
	m = New()
	if err := m.EnableSharedBacking(); err != nil {
		t.Fatal(err)
	}
	defer m.CloseSharedBacking()
	if err := m.EnableFlatBacking(); err == nil {
		t.Fatal("flat backing replaced shared storage")
	}
	m.MapHostSlice(0x20000, make([]byte, PageSize), PermRead|PermWrite)
	if _, err := m.SharedMappings(); err == nil {
		t.Fatal("external slice incorrectly reported as shared backing")
	}
}

func TestCloseSharedBackingInvalidatesOwnedPages(t *testing.T) {
	m := New()
	if err := m.EnableSharedBacking(); err != nil {
		t.Fatal(err)
	}
	defer m.CloseSharedBacking()
	for _, addr := range []uint64{0x10000, 0x20000} {
		if err := m.MapPage(addr, PermRead|PermWrite); err != nil {
			t.Fatal(err)
		}
	}
	m.Write8(0x10000, 91)
	external := make([]byte, PageSize)
	external[0] = 73
	m.MapHostSlice(0x20000, external, PermRead|PermWrite)
	m.MapHostSlice(0x30000, external, PermRead|PermWrite)
	before := m.MappingGeneration()
	if err := m.CloseSharedBacking(); err != nil {
		t.Fatal(err)
	}
	if m.getPage(0x10000) != nil {
		t.Fatal("closed storage remains in the page table")
	}
	if generation := m.MappingGeneration(); generation != before+2 || generation&1 != 0 {
		t.Fatalf("close did not invalidate cached mappings: %d", generation)
	}
	_, err := m.Read8(0x10000)
	fault, ok := err.(*Fault)
	if !ok || fault.Type != FaultUnmapped {
		t.Fatalf("closed page did not produce an unmapped fault: %v", err)
	}
	for _, addr := range []uint64{0x20000, 0x30000} {
		value, err := m.Read8(addr)
		if err != nil || value != 73 {
			t.Fatalf("external mapping removed at %x: value %d, error %v", addr, value, err)
		}
	}
	if err := m.MapPage(0x10000, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	value, err := m.Read8(0x10000)
	if err != nil || value != 0 {
		t.Fatalf("remap retained closed storage: value %d, error %v", value, err)
	}
	if err := m.CloseSharedBacking(); err != nil {
		t.Fatal(err)
	}
}
