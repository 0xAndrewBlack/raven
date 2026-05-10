//go:build guest_windows

package main

import (
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestAcceleratorEntriesRoundTrip(t *testing.T) {
	mem := mmu.New()
	const addr = uint64(0x4000)
	mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	want := []accelEntry{
		{fVirt: 0x09, key: 'S', cmd: 100},
		{fVirt: 0x11, key: 0x70, cmd: 200},
	}
	if !writeAcceleratorEntries(mem, addr, want) {
		t.Fatal("writeAcceleratorEntries returned false")
	}
	got, ok := readAcceleratorEntries(mem, addr, len(want))
	if !ok || len(got) != len(want) {
		t.Fatalf("read %d entries, ok %v", len(got), ok)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
		padding, err := mem.Read8(addr + uint64(i)*6 + 1)
		if err != nil || padding != 0 {
			t.Fatalf("entry %d padding = %#x, err %v", i, padding, err)
		}
	}
}

func TestAcceleratorEntriesRejectInvalidMemory(t *testing.T) {
	mem := mmu.New()
	if _, ok := readAcceleratorEntries(mem, 0x4000, 1); ok {
		t.Fatal("readAcceleratorEntries accepted unmapped memory")
	}
	if writeAcceleratorEntries(mem, 0x4000, []accelEntry{{key: 'A'}}) {
		t.Fatal("writeAcceleratorEntries accepted unmapped memory")
	}
	mem.MapRange(0x4000, mmu.PageSize, mmu.PermRead)
	if writeAcceleratorEntries(mem, 0x4000, []accelEntry{{key: 'A'}}) {
		t.Fatal("writeAcceleratorEntries accepted read-only memory")
	}
	if _, ok := readAcceleratorEntries(mem, 0x4000, 0); ok {
		t.Fatal("readAcceleratorEntries accepted an empty table")
	}
	if _, ok := readAcceleratorEntries(mem, 0x4000, maxAcceleratorEntries+1); ok {
		t.Fatal("readAcceleratorEntries accepted an oversized table")
	}
}

func TestAcceleratorWriteRejectsPartiallyMappedBuffer(t *testing.T) {
	mem := mmu.New()
	const page = uint64(0x4000)
	mem.MapRange(page, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	addr := page + mmu.PageSize - 3
	if err := mem.WriteBytes(addr, []byte{0xaa, 0xbb, 0xcc}); err != nil {
		t.Fatal(err)
	}
	if writeAcceleratorEntries(mem, addr, []accelEntry{{fVirt: 1, key: 'A', cmd: 2}}) {
		t.Fatal("writeAcceleratorEntries accepted a partially mapped buffer")
	}
	got, err := mem.ReadBytes(addr, 3)
	if err != nil || string(got) != "\xaa\xbb\xcc" {
		t.Fatalf("mapped bytes changed to %x, err %v", got, err)
	}
}

func TestLoadNamedResource(t *testing.T) {
	mem := mmu.New()
	const (
		moduleBase   = uint64(0x4000)
		resourceRVA  = uint32(0x1000)
		resourceBase = moduleBase + uint64(resourceRVA)
		dataAddr     = uint64(0x7000)
	)
	mem.MapRange(moduleBase, mmu.PageSize*4, mmu.PermRead|mmu.PermWrite)
	write16 := func(addr uint64, value uint16) {
		t.Helper()
		if err := mem.Write16(addr, value); err != nil {
			t.Fatal(err)
		}
	}
	write32 := func(addr uint64, value uint32) {
		t.Helper()
		if err := mem.Write32(addr, value); err != nil {
			t.Fatal(err)
		}
	}

	write16(resourceBase+14, 1)
	write32(resourceBase+16, 9)
	write32(resourceBase+20, 0x80000100)
	typeDir := resourceBase + 0x100
	write16(typeDir+12, 1)
	write32(typeDir+16, 0x80000200)
	write32(typeDir+20, 0x80000300)
	nameAddr := resourceBase + 0x200
	write16(nameAddr, 4)
	for i, char := range []uint16{'T', 'E', 'S', 'T'} {
		write16(nameAddr+2+uint64(i)*2, char)
	}
	languageDir := resourceBase + 0x300
	write16(languageDir+14, 1)
	write32(languageDir+16, 1033)
	write32(languageDir+20, 0x400)
	write32(resourceBase+0x400, uint32(dataAddr-moduleBase))
	write32(resourceBase+0x404, 8)
	if err := mem.WriteBytes(dataAddr, []byte("resource")); err != nil {
		t.Fatal(err)
	}

	addr, size, ok := loadNamedResource(mem, moduleBase, resourceRVA, 9, "TEST")
	if !ok || addr != dataAddr || size != 8 {
		t.Fatalf("resource = addr %#x, size %d, ok %v", addr, size, ok)
	}
	addr, size, ok = loadNamedResource(mem, moduleBase, resourceRVA, 9, "test")
	if !ok || addr != dataAddr || size != 8 {
		t.Fatalf("lowercase resource = addr %#x, size %d, ok %v", addr, size, ok)
	}
	if _, _, ok := loadNamedResource(mem, moduleBase, resourceRVA, 9, "MISSING"); ok {
		t.Fatal("loadNamedResource accepted an unknown name")
	}
	if _, ok := findResourceDirectoryEntry(mem, typeDir, resourceBase, 0, string(make([]byte, 4097))); ok {
		t.Fatal("findResourceDirectoryEntry accepted an oversized name")
	}
	write16(typeDir+12, 65535)
	if _, ok := findResourceDirectoryEntry(mem, typeDir, resourceBase, 0, "seventeen-letters"); ok {
		t.Fatal("findResourceDirectoryEntry exceeded its comparison budget")
	}
}

func TestDestroyAcceleratorTableLifecycle(t *testing.T) {
	tables := map[uint64][]accelEntry{7: {{key: 'A', cmd: 1}}}
	var mu sync.RWMutex
	if !destroyAcceleratorTable(tables, &mu, 7) {
		t.Fatal("first destroy failed")
	}
	if destroyAcceleratorTable(tables, &mu, 7) {
		t.Fatal("second destroy succeeded")
	}
	if destroyAcceleratorTable(tables, &mu, 0) {
		t.Fatal("null handle destroy succeeded")
	}
}

func TestModuleResourceRVAConcurrentAccess(t *testing.T) {
	hctx := &HandlerCtx{VfsModuleResRVA: make(map[uint64]uint32)}
	var wg sync.WaitGroup
	for i := uint64(1); i <= 32; i++ {
		wg.Add(1)
		go func(base uint64) {
			defer wg.Done()
			hctx.setModuleResourceRVA(base, uint32(base+100))
			_ = hctx.moduleResourceRVA(base)
		}(i)
	}
	wg.Wait()
	for i := uint64(1); i <= 32; i++ {
		if got := hctx.moduleResourceRVA(i); got != uint32(i+100) {
			t.Fatalf("module %#x resource RVA = %#x", i, got)
		}
	}
}
