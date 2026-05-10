package mmu

import (
	"sync"
	"testing"
)

func TestFetch64ChecksExecutePermissionAcrossPages(t *testing.T) {
	m := New()
	const addr = uint64(0x1ffc)
	m.MapPage(0x1000, PermRead|PermWrite|PermExecute)
	m.MapPage(0x2000, PermRead|PermWrite)
	for i := uint64(0); i < 8; i++ {
		if err := m.Write8(addr+i, byte(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Fetch64(addr); err == nil {
		t.Fatal("cross-page fetch succeeded through a non-executable page")
	}
	m.Mprotect(0x2000, PageSize, PermRead|PermExecute)
	if _, err := m.Fetch64(addr); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPageLookupsKeepPagesSeparate(t *testing.T) {
	m := New()
	const first = uint64(0x1000)
	const second = first + 1024*PageSize
	m.MapPage(first, PermRead|PermWrite)
	m.MapPage(second, PermRead|PermWrite)
	m.Write8(first, 0x11)
	m.Write8(second, 0x22)

	var wg sync.WaitGroup
	errs := make(chan string, 2)
	read := func(addr uint64, want byte) {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			got, err := m.Read8(addr)
			if err != nil || got != want {
				errs <- "lookup returned the wrong page"
				return
			}
		}
	}
	wg.Add(2)
	go read(first, 0x11)
	go read(second, 0x22)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestMapAndReadWrite(t *testing.T) {
	m := New()
	m.MapPage(0x1000, PermRead|PermWrite)

	if err := m.Write8(0x1000, 0xAB); err != nil {
		t.Fatal(err)
	}
	v, err := m.Read8(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xAB {
		t.Fatalf("expected 0xAB, got 0x%x", v)
	}
}

func TestReadUnmapped(t *testing.T) {
	m := New()
	_, err := m.Read8(0x9000)
	if err == nil {
		t.Fatal("expected fault on unmapped read")
	}
	f, ok := err.(*Fault)
	if !ok {
		t.Fatal("expected *Fault")
	}
	if f.Type != FaultUnmapped {
		t.Fatalf("expected FaultUnmapped, got %d", f.Type)
	}
}

func TestWriteToReadOnly(t *testing.T) {
	m := New()
	m.MapPage(0x2000, PermRead|PermExecute)
	err := m.Write8(0x2000, 0xFF)
	if err == nil {
		t.Fatal("expected fault on write to read-only page")
	}
	f, ok := err.(*Fault)
	if !ok {
		t.Fatal("expected *Fault")
	}
	if f.Type != FaultPermission {
		t.Fatalf("expected FaultPermission, got %d", f.Type)
	}
}

func TestFetch32(t *testing.T) {
	m := New()
	m.MapPage(0x1000, PermRead|PermExecute)
	// write raw bytes using getPage (bypasses permission checks)
	pe := m.getPage(0x1000)
	pe.Data[0] = 0x13 // addi x0, x0, 0  (NOP in RISC-V)
	pe.Data[1] = 0x00
	pe.Data[2] = 0x00
	pe.Data[3] = 0x00

	instr, err := m.Fetch32(0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if instr != 0x00000013 {
		t.Fatalf("expected 0x00000013, got 0x%08x", instr)
	}
}

func TestRead64Write64(t *testing.T) {
	m := New()
	m.MapPage(0x3000, PermRead|PermWrite)
	val := uint64(0xDEADBEEFCAFEBABE)
	if err := m.Write64(0x3000, val); err != nil {
		t.Fatal(err)
	}
	got, err := m.Read64(0x3000)
	if err != nil {
		t.Fatal(err)
	}
	if got != val {
		t.Fatalf("expected 0x%x, got 0x%x", val, got)
	}
}

func TestBrk(t *testing.T) {
	m := New()
	m.SetBrk(0x10000)
	newBrk := m.Brk(0x12000)
	if newBrk != 0x12000 {
		t.Fatalf("expected brk 0x12000, got 0x%x", newBrk)
	}
	// should be writable
	if err := m.Write8(0x11000, 0x42); err != nil {
		t.Fatalf("write to brk region failed: %v", err)
	}
}

func TestFlatBackingAliasesGuestMemory(t *testing.T) {
	m := New()
	if err := m.EnableFlatBacking(); err != nil {
		t.Skipf("flat backing unavailable: %v", err)
	}
	if err := m.MapPage(0x400000, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.Write32(0x400010, 0xDEADBEEF); err != nil {
		t.Fatal(err)
	}
	flat := m.FlatBase()
	if flat == nil {
		t.Fatal("FlatBase is nil after EnableFlatBacking")
	}
	got := uint32(flat[0x400010]) | uint32(flat[0x400011])<<8 | uint32(flat[0x400012])<<16 | uint32(flat[0x400013])<<24
	if got != 0xDEADBEEF {
		t.Fatalf("flat region sees 0x%x, want 0xDEADBEEF", got)
	}
	// Writes through the flat region must be visible to guest reads.
	flat[0x400020] = 0x5A
	v, err := m.Read8(0x400020)
	if err != nil || v != 0x5A {
		t.Fatalf("guest read got 0x%x err=%v, want 0x5A", v, err)
	}
	// Remapping a previously used page must hand back zeroed memory.
	m.Munmap(0x400000, PageSize)
	if err := m.MapPage(0x400000, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	v, err = m.Read8(0x400010)
	if err != nil || v != 0 {
		t.Fatalf("recycled page read got 0x%x err=%v, want 0", v, err)
	}
	// Pages above 4GiB still work via heap backing.
	if err := m.MapPage(1<<33, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.Write32(1<<33, 42); err != nil {
		t.Fatal(err)
	}
}
