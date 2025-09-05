package mmu

import "testing"

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
	// write raw bytes (we need write permission temporarily)
	m.pages[0x1000].Data[0] = 0x13 // addi x0, x0, 0  (NOP in RISC-V)
	m.pages[0x1000].Data[1] = 0x00
	m.pages[0x1000].Data[2] = 0x00
	m.pages[0x1000].Data[3] = 0x00

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
