package mmu

import (
	"testing"
)

func TestMunmap(t *testing.T) {
	m := New()
	m.MapPage(0x1000, PermRead|PermWrite)
	m.MapPage(0x2000, PermRead|PermWrite)

	// Write to both
	m.Write8(0x1000, 42)
	m.Write8(0x2000, 99)

	// Unmap the first page
	m.Munmap(0x1000, PageSize)

	// First page should now fault
	_, err := m.Read8(0x1000)
	if err == nil {
		t.Fatal("Expected fault on unmapped page")
	}

	// Second page should still work
	val, err := m.Read8(0x2000)
	if err != nil || val != 99 {
		t.Fatalf("Expected 99, got %d err=%v", val, err)
	}
}

func TestMprotect(t *testing.T) {
	m := New()
	m.MapPage(0x3000, PermRead|PermWrite)
	m.Write8(0x3000, 7)

	// Remove write permission
	m.Mprotect(0x3000, PageSize, PermRead)

	// Read should work
	val, err := m.Read8(0x3000)
	if err != nil || val != 7 {
		t.Fatalf("Read: expected 7, got %d err=%v", val, err)
	}

	// Write should fault
	err = m.Write8(0x3000, 8)
	if err == nil {
		t.Fatal("Expected fault on write to read-only page")
	}
}

func TestHighCanonicalRangeOperations(t *testing.T) {
	m := New()
	const page = uint64(0xfffffffffffff000)
	m.MapRange(page, PageSize, PermRead|PermWrite|PermExecute)
	if err := m.Write8(page+17, 0x7a); err != nil {
		t.Fatal(err)
	}

	m.MapRangeZero(page, PageSize, PermRead|PermWrite|PermExecute)
	if got, err := m.Read8(page + 17); err != nil || got != 0 {
		t.Fatalf("zeroed byte = %#x, err=%v", got, err)
	}
	if err := m.Mprotect(page, PageSize, PermRead|PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(page+17, 1); err == nil {
		t.Fatal("write succeeded after high canonical Mprotect")
	}

	m.Munmap(page, PageSize)
	if _, err := m.Read8(page + 17); err == nil {
		t.Fatal("read succeeded after high canonical Munmap")
	}
}

func TestMultiByteAccessRejectsAddressWrap(t *testing.T) {
	m := New()
	const page = uint64(0xfffffffffffff000)
	if err := m.MapPage(page, PermRead|PermWrite|PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(0, PermRead|PermWrite|PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(^uint64(0), 0xaa); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(0, 0x55); err != nil {
		t.Fatal(err)
	}

	writes := []struct {
		name string
		fn   func() error
	}{
		{name: "Write16", fn: func() error { return m.Write16(^uint64(0), 0x1234) }},
		{name: "Write32", fn: func() error { return m.Write32(^uint64(0), 0x12345678) }},
		{name: "Write64", fn: func() error { return m.Write64(^uint64(0), 0x123456789abcdef0) }},
		{name: "WriteBytes", fn: func() error { return m.WriteBytes(^uint64(0), []byte{1, 2}) }},
		{name: "Write32Raw", fn: func() error { return m.Write32Raw(^uint64(0), 0x12345678) }},
		{name: "Write64Raw", fn: func() error { return m.Write64Raw(^uint64(0), 0x123456789abcdef0) }},
		{name: "WriteBytesRaw", fn: func() error { return m.WriteBytesRaw(^uint64(0), []byte{1, 2}) }},
	}
	for _, tt := range writes {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("wrapped write succeeded")
			}
			high, highErr := m.Read8(^uint64(0))
			low, lowErr := m.Read8(0)
			if highErr != nil || lowErr != nil || high != 0xaa || low != 0x55 {
				t.Fatalf("wrapped write changed memory: high=%#x err=%v low=%#x err=%v", high, highErr, low, lowErr)
			}
		})
	}

	reads := []struct {
		name string
		fn   func() error
	}{
		{name: "Read16", fn: func() error { _, err := m.Read16(^uint64(0)); return err }},
		{name: "Read32", fn: func() error { _, err := m.Read32(^uint64(0)); return err }},
		{name: "Read64", fn: func() error { _, err := m.Read64(^uint64(0)); return err }},
		{name: "ReadBytes", fn: func() error { _, err := m.ReadBytes(^uint64(0), 2); return err }},
		{name: "ReadBytesRaw", fn: func() error { _, err := m.ReadBytesRaw(^uint64(0), 2); return err }},
		{name: "Fetch16", fn: func() error { _, err := m.Fetch16(^uint64(0)); return err }},
		{name: "Fetch32", fn: func() error { _, err := m.Fetch32(^uint64(0)); return err }},
		{name: "Fetch64", fn: func() error { _, err := m.Fetch64(^uint64(0)); return err }},
	}
	for _, tt := range reads {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("wrapped read succeeded")
			}
		})
	}
}

func TestZeroLengthByteAccessRejectsNonCanonicalAddress(t *testing.T) {
	m := New()
	const nonCanonical = uint64(1) << 47

	tests := []struct {
		name string
		fn   func() error
	}{
		{name: "WriteBytes", fn: func() error { return m.WriteBytes(nonCanonical, nil) }},
		{name: "WriteBytesRaw", fn: func() error { return m.WriteBytesRaw(nonCanonical, nil) }},
		{name: "ReadBytes", fn: func() error { _, err := m.ReadBytes(nonCanonical, 0); return err }},
		{name: "ReadBytesRaw", fn: func() error { _, err := m.ReadBytesRaw(nonCanonical, 0); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("zero-length access accepted a non-canonical address")
			}
		})
	}
}

func TestWriteRangeValidationIsAtomic(t *testing.T) {
	const page = uint64(0x50000)
	m := New()
	m.MapRange(page, 2*PageSize, PermRead|PermWrite)
	if err := m.Mprotect(page+PageSize, PageSize, PermRead); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		size int
		fn   func(uint64) error
	}{
		{name: "Write16", size: 2, fn: func(addr uint64) error { return m.Write16(addr, 0x1234) }},
		{name: "Write32", size: 4, fn: func(addr uint64) error { return m.Write32(addr, 0x12345678) }},
		{name: "Write64", size: 8, fn: func(addr uint64) error { return m.Write64(addr, 0x123456789abcdef0) }},
		{name: "WriteBytes", size: 8, fn: func(addr uint64) error {
			return m.WriteBytes(addr, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := page + PageSize - uint64(tt.size/2)
			initial := make([]byte, tt.size)
			for i := range initial {
				initial[i] = byte(0x80 + i)
			}
			if err := m.WriteBytesRaw(addr, initial); err != nil {
				t.Fatal(err)
			}
			err := tt.fn(addr)
			fault, ok := err.(*Fault)
			if !ok || *fault != (Fault{
				Addr: page + PageSize, Type: FaultPermission, Perms: PermRead,
			}) {
				t.Fatalf("fault=%T %v", err, err)
			}
			got, err := m.ReadBytesRaw(addr, tt.size)
			if err != nil {
				t.Fatal(err)
			}
			for i := range got {
				if got[i] != initial[i] {
					t.Fatalf("byte %d changed from %#x to %#x", i, initial[i], got[i])
				}
			}
		})
	}
}

func TestIsMapped(t *testing.T) {
	m := New()
	if m.IsMapped(0x5000) {
		t.Fatal("Should not be mapped")
	}
	m.MapPage(0x5000, PermRead)
	if !m.IsMapped(0x5000) {
		t.Fatal("Should be mapped")
	}
}

func TestMmapAllocatesAligned(t *testing.T) {
	m := New()
	addr := m.Mmap(0, 0x10000, PermRead|PermWrite)
	if addr == 0 {
		t.Fatal("Mmap returned 0")
	}
	if addr&(PageSize-1) != 0 {
		t.Fatalf("Mmap returned unaligned address: 0x%x", addr)
	}
	// Should be able to write to it
	err := m.Write8(addr, 42)
	if err != nil {
		t.Fatal(err)
	}
}
