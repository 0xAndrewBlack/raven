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
