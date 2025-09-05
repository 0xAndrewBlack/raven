package mmu

import (
	"fmt"
	"sync"
)

const (
	PageSize = 4096
	PageMask = ^uint64(PageSize - 1)
)

// Permission flags for memory pages.
const (
	PermRead    uint8 = 1 << 0
	PermWrite   uint8 = 1 << 1
	PermExecute uint8 = 1 << 2
)

// FaultType describes the kind of memory access violation.
type FaultType int

const (
	FaultUnmapped FaultType = iota
	FaultPermission
)

// Fault represents a guest segmentation fault.
type Fault struct {
	Addr  uint64
	Type  FaultType
	Perms uint8
}

func (f *Fault) Error() string {
	kind := "unmapped"
	if f.Type == FaultPermission {
		kind = "permission"
	}
	return fmt.Sprintf("segfault at 0x%x (%s, perms=0x%x)", f.Addr, kind, f.Perms)
}

// PageEntry holds the host-side backing slice and permission bits.
type PageEntry struct {
	Data  []byte
	Perms uint8
}

// MMU is a software memory management unit with page-level permissions.
// It is safe for concurrent use when protected externally or via its own mutex.
type MMU struct {
	mu       sync.RWMutex
	pages    map[uint64]*PageEntry // keyed by page-aligned virtual address
	brkAddr  uint64
	heapBase uint64
}

// New creates an MMU with no mapped pages.
func New() *MMU {
	return &MMU{
		pages: make(map[uint64]*PageEntry),
	}
}

// MapPage allocates a page at the given page-aligned virtual address.
func (m *MMU) MapPage(vaddr uint64, perms uint8) error {
	vaddr &= PageMask
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pages[vaddr]; ok {
		// already mapped - update permissions
		m.pages[vaddr].Perms = perms
		return nil
	}
	m.pages[vaddr] = &PageEntry{
		Data:  make([]byte, PageSize),
		Perms: perms,
	}
	return nil
}

// MapRange maps contiguous pages covering [start, start+size).
func (m *MMU) MapRange(start, size uint64, perms uint8) {
	end := start + size
	for addr := start & PageMask; addr < end; addr += PageSize {
		m.MapPage(addr, perms)
	}
}

// lookupPage returns the page entry for vaddr or a Fault.
func (m *MMU) lookupPage(vaddr uint64, requiredPerms uint8) (*PageEntry, uint64, error) {
	base := vaddr & PageMask
	offset := vaddr - base
	m.mu.RLock()
	pe, ok := m.pages[base]
	m.mu.RUnlock()
	if !ok {
		return nil, 0, &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: requiredPerms}
	}
	if pe.Perms&requiredPerms != requiredPerms {
		return nil, 0, &Fault{Addr: vaddr, Type: FaultPermission, Perms: pe.Perms}
	}
	return pe, offset, nil
}

// Read8 reads a single byte.
func (m *MMU) Read8(vaddr uint64) (uint8, error) {
	pe, off, err := m.lookupPage(vaddr, PermRead)
	if err != nil {
		return 0, err
	}
	return pe.Data[off], nil
}

// Read16 reads a 16-bit little-endian value.
func (m *MMU) Read16(vaddr uint64) (uint16, error) {
	b0, err := m.Read8(vaddr)
	if err != nil {
		return 0, err
	}
	b1, err := m.Read8(vaddr + 1)
	if err != nil {
		return 0, err
	}
	return uint16(b0) | uint16(b1)<<8, nil
}

// Read32 reads a 32-bit little-endian value.
func (m *MMU) Read32(vaddr uint64) (uint32, error) {
	lo, err := m.Read16(vaddr)
	if err != nil {
		return 0, err
	}
	hi, err := m.Read16(vaddr + 2)
	if err != nil {
		return 0, err
	}
	return uint32(lo) | uint32(hi)<<16, nil
}

// Read64 reads a 64-bit little-endian value.
func (m *MMU) Read64(vaddr uint64) (uint64, error) {
	lo, err := m.Read32(vaddr)
	if err != nil {
		return 0, err
	}
	hi, err := m.Read32(vaddr + 4)
	if err != nil {
		return 0, err
	}
	return uint64(lo) | uint64(hi)<<32, nil
}

// Write8 writes a single byte.
func (m *MMU) Write8(vaddr uint64, val uint8) error {
	pe, off, err := m.lookupPage(vaddr, PermWrite)
	if err != nil {
		return err
	}
	pe.Data[off] = val
	return nil
}

// Write16 writes a 16-bit little-endian value.
func (m *MMU) Write16(vaddr uint64, val uint16) error {
	if err := m.Write8(vaddr, uint8(val)); err != nil {
		return err
	}
	return m.Write8(vaddr+1, uint8(val>>8))
}

// Write32 writes a 32-bit little-endian value.
func (m *MMU) Write32(vaddr uint64, val uint32) error {
	if err := m.Write16(vaddr, uint16(val)); err != nil {
		return err
	}
	return m.Write16(vaddr+2, uint16(val>>16))
}

// Write64 writes a 64-bit little-endian value.
func (m *MMU) Write64(vaddr uint64, val uint64) error {
	if err := m.Write32(vaddr, uint32(val)); err != nil {
		return err
	}
	return m.Write32(vaddr+4, uint32(val>>32))
}

// WriteBytes copies a byte slice into guest memory (requires write permission).
func (m *MMU) WriteBytes(vaddr uint64, data []byte) error {
	for i, b := range data {
		if err := m.Write8(vaddr+uint64(i), b); err != nil {
			return err
		}
	}
	return nil
}

// ReadBytes reads n bytes from guest memory.
func (m *MMU) ReadBytes(vaddr uint64, n int) ([]byte, error) {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		b, err := m.Read8(vaddr + uint64(i))
		if err != nil {
			return nil, err
		}
		buf[i] = b
	}
	return buf, nil
}

// Fetch16 reads a 16-bit instruction (requires execute permission).
func (m *MMU) Fetch16(vaddr uint64) (uint16, error) {
	pe, off, err := m.lookupPage(vaddr, PermExecute)
	if err != nil {
		return 0, err
	}
	if off+2 > PageSize {
		pe1, off1, err1 := m.lookupPage(vaddr+1, PermExecute)
		if err1 != nil {
			return 0, err1
		}
		return uint16(pe.Data[off]) | uint16(pe1.Data[off1])<<8, nil
	}
	return uint16(pe.Data[off]) | uint16(pe.Data[off+1])<<8, nil
}

// Fetch32 reads a 32-bit instruction (requires execute permission).
func (m *MMU) Fetch32(vaddr uint64) (uint32, error) {
	pe, off, err := m.lookupPage(vaddr, PermExecute)
	if err != nil {
		return 0, err
	}
	if off+4 > PageSize {
		// crosses page boundary - read byte-by-byte with execute check
		var val uint32
		for i := uint64(0); i < 4; i++ {
			pe2, off2, err2 := m.lookupPage(vaddr+i, PermExecute)
			if err2 != nil {
				return 0, err2
			}
			val |= uint32(pe2.Data[off2]) << (i * 8)
		}
		return val, nil
	}
	return uint32(pe.Data[off]) |
		uint32(pe.Data[off+1])<<8 |
		uint32(pe.Data[off+2])<<16 |
		uint32(pe.Data[off+3])<<24, nil
}

// SetBrk sets the program break address.
func (m *MMU) SetBrk(addr uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.brkAddr = addr
	m.heapBase = addr
}

// Brk adjusts the program break, mapping new pages as needed.
func (m *MMU) Brk(addr uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if addr == 0 || addr < m.heapBase {
		return m.brkAddr
	}
	// map any new pages between old brk and new brk
	oldEnd := m.brkAddr
	for pg := oldEnd & PageMask; pg < addr; pg += PageSize {
		if _, ok := m.pages[pg]; !ok {
			m.pages[pg] = &PageEntry{
				Data:  make([]byte, PageSize),
				Perms: PermRead | PermWrite,
			}
		}
	}
	m.brkAddr = addr
	return m.brkAddr
}

// Mmap allocates anonymous pages at a hint address (simplified).
func (m *MMU) Mmap(addr, length uint64, perms uint8) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	length = (length + PageSize - 1) & PageMask // round up
	if addr == 0 {
		// find a free region above 0x4000_0000_0000
		addr = 0x400000000000
		for {
			conflict := false
			for pg := addr & PageMask; pg < addr+length; pg += PageSize {
				if _, ok := m.pages[pg]; ok {
					conflict = true
					break
				}
			}
			if !conflict {
				break
			}
			addr += length
			addr = (addr + PageSize - 1) & PageMask
		}
	}
	for pg := addr & PageMask; pg < addr+length; pg += PageSize {
		m.pages[pg] = &PageEntry{
			Data:  make([]byte, PageSize),
			Perms: perms,
		}
	}
	return addr
}

// Munmap removes pages covering [addr, addr+length).
func (m *MMU) Munmap(addr, length uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		delete(m.pages, pg)
	}
}

// Mprotect changes permissions on pages covering [addr, addr+length).
func (m *MMU) Mprotect(addr, length uint64, perms uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		pe, ok := m.pages[pg]
		if !ok {
			// Silently skip unmapped - Linux does this
			continue
		}
		pe.Perms = perms
	}
	return nil
}

// WriteBytesRaw copies data into guest memory, temporarily allowing writes.
// Used by the loader and syscall layer for placing data.
func (m *MMU) WriteBytesRaw(vaddr uint64, data []byte) error {
	for i, b := range data {
		addr := vaddr + uint64(i)
		base := addr & PageMask
		offset := addr - base
		m.mu.RLock()
		pe, ok := m.pages[base]
		m.mu.RUnlock()
		if !ok {
			return &Fault{Addr: addr, Type: FaultUnmapped, Perms: PermWrite}
		}
		pe.Data[offset] = b
	}
	return nil
}

// IsMapped checks if an address has a backing page.
func (m *MMU) IsMapped(vaddr uint64) bool {
	base := vaddr & PageMask
	m.mu.RLock()
	_, ok := m.pages[base]
	m.mu.RUnlock()
	return ok
}

// MapHostSlice aliases host memory into the guest address space.
// Instead of allocating new pages, each page's Data slice points directly
// at sub-slices of hostSlice. This enables zero-copy shared memory:
// guest CPU writes go directly to the host-visible buffer.
func (m *MMU) MapHostSlice(guestAddr uint64, hostSlice []byte, perms uint8) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	length := uint64(len(hostSlice))
	if guestAddr == 0 {
		// Find a free region
		guestAddr = 0x500000000000
		for {
			conflict := false
			for pg := guestAddr & PageMask; pg < guestAddr+length; pg += PageSize {
				if _, ok := m.pages[pg]; ok {
					conflict = true
					break
				}
			}
			if !conflict {
				break
			}
			guestAddr += (length + PageSize - 1) & PageMask
		}
	}

	offset := uint64(0)
	for offset < length {
		pgAddr := (guestAddr + offset) & PageMask
		remaining := length - offset
		pageOff := (guestAddr + offset) - pgAddr

		// How much of this page to cover
		sliceLen := PageSize - pageOff
		if sliceLen > remaining {
			sliceLen = remaining
		}

		if pageOff == 0 && sliceLen == PageSize {
			// Full page alias - point directly at host memory
			m.pages[pgAddr] = &PageEntry{
				Data:  hostSlice[offset : offset+PageSize],
				Perms: perms,
			}
		} else {
			// Partial page - need a full page buffer, copy partial
			// This handles the last page if hostSlice isn't page-aligned
			pe, exists := m.pages[pgAddr]
			if !exists {
				pe = &PageEntry{
					Data:  make([]byte, PageSize),
					Perms: perms,
				}
				m.pages[pgAddr] = pe
			}
			copy(pe.Data[pageOff:], hostSlice[offset:offset+sliceLen])
			pe.Perms = perms
		}

		offset += sliceLen
	}

	return guestAddr
}
