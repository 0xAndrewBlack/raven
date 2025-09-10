package mmu

import (
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	PageSize  = 4096
	PageMask  = ^uint64(PageSize - 1)
	PageShift = 12

	// Two-level page table: L1 covers top bits, L2 covers remaining bits.
	// We support addresses up to 48 bits (256 TB virtual address space).
	// L1 index = bits [47:27] → 2^21 = 2M entries
	// L2 index = bits [26:12] → 2^15 = 32K entries per L2 table
	l2Bits = 15
	l1Bits = 21
	l2Size = 1 << l2Bits // 32768
	l1Size = 1 << l1Bits // 2097152

	// TLB size (must be power of 2)
	tlbSize = 1024
	tlbMask = tlbSize - 1
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

// tlbEntry caches a recent page lookup.
type tlbEntry struct {
	tag  uint64     // page-aligned virtual address
	page *PageEntry // nil means empty slot
}

// MMU is a software memory management unit with page-level permissions.
// The hot path (Read/Write/Fetch) uses a two-level page table (slice of
// slices) and a small direct-mapped TLB - no locks, no hash maps.
type MMU struct {
	mu       sync.RWMutex            // only for structural mutations (Map/Mmap/Munmap)
	l1       [l1Size]*[l2Size]*PageEntry // two-level page table
	pages    map[uint64]*PageEntry   // fallback for MapHostSlice (external Data)
	tlb      [tlbSize]tlbEntry       // direct-mapped TLB
	brkAddr  uint64
	heapBase uint64
	// Debug: write watchpoint
	WatchAddr  uint64
	WatchSize  uint64
	WatchCB    func(addr, val uint64, size int)
}

// New creates an MMU with no mapped pages.
func New() *MMU {
	m := &MMU{
		pages: make(map[uint64]*PageEntry),
	}
	return m
}

// pageIndices splits a page-aligned address into L1 and L2 indices.
func pageIndices(vaddr uint64) (int, int) {
	vpn := vaddr >> PageShift
	return int(vpn >> l2Bits) & (l1Size - 1), int(vpn) & (l2Size - 1)
}

// storePage inserts a page into the two-level table.
func (m *MMU) storePage(vaddr uint64, pe *PageEntry) {
	i1, i2 := pageIndices(vaddr)
	if m.l1[i1] == nil {
		l2 := new([l2Size]*PageEntry)
		m.l1[i1] = l2
	}
	m.l1[i1][i2] = pe
	// Also invalidate TLB for this address
	slot := (vaddr >> PageShift) & tlbMask
	m.tlb[slot] = tlbEntry{} // clear
}

// getPage retrieves a page from the two-level table (no locks).
func (m *MMU) getPage(vaddr uint64) *PageEntry {
	i1, i2 := pageIndices(vaddr)
	l2 := m.l1[i1]
	if l2 == nil {
		return nil
	}
	return l2[i2]
}

// removePage removes a page from the two-level table.
func (m *MMU) removePage(vaddr uint64) {
	i1, i2 := pageIndices(vaddr)
	l2 := m.l1[i1]
	if l2 != nil {
		l2[i2] = nil
	}
	slot := (vaddr >> PageShift) & tlbMask
	m.tlb[slot] = tlbEntry{}
}

// MapPage allocates a page at the given page-aligned virtual address.
func (m *MMU) MapPage(vaddr uint64, perms uint8) error {
	vaddr &= PageMask
	m.mu.Lock()
	defer m.mu.Unlock()
	if pe := m.getPage(vaddr); pe != nil {
		pe.Perms = perms
		return nil
	}
	pe := &PageEntry{
		Data:  make([]byte, PageSize),
		Perms: perms,
	}
	m.storePage(vaddr, pe)
	return nil
}

// MapRange maps contiguous pages covering [start, start+size).
func (m *MMU) MapRange(start, size uint64, perms uint8) {
	end := start + size
	for addr := start & PageMask; addr < end; addr += PageSize {
		m.MapPage(addr, perms)
	}
}

// MapRangeZero maps contiguous pages covering [start, start+size) and zeroes them.
func (m *MMU) MapRangeZero(start, size uint64, perms uint8) {
	end := start + size
	for addr := start & PageMask; addr < end; addr += PageSize {
		m.MapPage(addr, perms)
		pe := m.getPage(addr)
		if pe != nil {
			for i := range pe.Data {
				pe.Data[i] = 0
			}
		}
	}
}

// LookupRead is the public version of lookupPage, for use by the CPU
// instruction fetch cache.
func (m *MMU) LookupRead(vaddr uint64, requiredPerms uint8) (*PageEntry, uint64, error) {
	return m.lookupPage(vaddr, requiredPerms)
}

// lookupPage returns the page entry for vaddr or a Fault.
// lookupPage resolves a virtual address to its backing PageEntry + offset.
// Uses a direct-mapped TLB for the fast path (no locks, no maps).
func (m *MMU) lookupPage(vaddr uint64, requiredPerms uint8) (*PageEntry, uint64, error) {
	base := vaddr & PageMask
	offset := vaddr & (PageSize - 1)

	// TLB lookup
	slot := (base >> PageShift) & tlbMask
	te := &m.tlb[slot]
	if te.page != nil && te.tag == base {
		if te.page.Perms&requiredPerms != requiredPerms {
			return nil, 0, &Fault{Addr: vaddr, Type: FaultPermission, Perms: te.page.Perms}
		}
		return te.page, offset, nil
	}

	// TLB miss → page table lookup
	pe := m.getPage(base)
	if pe == nil {
		return nil, 0, &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: requiredPerms}
	}
	if pe.Perms&requiredPerms != requiredPerms {
		return nil, 0, &Fault{Addr: vaddr, Type: FaultPermission, Perms: pe.Perms}
	}

	// Fill TLB
	te.tag = base
	te.page = pe
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
	pe, off, err := m.lookupPage(vaddr, PermRead)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-2 {
		return binary.LittleEndian.Uint16(pe.Data[off:]), nil
	}
	// Cross-page boundary
	b0 := pe.Data[off]
	pe1, off1, err := m.lookupPage(vaddr+1, PermRead)
	if err != nil {
		return 0, err
	}
	return uint16(b0) | uint16(pe1.Data[off1])<<8, nil
}

// Read32 reads a 32-bit little-endian value.
func (m *MMU) Read32(vaddr uint64) (uint32, error) {
	pe, off, err := m.lookupPage(vaddr, PermRead)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-4 {
		return binary.LittleEndian.Uint32(pe.Data[off:]), nil
	}
	// Cross-page boundary - read byte by byte
	var val uint32
	val = uint32(pe.Data[off])
	for i := uint64(1); i < 4; i++ {
		b, err := m.Read8(vaddr + i)
		if err != nil {
			return 0, err
		}
		val |= uint32(b) << (i * 8)
	}
	return val, nil
}

// Read64 reads a 64-bit little-endian value.
func (m *MMU) Read64(vaddr uint64) (uint64, error) {
	pe, off, err := m.lookupPage(vaddr, PermRead)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-8 {
		return binary.LittleEndian.Uint64(pe.Data[off:]), nil
	}
	// Cross-page boundary - read byte by byte
	var val uint64
	val = uint64(pe.Data[off])
	for i := uint64(1); i < 8; i++ {
		b, err := m.Read8(vaddr + i)
		if err != nil {
			return 0, err
		}
		val |= uint64(b) << (i * 8)
	}
	return val, nil
}

// Write8 writes a single byte.
func (m *MMU) checkWatch(addr, val uint64, size int) {
	if m.WatchCB != nil && m.WatchSize > 0 {
		end := addr + uint64(size)
		watchEnd := m.WatchAddr + m.WatchSize
		if addr < watchEnd && end > m.WatchAddr {
			m.WatchCB(addr, val, size)
		}
	}
}

func (m *MMU) Write8(vaddr uint64, val uint8) error {
	m.checkWatch(vaddr, uint64(val), 1)
	pe, off, err := m.lookupPage(vaddr, PermWrite)
	if err != nil {
		return err
	}
	pe.Data[off] = val
	return nil
}

// Write16 writes a 16-bit little-endian value.
func (m *MMU) Write16(vaddr uint64, val uint16) error {
	m.checkWatch(vaddr, uint64(val), 2)
	pe, off, err := m.lookupPage(vaddr, PermWrite)
	if err != nil {
		return err
	}
	if off <= PageSize-2 {
		binary.LittleEndian.PutUint16(pe.Data[off:], val)
		return nil
	}
	pe.Data[off] = uint8(val)
	return m.Write8(vaddr+1, uint8(val>>8))
}

// Write32 writes a 32-bit little-endian value.
func (m *MMU) Write32(vaddr uint64, val uint32) error {
	m.checkWatch(vaddr, uint64(val), 4)
	pe, off, err := m.lookupPage(vaddr, PermWrite)
	if err != nil {
		return err
	}
	if off <= PageSize-4 {
		binary.LittleEndian.PutUint32(pe.Data[off:], val)
		return nil
	}
	pe.Data[off] = uint8(val)
	for i := uint64(1); i < 4; i++ {
		if err := m.Write8(vaddr+i, uint8(val>>(i*8))); err != nil {
			return err
		}
	}
	return nil
}

// Write64 writes a 64-bit little-endian value.
func (m *MMU) Write64(vaddr uint64, val uint64) error {
	m.checkWatch(vaddr, val, 8)
	pe, off, err := m.lookupPage(vaddr, PermWrite)
	if err != nil {
		return err
	}
	if off <= PageSize-8 {
		binary.LittleEndian.PutUint64(pe.Data[off:], val)
		return nil
	}
	pe.Data[off] = uint8(val)
	for i := uint64(1); i < 8; i++ {
		if err := m.Write8(vaddr+i, uint8(val>>(i*8))); err != nil {
			return err
		}
	}
	return nil
}

// WriteBytes copies a byte slice into guest memory (requires write permission).
func (m *MMU) WriteBytes(vaddr uint64, data []byte) error {
	startVaddr := vaddr
	origData := data
	for len(data) > 0 {
		pe, off, err := m.lookupPage(vaddr, PermWrite)
		if err != nil {
			return err
		}
		n := copy(pe.Data[off:], data)
		data = data[n:]
		vaddr += uint64(n)
	}
	if m.WatchCB != nil && m.WatchSize > 0 {
		end := startVaddr + uint64(len(origData))
		watchEnd := m.WatchAddr + m.WatchSize
		if startVaddr < watchEnd && end > m.WatchAddr {
			// Fire callback for each 8-byte window so corruption in the second
			// half of a 16-byte XMM store is also detected.
			for i := 0; i+8 <= len(origData); i += 8 {
				chunkAddr := startVaddr + uint64(i)
				val := uint64(origData[i]) | uint64(origData[i+1])<<8 | uint64(origData[i+2])<<16 | uint64(origData[i+3])<<24 |
					uint64(origData[i+4])<<32 | uint64(origData[i+5])<<40 | uint64(origData[i+6])<<48 | uint64(origData[i+7])<<56
				m.WatchCB(chunkAddr, val, 8)
			}
			if len(origData)%8 != 0 {
				m.WatchCB(startVaddr+uint64(len(origData)&^7), 0, len(origData)%8)
			}
		}
	}
	return nil
}

// ReadCString reads a null-terminated string from memory.
func (m *MMU) ReadCString(vaddr uint64, maxLen int) string {
	var res []byte
	for i := 0; i < maxLen; i++ {
		b, err := m.Read8(vaddr + uint64(i))
		if err != nil || b == 0 {
			break
		}
		res = append(res, b)
	}
	return string(res)
}

// ReadBytesRaw reads data from guest memory, bypassing permission checks.
func (m *MMU) ReadBytesRaw(vaddr uint64, n int) ([]byte, error) {
	buf := make([]byte, n)
	pos := 0
	for pos < n {
		base := vaddr & PageMask
		offset := vaddr & (PageSize - 1)
		pe := m.getPage(base)
		if pe == nil {
			return nil, &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: PermRead}
		}
		chunk := int(PageSize - offset)
		if chunk > n-pos {
			chunk = n - pos
		}
		copy(buf[pos:], pe.Data[offset:offset+uint64(chunk)])
		pos += chunk
		vaddr += uint64(chunk)
	}
	return buf, nil
}

// ReadBytes reads n bytes from guest memory.
func (m *MMU) ReadBytes(vaddr uint64, n int) ([]byte, error) {
	buf := make([]byte, n)
	pos := 0
	for pos < n {
		pe, off, err := m.lookupPage(vaddr, PermRead)
		if err != nil {
			return nil, err
		}
		copied := copy(buf[pos:], pe.Data[off:])
		pos += copied
		vaddr += uint64(copied)
	}
	return buf, nil
}

// Fetch16 reads a 16-bit instruction (requires execute permission).
func (m *MMU) Fetch16(vaddr uint64) (uint16, error) {
	pe, off, err := m.lookupPage(vaddr, PermExecute)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-2 {
		return binary.LittleEndian.Uint16(pe.Data[off:]), nil
	}
	b0 := pe.Data[off]
	pe1, off1, err1 := m.lookupPage(vaddr+1, PermExecute)
	if err1 != nil {
		return 0, err1
	}
	return uint16(b0) | uint16(pe1.Data[off1])<<8, nil
}

// Fetch32 reads a 32-bit instruction (requires execute permission).
func (m *MMU) Fetch32(vaddr uint64) (uint32, error) {
	pe, off, err := m.lookupPage(vaddr, PermExecute)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-4 {
		return binary.LittleEndian.Uint32(pe.Data[off:]), nil
	}
	// crosses page boundary
	var val uint32
	val = uint32(pe.Data[off])
	for i := uint64(1); i < 4; i++ {
		addr := vaddr + i
		pe2, off2, err2 := m.lookupPage(addr, PermExecute)
		if err2 != nil {
			return 0, err2
		}
		val |= uint32(pe2.Data[off2]) << (i * 8)
	}
	return val, nil
}

// SetBrk sets the program break address.
func (m *MMU) SetBrk(addr uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.brkAddr = addr
	m.heapBase = addr
}

// GetBrkBase returns the initial program break (heap base).
func (m *MMU) GetBrkBase() uint64 {
	return m.heapBase
}

// Brk adjusts the program break, mapping new pages as needed.
func (m *MMU) Brk(addr uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if addr == 0 || addr < m.heapBase {
		return m.brkAddr
	}
	oldEnd := m.brkAddr
	if addr < oldEnd {
		// Shrink heap
		startUnmap := (addr + PageSize - 1) & PageMask
		for pg := startUnmap; pg < oldEnd; pg += PageSize {
			m.storePage(pg, nil)
		}
		m.brkAddr = addr
		return addr
	}
	
	if addr > oldEnd {
		// Zero the partial page from oldEnd to min(addr, page boundary)
		pe := m.getPage(oldEnd & PageMask)
		if pe != nil {
			pageOff := oldEnd & (PageSize - 1)
			endOff := uint64(PageSize)
			if (addr & PageMask) == (oldEnd & PageMask) {
				endOff = addr & (PageSize - 1)
			}
			for i := pageOff; i < endOff; i++ {
				pe.Data[i] = 0
			}
		}
	}

	for pg := oldEnd & PageMask; pg < addr; pg += PageSize {
		if m.getPage(pg) == nil {
			pe := &PageEntry{
				Data:  make([]byte, PageSize),
				Perms: PermRead | PermWrite,
			}
			m.storePage(pg, pe)
		}
	}
	m.brkAddr = addr
	return m.brkAddr
}

// Mmap allocates anonymous pages at a hint address (simplified).
func (m *MMU) Mmap(addr, length uint64, perms uint8) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	length = (length + PageSize - 1) & PageMask
	
	// If a hint address is provided, check if it's available.
	if addr != 0 {
		addr = addr & PageMask // MUST be page-aligned
		conflict := false
		for pg := addr; pg < addr+length; pg += PageSize {
			if m.getPage(pg) != nil {
				conflict = true
				break
			}
		}
		if conflict {
			addr = 0 // Hint failed, fallback to finding a free region
		}
	}

	if addr == 0 {
		addr = 0x400000000000
		for {
			conflict := false
			for pg := addr; pg < addr+length; pg += PageSize {
				if m.getPage(pg) != nil {
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
	for pg := addr; pg < addr+length; pg += PageSize {
		pe := &PageEntry{
			Data:  make([]byte, PageSize),
			Perms: perms,
		}
		m.storePage(pg, pe)
	}
	return addr
}

// Munmap removes pages covering [addr, addr+length).
func (m *MMU) Munmap(addr, length uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		m.removePage(pg)
	}
}

// Mprotect changes permissions on pages covering [addr, addr+length).
func (m *MMU) Mprotect(addr, length uint64, perms uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		pe := m.getPage(pg)
		if pe == nil {
			continue
		}
		pe.Perms = perms
		// Invalidate TLB for permission change
		slot := (pg >> PageShift) & tlbMask
		m.tlb[slot] = tlbEntry{}
	}
	return nil
}

// Write32Raw writes a 32-bit value bypassing permission checks.
func (m *MMU) Write32Raw(vaddr uint64, val uint32) error {
	base := vaddr & PageMask
	offset := vaddr & (PageSize - 1)
	pe := m.getPage(base)
	if pe == nil {
		return &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: PermWrite}
	}
	if offset <= PageSize-4 {
		binary.LittleEndian.PutUint32(pe.Data[offset:], val)
		return nil
	}
	var buf [4]byte
	buf[0] = byte(val)
	buf[1] = byte(val >> 8)
	buf[2] = byte(val >> 16)
	buf[3] = byte(val >> 24)
	return m.WriteBytesRaw(vaddr, buf[:])
}

// Write64Raw writes a 64-bit value bypassing permission checks.
func (m *MMU) Write64Raw(vaddr uint64, val uint64) error {
	base := vaddr & PageMask
	offset := vaddr & (PageSize - 1)
	pe := m.getPage(base)
	if pe == nil {
		return &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: PermWrite}
	}
	if offset <= PageSize-8 {
		binary.LittleEndian.PutUint64(pe.Data[offset:], val)
		return nil
	}
	var buf [8]byte
	buf[0] = byte(val)
	buf[1] = byte(val >> 8)
	buf[2] = byte(val >> 16)
	buf[3] = byte(val >> 24)
	buf[4] = byte(val >> 32)
	buf[5] = byte(val >> 40)
	buf[6] = byte(val >> 48)
	buf[7] = byte(val >> 56)
	return m.WriteBytesRaw(vaddr, buf[:])
}

// WriteBytesRaw copies data into guest memory, bypassing permission checks.
func (m *MMU) WriteBytesRaw(vaddr uint64, data []byte) error {
	for len(data) > 0 {
		base := vaddr & PageMask
		offset := vaddr & (PageSize - 1)
		pe := m.getPage(base)
		if pe == nil {
			return &Fault{Addr: vaddr, Type: FaultUnmapped, Perms: PermWrite}
		}
		n := copy(pe.Data[offset:], data)
		data = data[n:]
		vaddr += uint64(n)
	}
	return nil
}

// IsMapped checks if an address has a backing page.
func (m *MMU) IsMapped(vaddr uint64) bool {
	return m.getPage(vaddr&PageMask) != nil
}

// MapHostSlice aliases host memory into the guest address space.
func (m *MMU) MapHostSlice(guestAddr uint64, hostSlice []byte, perms uint8) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	length := uint64(len(hostSlice))
	if guestAddr == 0 {
		guestAddr = 0x500000000000
		for {
			conflict := false
			for pg := guestAddr & PageMask; pg < guestAddr+length; pg += PageSize {
				if m.getPage(pg) != nil {
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

		sliceLen := PageSize - pageOff
		if sliceLen > remaining {
			sliceLen = remaining
		}

		pe := m.getPage(pgAddr)
		if pe == nil {
			// Create a new page entry. Data initially points to a fresh page,
			// but we'll override parts of it with the hostSlice.
			pe = &PageEntry{
				Data:  make([]byte, PageSize),
				Perms: perms,
			}
			m.storePage(pgAddr, pe)
		}

		// To maintain zero-copy, we must alias. If we are covering the full page,
		// we can just swap the Data slice. If it's a partial page, we have a problem
		// with the current PageEntry.Data design which assumes a 4KB slice.
		// For Wayland/shm, it's almost always page-aligned and full-page.
		if pageOff == 0 && sliceLen == PageSize {
			pe.Data = hostSlice[offset : offset+PageSize]
		} else {
			// Partial page: we copy for now to maintain the 4KB invariant,
			// but this is sub-optimal.
			copy(pe.Data[pageOff:], hostSlice[offset:offset+sliceLen])
		}
		pe.Perms = perms

		offset += sliceLen
	}

	return guestAddr
}
