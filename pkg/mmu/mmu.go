package mmu

import (
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	PageSize  = 4096
	PageMask  = ^uint64(PageSize - 1)
	PageShift = 12

	// Two-level page table: L1 covers top bits, L2 covers remaining bits.
	// We support addresses up to 48 bits (256 TB virtual address space).
	// L1 index = bits [47:27] -> 2^21 = 2M entries
	// L2 index = bits [26:12] -> 2^15 = 32K entries per L2 table
	l2Bits = 15
	l1Bits = 21
	l2Size = 1 << l2Bits // 32768
	l1Size = 1 << l1Bits // 2097152

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
	// CodeVersion increments on every write to this page while it is
	// executable. The JIT snapshots it per compiled block so a write to
	// one page only invalidates the blocks that overlap that page.
	CodeVersion atomic.Uint32
}

type l2Table [l2Size]atomic.Pointer[PageEntry]

// MMU is a software memory management unit with page-level permissions.
// The hot path (Read/Write/Fetch) uses a two-level page table (slice of
// slices) and a small direct-mapped TLB - no locks, no hash maps.
type MMU struct {
	mu       sync.RWMutex // only for structural mutations (Map/Mmap/Munmap)
	l1       [l1Size]atomic.Pointer[l2Table]
	pages    map[uint64]*PageEntry // fallback for MapHostSlice (external Data)
	brkAddr  uint64
	heapBase uint64
	// Mode32 constrains Mmap allocations to the lower 4 GB (for PE32).
	Mode32 bool
	// Debug: write watchpoint
	WatchAddr  uint64
	WatchSize  uint64
	WatchCB    func(addr, val uint64, size int)
	mappingGen atomic.Uint64
	codeGen    atomic.Uint64
	// flat, when non-nil, is a reserved low-4GiB host region; guest pages
	// below 4GiB alias into it at their guest offset, so flatBase+guestAddr
	// is the host address of guest memory (the layout native code needs).
	flat []byte
	// perm is one byte of permission bits per 4KiB page in the flat region
	// (1M entries). Generated machine code consults it before touching flat
	// memory so an unmapped or wrongly-permissioned access faults into the
	// interpreter instead of segfaulting the host. Only maintained while
	// flat backing is on.
	perm []byte
}

const flatPages = 1 << 20 // 4GiB / 4KiB

// New creates an MMU with no mapped pages.
func New() *MMU {
	m := &MMU{
		pages: make(map[uint64]*PageEntry),
	}
	return m
}

// EnableFlatBacking reserves a contiguous 4GiB anonymous region and backs
// every subsequently mapped page below 4GiB with a slice of it. Call before
// mapping anything. Native code can then address guest memory as
// FlatBase()[guestAddr].
func (m *MMU) EnableFlatBacking() error {
	if m.flat != nil {
		return nil
	}
	region, err := unix.Mmap(-1, 0, 1<<32,
		unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE)
	if err != nil {
		return err
	}
	m.flat = region
	m.perm = make([]byte, flatPages)
	return nil
}

// FlatBase returns the host backing region for guest addresses below 4GiB,
// or nil when flat backing is disabled.
func (m *MMU) FlatBase() []byte { return m.flat }

// PermBitmap returns the per-page permission byte array for the flat region
// (one byte per 4KiB page), or nil when flat backing is disabled. Generated
// code indexes it by guestAddr>>12 and tests the PermRead/PermWrite bits.
func (m *MMU) PermBitmap() []byte { return m.perm }

// setPerm records a page's permissions in the flat bitmap (no-op when flat
// backing is off or the page is above 4GiB).
func (m *MMU) setPerm(vaddr uint64, perms uint8) {
	if m.perm != nil && vaddr < 1<<32 {
		m.perm[vaddr>>PageShift] = perms
	}
}

// pageData returns a zeroed backing slice for a page at vaddr: a window of
// the flat region when enabled and in range, a heap slice otherwise.
func (m *MMU) pageData(vaddr uint64) []byte {
	if m.flat != nil && vaddr < 1<<32 {
		window := m.flat[vaddr : vaddr+PageSize : vaddr+PageSize]
		if unix.Mprotect(window, unix.PROT_READ|unix.PROT_WRITE) == nil {
			clear(window)
			return window
		}
	}
	return make([]byte, PageSize)
}

// pageIndices splits a page-aligned address into L1 and L2 indices.
func pageIndices(vaddr uint64) (int, int) {
	vpn := vaddr >> PageShift
	return int(vpn>>l2Bits) & (l1Size - 1), int(vpn) & (l2Size - 1)
}

// storePage inserts a page into the two-level table.
func (m *MMU) storePage(vaddr uint64, pe *PageEntry) {
	i1, i2 := pageIndices(vaddr)
	l2 := m.l1[i1].Load()
	if l2 == nil {
		candidate := new(l2Table)
		if m.l1[i1].CompareAndSwap(nil, candidate) {
			l2 = candidate
		} else {
			l2 = m.l1[i1].Load()
		}
	}
	l2[i2].Store(pe)
	if m.perm != nil {
		// Only pages whose backing slice actually aliases the flat region
		// are safe for native flat-address access; host-slice pages
		// (MapHostSlice) must fault into the interpreter.
		if pe != nil && m.isFlatBacked(vaddr, pe) {
			m.setPerm(vaddr, pe.Perms)
		} else {
			m.setPerm(vaddr, 0)
		}
	}
}

// isFlatBacked reports whether pe.Data is the flat-region window for vaddr,
// i.e. FlatBase()+vaddr addresses the same bytes.
func (m *MMU) isFlatBacked(vaddr uint64, pe *PageEntry) bool {
	if m.flat == nil || vaddr >= 1<<32 || len(pe.Data) < PageSize {
		return false
	}
	return &pe.Data[0] == &m.flat[vaddr]
}

// getPage retrieves a page from the two-level table (no locks).
func (m *MMU) getPage(vaddr uint64) *PageEntry {
	i1, i2 := pageIndices(vaddr)
	l2 := m.l1[i1].Load()
	if l2 == nil {
		return nil
	}
	return l2[i2].Load()
}

// removePage removes a page from the two-level table.
func (m *MMU) removePage(vaddr uint64) {
	m.setPerm(vaddr, 0)
	i1, i2 := pageIndices(vaddr)
	l2 := m.l1[i1].Load()
	if l2 != nil {
		l2[i2].Store(nil)
	}
}

func (m *MMU) beginMappingMutation() {
	m.mappingGen.Add(1)
}

func (m *MMU) endMappingMutation() {
	m.mappingGen.Add(1)
}

// MapPage allocates a page at the given page-aligned virtual address.
func (m *MMU) MapPage(vaddr uint64, perms uint8) error {
	vaddr &= PageMask
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beginMappingMutation()
	defer m.endMappingMutation()
	return m.mapPageLocked(vaddr, perms)
}

func (m *MMU) mapPageLocked(vaddr uint64, perms uint8) error {
	if pe := m.getPage(vaddr); pe != nil {
		m.storePage(vaddr, &PageEntry{Data: pe.Data, Perms: perms})
		return nil
	}
	pe := &PageEntry{
		Data:  m.pageData(vaddr),
		Perms: perms,
	}
	m.storePage(vaddr, pe)
	return nil
}

// MapRange maps contiguous pages covering [start, start+size).
func (m *MMU) MapRange(start, size uint64, perms uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beginMappingMutation()
	defer m.endMappingMutation()
	end := start + size
	for addr := start & PageMask; addr < end; addr += PageSize {
		m.mapPageLocked(addr, perms)
	}
}

// MapRangeZero maps contiguous pages covering [start, start+size) and zeroes them.
func (m *MMU) MapRangeZero(start, size uint64, perms uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beginMappingMutation()
	defer m.endMappingMutation()
	end := start + size
	for addr := start & PageMask; addr < end; addr += PageSize {
		m.mapPageLocked(addr, perms)
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

func (m *MMU) MappingGeneration() uint64 {
	return m.mappingGen.Load()
}

func (m *MMU) CodeGeneration() uint64 {
	return m.codeGen.Load()
}

func (m *MMU) noteExecutableWrite(pe *PageEntry) {
	if pe.Perms&PermExecute != 0 {
		pe.CodeVersion.Add(1)
		m.codeGen.Add(1)
	}
}

// NoteExecutableWrite lets external fast write paths (the JIT's cached-page
// stores) keep code invalidation working when they bypass Write8/16/32/64.
func (m *MMU) NoteExecutableWrite(pe *PageEntry) {
	m.noteExecutableWrite(pe)
}

// lookupPage returns the page entry for vaddr or a Fault.
// lookupPage resolves a virtual address to its backing PageEntry + offset.
// Uses a direct-mapped TLB for the fast path (no locks, no maps).
func (m *MMU) lookupPage(vaddr uint64, requiredPerms uint8) (*PageEntry, uint64, error) {
	base := vaddr & PageMask
	offset := vaddr & (PageSize - 1)
	pe := m.getPage(base)
	if pe == nil {
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
	m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
		return nil
	}
	pe.Data[off] = uint8(val)
	m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
		return nil
	}
	pe.Data[off] = uint8(val)
	m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
		return nil
	}
	pe.Data[off] = uint8(val)
	m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
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
	for {
		generation := m.MappingGeneration()
		if generation&1 != 0 {
			continue
		}
		value, err := m.fetch16Once(vaddr)
		if m.MappingGeneration() == generation {
			return value, err
		}
	}
}

func (m *MMU) fetch16Once(vaddr uint64) (uint16, error) {
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
	for {
		generation := m.MappingGeneration()
		if generation&1 != 0 {
			continue
		}
		value, err := m.fetch32Once(vaddr)
		if m.MappingGeneration() == generation {
			return value, err
		}
	}
}

func (m *MMU) fetch32Once(vaddr uint64) (uint32, error) {
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

func (m *MMU) Fetch64(vaddr uint64) (uint64, error) {
	for {
		generation := m.MappingGeneration()
		if generation&1 != 0 {
			continue
		}
		value, err := m.fetch64Once(vaddr)
		if m.MappingGeneration() == generation {
			return value, err
		}
	}
}

func (m *MMU) fetch64Once(vaddr uint64) (uint64, error) {
	pe, off, err := m.lookupPage(vaddr, PermExecute)
	if err != nil {
		return 0, err
	}
	if off <= PageSize-8 {
		return binary.LittleEndian.Uint64(pe.Data[off:]), nil
	}
	var val uint64
	for i := uint64(0); i < 8; i++ {
		page, pageOff, pageErr := m.lookupPage(vaddr+i, PermExecute)
		if pageErr != nil {
			return 0, pageErr
		}
		val |= uint64(page.Data[pageOff]) << (i * 8)
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
	m.beginMappingMutation()
	defer m.endMappingMutation()
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
	m.beginMappingMutation()
	defer m.endMappingMutation()
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
		start := uint64(0x400000000000)
		if m.Mode32 {
			start = 0x10000000 // PE32: allocate in lower 4GB
		}
		addr = start
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
			if m.Mode32 && addr+length > 0x7FFF0000 {
				panic("mmu: out of 32-bit address space")
			}
		}
	}
	for pg := addr; pg < addr+length; pg += PageSize {
		pe := &PageEntry{
			Data:  m.pageData(pg),
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
	m.beginMappingMutation()
	defer m.endMappingMutation()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		m.removePage(pg)
	}
}

// QueryRegion returns information about the virtual memory region containing addr.
// base is the start address of the contiguous region with the same permissions.
// size is the total size of that contiguous region.
// mapped is false if the address is not mapped (free region).
// perms holds the page permissions (PermRead|PermWrite|PermExecute).
func (m *MMU) QueryRegion(addr uint64) (base, size uint64, mapped bool, perms uint8) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pg := addr & PageMask
	pe := m.getPage(pg)
	if pe == nil {
		// Unmapped: scan forward to find next mapped page for the free-region size.
		base = pg
		perms = 0
		mapped = false
		end := pg + PageSize
		for i := 0; i < 65536; i++ { // cap at 256 MB scan
			if m.getPage(end) != nil {
				break
			}
			end += PageSize
		}
		size = end - base
		return
	}
	// Mapped: find the start of the contiguous region with identical permissions.
	p := pe.Perms
	start := pg
	for start >= PageSize {
		prev := start - PageSize
		pp := m.getPage(prev)
		if pp == nil || pp.Perms != p {
			break
		}
		start = prev
	}
	// Find the end of the contiguous region.
	end := pg + PageSize
	for i := 0; i < 65536; i++ {
		np := m.getPage(end)
		if np == nil || np.Perms != p {
			break
		}
		end += PageSize
	}
	return start, end - start, true, p
}
func (m *MMU) Mprotect(addr, length uint64, perms uint8) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beginMappingMutation()
	defer m.endMappingMutation()
	end := addr + length
	for pg := addr & PageMask; pg < end; pg += PageSize {
		pe := m.getPage(pg)
		if pe == nil {
			continue
		}
		m.storePage(pg, &PageEntry{Data: pe.Data, Perms: perms})
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
		m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
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
		m.noteExecutableWrite(pe)
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
	m.beginMappingMutation()
	defer m.endMappingMutation()

	length := uint64(len(hostSlice))
	if guestAddr == 0 {
		if m.Mode32 {
			guestAddr = 0x10000000
		} else {
			guestAddr = 0x500000000000
		}
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

		var data []byte
		if pageOff == 0 && sliceLen == PageSize {
			data = hostSlice[offset : offset+PageSize]
		} else {
			data = make([]byte, PageSize)
			if current := m.getPage(pgAddr); current != nil {
				copy(data, current.Data)
			}
			copy(data[pageOff:], hostSlice[offset:offset+sliceLen])
		}
		m.storePage(pgAddr, &PageEntry{Data: data, Perms: perms})

		offset += sliceLen
	}
	return guestAddr
}
