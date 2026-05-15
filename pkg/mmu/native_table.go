package mmu

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

type NativeTableLimitations uint32

const (
	// NativeTableExecutableWriteSlowPath means direct writes to executable
	// pages must use the MMU write path to update code generations.
	NativeTableExecutableWriteSlowPath NativeTableLimitations = 1 << iota
	// NativeTableWriteWatchSlowPath means direct writes cannot run WatchCB.
	NativeTableWriteWatchSlowPath
)

var (
	nativePointerSize          = unsafe.Sizeof(uintptr(0))
	nativeL1EntrySize          = unsafe.Sizeof(atomic.Pointer[l2Table]{})
	nativeL2EntrySize          = unsafe.Sizeof(atomic.Pointer[PageEntry]{})
	nativePageEntrySize        = unsafe.Sizeof(PageEntry{})
	nativePageDataOffset       = unsafe.Offsetof(PageEntry{}.Data)
	nativePageDataLengthOffset = nativePageDataOffset + nativePointerSize
	nativePagePermsOffset      = unsafe.Offsetof(PageEntry{}.Perms)
	nativePageCodeOffset       = unsafe.Offsetof(PageEntry{}.CodeVersion)
	nativeGenerationSize       = unsafe.Sizeof(atomic.Uint64{})
	nativeUsersSize            = unsafe.Sizeof(atomic.Uint64{})
	nativePointerAlignment     = unsafe.Alignof(uintptr(0))
	nativeL1EntryAlignment     = unsafe.Alignof(atomic.Pointer[l2Table]{})
	nativeL2EntryAlignment     = unsafe.Alignof(atomic.Pointer[PageEntry]{})
	nativePageEntryAlignment   = unsafe.Alignof(PageEntry{})
	nativeGenerationAlignment  = unsafe.Alignof(atomic.Uint64{})
	nativeUsersAlignment       = unsafe.Alignof(atomic.Uint64{})
)

// NativeTableDescriptor describes the in-place sparse table for an amd64
// emitter. L1Root points at atomic L2 pointers. Each L2 table contains atomic
// PageEntry pointers. PageDataOffset addresses the slice data word and
// PageDataLengthOffset addresses its length word.
//
// The descriptor is valid only while this value remains reachable and only
// for synchronous native blocks owned by the same process. A generated lookup
// must load Generation, reject odd values, increment ActiveUsers, then confirm
// that Generation is unchanged before traversing the table. It must decrement
// ActiveUsers after the final memory access. Mapping mutations publish an odd
// generation and wait for ActiveUsers to drain before replacing table entries.
// On a failed check generated code must release ActiveUsers, when acquired,
// and discard every loaded pointer before retrying or leaving native code.
type NativeTableDescriptor struct {
	L1Root                unsafe.Pointer
	Generation            unsafe.Pointer
	ActiveUsers           unsafe.Pointer
	L1EntrySize           uintptr
	L2EntrySize           uintptr
	PageEntrySize         uintptr
	PageDataOffset        uintptr
	PageDataLengthOffset  uintptr
	PagePermissionsOffset uintptr
	PageCodeVersionOffset uintptr
	L1Shift               uint8
	L2Shift               uint8
	AddressBits           uint8
	PointerSize           uint8
	PointerAlignment      uintptr
	L1EntryAlignment      uintptr
	L2EntryAlignment      uintptr
	PageEntryAlignment    uintptr
	GenerationAlignment   uintptr
	ActiveUsersAlignment  uintptr
	L1Mask                uint64
	L2Mask                uint64
	PageOffsetMask        uint64
	GenerationSize        uintptr
	ActiveUsersSize       uintptr
	Limitations           NativeTableLimitations

	owner *MMU
}

// NativePage is a stable page-table snapshot for one guest address.
type NativePage struct {
	Entry          *PageEntry
	HostPage       unsafe.Pointer
	HostPointer    unsafe.Pointer
	GuestPage      uint64
	Offset         uint64
	BytesToPageEnd uint64
	Generation     uint64
	Permissions    uint8
}

// Contains reports whether size bytes fit in this page snapshot.
func (p NativePage) Contains(size uint64) bool {
	return size <= p.BytesToPageEnd
}

// NativeRange describes a permission-checked range under one table generation.
// First and Last are equal for a single-page range. Intermediate pages are
// checked but are not retained in the result.
type NativeRange struct {
	Address    uint64
	Length     uint64
	Generation uint64
	PageCount  uint64
	FirstBytes uint64
	LastBytes  uint64
	First      NativePage
	Last       NativePage
}

// NativeTable returns a descriptor over the MMU's existing sparse table.
func (m *MMU) NativeTable() NativeTableDescriptor {
	if runtime.GOARCH != "amd64" ||
		nativePointerSize != 8 ||
		nativeL1EntrySize != nativePointerSize ||
		nativeL2EntrySize != nativePointerSize ||
		nativeGenerationSize != unsafe.Sizeof(uint64(0)) ||
		nativeUsersSize != unsafe.Sizeof(uint64(0)) {
		panic("mmu: native table requires amd64 pointer and atomic layouts")
	}
	validateNativeAtomicLayout()

	m.mu.Lock()
	l1Root := unsafe.Pointer(&m.l1[0])
	generation := unsafe.Pointer(&m.mappingGen)
	activeUsers := unsafe.Pointer(&m.nativeUsers)
	if uintptr(l1Root)%nativeL1EntryAlignment != 0 ||
		uintptr(generation)%nativeGenerationAlignment != 0 ||
		uintptr(activeUsers)%nativeUsersAlignment != 0 {
		m.mu.Unlock()
		panic("mmu: native table roots are not atomically aligned")
	}
	d := NativeTableDescriptor{
		L1Root:                l1Root,
		Generation:            generation,
		ActiveUsers:           activeUsers,
		L1EntrySize:           nativeL1EntrySize,
		L2EntrySize:           nativeL2EntrySize,
		PageEntrySize:         nativePageEntrySize,
		PageDataOffset:        nativePageDataOffset,
		PageDataLengthOffset:  nativePageDataLengthOffset,
		PagePermissionsOffset: nativePagePermsOffset,
		PageCodeVersionOffset: nativePageCodeOffset,
		L1Shift:               PageShift + l2Bits,
		L2Shift:               PageShift,
		AddressBits:           PageShift + l2Bits + l1Bits,
		PointerSize:           uint8(nativePointerSize),
		PointerAlignment:      nativePointerAlignment,
		L1EntryAlignment:      nativeL1EntryAlignment,
		L2EntryAlignment:      nativeL2EntryAlignment,
		PageEntryAlignment:    nativePageEntryAlignment,
		GenerationAlignment:   nativeGenerationAlignment,
		ActiveUsersAlignment:  nativeUsersAlignment,
		L1Mask:                l1Size - 1,
		L2Mask:                l2Size - 1,
		PageOffsetMask:        PageSize - 1,
		GenerationSize:        nativeGenerationSize,
		ActiveUsersSize:       nativeUsersSize,
		Limitations: NativeTableExecutableWriteSlowPath |
			NativeTableWriteWatchSlowPath,
		owner: m,
	}
	m.mu.Unlock()
	runtime.KeepAlive(m)
	return d
}

// Acquire pins table entries against mapping mutation. A false result means
// the caller must retry or leave native execution without dereferencing them.
func (d NativeTableDescriptor) Acquire() (uint64, bool) {
	d.requireValid()
	generation := (*atomic.Uint64)(d.Generation).Load()
	if generation&1 != 0 {
		runtime.KeepAlive(d.owner)
		return 0, false
	}
	users := (*atomic.Uint64)(d.ActiveUsers)
	users.Add(1)
	if (*atomic.Uint64)(d.Generation).Load() != generation {
		users.Add(^uint64(0))
		runtime.KeepAlive(d.owner)
		return 0, false
	}
	runtime.KeepAlive(d.owner)
	return generation, true
}

// Release ends an access started by Acquire.
func (d NativeTableDescriptor) Release() {
	d.requireValid()
	(*atomic.Uint64)(d.ActiveUsers).Add(^uint64(0))
	runtime.KeepAlive(d.owner)
}

// MappingGeneration loads the generation through the descriptor.
func (d NativeTableDescriptor) MappingGeneration() uint64 {
	d.requireValid()
	generation := (*atomic.Uint64)(d.Generation).Load()
	runtime.KeepAlive(d.owner)
	return generation
}

// GenerationMatches reports whether generation is still current and even.
func (d NativeTableDescriptor) GenerationMatches(generation uint64) bool {
	return generation&1 == 0 && d.MappingGeneration() == generation
}

// ResolveRead resolves one readable guest byte.
func (d NativeTableDescriptor) ResolveRead(addr uint64) (NativePage, error) {
	return d.Resolve(addr, PermRead)
}

// ResolveWrite resolves one writable guest byte.
func (d NativeTableDescriptor) ResolveWrite(addr uint64) (NativePage, error) {
	return d.Resolve(addr, PermWrite)
}

// Resolve returns a page snapshot after an even, unchanged generation check.
func (d NativeTableDescriptor) Resolve(addr uint64, requiredPerms uint8) (NativePage, error) {
	d.requireValid()
	if !isCanonicalAddress(addr, d.AddressBits) {
		return NativePage{}, nativeTableFault(addr, requiredPerms, nil)
	}

	for {
		generation := (*atomic.Uint64)(d.Generation).Load()
		if generation&1 != 0 {
			runtime.Gosched()
			continue
		}
		page, fault := d.resolveOnce(addr, requiredPerms)
		if (*atomic.Uint64)(d.Generation).Load() != generation {
			runtime.Gosched()
			continue
		}
		if fault != nil {
			runtime.KeepAlive(d.owner)
			return NativePage{}, fault
		}
		page.Generation = generation
		runtime.KeepAlive(d.owner)
		return page, nil
	}
}

// ValidateRange checks every page in [addr, addr+size) under one generation.
func (d NativeTableDescriptor) ValidateRange(addr, size uint64, requiredPerms uint8) (NativeRange, error) {
	d.requireValid()
	if size == 0 {
		if !isCanonicalAddress(addr, d.AddressBits) {
			return NativeRange{}, nativeTableFault(addr, requiredPerms, nil)
		}
		for {
			generation := (*atomic.Uint64)(d.Generation).Load()
			if generation&1 != 0 {
				runtime.Gosched()
				continue
			}
			if (*atomic.Uint64)(d.Generation).Load() == generation {
				runtime.KeepAlive(d.owner)
				return NativeRange{Address: addr, Generation: generation}, nil
			}
		}
	}

	lastAddr, faultAddr, ok := canonicalRangeEnd(addr, size, d.AddressBits)
	if !ok {
		return NativeRange{}, nativeTableFault(faultAddr, requiredPerms, nil)
	}

	for {
		generation := (*atomic.Uint64)(d.Generation).Load()
		if generation&1 != 0 {
			runtime.Gosched()
			continue
		}

		var first, last NativePage
		var fault *Fault
		pageCount := uint64(0)
		for current := addr; ; {
			page, pageFault := d.resolveOnce(current, requiredPerms)
			if pageFault != nil {
				fault = pageFault
				break
			}
			if pageCount == 0 {
				first = page
			}
			last = page
			pageCount++
			if page.GuestPage == lastAddr&^d.PageOffsetMask {
				break
			}
			current = page.GuestPage + uint64(PageSize)
		}

		if (*atomic.Uint64)(d.Generation).Load() != generation {
			runtime.Gosched()
			continue
		}
		if fault != nil {
			runtime.KeepAlive(d.owner)
			return NativeRange{}, fault
		}

		first.Generation = generation
		last.Generation = generation
		firstBytes := size
		if firstBytes > first.BytesToPageEnd {
			firstBytes = first.BytesToPageEnd
		}
		lastBytes := (lastAddr & d.PageOffsetMask) + 1
		if pageCount == 1 {
			lastBytes = size
		}
		runtime.KeepAlive(d.owner)
		return NativeRange{
			Address:    addr,
			Length:     size,
			Generation: generation,
			PageCount:  pageCount,
			FirstBytes: firstBytes,
			LastBytes:  lastBytes,
			First:      first,
			Last:       last,
		}, nil
	}
}

// DirectWriteNeedsSlowPath reports whether a native write cannot preserve MMU
// side effects. The caller must snapshot writeWatchActive without racing with
// watchpoint configuration.
func (d NativeTableDescriptor) DirectWriteNeedsSlowPath(page NativePage, writeWatchActive bool) bool {
	d.requireValid()
	runtime.KeepAlive(d.owner)
	return page.Permissions&PermExecute != 0 || writeWatchActive
}

func (d NativeTableDescriptor) resolveOnce(addr uint64, requiredPerms uint8) (NativePage, *Fault) {
	l1Index := (addr >> d.L1Shift) & d.L1Mask
	l1Slot := (*atomic.Pointer[l2Table])(unsafe.Add(d.L1Root, uintptr(l1Index)*d.L1EntrySize))
	l2 := l1Slot.Load()
	if l2 == nil {
		return NativePage{}, nativeTableFault(addr, requiredPerms, nil)
	}

	l2Index := (addr >> d.L2Shift) & d.L2Mask
	l2Slot := (*atomic.Pointer[PageEntry])(unsafe.Add(unsafe.Pointer(l2), uintptr(l2Index)*d.L2EntrySize))
	entry := l2Slot.Load()
	if entry == nil {
		return NativePage{}, nativeTableFault(addr, requiredPerms, nil)
	}

	entryPointer := unsafe.Pointer(entry)
	perms := *(*uint8)(unsafe.Add(entryPointer, d.PagePermissionsOffset))
	if perms&requiredPerms != requiredPerms {
		return NativePage{}, nativeTableFault(addr, requiredPerms, entry)
	}
	hostPage := *(*unsafe.Pointer)(unsafe.Add(entryPointer, d.PageDataOffset))
	dataLength := *(*uintptr)(unsafe.Add(entryPointer, d.PageDataLengthOffset))
	offset := addr & d.PageOffsetMask
	if hostPage == nil || offset >= uint64(dataLength) {
		return NativePage{}, nativeTableFault(addr, requiredPerms, nil)
	}
	available := uint64(dataLength) - offset
	if pageRemaining := uint64(PageSize) - offset; available > pageRemaining {
		available = pageRemaining
	}
	return NativePage{
		Entry:          entry,
		HostPage:       hostPage,
		HostPointer:    unsafe.Add(hostPage, uintptr(offset)),
		GuestPage:      addr &^ d.PageOffsetMask,
		Offset:         offset,
		BytesToPageEnd: available,
		Permissions:    perms,
	}, nil
}

func (d NativeTableDescriptor) requireValid() {
	if d.owner == nil || d.L1Root == nil || d.Generation == nil || d.ActiveUsers == nil {
		panic("mmu: invalid native table descriptor")
	}
}

func nativeTableFault(addr uint64, requiredPerms uint8, entry *PageEntry) *Fault {
	if entry == nil {
		return &Fault{Addr: addr, Type: FaultUnmapped, Perms: requiredPerms}
	}
	return &Fault{Addr: addr, Type: FaultPermission, Perms: entry.Perms}
}

func validateNativeAtomicLayout() {
	var target byte
	var pointer atomic.Pointer[byte]
	pointer.Store(&target)
	if *(*unsafe.Pointer)(unsafe.Pointer(&pointer)) != unsafe.Pointer(&target) {
		panic("mmu: atomic pointer payload is not at offset zero")
	}

	const marker = uint64(0x9e3779b97f4a7c15)
	var generation atomic.Uint64
	generation.Store(marker)
	if *(*uint64)(unsafe.Pointer(&generation)) != marker {
		panic("mmu: atomic uint64 payload is not at offset zero")
	}
}
