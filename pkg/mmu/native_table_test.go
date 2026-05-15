package mmu

import (
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestNativeTableDescriptorLayout(t *testing.T) {
	m := New()
	d := m.NativeTable()

	if d.PointerSize != uint8(unsafe.Sizeof(uintptr(0))) {
		t.Fatalf("pointer size = %d", d.PointerSize)
	}
	if d.PointerAlignment != unsafe.Alignof(uintptr(0)) ||
		d.L1EntryAlignment != unsafe.Alignof(atomic.Pointer[l2Table]{}) ||
		d.L2EntryAlignment != unsafe.Alignof(atomic.Pointer[PageEntry]{}) ||
		d.PageEntryAlignment != unsafe.Alignof(PageEntry{}) ||
		d.GenerationAlignment != unsafe.Alignof(atomic.Uint64{}) ||
		d.ActiveUsersAlignment != unsafe.Alignof(atomic.Uint64{}) {
		t.Fatal("descriptor alignments do not match Go layouts")
	}
	if d.L1EntrySize != unsafe.Sizeof(atomic.Pointer[l2Table]{}) {
		t.Fatalf("L1 entry size = %d", d.L1EntrySize)
	}
	if d.L2EntrySize != unsafe.Sizeof(atomic.Pointer[PageEntry]{}) {
		t.Fatalf("L2 entry size = %d", d.L2EntrySize)
	}
	if d.PageEntrySize != unsafe.Sizeof(PageEntry{}) {
		t.Fatalf("PageEntry size = %d", d.PageEntrySize)
	}
	if d.PageDataOffset != unsafe.Offsetof(PageEntry{}.Data) {
		t.Fatalf("data offset = %d", d.PageDataOffset)
	}
	if d.PageDataLengthOffset != unsafe.Offsetof(PageEntry{}.Data)+unsafe.Sizeof(uintptr(0)) {
		t.Fatalf("data length offset = %d", d.PageDataLengthOffset)
	}
	if d.PagePermissionsOffset != unsafe.Offsetof(PageEntry{}.Perms) {
		t.Fatalf("permission offset = %d", d.PagePermissionsOffset)
	}
	if d.PageCodeVersionOffset != unsafe.Offsetof(PageEntry{}.CodeVersion) {
		t.Fatalf("code version offset = %d", d.PageCodeVersionOffset)
	}
	if d.L1Shift != 27 || d.L2Shift != 12 || d.AddressBits != 48 {
		t.Fatalf("table shifts = %d/%d address bits = %d", d.L1Shift, d.L2Shift, d.AddressBits)
	}
	if d.L1Mask != l1Size-1 || d.L2Mask != l2Size-1 {
		t.Fatalf("table masks = %#x/%#x", d.L1Mask, d.L2Mask)
	}
	if d.PageOffsetMask != PageSize-1 {
		t.Fatalf("page mask = %#x", d.PageOffsetMask)
	}
	if d.MappingGeneration()&1 != 0 {
		t.Fatal("initial generation is odd")
	}
	if d.ActiveUsersSize != unsafe.Sizeof(atomic.Uint64{}) {
		t.Fatalf("active user size = %d", d.ActiveUsersSize)
	}
}

func TestNativeTableResolveMatchesLookup(t *testing.T) {
	m := New()
	d := m.NativeTable()
	const high = uint64(0x123456789000)

	if err := m.MapPage(0x2000, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(high, PermRead|PermExecute); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(0x207b, 0xa5); err != nil {
		t.Fatal(err)
	}
	if err := m.Write32Raw(high+31, 0xdecafbad); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		addr  uint64
		perms uint8
	}{
		{name: "read", addr: 0x207b, perms: PermRead},
		{name: "write", addr: 0x207b, perms: PermWrite},
		{name: "high execute", addr: high + 31, perms: PermExecute},
		{name: "high write denied", addr: high + 31, perms: PermWrite},
		{name: "unmapped", addr: high + PageSize, perms: PermRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantEntry, wantOffset, wantErr := m.LookupRead(tt.addr, tt.perms)
			got, gotErr := d.Resolve(tt.addr, tt.perms)
			compareNativeFaults(t, gotErr, wantErr)
			if wantErr != nil {
				return
			}
			if got.Entry != wantEntry || got.Offset != wantOffset {
				t.Fatalf("entry/offset mismatch: %p/%d want %p/%d", got.Entry, got.Offset, wantEntry, wantOffset)
			}
			if got.HostPage != unsafe.Pointer(unsafe.SliceData(wantEntry.Data)) {
				t.Fatalf("host page = %p, want %p", got.HostPage, unsafe.SliceData(wantEntry.Data))
			}
			if got.HostPointer != unsafe.Pointer(&wantEntry.Data[wantOffset]) {
				t.Fatalf("host pointer = %p, want %p", got.HostPointer, &wantEntry.Data[wantOffset])
			}
			if got.BytesToPageEnd != PageSize-wantOffset {
				t.Fatalf("bytes to page end = %d", got.BytesToPageEnd)
			}
			if !d.GenerationMatches(got.Generation) {
				t.Fatalf("generation %d is stale", got.Generation)
			}
		})
	}

	writePage, err := d.ResolveWrite(0x207b)
	if err != nil {
		t.Fatal(err)
	}
	*(*byte)(writePage.HostPointer) = 0x5a
	value, err := m.Read8(0x207b)
	if err != nil || value != 0x5a {
		t.Fatalf("read after native write = %#x, %v", value, err)
	}
}

func TestNativeTableMapRemapProtectUnmap(t *testing.T) {
	m := New()
	d := m.NativeTable()
	const addr = uint64(0x200004000)

	first := make([]byte, PageSize)
	first[17] = 0x11
	second := make([]byte, PageSize)
	second[17] = 0x22

	before := d.MappingGeneration()
	m.MapHostSlice(addr, first, PermRead|PermWrite)
	read, err := d.ResolveRead(addr + 17)
	if err != nil || *(*byte)(read.HostPointer) != 0x11 {
		t.Fatalf("first mapping: value=%#x err=%v", nativeByte(read), err)
	}
	if generation := d.MappingGeneration(); generation != before+2 || generation&1 != 0 {
		t.Fatalf("map generation = %d, want %d", generation, before+2)
	}

	m.MapHostSlice(addr, second, PermRead)
	read, err = d.ResolveRead(addr + 17)
	if err != nil || *(*byte)(read.HostPointer) != 0x22 {
		t.Fatalf("remap: value=%#x err=%v", nativeByte(read), err)
	}
	_, err = d.ResolveWrite(addr + 17)
	assertNativeFault(t, err, addr+17, FaultPermission, PermRead)

	if err := m.Mprotect(addr, PageSize, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ResolveWrite(addr + 17); err != nil {
		t.Fatalf("resolve after protect: %v", err)
	}

	m.Munmap(addr, PageSize)
	_, err = d.ResolveRead(addr + 17)
	assertNativeFault(t, err, addr+17, FaultUnmapped, PermRead)

	m.MapHostSlice(addr, first, PermRead)
	read, err = d.ResolveRead(addr + 17)
	if err != nil || *(*byte)(read.HostPointer) != 0x11 {
		t.Fatalf("map after unmap: value=%#x err=%v", nativeByte(read), err)
	}
}

func TestNativeTableRejectsNonCanonicalAddresses(t *testing.T) {
	m := New()
	d := m.NativeTable()
	if err := m.MapPage(0x3000, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}

	for _, addr := range []uint64{
		1<<48 | 0x3000,
		0xffff000000003000,
	} {
		_, _, lookupErr := m.LookupRead(addr, PermRead)
		_, nativeErr := d.ResolveRead(addr)
		compareNativeFaults(t, nativeErr, lookupErr)
		assertNativeFault(t, nativeErr, addr, FaultUnmapped, PermRead)
	}

	if err := m.MapPage(1<<48, PermRead); err == nil {
		t.Fatal("MapPage accepted an address outside the table")
	}
	value, err := m.Read8(0x3000)
	if err != nil || value != 0 {
		t.Fatalf("invalid mapping changed low page: value=%d err=%v", value, err)
	}
}

func TestNativeTableAcceptsHighCanonicalAddresses(t *testing.T) {
	m := New()
	d := m.NativeTable()
	const page = uint64(0xfffffffffffff000)
	if err := m.MapPage(page, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(page+17, 0x5a); err != nil {
		t.Fatal(err)
	}

	resolved, err := d.ResolveRead(page + 17)
	if err != nil {
		t.Fatal(err)
	}
	if got := *(*byte)(resolved.HostPointer); got != 0x5a {
		t.Fatalf("high canonical byte = %#x, want 0x5a", got)
	}
	if resolved.GuestPage != page {
		t.Fatalf("guest page = %#x, want %#x", resolved.GuestPage, page)
	}

	const (
		lowCanonical  = uint64(0x0000123456789000)
		highCanonical = uint64(0xffff923456789000)
	)
	if err := m.MapPage(lowCanonical, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.MapPage(highCanonical, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(lowCanonical, 0x11); err != nil {
		t.Fatal(err)
	}
	if err := m.Write8(highCanonical, 0x22); err != nil {
		t.Fatal(err)
	}
	low, lowErr := m.Read8(lowCanonical)
	high, highErr := m.Read8(highCanonical)
	if lowErr != nil || highErr != nil || low != 0x11 || high != 0x22 {
		t.Fatalf("canonical pages alias: low=%#x err=%v high=%#x err=%v", low, lowErr, high, highErr)
	}

	for _, addr := range []uint64{
		0x0000fffffffff000,
		0xffff000000003000,
	} {
		if err := m.MapPage(addr, PermRead); err == nil {
			t.Fatalf("MapPage accepted non-canonical address %#x", addr)
		}
	}
}

func TestNativeTableValidateRange(t *testing.T) {
	m := New()
	d := m.NativeTable()
	m.MapRange(0x1000, 3*PageSize, PermRead|PermWrite)

	tests := []struct {
		name       string
		addr       uint64
		size       uint64
		perms      uint8
		pageCount  uint64
		firstBytes uint64
		lastBytes  uint64
		faultAddr  uint64
		faultType  FaultType
		faultPerms uint8
	}{
		{name: "empty", addr: 0x1fff, size: 0, perms: PermRead},
		{name: "one page", addr: 0x1100, size: 32, perms: PermRead, pageCount: 1, firstBytes: 32, lastBytes: 32},
		{name: "two pages", addr: 0x1ff8, size: 16, perms: PermWrite, pageCount: 2, firstBytes: 8, lastBytes: 8},
		{name: "three pages", addr: 0x1ff0, size: PageSize + 32, perms: PermRead, pageCount: 3, firstBytes: 16, lastBytes: 16},
		{name: "unmapped end", addr: 0x3ff8, size: 16, perms: PermRead, faultAddr: 0x4000, faultType: FaultUnmapped, faultPerms: PermRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.ValidateRange(tt.addr, tt.size, tt.perms)
			if tt.faultAddr != 0 {
				assertNativeFault(t, err, tt.faultAddr, tt.faultType, tt.faultPerms)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.PageCount != tt.pageCount || got.FirstBytes != tt.firstBytes || got.LastBytes != tt.lastBytes {
				t.Fatalf("range metadata = pages:%d first:%d last:%d", got.PageCount, got.FirstBytes, got.LastBytes)
			}
			if tt.size != 0 && !d.GenerationMatches(got.Generation) {
				t.Fatalf("range generation %d is stale", got.Generation)
			}
		})
	}

	if err := m.Mprotect(0x2000, PageSize, PermRead); err != nil {
		t.Fatal(err)
	}
	_, err := d.ValidateRange(0x1ff8, 16, PermWrite)
	assertNativeFault(t, err, 0x2000, FaultPermission, PermRead)

	_, err = d.ValidateRange((1<<47)-8, 16, PermRead)
	assertNativeFault(t, err, 1<<47, FaultUnmapped, PermRead)

	_, err = d.ValidateRange(^uint64(0)-3, 8, PermRead)
	assertNativeFault(t, err, ^uint64(0), FaultUnmapped, PermRead)
}

func TestNativeTableRandomizedAgainstLookupRead(t *testing.T) {
	const pageCount = 384
	rng := rand.New(rand.NewSource(0x4d4d55))
	m := New()
	d := m.NativeTable()
	pages := make(map[uint64]uint8, pageCount)

	for len(pages) < pageCount {
		page := (uint64(rng.Int63n(1<<32)) << PageShift) & ((uint64(1) << 48) - PageSize)
		perms := uint8(1 + rng.Intn(7))
		if _, exists := pages[page]; exists {
			continue
		}
		if err := m.MapPage(page, perms); err != nil {
			t.Fatal(err)
		}
		value := byte(len(pages))
		if err := m.WriteBytesRaw(page+127, []byte{value}); err != nil {
			t.Fatal(err)
		}
		pages[page] = perms
	}

	addresses := make([]uint64, 0, len(pages))
	for page := range pages {
		addresses = append(addresses, page)
	}
	for i := 0; i < 5000; i++ {
		page := addresses[rng.Intn(len(addresses))]
		addr := page + uint64(rng.Intn(PageSize))
		if rng.Intn(5) == 0 {
			addr += 1 << 47
		}
		required := uint8(1 << rng.Intn(3))

		wantEntry, wantOffset, wantErr := m.LookupRead(addr, required)
		got, gotErr := d.Resolve(addr, required)
		compareNativeFaults(t, gotErr, wantErr)
		switch required {
		case PermRead:
			_, readErr := m.Read8(addr)
			compareNativeFaults(t, gotErr, readErr)
		case PermWrite:
			writeErr := m.Write8(addr, 0x5c)
			compareNativeFaults(t, gotErr, writeErr)
			if writeErr == nil && *(*byte)(got.HostPointer) != 0x5c {
				t.Fatalf("iteration %d: descriptor did not observe Write8 at %#x", i, addr)
			}
		}
		if wantErr == nil {
			if got.Entry != wantEntry || got.Offset != wantOffset || got.Permissions != wantEntry.Perms {
				t.Fatalf("iteration %d: descriptor lookup differs at %#x", i, addr)
			}
		}
	}
}

func TestNativeTableConcurrentMutation(t *testing.T) {
	m := New()
	const addr = uint64(0x3456789000)
	first := make([]byte, PageSize)
	second := make([]byte, PageSize)
	for i := range first {
		first[i] = 0x11
		second[i] = 0x22
	}
	m.MapHostSlice(addr, first, PermRead)
	d := m.NativeTable()

	var stop atomic.Bool
	var failed atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(offset uint64) {
			defer wg.Done()
			for !stop.Load() {
				page, err := d.ResolveRead(addr + offset)
				if err != nil {
					if fault, ok := err.(*Fault); !ok ||
						(fault.Type != FaultUnmapped && fault.Type != FaultPermission) {
						failed.Store(true)
						return
					}
					runtime.Gosched()
					continue
				}
				value := *(*byte)(page.HostPointer)
				if value != 0x11 && value != 0x22 {
					failed.Store(true)
					return
				}
			}
		}(uint64(i * 97))
	}

	for i := 0; i < 3000; i++ {
		switch i % 5 {
		case 0:
			m.MapHostSlice(addr, first, PermRead)
		case 1:
			m.MapHostSlice(addr, second, PermRead|PermWrite)
		case 2:
			if err := m.Mprotect(addr, PageSize, PermWrite); err != nil {
				t.Fatal(err)
			}
		case 3:
			m.Munmap(addr, PageSize)
		case 4:
			m.MapHostSlice(addr, second, PermRead)
		}
	}
	stop.Store(true)
	wg.Wait()
	if failed.Load() {
		t.Fatal("descriptor returned a torn or invalid page during mutation")
	}
	if d.MappingGeneration()&1 != 0 {
		t.Fatal("mapping generation remained odd")
	}
}

func TestNativeTableAcquireBlocksMappingMutation(t *testing.T) {
	m := New()
	const addr = uint64(0x3456789000)
	if err := m.MapPage(addr, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	d := m.NativeTable()
	if _, ok := d.Acquire(); !ok {
		t.Fatal("failed to acquire stable native table")
	}

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		m.Munmap(addr, PageSize)
		close(done)
	}()
	<-started
	for i := 0; i < 1000 && d.MappingGeneration()&1 == 0; i++ {
		runtime.Gosched()
	}
	if d.MappingGeneration()&1 == 0 {
		t.Fatal("mapping mutation did not publish an odd generation")
	}
	select {
	case <-done:
		t.Fatal("mapping mutation completed while native access was active")
	default:
	}

	d.Release()
	<-done
	if d.MappingGeneration()&1 != 0 {
		t.Fatal("mapping mutation left an odd generation")
	}
	if _, err := d.ResolveRead(addr); err == nil {
		t.Fatal("page remained mapped after mutation")
	}
}

func TestNativeTableSnapshotKeepsPageAliveAcrossGC(t *testing.T) {
	m := New()
	const addr = uint64(0x456789a000)
	first := make([]byte, PageSize)
	first[23] = 0x7d
	m.MapHostSlice(addr, first, PermRead)
	d := m.NativeTable()

	stale, err := d.ResolveRead(addr + 23)
	if err != nil {
		t.Fatal(err)
	}
	m.Munmap(addr, PageSize)
	first = nil
	for i := 0; i < 5; i++ {
		runtime.GC()
	}

	if value := *(*byte)(stale.HostPointer); value != 0x7d {
		t.Fatalf("snapshot page value = %#x", value)
	}
	if stale.Entry == nil || len(stale.Entry.Data) != PageSize {
		t.Fatal("snapshot did not keep its page entry alive")
	}
}

func TestNativeTableWriteLimitations(t *testing.T) {
	m := New()
	d := m.NativeTable()
	const addr = uint64(0x8000)
	if err := m.MapPage(addr, PermRead|PermWrite|PermExecute); err != nil {
		t.Fatal(err)
	}
	page, err := d.ResolveWrite(addr)
	if err != nil {
		t.Fatal(err)
	}
	if d.Limitations&NativeTableExecutableWriteSlowPath == 0 ||
		d.Limitations&NativeTableWriteWatchSlowPath == 0 {
		t.Fatalf("missing limitations: %#x", d.Limitations)
	}
	if !d.DirectWriteNeedsSlowPath(page, false) {
		t.Fatal("executable write did not require the slow path")
	}

	if err := m.Mprotect(addr, PageSize, PermRead|PermWrite); err != nil {
		t.Fatal(err)
	}
	page, err = d.ResolveWrite(addr)
	if err != nil {
		t.Fatal(err)
	}
	if d.DirectWriteNeedsSlowPath(page, false) {
		t.Fatal("ordinary write unexpectedly required the slow path")
	}

	if !d.DirectWriteNeedsSlowPath(page, true) {
		t.Fatal("watched write did not require the slow path")
	}
}

func BenchmarkNativeTableResolve(b *testing.B) {
	m := New()
	const addr = uint64(0x123456789123)
	if err := m.MapPage(addr, PermRead|PermWrite); err != nil {
		b.Fatal(err)
	}
	d := m.NativeTable()

	b.Run("LookupRead", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			entry, offset, err := m.LookupRead(addr, PermRead)
			if err != nil || entry == nil || offset != addr&(PageSize-1) {
				b.Fatal("lookup failed")
			}
		}
	})
	b.Run("NativeDescriptor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			page, err := d.ResolveRead(addr)
			if err != nil || page.Entry == nil || page.Offset != addr&(PageSize-1) {
				b.Fatal("lookup failed")
			}
		}
	})
}

func compareNativeFaults(t *testing.T, got, want error) {
	t.Helper()
	if got == nil || want == nil {
		if got != nil || want != nil {
			t.Fatalf("errors differ: got %v want %v", got, want)
		}
		return
	}
	gotFault, gotOK := got.(*Fault)
	wantFault, wantOK := want.(*Fault)
	if !gotOK || !wantOK {
		t.Fatalf("fault types differ: got %T want %T", got, want)
	}
	if *gotFault != *wantFault {
		t.Fatalf("faults differ: got %+v want %+v", gotFault, wantFault)
	}
}

func assertNativeFault(t *testing.T, err error, addr uint64, faultType FaultType, perms uint8) {
	t.Helper()
	fault, ok := err.(*Fault)
	if !ok {
		t.Fatalf("error = %T %v, want *Fault", err, err)
	}
	if fault.Addr != addr || fault.Type != faultType || fault.Perms != perms {
		t.Fatalf("fault = %+v, want addr=%#x type=%d perms=%#x", fault, addr, faultType, perms)
	}
}

func nativeByte(page NativePage) byte {
	if page.HostPointer == nil {
		return 0
	}
	return *(*byte)(page.HostPointer)
}
