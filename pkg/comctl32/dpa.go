//go:build guest_windows

package comctl32

import "sync"

// DPA (Dynamic Pointer Array) and DSA (Dynamic Structure Array)
// ReactOS: comctl32/dpa.c, comctl32/dsa.c

// DPA is a dynamic array of pointers (uint64 in 64-bit emulation context)
type DPA struct {
	mu   sync.Mutex
	ptrs []uint64
	grow int // growth increment (not used for correctness, only perf)
}

var (
	dpaMu     sync.Mutex
	dpaMap    = map[uint64]*DPA{}
	dpaNextID uint64 = 0x50000
)

func allocDPA(grow int) uint64 {
	d := &DPA{grow: grow}
	dpaMu.Lock()
	dpaNextID++
	id := dpaNextID
	dpaMap[id] = d
	dpaMu.Unlock()
	return id
}

func getDPA(h uint64) *DPA {
	dpaMu.Lock()
	defer dpaMu.Unlock()
	return dpaMap[h]
}

// DPA_Create creates a DPA (DPA_Create)
func DPACreate(cGrow int32) uint64 {
	return allocDPA(int(cGrow))
}

// DPA_CreateEx creates a DPA with a custom heap (DPA_CreateEx) - heap ignored
func DPACreateEx(cGrow int32, _ uint64) uint64 {
	return allocDPA(int(cGrow))
}

// DPA_Destroy frees a DPA (DPA_Destroy)
func DPADestroy(h uint64) bool {
	dpaMu.Lock()
	defer dpaMu.Unlock()
	if _, ok := dpaMap[h]; ok {
		delete(dpaMap, h)
		return true
	}
	return false
}

// DPA_Clone copies a DPA (DPA_Clone)
func DPAClone(h, hDst uint64) uint64 {
	src := getDPA(h)
	if src == nil {
		return 0
	}
	src.mu.Lock()
	ptrs := make([]uint64, len(src.ptrs))
	copy(ptrs, src.ptrs)
	grow := src.grow
	src.mu.Unlock()

	var id uint64
	if hDst != 0 {
		dst := getDPA(hDst)
		if dst == nil {
			return 0
		}
		dst.mu.Lock()
		dst.ptrs = ptrs
		dst.mu.Unlock()
		id = hDst
	} else {
		id = allocDPA(grow)
		dst := getDPA(id)
		if dst == nil {
			return 0
		}
		dst.mu.Lock()
		dst.ptrs = ptrs
		dst.mu.Unlock()
	}
	return id
}

// DPA_GetPtr returns the pointer at index i (DPA_GetPtr)
func DPAGetPtr(h uint64, i int32) uint64 {
	d := getDPA(h)
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.ptrs) {
		return 0
	}
	return d.ptrs[i]
}

// DPA_GetPtrIndex returns the index of ptr in DPA, or -1 (DPA_GetPtrIndex)
func DPAGetPtrIndex(h uint64, ptr uint64) int32 {
	d := getDPA(h)
	if d == nil {
		return -1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, p := range d.ptrs {
		if p == ptr {
			return int32(i)
		}
	}
	return -1
}

// DPA_SetPtr sets pointer at index i (DPA_SetPtr)
func DPASetPtr(h uint64, i int32, ptr uint64) bool {
	d := getDPA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.ptrs) {
		return false
	}
	d.ptrs[i] = ptr
	return true
}

// DPA_InsertPtr inserts a pointer at index i (DPA_InsertPtr)
// i = -1 appends
func DPAInsertPtr(h uint64, i int32, ptr uint64) int32 {
	d := getDPA(h)
	if d == nil {
		return -1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := int32(len(d.ptrs))
	if i < 0 || i >= n {
		d.ptrs = append(d.ptrs, ptr)
		return n
	}
	d.ptrs = append(d.ptrs, 0)
	copy(d.ptrs[i+1:], d.ptrs[i:])
	d.ptrs[i] = ptr
	return i
}

// DPA_DeletePtr removes pointer at index i (DPA_DeletePtr)
func DPADeletePtr(h uint64, i int32) uint64 {
	d := getDPA(h)
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.ptrs) {
		return 0
	}
	ptr := d.ptrs[i]
	d.ptrs = append(d.ptrs[:i], d.ptrs[i+1:]...)
	return ptr
}

// DPA_DeleteAllPtrs removes all pointers (DPA_DeleteAllPtrs)
func DPADeleteAllPtrs(h uint64) bool {
	d := getDPA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ptrs = d.ptrs[:0]
	return true
}

// DPA_Grow pre-allocates capacity (DPA_Grow)
func DPAGrow(h uint64, cp int32) bool {
	d := getDPA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if int(cp) > cap(d.ptrs) {
		newSlice := make([]uint64, len(d.ptrs), cp)
		copy(newSlice, d.ptrs)
		d.ptrs = newSlice
	}
	return true
}

// DPA_Search binary/linear search (DPA_Search)
// pfnCmp and lParam are guest pointers; we do linear scan returning index or -1
func DPASearch(h uint64, pFind uint64, iStart int32) int32 {
	d := getDPA(h)
	if d == nil {
		return -1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if iStart < 0 {
		iStart = 0
	}
	for i := int(iStart); i < len(d.ptrs); i++ {
		if d.ptrs[i] == pFind {
			return int32(i)
		}
	}
	return -1
}

// DPA_Sort sorts the DPA using a guest comparator (DPA_Sort)
// We can't call guest code here so we skip the actual sort - returns true
func DPASort(_ uint64, _ uint64, _ uint64) bool {
	return true
}

// DPA_EnumCallback calls pfnCB for each item (DPA_EnumCallback)
// Cannot call guest fn here; returns without enumeration
func DPAEnumCallback(_ uint64, _ uint64, _ uint64) {}

// DPA_DestroyCallback calls pfnCB for each item then destroys (DPA_DestroyCallback)
func DPADestroyCallback(h uint64, _ uint64, _ uint64) {
	DPADestroy(h)
}

// ─── DSA (Dynamic Structure Array) ───────────────────────────────────────────

// DSA is a dynamic array of fixed-size structs stored as raw bytes
type DSA struct {
	mu       sync.Mutex
	itemSize int32
	items    [][]byte
}

var (
	dsaMu     sync.Mutex
	dsaMap    = map[uint64]*DSA{}
	dsaNextID uint64 = 0x60000
)

func allocDSA(itemSize int32) uint64 {
	d := &DSA{itemSize: itemSize}
	dsaMu.Lock()
	dsaNextID++
	id := dsaNextID
	dsaMap[id] = d
	dsaMu.Unlock()
	return id
}

func getDSA(h uint64) *DSA {
	dsaMu.Lock()
	defer dsaMu.Unlock()
	return dsaMap[h]
}

// DSA_Create creates a DSA (DSA_Create)
func DSACreate(cbItem int32, _ int32) uint64 {
	if cbItem <= 0 {
		return 0
	}
	return allocDSA(cbItem)
}

// DSA_Destroy frees a DSA (DSA_Destroy)
func DSADestroy(h uint64) bool {
	dsaMu.Lock()
	defer dsaMu.Unlock()
	if _, ok := dsaMap[h]; ok {
		delete(dsaMap, h)
		return true
	}
	return false
}

// DSA_DestroyCallback destroys after calling cb for each item
func DSADestroyCallback(h uint64, _ uint64, _ uint64) {
	DSADestroy(h)
}

// DSA_EnumCallback calls pfnCB for each item (no-op: cannot call guest)
func DSAEnumCallback(_ uint64, _ uint64, _ uint64) {}

// DSA_GetItem copies item at index into pDest (DSA_GetItem)
// Returns true on success. pDest is a host-side byte slice pointer (passed by main.go).
func DSAGetItem(h uint64, i int32) ([]byte, bool) {
	d := getDSA(h)
	if d == nil {
		return nil, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.items) {
		return nil, false
	}
	out := make([]byte, len(d.items[i]))
	copy(out, d.items[i])
	return out, true
}

// DSA_GetItemPtr returns a pointer to the item data (as index into items slice)
func DSAGetItemIndex(h uint64, i int32) bool {
	d := getDSA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return i >= 0 && int(i) < len(d.items)
}

// DSA_SetItem replaces item data at index i (DSA_SetItem)
func DSASetItem(h uint64, i int32, data []byte) bool {
	d := getDSA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.items) {
		return false
	}
	copy(d.items[i], data)
	return true
}

// DSA_InsertItem inserts item data at index i (DSA_InsertItem)
// i = -1 appends. data may be nil (zero-filled slot).
func DSAInsertItem(h uint64, i int32, data []byte) int32 {
	d := getDSA(h)
	if d == nil {
		return -1
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	item := make([]byte, d.itemSize)
	if data != nil {
		n := int(d.itemSize)
		if len(data) < n {
			n = len(data)
		}
		copy(item, data[:n])
	}
	n := int32(len(d.items))
	if i < 0 || i >= n {
		d.items = append(d.items, item)
		return n
	}
	d.items = append(d.items, nil)
	copy(d.items[i+1:], d.items[i:])
	d.items[i] = item
	return i
}

// DSA_DeleteItem removes item at index i (DSA_DeleteItem)
func DSADeleteItem(h uint64, i int32) bool {
	d := getDSA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if i < 0 || int(i) >= len(d.items) {
		return false
	}
	d.items = append(d.items[:i], d.items[i+1:]...)
	return true
}

// DSA_DeleteAllItems removes all items (DSA_DeleteAllItems)
func DSADeleteAllItems(h uint64) bool {
	d := getDSA(h)
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.items = d.items[:0]
	return true
}

// DSA_GetItemCount returns number of items
func DSAGetItemCount(h uint64) int32 {
	d := getDSA(h)
	if d == nil {
		return 0
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return int32(len(d.items))
}
