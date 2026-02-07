//go:build guest_windows

package comctl32

import "sync"

// FlatScrollBar stubs (FlatSB_*)
// ReactOS: comctl32/flatsb.c
// These replace the system scrollbar with a custom "flat" look.
// We store per-window flat-scroll state but otherwise behave like the system scrollbar.

const (
	// FlatSB properties (WSB_PROP_*)
	WSB_PROP_CYVSCROLL = 0x00000001
	WSB_PROP_CXHSCROLL = 0x00000002
	WSB_PROP_CYHSCROLL = 0x00000004
	WSB_PROP_CXVSCROLL = 0x00000008
	WSB_PROP_CXHTHUMB  = 0x00000010
	WSB_PROP_CYVTHUMB  = 0x00000020
	WSB_PROP_VBKGCOLOR = 0x00000040
	WSB_PROP_HBKGCOLOR = 0x00000080
	WSB_PROP_VSTYLE    = 0x00000100
	WSB_PROP_HSTYLE    = 0x00000200
	WSB_PROP_WINSTYLE  = 0x00000400
	WSB_PROP_PALETTE   = 0x00000800
	WSB_PROP_NOCHANGE  = 0x00001000

	// Style values
	FSB_REGULAR_MODE = 0
	FSB_ENCARTA_MODE = 1
	FSB_FLAT_MODE    = 2
)

type flatSBState struct {
	mu          sync.Mutex
	props       map[uint32]int32
	bars        map[int32]*flatScrollState
	initialized bool
}

type flatScrollState struct {
	min      int32
	max      int32
	page     uint32
	pos      int32
	trackPos int32
}

var (
	fsbMu  sync.Mutex
	fsbMap = map[uint64]*flatSBState{}
)

func getFSB(hwnd uint64) *flatSBState {
	fsbMu.Lock()
	defer fsbMu.Unlock()
	s := fsbMap[hwnd]
	if s == nil {
		s = &flatSBState{
			props: make(map[uint32]int32),
			bars:  make(map[int32]*flatScrollState),
		}
		fsbMap[hwnd] = s
	}
	return s
}

func getFSBBar(s *flatSBState, nBar int32) *flatScrollState {
	bar := s.bars[nBar]
	if bar == nil {
		bar = &flatScrollState{}
		s.bars[nBar] = bar
	}
	return bar
}

// InitializeFlatSB initializes flat scroll bars for hwnd
func InitializeFlatSB(hwnd uint64) bool {
	s := getFSB(hwnd)
	s.mu.Lock()
	s.initialized = true
	s.mu.Unlock()
	return true
}

// UninitializeFlatSB removes flat scroll bars for hwnd
func UninitializeFlatSB(hwnd uint64) uint32 {
	fsbMu.Lock()
	defer fsbMu.Unlock()
	delete(fsbMap, hwnd)
	return 0 // S_OK
}

// FlatSB_GetScrollProp gets a flat-scroll property
func FlatSBGetScrollProp(hwnd uint64, propIndex uint32, pValue *int32) bool {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.props[propIndex]; ok {
		*pValue = v
		return true
	}
	*pValue = 0
	return true
}

// FlatSB_SetScrollProp sets a flat-scroll property
func FlatSBSetScrollProp(hwnd uint64, index uint32, newValue int32, _ bool) bool {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.props[index] = newValue
	return true
}

// FlatSBGetScrollPos gets the current flat-scroll position for a bar.
func FlatSBGetScrollPos(hwnd uint64, nBar int32) int32 {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	return getFSBBar(s, nBar).pos
}

// FlatSBGetScrollRange gets the current flat-scroll range for a bar.
func FlatSBGetScrollRange(hwnd uint64, nBar int32) (int32, int32) {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	bar := getFSBBar(s, nBar)
	return bar.min, bar.max
}

// FlatSBGetScrollInfo gets the tracked flat-scroll info for a bar.
func FlatSBGetScrollInfo(hwnd uint64, nBar int32) (min, max int32, page uint32, pos, trackPos int32) {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	bar := getFSBBar(s, nBar)
	return bar.min, bar.max, bar.page, bar.pos, bar.trackPos
}

// FlatSBSetScrollInfo updates the tracked flat-scroll info and returns the resulting position.
func FlatSBSetScrollInfo(hwnd uint64, nBar int32, mask uint32, min, max int32, page uint32, pos, trackPos int32, _ bool) int32 {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	bar := getFSBBar(s, nBar)
	if mask&0x01 != 0 {
		bar.min = min
		bar.max = max
	}
	if mask&0x02 != 0 {
		bar.page = page
	}
	if mask&0x04 != 0 {
		bar.pos = pos
	}
	if mask&0x10 != 0 {
		bar.trackPos = trackPos
	}
	if bar.pos < bar.min {
		bar.pos = bar.min
	}
	if bar.max >= bar.min && bar.pos > bar.max {
		bar.pos = bar.max
	}
	if bar.trackPos < bar.min {
		bar.trackPos = bar.min
	}
	if bar.max >= bar.min && bar.trackPos > bar.max {
		bar.trackPos = bar.max
	}
	return bar.pos
}

// FlatSBSetScrollPos updates the tracked flat-scroll position and returns the previous one.
func FlatSBSetScrollPos(hwnd uint64, nBar int32, pos int32, _ bool) int32 {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	bar := getFSBBar(s, nBar)
	old := bar.pos
	bar.pos = pos
	if bar.pos < bar.min {
		bar.pos = bar.min
	}
	if bar.max >= bar.min && bar.pos > bar.max {
		bar.pos = bar.max
	}
	bar.trackPos = bar.pos
	return old
}

// FlatSBSetScrollRange updates the tracked flat-scroll range.
func FlatSBSetScrollRange(hwnd uint64, nBar int32, min, max int32, _ bool) bool {
	s := getFSB(hwnd)
	s.mu.Lock()
	defer s.mu.Unlock()
	bar := getFSBBar(s, nBar)
	bar.min = min
	bar.max = max
	if bar.pos < min {
		bar.pos = min
	}
	if max >= min && bar.pos > max {
		bar.pos = max
	}
	if bar.trackPos < min {
		bar.trackPos = min
	}
	if max >= min && bar.trackPos > max {
		bar.trackPos = max
	}
	return true
}

// ─── MRU (Most Recently Used) list ───────────────────────────────────────────

// MRU list stub - just tracks strings in order
type mruList struct {
	mu      sync.Mutex
	items   []string
	maxSize int
}

var (
	mruMu     sync.Mutex
	mruMap           = map[uint64]*mruList{}
	mruNextID uint64 = 0x80000
)

// CreateMRUListW creates an MRU list handle
func CreateMRUListW(maxItems int32) uint64 {
	m := &mruList{maxSize: int(maxItems)}
	mruMu.Lock()
	mruNextID++
	id := mruNextID
	mruMap[id] = m
	mruMu.Unlock()
	return id
}

// FreeMRUList frees an MRU list
func FreeMRUList(h uint64) {
	mruMu.Lock()
	defer mruMu.Unlock()
	delete(mruMap, h)
}

// AddMRUStringW adds a string to the MRU list, returns index or -1
func AddMRUStringW(h uint64, s string) int32 {
	mruMu.Lock()
	m := mruMap[h]
	mruMu.Unlock()
	if m == nil {
		return -1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Remove existing
	for i, item := range m.items {
		if item == s {
			m.items = append(m.items[:i], m.items[i+1:]...)
			break
		}
	}
	// Prepend
	m.items = append([]string{s}, m.items...)
	if len(m.items) > m.maxSize {
		m.items = m.items[:m.maxSize]
	}
	return 0
}

// EnumMRUListW enumerates MRU items; returns count or -1 for full list count
func EnumMRUListW(h uint64, nItem int32, _ uint64, _ uint32) int32 {
	mruMu.Lock()
	m := mruMap[h]
	mruMu.Unlock()
	if m == nil {
		return -1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if nItem < 0 {
		return int32(len(m.items))
	}
	return -1
}

// ─── DllGetVersion ───────────────────────────────────────────────────────────

// DLLVERSIONINFO values for comctl32.dll version 6.0 (WindowsXP-era)
const (
	DllVersionMajor    = 6
	DllVersionMinor    = 0
	DllVersionBuildNum = 2600
	DllVersionPlatform = 1 // DLLVER_PLATFORM_WINDOWS
)
