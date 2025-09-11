package win32

import "sync"

// Scrollbar info - mirrors Windows SCROLLINFO struct.
// ReactOS: win32ss/user/user32/controls/scroll.c
type ScrollInfo struct {
	Min  int32
	Max  int32
	Page uint32
	Pos  int32
	// TrackPos is only valid during SB_THUMBTRACK/SB_THUMBPOSITION.
	TrackPos int32
}

// SIF_* flags for GetScrollInfo / SetScrollInfo.
const (
	SIF_RANGE    = 0x0001
	SIF_PAGE     = 0x0002
	SIF_POS      = 0x0004
	SIF_DISABLENOSCROLL = 0x0008
	SIF_TRACKPOS = 0x0010
	SIF_ALL      = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS
)

// SB_* bar identifiers (nBar param of SetScrollInfo etc.)
const (
	SB_HORZ = 0
	SB_VERT = 1
	SB_CTL  = 2
	SB_BOTH = 3
)

// Scroll message codes (wParam of WM_HSCROLL / WM_VSCROLL)
const (
	SB_LINEUP        = 0
	SB_LINELEFT      = 0
	SB_LINEDOWN      = 1
	SB_LINERIGHT     = 1
	SB_PAGEUP        = 2
	SB_PAGELEFT      = 2
	SB_PAGEDOWN      = 3
	SB_PAGERIGHT     = 3
	SB_THUMBPOSITION = 4
	SB_THUMBTRACK    = 5
	SB_TOP           = 6
	SB_LEFT          = 6
	SB_BOTTOM        = 7
	SB_RIGHT         = 7
	SB_ENDSCROLL     = 8
)

type scrollKey struct {
	hwnd uint64
	bar  int // SB_HORZ or SB_VERT or SB_CTL
}

var (
	scrollMu   sync.RWMutex
	scrollData = make(map[scrollKey]ScrollInfo)
)

// SetScrollInfo stores the scrollbar state for (hwnd, nBar).
// Returns the new thumb position (clamped to range).
func SetScrollInfo(hwnd uint64, nBar int, si *ScrollInfo, mask uint32) int32 {
	if si == nil {
		return 0
	}
	k := scrollKey{hwnd, nBar}
	scrollMu.Lock()
	cur := scrollData[k]
	if mask&SIF_RANGE != 0 {
		cur.Min = si.Min
		cur.Max = si.Max
	}
	if mask&SIF_PAGE != 0 {
		cur.Page = si.Page
	}
	if mask&SIF_POS != 0 {
		cur.Pos = clampScroll(si.Pos, cur.Min, cur.Max)
	}
	scrollData[k] = cur
	pos := cur.Pos
	scrollMu.Unlock()
	return pos
}

// GetScrollInfo retrieves scrollbar state into si.
// Returns true on success.
func GetScrollInfo(hwnd uint64, nBar int, si *ScrollInfo, mask uint32) bool {
	if si == nil {
		return false
	}
	k := scrollKey{hwnd, nBar}
	scrollMu.RLock()
	cur := scrollData[k]
	scrollMu.RUnlock()
	if mask&SIF_RANGE != 0 {
		si.Min = cur.Min
		si.Max = cur.Max
	}
	if mask&SIF_PAGE != 0 {
		si.Page = cur.Page
	}
	if mask&SIF_POS != 0 {
		si.Pos = cur.Pos
	}
	if mask&SIF_TRACKPOS != 0 {
		si.TrackPos = cur.TrackPos
	}
	return true
}

// GetScrollPos returns the current thumb position.
func GetScrollPos(hwnd uint64, nBar int) int32 {
	k := scrollKey{hwnd, nBar}
	scrollMu.RLock()
	pos := scrollData[k].Pos
	scrollMu.RUnlock()
	return pos
}

// SetScrollPos sets just the thumb position.  Returns previous position.
func SetScrollPos(hwnd uint64, nBar int, pos int32) int32 {
	k := scrollKey{hwnd, nBar}
	scrollMu.Lock()
	cur := scrollData[k]
	prev := cur.Pos
	cur.Pos = clampScroll(pos, cur.Min, cur.Max)
	scrollData[k] = cur
	scrollMu.Unlock()
	return prev
}

// GetScrollRange returns the min/max of the scrollbar.
func GetScrollRange(hwnd uint64, nBar int) (min, max int32) {
	k := scrollKey{hwnd, nBar}
	scrollMu.RLock()
	cur := scrollData[k]
	scrollMu.RUnlock()
	return cur.Min, cur.Max
}

// SetScrollRange sets min/max.
func SetScrollRange(hwnd uint64, nBar int, min, max int32) {
	k := scrollKey{hwnd, nBar}
	scrollMu.Lock()
	cur := scrollData[k]
	cur.Min = min
	cur.Max = max
	cur.Pos = clampScroll(cur.Pos, min, max)
	scrollData[k] = cur
	scrollMu.Unlock()
}

func clampScroll(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
