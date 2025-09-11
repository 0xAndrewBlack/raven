// Package comctl32 implements Windows Common Controls (comctl32.dll) in pure Go,
// mirroring the ReactOS/Wine implementation for use by the Raven PE emulator.
package comctl32

import (
	"sync"
	"sync/atomic"
)

// ImageList flags (ILC_*)
const (
	ILC_MASK       = 0x0001
	ILC_COLOR      = 0x0000
	ILC_COLORDDB   = 0x00FE
	ILC_COLOR4     = 0x0004
	ILC_COLOR8     = 0x0008
	ILC_COLOR16    = 0x0010
	ILC_COLOR24    = 0x0018
	ILC_COLOR32    = 0x0020
	ILC_PALETTE    = 0x0800
	ILC_MIRROR     = 0x2000
	ILC_PERITEMMIRROR = 0x8000
	ILC_ORIGINALSIZE  = 0x00010000
	ILC_HIGHQUALITYSCALE = 0x00020000
)

// ImageList draw flags (ILD_*)
const (
	ILD_NORMAL      = 0x0000
	ILD_TRANSPARENT = 0x0001
	ILD_MASK        = 0x0010
	ILD_IMAGE       = 0x0020
	ILD_ROP         = 0x0040
	ILD_BLEND25     = 0x0002
	ILD_BLEND50     = 0x0004
	ILD_OVERLAYMASK = 0x0F00
	ILD_PRESERVEALPHA = 0x1000
	ILD_SCALE       = 0x2000
	ILD_DPISCALE    = 0x4000
	ILD_ASYNC       = 0x8000
	ILD_SELECTED    = ILD_BLEND50
	ILD_FOCUS       = ILD_BLEND25
	ILD_BLEND       = ILD_BLEND50
)

// ImageList background color sentinel
const CLR_NONE = uint32(0xFFFFFFFF)

// ilImage is a single image slot in an ImageList
type ilImage struct {
	// In a real impl these would hold pixel data.
	// We track metadata only (sufficient for NPP which just uses icons for toolbar).
	overlayIdx int
}

// ImageList holds state for an HIMAGELIST handle
type ImageList struct {
	mu        sync.Mutex
	cx, cy    int32 // per-image width/height
	flags     uint32
	bkColor   uint32
	images    []ilImage
	dragIndex int // for drag operations; -1 = none
}

var (
	ilMu     sync.Mutex
	ilMap    = map[uint64]*ImageList{}
	ilNextID uint64 = 0x10000 // starts at 64K to avoid confusion with HWNDs
)

// allocIL allocates a new ImageList and returns its handle
func allocIL(cx, cy int32, flags uint32) uint64 {
	il := &ImageList{
		cx:        cx,
		cy:        cy,
		flags:     flags,
		bkColor:   CLR_NONE,
		dragIndex: -1,
	}
	id := atomic.AddUint64(&ilNextID, 1)
	ilMu.Lock()
	ilMap[id] = il
	ilMu.Unlock()
	return id
}

func getIL(h uint64) *ImageList {
	ilMu.Lock()
	defer ilMu.Unlock()
	return ilMap[h]
}

// ImageListCreate creates a new image list (ImageList_Create)
func ImageListCreate(cx, cy int32, flags uint32, cInitial, cGrow int32) uint64 {
	if cx <= 0 || cy <= 0 {
		return 0
	}
	id := allocIL(cx, cy, flags)
	il := getIL(id)
	if il != nil && cInitial > 0 {
		il.images = make([]ilImage, 0, cInitial)
	}
	return id
}

// ImageListDestroy destroys an image list (ImageList_Destroy)
func ImageListDestroy(h uint64) bool {
	ilMu.Lock()
	defer ilMu.Unlock()
	if _, ok := ilMap[h]; ok {
		delete(ilMap, h)
		return true
	}
	return false
}

// ImageListGetImageCount returns the number of images (ImageList_GetImageCount)
func ImageListGetImageCount(h uint64) int32 {
	il := getIL(h)
	if il == nil {
		return 0
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	return int32(len(il.images))
}

// ImageListSetImageCount sets the image count (ImageList_SetImageCount)
func ImageListSetImageCount(h uint64, count uint32) bool {
	il := getIL(h)
	if il == nil {
		return false
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	cur := uint32(len(il.images))
	if count > cur {
		extra := make([]ilImage, count-cur)
		il.images = append(il.images, extra...)
	} else {
		il.images = il.images[:count]
	}
	return true
}

// ImageListAdd adds an image (returns index, -1 on error) (ImageList_Add)
func ImageListAdd(h uint64) int32 {
	il := getIL(h)
	if il == nil {
		return -1
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	idx := int32(len(il.images))
	il.images = append(il.images, ilImage{})
	return idx
}

// ImageListAddMasked adds a masked image (ImageList_AddMasked)
func ImageListAddMasked(h uint64) int32 {
	return ImageListAdd(h)
}

// ImageListReplaceIcon replaces or adds an icon (ImageList_ReplaceIcon)
func ImageListReplaceIcon(h uint64, i int32) int32 {
	il := getIL(h)
	if il == nil {
		return -1
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	if i < 0 || i >= int32(len(il.images)) {
		// Append
		idx := int32(len(il.images))
		il.images = append(il.images, ilImage{})
		return idx
	}
	return i
}

// ImageListRemove removes an image (ImageList_Remove, i=-1 removes all)
func ImageListRemove(h uint64, i int32) bool {
	il := getIL(h)
	if il == nil {
		return false
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	if i < 0 {
		il.images = il.images[:0]
		return true
	}
	if i >= int32(len(il.images)) {
		return false
	}
	il.images = append(il.images[:i], il.images[i+1:]...)
	return true
}

// ImageListGetIconSize returns cx/cy (ImageList_GetIconSize)
func ImageListGetIconSize(h uint64) (cx, cy int32, ok bool) {
	il := getIL(h)
	if il == nil {
		return 0, 0, false
	}
	return il.cx, il.cy, true
}

// ImageListSetIconSize sets cx/cy and clears images (ImageList_SetIconSize)
func ImageListSetIconSize(h uint64, cx, cy int32) bool {
	il := getIL(h)
	if il == nil {
		return false
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	il.cx = cx
	il.cy = cy
	il.images = il.images[:0]
	return true
}

// ImageListGetBkColor returns background color (ImageList_GetBkColor)
func ImageListGetBkColor(h uint64) uint32 {
	il := getIL(h)
	if il == nil {
		return CLR_NONE
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	return il.bkColor
}

// ImageListSetBkColor sets background color (ImageList_SetBkColor)
func ImageListSetBkColor(h uint64, clr uint32) uint32 {
	il := getIL(h)
	if il == nil {
		return CLR_NONE
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	old := il.bkColor
	il.bkColor = clr
	return old
}

// ImageListSetOverlayImage sets an overlay mask index (ImageList_SetOverlayImage)
func ImageListSetOverlayImage(h uint64, iImage int32, iOverlay int32) bool {
	il := getIL(h)
	if il == nil {
		return false
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	if iImage < 0 || iImage >= int32(len(il.images)) {
		return false
	}
	il.images[iImage].overlayIdx = int(iOverlay)
	return true
}

// ImageListDuplicate duplicates an image list (ImageList_Duplicate)
func ImageListDuplicate(h uint64) uint64 {
	il := getIL(h)
	if il == nil {
		return 0
	}
	il.mu.Lock()
	defer il.mu.Unlock()
	newID := allocIL(il.cx, il.cy, il.flags)
	newIL := getIL(newID)
	if newIL == nil {
		return 0
	}
	newIL.bkColor = il.bkColor
	newIL.images = make([]ilImage, len(il.images))
	copy(newIL.images, il.images)
	return newID
}

// ImageListCopy copies one image to another slot (ImageList_Copy)
func ImageListCopy(hDst uint64, iDst int32, hSrc uint64, iSrc int32, uFlags uint32) bool {
	src := getIL(hSrc)
	dst := getIL(hDst)
	if src == nil || dst == nil {
		return false
	}
	src.mu.Lock()
	defer src.mu.Unlock()
	if iSrc < 0 || iSrc >= int32(len(src.images)) {
		return false
	}
	srcImg := src.images[iSrc]
	dst.mu.Lock()
	defer dst.mu.Unlock()
	if iDst < 0 || iDst >= int32(len(dst.images)) {
		return false
	}
	if uFlags&0x1 != 0 { // ILCF_SWAP
		dst.images[iDst], src.images[iSrc] = src.images[iSrc], dst.images[iDst]
	} else {
		dst.images[iDst] = srcImg
	}
	return true
}
