//go:build guest_windows

package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/arch"
	comctl32pkg "github.com/mirkobrombin/Raven/pkg/comctl32"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	subclassDispatchThunkID uint32 = 0x3FFB
	subclassReturnThunkID   uint32 = 0x3FFA
	subclassContinueThunkID uint32 = 0x3FF9
)

type subclassWindowInfo struct {
	original uint64
	builtin  bool
}

type subclassDispatchFrame struct {
	hwnd       uint64
	entries    []comctl32pkg.SubclassEntry
	next       int
	original   uint64
	builtin    bool
	returnAddr uint64
	resumeSP   uint64
	returns    []subclassContinuation
}

type subclassContinuation struct {
	returnAddr uint64
	resumeSP   uint64
}

type subclassCPUDispatch struct {
	mu     sync.Mutex
	frames []subclassDispatchFrame
}

type subclassDispatchRuntime struct {
	cpus    sync.Map
	windows sync.Map
}

func (r *subclassDispatchRuntime) cpu(cpu arch.CPU) *subclassCPUDispatch {
	state := new(subclassCPUDispatch)
	actual, _ := r.cpus.LoadOrStore(cpu, state)
	return actual.(*subclassCPUDispatch)
}

func (r *subclassDispatchRuntime) installWindow(hwnd uint64, info subclassWindowInfo) subclassWindowInfo {
	actual, _ := r.windows.LoadOrStore(hwnd, info)
	return actual.(subclassWindowInfo)
}

func (r *subclassDispatchRuntime) removeWindow(hwnd uint64) (subclassWindowInfo, bool) {
	info, ok := r.windows.LoadAndDelete(hwnd)
	if !ok {
		return subclassWindowInfo{}, false
	}
	return info.(subclassWindowInfo), true
}

func (r *subclassDispatchRuntime) window(hwnd uint64) (subclassWindowInfo, bool) {
	info, ok := r.windows.Load(hwnd)
	if !ok {
		return subclassWindowInfo{}, false
	}
	return info.(subclassWindowInfo), true
}

func (r *subclassDispatchRuntime) begin(cpu arch.CPU, frame subclassDispatchFrame) {
	state := r.cpu(cpu)
	state.mu.Lock()
	state.frames = append(state.frames, frame)
	state.mu.Unlock()
}

func (r *subclassDispatchRuntime) nextEntry(cpu arch.CPU, hwnd uint64) (comctl32pkg.SubclassEntry, subclassDispatchFrame, bool) {
	state := r.cpu(cpu)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.frames) == 0 {
		return comctl32pkg.SubclassEntry{}, subclassDispatchFrame{}, false
	}
	frame := &state.frames[len(state.frames)-1]
	if frame.hwnd != hwnd {
		return comctl32pkg.SubclassEntry{}, subclassDispatchFrame{}, false
	}
	for frame.next < len(frame.entries) {
		snapshot := frame.entries[frame.next]
		frame.next++
		if current, ok := comctl32pkg.CurrentSubclass(hwnd, snapshot.Token); ok {
			return current, *frame, true
		}
	}
	return comctl32pkg.SubclassEntry{}, *frame, false
}

func (r *subclassDispatchRuntime) activeFrame(cpu arch.CPU, hwnd uint64) (subclassDispatchFrame, bool) {
	state := r.cpu(cpu)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.frames) == 0 {
		return subclassDispatchFrame{}, false
	}
	frame := state.frames[len(state.frames)-1]
	return frame, frame.hwnd == hwnd
}

func (r *subclassDispatchRuntime) pushContinuation(cpu arch.CPU, hwnd uint64, continuation subclassContinuation) bool {
	state := r.cpu(cpu)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.frames) == 0 {
		return false
	}
	frame := &state.frames[len(state.frames)-1]
	if frame.hwnd != hwnd {
		return false
	}
	frame.returns = append(frame.returns, continuation)
	return true
}

func (r *subclassDispatchRuntime) popContinuation(cpu arch.CPU) (subclassContinuation, bool) {
	state := r.cpu(cpu)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.frames) == 0 {
		return subclassContinuation{}, false
	}
	frame := &state.frames[len(state.frames)-1]
	if len(frame.returns) == 0 {
		return subclassContinuation{}, false
	}
	index := len(frame.returns) - 1
	continuation := frame.returns[index]
	frame.returns = frame.returns[:index]
	return continuation, true
}

func (r *subclassDispatchRuntime) finish(cpu arch.CPU) (subclassDispatchFrame, bool) {
	state := r.cpu(cpu)
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.frames) == 0 {
		return subclassDispatchFrame{}, false
	}
	index := len(state.frames) - 1
	frame := state.frames[index]
	state.frames = state.frames[:index]
	if len(state.frames) == 0 {
		r.cpus.Delete(cpu)
	}
	return frame, true
}

func pointerSized(value uint64, is32 bool) uint64 {
	if is32 {
		return value & 0xFFFFFFFF
	}
	return value
}

func guestReturnAddress(ctx *ntapi.TrapContext) (uint64, bool) {
	if ctx == nil || ctx.CPU == nil || ctx.Mem == nil {
		return 0, false
	}
	sp := ctx.CPU.GetSP()
	if ctx.CPU.GetArch() == arch.ArchI386 {
		value, err := ctx.Mem.Read32(sp)
		return uint64(value), err == nil
	}
	value, err := ctx.Mem.Read64(sp)
	return value, err == nil
}

func guestCallResumeSP(ctx *ntapi.TrapContext) uint64 {
	if ctx.CPU.GetArch() == arch.ArchI386 {
		return ctx.CPU.GetSP() + 20
	}
	return ctx.CPU.GetSP() + 8
}

func redirectSubclassProc(ctx *ntapi.TrapContext, proc, hwnd uint64, msg uint32, wParam, lParam, id, refData, returnAddr uint64) bool {
	rw, ok := ctx.CPU.(ntapi.RegisterWriter)
	if !ok || proc == 0 {
		return false
	}
	sp := ctx.CPU.GetSP()
	if ctx.CPU.GetArch() == arch.ArchI386 {
		sp -= 8
		values := [...]uint64{returnAddr, hwnd, uint64(msg), wParam, lParam, id, refData}
		for index, value := range values {
			ctx.Mem.Write32(sp+uint64(index)*4, uint32(value))
		}
		rw.WriteReg(4, sp)
	} else {
		sp -= 16
		ctx.Mem.Write64(sp, returnAddr)
		ctx.Mem.Write64(sp+0x28, id)
		ctx.Mem.Write64(sp+0x30, refData)
		rw.WriteReg(4, sp)
		rw.WriteReg(1, hwnd)
		rw.WriteReg(2, uint64(msg))
		rw.WriteReg(8, wParam)
		rw.WriteReg(9, lParam)
	}
	ctx.CPU.SetPC(proc)
	ctx.ReturnOverridden = true
	ctx.PCRedirected = true
	return true
}

func redirectWindowProc(ctx *ntapi.TrapContext, proc, hwnd uint64, msg uint32, wParam, lParam, returnAddr uint64) bool {
	rw, ok := ctx.CPU.(ntapi.RegisterWriter)
	if !ok || proc == 0 {
		return false
	}
	sp := ctx.CPU.GetSP()
	if ctx.CPU.GetArch() == arch.ArchI386 {
		values := [...]uint64{returnAddr, hwnd, uint64(msg), wParam, lParam}
		for index, value := range values {
			ctx.Mem.Write32(sp+uint64(index)*4, uint32(value))
		}
	} else {
		ctx.Mem.Write64(sp, returnAddr)
		rw.WriteReg(1, hwnd)
		rw.WriteReg(2, uint64(msg))
		rw.WriteReg(8, wParam)
		rw.WriteReg(9, lParam)
	}
	ctx.CPU.SetPC(proc)
	ctx.ReturnOverridden = true
	ctx.PCRedirected = true
	return true
}

func writeSubclassThunk(mem *mmu.MMU, addr uint64, handlerID uint32, popBytes uint16) {
	mem.Write8(addr, 0xB8)
	mem.Write32(addr+1, handlerID)
	mem.Write8(addr+5, 0x0F)
	mem.Write8(addr+6, 0x01)
	mem.Write8(addr+7, 0xC1)
	if popBytes == 0 {
		mem.Write8(addr+8, 0xC3)
		return
	}
	mem.Write8(addr+8, 0xC2)
	mem.Write16(addr+9, popBytes)
}

func installSubclassThunkPage(hctx *HandlerCtx) bool {
	if hctx.SubclassWndProc != 0 && hctx.SubclassReturn != 0 && hctx.SubclassContinue != 0 {
		return true
	}
	page := hctx.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	popBytes := uint16(0)
	if is32 {
		popBytes = 16
	}
	writeSubclassThunk(hctx.Mem, page, subclassDispatchThunkID, popBytes)
	hctx.SubclassReturn = page + 32
	hctx.Mem.Write8(hctx.SubclassReturn, 0x50)
	writeSubclassThunk(hctx.Mem, hctx.SubclassReturn+1, subclassReturnThunkID, 0)
	hctx.SubclassContinue = page + 64
	hctx.Mem.Write8(hctx.SubclassContinue, 0x50)
	writeSubclassThunk(hctx.Mem, hctx.SubclassContinue+1, subclassContinueThunkID, 0)
	if err := hctx.Mem.Mprotect(page, mmu.PageSize, mmu.PermRead|mmu.PermExecute); err != nil {
		return false
	}
	hctx.SubclassWndProc = page
	return true
}

func rebindOrdinalImports(hctx *HandlerCtx, synth *ntapi.SynthPE, dllName string, bindings map[uint16]string) int {
	if hctx == nil || synth == nil || hctx.Mem == nil {
		return 0
	}
	rebound := 0
	for ordinal, name := range bindings {
		addr := synth.Exports[name]
		if addr == 0 {
			placeholder := fmt.Sprintf("ord_%d", ordinal)
			addr = synth.Exports[placeholder]
			if addr != 0 {
				synth.Exports[name] = addr
			}
		}
		if addr == 0 {
			continue
		}
		synth.ExportOrds[ordinal] = addr
		if hctx.MainModule == nil {
			continue
		}
		for _, imp := range hctx.MainModule.Imports {
			if imp.FuncName != "" || imp.Ordinal != ordinal || !strings.EqualFold(imp.DLLName, dllName) {
				continue
			}
			if hctx.MainModule.Is64 {
				hctx.Mem.Write64Raw(imp.IATSlot, addr)
			} else {
				hctx.Mem.Write32Raw(imp.IATSlot, uint32(addr))
			}
			rebound++
		}
	}
	return rebound
}

func registerComctl32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	hwndAlloc := hctx.HwndAlloc
	hwndChildren := hctx.HwndChildren
	gdiMgr := hctx.GdiMgr
	getDC := hctx.GetDCFn
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc
	peLoadRawResource := hctx.PeLoadRawResource
	decodeDIBSlots := hctx.DecodeDIBSlots
	mainModule := hctx.MainModule
	bitmapHandles := hctx.BitmapHandles

	comctl32, ok := hctx.SynthByName["comctl32.dll"]
	if !ok {
		return
	}
	if hctx.SubclassRuntime == nil {
		hctx.SubclassRuntime = new(subclassDispatchRuntime)
	}
	subclasses := hctx.SubclassRuntime
	if !installSubclassThunkPage(hctx) {
		return
	}
	hctx.HasWindowSubclass = comctl32pkg.HasWindowSubclass
	restoreSubclassWindow := func(hwnd uint64) {
		if info, found := subclasses.removeWindow(hwnd); found && hctx.HwndWndProc[hwnd] == hctx.SubclassWndProc {
			hctx.HwndWndProc[hwnd] = info.original
		}
		comctl32pkg.RemoveAllSubclasses(hwnd)
	}
	hctx.ClearSubclasses = restoreSubclassWindow
	callBuiltinOriginal := func(ctx *ntapi.TrapContext, hwnd uint64, msg uint32, wParam, lParam uint64) uint64 {
		if hctx.BuiltinWndProc == nil {
			return 0
		}
		wasCallingBuiltin := hctx.CallBuiltinControl
		hctx.CallBuiltinControl = true
		result, handled := hctx.BuiltinWndProc(hwnd, msg, wParam, lParam)
		hctx.CallBuiltinControl = wasCallingBuiltin
		if handled {
			return result
		}
		return 0
	}
	d.RegisterHandler(subclassDispatchThunkID, "comctl32SubclassDispatch", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		returnAddr, hasReturn := guestReturnAddress(ctx)
		info, installed := subclasses.window(hwnd)
		if !hasReturn || !installed {
			ctx.SetReturn(0)
			return 0
		}

		subclasses.begin(ctx.CPU, subclassDispatchFrame{
			hwnd:       hwnd,
			entries:    comctl32pkg.GetSubclassChain(hwnd),
			original:   info.original,
			builtin:    info.builtin,
			returnAddr: returnAddr,
			resumeSP:   guestCallResumeSP(ctx),
		})
		if entry, _, found := subclasses.nextEntry(ctx.CPU, hwnd); found {
			if redirectSubclassProc(ctx, entry.PfnSubclass, hwnd, msg, wParam, lParam,
				entry.UIDSubclass, entry.DwRefData, hctx.SubclassReturn) {
				return 0
			}
		}
		_, _ = subclasses.finish(ctx.CPU)
		if redirectWindowProc(ctx, info.original, hwnd, msg, wParam, lParam, returnAddr) {
			return 0
		}
		if info.builtin {
			ctx.SetReturn(callBuiltinOriginal(ctx, hwnd, msg, wParam, lParam))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterHandler(subclassReturnThunkID, "comctl32SubclassReturn", func(ctx *ntapi.TrapContext) uint32 {
		sp := ctx.CPU.GetSP()
		var result uint64
		if ctx.CPU.GetArch() == arch.ArchI386 {
			value, _ := ctx.Mem.Read32(sp)
			result = uint64(value)
			ctx.CPU.SetSP(sp + 4)
		} else {
			result, _ = ctx.Mem.Read64(sp)
			ctx.CPU.SetSP(sp + 8)
		}
		frame, found := subclasses.finish(ctx.CPU)
		ctx.SetReturn(result)
		if found {
			ctx.CPU.SetSP(frame.resumeSP)
			ctx.CPU.SetPC(frame.returnAddr)
			ctx.PCRedirected = true
		}
		return 0
	})
	d.RegisterHandler(subclassContinueThunkID, "comctl32SubclassContinue", func(ctx *ntapi.TrapContext) uint32 {
		sp := ctx.CPU.GetSP()
		var result uint64
		if ctx.CPU.GetArch() == arch.ArchI386 {
			value, _ := ctx.Mem.Read32(sp)
			result = uint64(value)
		} else {
			result, _ = ctx.Mem.Read64(sp)
		}
		continuation, found := subclasses.popContinuation(ctx.CPU)
		ctx.SetReturn(result)
		if found {
			ctx.CPU.SetSP(continuation.resumeSP)
			ctx.CPU.SetPC(continuation.returnAddr)
			ctx.PCRedirected = true
		}
		return 0
	})
	rebindOrdinalImports(hctx, comctl32, "comctl32.dll", map[uint16]string{
		2:   "MenuHelp",
		4:   "GetEffectiveClientRect",
		236: "Str_SetPtrW",
		329: "DPA_Destroy",
		334: "DPA_InsertPtr",
		337: "DPA_DeleteAllPtrs",
		338: "DPA_Sort",
		340: "DPA_CreateEx",
	})

	// MUI language: stored per-process; default en-US (0x0409).
	muiLanguage := uint32(0x0409)
	type imageListStreamSnapshot struct {
		cx      int32
		cy      int32
		flags   uint32
		bkColor uint32
		count   uint32
	}
	type imageListDragState struct {
		himlTrack     uint64
		himlDrag      uint64
		himlNoCursor  uint64
		cursorHiml    uint64
		hwnd          uint64
		dragIndex     int32
		cursorIndex   int32
		x             int32
		y             int32
		hotspotX      int32
		hotspotY      int32
		cursorOffsetX int32
		cursorOffsetY int32
		visible       bool
	}
	var (
		comctlMu             sync.Mutex
		imageListStreams     = map[uint64]imageListStreamSnapshot{}
		registeredClassNames = map[string]struct{}{}
		dragListWindows      = map[uint64]bool{}
		imageListDrag        = imageListDragState{dragIndex: -1, cursorIndex: -1}
	)
	makePlaceholderIcon := func(cx, cy int32, seed uint64) []byte {
		if cx <= 0 {
			cx = 16
		}
		if cy <= 0 {
			cy = 16
		}
		pix := make([]byte, cx*cy*4)
		base := uint32(seed&0xFFFFFF) | 0x404040
		for y := int32(0); y < cy; y++ {
			for x := int32(0); x < cx; x++ {
				off := int((y*cx + x) * 4)
				c := base
				if x == 0 || y == 0 || x == cx-1 || y == cy-1 {
					c = 0x202020
				}
				pix[off+0] = byte(c)
				pix[off+1] = byte(c >> 8)
				pix[off+2] = byte(c >> 16)
				pix[off+3] = 0xFF
			}
		}
		return pix
	}
	slotsToImageList := func(himl uint64, slots [][]uint32, maskColor uint32) int32 {
		first := int32(-1)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		if !ok || cx <= 0 || cy <= 0 {
			return -1
		}
		for _, slot := range slots {
			if len(slot) == 0 {
				continue
			}
			pix := make([]byte, cx*cy*4)
			for i, c := range slot {
				if i*4+3 >= len(pix) {
					break
				}
				if c == maskColor {
					pix[i*4+3] = 0
				} else {
					pix[i*4+0] = byte(c)
					pix[i*4+1] = byte(c >> 8)
					pix[i*4+2] = byte(c >> 16)
					pix[i*4+3] = 0xFF
				}
			}
			idx := comctl32pkg.ImageListAddImage(himl, pix, nil, true)
			if first < 0 {
				first = idx
			}
		}
		return first
	}
	extractBitmapSlots := func(hbm uint64, cx, cy int32, maskColor *uint32) [][]uint32 {
		if bd := bitmapHandles[hbm]; bd != nil && len(bd.slots) > 0 {
			return bd.slots
		}
		obj := gdiMgr.GetObject(hbm)
		if obj == nil || obj.Bitmap == nil || obj.Bitmap.Surf == nil {
			return nil
		}
		bm := obj.Bitmap
		width := bm.Width
		height := bm.Height
		if width <= 0 || height <= 0 {
			return nil
		}
		if cx <= 0 {
			cx = width
		}
		if cy <= 0 {
			cy = height
		}
		nSlots := int(width / cx)
		if nSlots <= 0 {
			nSlots = 1
		}
		slots := make([][]uint32, nSlots)
		for s := 0; s < nSlots; s++ {
			slot := make([]uint32, cx*cy)
			for y := int32(0); y < cy && y < height; y++ {
				for x := int32(0); x < cx; x++ {
					srcX := int32(s)*cx + x
					if srcX >= width {
						break
					}
					c := bm.Surf.GetPixel(srcX, y)
					if maskColor != nil && c == *maskColor {
						c = 0
					}
					slot[y*cx+x] = c
				}
			}
			slots[s] = slot
		}
		return slots
	}
	resetImageListDrag := func() {
		if imageListDrag.himlDrag != 0 {
			comctl32pkg.ImageListDestroy(imageListDrag.himlDrag)
		}
		if imageListDrag.himlNoCursor != 0 && imageListDrag.himlNoCursor != imageListDrag.himlDrag {
			comctl32pkg.ImageListDestroy(imageListDrag.himlNoCursor)
		}
		imageListDrag = imageListDragState{dragIndex: -1, cursorIndex: -1}
	}

	d.RegisterAutoStubHandler(comctl32, "InitCommonControls", func(ctx *ntapi.TrapContext) uint32 {
		return 0 // void function
	})
	// ICC flags that have been registered via InitCommonControlsEx
	var registeredICC uint32
	d.RegisterAutoStubHandler(comctl32, "InitCommonControlsEx", func(ctx *ntapi.TrapContext) uint32 {
		// INITCOMMONCONTROLSEX: DWORD dwSize (+0), DWORD dwICC (+4)
		pInitCtrls := ctx.Arg(0)
		if pInitCtrls != 0 {
			dwSize, _ := ctx.Mem.Read32(pInitCtrls)
			dwICC, _ := ctx.Mem.Read32(pInitCtrls + 4)
			if dwSize >= 8 {
				registeredICC |= dwICC
				ravelog.Logf("[comctl32] InitCommonControlsEx ICC=0x%08x (cumulative=0x%08x)\n", dwICC, registeredICC)
			}
		}
		ctx.SetReturn(1) // TRUE - always succeed
		return 0
	})

	// CreateStatusWindowW: creates a status bar child window
	d.RegisterAutoStubHandler(comctl32, "CreateStatusWindowW", func(ctx *ntapi.TrapContext) uint32 {
		style := uint32(ctx.Arg(0))
		_ = ctx.Arg(1) // lpszText
		hwndParent := ctx.Arg(2)
		_ = ctx.Arg(3) // wID
		hwnd := hwndAlloc()
		var defW, defH int32 = 800, 600
		if hctx.WlWindow != nil {
			defW, defH = hctx.WlWindow.Width, hctx.WlWindow.Height
		}
		const sbHeight int32 = 20
		hwndChildren[hwnd] = &controlState{
			className:  "msctls_statusbar32",
			parentHWND: hwndParent,
			x:          0, y: defH - sbHeight, w: defW, h: sbHeight,
			visible: style&0x10000000 != 0,
		}
		ravelog.Logf("[comctl32] CreateStatusWindowW hwnd=0x%x parent=0x%x\n", hwnd, hwndParent)
		ctx.SetReturn(hwnd)
		return 0
	})

	// ImageList_Create - allocate image list with dimensions and flags
	d.RegisterAutoStubHandler(comctl32, "ImageList_Create", func(ctx *ntapi.TrapContext) uint32 {
		cx := int32(ctx.Arg(0))
		cy := int32(ctx.Arg(1))
		flags := uint32(ctx.Arg(2))
		cInitial := int32(ctx.Arg(3))
		cGrow := int32(ctx.Arg(4))
		h := comctl32pkg.ImageListCreate(cx, cy, flags, cInitial, cGrow)
		ravelog.Logf("[comctl32] ImageList_Create cx=%d cy=%d flags=0x%x → 0x%x\n", cx, cy, flags, h)
		ctx.SetReturn(h)
		return 0
	})

	// ImageList_ReplaceIcon - replace or append icon; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_ReplaceIcon", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		hicon := ctx.Arg(2)
		cx, cy, _ := comctl32pkg.ImageListGetIconSize(himl)
		pixels := hctx.iconPixels(hicon, cx, cy)
		idx := comctl32pkg.ImageListReplaceIconData(himl, i, pixels)
		ravelog.Logf("[comctl32] ImageList_ReplaceIcon himl=0x%x i=%d hicon=0x%x pixels=%d -> %d\n",
			himl, i, hicon, len(pixels), idx)
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})

	// ImageList_SetImageCount - resize image array
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetImageCount", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		uNewCount := uint32(ctx.Arg(1))
		if comctl32pkg.ImageListSetImageCount(himl, uNewCount) {
			ctx.SetReturn(1)
		}
		return 0
	})

	// ImageList_GetImageCount - return stored count
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageCount", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		ctx.SetReturn(uint64(comctl32pkg.ImageListGetImageCount(himl)))
		return 0
	})

	// ImageList_Destroy - free image list handle
	d.RegisterAutoStubHandler(comctl32, "ImageList_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		if comctl32pkg.ImageListDestroy(himl) {
			ctx.SetReturn(1)
		}
		return 0
	})

	// ImageList_AddMasked - adds bitmap with mask colour; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_AddMasked", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		hbm := ctx.Arg(1)
		crMask := uint32(ctx.Arg(2))
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		idx := int32(-1)
		if ok {
			idx = slotsToImageList(himl, extractBitmapSlots(hbm, cx, cy, &crMask), crMask)
		}
		if idx < 0 {
			idx = comctl32pkg.ImageListAddMasked(himl)
		}
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})

	// ImageList_Add - adds bitmap without mask; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_Add", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		hbmImage := ctx.Arg(1)
		hbmMask := ctx.Arg(2)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		idx := int32(-1)
		if ok {
			var maskColor *uint32
			if hbmMask != 0 {
				zero := uint32(0)
				maskColor = &zero
			}
			idx = slotsToImageList(himl, extractBitmapSlots(hbmImage, cx, cy, maskColor), 0)
		}
		if idx < 0 {
			idx = comctl32pkg.ImageListAdd(himl)
		}
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})

	// ImageList_Remove - remove image at index (-1 = all)
	d.RegisterAutoStubHandler(comctl32, "ImageList_Remove", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		if comctl32pkg.ImageListRemove(himl, i) {
			ctx.SetReturn(1)
		}
		return 0
	})

	// ImageList_SetIconSize - set icon size, clears all images
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetIconSize", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		cx := int32(ctx.Arg(1))
		cy := int32(ctx.Arg(2))
		if comctl32pkg.ImageListSetIconSize(himl, cx, cy) {
			ctx.SetReturn(1)
		}
		return 0
	})

	// ImageList_Draw - draw image from list to HDC
	d.RegisterAutoStubHandler(comctl32, "ImageList_Draw", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		hdc := ctx.Arg(2)
		x := int32(ctx.Arg(3))
		y := int32(ctx.Arg(4))
		fStyle := uint32(ctx.Arg(5))
		dc := getDC(hdc)
		ok := comctl32pkg.ImageListDrawTo(himl, i, dc, x, y, fStyle)
		ravelog.Logf("[comctl32] ImageList_Draw himl=0x%x i=%d hdc=0x%x x=%d y=%d style=0x%x ok=%v\n",
			himl, i, hdc, x, y, fStyle, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// ImageList_DrawEx - extended draw
	d.RegisterAutoStubHandler(comctl32, "ImageList_DrawEx", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		hdc := ctx.Arg(2)
		x := int32(ctx.Arg(3))
		y := int32(ctx.Arg(4))
		dx := int32(ctx.Arg(5))
		dy := int32(ctx.Arg(6))
		rgbBk := uint32(ctx.Arg(7))
		rgbFg := uint32(ctx.Arg(8))
		fStyle := uint32(ctx.Arg(9))
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		if dx == 0 {
			dx = cx
		}
		if dy == 0 {
			dy = cy
		}
		ok = ok && comctl32pkg.ImageListDrawTo(himl, i, getDC(hdc), x, y, fStyle)
		ravelog.Logf("[comctl32] ImageList_DrawEx himl=0x%x i=%d hdc=0x%x x=%d y=%d dx=%d dy=%d rgbBk=0x%x rgbFg=0x%x style=0x%x ok=%v\n",
			himl, i, hdc, x, y, dx, dy, rgbBk, rgbFg, fStyle, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// ImageList_GetIconSize - return icon dimensions from tracked state
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetIconSize", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		pCx := ctx.Arg(1)
		pCy := ctx.Arg(2)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		if ok {
			if pCx != 0 {
				ctx.Mem.Write32(pCx, uint32(cx))
			}
			if pCy != 0 {
				ctx.Mem.Write32(pCy, uint32(cy))
			}
			ctx.SetReturn(1)
		}
		return 0
	})

	// ImageList_SetBkColor - set background colour, return previous
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		clr := uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(comctl32pkg.ImageListSetBkColor(h, clr)))
		return 0
	})

	// ImageList_Copy - copy image between slots/lists
	d.RegisterAutoStubHandler(comctl32, "ImageList_Copy", func(ctx *ntapi.TrapContext) uint32 {
		hDst := ctx.Arg(0)
		iDst := int32(ctx.Arg(1))
		hSrc := ctx.Arg(2)
		iSrc := int32(ctx.Arg(3))
		uFlags := uint32(ctx.Arg(4))
		if comctl32pkg.ImageListCopy(hDst, iDst, hSrc, iSrc, uFlags) {
			ctx.SetReturn(1)
		}
		return 0
	})

	// ── ImageList full coverage ──────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "ImageList_AddIcon", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		hIcon := ctx.Arg(1)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(h)
		idx := int32(-1)
		if ok {
			idx = comctl32pkg.ImageListAddImage(h, makePlaceholderIcon(cx, cy, hIcon), nil, true)
		}
		if idx < 0 {
			idx = comctl32pkg.ImageListAdd(h)
		}
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		ctx.SetReturn(uint64(comctl32pkg.ImageListGetBkColor(h)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: ImageList_GetImageInfo in dll/win32/comctl32/imagelist.c
		// IMAGEINFO: { HBITMAP hbmImage, HBITMAP hbmMask, int Unused1, int Unused2, RECT rcImage }
		// x64: 8+8+4+4+16 = 40 bytes
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		pInfo := ctx.Arg(2)
		if pInfo == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		// Zero the struct
		for off := uint64(0); off < 40; off += 4 {
			ctx.Mem.Write32(pInfo+off, 0)
		}
		// Fill rcImage with the image rect
		x := i * cx
		ctx.Mem.Write32(pInfo+24, uint32(x))    // rcImage.left
		ctx.Mem.Write32(pInfo+28, 0)            // rcImage.top
		ctx.Mem.Write32(pInfo+32, uint32(x+cx)) // rcImage.right
		ctx.Mem.Write32(pInfo+36, uint32(cy))   // rcImage.bottom
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageRect", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		prc := ctx.Arg(2)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(h)
		if ok && prc != 0 {
			x := i * cx
			ctx.Mem.Write32(prc, uint32(x))
			ctx.Mem.Write32(prc+4, 0)
			ctx.Mem.Write32(prc+8, uint32(x+cx))
			ctx.Mem.Write32(prc+12, uint32(cy))
		}
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetIcon", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: ImageList_GetIcon in dll/win32/comctl32/imagelist.c
		// Return a fake non-zero HICON so callers don't treat it as error.
		himl := ctx.Arg(0)
		if comctl32pkg.ImageListGetImageCount(himl) == 0 {
			ctx.SetReturn(0) // empty list → error
			return 0
		}
		ctx.SetReturn(0xCC000001) // fake HICON
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetFlags", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		flags := comctl32pkg.ImageListGetFlags(himl)
		ravelog.Logf("[comctl32] ImageList_GetFlags himl=0x%x -> 0x%x\n", himl, flags)
		ctx.SetReturn(uint64(flags))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetFlags", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		flags := uint32(ctx.Arg(1))
		ok := comctl32pkg.ImageListSetFlags(himl, flags)
		ravelog.Logf("[comctl32] ImageList_SetFlags himl=0x%x flags=0x%x ok=%v\n", himl, flags, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetOverlayImage", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		iImg := int32(ctx.Arg(1))
		iOvl := int32(ctx.Arg(2))
		if comctl32pkg.ImageListSetOverlayImage(h, iImg, iOvl) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetDragImage", func(ctx *ntapi.TrapContext) uint32 {
		ppt := ctx.Arg(0)
		pptHotspot := ctx.Arg(1)
		comctlMu.Lock()
		drag := imageListDrag
		comctlMu.Unlock()
		if drag.himlDrag != 0 {
			if ppt != 0 {
				ctx.Mem.Write32(ppt, uint32(drag.x))
				ctx.Mem.Write32(ppt+4, uint32(drag.y))
			}
			if pptHotspot != 0 {
				ctx.Mem.Write32(pptHotspot, uint32(drag.hotspotX))
				ctx.Mem.Write32(pptHotspot+4, uint32(drag.hotspotY))
			}
		}
		ravelog.Logf("[comctl32] ImageList_GetDragImage ppt=0x%x pptHotspot=0x%x -> himl=0x%x pos=%d,%d hotspot=%d,%d\n",
			ppt, pptHotspot, drag.himlDrag, drag.x, drag.y, drag.hotspotX, drag.hotspotY)
		ctx.SetReturn(drag.himlDrag)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_BeginDrag", func(ctx *ntapi.TrapContext) uint32 {
		himlTrack := ctx.Arg(0)
		iTrack := int32(ctx.Arg(1))
		dxHotspot := int32(ctx.Arg(2))
		dyHotspot := int32(ctx.Arg(3))
		flags := comctl32pkg.ImageListGetFlags(himlTrack)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himlTrack)
		count := comctl32pkg.ImageListGetImageCount(himlTrack)
		ok = ok && iTrack >= 0 && iTrack < count
		comctlMu.Lock()
		alreadyDragging := imageListDrag.himlDrag != 0
		if ok && !alreadyDragging {
			dragHiml := comctl32pkg.ImageListCreate(cx, cy, flags, 1, 1)
			ok = dragHiml != 0 && comctl32pkg.ImageListSetImageCount(dragHiml, 1)
			if ok {
				imageListDrag = imageListDragState{
					himlTrack:    himlTrack,
					himlDrag:     dragHiml,
					himlNoCursor: dragHiml,
					dragIndex:    iTrack,
					cursorIndex:  -1,
					hotspotX:     dxHotspot,
					hotspotY:     dyHotspot,
				}
			}
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_BeginDrag himl=0x%x iTrack=%d dxHotspot=%d dyHotspot=%d ok=%v active=%v\n",
			himlTrack, iTrack, dxHotspot, dyHotspot, ok && !alreadyDragging, alreadyDragging)
		if ok && !alreadyDragging {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_EndDrag", func(ctx *ntapi.TrapContext) uint32 {
		comctlMu.Lock()
		drag := imageListDrag
		resetImageListDrag()
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_EndDrag himlDrag=0x%x hwnd=0x%x visible=%v\n", drag.himlDrag, drag.hwnd, drag.visible)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragEnter", func(ctx *ntapi.TrapContext) uint32 {
		hwndLock := ctx.Arg(0)
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		comctlMu.Lock()
		ok := imageListDrag.himlDrag != 0
		if ok {
			imageListDrag.hwnd = hwndLock
			imageListDrag.x = x
			imageListDrag.y = y
			imageListDrag.visible = true
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_DragEnter hwnd=0x%x x=%d y=%d ok=%v\n", hwndLock, x, y, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragLeave", func(ctx *ntapi.TrapContext) uint32 {
		hwndLock := ctx.Arg(0)
		comctlMu.Lock()
		ok := imageListDrag.himlDrag != 0
		if ok {
			if imageListDrag.hwnd == 0 || hwndLock == 0 || imageListDrag.hwnd == hwndLock {
				imageListDrag.visible = false
			}
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_DragLeave hwnd=0x%x ok=%v\n", hwndLock, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragMove", func(ctx *ntapi.TrapContext) uint32 {
		x := int32(ctx.Arg(0))
		y := int32(ctx.Arg(1))
		comctlMu.Lock()
		ok := imageListDrag.himlDrag != 0
		if ok {
			imageListDrag.x = x
			imageListDrag.y = y
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_DragMove x=%d y=%d ok=%v\n", x, y, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragShowNolock", func(ctx *ntapi.TrapContext) uint32 {
		bShow := ctx.Arg(0) != 0
		comctlMu.Lock()
		ok := imageListDrag.himlDrag != 0
		changed := false
		if ok && imageListDrag.visible != bShow {
			imageListDrag.visible = bShow
			changed = true
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_DragShowNolock show=%v ok=%v changed=%v\n", bShow, ok, changed)
		if ok && changed {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetDragCursorImage", func(ctx *ntapi.TrapContext) uint32 {
		himlDrag := ctx.Arg(0)
		iDrag := int32(ctx.Arg(1))
		dxHotspot := int32(ctx.Arg(2))
		dyHotspot := int32(ctx.Arg(3))
		flags := comctl32pkg.ImageListGetFlags(himlDrag)
		baseFlags := flags
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himlDrag)
		count := comctl32pkg.ImageListGetImageCount(himlDrag)
		ok = ok && iDrag >= 0 && iDrag < count
		comctlMu.Lock()
		if ok && imageListDrag.himlDrag != 0 {
			if baseFlags == 0 {
				baseFlags = comctl32pkg.ImageListGetFlags(imageListDrag.himlNoCursor)
			}
			if imageListDrag.himlDrag != imageListDrag.himlNoCursor {
				comctl32pkg.ImageListDestroy(imageListDrag.himlDrag)
			}
			merged := comctl32pkg.ImageListCreate(cx, cy, baseFlags, 1, 1)
			ok = merged != 0 && comctl32pkg.ImageListSetImageCount(merged, 1)
			if ok {
				imageListDrag.himlDrag = merged
				imageListDrag.cursorHiml = himlDrag
				imageListDrag.cursorIndex = iDrag
				imageListDrag.cursorOffsetX = dxHotspot
				imageListDrag.cursorOffsetY = dyHotspot
			}
		} else {
			ok = false
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] ImageList_SetDragCursorImage himl=0x%x iDrag=%d dxHotspot=%d dyHotspot=%d ok=%v\n",
			himlDrag, iDrag, dxHotspot, dyHotspot, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Duplicate", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		ctx.SetReturn(comctl32pkg.ImageListDuplicate(h))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Replace", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		hbmImage := ctx.Arg(2)
		hbmMask := ctx.Arg(3)
		cx, cy, sizeOK := comctl32pkg.ImageListGetIconSize(himl)
		ok := false
		if sizeOK {
			var maskColor *uint32
			if hbmMask != 0 {
				zero := uint32(0)
				maskColor = &zero
			}
			slots := extractBitmapSlots(hbmImage, cx, cy, maskColor)
			if len(slots) > 0 {
				pix := make([]byte, cx*cy*4)
				for idx2, c := range slots[0] {
					if idx2*4+3 >= len(pix) {
						break
					}
					pix[idx2*4+0] = byte(c)
					pix[idx2*4+1] = byte(c >> 8)
					pix[idx2*4+2] = byte(c >> 16)
					pix[idx2*4+3] = 0xFF
				}
				ok = comctl32pkg.ImageListReplaceImage(himl, i, pix, nil, true)
			}
		}
		if !ok {
			ok = comctl32pkg.ImageListReplace(himl, i)
		}
		ravelog.Logf("[comctl32] ImageList_Replace himl=0x%x i=%d hbmImage=0x%x hbmMask=0x%x ok=%v\n",
			himl, i, hbmImage, hbmMask, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Merge", func(ctx *ntapi.TrapContext) uint32 {
		// Returns new imagelist that merges two lists; stub creates empty list
		h1 := ctx.Arg(0)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(h1)
		if !ok {
			cx, cy = 16, 16
		}
		newH := comctl32pkg.ImageListCreate(cx, cy, 0, 0, 4)
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImageA", func(ctx *ntapi.TrapContext) uint32 {
		newH := comctl32pkg.ImageListCreate(16, 16, uint32(ctx.Arg(6)), 0, int32(ctx.Arg(3)))
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		lpbmp := ctx.Arg(1)
		cx := int32(ctx.Arg(2))
		cGrow := int32(ctx.Arg(3))
		crMask := uint32(ctx.Arg(4))
		uType := uint32(ctx.Arg(5))
		uFlags := uint32(ctx.Arg(6))
		if cx <= 0 {
			cx = 16
		}
		cy := cx
		newH := comctl32pkg.ImageListCreate(cx, cy, uFlags, 0, cGrow)
		if uType == 0 && lpbmp < 0x10000 && mainModule != nil && (hInst == 0 || hInst == mainModule.BaseAddr) {
			if addr, sz, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2, uint32(lpbmp)); ok {
				slots := decodeDIBSlots(addr, sz, int(cx), int(cy))
				slotsToImageList(newH, slots, crMask)
			}
		}
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImage", func(ctx *ntapi.TrapContext) uint32 {
		newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Read", func(ctx *ntapi.TrapContext) uint32 {
		pstm := ctx.Arg(0)
		var snap imageListStreamSnapshot
		comctlMu.Lock()
		snap, ok := imageListStreams[pstm]
		comctlMu.Unlock()
		var himl uint64
		if ok && pstm != 0 {
			himl = comctl32pkg.ImageListCreate(snap.cx, snap.cy, snap.flags, int32(snap.count), 1)
			if himl != 0 {
				comctl32pkg.ImageListSetImageCount(himl, snap.count)
				comctl32pkg.ImageListSetBkColor(himl, snap.bkColor)
			}
		}
		ravelog.Logf("[comctl32] ImageList_Read pstm=0x%x restored=%v himl=0x%x count=%d flags=0x%x\n",
			pstm, ok, himl, snap.count, snap.flags)
		ctx.SetReturn(himl)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Write", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		pstm := ctx.Arg(1)
		cx, cy, ok := comctl32pkg.ImageListGetIconSize(himl)
		flags := comctl32pkg.ImageListGetFlags(himl)
		count := uint32(comctl32pkg.ImageListGetImageCount(himl))
		bkColor := comctl32pkg.ImageListGetBkColor(himl)
		if ok && pstm != 0 {
			comctlMu.Lock()
			imageListStreams[pstm] = imageListStreamSnapshot{
				cx:      cx,
				cy:      cy,
				flags:   flags,
				bkColor: bkColor,
				count:   count,
			}
			comctlMu.Unlock()
		}
		ravelog.Logf("[comctl32] ImageList_Write himl=0x%x pstm=0x%x count=%d flags=0x%x ok=%v\n",
			himl, pstm, count, flags, ok && pstm != 0)
		if ok && pstm != 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DrawIndirect", func(ctx *ntapi.TrapContext) uint32 {
		pimldp := ctx.Arg(0)
		if pimldp == 0 {
			ravelog.Logf("[comctl32] ImageList_DrawIndirect pimldp=0x0 ok=false\n")
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := ctx.Mem.Read32(pimldp)
		himl, _ := ctx.Mem.Read64(pimldp + 8)
		iRaw, _ := ctx.Mem.Read32(pimldp + 16)
		hdcDst, _ := ctx.Mem.Read64(pimldp + 24)
		xRaw, _ := ctx.Mem.Read32(pimldp + 32)
		yRaw, _ := ctx.Mem.Read32(pimldp + 36)
		cxRaw, _ := ctx.Mem.Read32(pimldp + 40)
		cyRaw, _ := ctx.Mem.Read32(pimldp + 44)
		xBitmapRaw, _ := ctx.Mem.Read32(pimldp + 48)
		yBitmapRaw, _ := ctx.Mem.Read32(pimldp + 52)
		rgbBk, _ := ctx.Mem.Read32(pimldp + 56)
		rgbFg, _ := ctx.Mem.Read32(pimldp + 60)
		fStyle, _ := ctx.Mem.Read32(pimldp + 64)
		dwRop, _ := ctx.Mem.Read32(pimldp + 68)
		fState, _ := ctx.Mem.Read32(pimldp + 72)
		frame, _ := ctx.Mem.Read32(pimldp + 76)
		crEffect, _ := ctx.Mem.Read32(pimldp + 80)
		i := int32(iRaw)
		ok := himl != 0 && comctl32pkg.ImageListDrawTo(himl, i, getDC(hdcDst), int32(xRaw), int32(yRaw), fStyle)
		ravelog.Logf("[comctl32] ImageList_DrawIndirect pimldp=0x%x cbSize=%d himl=0x%x i=%d hdc=0x%x x=%d y=%d cx=%d cy=%d xBitmap=%d yBitmap=%d rgbBk=0x%x rgbFg=0x%x style=0x%x rop=0x%x state=0x%x frame=%d effect=0x%x ok=%v\n",
			pimldp, cbSize, himl, i, hdcDst, int32(xRaw), int32(yRaw), int32(cxRaw), int32(cyRaw),
			int32(xBitmapRaw), int32(yBitmapRaw), rgbBk, rgbFg, fStyle, dwRop, fState, frame, crEffect, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "HIMAGELIST_QueryInterface", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004002) // E_NOINTERFACE
		return 0
	})

	// ── Icon loading ────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "LoadIconWithScaleDown", func(ctx *ntapi.TrapContext) uint32 {
		// LoadIconWithScaleDown(hInst, pszName, cx, cy, phico) → HRESULT
		phico := ctx.Arg(4)
		if phico != 0 {
			ctx.Mem.Write64(phico, 0) // NULL icon
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "LoadIconMetric", func(ctx *ntapi.TrapContext) uint32 {
		phico := ctx.Arg(3)
		if phico != 0 {
			ctx.Mem.Write64(phico, 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})

	// ── Subclass mechanism ───────────────────────────────────────────────
	// ord=410: SetWindowSubclass
	d.RegisterAutoStubHandler(comctl32, "SetWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pfn := ctx.Arg(1)
		is32 := ctx.CPU.GetArch() == arch.ArchI386
		uid := pointerSized(ctx.Arg(2), is32)
		ref := pointerSized(ctx.Arg(3), is32)
		hadSubclass := comctl32pkg.HasWindowSubclass(hwnd)
		if comctl32pkg.SetWindowSubclass(hwnd, pfn, uid, ref) {
			if !hadSubclass {
				original := hctx.HwndWndProc[hwnd]
				info := subclasses.installWindow(hwnd, subclassWindowInfo{
					original: original,
					builtin:  original == 0 && hctx.HwndChildren[hwnd] != nil,
				})
				if hctx.HwndWndProc[hwnd] != hctx.SubclassWndProc {
					hctx.HwndWndProc[hwnd] = hctx.SubclassWndProc
				}
				ravelog.Logf("[comctl32] SetWindowSubclass hwnd=0x%x proc=0x%x id=0x%x original=0x%x builtin=%v\n",
					hwnd, pfn, uid, info.original, info.builtin)
			}
			ctx.SetReturn(1)
		}
		return 0
	})
	// ord=411: GetWindowSubclass
	d.RegisterAutoStubHandler(comctl32, "GetWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pfn := ctx.Arg(1)
		is32 := ctx.CPU.GetArch() == arch.ArchI386
		uid := pointerSized(ctx.Arg(2), is32)
		pRef := ctx.Arg(3)
		ref, ok := comctl32pkg.GetWindowSubclass(hwnd, pfn, uid)
		if ok && pRef != 0 {
			if is32 {
				ctx.Mem.Write32(pRef, uint32(ref))
			} else {
				ctx.Mem.Write64(pRef, ref)
			}
		}
		if ok {
			ctx.SetReturn(1)
		}
		return 0
	})
	// ord=412: RemoveWindowSubclass
	d.RegisterAutoStubHandler(comctl32, "RemoveWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pfn := ctx.Arg(1)
		uid := pointerSized(ctx.Arg(2), ctx.CPU.GetArch() == arch.ArchI386)
		if comctl32pkg.RemoveWindowSubclass(hwnd, pfn, uid) {
			if !comctl32pkg.HasWindowSubclass(hwnd) {
				if info, found := subclasses.removeWindow(hwnd); found && hctx.HwndWndProc[hwnd] == hctx.SubclassWndProc {
					hctx.HwndWndProc[hwnd] = info.original
				}
			}
			ctx.SetReturn(1)
		}
		return 0
	})
	// ord=413: DefSubclassProc - call next subclass in chain, then default
	d.RegisterAutoStubHandler(comctl32, "DefSubclassProc", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		uMsg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		returnAddr, hasReturn := guestReturnAddress(ctx)
		if hasReturn {
			if entry, frame, found := subclasses.nextEntry(ctx.CPU, hwnd); found {
				continuation := subclassContinuation{
					returnAddr: returnAddr,
					resumeSP:   guestCallResumeSP(ctx),
				}
				if !subclasses.pushContinuation(ctx.CPU, hwnd, continuation) {
					ctx.SetReturn(0)
					return 0
				}
				if redirectSubclassProc(ctx, entry.PfnSubclass, hwnd, uMsg, wParam, lParam,
					entry.UIDSubclass, entry.DwRefData, hctx.SubclassContinue) {
					return 0
				}
				_, _ = subclasses.popContinuation(ctx.CPU)
			} else if frame.hwnd == hwnd {
				continuation := subclassContinuation{
					returnAddr: returnAddr,
					resumeSP:   guestCallResumeSP(ctx),
				}
				pushed := frame.original != 0 && subclasses.pushContinuation(ctx.CPU, hwnd, continuation)
				if pushed &&
					redirectWindowProc(ctx, frame.original, hwnd, uMsg, wParam, lParam, hctx.SubclassContinue) {
					return 0
				}
				if pushed {
					_, _ = subclasses.popContinuation(ctx.CPU)
				}
				if frame.builtin {
					ctx.SetReturn(callBuiltinOriginal(ctx, hwnd, uMsg, wParam, lParam))
					return 0
				}
			}
		}
		if hctx.BuiltinWndProc != nil {
			result := callBuiltinOriginal(ctx, hwnd, uMsg, wParam, lParam)
			if result != 0 {
				ctx.SetReturn(result)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// ── DPA / DSA ────────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "DPA_Create", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DPACreate(int32(ctx.Arg(0))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_CreateEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DPACreateEx(int32(ctx.Arg(0)), ctx.Arg(1)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DPADestroy(ctx.Arg(0)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Clone", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DPAClone(ctx.Arg(0), ctx.Arg(1)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_GetPtr", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DPAGetPtr(ctx.Arg(0), int32(ctx.Arg(1))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_GetPtrIndex", func(ctx *ntapi.TrapContext) uint32 {
		idx := comctl32pkg.DPAGetPtrIndex(ctx.Arg(0), ctx.Arg(1))
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_SetPtr", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DPASetPtr(ctx.Arg(0), int32(ctx.Arg(1)), ctx.Arg(2)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_InsertPtr", func(ctx *ntapi.TrapContext) uint32 {
		idx := comctl32pkg.DPAInsertPtr(ctx.Arg(0), int32(ctx.Arg(1)), ctx.Arg(2))
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_DeletePtr", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DPADeletePtr(ctx.Arg(0), int32(ctx.Arg(1))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_DeleteAllPtrs", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DPADeleteAllPtrs(ctx.Arg(0)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Grow", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DPAGrow(ctx.Arg(0), int32(ctx.Arg(1))) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Search", func(ctx *ntapi.TrapContext) uint32 {
		// DPA_Search(hdpa, pFind, iStart, pfnCmp, lParam, options)
		// We ignore comparator and do pointer equality
		idx := comctl32pkg.DPASearch(ctx.Arg(0), ctx.Arg(1), int32(ctx.Arg(2)))
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Sort", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.DPASort(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_EnumCallback", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.DPAEnumCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_DestroyCallback", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.DPADestroyCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		return 0
	})

	d.RegisterAutoStubHandler(comctl32, "DSA_Create", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(comctl32pkg.DSACreate(int32(ctx.Arg(0)), int32(ctx.Arg(1))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DSADestroy(ctx.Arg(0)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_DestroyCallback", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.DSADestroyCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_EnumCallback", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.DSAEnumCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_InsertItem", func(ctx *ntapi.TrapContext) uint32 {
		// DSA_InsertItem(hdsa, index, pItem) - pItem is guest pointer
		h := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		pItem := ctx.Arg(2)
		_ = h
		_ = i
		_ = pItem
		// We don't copy guest memory here; just track count via insert
		idx := comctl32pkg.DSAInsertItem(h, i, nil)
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_DeleteItem", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DSADeleteItem(ctx.Arg(0), int32(ctx.Arg(1))) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_DeleteAllItems", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DSADeleteAllItems(ctx.Arg(0)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_GetItem", func(ctx *ntapi.TrapContext) uint32 {
		// DSA_GetItem(hdsa, index, pDest) - copies item into pDest
		hdsa := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		pDest := ctx.Arg(2)
		data, ok := comctl32pkg.DSAGetItem(hdsa, idx)
		if ok && pDest != 0 {
			ctx.Mem.WriteBytes(pDest, data)
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_GetItemPtr", func(ctx *ntapi.TrapContext) uint32 {
		// DSA_GetItemPtr(hdsa, index) - returns pointer to item
		// We can't return a guest pointer to Go-side data, return NULL
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_SetItem", func(ctx *ntapi.TrapContext) uint32 {
		// DSA_SetItem(hdsa, index, pSrc)
		hdsa := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		pSrc := ctx.Arg(2)
		// Read item data from guest memory (need to know item size)
		if comctl32pkg.DSAGetItemIndex(hdsa, idx) && pSrc != 0 {
			if existing, ok := comctl32pkg.DSAGetItem(hdsa, idx); ok {
				data := make([]byte, len(existing))
				for i := range data {
					data[i], _ = ctx.Mem.Read8(pSrc + uint64(i))
				}
				comctl32pkg.DSASetItem(hdsa, idx, data)
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// ── PropertySheet ────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPage", func(ctx *ntapi.TrapContext) uint32 {
		h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPageA", func(ctx *ntapi.TrapContext) uint32 {
		h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreatePropertySheetPageW", func(ctx *ntapi.TrapContext) uint32 {
		h := comctl32pkg.CreatePropertySheetPage(0, "", ctx.Arg(0))
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DestroyPropertySheetPage", func(ctx *ntapi.TrapContext) uint32 {
		if comctl32pkg.DestroyPropertySheetPage(ctx.Arg(0)) {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "PropertySheet", func(ctx *ntapi.TrapContext) uint32 {
		// PROPSHEETHEADER (x64): dwFlags +4, pszCaption +32, nPages +40
		pHdr := ctx.Arg(0)
		var caption string
		var nPages uint32
		if pHdr != 0 {
			dwFlags, _ := ctx.Mem.Read32(pHdr + 4)
			nPages, _ = ctx.Mem.Read32(pHdr + 40)
			pszCaption, _ := ctx.Mem.Read64(pHdr + 32)
			if pszCaption != 0 && dwFlags&0x00000002 == 0 {
				caption = readGuestUTF16(pszCaption)
			}
		}
		ravelog.Logf("[comctl32] PropertySheet nPages=%d caption=%q\n", nPages, caption)
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(caption))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "PropertySheetA", func(ctx *ntapi.TrapContext) uint32 {
		pHdr := ctx.Arg(0)
		var nPages uint32
		if pHdr != 0 {
			nPages, _ = ctx.Mem.Read32(pHdr + 40)
		}
		ravelog.Logf("[comctl32] PropertySheetA nPages=%d\n", nPages)
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "PropertySheetW", func(ctx *ntapi.TrapContext) uint32 {
		// PROPSHEETHEADERW (x64): dwFlags +4, pszCaption +32, nPages +40
		pHdr := ctx.Arg(0)
		var caption string
		var nPages uint32
		if pHdr != 0 {
			dwFlags, _ := ctx.Mem.Read32(pHdr + 4)
			nPages, _ = ctx.Mem.Read32(pHdr + 40)
			pszCaption, _ := ctx.Mem.Read64(pHdr + 32)
			if pszCaption != 0 && dwFlags&0x00000002 == 0 {
				caption = readGuestUTF16(pszCaption)
			}
		}
		ravelog.Logf("[comctl32] PropertySheetW nPages=%d caption=%q\n", nPages, caption)
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(caption))))
		return 0
	})

	// ── FlatScrollBar ────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "InitializeFlatSB", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.InitializeFlatSB(ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "UninitializeFlatSB", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(comctl32pkg.UninitializeFlatSB(ctx.Arg(0))))
		return 0
	})
	for _, fn := range []string{
		"FlatSB_EnableScrollBar", "FlatSB_ShowScrollBar",
	} {
		fn := fn
		d.RegisterAutoStubHandler(comctl32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			ravelog.Logf("[comctl32] %s hwnd=0x%x\n", fn, hwnd)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: FlatSB_GetScrollInfo - fill SCROLLINFO with defaults
		// SCROLLINFO: cbSize(+0), fMask(+4), nMin(+8), nMax(+12), nPage(+16), nPos(+20), nTrackPos(+24)
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		psi := ctx.Arg(2)
		var fMask uint32
		if psi != 0 {
			fMask, _ = ctx.Mem.Read32(psi + 4)
			nMin, nMax, nPage, nPos, nTrackPos := comctl32pkg.FlatSBGetScrollInfo(hwnd, nBar)
			if fMask&0x01 != 0 { // SIF_RANGE
				ctx.Mem.Write32(psi+8, uint32(nMin))
				ctx.Mem.Write32(psi+12, uint32(nMax))
			}
			if fMask&0x02 != 0 { // SIF_PAGE
				ctx.Mem.Write32(psi+16, nPage)
			}
			if fMask&0x04 != 0 { // SIF_POS
				ctx.Mem.Write32(psi+20, uint32(nPos))
			}
			if fMask&0x10 != 0 { // SIF_TRACKPOS
				ctx.Mem.Write32(psi+24, uint32(nTrackPos))
			}
		}
		ravelog.Logf("[comctl32] FlatSB_GetScrollInfo hwnd=0x%x nBar=%d psi=0x%x mask=0x%x\n", hwnd, nBar, psi, fMask)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		pos := comctl32pkg.FlatSBGetScrollPos(hwnd, nBar)
		ravelog.Logf("[comctl32] FlatSB_GetScrollPos hwnd=0x%x nBar=%d -> %d\n", hwnd, nBar, pos)
		ctx.SetReturn(uint64(int64(pos)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollProp", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: FlatSB_GetScrollProp in dll/win32/comctl32/flatsb.c
		hwnd := ctx.Arg(0)
		propIdx := uint32(ctx.Arg(1))
		pValue := ctx.Arg(2)
		var val int32
		ok := comctl32pkg.FlatSBGetScrollProp(hwnd, propIdx, &val)
		if pValue != 0 {
			ctx.Mem.Write32(pValue, uint32(val))
		}
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		pMinPos := ctx.Arg(2)
		pMaxPos := ctx.Arg(3)
		minPos, maxPos := comctl32pkg.FlatSBGetScrollRange(hwnd, nBar)
		if pMinPos != 0 {
			ctx.Mem.Write32(pMinPos, uint32(minPos))
		}
		if pMaxPos != 0 {
			ctx.Mem.Write32(pMaxPos, uint32(maxPos))
		}
		ravelog.Logf("[comctl32] FlatSB_GetScrollRange hwnd=0x%x nBar=%d pMin=0x%x pMax=0x%x -> [%d,%d]\n",
			hwnd, nBar, pMinPos, pMaxPos, minPos, maxPos)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		psi := ctx.Arg(2)
		fRedraw := ctx.Arg(3) != 0
		var (
			mask     uint32
			minPos   int32
			maxPos   int32
			page     uint32
			pos      int32
			trackPos int32
		)
		if psi != 0 {
			mask, _ = ctx.Mem.Read32(psi + 4)
			v, _ := ctx.Mem.Read32(psi + 8)
			minPos = int32(v)
			v, _ = ctx.Mem.Read32(psi + 12)
			maxPos = int32(v)
			page, _ = ctx.Mem.Read32(psi + 16)
			v, _ = ctx.Mem.Read32(psi + 20)
			pos = int32(v)
			v, _ = ctx.Mem.Read32(psi + 24)
			trackPos = int32(v)
		}
		newPos := comctl32pkg.FlatSBSetScrollInfo(hwnd, nBar, mask, minPos, maxPos, page, pos, trackPos, fRedraw)
		ravelog.Logf("[comctl32] FlatSB_SetScrollInfo hwnd=0x%x nBar=%d psi=0x%x mask=0x%x min=%d max=%d page=%d pos=%d track=%d redraw=%v -> %d\n",
			hwnd, nBar, psi, mask, minPos, maxPos, page, pos, trackPos, fRedraw, newPos)
		ctx.SetReturn(uint64(int64(newPos)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		pos := int32(ctx.Arg(2))
		fRedraw := ctx.Arg(3) != 0
		oldPos := comctl32pkg.FlatSBSetScrollPos(hwnd, nBar, pos, fRedraw)
		ravelog.Logf("[comctl32] FlatSB_SetScrollPos hwnd=0x%x nBar=%d pos=%d redraw=%v -> old=%d\n",
			hwnd, nBar, pos, fRedraw, oldPos)
		ctx.SetReturn(uint64(int64(oldPos)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollProp", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: FlatSB_SetScrollProp in dll/win32/comctl32/flatsb.c
		hwnd := ctx.Arg(0)
		index := uint32(ctx.Arg(1))
		newValue := int32(ctx.Arg(2))
		fRedraw := ctx.Arg(3) != 0
		if comctl32pkg.FlatSBSetScrollProp(hwnd, index, newValue, fRedraw) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int32(ctx.Arg(1))
		minPos := int32(ctx.Arg(2))
		maxPos := int32(ctx.Arg(3))
		fRedraw := ctx.Arg(4) != 0
		ok := comctl32pkg.FlatSBSetScrollRange(hwnd, nBar, minPos, maxPos, fRedraw)
		ravelog.Logf("[comctl32] FlatSB_SetScrollRange hwnd=0x%x nBar=%d min=%d max=%d redraw=%v ok=%v\n",
			hwnd, nBar, minPos, maxPos, fRedraw, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// ── MRU ──────────────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "CreateMRUListW", func(ctx *ntapi.TrapContext) uint32 {
		// MRUINFO struct: cbSize, uMax, fFlags, hKey, lpszSubKey, lpfnCompare
		pInfo := ctx.Arg(0)
		uMax := int32(8)
		if pInfo != 0 {
			v, _ := ctx.Mem.Read32(pInfo + 4)
			uMax = int32(v)
		}
		ctx.SetReturn(comctl32pkg.CreateMRUListW(uMax))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "AddMRUStringW", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		pStr := ctx.Arg(1)
		s := ""
		if pStr != 0 {
			s = readGuestUTF16(pStr)
		}
		ctx.SetReturn(uint64(int64(comctl32pkg.AddMRUStringW(h, s))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "EnumMRUListW", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		n := int32(ctx.Arg(1))
		ctx.SetReturn(uint64(int64(comctl32pkg.EnumMRUListW(h, n, 0, 0))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FreeMRUList", func(ctx *ntapi.TrapContext) uint32 {
		comctl32pkg.FreeMRUList(ctx.Arg(0))
		return 0
	})

	// ── DllGetVersion ─────────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "DllGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(0)
		if pInfo != 0 {
			// DLLVERSIONINFO: cbSize(4), dwMajorVersion(4), dwMinorVersion(4),
			//                 dwBuildNumber(4), dwPlatformID(4)
			ctx.Mem.Write32(pInfo, 20) // cbSize
			ctx.Mem.Write32(pInfo+4, comctl32pkg.DllVersionMajor)
			ctx.Mem.Write32(pInfo+8, comctl32pkg.DllVersionMinor)
			ctx.Mem.Write32(pInfo+12, comctl32pkg.DllVersionBuildNum)
			ctx.Mem.Write32(pInfo+16, comctl32pkg.DllVersionPlatform)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})

	// ── Misc named exports ────────────────────────────────────────────────
	d.RegisterAutoStubHandler(comctl32, "GetEffectiveClientRect", func(ctx *ntapi.TrapContext) uint32 {
		// GetEffectiveClientRect(hwnd, prc, lpInfo) - fills rect subtracting toolbars
		// Stub: copy GetClientRect result
		hwnd := ctx.Arg(0)
		prc := ctx.Arg(1)
		if prc == 0 {
			return 0
		}
		var width, height int32
		if cs := hwndChildren[hwnd]; cs != nil {
			width, height = cs.w, cs.h
		} else if win := hctx.WlWindows[hwnd]; win != nil {
			width, height = win.Width, win.Height
		} else if hwnd == hctx.MainHWND && hctx.WlWindow != nil {
			width, height = hctx.WlWindow.Width, hctx.WlWindow.Height
		} else {
			width, height = 800, 600
		}
		if width < 0 {
			width = 0
		}
		if height < 0 {
			height = 0
		}
		ctx.Mem.Write32(prc, 0)
		ctx.Mem.Write32(prc+4, 0)
		ctx.Mem.Write32(prc+8, uint32(width))
		ctx.Mem.Write32(prc+12, uint32(height))
		ravelog.Logf("[comctl32] GetEffectiveClientRect hwnd=0x%x -> 0,0,%d,%d\n", hwnd, width, height)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateMappedBitmap", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // stub HBITMAP
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateToolbar", func(ctx *ntapi.TrapContext) uint32 {
		hwndParent := ctx.Arg(0)
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className:  "ToolbarWindow32",
			parentHWND: hwndParent,
			visible:    true,
		}
		ravelog.Logf("[comctl32] CreateToolbar hwnd=0x%x parent=0x%x\n", hwnd, hwndParent)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateToolbarEx", func(ctx *ntapi.TrapContext) uint32 {
		// CreateToolbarEx(hwndP, ws, wID, nBitmaps, hBMInst, wBMID,
		//   lpButtons, iNumButtons, dxButton, dyButton, dxBitmap, dyBitmap, uStructSize)
		hwndParent := ctx.Arg(0)
		ws := uint32(ctx.Arg(1))
		wID := ctx.Arg(2)
		iNumButtons := int32(ctx.Arg(7))
		dxButton := int32(ctx.Arg(8))
		dyButton := int32(ctx.Arg(9))
		dxBitmap := int32(ctx.Arg(10))
		dyBitmap := int32(ctx.Arg(11))
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className:     "ToolbarWindow32",
			parentHWND:    hwndParent,
			ctrlID:        wID,
			style:         ws,
			visible:       ws&0x10000000 != 0, // WS_VISIBLE
			tbBtnW:        dxButton,
			tbBtnH:        dyButton,
			tbBitmapIconW: dxBitmap,
			tbBitmapIconH: dyBitmap,
			tbButtons:     make([]tbButtonData, 0, iNumButtons),
		}
		ravelog.Logf("[comctl32] CreateToolbarEx hwnd=0x%x parent=0x%x buttons=%d btn=%dx%d bmp=%dx%d\n",
			hwnd, hwndParent, iNumButtons, dxButton, dyButton, dxBitmap, dyBitmap)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateUpDownControl", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hwndChildren[hwnd] = &controlState{
			className: "msctls_updown32",
			visible:   true,
		}
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateStatusWindow", func(ctx *ntapi.TrapContext) uint32 {
		style := uint32(ctx.Arg(0))
		hwndParent := ctx.Arg(2)
		hwnd := hwndAlloc()
		var defW, defH int32 = 800, 600
		if hctx.WlWindow != nil {
			defW, defH = hctx.WlWindow.Width, hctx.WlWindow.Height
		}
		const sbHeight int32 = 20
		hwndChildren[hwnd] = &controlState{
			className:  "msctls_statusbar32",
			parentHWND: hwndParent,
			x:          0, y: defH - sbHeight, w: defW, h: sbHeight,
			visible: style&0x10000000 != 0,
		}
		ravelog.Logf("[comctl32] CreateStatusWindow hwnd=0x%x parent=0x%x\n", hwnd, hwndParent)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateStatusWindowA", func(ctx *ntapi.TrapContext) uint32 {
		style := uint32(ctx.Arg(0))
		hwndParent := ctx.Arg(2)
		hwnd := hwndAlloc()
		var defW, defH int32 = 800, 600
		if hctx.WlWindow != nil {
			defW, defH = hctx.WlWindow.Width, hctx.WlWindow.Height
		}
		const sbHeight int32 = 20
		hwndChildren[hwnd] = &controlState{
			className:  "msctls_statusbar32",
			parentHWND: hwndParent,
			x:          0, y: defH - sbHeight, w: defW, h: sbHeight,
			visible: style&0x10000000 != 0,
		}
		ravelog.Logf("[comctl32] CreateStatusWindowA hwnd=0x%x parent=0x%x\n", hwnd, hwndParent)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawStatusText", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawStatusTextA", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawStatusTextW", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawInsert", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "LBItemFromPt", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "MakeDragList", func(ctx *ntapi.TrapContext) uint32 {
		hwndLB := ctx.Arg(0)
		ok := hwndLB != 0
		if ok {
			comctlMu.Lock()
			dragListWindows[hwndLB] = true
			comctlMu.Unlock()
		}
		ravelog.Logf("[comctl32] MakeDragList hwndLB=0x%x ok=%v\n", hwndLB, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "MenuHelp", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ShowHideMenuCtl", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		uFlags := ctx.Arg(1)
		lpInfo := ctx.Arg(2)
		var (
			menuHandle1 uint32
			menuHandle2 uint32
			controlID   uint32
			foundPair   bool
			visible     bool
		)
		if lpInfo != 0 {
			menuHandle1, _ = ctx.Mem.Read32(lpInfo)
			menuHandle2, _ = ctx.Mem.Read32(lpInfo + 4)
			for off := uint64(8); off < 8+64*8; off += 8 {
				menuID, _ := ctx.Mem.Read32(lpInfo + off)
				ctrlID, _ := ctx.Mem.Read32(lpInfo + off + 4)
				if menuID == 0 && ctrlID == 0 {
					break
				}
				if uint64(menuID) == uFlags {
					controlID = ctrlID
					foundPair = true
					break
				}
			}
		}
		if foundPair {
			for childHwnd, cs := range hwndChildren {
				if cs.parentHWND == hwnd && cs.ctrlID == uint64(controlID) {
					cs.visible = !cs.visible
					visible = cs.visible
					ravelog.Logf("[comctl32] ShowHideMenuCtl hwnd=0x%x flags=0x%x menu=(0x%x,0x%x) ctrlID=%d child=0x%x visible=%v\n",
						hwnd, uFlags, menuHandle1, menuHandle2, controlID, childHwnd, visible)
					ctx.SetReturn(1)
					return 0
				}
			}
		}
		ravelog.Logf("[comctl32] ShowHideMenuCtl hwnd=0x%x flags=0x%x menu=(0x%x,0x%x) ctrlID=%d foundPair=%v visible=%v\n",
			hwnd, uFlags, menuHandle1, menuHandle2, controlID, foundPair, visible)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "RegisterClassNameW", func(ctx *ntapi.TrapContext) uint32 {
		classNamePtr := ctx.Arg(0)
		className := ""
		if classNamePtr != 0 {
			className = readGuestUTF16(classNamePtr)
		}
		comctlMu.Lock()
		_, alreadyRegistered := registeredClassNames[className]
		if className != "" {
			registeredClassNames[className] = struct{}{}
		}
		comctlMu.Unlock()
		ravelog.Logf("[comctl32] RegisterClassNameW className=%q ptr=0x%x alreadyRegistered=%v\n",
			className, classNamePtr, alreadyRegistered)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "GetMUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(muiLanguage))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "InitMUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: InitMUILanguage in dll/win32/comctl32/commctrl.c
		muiLanguage = uint32(ctx.Arg(0))
		return 0
	})
	// TaskDialog / TaskDialogIndirect: modal dialogs; stub returns IDOK.
	d.RegisterAutoStubHandler(comctl32, "TaskDialog", func(ctx *ntapi.TrapContext) uint32 {
		// TaskDialog(hwndOwner, hInstance, pszWindowTitle, pszMainInstruction,
		//            pszContent, dwCommonButtons, pszIcon, pnButton)
		pnButton := ctx.Arg(7)
		if pnButton != 0 {
			ctx.Mem.Write32(pnButton, 1) // IDOK
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "TaskDialogIndirect", func(ctx *ntapi.TrapContext) uint32 {
		// TaskDialogIndirect(pTaskConfig, pnButton, pnRadioButton, pfVerificationFlagChecked)
		pnButton := ctx.Arg(1)
		if pnButton != 0 {
			ctx.Mem.Write32(pnButton, 1) // IDOK
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetFilter", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		i := int32(ctx.Arg(1))
		dwFilter := uint32(ctx.Arg(2))
		ok := comctl32pkg.ImageListSetFilter(himl, i, dwFilter)
		ravelog.Logf("[comctl32] ImageList_SetFilter himl=0x%x i=%d filter=0x%x ok=%v\n", himl, i, dwFilter, ok)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "_TrackMouseEvent", func(ctx *ntapi.TrapContext) uint32 {
		// _TrackMouseEvent is the comctl32 version - same as user32!TrackMouseEvent
		pTME := ctx.Arg(0)
		if pTME == 0 {
			ctx.SetReturn(0)
			return 0
		}
		flags, _ := ctx.Mem.Read32(pTME + 4)
		hwnd, _ := ctx.Mem.Read64(pTME + 8)
		if flags&0x80000000 != 0 { // TME_CANCEL
			delete(hctx.TrackMouseHwnds, hwnd)
		} else {
			hctx.TrackMouseHwnds[hwnd] = flags
		}
		ctx.SetReturn(1)
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing comctl32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(comctl32, "AddMRUData", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		lpData := ctx.Arg(1)
		cbData := ctx.Arg(2)
		ravelog.Logf("[comctl32] AddMRUData handle=0x%x data=0x%x size=%d\n", hMRU, lpData, cbData)
		ctx.SetReturn(0) // index 0
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "AddMRUStringA", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		lpszString := ctx.Arg(1)
		ravelog.Logf("[comctl32] AddMRUStringA handle=0x%x\n", hMRU)
		_ = lpszString
		ctx.SetReturn(0) // index 0
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Alloc", func(ctx *ntapi.TrapContext) uint32 {
		dwSize := ctx.Arg(0)
		ravelog.Logf("[comctl32] Alloc size=%d\n", dwSize)
		buf := sharedHeapAlloc(dwSize, true)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateMRUListA", func(ctx *ntapi.TrapContext) uint32 {
		lpCreateInfo := ctx.Arg(0)
		ravelog.Logf("[comctl32] CreateMRUListA info=0x%x\n", lpCreateInfo)
		ctx.SetReturn(0xDEAD0100) // fake MRU handle
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateMRUListLazyA", func(ctx *ntapi.TrapContext) uint32 {
		lpCreateInfo := ctx.Arg(0)
		param1 := ctx.Arg(1)
		param2 := ctx.Arg(2)
		param3 := ctx.Arg(3)
		ravelog.Logf("[comctl32] CreateMRUListLazyA info=0x%x\n", lpCreateInfo)
		_ = param1
		_ = param2
		_ = param3
		ctx.SetReturn(0xDEAD0101) // fake MRU handle
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateMRUListLazyW", func(ctx *ntapi.TrapContext) uint32 {
		lpCreateInfo := ctx.Arg(0)
		param1 := ctx.Arg(1)
		param2 := ctx.Arg(2)
		param3 := ctx.Arg(3)
		ravelog.Logf("[comctl32] CreateMRUListLazyW info=0x%x\n", lpCreateInfo)
		_ = param1
		_ = param2
		_ = param3
		ctx.SetReturn(0xDEAD0101) // fake MRU handle
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreatePage", func(ctx *ntapi.TrapContext) uint32 {
		pPageInfo := ctx.Arg(0)
		hModule := ctx.Arg(1)
		ravelog.Logf("[comctl32] CreatePage info=0x%x module=0x%x\n", pPageInfo, hModule)
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateProxyPage", func(ctx *ntapi.TrapContext) uint32 {
		pPageInfo := ctx.Arg(0)
		pProxyPage := ctx.Arg(1)
		ravelog.Logf("[comctl32] CreateProxyPage info=0x%x proxy=0x%x\n", pPageInfo, pProxyPage)
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_LoadStream", func(ctx *ntapi.TrapContext) uint32 {
		phdpa := ctx.Arg(0)
		pfn := ctx.Arg(1)
		pstream := ctx.Arg(2)
		pvInstData := ctx.Arg(3)
		ravelog.Logf("[comctl32] DPA_LoadStream hdpa=0x%x fn=0x%x\n", phdpa, pfn)
		_ = pstream
		_ = pvInstData
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_Merge", func(ctx *ntapi.TrapContext) uint32 {
		hdpaDest := ctx.Arg(0)
		hdpaSrc := ctx.Arg(1)
		dwFlags := ctx.Arg(2)
		pfnCompare := ctx.Arg(3)
		pfnMerge := ctx.Arg(4)
		lParam := ctx.Arg(5)
		ravelog.Logf("[comctl32] DPA_Merge dest=0x%x src=0x%x flags=0x%x\n", hdpaDest, hdpaSrc, dwFlags)
		_ = pfnCompare
		_ = pfnMerge
		_ = lParam
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DPA_SaveStream", func(ctx *ntapi.TrapContext) uint32 {
		hdpa := ctx.Arg(0)
		pfn := ctx.Arg(1)
		pstream := ctx.Arg(2)
		pvInstData := ctx.Arg(3)
		ravelog.Logf("[comctl32] DPA_SaveStream hdpa=0x%x fn=0x%x\n", hdpa, pfn)
		_ = pstream
		_ = pvInstData
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DelMRUString", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		nItem := ctx.Arg(1)
		ravelog.Logf("[comctl32] DelMRUString handle=0x%x item=%d\n", hMRU, nItem)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DllInstall", func(ctx *ntapi.TrapContext) uint32 {
		bInstall := ctx.Arg(0)
		pszCmdLine := ctx.Arg(1)
		ravelog.Logf("[comctl32] DllInstall install=%d\n", bInstall)
		_ = pszCmdLine
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DoReaderMode", func(ctx *ntapi.TrapContext) uint32 {
		prmi := ctx.Arg(0)
		ravelog.Logf("[comctl32] DoReaderMode info=0x%x\n", prmi)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawShadowText", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		pszText := ctx.Arg(1)
		cch := ctx.Arg(2)
		prc := ctx.Arg(3)
		dwFlags := ctx.Arg(4)
		crText := ctx.Arg(5)
		ravelog.Logf("[comctl32] DrawShadowText hdc=0x%x text=0x%x cch=%d flags=0x%x\n", hdc, pszText, cch, dwFlags)
		_ = prc
		_ = crText
		ctx.SetReturn(0) // 0 = no height
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawTextExPrivWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] DrawTextExPrivWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DrawTextWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] DrawTextWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "EnumMRUListA", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		nItem := ctx.Arg(1)
		lpData := ctx.Arg(2)
		cbData := ctx.Arg(3)
		ravelog.Logf("[comctl32] EnumMRUListA handle=0x%x item=%d\n", hMRU, nItem)
		_ = lpData
		_ = cbData
		ctx.SetReturn(^uint64(0)) // -1 = no more items
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ExtTextOutWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] ExtTextOutWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FindMRUData", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		lpData := ctx.Arg(1)
		cbData := ctx.Arg(2)
		lpRegNum := ctx.Arg(3)
		ravelog.Logf("[comctl32] FindMRUData handle=0x%x\n", hMRU)
		_ = lpData
		_ = cbData
		if lpRegNum != 0 {
			ctx.Mem.Write32(lpRegNum, 0)
		}
		ctx.SetReturn(^uint64(0)) // -1 = not found
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FindMRUStringA", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		lpszString := ctx.Arg(1)
		lpRegNum := ctx.Arg(2)
		ravelog.Logf("[comctl32] FindMRUStringA handle=0x%x\n", hMRU)
		_ = lpszString
		if lpRegNum != 0 {
			ctx.Mem.Write32(lpRegNum, 0)
		}
		ctx.SetReturn(^uint64(0)) // -1 = not found
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FindMRUStringW", func(ctx *ntapi.TrapContext) uint32 {
		hMRU := ctx.Arg(0)
		lpszString := ctx.Arg(1)
		lpRegNum := ctx.Arg(2)
		ravelog.Logf("[comctl32] FindMRUStringW handle=0x%x\n", hMRU)
		_ = lpszString
		if lpRegNum != 0 {
			ctx.Mem.Write32(lpRegNum, 0)
		}
		ctx.SetReturn(^uint64(0)) // -1 = not found
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Free", func(ctx *ntapi.TrapContext) uint32 {
		lpMem := ctx.Arg(0)
		ravelog.Logf("[comctl32] Free mem=0x%x\n", lpMem)
		ctx.SetReturn(1) // TRUE (success)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "GetCharWidthWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] GetCharWidthWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "GetSize", func(ctx *ntapi.TrapContext) uint32 {
		lpMem := ctx.Arg(0)
		ravelog.Logf("[comctl32] GetSize mem=0x%x\n", lpMem)
		ctx.SetReturn(0) // unknown size
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "GetTextExtentPoint32Wrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] GetTextExtentPoint32Wrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "GetTextExtentPointWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] GetTextExtentPointWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetColorTable", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		iStart := ctx.Arg(1)
		cEntries := ctx.Arg(2)
		prgb := ctx.Arg(3)
		ravelog.Logf("[comctl32] ImageList_SetColorTable iml=0x%x start=%d entries=%d\n", himl, iStart, cEntries)
		_ = prgb
		ctx.SetReturn(cEntries) // return number of entries set
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "IntlStrEqWorkerA", func(ctx *ntapi.TrapContext) uint32 {
		fCaseSens := ctx.Arg(0)
		lpString1 := ctx.Arg(1)
		lpString2 := ctx.Arg(2)
		nChar := ctx.Arg(3)
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read8(lpString1 + i*1)
			c2, _ := ctx.Mem.Read8(lpString2 + i*1)
			if fCaseSens == 0 {
				if c1 >= 65 && c1 <= 90 {
					c1 += 32
				}
				if c2 >= 65 && c2 <= 90 {
					c2 += 32
				}
			}
			if c1 != c2 {
				ctx.SetReturn(0)
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(1) // TRUE - strings are equal
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "IntlStrEqWorkerW", func(ctx *ntapi.TrapContext) uint32 {
		fCaseSens := ctx.Arg(0)
		lpString1 := ctx.Arg(1)
		lpString2 := ctx.Arg(2)
		nChar := ctx.Arg(3)
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read16(lpString1 + i*2)
			c2, _ := ctx.Mem.Read16(lpString2 + i*2)
			if fCaseSens == 0 {
				if c1 >= 65 && c1 <= 90 {
					c1 += 32
				}
				if c2 >= 65 && c2 <= 90 {
					c2 += 32
				}
			}
			if c1 != c2 {
				ctx.SetReturn(0)
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(1) // TRUE - strings are equal
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "MirrorIcon", func(ctx *ntapi.TrapContext) uint32 {
		phInstOrig := ctx.Arg(0)
		phIconOrig := ctx.Arg(1)
		ravelog.Logf("[comctl32] MirrorIcon orig=0x%x icon=0x%x\n", phInstOrig, phIconOrig)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ReAlloc", func(ctx *ntapi.TrapContext) uint32 {
		lpMem := ctx.Arg(0)
		dwSize := ctx.Arg(1)
		ravelog.Logf("[comctl32] ReAlloc mem=0x%x size=%d\n", lpMem, dwSize)
		buf := sharedHeapAlloc(dwSize, true)
		if lpMem != 0 && buf != 0 {
			for i := uint64(0); i < dwSize && i < 0x10000; i++ {
				b, _ := ctx.Mem.Read8(lpMem + i)
				ctx.Mem.Write8(buf+i, b)
			}
		}
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "SendNotify", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		code := ctx.Arg(1)
		lpnmh := ctx.Arg(2)
		ravelog.Logf("[comctl32] SendNotify hwnd=0x%x code=0x%x\n", hwnd, code)
		_ = lpnmh
		ctx.SetReturn(0) // LRESULT=0
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "SendNotifyEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hwndFrom := ctx.Arg(1)
		code := ctx.Arg(2)
		lpnmh := ctx.Arg(3)
		ravelog.Logf("[comctl32] SendNotifyEx hwnd=0x%x from=0x%x code=0x%x\n", hwnd, hwndFrom, code)
		_ = lpnmh
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "SetPathWordBreakProc", func(ctx *ntapi.TrapContext) uint32 {
		hwndEdit := ctx.Arg(0)
		bSet := ctx.Arg(1)
		ravelog.Logf("[comctl32] SetPathWordBreakProc hwnd=0x%x set=%d\n", hwndEdit, bSet)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "SmoothScrollWindow", func(ctx *ntapi.TrapContext) uint32 {
		psInfo := ctx.Arg(0)
		ravelog.Logf("[comctl32] SmoothScrollWindow info=0x%x\n", psInfo)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCSpnA", func(ctx *ntapi.TrapContext) uint32 {
		lpStr := ctx.Arg(0)
		lpSet := ctx.Arg(1)
		if lpStr == 0 || lpSet == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var count uint64
		for i := lpStr; ; i += 1 {
			ch, _ := ctx.Mem.Read8(i)
			if ch == 0 {
				break
			}
			found := false
			for j := lpSet; ; j += 1 {
				s, _ := ctx.Mem.Read8(j)
				if s == 0 {
					break
				}
				if s == ch {
					found = true
					break
				}
			}
			if found {
				break
			}
			count++
		}
		ctx.SetReturn(count)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCSpnIA", func(ctx *ntapi.TrapContext) uint32 {
		lpStr := ctx.Arg(0)
		lpSet := ctx.Arg(1)
		if lpStr == 0 || lpSet == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint8) uint8 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var count uint64
		for i := lpStr; ; i += 1 {
			ch, _ := ctx.Mem.Read8(i)
			if ch == 0 {
				break
			}
			found := false
			for j := lpSet; ; j += 1 {
				s, _ := ctx.Mem.Read8(j)
				if s == 0 {
					break
				}
				if lo(s) == lo(ch) {
					found = true
					break
				}
			}
			if found {
				break
			}
			count++
		}
		ctx.SetReturn(count)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCSpnIW", func(ctx *ntapi.TrapContext) uint32 {
		lpStr := ctx.Arg(0)
		lpSet := ctx.Arg(1)
		if lpStr == 0 || lpSet == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint16) uint16 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var count uint64
		for i := lpStr; ; i += 2 {
			ch, _ := ctx.Mem.Read16(i)
			if ch == 0 {
				break
			}
			found := false
			for j := lpSet; ; j += 2 {
				s, _ := ctx.Mem.Read16(j)
				if s == 0 {
					break
				}
				if lo(s) == lo(ch) {
					found = true
					break
				}
			}
			if found {
				break
			}
			count++
		}
		ctx.SetReturn(count)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCSpnW", func(ctx *ntapi.TrapContext) uint32 {
		lpStr := ctx.Arg(0)
		lpSet := ctx.Arg(1)
		if lpStr == 0 || lpSet == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var count uint64
		for i := lpStr; ; i += 2 {
			ch, _ := ctx.Mem.Read16(i)
			if ch == 0 {
				break
			}
			found := false
			for j := lpSet; ; j += 2 {
				s, _ := ctx.Mem.Read16(j)
				if s == 0 {
					break
				}
				if s == ch {
					found = true
					break
				}
			}
			if found {
				break
			}
			count++
		}
		ctx.SetReturn(count)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrChrA", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		for addr := lpStart; ; addr += 1 {
			ch, _ := ctx.Mem.Read8(addr)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if uint64(ch) == wMatch {
				ctx.SetReturn(addr)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrChrIA", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint64) uint64 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for addr := lpStart; ; addr += 1 {
			ch, _ := ctx.Mem.Read8(addr)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if lo(uint64(ch)) == lo(wMatch) {
				ctx.SetReturn(addr)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrChrIW", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint64) uint64 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for addr := lpStart; ; addr += 2 {
			ch, _ := ctx.Mem.Read16(addr)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if lo(uint64(ch)) == lo(wMatch) {
				ctx.SetReturn(addr)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrChrW", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		wMatch := ctx.Arg(1)
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		for addr := lpStart; ; addr += 2 {
			ch, _ := ctx.Mem.Read16(addr)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			if uint64(ch) == wMatch {
				ctx.SetReturn(addr)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCmpNA", func(ctx *ntapi.TrapContext) uint32 {
		lpStr1 := ctx.Arg(0)
		lpStr2 := ctx.Arg(1)
		nChar := ctx.Arg(2)
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read8(lpStr1 + i*1)
			c2, _ := ctx.Mem.Read8(lpStr2 + i*1)
			if c1 != c2 {
				if c1 < c2 {
					ctx.SetReturn(^uint64(0))
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(0) // equal
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCmpNIA", func(ctx *ntapi.TrapContext) uint32 {
		lpStr1 := ctx.Arg(0)
		lpStr2 := ctx.Arg(1)
		nChar := ctx.Arg(2)
		lo := func(c uint8) uint8 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read8(lpStr1 + i*1)
			c2, _ := ctx.Mem.Read8(lpStr2 + i*1)
			l1, l2 := lo(c1), lo(c2)
			if l1 != l2 {
				if l1 < l2 {
					ctx.SetReturn(^uint64(0))
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCmpNIW", func(ctx *ntapi.TrapContext) uint32 {
		lpStr1 := ctx.Arg(0)
		lpStr2 := ctx.Arg(1)
		nChar := ctx.Arg(2)
		lo := func(c uint16) uint16 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read16(lpStr1 + i*2)
			c2, _ := ctx.Mem.Read16(lpStr2 + i*2)
			l1, l2 := lo(c1), lo(c2)
			if l1 != l2 {
				if l1 < l2 {
					ctx.SetReturn(^uint64(0))
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrCmpNW", func(ctx *ntapi.TrapContext) uint32 {
		lpStr1 := ctx.Arg(0)
		lpStr2 := ctx.Arg(1)
		nChar := ctx.Arg(2)
		for i := uint64(0); i < nChar; i++ {
			c1, _ := ctx.Mem.Read16(lpStr1 + i*2)
			c2, _ := ctx.Mem.Read16(lpStr2 + i*2)
			if c1 != c2 {
				if c1 < c2 {
					ctx.SetReturn(^uint64(0))
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
			if c1 == 0 {
				break
			}
		}
		ctx.SetReturn(0) // equal
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRChrA", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		lpEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		_ = lpEnd
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var lastMatch uint64
		for addr := lpStart; ; addr += 1 {
			ch, _ := ctx.Mem.Read8(addr)
			if ch == 0 {
				break
			}
			if lpEnd != 0 && addr >= lpEnd {
				break
			}
			if uint64(ch) == wMatch {
				lastMatch = addr
			}
		}
		ctx.SetReturn(lastMatch)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRChrIA", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		lpEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		_ = lpEnd
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint64) uint64 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var lastMatch uint64
		for addr := lpStart; ; addr += 1 {
			ch, _ := ctx.Mem.Read8(addr)
			if ch == 0 {
				break
			}
			if lpEnd != 0 && addr >= lpEnd {
				break
			}
			if lo(uint64(ch)) == lo(wMatch) {
				lastMatch = addr
			}
		}
		ctx.SetReturn(lastMatch)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRChrIW", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		lpEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		_ = lpEnd
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint64) uint64 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var lastMatch uint64
		for addr := lpStart; ; addr += 2 {
			ch, _ := ctx.Mem.Read16(addr)
			if ch == 0 {
				break
			}
			if lpEnd != 0 && addr >= lpEnd {
				break
			}
			if lo(uint64(ch)) == lo(wMatch) {
				lastMatch = addr
			}
		}
		ctx.SetReturn(lastMatch)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRChrW", func(ctx *ntapi.TrapContext) uint32 {
		lpStart := ctx.Arg(0)
		lpEnd := ctx.Arg(1)
		wMatch := ctx.Arg(2)
		_ = lpEnd
		if lpStart == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var lastMatch uint64
		for addr := lpStart; ; addr += 2 {
			ch, _ := ctx.Mem.Read16(addr)
			if ch == 0 {
				break
			}
			if lpEnd != 0 && addr >= lpEnd {
				break
			}
			if uint64(ch) == wMatch {
				lastMatch = addr
			}
		}
		ctx.SetReturn(lastMatch)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRStrIA", func(ctx *ntapi.TrapContext) uint32 {
		lpSource := ctx.Arg(0)
		lpLast := ctx.Arg(1)
		lpSrch := ctx.Arg(2)
		_ = lpLast
		if lpSource == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint8) uint8 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var lastFound uint64
		for i := lpSource; ; i += 1 {
			ch, _ := ctx.Mem.Read8(i)
			if ch == 0 {
				break
			}
			if lpLast != 0 && i >= lpLast {
				break
			}
			match := true
			for j := uint64(0); ; j += 1 {
				s, _ := ctx.Mem.Read8(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read8(i + j)
				if lo(t) != lo(s) {
					match = false
					break
				}
			}
			if match {
				lastFound = i
			}
		}
		ctx.SetReturn(lastFound)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrRStrIW", func(ctx *ntapi.TrapContext) uint32 {
		lpSource := ctx.Arg(0)
		lpLast := ctx.Arg(1)
		lpSrch := ctx.Arg(2)
		_ = lpLast
		if lpSource == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint16) uint16 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		var lastFound uint64
		for i := lpSource; ; i += 2 {
			ch, _ := ctx.Mem.Read16(i)
			if ch == 0 {
				break
			}
			if lpLast != 0 && i >= lpLast {
				break
			}
			match := true
			for j := uint64(0); ; j += 2 {
				s, _ := ctx.Mem.Read16(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read16(i + j)
				if lo(t) != lo(s) {
					match = false
					break
				}
			}
			if match {
				lastFound = i
			}
		}
		ctx.SetReturn(lastFound)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrStrA", func(ctx *ntapi.TrapContext) uint32 {
		lpFirst := ctx.Arg(0)
		lpSrch := ctx.Arg(1)
		if lpFirst == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Simple O(n*m) substring search
		for i := lpFirst; ; i += 1 {
			ch, _ := ctx.Mem.Read8(i)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			match := true
			for j := uint64(0); ; j += 1 {
				s, _ := ctx.Mem.Read8(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read8(i + j)
				if t != s {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(i)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrStrIA", func(ctx *ntapi.TrapContext) uint32 {
		lpFirst := ctx.Arg(0)
		lpSrch := ctx.Arg(1)
		if lpFirst == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint8) uint8 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for i := lpFirst; ; i += 1 {
			ch, _ := ctx.Mem.Read8(i)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			match := true
			for j := uint64(0); ; j += 1 {
				s, _ := ctx.Mem.Read8(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read8(i + j)
				if lo(t) != lo(s) {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(i)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrStrIW", func(ctx *ntapi.TrapContext) uint32 {
		lpFirst := ctx.Arg(0)
		lpSrch := ctx.Arg(1)
		if lpFirst == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo := func(c uint16) uint16 {
			if c >= 65 && c <= 90 {
				return c + 32
			}
			return c
		}
		for i := lpFirst; ; i += 2 {
			ch, _ := ctx.Mem.Read16(i)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			match := true
			for j := uint64(0); ; j += 2 {
				s, _ := ctx.Mem.Read16(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read16(i + j)
				if lo(t) != lo(s) {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(i)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrStrW", func(ctx *ntapi.TrapContext) uint32 {
		lpFirst := ctx.Arg(0)
		lpSrch := ctx.Arg(1)
		if lpFirst == 0 || lpSrch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Simple O(n*m) substring search
		for i := lpFirst; ; i += 2 {
			ch, _ := ctx.Mem.Read16(i)
			if ch == 0 {
				ctx.SetReturn(0)
				return 0
			}
			match := true
			for j := uint64(0); ; j += 2 {
				s, _ := ctx.Mem.Read16(lpSrch + j)
				if s == 0 {
					break
				}
				t, _ := ctx.Mem.Read16(i + j)
				if t != s {
					match = false
					break
				}
			}
			if match {
				ctx.SetReturn(i)
				return 0
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrToIntA", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(0)
		if lpSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var neg bool
		addr := lpSrc
		ch, _ := ctx.Mem.Read8(addr)
		if ch == uint8('-') {
			neg = true
			addr += 1
			ch, _ = ctx.Mem.Read8(addr)
		}
		if ch == uint8('+') {
			addr += 1
			ch, _ = ctx.Mem.Read8(addr)
		}
		var result int64
		for ch >= uint8('0') && ch <= uint8('9') {
			result = result*10 + int64(ch-uint8('0'))
			addr += 1
			ch, _ = ctx.Mem.Read8(addr)
		}
		if neg {
			result = -result
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "StrToIntW", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(0)
		if lpSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var neg bool
		addr := lpSrc
		ch, _ := ctx.Mem.Read16(addr)
		if ch == uint16('-') {
			neg = true
			addr += 2
			ch, _ = ctx.Mem.Read16(addr)
		}
		if ch == uint16('+') {
			addr += 2
			ch, _ = ctx.Mem.Read16(addr)
		}
		var result int64
		for ch >= uint16('0') && ch <= uint16('9') {
			result = result*10 + int64(ch-uint16('0'))
			addr += 2
			ch, _ = ctx.Mem.Read16(addr)
		}
		if neg {
			result = -result
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Str_GetPtrA", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(0)
		lpDest := ctx.Arg(1)
		nMaxLen := ctx.Arg(2)
		if lpSrc == 0 || lpDest == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var i uint64
		for i = 0; i < nMaxLen-1; i++ {
			ch, _ := ctx.Mem.Read8(lpSrc + i*1)
			ctx.Mem.Write8(lpDest+i*1, ch)
			if ch == 0 {
				ctx.SetReturn(i)
				return 0
			}
		}
		ctx.Mem.Write8(lpDest+i*1, 0) // NUL terminate
		ctx.SetReturn(i)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Str_GetPtrW", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(0)
		lpDest := ctx.Arg(1)
		nMaxLen := ctx.Arg(2)
		if lpSrc == 0 || lpDest == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var i uint64
		for i = 0; i < nMaxLen-1; i++ {
			ch, _ := ctx.Mem.Read16(lpSrc + i*2)
			ctx.Mem.Write16(lpDest+i*2, ch)
			if ch == 0 {
				ctx.SetReturn(i)
				return 0
			}
		}
		ctx.Mem.Write16(lpDest+i*2, 0) // NUL terminate
		ctx.SetReturn(i)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Str_SetPtrA", func(ctx *ntapi.TrapContext) uint32 {
		lppDest := ctx.Arg(0)
		lpSrc := ctx.Arg(1)
		ravelog.Logf("[comctl32] Str_SetPtrA dest=0x%x src=0x%x\n", lppDest, lpSrc)
		if lppDest == 0 {
			return 0
		}
		is32 := ctx.State != nil && ctx.State.Is32
		old, _ := readGuestPointer(ctx.Mem, lppDest, is32)
		if lpSrc == 0 {
			if old != 0 {
				hctx.HeapFree(old)
			}
			writeGuestPointer(ctx.Mem, lppDest, 0, is32)
			ctx.SetReturn(1)
			return 0
		}
		source := hctx.ReadGuestString(lpSrc)
		replacement := hctx.HeapAlloc(uint64(len(source)+1), false)
		if replacement == 0 {
			return 0
		}
		ctx.Mem.WriteBytes(replacement, append([]byte(source), 0))
		if old != 0 {
			hctx.HeapFree(old)
		}
		writeGuestPointer(ctx.Mem, lppDest, replacement, is32)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "Str_SetPtrW", func(ctx *ntapi.TrapContext) uint32 {
		lppDest := ctx.Arg(0)
		lpSrc := ctx.Arg(1)
		ravelog.Logf("[comctl32] Str_SetPtrW dest=0x%x src=0x%x\n", lppDest, lpSrc)
		if lppDest == 0 {
			return 0
		}
		is32 := ctx.State != nil && ctx.State.Is32
		old, _ := readGuestPointer(ctx.Mem, lppDest, is32)
		if lpSrc == 0 {
			if old != 0 {
				hctx.HeapFree(old)
			}
			writeGuestPointer(ctx.Mem, lppDest, 0, is32)
			ctx.SetReturn(1)
			return 0
		}
		source := utf16Encode(hctx.ReadGuestUTF16(lpSrc))
		replacement := hctx.HeapAlloc(uint64((len(source)+1)*2), false)
		if replacement == 0 {
			return 0
		}
		for i, ch := range source {
			ctx.Mem.Write16(replacement+uint64(i)*2, ch)
		}
		ctx.Mem.Write16(replacement+uint64(len(source))*2, 0)
		if old != 0 {
			hctx.HeapFree(old)
		}
		writeGuestPointer(ctx.Mem, lppDest, replacement, is32)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "TextOutWrap", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		ravelog.Logf("[comctl32] TextOutWrap hdc=0x%x - forwarding as nop\n", hdc)
		ctx.SetReturn(1) // TRUE
		return 0
	})
}
