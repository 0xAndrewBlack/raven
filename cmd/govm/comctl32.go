package main

import (
	comctl32pkg "github.com/mirkobrombin/Raven/pkg/comctl32"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerComctl32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	hwndAlloc := hctx.HwndAlloc
	hwndChildren := hctx.HwndChildren
	readGuestUTF16 := hctx.ReadGuestUTF16

	comctl32, ok := hctx.SynthByName["comctl32.dll"]
	if !ok {
		return
	}
	_ = comctl32

	// MUI language: stored per-process; default en-US (0x0409).
	muiLanguage := uint32(0x0409)

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
		idx := comctl32pkg.ImageListReplaceIcon(himl, i)
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
		idx := comctl32pkg.ImageListAddMasked(himl)
		ctx.SetReturn(uint64(int64(idx)))
		return 0
	})

	// ImageList_Add - adds bitmap without mask; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_Add", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		idx := comctl32pkg.ImageListAdd(himl)
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

	// ImageList_Draw - draw image from list to HDC (no-op stub)
	d.RegisterAutoStubHandler(comctl32, "ImageList_Draw", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	// ImageList_DrawEx - extended draw (no-op stub)
	d.RegisterAutoStubHandler(comctl32, "ImageList_DrawEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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
		idx := comctl32pkg.ImageListAdd(h)
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
		ctx.Mem.Write32(pInfo+24, uint32(x))       // rcImage.left
		ctx.Mem.Write32(pInfo+28, 0)                // rcImage.top
		ctx.Mem.Write32(pInfo+32, uint32(x+cx))     // rcImage.right
		ctx.Mem.Write32(pInfo+36, uint32(cy))        // rcImage.bottom
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
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetFlags", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_BeginDrag", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_EndDrag", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragEnter", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragLeave", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragMove", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DragShowNolock", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetDragCursorImage", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Duplicate", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		ctx.SetReturn(comctl32pkg.ImageListDuplicate(h))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Replace", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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
		newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
		newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_LoadImage", func(ctx *ntapi.TrapContext) uint32 {
		newH := comctl32pkg.ImageListCreate(16, 16, 0, 0, 4)
		ctx.SetReturn(newH)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Read", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_Write", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_DrawIndirect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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
		uid := uint32(ctx.Arg(2))
		ref := ctx.Arg(3)
		if comctl32pkg.SetWindowSubclass(hwnd, pfn, uid, ref) {
			ctx.SetReturn(1)
		}
		return 0
	})
	// ord=411: GetWindowSubclass
	d.RegisterAutoStubHandler(comctl32, "GetWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pfn := ctx.Arg(1)
		uid := uint32(ctx.Arg(2))
		pRef := ctx.Arg(3)
		ref, ok := comctl32pkg.GetWindowSubclass(hwnd, pfn, uid)
		if ok {
			if pRef != 0 {
				ctx.Mem.Write64(pRef, ref)
			}
			ctx.SetReturn(1)
		}
		return 0
	})
	// ord=412: RemoveWindowSubclass
	d.RegisterAutoStubHandler(comctl32, "RemoveWindowSubclass", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pfn := ctx.Arg(1)
		uid := uint32(ctx.Arg(2))
		if comctl32pkg.RemoveWindowSubclass(hwnd, pfn, uid) {
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
		// We can't call guest subclass procs without a full call-chain.
		// Try built-in window procedure first (handles builtin controls),
		// then fall back to 0 (DefWindowProcW default for most messages).
		if hctx.BuiltinWndProc != nil {
			if res, handled := hctx.BuiltinWndProc(hwnd, uMsg, wParam, lParam); handled {
				ctx.SetReturn(res)
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
		_ = fn
		d.RegisterAutoStubHandler(comctl32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: FlatSB_GetScrollInfo - fill SCROLLINFO with defaults
		// SCROLLINFO: cbSize(+0), fMask(+4), nMin(+8), nMax(+12), nPage(+16), nPos(+20), nTrackPos(+24)
		psi := ctx.Arg(2)
		if psi != 0 {
			fMask, _ := ctx.Mem.Read32(psi + 4)
			if fMask&0x01 != 0 { // SIF_RANGE
				ctx.Mem.Write32(psi+8, 0)  // nMin
				ctx.Mem.Write32(psi+12, 0) // nMax
			}
			if fMask&0x02 != 0 { // SIF_PAGE
				ctx.Mem.Write32(psi+16, 0) // nPage
			}
			if fMask&0x04 != 0 { // SIF_POS
				ctx.Mem.Write32(psi+20, 0) // nPos
			}
			if fMask&0x10 != 0 { // SIF_TRACKPOS
				ctx.Mem.Write32(psi+24, 0) // nTrackPos
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
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
		// ReactOS: FlatSB_GetScrollRange - returns min=0, max=0 as default
		pMinPos := ctx.Arg(2)
		pMaxPos := ctx.Arg(3)
		if pMinPos != 0 {
			ctx.Mem.Write32(pMinPos, 0)
		}
		if pMaxPos != 0 {
			ctx.Mem.Write32(pMaxPos, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
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
		ctx.SetReturn(1)
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
		if prc != 0 {
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.Mem.Write32(prc, 0)
				ctx.Mem.Write32(prc+4, 0)
				ctx.Mem.Write32(prc+8, uint32(cs.w))
				ctx.Mem.Write32(prc+12, uint32(cs.h))
			}
		}
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
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "MenuHelp", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ShowHideMenuCtl", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "RegisterClassNameW", func(ctx *ntapi.TrapContext) uint32 {
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
		ctx.SetReturn(0)
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
}
