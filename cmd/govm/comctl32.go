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
	wlWindow := hctx.WlWindow

	comctl32, ok := hctx.SynthByName["comctl32.dll"]
	if !ok {
		return
	}
	_ = comctl32

	d.RegisterAutoStubHandler(comctl32, "InitCommonControls", func(ctx *ntapi.TrapContext) uint32 {
		return 0 // void function
	})
	d.RegisterAutoStubHandler(comctl32, "InitCommonControlsEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
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
		if wlWindow != nil {
			defW, defH = wlWindow.Width, wlWindow.Height
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

	// ImageList_Create: return a fake handle
	var nextImageList uint64 = 0x90000
	imageListCount := map[uint64]uint64{} // handle → count
	d.RegisterAutoStubHandler(comctl32, "ImageList_Create", func(ctx *ntapi.TrapContext) uint32 {
		nextImageList++
		imageListCount[nextImageList] = 0
		ctx.SetReturn(nextImageList)
		return 0
	})

	// ImageList_AddIcon / ImageList_ReplaceIcon
	d.RegisterAutoStubHandler(comctl32, "ImageList_ReplaceIcon", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		idx := imageListCount[himl]
		imageListCount[himl]++
		ctx.SetReturn(idx)
		return 0
	})

	// ImageList_SetImageCount
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetImageCount", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	// ImageList_GetImageCount
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageCount", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		count := imageListCount[himl]
		ctx.SetReturn(count)
		return 0
	})

	// ImageList_Destroy
	d.RegisterAutoStubHandler(comctl32, "ImageList_Destroy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	// ImageList_AddMasked - adds bitmap with mask colour; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_AddMasked", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		idx := imageListCount[himl]
		imageListCount[himl]++
		ctx.SetReturn(idx)
		return 0
	})

	// ImageList_Add - adds bitmap without mask; return index
	d.RegisterAutoStubHandler(comctl32, "ImageList_Add", func(ctx *ntapi.TrapContext) uint32 {
		himl := ctx.Arg(0)
		idx := imageListCount[himl]
		imageListCount[himl]++
		ctx.SetReturn(idx)
		return 0
	})

	// ImageList_Remove - remove image at index (-1 = all)
	d.RegisterAutoStubHandler(comctl32, "ImageList_Remove", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	// ImageList_SetIconSize - set icon size for image list
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetIconSize", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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

	// ImageList_GetIconSize - return icon dimensions
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetIconSize", func(ctx *ntapi.TrapContext) uint32 {
		pCx := ctx.Arg(1)
		pCy := ctx.Arg(2)
		if pCx != 0 {
			ctx.Mem.Write32(pCx, 16)
		}
		if pCy != 0 {
			ctx.Mem.Write32(pCy, 16)
		}
		ctx.SetReturn(1)
		return 0
	})

	// ImageList_SetBkColor
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xFFFFFFFF) // CLR_NONE
		return 0
	})

	// ImageList_Copy
	d.RegisterAutoStubHandler(comctl32, "ImageList_Copy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
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
	d.RegisterAutoStubHandler(comctl32, "ImageList_SetBkColor", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		clr := uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(comctl32pkg.ImageListSetBkColor(h, clr)))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "ImageList_GetImageInfo", func(ctx *ntapi.TrapContext) uint32 {
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
		ctx.SetReturn(0)
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
		// We can't call guest subclass procs without a full call-chain,
		// so fall through to DefWindowProcW (return 0 is safe for most messages)
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
		// DSA_GetItem(hdsa, index, pDest) - copies into pDest; stub returns 1
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_GetItemPtr", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "DSA_SetItem", func(ctx *ntapi.TrapContext) uint32 {
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
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "PropertySheetA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "PropertySheetW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(int64(comctl32pkg.PropertySheet(""))))
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
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollProp", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
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
		ctx.SetReturn(1)
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
		ctx.SetReturn(hwndAlloc()) // fake toolbar HWND
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateToolbarEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hwndAlloc()) // fake toolbar HWND
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateUpDownControl", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hwndAlloc()) // fake updown HWND
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateStatusWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hwndAlloc()) // fake status HWND
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "CreateStatusWindowA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hwndAlloc()) // fake status HWND
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
		ctx.SetReturn(0x0409)
		return 0 // en-US
	})
	d.RegisterAutoStubHandler(comctl32, "InitMUILanguage", func(ctx *ntapi.TrapContext) uint32 {
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
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_EnableScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - FlatSB not supported
		return 0
	})
	d.RegisterAutoStubHandler(comctl32, "FlatSB_ShowScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
}
