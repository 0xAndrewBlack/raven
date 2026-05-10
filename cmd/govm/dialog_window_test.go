//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/wl"
)

func TestWaylandWindowHWNDResolvesOwnedWindowWithoutMainFallback(t *testing.T) {
	mainWindow := wl.NewHeadlessWindow("main", 320, 200, 0)
	dialogWindow := wl.NewHeadlessWindow("Replace", 260, 140, 0)
	unknownWindow := wl.NewHeadlessWindow("unknown", 100, 80, 0)
	owned := map[*wl.Window]uint64{dialogWindow: 0x5002e}

	if got := waylandWindowHWND(mainWindow, 0x10010, owned, mainWindow); got != 0x10010 {
		t.Fatalf("main HWND = 0x%x", got)
	}
	if got := waylandWindowHWND(mainWindow, 0x10010, owned, dialogWindow); got != 0x5002e {
		t.Fatalf("dialog HWND = 0x%x", got)
	}
	if got := waylandWindowHWND(mainWindow, 0x10010, owned, unknownWindow); got != 0 {
		t.Fatalf("unknown window resolved to HWND 0x%x", got)
	}
	if got := waylandWindowHWND(mainWindow, 0x10010, owned, nil); got != 0 {
		t.Fatalf("nil window resolved to HWND 0x%x", got)
	}
}

func TestDialogCancelControlFindsDirectIDCANCEL(t *testing.T) {
	const dialog = uint64(0x5002e)
	children := map[uint64]*controlState{
		0x50040: {parentHWND: dialog, ctrlID: 1},
		0x50041: {parentHWND: dialog, ctrlID: 2},
		0x50042: {parentHWND: 0x50040, ctrlID: 2},
	}
	if got := dialogCancelControl(children, dialog); got != 0x50041 {
		t.Fatalf("cancel control = %#x, want 0x50041", got)
	}
}

func TestDialogCloseControlFindsNamedCloseButton(t *testing.T) {
	const dialog = uint64(0x5002e)
	children := map[uint64]*controlState{
		0x50031: {parentHWND: dialog, ctrlID: 6002, className: "ListBox"},
		0x50032: {parentHWND: dialog, ctrlID: 6001, className: "Button", text: "&Close"},
	}
	hwnd, id := dialogCloseControl(children, dialog)
	if hwnd != 0x50032 || id != 6001 {
		t.Fatalf("close control = (%#x, %d), want (0x50032, 6001)", hwnd, id)
	}
}

func TestDialogCloseControlPrefersIDCANCEL(t *testing.T) {
	const dialog = uint64(0x5002e)
	children := map[uint64]*controlState{
		0x50031: {parentHWND: dialog, ctrlID: 6001, className: "Button", text: "Close"},
		0x50032: {parentHWND: dialog, ctrlID: 2, className: "Button", text: "Cancel"},
	}
	hwnd, id := dialogCloseControl(children, dialog)
	if hwnd != 0x50032 || id != 2 {
		t.Fatalf("close control = (%#x, %d), want (0x50032, 2)", hwnd, id)
	}
}

func TestDialogCloseControlFallsBackToOK(t *testing.T) {
	const dialog = uint64(0x5002e)
	children := map[uint64]*controlState{
		0x50031: {parentHWND: dialog, ctrlID: 1, className: "Button", text: "OK"},
	}
	hwnd, id := dialogCloseControl(children, dialog)
	if hwnd != 0x50031 || id != 1 {
		t.Fatalf("close control = (%#x, %d), want (0x50031, 1)", hwnd, id)
	}
}

func TestRenderOwnedDialogUsesLocalSurfaceCoordinates(t *testing.T) {
	const root = uint64(0x50001)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root: {
			className: "dialog", x: 400, y: 250, w: 260, h: 140, visible: true,
		},
		0x50002: {
			className: "Static", parentHWND: root, x: 412, y: 266,
			w: 80, h: 20, text: "Find:", visible: true,
		},
		0x50003: {
			className: "Edit", parentHWND: root, x: 462, y: 262,
			w: 120, h: 24, text: "needle", visible: true,
		},
		0x50004: {
			className: "Button", parentHWND: root, x: 586, y: 300,
			w: 62, h: 26, text: "&Find Next", visible: true,
		},
	}}
	win := wl.NewHeadlessWindow("Find", 260, 140, 0)

	renderOwnedDialog(hctx, root, win)

	if got := dialogPixel(win, 0, 0); got != 0xF0F0F0 {
		t.Fatalf("dialog background = 0x%06x, want 0xF0F0F0", got)
	}
	if got := dialogPixel(win, 62, 12); got != 0x7A7A7A {
		t.Fatalf("edit border = 0x%06x, want 0x7A7A7A", got)
	}
	if got := dialogPixel(win, 186, 50); got != 0x7A7A7A {
		t.Fatalf("button border = 0x%06x, want 0x7A7A7A", got)
	}
}

func TestRenderOwnedDialogDrawsSixteenPixelRightAlignedStatic(t *testing.T) {
	const root = uint64(0x50010)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root: {className: "dialog", w: 180, h: 60, visible: true},
		0x50011: {
			className: "Static", parentHWND: root, x: 2, y: 10,
			w: 146, h: 16, style: 2, text: "Find what:", visible: true,
		},
	}}
	win := wl.NewHeadlessWindow("Find in Files", 180, 60, 0)

	renderOwnedDialog(hctx, root, win)

	left := 2 + 146 - int32(len("Find what:")*8) - 2
	if !dialogRegionContainsColor(win, left, 10, 148, 26, 0x000000) {
		t.Fatal("16-pixel SS_RIGHT static text was not rendered")
	}
	if dialogRegionContainsColor(win, 2, 10, left, 26, 0x000000) {
		t.Fatal("SS_RIGHT static text was rendered in the left padding")
	}
}

func TestRenderOwnedDialogUsesVariableWidthGUIFont(t *testing.T) {
	const root = uint64(0x50020)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root:    {className: "dialog", w: 180, h: 70, visible: true},
		0x50021: {className: "Static", parentHWND: root, x: 10, y: 8, w: 150, h: 20, text: "iiii", visible: true},
		0x50022: {className: "Static", parentHWND: root, x: 10, y: 38, w: 150, h: 20, text: "WWWW", visible: true},
	}}
	win := wl.NewHeadlessWindow("Font", 180, 70, 0)

	renderOwnedDialog(hctx, root, win)

	narrowWidth := dialogInkWidth(win, 10, 8, 160, 28, 0xF0F0F0)
	wideWidth := dialogInkWidth(win, 10, 38, 160, 58, 0xF0F0F0)
	if narrowWidth <= 0 || wideWidth <= narrowWidth {
		t.Fatalf("GUI font widths = narrow %d, wide %d", narrowWidth, wideWidth)
	}
}

func TestControlHitHeightUsesClosedComboBoxHeight(t *testing.T) {
	dropdown := &controlState{className: "combobox", style: 2, h: 300}
	if got := controlHitHeight(dropdown); got != 24 {
		t.Fatalf("dropdown hit height = %d, want 24", got)
	}
	dropdown.comboDropped = true
	if got := controlHitHeight(dropdown); got != 24 {
		t.Fatalf("open dropdown header hit height = %d, want 24", got)
	}
	simple := &controlState{className: "combobox", style: 1, h: 300}
	if got := controlHitHeight(simple); got != 300 {
		t.Fatalf("simple combo hit height = %d, want 300", got)
	}
}

func TestRenderOwnedDialogKeepsControlsAboveTabBackground(t *testing.T) {
	const root = uint64(0x51000)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root: {className: "dialog", w: 220, h: 120, visible: true},
		0x51001: {
			className: "Edit", parentHWND: root, x: 20, y: 40,
			w: 100, h: 24, visible: true,
		},
		0x51002: {
			className: "systabcontrol32", parentHWND: root, x: 0, y: 0,
			w: 220, h: 120, visible: true, tabTitles: []string{"Find"},
		},
	}}
	win := wl.NewHeadlessWindow("Find", 220, 120, 0)

	renderOwnedDialog(hctx, root, win)

	if got := dialogPixel(win, 20, 40); got != 0x7A7A7A {
		t.Fatalf("edit border above tab = 0x%06x, want 0x7A7A7A", got)
	}
}

func TestRenderOwnedDialogRendersFindOnItsOwnSurface(t *testing.T) {
	const root = uint64(0x51500)
	hctx := &HandlerCtx{
		HwndChildren: map[uint64]*controlState{
			root: {className: "dialog", w: 380, h: 130, visible: true},
		},
		FindDialog: &FindDialogState{DlgHWND: root, FindText: "needle"},
	}
	win := wl.NewHeadlessWindow("Find", 380, 130, 0)

	renderOwnedDialog(hctx, root, win)

	if got := dialogPixel(win, 84, 8); got != 0x808080 {
		t.Fatalf("find edit border = 0x%06x, want 0x808080", got)
	}
	if hctx.FindDialog.FindEditW <= 0 || hctx.FindDialog.CancelBtnW <= 0 {
		t.Fatal("find dialog hit targets were not initialized")
	}
}

func TestRenderOwnedDialogRendersInteractivePrintControls(t *testing.T) {
	const root = uint64(0x51800)
	hctx := &HandlerCtx{
		HwndChildren: map[uint64]*controlState{
			root: {className: "dialog", w: 520, h: 360, visible: true},
		},
		PrintDialog: &PrintDialogState{
			DlgHWND: root, OutputPath: "document.png", AllPages: true,
			FromPage: 1, ToPage: 1, MinPage: 1, MaxPage: 10,
			AllowPageRange: true, Copies: 1,
		},
	}
	win := wl.NewHeadlessWindow("Print", 520, 360, 0)

	renderOwnedDialog(hctx, root, win)

	if hctx.PrintDialog.PrintBtnW <= 0 || hctx.PrintDialog.CancelBtnW <= 0 || hctx.PrintDialog.CopiesPlusX <= 0 || hctx.PrintDialog.ToPlusX <= 0 {
		t.Fatal("print dialog hit targets were not initialized")
	}
	if got := dialogPixel(win, 20, 44); got != 0xA0A0A0 {
		t.Fatalf("printer group border = 0x%06x, want 0xA0A0A0", got)
	}
}

func TestTopLevelDialogTargetFindsDescendantOwner(t *testing.T) {
	const (
		mainHWND = uint64(0x52000)
		dialog   = uint64(0x52001)
		page     = uint64(0x52002)
		button   = uint64(0x52003)
	)
	win := wl.NewHeadlessWindow("Find", 200, 100, 0)
	hctx := &HandlerCtx{
		MainHWND: mainHWND,
		HwndChildren: map[uint64]*controlState{
			dialog: {className: "dialog", parentHWND: mainHWND},
			page:   {className: "dialog", parentHWND: dialog, style: 0x40000000},
			button: {className: "button", parentHWND: page},
		},
		WlWindows: map[uint64]*wl.Window{dialog: win},
	}

	root, target, ok := topLevelDialogTarget(hctx, button)
	if !ok || root != dialog || target != win {
		t.Fatalf("target = (0x%x, %p, %v), want (0x%x, %p, true)", root, target, ok, dialog, win)
	}
}

func TestRenderOwnedDialogUsesExplicitlyShownChildPage(t *testing.T) {
	const (
		root  = uint64(0x53000)
		page1 = uint64(0x53001)
		page2 = uint64(0x53002)
	)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root:  {className: "dialog", w: 240, h: 140, visible: true},
		page1: {className: "dialog", parentHWND: root, w: 240, h: 140, style: 0x40000000, visible: true, showCalled: true},
		page2: {className: "dialog", parentHWND: root, w: 240, h: 140, style: 0x40000000, visible: true},
		0x53003: {
			className: "Edit", parentHWND: page1, x: 20, y: 30,
			w: 80, h: 20, visible: true,
		},
		0x53004: {
			className: "Edit", parentHWND: page2, x: 120, y: 30,
			w: 80, h: 20, visible: true,
		},
	}}
	win := wl.NewHeadlessWindow("Preferences", 240, 140, 0)

	renderOwnedDialog(hctx, root, win)

	if got := dialogPixel(win, 20, 30); got != 0x7A7A7A {
		t.Fatalf("shown page edit = 0x%06x, want 0x7A7A7A", got)
	}
	if got := dialogPixel(win, 120, 30); got == 0x7A7A7A {
		t.Fatalf("unshown page edit was rendered")
	}
}

func TestListBoxMultiColumnGeometry(t *testing.T) {
	state := &controlState{
		style:           0x0311,
		w:               234,
		h:               158,
		listItems:       make([]string, 40),
		listItemHeight:  27,
		listColumnWidth: 29,
	}
	left, top, right, bottom, ok := listBoxItemRect(state, 17)
	if !ok || left != 87 || top != 54 || right != 116 || bottom != 81 {
		t.Fatalf("item rect = (%d,%d,%d,%d,%v)", left, top, right, bottom, ok)
	}
	index, outside := listBoxItemFromPoint(state, 115, 25)
	if outside || index != 15 {
		t.Fatalf("item from point = (%d,%v), want (15,false)", index, outside)
	}
}

func TestListBoxVariableOwnerDrawGeometry(t *testing.T) {
	state := &controlState{
		style:           0x0020,
		w:               120,
		h:               80,
		listItems:       make([]string, 3),
		listItemHeights: []int32{10, 20, 30},
	}
	left, top, right, bottom, ok := listBoxItemRect(state, 2)
	if !ok || left != 0 || top != 30 || right != 120 || bottom != 60 {
		t.Fatalf("item rect = (%d,%d,%d,%d,%v)", left, top, right, bottom, ok)
	}
	index, outside := listBoxItemFromPoint(state, 40, 25)
	if outside || index != 1 {
		t.Fatalf("item from point = (%d,%v), want (1,false)", index, outside)
	}
}

func TestListBoxItemFromPointReportsOutside(t *testing.T) {
	state := &controlState{w: 100, h: 50, listItems: make([]string, 2)}
	index, outside := listBoxItemFromPoint(state, -1, 5)
	if !outside || index != 0 {
		t.Fatalf("item from point = (%d,%v), want (0,true)", index, outside)
	}
	index, outside = listBoxItemFromPoint(state, 80, 45)
	if outside || index != 1 {
		t.Fatalf("blank client point = (%d,%v), want (1,false)", index, outside)
	}
}

func dialogPixel(win *wl.Window, x, y int32) uint32 {
	off := int(y*win.Stride + x*4)
	return uint32(win.Pix[off+2])<<16 | uint32(win.Pix[off+1])<<8 | uint32(win.Pix[off])
}

func dialogRegionContainsColor(win *wl.Window, left, top, right, bottom int32, color uint32) bool {
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			if dialogPixel(win, x, y) == color {
				return true
			}
		}
	}
	return false
}

func dialogInkWidth(win *wl.Window, left, top, right, bottom int32, background uint32) int32 {
	minX, maxX := right, left-1
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			if dialogPixel(win, x, y) == background {
				continue
			}
			if x < minX {
				minX = x
			}
			if x > maxX {
				maxX = x
			}
		}
	}
	if maxX < minX {
		return 0
	}
	return maxX - minX + 1
}
