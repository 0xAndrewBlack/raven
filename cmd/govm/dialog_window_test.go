//go:build guest_windows

package main

import (
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/wl"
)

func TestOwnedControlPaintSnapshotRestoresDialogSurface(t *testing.T) {
	win := wl.NewHeadlessWindow("dialog", 20, 20, 0)
	root := &controlState{x: 10, y: 10}
	control := &controlState{x: 12, y: 13, w: 4, h: 5}
	win.DrawRectAbs(2, 3, 6, 8, 0x000000)
	captureOwnedControlPaint(control, root, win)
	win.DrawRectAbs(0, 0, 20, 20, 0xFFFFFF)
	restoreOwnedControlPaint(control, root, win)

	if got := dialogPixel(win, 2, 3); got != 0x000000 {
		t.Fatalf("restored control pixel = %#06x, want black", got)
	}
	if got := dialogPixel(win, 1, 3); got != 0xFFFFFF {
		t.Fatalf("pixel outside restored control = %#06x, want white", got)
	}
}

func TestOwnedControlPaintSnapshotConcurrentAccess(t *testing.T) {
	win := wl.NewHeadlessWindow("dialog", 20, 20, 0)
	root := &controlState{}
	control := &controlState{x: 2, y: 3, w: 4, h: 5}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				captureOwnedControlPaint(control, root, win)
				restoreOwnedControlPaint(control, root, win)
			}
		}()
	}
	workers.Wait()
}

func TestOwnedControlPaintSnapshotRejectsChangedGeometry(t *testing.T) {
	win := wl.NewHeadlessWindow("dialog", 20, 20, 0)
	root := &controlState{}
	control := &controlState{x: 2, y: 3, w: 4, h: 5}
	win.DrawRectAbs(2, 3, 6, 8, 0x000000)
	captureOwnedControlPaint(control, root, win)
	win.DrawRectAbs(0, 0, 20, 20, 0xFFFFFF)

	control.mutateGeometry(func(geometry *controlGeometry) {
		geometry.x = 8
	})
	restoreOwnedControlPaint(control, root, win)

	if got := dialogPixel(win, 2, 3); got != 0xFFFFFF {
		t.Fatalf("stale control pixel restored after move: %#06x", got)
	}
}

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

	renderOwnedDialog(hctx, root, nil, win)

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

	renderOwnedDialog(hctx, root, nil, win)

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

	renderOwnedDialog(hctx, root, nil, win)

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
	hctx := &HandlerCtx{
		HwndChildren: map[uint64]*controlState{
			root: {className: "dialog", w: 220, h: 120, visible: true},
			0x51001: {
				className: "Edit", parentHWND: root, x: 20, y: 40,
				w: 100, h: 24, visible: true,
			},
			0x51002: {
				className: "systabcontrol32", parentHWND: root, x: 0, y: 0,
				w: 220, h: 120, visible: true, tabTitles: []string{"Find"},
			},
		},
		HwndZOrder: []uint64{0x51001, 0x51002},
	}
	win := wl.NewHeadlessWindow("Find", 220, 120, 0)

	renderOwnedDialog(hctx, root, nil, win)

	if got := dialogPixel(win, 20, 40); got != 0x7A7A7A {
		t.Fatalf("edit border above tab = 0x%06x, want 0x7A7A7A", got)
	}
}

func TestRenderOwnedDialogPreservesLightTabColors(t *testing.T) {
	resetDarkModeState()
	t.Cleanup(resetDarkModeState)
	const root = uint64(0x51100)
	tab := &controlState{
		className: "SysTabControl32", parentHWND: root, x: 10, y: 10,
		w: 200, h: 80, visible: true, tabTitles: []string{"General", "Advanced"}, tabCurSel: 0,
	}
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root:    {className: "dialog", w: 220, h: 100, visible: true},
		0x51101: tab,
	}}
	win := wl.NewHeadlessWindow("Preferences", 220, 100, 0)

	renderOwnedDialog(hctx, root, nil, win)

	firstWidth, _ := newDialogTextPainter(win).measure("General")
	if got := dialogPixel(win, 15, 15); got != 0xF0F0F0 {
		t.Fatalf("selected tab background = 0x%06x, want 0xF0F0F0", got)
	}
	if got := dialogPixel(win, 10+firstWidth+25, 15); got != 0xE1E1E1 {
		t.Fatalf("inactive tab background = 0x%06x, want 0xE1E1E1", got)
	}
	if got := dialogPixel(win, 15, 40); got != 0xF0F0F0 {
		t.Fatalf("tab page background = 0x%06x, want 0xF0F0F0", got)
	}
}

func TestRenderOwnedDialogDarkTabTreeAndListView(t *testing.T) {
	resetDarkModeState()
	t.Cleanup(resetDarkModeState)
	const root = uint64(0x51200)
	setWindowThemeSelection(root, windowThemeSelection{SubAppName: "DarkMode_Explorer"})

	treeRoot := &tvItem{expanded: true}
	treeParent := &tvItem{text: "General", handle: 1, expanded: true, parent: treeRoot}
	treeChild := &tvItem{text: "Dark Mode", handle: 2, parent: treeParent}
	treeParent.children = []*tvItem{treeChild}
	treeRoot.children = []*tvItem{treeParent}
	tree := &treeViewState{root: treeRoot, selected: treeChild}
	list := &listViewState{
		columns: []lvColumn{{text: "Setting", width: 100}, {text: "Value", width: 90}},
		items: []lvItem{
			{text: "Theme", subItems: []string{"Dark", "Ignored"}},
			{text: "Toolbar", subItems: []string{"Visible"}, state: 0x0002},
		},
		selectedIdx: 1,
	}
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root: {className: "dialog", w: 440, h: 250, visible: true},
		0x51201: {
			className: "SysTabControl32", parentHWND: root, x: 10, y: 10,
			w: 420, h: 70, visible: true, tabTitles: []string{"General", "Advanced"}, tabCurSel: 0,
		},
		0x51202: {
			className: "SysTreeView32", parentHWND: root, x: 10, y: 90,
			w: 180, h: 140, visible: true, treeView: tree,
		},
		0x51203: {
			className: "SysListView32", parentHWND: root, x: 200, y: 90,
			w: 230, h: 140, visible: true, listView: list,
		},
	}}
	treeControl := hctx.HwndChildren[0x51202]
	treeControl.guestPainted = true
	treeControl.guestPaintX = 10
	treeControl.guestPaintY = 90
	treeControl.guestPaintW = treeControl.w
	treeControl.guestPaintH = treeControl.h
	treeControl.guestPaintPixels = make([]byte, int(treeControl.w*treeControl.h*4))
	for index := range treeControl.guestPaintPixels {
		treeControl.guestPaintPixels[index] = 0xFF
	}
	hctx.HwndWndProc = map[uint64]uint64{0x51202: 0x140001000}
	win := wl.NewHeadlessWindow("Preferences", 440, 250, 0)

	renderOwnedDialog(hctx, root, nil, win)

	if got := dialogPixel(win, 15, 50); got != darkPalette.Control {
		t.Fatalf("dark tab page = 0x%06x, want 0x%06x", got, darkPalette.Control)
	}
	if got := dialogPixel(win, 15, 150); got != darkPalette.Background {
		t.Fatalf("dark tree background = 0x%06x, want 0x%06x", got, darkPalette.Background)
	}
	if got := dialogPixel(win, 180, 120); got != darkPalette.Highlight {
		t.Fatalf("dark tree selection = 0x%06x, want 0x%06x", got, darkPalette.Highlight)
	}
	if got := dialogPixel(win, 420, 100); got != darkPalette.Input {
		t.Fatalf("dark list header = 0x%06x, want 0x%06x", got, darkPalette.Input)
	}
	if got := dialogPixel(win, 420, 140); got != darkPalette.Highlight {
		t.Fatalf("dark list selection = 0x%06x, want 0x%06x", got, darkPalette.Highlight)
	}
	if dialogInkWidth(win, 206, 115, 260, 131, darkPalette.Background) == 0 {
		t.Fatal("dark list text was not rendered")
	}
	if !dialogRegionHasUnquantizedGray(win, 30, 93, 90, 108) {
		t.Fatal("dark tree text lost antialias coverage")
	}
	if dialogInkWidth(win, 310, 115, 350, 131, darkPalette.Background) == 0 {
		t.Fatal("dark list subitem was not rendered")
	}
	if dialogInkWidth(win, 400, 115, 425, 131, darkPalette.Background) != 0 {
		t.Fatal("list subitem without a matching column was rendered")
	}
}

func TestRenderOwnedDialogDarkListBoxOverridesGuestCache(t *testing.T) {
	resetDarkModeState()
	t.Cleanup(resetDarkModeState)
	const (
		root    = uint64(0x51300)
		listBox = uint64(0x51301)
		button  = uint64(0x51302)
		swatch  = uint64(0x51303)
	)
	setWindowThemeSelection(root, windowThemeSelection{SubAppName: "DarkMode_Explorer"})
	control := &controlState{
		className: "ListBox", parentHWND: root, x: 10, y: 10,
		w: 180, h: 80, visible: true,
		listItems:  []string{"General", "Dark Mode"},
		listCurSel: 1,
	}
	control.guestPainted = true
	control.guestPaintX = 10
	control.guestPaintY = 10
	control.guestPaintW = control.w
	control.guestPaintH = control.h
	control.guestPaintPixels = make([]byte, int(control.w*control.h*4))
	for index := range control.guestPaintPixels {
		control.guestPaintPixels[index] = 0xFF
	}
	buttonControl := &controlState{
		className: "Button", parentHWND: root, x: 210, y: 10,
		w: 100, h: 30, visible: true, text: "Close", ctrlID: 1,
		guestPainted: true, guestPaintX: 210, guestPaintY: 10,
		guestPaintW: 100, guestPaintH: 30,
		guestPaintPixels: make([]byte, 100*30*4),
	}
	for index := range buttonControl.guestPaintPixels {
		buttonControl.guestPaintPixels[index] = 0xFF
	}
	swatchPixels := make([]byte, 25*25*4)
	for offset := 0; offset < len(swatchPixels); offset += 4 {
		swatchPixels[offset] = 0xFF
		swatchPixels[offset+2] = 0xFF
		swatchPixels[offset+3] = 0xFF
	}
	swatchControl := &controlState{
		className: "Button", parentHWND: root, x: 210, y: 50,
		w: 25, h: 25, visible: true,
		guestPainted: true, guestPaintX: 210, guestPaintY: 50,
		guestPaintW: 25, guestPaintH: 25, guestPaintPixels: swatchPixels,
	}
	hctx := &HandlerCtx{
		HwndChildren: map[uint64]*controlState{
			root:    {className: "dialog", w: 330, h: 100, visible: true},
			listBox: control,
			button:  buttonControl,
			swatch:  swatchControl,
		},
		HwndWndProc: map[uint64]uint64{
			listBox: 0x140001000,
			button:  0x140001100,
			swatch:  0x140001200,
		},
	}
	win := wl.NewHeadlessWindow("Preferences", 330, 100, 0)

	renderOwnedDialog(hctx, root, nil, win)

	if got := dialogPixel(win, 180, 20); got != darkPalette.Background {
		t.Fatalf("dark list box background = 0x%06x, want 0x%06x", got, darkPalette.Background)
	}
	if got := dialogPixel(win, 180, 36); got != darkPalette.Highlight {
		t.Fatalf("dark list box selection = 0x%06x, want 0x%06x", got, darkPalette.Highlight)
	}
	if got := dialogPixel(win, 215, 20); got != darkPalette.Control {
		t.Fatalf("dark button background = 0x%06x, want 0x%06x", got, darkPalette.Control)
	}
	if got := dialogPixel(win, 220, 60); got != 0xFF00FF {
		t.Fatalf("custom swatch = 0x%06x, want 0xFF00FF", got)
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

	renderOwnedDialog(hctx, root, nil, win)

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

	renderOwnedDialog(hctx, root, nil, win)

	if hctx.PrintDialog.PrintBtnW <= 0 || hctx.PrintDialog.CancelBtnW <= 0 || hctx.PrintDialog.CopiesPlusX <= 0 || hctx.PrintDialog.ToPlusX <= 0 {
		t.Fatal("print dialog hit targets were not initialized")
	}
	if got := dialogPixel(win, 20, 44); got != 0xA0A0A0 {
		t.Fatalf("printer group border = 0x%06x, want 0xA0A0A0", got)
	}
}

func TestRepaintHostManagedPrintDialogUpdatesInteractiveState(t *testing.T) {
	const root = uint64(0x51900)
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
	renderOwnedDialog(hctx, root, nil, win)
	allChecked := dialogPixel(win, 46, 182)
	pagesUnchecked := dialogPixel(win, 46, 210)
	oneCopy := dialogPixel(win, 151, 292)

	hctx.PrintDialog.AllPages = false
	hctx.PrintDialog.Copies = 2
	if !repaintHostManagedDialog(hctx, root, nil, win) {
		t.Fatal("host-managed print dialog repaint was not handled")
	}

	if got := dialogPixel(win, 46, 182); got == allChecked {
		t.Fatalf("All radio pixel did not change: 0x%06x", got)
	}
	if got := dialogPixel(win, 46, 210); got == pagesUnchecked {
		t.Fatalf("Pages radio pixel did not change: 0x%06x", got)
	}
	if got := dialogPixel(win, 151, 292); got == oneCopy {
		t.Fatalf("copies text pixel did not change: 0x%06x", got)
	}
}

func TestRepaintHostManagedPrintDialogQueuesWhileRendering(t *testing.T) {
	const root = uint64(0x51910)
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
	renderOwnedDialog(hctx, root, nil, win)
	oneCopy := dialogPixel(win, 151, 292)

	state, acquired := hctx.beginDialogRender(root)
	if !acquired {
		t.Fatal("initial print dialog render was not acquired")
	}
	hctx.PrintDialog.Copies = 2
	if !repaintHostManagedDialog(hctx, root, nil, win) {
		t.Fatal("host-managed print dialog repaint was not handled")
	}
	if !state.finishPass() {
		t.Fatal("repaint requested during rendering was not queued")
	}
	renderOwnedDialogPass(hctx, root, nil, win)
	if state.finishPass() {
		t.Fatal("queued repaint state was not drained")
	}
	if got := dialogPixel(win, 151, 292); got == oneCopy {
		t.Fatalf("queued copies repaint did not change: 0x%06x", got)
	}
}

func TestDialogRenderStateSeparatesDialogsAndConcurrentRequests(t *testing.T) {
	hctx := &HandlerCtx{}
	first, acquired := hctx.beginDialogRender(0x51920)
	if !acquired {
		t.Fatal("first dialog render was not acquired")
	}
	second, acquired := hctx.beginDialogRender(0x51921)
	if !acquired {
		t.Fatal("second dialog render was blocked by first dialog")
	}

	const requests = 32
	var workers sync.WaitGroup
	for index := 0; index < requests; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			state, got := hctx.beginDialogRender(0x51920)
			if got || state != first {
				t.Errorf("concurrent request acquired active dialog: acquired=%t state=%p", got, state)
			}
		}()
	}
	workers.Wait()
	if !first.finishPass() {
		t.Fatal("concurrent repaint requests were lost")
	}
	if first.finishPass() {
		t.Fatal("pending repaint was not drained in one pass")
	}
	if second.finishPass() {
		t.Fatal("independent dialog gained a spurious pending repaint")
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

	renderOwnedDialog(hctx, root, nil, win)

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

func dialogRegionHasUnquantizedGray(win *wl.Window, left, top, right, bottom int32) bool {
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			color := dialogPixel(win, x, y)
			switch color {
			case darkPalette.Background, darkPalette.Control, darkPalette.Input,
				darkPalette.Border, darkPalette.Text, darkPalette.SecondaryText,
				darkPalette.DisabledText, darkPalette.Highlight, darkPalette.HighlightText:
				continue
			}
			r := color >> 16 & 0xFF
			g := color >> 8 & 0xFF
			b := color & 0xFF
			if r == g && g == b {
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
