//go:build guest_windows

package main

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

func TestWindowCleanupClearsSubclassAndDarkStatePE32AndPE64(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(map[bool]string{true: "PE32", false: "PE64"}[is32], func(t *testing.T) {
			resetDarkModeState()
			hwnd := uint64(0x7A000)
			cleared := uint64(0)
			hctx := &HandlerCtx{
				ProcState:            &ntapi.ProcessState{Is32: is32},
				HwndChildren:         map[uint64]*controlState{hwnd: {className: "static"}},
				HwndWndProc:          map[uint64]uint64{hwnd: 0x1234},
				HwndTitle:            map[uint64]string{hwnd: "cleanup"},
				HwndExplicitlyHidden: map[uint64]bool{hwnd: true},
				WindowLongPtr:        map[uint64]map[int32]uint64{hwnd: {-16: 1}},
				HwndClassAtom:        map[uint64]uint16{hwnd: 4},
				WindowProps:          map[uint64]map[string]uint64{hwnd: {"prop": 1}},
				WinErasePending:      map[uint64]bool{hwnd: true},
				WinInvalid:           map[uint64]bool{hwnd: true},
				ClearSubclasses:      func(got uint64) { cleared = got },
				ReleaseDialogPaintDC: func(uint64) {},
				RequestWindowRepaint: func(uint64) {},
				HwndMenuBar:          map[uint64]uint64{},
				WindowCPU:            nil,
			}
			if !allowDarkModeForWindow(hwnd, true) || !setImmersiveDarkModeForWindow(hwnd, true) {
				t.Fatal("failed to establish dark window state")
			}

			cleanupHandlerWindowState(hctx, hwnd)

			if cleared != hwnd {
				t.Fatalf("subclass cleanup hwnd = %#x", cleared)
			}
			if hctx.HwndChildren[hwnd] != nil || hctx.HwndWndProc[hwnd] != 0 ||
				hctx.HwndTitle[hwnd] != "" || hctx.WinInvalid[hwnd] {
				t.Fatal("window state survived cleanup")
			}
			if darkModeAllowedForWindow(hwnd) {
				t.Fatal("dark window state survived cleanup")
			}
			if _, ok := immersiveDarkModeForWindow(hwnd); ok {
				t.Fatal("DWM dark state survived cleanup")
			}
		})
	}
}

func TestDestroyPrunesRootAndDescendantMessages(t *testing.T) {
	const (
		root  = uint64(0x79000)
		child = uint64(0x79001)
		other = uint64(0x79002)
	)
	children := map[uint64]*controlState{
		root:  {className: "dialog"},
		child: {className: "button", parentHWND: root},
		other: {className: "static"},
	}
	queue := &messageQueue{items: []queuedMsg{
		{hwnd: root, message: 0x000F},
		{hwnd: child, message: 0x0014},
		{hwnd: child, message: 0x000F},
		{hwnd: other, message: 0x0113},
	}}

	pruneDestroyedWindowMessages(queue, root, children)

	if len(queue.items) != 1 || queue.items[0].hwnd != other || queue.items[0].message != 0x0113 {
		t.Fatalf("remaining messages = %+v", queue.items)
	}
}

func TestDestroyPendingCoversDescendants(t *testing.T) {
	const (
		root       = uint64(0x79100)
		child      = uint64(0x79101)
		grandchild = uint64(0x79102)
		other      = uint64(0x79103)
	)
	children := map[uint64]*controlState{
		root:       {className: "dialog"},
		child:      {className: "dialog", parentHWND: root},
		grandchild: {className: "button", parentHWND: child},
		other:      {className: "static"},
	}
	pending := map[uint64]bool{root: true}
	if !windowOrAncestorDestroyPending(root, pending, children) {
		t.Fatal("destroying root was not pending")
	}
	if !windowOrAncestorDestroyPending(grandchild, pending, children) {
		t.Fatal("destroying ancestor did not cover descendant")
	}
	if windowOrAncestorDestroyPending(other, pending, children) {
		t.Fatal("unrelated window inherited destroy state")
	}
}

func TestSurfaceResizeSchedulesRepaint(t *testing.T) {
	for _, test := range []struct {
		name        string
		mainWindow  bool
		wantBuiltin bool
	}{
		{name: "main window", mainWindow: true, wantBuiltin: true},
		{name: "owned window", mainWindow: false, wantBuiltin: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			const hwnd = uint64(0x79200)
			hctx := &HandlerCtx{}
			var queued uint64

			repaintAfterSurfaceResize(hctx, hwnd, test.mainWindow, func(got uint64) {
				queued = got
			})

			if hctx.RepaintBuiltin != test.wantBuiltin {
				t.Fatalf("builtin recomposition = %v, want %v", hctx.RepaintBuiltin, test.wantBuiltin)
			}
			if queued != hwnd {
				t.Fatalf("queued paint hwnd = %#x, want %#x", queued, hwnd)
			}
		})
	}
}

func TestChildPaintCommitRecomposesBuiltinControls(t *testing.T) {
	const (
		mainHWND  = uint64(0x79210)
		childHWND = uint64(0x79211)
	)
	hctx := &HandlerCtx{MainHWND: mainHWND, HasBaseFrame: true}

	prepareMainSurfacePaintCommit(hctx, childHWND)

	if !hctx.FrameReady {
		t.Fatal("child paint did not mark the frame ready")
	}
	if !hctx.RepaintBuiltin {
		t.Fatal("child paint did not request builtin control recomposition")
	}

	hctx.FrameReady = false
	hctx.RepaintBuiltin = false
	prepareMainSurfacePaintCommit(hctx, mainHWND)
	if !hctx.FrameReady {
		t.Fatal("main paint did not mark the frame ready")
	}
	if hctx.RepaintBuiltin {
		t.Fatal("main paint requested redundant builtin recomposition")
	}
}

func TestWindowHierarchyVisibility(t *testing.T) {
	const (
		root  = uint64(0x79200)
		child = uint64(0x79201)
	)
	children := map[uint64]*controlState{
		root:  {className: "dialog", visible: true},
		child: {className: "button", parentHWND: root, visible: true},
	}
	if !windowHierarchyVisible(child, children) {
		t.Fatal("visible hierarchy was rejected")
	}
	children[root].visible = false
	if windowHierarchyVisible(child, children) {
		t.Fatal("hidden ancestor did not hide descendant")
	}
	if !windowHierarchyVisible(0x7FFFF, children) {
		t.Fatal("untracked top-level window was treated as hidden")
	}
}

func TestChildScrollbarGeometry(t *testing.T) {
	state := &controlState{
		x: 2, y: 72, w: 1096, h: 581,
		style: win32.WS_VSCROLL | win32.WS_HSCROLL,
	}
	vertical, horizontal, corner, hasVertical, hasHorizontal := childScrollbarRects(state)
	if !hasVertical || !hasHorizontal {
		t.Fatal("scrollbar styles were not detected")
	}
	if vertical != (win32.Rect{Left: 1081, Top: 72, Right: 1098, Bottom: 636}) {
		t.Fatalf("vertical scrollbar = %+v", vertical)
	}
	if horizontal != (win32.Rect{Left: 2, Top: 636, Right: 1081, Bottom: 653}) {
		t.Fatalf("horizontal scrollbar = %+v", horizontal)
	}
	if corner != (win32.Rect{Left: 1081, Top: 636, Right: 1098, Bottom: 653}) {
		t.Fatalf("scrollbar corner = %+v", corner)
	}
}

func TestOwnedStatusBarUsesDialogGeometry(t *testing.T) {
	root := &controlState{x: 159, y: 182, w: 782, h: 394}
	status := &controlState{
		className: "msctls_statusbar32",
		x:         159,
		y:         862,
		w:         1100,
		h:         20,
	}
	if !normalizeOwnedStatusBar(status, root, 782, 394) {
		t.Fatal("owned status bar was not recognized")
	}
	if status.x != 159 || status.y != 556 || status.w != 782 || status.h != 20 {
		t.Fatalf("owned status geometry = (%d,%d %dx%d)", status.x, status.y, status.w, status.h)
	}
	if normalizeOwnedStatusBar(&controlState{className: "button"}, root, 782, 394) {
		t.Fatal("non-status control was normalized")
	}
}

func TestOwnedDialogCustomPaintPrimesOncePerLayout(t *testing.T) {
	const (
		root  = uint64(0x7B000)
		child = uint64(0x7B001)
	)
	hctx := &HandlerCtx{
		HwndChildren: map[uint64]*controlState{
			root:  {className: "dialog", visible: true},
			child: {className: "systabcontrol32", parentHWND: root, visible: true, w: 300, h: 200},
		},
		HwndWndProc:        map[uint64]uint64{child: 0x1234},
		RenderDialogCustom: func(uint64, *wl.Window) {},
	}
	clearOwnedDialogColor(root)
	t.Cleanup(func() { clearOwnedDialogColor(root) })

	if !shouldPrimeOwnedDialogCustomPaint(hctx, root) {
		t.Fatal("initial custom paint was not primed")
	}
	if shouldPrimeOwnedDialogCustomPaint(hctx, root) {
		t.Fatal("unchanged custom layout was primed again")
	}
	hctx.HwndChildren[child].w++
	if !shouldPrimeOwnedDialogCustomPaint(hctx, root) {
		t.Fatal("changed custom layout did not re-prime")
	}
	clearOwnedDialogColor(root)
	if !shouldPrimeOwnedDialogCustomPaint(hctx, root) {
		t.Fatal("dialog lifecycle reset did not re-prime")
	}
}

func TestOwnedDialogVisibilityRejectsHiddenPageDescendants(t *testing.T) {
	const (
		root        = uint64(0x7C000)
		activePage  = uint64(0x7C001)
		hiddenPage  = uint64(0x7C002)
		activeChild = uint64(0x7C003)
		hiddenChild = uint64(0x7C004)
	)
	hctx := &HandlerCtx{HwndChildren: map[uint64]*controlState{
		root:        {className: "dialog", visible: true},
		activePage:  {className: "dialog", parentHWND: root, visible: true},
		hiddenPage:  {className: "dialog", parentHWND: root, visible: false},
		activeChild: {className: "static", parentHWND: activePage, visible: true},
		hiddenChild: {className: "edit", parentHWND: hiddenPage, visible: true},
	}}

	if !visibleOwnedDialogDescendant(hctx, activeChild, root) {
		t.Fatal("visible active-page child was rejected")
	}
	if visibleOwnedDialogDescendant(hctx, hiddenChild, root) {
		t.Fatal("visible child of a hidden page was accepted")
	}
	if visibleOwnedDialogDescendant(hctx, root, root) {
		t.Fatal("dialog root was accepted as its own descendant")
	}
}

func TestDarkNotificationLayoutsPE32AndPE64(t *testing.T) {
	tests := []struct {
		name     string
		is32     bool
		custom   customDrawLayout
		menu     uahMenuLayout
		drawItem uahDrawItemLayout
	}{
		{
			name: "PE32", is32: true,
			custom:   customDrawLayout{headerSize: 12, drawStage: 12, hdc: 16, rect: 20, itemSpec: 36, itemState: 40, itemParam: 44, structureSize: 48},
			menu:     uahMenuLayout{hdc: 4, size: 12},
			drawItem: uahDrawItemLayout{hwndItem: 20, hdc: 24, rect: 28, itemData: 44, size: 48},
		},
		{
			name:     "PE64",
			custom:   customDrawLayout{headerSize: 24, drawStage: 24, hdc: 32, rect: 40, itemSpec: 56, itemState: 64, itemParam: 72, structureSize: 80},
			menu:     uahMenuLayout{hdc: 8, size: 24},
			drawItem: uahDrawItemLayout{hwndItem: 24, hdc: 32, rect: 40, itemData: 56, size: 64},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := customDrawOffsets(test.is32); got != test.custom {
				t.Fatalf("NMCUSTOMDRAW layout = %+v, want %+v", got, test.custom)
			}
			if got := uahMenuOffsets(test.is32); got != test.menu {
				t.Fatalf("UAHMENU layout = %+v, want %+v", got, test.menu)
			}
			if got := uahDrawItemOffsets(test.is32); got != test.drawItem {
				t.Fatalf("UAH draw item layout = %+v, want %+v", got, test.drawItem)
			}
		})
	}
}

func TestUAHMenuStructuresPE32AndPE64(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(map[bool]string{true: "PE32", false: "PE64"}[is32], func(t *testing.T) {
			mem := mmu.New()
			mem.MapPage(0x1000, mmu.PermRead|mmu.PermWrite)
			mem.MapPage(0x2000, mmu.PermRead|mmu.PermWrite)
			hctx := &HandlerCtx{Mem: mem, ProcState: &ntapi.ProcessState{Is32: is32}}
			readPtr := func(addr uint64) uint64 {
				if is32 {
					value, _ := mem.Read32(addr)
					return uint64(value)
				}
				value, _ := mem.Read64(addr)
				return value
			}
			writeUAHMenuStruct(hctx, 0x1000, 0x11223344, 0x55667788)
			menuLayout := uahMenuOffsets(is32)
			if got := readPtr(0x1000); got != 0x11223344 {
				t.Fatalf("menu handle = %#x", got)
			}
			if got := readPtr(0x1000 + menuLayout.hdc); got != 0x55667788 {
				t.Fatalf("menu DC = %#x", got)
			}

			item := &menuItem{id: 42, flags: 7, itemData: 0x1234}
			writeUAHDrawItemStruct(hctx, 0x2000, 0x77, 0x88, item, 3, 4, 5, 60, 70)
			layout := uahDrawItemOffsets(is32)
			if got, _ := mem.Read32(0x2004); got != 42 {
				t.Fatalf("item ID = %d", got)
			}
			if got := readPtr(0x2000 + layout.hdc); got != 0x88 {
				t.Fatalf("item DC = %#x", got)
			}
			if got, _ := mem.Read32(0x2000 + layout.rect + 12); got != 70 {
				t.Fatalf("item bottom = %d", got)
			}
		})
	}
}

func TestCustomDrawMessageOrder(t *testing.T) {
	stages := customDrawFollowUpStages(cdrfNotifyItemDraw|cdrfNotifyPostPaint, 2)
	want := []customDrawStage{
		{stage: cddsItem | cddsPrePaint, item: 0},
		{stage: cddsItem | cddsPrePaint, item: 1},
		{stage: cddsPostPaint, item: 0},
	}
	if len(stages) != len(want) {
		t.Fatalf("stages = %+v, want %+v", stages, want)
	}
	for i := range want {
		if stages[i] != want[i] {
			t.Fatalf("stage %d = %+v, want %+v", i, stages[i], want[i])
		}
	}
}

func TestToolbarCustomDrawItemsUseCommandAndButtonRect(t *testing.T) {
	state := &controlState{
		className: "ToolbarWindow32",
		w:         200,
		h:         26,
		toolbar: &toolbarState{buttons: []tbButton{
			{id: 41001, state: 0x04, param: 0x1234},
			{id: 0, state: 0x04, style: 0x01},
			{id: 41002, state: 0x01},
		}},
	}

	items := hostCustomDrawItems(state)
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	if items[0].spec != 41001 || items[0].param != 0x1234 || items[0].rect != [4]int32{2, 2, 26, 24} {
		t.Fatalf("first item = %+v", items[0])
	}
	if items[1].key != 1 || items[1].spec != 0 || items[1].rect != [4]int32{26, 2, 34, 24} {
		t.Fatalf("separator rect = %+v", items[1].rect)
	}
	if items[2].key != 2 || items[2].spec != 41002 || items[2].state&0x000C != 0x000C ||
		items[2].rect != [4]int32{34, 2, 58, 24} {
		t.Fatalf("third item = %+v", items[2])
	}
}

func TestCustomDrawSkippedItemsAreScopedToControl(t *testing.T) {
	state := &controlState{}
	state.setCustomDrawSkipped(map[uint64]struct{}{7: {}, 11: {}})
	if !state.customDrawItemSkipped(7) || !state.customDrawItemSkipped(11) {
		t.Fatal("custom draw item skip was not installed")
	}
	if state.customDrawItemSkipped(8) {
		t.Fatal("custom draw skipped an unrelated item")
	}
	state.setCustomDrawSkipped(nil)
	if state.customDrawItemSkipped(7) {
		t.Fatal("custom draw item skip survived the paint")
	}
}

func TestToolbarCustomDrawStructureSize(t *testing.T) {
	if got := customDrawStructureSize("ToolbarWindow32", true); got != 112 {
		t.Fatalf("PE32 NMTBCUSTOMDRAW size = %d, want 112", got)
	}
	if got := customDrawStructureSize("ToolbarWindow32", false); got != 160 {
		t.Fatalf("PE64 NMTBCUSTOMDRAW size = %d, want 160", got)
	}
	if got := customDrawStructureSize("SysTreeView32", false); got != 80 {
		t.Fatalf("PE64 NMCUSTOMDRAW size = %d, want 80", got)
	}
}

func TestListViewCustomDrawItemsDescribeVisibleRows(t *testing.T) {
	state := &controlState{
		className: "SysListView32",
		w:         320,
		h:         70,
		listView: &listViewState{items: []lvItem{
			{param: 0x111},
			{param: 0x222, state: 0x0002},
			{param: 0x333},
		}},
	}

	items := hostCustomDrawItems(state)
	if len(items) != 2 {
		t.Fatalf("visible items = %d, want 2", len(items))
	}
	if items[0].spec != 0 || items[0].param != 0x111 || items[0].rect != [4]int32{2, 24, 318, 42} {
		t.Fatalf("first item = %+v", items[0])
	}
	if items[1].spec != 1 || items[1].param != 0x222 || items[1].state != 0x0001 ||
		items[1].rect != [4]int32{2, 42, 318, 60} {
		t.Fatalf("selected item = %+v", items[1])
	}
}

func TestTreeViewCustomDrawItemsDescribeExpandedRows(t *testing.T) {
	child := &tvItem{handle: 0x102, param: 0x202}
	first := &tvItem{handle: 0x101, param: 0x201, expanded: true, children: []*tvItem{child}}
	collapsedChild := &tvItem{handle: 0x104, param: 0x204}
	second := &tvItem{handle: 0x103, param: 0x203, children: []*tvItem{collapsedChild}}
	root := &tvItem{children: []*tvItem{first, second}}
	state := &controlState{
		className:     "SysTreeView32",
		w:             240,
		h:             80,
		treeViewIndex: map[uint64]*tvItem{first.handle: first, child.handle: child, second.handle: second},
		treeView: &treeViewState{
			root:     root,
			selected: child,
		},
	}

	items := hostCustomDrawItems(state)
	if len(items) != 3 {
		t.Fatalf("visible items = %d, want 3", len(items))
	}
	if items[0].spec != first.handle || items[0].param != first.param ||
		items[0].rect != [4]int32{2, 2, 238, 20} {
		t.Fatalf("first item = %+v", items[0])
	}
	if items[1].spec != child.handle || items[1].param != child.param || items[1].state != 0x0001 ||
		items[1].rect != [4]int32{2, 20, 238, 38} {
		t.Fatalf("selected child = %+v", items[1])
	}
	if items[2].spec != second.handle || items[2].rect != [4]int32{2, 38, 238, 56} {
		t.Fatalf("collapsed item = %+v", items[2])
	}
}

func TestCtlColorMessageForClass(t *testing.T) {
	tests := map[string]uint32{
		"Edit":               wmCtlColorEdit,
		"SysListView32":      wmCtlColorListBox,
		"Button":             wmCtlColorButton,
		"#32770":             wmCtlColorDialog,
		"SCROLLBAR":          wmCtlColorScrollbar,
		"Static":             wmCtlColorStatic,
		"ToolbarWindow32":    0,
		"RavenCustomControl": 0,
	}
	for className, want := range tests {
		if got := ctlColorMessageForClass(className); got != want {
			t.Fatalf("%s message = %#x, want %#x", className, got, want)
		}
	}
}
