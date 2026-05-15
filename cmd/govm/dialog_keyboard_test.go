//go:build guest_windows

package main

import (
	"sync"
	"testing"
)

func TestNextDialogTabItemWrapsAndSkipsUnavailableControls(t *testing.T) {
	const dialog = uint64(0x5000)
	children := map[uint64]*controlState{
		0x5004: {parentHWND: dialog, style: 0x00010000, visible: true},
		0x5001: {parentHWND: dialog, style: 0x00010000, visible: true},
		0x5002: {parentHWND: dialog, style: 0x08010000, visible: true},
		0x5003: {parentHWND: dialog, style: 0x00010000},
		0x6000: {parentHWND: 0x6001, style: 0x00010000, visible: true},
	}
	order := []uint64{0x5004, 0x5002, 0x5001, 0x5003, 0x6000}
	if got := nextDialogTabItem(children, order, dialog, 0, false); got != 0x5004 {
		t.Fatalf("first item = %#x, want 0x5004", got)
	}
	if got := nextDialogTabItem(children, order, dialog, 0x5004, false); got != 0x5001 {
		t.Fatalf("next item = %#x, want 0x5001", got)
	}
	if got := nextDialogTabItem(children, order, dialog, 0x5001, false); got != 0x5004 {
		t.Fatalf("wrapped item = %#x, want 0x5004", got)
	}
	if got := nextDialogTabItem(children, order, dialog, 0x5004, true); got != 0x5001 {
		t.Fatalf("reverse wrapped item = %#x, want 0x5001", got)
	}
}

func TestNextDialogTabItemReturnsZeroWithoutTabStops(t *testing.T) {
	children := map[uint64]*controlState{
		1: {parentHWND: 9, visible: true},
	}
	if got := nextDialogTabItem(children, []uint64{1}, 9, 0, false); got != 0 {
		t.Fatalf("item = %#x, want 0", got)
	}
}

func TestDialogTabItemsTraverseControlParents(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, exStyle: 0x00010000, visible: true},
		12: {parentHWND: 11, style: 0x00010000, visible: true},
		13: {parentHWND: dialog, exStyle: 0x00010000},
		14: {parentHWND: 13, style: 0x00010000, visible: true},
	}
	items := dialogTabItems(children, []uint64{11, 12, 13, 14}, dialog)
	if len(items) != 1 || items[0] != 12 {
		t.Fatalf("items = %v, want [12]", items)
	}
}

func TestWindowBelongsToDialog(t *testing.T) {
	children := map[uint64]*controlState{
		11: {parentHWND: 10},
		12: {parentHWND: 11},
		20: {parentHWND: 21},
	}
	if !windowBelongsToDialog(children, 12, 10) {
		t.Fatal("nested control was not recognized")
	}
	if windowBelongsToDialog(children, 20, 10) {
		t.Fatal("unrelated control was accepted")
	}
}

func TestReorderWindow(t *testing.T) {
	order := []uint64{10, 20, 30}
	order = reorderWindow(order, 30, 10)
	if len(order) != 3 || order[0] != 10 || order[1] != 30 || order[2] != 20 {
		t.Fatalf("order = %v, want [10 30 20]", order)
	}
}

func TestReorderWindowRejectsInvalidInsertAfter(t *testing.T) {
	order := []uint64{10, 20, 30}
	reordered, ok := reorderWindowGrouped(order, 30, 99, nil)
	if ok {
		t.Fatal("invalid insert-after handle was accepted")
	}
	if len(reordered) != 3 || reordered[0] != 10 || reordered[1] != 20 || reordered[2] != 30 {
		t.Fatalf("order changed after invalid insert-after: %v", reordered)
	}
}

func TestReorderWindowNotTopmostStartsNonTopmostGroup(t *testing.T) {
	order := []uint64{10, 20, 30, 40}
	topmost := map[uint64]bool{10: true, 20: true, 30: true}
	reordered, ok := reorderWindowGrouped(order, 30, ^uint64(1), topmost)
	if !ok {
		t.Fatal("HWND_NOTOPMOST was rejected")
	}
	want := []uint64{10, 20, 30, 40}
	for i := range want {
		if reordered[i] != want[i] {
			t.Fatalf("order = %v, want %v", reordered, want)
		}
	}
	if topmost[30] {
		t.Fatal("HWND_NOTOPMOST did not clear topmost state")
	}
}

func TestHandlerCtxZOrderConcurrentSnapshots(t *testing.T) {
	hctx := &HandlerCtx{HwndTopmost: make(map[uint64]bool)}
	for hwnd := uint64(1); hwnd <= 16; hwnd++ {
		hctx.addZOrder(hwnd, false)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for iteration := 0; iteration < 1000; iteration++ {
				hwnd := uint64((iteration+offset)%16 + 1)
				hctx.reorderZOrder(hwnd, 0)
				if got := len(hctx.snapshotZOrder()); got != 16 {
					t.Errorf("snapshot length = %d, want 16", got)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
}

func TestBackToFrontChildWindowsUsesZOrder(t *testing.T) {
	const parent = uint64(1)
	children := map[uint64]*controlState{
		10: {parentHWND: parent},
		20: {parentHWND: parent},
		30: {parentHWND: 2},
	}
	order := []uint64{10, 30, 20}
	got := backToFrontChildWindows(children, order, parent)
	if len(got) != 2 || got[0] != 20 || got[1] != 10 {
		t.Fatalf("paint order = %v, want [20 10]", got)
	}
}

func TestNewChildWindowStartsAtBottomOfSiblingZOrder(t *testing.T) {
	const (
		firstParent  = uint64(1)
		secondParent = uint64(2)
	)
	children := map[uint64]*controlState{
		10: {parentHWND: firstParent},
		20: {parentHWND: secondParent},
		30: {parentHWND: firstParent},
	}
	hctx := &HandlerCtx{HwndTopmost: make(map[uint64]bool)}
	hctx.addZOrder(90, true)
	hctx.addZOrder(10, false)
	hctx.addZOrder(20, false)
	hctx.addZOrder(30, false)

	if !hctx.placeNewChildAtBottom(30) {
		t.Fatal("new child could not be placed at the bottom")
	}

	order := hctx.snapshotZOrder()
	got := orderedChildWindows(children, order, firstParent)
	want := []uint64{10, 30}
	if len(got) != len(want) {
		t.Fatalf("first parent z-order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("first parent z-order = %v, want %v", got, want)
		}
	}
	if got := orderedChildWindows(children, order, secondParent); len(got) != 1 || got[0] != 20 {
		t.Fatalf("second parent z-order = %v, want [20]", got)
	}
	if order[0] != 90 || !hctx.HwndTopmost[90] {
		t.Fatalf("topmost window lost its group: order=%v topmost=%v", order, hctx.HwndTopmost[90])
	}

	hctx.addZOrder(40, false)
	order = hctx.snapshotZOrder()
	if len(order) < 2 || order[0] != 90 || order[1] != 40 {
		t.Fatalf("new top-level window did not start above normal windows: %v", order)
	}
}

func TestChildPaintOrderUsesZOrderWithoutClassPriority(t *testing.T) {
	const parent = uint64(1)
	children := map[uint64]*controlState{
		10: {parentHWND: parent, className: "ToolbarWindow32"},
		20: {parentHWND: parent, className: "ReBarWindow32"},
		30: {parentHWND: parent, className: "Scintilla"},
	}
	got := childPaintOrder(children, []uint64{20, 10, 30}, parent)
	want := []uint64{30, 10, 20}
	if len(got) != len(want) {
		t.Fatalf("paint order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("paint order = %v, want %v", got, want)
		}
	}
}

func TestDialogControlAvailableChecksAncestors(t *testing.T) {
	children := map[uint64]*controlState{
		11: {parentHWND: 10, visible: false},
		12: {parentHWND: 11, visible: true},
		21: {parentHWND: 20, visible: true},
		22: {parentHWND: 21, visible: true},
	}
	if dialogControlAvailable(children, 12, 10) {
		t.Fatal("control under a hidden parent was available")
	}
	if !dialogControlAvailable(children, 22, 20) {
		t.Fatal("control under visible parents was unavailable")
	}
}

func TestDialogControlWantsKey(t *testing.T) {
	multiline := &controlState{className: "Edit", style: 0x1004}
	if !dialogControlWantsKey(multiline, 0x0d) {
		t.Fatal("multiline edit did not retain Enter")
	}
	if dialogControlWantsKey(multiline, 0x09) {
		t.Fatal("multiline edit retained Tab")
	}
	if !dialogControlWantsKey(&controlState{className: "Scintilla"}, 0x09) {
		t.Fatal("custom control did not retain Tab")
	}
}

func TestNextDialogGroupItemWrapsWithinGroup(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, style: 0x00020009, visible: true},
		12: {parentHWND: dialog, style: 0x00000009, visible: true},
		13: {parentHWND: dialog, style: 0x00000009, visible: true},
		14: {parentHWND: dialog, style: 0x00020009, visible: true},
		15: {parentHWND: dialog, style: 0x00000009, visible: true},
	}
	order := []uint64{11, 12, 13, 14, 15}
	if got := nextDialogGroupItem(children, order, dialog, 12, false); got != 13 {
		t.Fatalf("next item = %d, want 13", got)
	}
	if got := nextDialogGroupItem(children, order, dialog, 13, false); got != 11 {
		t.Fatalf("wrapped item = %d, want 11", got)
	}
	if got := nextDialogGroupItem(children, order, dialog, 11, true); got != 13 {
		t.Fatalf("reverse wrapped item = %d, want 13", got)
	}
}

func TestDialogGroupPreservesUnavailableBoundary(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, style: 0x00020009, visible: true},
		12: {parentHWND: dialog, style: 0x00000009, visible: true},
		13: {parentHWND: dialog, style: 0x00020009},
		14: {parentHWND: dialog, style: 0x00000009, visible: true},
	}
	items := dialogGroupItems(children, []uint64{11, 12, 13, 14}, dialog, 14)
	if len(items) != 1 || items[0] != 14 {
		t.Fatalf("items = %v, want [14]", items)
	}
}

func TestNextDialogGroupItemWithNullCurrent(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, visible: true},
		12: {parentHWND: dialog, visible: true},
	}
	order := []uint64{11, 12}
	if got := nextDialogGroupItem(children, order, dialog, 0, false); got != 11 {
		t.Fatalf("forward item = %d, want 11", got)
	}
	if got := nextDialogGroupItem(children, order, dialog, 0, true); got != 12 {
		t.Fatalf("reverse item = %d, want 12", got)
	}
}

func TestDialogGroupTraversesControlParent(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, exStyle: 0x00010000, visible: true},
		12: {parentHWND: 11, style: 0x00020009, visible: true},
		13: {parentHWND: 11, style: 0x00000009, visible: true},
	}
	order := []uint64{11, 12, 13}
	if got := nextDialogGroupItem(children, order, dialog, 12, false); got != 13 {
		t.Fatalf("nested next item = %d, want 13", got)
	}
}

func TestSelectAutoRadioButtonClearsGroup(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, className: "Button", style: 0x00020009, checkState: 1},
		12: {parentHWND: dialog, className: "Button", style: 0x00000009, visible: true},
		13: {parentHWND: dialog, className: "Button", style: 0x00020009, visible: true, checkState: 1},
	}
	if !selectAutoRadioButton(children, []uint64{11, 12, 13}, dialog, 12) {
		t.Fatal("selection failed")
	}
	if children[11].checkState != 0 || children[12].checkState != 1 || children[13].checkState != 1 {
		t.Fatalf("states = %d %d %d", children[11].checkState, children[12].checkState, children[13].checkState)
	}
}

func TestNextDialogGroupItemUsesUnavailableCurrentPosition(t *testing.T) {
	const dialog = uint64(10)
	children := map[uint64]*controlState{
		11: {parentHWND: dialog, style: 0x00020009, visible: true},
		12: {parentHWND: dialog, style: 0x00000009},
		13: {parentHWND: dialog, style: 0x00000009, visible: true},
		20: {parentHWND: 21, visible: true},
	}
	order := []uint64{11, 12, 13, 20}
	if got := nextDialogGroupItem(children, order, dialog, 12, false); got != 13 {
		t.Fatalf("forward item = %d, want 13", got)
	}
	if got := nextDialogGroupItem(children, order, dialog, 12, true); got != 11 {
		t.Fatalf("reverse item = %d, want 11", got)
	}
	if got := nextDialogGroupItem(children, order, dialog, 20, false); got != 0 {
		t.Fatalf("foreign item returned %d, want 0", got)
	}
	children[11].visible = false
	children[13].visible = false
	if got := nextDialogGroupItem(children, order, dialog, 12, false); got != 12 {
		t.Fatalf("unavailable fallback = %d, want 12", got)
	}
}
