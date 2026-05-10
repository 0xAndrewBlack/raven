//go:build guest_windows

package main

import (
	"sync"
	"testing"
)

func TestTabItemOffsets(t *testing.T) {
	tests := []struct {
		name        string
		is32        bool
		text, param uint64
	}{
		{name: "win64", text: 16, param: 32},
		{name: "win32", is32: true, text: 12, param: 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, param := tabItemOffsets(tt.is32)
			if text != tt.text || param != tt.param {
				t.Fatalf("offsets = (%d, %d), want (%d, %d)", text, param, tt.text, tt.param)
			}
		})
	}
}

func TestCommonControlItemOffsets(t *testing.T) {
	tree32 := treeViewItemOffsets(true)
	if tree32.item != 4 || tree32.state != 8 || tree32.text != 16 || tree32.textMax != 20 || tree32.param != 36 || tree32.insertItem != 8 {
		t.Fatalf("PE32 TVITEM layout = %+v", tree32)
	}
	tree64 := treeViewItemOffsets(false)
	if tree64.item != 8 || tree64.state != 16 || tree64.text != 24 || tree64.textMax != 32 || tree64.param != 48 || tree64.insertItem != 16 {
		t.Fatalf("PE64 TVITEM layout = %+v", tree64)
	}

	list32 := listViewItemOffsets(true)
	if list32.text != 20 || list32.textMax != 24 || list32.image != 28 || list32.param != 32 {
		t.Fatalf("PE32 LVITEM layout = %+v", list32)
	}
	list64 := listViewItemOffsets(false)
	if list64.text != 24 || list64.textMax != 32 || list64.image != 36 || list64.param != 40 {
		t.Fatalf("PE64 LVITEM layout = %+v", list64)
	}
	if listViewColumnTextOffset(true) != 12 || listViewColumnTextOffset(false) != 16 {
		t.Fatal("LVCOLUMN text offsets do not match PE32 and PE64 layouts")
	}
	notifyList32 := listViewNotifyOffsets(true)
	if notifyList32.header != 12 || notifyList32.size != 72 {
		t.Fatalf("PE32 NMLVDISPINFO layout = %+v", notifyList32)
	}
	notifyList64 := listViewNotifyOffsets(false)
	if notifyList64.header != 24 || notifyList64.size != 112 {
		t.Fatalf("PE64 NMLVDISPINFO layout = %+v", notifyList64)
	}

	notify32 := treeViewNotifyOffsets(true)
	if notify32.action != 12 || notify32.itemOld != 16 || notify32.itemNew != 56 || notify32.point != 96 || notify32.size != 104 {
		t.Fatalf("PE32 NMTREEVIEW layout = %+v", notify32)
	}
	notify64 := treeViewNotifyOffsets(false)
	if notify64.action != 24 || notify64.itemOld != 32 || notify64.itemNew != 88 || notify64.point != 144 || notify64.size != 152 {
		t.Fatalf("PE64 NMTREEVIEW layout = %+v", notify64)
	}
}

func TestTreeViewMessageIDs(t *testing.T) {
	tests := map[string]struct {
		got  int
		want int
	}{
		"TVM_INSERTITEMA":  {got: tvmInsertItemA, want: 0x1100},
		"TVM_DELETEITEM":   {got: tvmDeleteItem, want: 0x1101},
		"TVM_EXPAND":       {got: tvmExpand, want: 0x1102},
		"TVM_GETITEMRECT":  {got: tvmGetItemRect, want: 0x1104},
		"TVM_GETCOUNT":     {got: tvmGetCount, want: 0x1105},
		"TVM_GETNEXTITEM":  {got: tvmGetNextItem, want: 0x110A},
		"TVM_SELECTITEM":   {got: tvmSelectItem, want: 0x110B},
		"TVM_GETITEMA":     {got: tvmGetItemA, want: 0x110C},
		"TVM_SETITEMA":     {got: tvmSetItemA, want: 0x110D},
		"TVM_SORTCHILDREN": {got: tvmSortChildren, want: 0x1113},
		"TVM_INSERTITEMW":  {got: tvmInsertItemW, want: 0x1132},
		"TVM_GETITEMW":     {got: tvmGetItemW, want: 0x113E},
		"TVM_SETITEMW":     {got: tvmSetItemW, want: 0x113F},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %#x, want %#x", name, tt.got, tt.want)
			}
		})
	}
}

func TestTextCallbackPointerWidth(t *testing.T) {
	if !isTextCallbackPointer(0xFFFFFFFF, true) || isTextCallbackPointer(0xFFFFFFFF, false) {
		t.Fatal("PE32 callback pointer was not width-sensitive")
	}
	if !isTextCallbackPointer(^uint64(0), false) {
		t.Fatal("PE64 callback pointer was not recognized")
	}
}

func TestSetListViewExtendedStyle(t *testing.T) {
	lv := &listViewState{extStyle: 0x00000021}
	if old := setListViewExtendedStyle(lv, 0x00000020, 0); old != 0x00000021 {
		t.Fatalf("masked old style = %#x, want %#x", old, uint32(0x00000021))
	}
	if lv.extStyle != 0x00000001 {
		t.Fatalf("masked style = %#x, want %#x", lv.extStyle, uint32(0x00000001))
	}
	if old := setListViewExtendedStyle(lv, 0, 0x00010000); old != 0x00000001 {
		t.Fatalf("replacement old style = %#x, want %#x", old, uint32(0x00000001))
	}
	if lv.extStyle != 0x00010000 {
		t.Fatalf("replacement style = %#x, want %#x", lv.extStyle, uint32(0x00010000))
	}
}

func TestToolbarLayouts(t *testing.T) {
	layout32 := toolbarButtonOffsets(true)
	if layout32.size != 20 || layout32.data != 12 || layout32.string != 16 {
		t.Fatalf("PE32 TBBUTTON layout = %+v", layout32)
	}
	layout64 := toolbarButtonOffsets(false)
	if layout64.size != 32 || layout64.data != 16 || layout64.string != 24 {
		t.Fatalf("PE64 TBBUTTON layout = %+v", layout64)
	}
	if toolbarAddBitmapResourceOffset(true) != 4 || toolbarAddBitmapResourceOffset(false) != 8 {
		t.Fatal("TBADDBITMAP resource offsets do not match PE32 and PE64 layouts")
	}
	info32 := toolbarButtonInfoOffsets(true)
	if info32.param != 20 || info32.text != 24 || info32.textMax != 28 {
		t.Fatalf("PE32 TBBUTTONINFO layout = %+v", info32)
	}
	info64 := toolbarButtonInfoOffsets(false)
	if info64.param != 24 || info64.text != 32 || info64.textMax != 40 {
		t.Fatalf("PE64 TBBUTTONINFO layout = %+v", info64)
	}
}

func TestSetToolbarButtonFlag(t *testing.T) {
	toolbar := &toolbarState{buttons: []tbButton{{id: 7, state: 0x04}}}
	if !setToolbarButtonFlag(toolbar, 7, 0x01, true) || toolbar.buttons[0].state != 0x05 {
		t.Fatalf("checked state = %#x", toolbar.buttons[0].state)
	}
	if !setToolbarButtonFlag(toolbar, 7, 0x04, false) || toolbar.buttons[0].state != 0x01 {
		t.Fatalf("disabled state = %#x", toolbar.buttons[0].state)
	}
	if setToolbarButtonFlag(toolbar, 8, 0x01, true) {
		t.Fatal("unknown command was reported as updated")
	}
}

func TestMakeToolbarPlaceholderIcon(t *testing.T) {
	icon := makeToolbarPlaceholderIcon(16, 16, 3)
	if len(icon) != 256 {
		t.Fatalf("placeholder pixel count = %d", len(icon))
	}
	nonTransparent := 0
	for _, pixel := range icon {
		if pixel>>24 != 0 {
			nonTransparent++
		}
	}
	if nonTransparent == 0 || nonTransparent == len(icon) {
		t.Fatalf("placeholder opaque pixel count = %d", nonTransparent)
	}
	if !toolbarIconHasVisiblePixel(icon) || toolbarIconHasVisiblePixel(make([]uint32, 16)) {
		t.Fatal("toolbar icon visibility detection failed")
	}
}

func TestToolbarFallbackIconCache(t *testing.T) {
	hctx := &HandlerCtx{}
	icon := makeToolbarPlaceholderIcon(16, 16, 3)
	key := toolbarFallbackKey{parent: 10, layout: 20}
	cacheToolbarFallbackIcon(hctx, key, 2, 16, 16, icon)
	icon[0] = 0xFFFFFFFF

	cached := toolbarFallbackIcon(hctx, key, 2, 16, 16)
	if len(cached) != 256 || cached[0] != 0 {
		t.Fatal("toolbar fallback cache did not retain an independent icon copy")
	}
	if toolbarFallbackIcon(hctx, toolbarFallbackKey{parent: 11, layout: 20}, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache crossed parent windows")
	}
	if toolbarFallbackIcon(hctx, toolbarFallbackKey{parent: 10, layout: 21}, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache crossed toolbar layouts")
	}
	if toolbarFallbackIcon(hctx, key, 2, 24, 24) != nil {
		t.Fatal("toolbar fallback cache accepted mismatched dimensions")
	}

	cacheToolbarFallbackIcon(hctx, key, 0, 24, 24, makeToolbarPlaceholderIcon(24, 24, 4))
	if toolbarFallbackIcon(hctx, key, 2, 16, 16) != nil {
		t.Fatal("toolbar fallback cache retained icons with stale dimensions")
	}
}

func TestToolbarFallbackIconCacheConcurrent(t *testing.T) {
	hctx := &HandlerCtx{}
	icon := makeToolbarPlaceholderIcon(16, 16, 7)
	var wg sync.WaitGroup
	key := toolbarFallbackKey{parent: 10, layout: 20}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				cacheToolbarFallbackIcon(hctx, key, index, 16, 16, icon)
				_ = toolbarFallbackIcon(hctx, key, index, 16, 16)
			}
		}(i)
	}
	wg.Wait()
}

func TestToolbarImagePixels(t *testing.T) {
	pixels := []byte{
		1, 2, 3, 0,
		4, 5, 6, 128,
	}
	got := toolbarImagePixels(pixels, nil, true, 2, 1)
	if len(got) != 2 || got[0] != 0x00030201 || got[1] != 0x80060504 {
		t.Fatalf("alpha image pixels = %#v", got)
	}

	got = toolbarImagePixels(pixels, []byte{0, 1}, false, 2, 1)
	if got[0] != 0xFF030201 || got[1] != 0 {
		t.Fatalf("masked image pixels = %#v", got)
	}

	got = toolbarImagePixels(pixels, []byte{0x40, 0, 0, 0}, false, 2, 1)
	if got[0] != 0xFF030201 || got[1] != 0 {
		t.Fatalf("packed masked image pixels = %#v", got)
	}
}

func TestToolbarLayoutSignature(t *testing.T) {
	first := &toolbarState{buttons: []tbButton{{id: 1, iBitmap: 2}, {id: 3, iBitmap: 4, style: 1}}}
	second := &toolbarState{buttons: append([]tbButton(nil), first.buttons...)}
	if toolbarLayoutSignature(first) == 0 || toolbarLayoutSignature(first) != toolbarLayoutSignature(second) {
		t.Fatal("equivalent toolbar layouts did not produce the same signature")
	}
	second.buttons[1].id = 5
	if toolbarLayoutSignature(first) == toolbarLayoutSignature(second) {
		t.Fatal("different toolbar layouts produced the same signature")
	}
}

func TestTabInputNeedsSubclassFirst(t *testing.T) {
	tests := []struct {
		name      string
		hasGuest  bool
		inBuiltin bool
		msg       uint32
		wantDefer bool
	}{
		{name: "subclass mouse down", hasGuest: true, msg: 0x0201, wantDefer: true},
		{name: "subclass double click", hasGuest: true, msg: 0x0203, wantDefer: true},
		{name: "default control mouse down", msg: 0x0201},
		{name: "call original mouse down", hasGuest: true, inBuiltin: true, msg: 0x0201},
		{name: "control message", hasGuest: true, msg: 0x130b},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tabInputNeedsSubclassFirst(tt.hasGuest, tt.inBuiltin, tt.msg); got != tt.wantDefer {
				t.Fatalf("tabInputNeedsSubclassFirst() = %v, want %v", got, tt.wantDefer)
			}
		})
	}
}

func TestSelectTabFromInputNotifiesInNativeOrder(t *testing.T) {
	if tcmAdjustRect != 0x1328 || tcnSelChange != 0xFFFFFDD9 || tcnSelChanging != 0xFFFFFDD8 {
		t.Fatalf("tab ABI values = (%#x, %#x, %#x)", tcmAdjustRect, tcnSelChange, tcnSelChanging)
	}
	tab := &tabState{items: []tabItem{{text: "one"}, {text: "two"}}, curSel: 0}
	var notifications []uint32
	changed := selectTabFromInput(tab, 1, func(code uint32) uint64 {
		notifications = append(notifications, code)
		return 0
	})
	if !changed || tab.curSel != 1 {
		t.Fatalf("selection changed=%v curSel=%d, want true and 1", changed, tab.curSel)
	}
	if len(notifications) != 2 || notifications[0] != tcnSelChanging || notifications[1] != tcnSelChange {
		t.Fatalf("notifications = %#v, want TCN_SELCHANGING then TCN_SELCHANGE", notifications)
	}
}

func TestSelectTabFromInputCanBeCancelled(t *testing.T) {
	tab := &tabState{items: []tabItem{{text: "one"}, {text: "two"}}, curSel: 0}
	var notifications []uint32
	changed := selectTabFromInput(tab, 1, func(code uint32) uint64 {
		notifications = append(notifications, code)
		return 1
	})
	if changed || tab.curSel != 0 {
		t.Fatalf("selection changed=%v curSel=%d, want false and 0", changed, tab.curSel)
	}
	if len(notifications) != 1 || notifications[0] != tcnSelChanging {
		t.Fatalf("notifications = %#v, want only TCN_SELCHANGING", notifications)
	}
}

func TestAdjustTabRect(t *testing.T) {
	window := [4]int32{0, 0, 100, 100}
	display := adjustTabRect(window, 0, false, 22, 1)
	if want := [4]int32{4, 26, 96, 96}; display != want {
		t.Fatalf("display rect = %v, want %v", display, want)
	}
	if got := adjustTabRect(display, 0, true, 22, 1); got != window {
		t.Fatalf("round trip = %v, want %v", got, window)
	}
}

func TestAdjustBottomTabRect(t *testing.T) {
	window := [4]int32{0, 0, 100, 100}
	got := adjustTabRect(window, 0x0002, false, 22, 1)
	want := [4]int32{4, 4, 96, 74}
	if got != want {
		t.Fatalf("bottom display rect = %v, want %v", got, want)
	}
}

func TestTabRowCount(t *testing.T) {
	if got := tabRowCount(nil); got != 0 {
		t.Fatalf("nil tab row count = %d, want 0", got)
	}
	tab := &tabState{items: []tabItem{{text: "readme.txt"}}}
	if got := tabRowCount(tab); got != 1 {
		t.Fatalf("populated tab row count = %d, want 1", got)
	}
}
