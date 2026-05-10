//go:build guest_windows

package main

import (
	"reflect"
	"testing"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestMenuItemInfoLayouts(t *testing.T) {
	for _, test := range []struct {
		name                      string
		is32                      bool
		legacySize, currentSize   uint32
		typeDataOffset, cchOffset uint64
	}{
		{name: "PE32", is32: true, legacySize: 44, currentSize: 48, typeDataOffset: 36, cchOffset: 40},
		{name: "PE64", legacySize: 72, currentSize: 80, typeDataOffset: 56, cchOffset: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := menuItemInfoLayoutFor(test.is32)
			if layout.legacySize != test.legacySize || layout.currentSize != test.currentSize || layout.dwTypeDataOffset != test.typeDataOffset || layout.cchOffset != test.cchOffset {
				t.Fatalf("layout = %+v", layout)
			}
			if !layout.validSize(test.legacySize) || !layout.validSize(test.currentSize) || layout.validSize(test.currentSize+8) {
				t.Fatalf("invalid size validation for %+v", layout)
			}
		})
	}
}

func TestReadGuestPointerUsesGuestWidth(t *testing.T) {
	mem := mmu.New()
	const address = uint64(0x4000)
	mem.MapRange(address, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.Write64(address, 0x8877665544332211); err != nil {
		t.Fatal(err)
	}
	if got, err := readGuestPointer(mem, address, true); err != nil || got != 0x44332211 {
		t.Fatalf("PE32 pointer = %#x", got)
	}
	if got, err := readGuestPointer(mem, address, false); err != nil || got != 0x8877665544332211 {
		t.Fatalf("PE64 pointer = %#x", got)
	}
}

func TestMenuANSIUsesWindows1252(t *testing.T) {
	encoded, err := encodeMenuANSI("Caf\u00e9 \u03a9")
	if err != nil || string(encoded) != "Caf\xe9 ?" {
		t.Fatalf("encoded = %x, err %v", encoded, err)
	}
	decoded, err := decodeMenuANSI(encoded)
	if err != nil || decoded != "Caf\u00e9 ?" {
		t.Fatalf("decoded = %q, err %v", decoded, err)
	}
}

func TestGetMenuItemInfoModernFields(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		layout := menuItemInfoLayoutFor(is32)
		mem := mmu.New()
		const info = uint64(0x4000)
		const text = uint64(0x5000)
		mem.MapRange(info, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
		mask := miimState | miimID | miimSubmenu | miimCheckmarks | miimData | miimString | miimFType | miimBitmap
		mem.Write32(info, layout.currentSize)
		mem.Write32(info+4, mask)
		writeGuestPointer(mem, info+layout.dwTypeDataOffset, text, is32)
		mem.Write32(info+layout.cchOffset, 16)
		item := menuItem{
			flags: 0x1008 | mftOwnerDraw, id: 77, text: "Caf\u00e9", submenu: []menuItem{{id: 1}},
			checkedBitmap: 2, uncheckedBitmap: 3, itemData: 4, bitmap: 5,
		}
		menus := map[uint64]*menuData{10: {items: []menuItem{item}}}
		if !getMenuItemInfo(mem, info, is32, true, 10, &menus[10].items[0], menus) {
			t.Fatalf("PE32=%v: getMenuItemInfo returned false", is32)
		}
		if state, _ := mem.Read32(info + 12); state != 0x1008 {
			t.Fatalf("PE32=%v: state = %#x", is32, state)
		}
		if id, _ := mem.Read32(info + 16); id != 77 {
			t.Fatalf("PE32=%v: id = %d", is32, id)
		}
		if submenu, _ := readGuestPointer(mem, info+layout.hSubMenuOffset, is32); submenu == 0 {
			t.Fatalf("PE32=%v: submenu is null", is32)
		}
		if bitmap, _ := readGuestPointer(mem, info+layout.hbmpItemOffset, is32); bitmap != 5 {
			t.Fatalf("PE32=%v: bitmap = %#x", is32, bitmap)
		}
		if got, err := readMenuText(mem, text, true); err != nil || got != "Caf\u00e9" {
			t.Fatalf("PE32=%v: text = %q, err %v", is32, got, err)
		}
	}
}

func TestSetMenuItemInfoANSIFields(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x4000)
	const text = uint64(0x5000)
	mem.MapRange(info, mmu.PageSize*2, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(true)
	mask := miimState | miimID | miimCheckmarks | miimData | miimString | miimFType | miimBitmap
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, mask)
	mem.Write32(info+8, mftOwnerDraw)
	mem.Write32(info+12, 0x1008)
	mem.Write32(info+16, 88)
	writeGuestPointer(mem, info+layout.hbmpCheckedOffset, 2, true)
	writeGuestPointer(mem, info+layout.hbmpUncheckedOffset, 3, true)
	writeGuestPointer(mem, info+layout.dwItemDataOffset, 4, true)
	writeGuestPointer(mem, info+layout.dwTypeDataOffset, text, true)
	writeGuestPointer(mem, info+layout.hbmpItemOffset, 5, true)
	mem.WriteBytes(text, []byte{'C', 'a', 'f', 0xe9, 0})
	item := menuItem{}
	if !setMenuItemInfo(mem, info, true, false, 1, &item, map[uint64]*menuData{}) {
		t.Fatal("setMenuItemInfo returned false")
	}
	if item.id != 88 || item.text != "Caf\u00e9" || item.checkedBitmap != 2 || item.uncheckedBitmap != 3 || item.itemData != 4 || item.bitmap != 5 {
		t.Fatalf("item = %+v", item)
	}
}

func TestMenuItemInfoRejectsInvalidInputs(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x4000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.Write32(info, 52)
	mem.Write32(info+4, miimString)
	item := menuItem{text: "x"}
	if getMenuItemInfo(mem, info, true, true, 1, &item, map[uint64]*menuData{}) {
		t.Fatal("accepted oversized cbSize")
	}
	mem.Write32(info, 48)
	mem.Write32(info+4, miimType|miimString)
	if setMenuItemInfo(mem, info, true, true, 1, &item, map[uint64]*menuData{}) {
		t.Fatal("accepted incompatible MIIM_TYPE and MIIM_STRING")
	}
	mem.Write32(info+4, miimFType)
	mem.Write32(info+8, mftBitmap)
	if setMenuItemInfo(mem, info, true, true, 1, &item, map[uint64]*menuData{}) {
		t.Fatal("accepted MFT_BITMAP through MIIM_FTYPE")
	}
}

func TestGetMenuItemInfoPreservesLegacyBitmapType(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x4000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(true)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimFType)
	item := menuItem{flags: mftBitmap}
	if !getMenuItemInfo(mem, info, true, true, 1, &item, map[uint64]*menuData{}) {
		t.Fatal("getMenuItemInfo returned false")
	}
	if itemType, _ := mem.Read32(info + 8); itemType&mftBitmap == 0 {
		t.Fatalf("fType = %#x", itemType)
	}
}

func TestEnsureMenuItemSubmenuAllocatesUniqueHandles(t *testing.T) {
	menus := map[uint64]*menuData{}
	first := menuItem{submenu: []menuItem{{id: 1}}}
	second := menuItem{submenu: []menuItem{{id: 2}}}
	firstHandle := ensureMenuItemSubmenu(10, 0, &first, menus)
	secondHandle := ensureMenuItemSubmenu(20, 0, &second, menus)
	if firstHandle == 0 || secondHandle == 0 || firstHandle == secondHandle {
		t.Fatalf("submenu handles = %#x, %#x", firstHandle, secondHandle)
	}
	if ensureMenuItemSubmenu(10, 0, &first, menus) != firstHandle {
		t.Fatal("submenu handle changed between calls")
	}
}

func TestSetMenuItemSubmenuRejectsCyclesAndTracksMutations(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x4000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(true)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimSubmenu)
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{id: 10}}},
		2: {items: []menuItem{{id: 20}}},
	}
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 2, true)
	if !setMenuItemInfo(mem, info, true, true, 1, &menus[1].items[0], menus) {
		t.Fatal("valid submenu assignment failed")
	}
	menus[2].items = append(menus[2].items, menuItem{id: 21})
	if got := len(menus[1].items[0].submenuItems()); got != 2 {
		t.Fatalf("parent sees %d submenu items after mutation", got)
	}
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 1, true)
	if setMenuItemInfo(mem, info, true, true, 2, &menus[2].items[0], menus) {
		t.Fatal("accepted cyclic submenu assignment")
	}
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 99, true)
	if setMenuItemInfo(mem, info, true, true, 1, &menus[1].items[0], menus) {
		t.Fatal("accepted unknown submenu handle")
	}
}

func TestInsertMenuItemByPositionPE32(t *testing.T) {
	mem := mmu.New()
	const (
		info = uint64(0x4000)
		text = uint64(0x4100)
	)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(true)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimFType|miimState|miimID|miimString|miimData|miimBitmap)
	mem.Write32(info+8, 0x40)
	mem.Write32(info+12, 0x80)
	mem.Write32(info+16, 25)
	writeGuestPointer(mem, info+layout.dwItemDataOffset, 0x1234, true)
	writeGuestPointer(mem, info+layout.dwTypeDataOffset, text, true)
	writeGuestPointer(mem, info+layout.hbmpItemOffset, 0x5678, true)
	for index, char := range utf16.Encode([]rune("middle")) {
		mem.Write16(text+uint64(index)*2, char)
	}
	mem.Write16(text+12, 0)
	menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}, {id: 30}}}}
	if !insertMenuItem(mem, info, true, true, 1, 1, true, menus) {
		t.Fatal("PE32 position insertion failed")
	}
	got := menus[1].items
	if len(got) != 3 || got[0].id != 10 || got[1].id != 25 || got[2].id != 30 {
		t.Fatalf("menu order = %#v", got)
	}
	if got[1].text != "middle" || got[1].flags != 0xc0 || got[1].itemData != 0x1234 || got[1].bitmap != 0x5678 {
		t.Fatalf("inserted item = %#v", got[1])
	}
}

func TestInsertMenuItemByCommandANSIPE64(t *testing.T) {
	mem := mmu.New()
	const (
		info = uint64(0x5000)
		text = uint64(0x5100)
	)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimID|miimString|miimSubmenu|miimCheckmarks)
	mem.Write32(info+16, 15)
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 2, false)
	writeGuestPointer(mem, info+layout.hbmpCheckedOffset, 0x123456789, false)
	writeGuestPointer(mem, info+layout.hbmpUncheckedOffset, 0x987654321, false)
	writeGuestPointer(mem, info+layout.dwTypeDataOffset, text, false)
	mem.WriteBytes(text, []byte{'c', 'a', 'f', 0xe9, 0})
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{id: 10}, {id: 20}}},
		2: {items: []menuItem{{id: 50}}},
	}
	if !insertMenuItem(mem, info, false, false, 1, 20, false, menus) {
		t.Fatal("PE64 command insertion failed")
	}
	got := menus[1].items
	if len(got) != 3 || got[1].id != 15 || got[2].id != 20 {
		t.Fatalf("menu order = %#v", got)
	}
	if got[1].text != "café" || got[1].flags&0x0010 == 0 || got[1].submenuHandle != 2 || got[1].submenuData != menus[2] {
		t.Fatalf("inserted submenu = %#v", got[1])
	}
	if got[1].checkedBitmap != 0x123456789 || got[1].uncheckedBitmap != 0x987654321 {
		t.Fatalf("checkmark bitmaps = %#x, %#x", got[1].checkedBitmap, got[1].uncheckedBitmap)
	}
}

func TestInsertMenuItemRejectsInvalidTargetAtomically(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x6000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimSubmenu)
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 99, false)
	menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}}}}
	if insertMenuItem(mem, info, false, true, 1, 0, true, menus) {
		t.Fatal("accepted unknown submenu")
	}
	if len(menus[1].items) != 1 || menus[1].items[0].id != 10 {
		t.Fatalf("menu changed after failed insertion: %#v", menus[1].items)
	}
}

func TestInsertMenuItemMissingTargetAppends(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x7000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimID)
	mem.Write32(info+16, 20)
	menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}}}}
	if !insertMenuItem(mem, info, false, true, 1, 99, false, menus) {
		t.Fatal("missing command did not append")
	}
	mem.Write32(info+16, 30)
	if !insertMenuItem(mem, info, false, true, 1, 99, true, menus) {
		t.Fatal("out-of-range position did not append")
	}
	if got := menus[1].items; len(got) != 3 || got[1].id != 20 || got[2].id != 30 {
		t.Fatalf("appended menu = %#v", got)
	}
}

func TestInsertMenuItemByCommandSearchesSubmenus(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x8000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimID)
	mem.Write32(info+16, 15)
	menus := map[uint64]*menuData{1: {items: []menuItem{{flags: 0x0010, submenu: []menuItem{{id: 10}, {id: 20}}}}}}
	if !insertMenuItem(mem, info, false, true, 1, 20, false, menus) {
		t.Fatal("recursive command insertion failed")
	}
	root := &menus[1].items[0]
	if root.submenuHandle == 0 || root.submenuData == nil || menus[root.submenuHandle] != root.submenuData {
		t.Fatalf("inline submenu was not materialized: %#v", root)
	}
	if got := root.submenuItems(); len(got) != 3 || got[0].id != 10 || got[1].id != 15 || got[2].id != 20 {
		t.Fatalf("submenu order = %#v", got)
	}
}

func TestInsertMenuItemNestedSubmenuRejectsCycle(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x8800)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimSubmenu)
	writeGuestPointer(mem, info+layout.hSubMenuOffset, 1, false)
	menus := map[uint64]*menuData{1: {items: []menuItem{{flags: 0x0010, submenu: []menuItem{{id: 20}}}}}}
	if insertMenuItem(mem, info, false, true, 1, 20, false, menus) {
		t.Fatal("accepted cycle through nested insertion target")
	}
	root := &menus[1].items[0]
	if root.submenuHandle != 0 || root.submenuData != nil || len(menus) != 1 {
		t.Fatalf("failed insertion materialized submenu: %#v, menus=%#v", root, menus)
	}
	if got := root.submenuItems(); len(got) != 1 || got[0].id != 20 {
		t.Fatalf("submenu changed after rejected cycle: %#v", got)
	}
}

func TestInsertMenuItemLegacyLayouts(t *testing.T) {
	for _, test := range []struct {
		name string
		is32 bool
		wide bool
	}{
		{name: "PE32 Unicode", is32: true, wide: true},
		{name: "PE64 ANSI", wide: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			const (
				info = uint64(0x9000)
				text = uint64(0x9100)
			)
			mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			layout := menuItemInfoLayoutFor(test.is32)
			mem.Write32(info, layout.legacySize)
			mem.Write32(info+4, miimID|miimString)
			mem.Write32(info+16, 7)
			writeGuestPointer(mem, info+layout.dwTypeDataOffset, text, test.is32)
			if test.wide {
				mem.Write16(text, 'o')
				mem.Write16(text+2, 'k')
				mem.Write16(text+4, 0)
			} else {
				mem.WriteBytes(text, []byte{'o', 'k', 0})
			}
			menus := map[uint64]*menuData{1: {}}
			if !insertMenuItem(mem, info, test.is32, test.wide, 1, uint64(^uint32(0)), true, menus) {
				t.Fatal("legacy insertion failed")
			}
			if got := menus[1].items; len(got) != 1 || got[0].id != 7 || got[0].text != "ok" {
				t.Fatalf("inserted menu = %#v", got)
			}
		})
	}
}

func TestInsertMenuItemRejectsInvalidGuestMemory(t *testing.T) {
	mem := mmu.New()
	menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}}}}
	if insertMenuItem(mem, 0xa000, false, true, 1, 0, true, menus) {
		t.Fatal("accepted unmapped MENUITEMINFO")
	}
	const info = uint64(0xb000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimString)
	writeGuestPointer(mem, info+layout.dwTypeDataOffset, 0xc000, false)
	if insertMenuItem(mem, info, false, true, 1, 0, true, menus) {
		t.Fatal("accepted unmapped menu string")
	}
	if len(menus[1].items) != 1 || menus[1].items[0].id != 10 {
		t.Fatalf("menu changed after invalid guest memory: %#v", menus[1].items)
	}
}

func TestFindMenuItemRecursiveUsesWin32SearchOrder(t *testing.T) {
	menu := &menuData{items: []menuItem{
		{flags: 0x0010, id: 20, submenu: []menuItem{{id: 20}}},
		{id: 30},
	}}
	if got := findMenuItemRecursive(menu, 20, false); got == nil || got != &menu.items[0].submenu[0] {
		t.Fatalf("recursive search returned %#v", got)
	}
	if got := findMenuItemRecursive(menu, 0, true); got != &menu.items[0] {
		t.Fatalf("position search returned %#v", got)
	}
	if got := findMenuItemRecursive(menu, 99, false); got != nil {
		t.Fatalf("missing command returned %#v", got)
	}
}

func TestSetMenuItemBitmapsStoresBothStates(t *testing.T) {
	submenu := &menuData{items: []menuItem{{id: 20}}}
	root := menuItem{}
	root.bindSubmenu(2, submenu)
	menus := map[uint64]*menuData{
		1: {items: []menuItem{root, {id: 10}}},
		2: submenu,
	}
	if !setMenuItemBitmaps(menus, 1, 20, false, 0x1111, 0x2222) {
		t.Fatal("recursive bitmap assignment failed")
	}
	if submenu.items[0].uncheckedBitmap != 0x1111 || submenu.items[0].checkedBitmap != 0x2222 {
		t.Fatalf("bitmap states = %#x, %#x", submenu.items[0].uncheckedBitmap, submenu.items[0].checkedBitmap)
	}
	if !setMenuItemBitmaps(menus, 1, 1, true, 0x3333, 0x4444) {
		t.Fatal("position bitmap assignment failed")
	}
	if menus[1].items[1].uncheckedBitmap != 0x3333 || menus[1].items[1].checkedBitmap != 0x4444 {
		t.Fatalf("position bitmap states = %#x, %#x", menus[1].items[1].uncheckedBitmap, menus[1].items[1].checkedBitmap)
	}
	if setMenuItemBitmaps(menus, 1, 99, false, 1, 2) || setMenuItemBitmaps(menus, 99, 0, true, 1, 2) {
		t.Fatal("accepted missing menu item")
	}
}

func TestNestedMenuItemInfoBitmapRoundTripUsesOwningMenu(t *testing.T) {
	mem := mmu.New()
	const info = uint64(0x4000)
	mem.MapRange(info, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	layout := menuItemInfoLayoutFor(false)
	mem.Write32(info, layout.currentSize)
	mem.Write32(info+4, miimCheckmarks)
	writeGuestPointer(mem, info+layout.hbmpCheckedOffset, 0x1111, false)
	writeGuestPointer(mem, info+layout.hbmpUncheckedOffset, 0x2222, false)

	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenu: []menuItem{{id: 20}}}}},
	}
	item, owner := locateMenuItem(menus, 1, 20, false)
	if item == nil || owner == 0 || owner == 1 {
		t.Fatalf("nested item owner = %#x, item = %#v", owner, item)
	}
	if !setMenuItemInfo(mem, info, false, true, owner, item, menus) {
		t.Fatal("nested SetMenuItemInfo failed")
	}
	writeGuestPointer(mem, info+layout.hbmpCheckedOffset, 0, false)
	writeGuestPointer(mem, info+layout.hbmpUncheckedOffset, 0, false)
	item, readOwner := locateMenuItem(menus, 1, 20, false)
	if item == nil || readOwner != owner || !getMenuItemInfo(mem, info, false, true, readOwner, item, menus) {
		t.Fatal("nested GetMenuItemInfo failed")
	}
	checked, _ := readGuestPointer(mem, info+layout.hbmpCheckedOffset, false)
	unchecked, _ := readGuestPointer(mem, info+layout.hbmpUncheckedOffset, false)
	if checked != 0x1111 || unchecked != 0x2222 {
		t.Fatalf("round trip bitmaps = %#x, %#x", checked, unchecked)
	}
}

func TestLocatedMenuItemRollsBackFailedMaterialization(t *testing.T) {
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenu: []menuItem{{flags: 0x10, submenu: []menuItem{{id: 20}}}}}}},
	}
	if withLocatedMenuItem(menus, 1, 20, false, func(*menuItem, uint64) bool { return false }) {
		t.Fatal("failed action returned success")
	}
	root := &menus[1].items[0]
	if root.submenuHandle != 0 || root.submenuData != nil || len(root.submenu) != 1 || len(menus) != 1 {
		t.Fatalf("failed lookup changed menu state: item=%+v menus=%#v", root, menus)
	}
	inner := &root.submenu[0]
	if inner.submenuHandle != 0 || inner.submenuData != nil || len(inner.submenu) != 1 {
		t.Fatalf("failed lookup changed inner submenu: %+v", inner)
	}
	if withLocatedMenuItem(menus, 1, 99, false, func(*menuItem, uint64) bool { return true }) {
		t.Fatal("missing item returned success")
	}
	if root.submenuHandle != 0 || root.submenuData != nil || len(menus) != 1 {
		t.Fatal("missing lookup materialized submenu")
	}
}

func TestWriteMenuStringUsesWindowsCharacterCounts(t *testing.T) {
	mem := mmu.New()
	const address = uint64(0x4000)
	mem.MapRange(address, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if written, ok := writeMenuString(mem, address, 4, "A\U0001f600B", true); !ok || written != 3 {
		t.Fatalf("wide write = (%d,%v)", written, ok)
	}
	first, _ := mem.Read16(address)
	high, _ := mem.Read16(address + 2)
	low, _ := mem.Read16(address + 4)
	terminator, _ := mem.Read16(address + 6)
	if first != 'A' || high < 0xd800 || low < 0xdc00 || terminator != 0 {
		t.Fatalf("wide units = %#x %#x %#x %#x", first, high, low, terminator)
	}
	if written, ok := writeMenuString(mem, address, 8, "Caf\u00e9", false); !ok || written != 4 {
		t.Fatalf("ANSI write = (%d,%v)", written, ok)
	}
	bytes, _ := mem.ReadBytes(address, 5)
	if string(bytes) != "Caf\xe9\x00" {
		t.Fatalf("ANSI bytes = %x", bytes)
	}
	if _, ok := writeMenuString(mem, address+mmu.PageSize-1, 4, "abc", false); ok {
		t.Fatal("accepted inaccessible output range")
	}
	if written, ok := writeMenuString(mem, 0, 0, "A\U0001f600", true); !ok || written != 3 {
		t.Fatalf("wide length query = (%d,%v)", written, ok)
	}
	if written, ok := writeMenuString(mem, 0, 8, "Caf\u00e9", false); !ok || written != 4 {
		t.Fatalf("ANSI length query = (%d,%v)", written, ok)
	}
}

func TestRemoveAndDeleteMenuItemHandleNestedSubmenus(t *testing.T) {
	grandchild := &menuData{items: []menuItem{{id: 30}}}
	child := &menuData{items: []menuItem{{id: 20}, {flags: 0x10, submenuHandle: 3, submenuData: grandchild}}}
	rootItem := menuItem{flags: 0x10, submenuHandle: 2, submenuData: child}
	menus := map[uint64]*menuData{1: {items: []menuItem{rootItem, {id: 10}}}, 2: child, 3: grandchild}
	if !removeMenuItem(menus, 1, 20, false, false) || len(child.items) != 1 {
		t.Fatal("RemoveMenu did not remove nested command")
	}
	if menus[2] == nil || menus[3] == nil {
		t.Fatal("RemoveMenu destroyed a submenu")
	}
	if !removeMenuItem(menus, 1, 0, true, true) {
		t.Fatal("DeleteMenu did not remove root popup")
	}
	if menus[2] != nil || menus[3] != nil || len(menus[1].items) != 1 {
		t.Fatalf("DeleteMenu left submenu tree: %#v", menus)
	}
	if removeMenuItem(menus, 1, 99, false, false) || removeMenuItem(menus, 99, 0, true, false) {
		t.Fatal("accepted missing menu item")
	}
}

func TestDeleteMenuInvalidatesSharedSubmenuReferences(t *testing.T) {
	shared := &menuData{items: []menuItem{{id: 30}}}
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenuHandle: 3, submenuData: shared}}},
		2: {items: []menuItem{{flags: 0x10, submenuHandle: 3, submenuData: shared}}},
		3: shared,
	}
	if !removeMenuItem(menus, 1, 0, true, true) {
		t.Fatal("DeleteMenu failed")
	}
	reference := &menus[2].items[0]
	if menus[3] != nil || reference.submenuHandle != 0 || reference.submenuData != nil || reference.flags&0x10 != 0 {
		t.Fatalf("shared reference survived deletion: %+v", reference)
	}
}

func TestModifyMenuItemUpdatesNestedKindsAtomically(t *testing.T) {
	child := &menuData{items: []menuItem{{id: 20, text: "old", bitmap: 3, itemData: 4}}}
	replacement := &menuData{items: []menuItem{{id: 30}}}
	descendant := &menuData{items: []menuItem{{id: 40}}}
	child.items = append(child.items, menuItem{flags: 0x10, submenuHandle: 4, submenuData: descendant})
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenuHandle: 2, submenuData: child}}},
		2: child,
		3: replacement,
		4: descendant,
	}
	if !modifyMenuItem(menus, 1, 20, false, 0, 21, 0, "new") {
		t.Fatal("nested string modification failed")
	}
	item := &child.items[0]
	if item.id != 21 || item.text != "new" || item.bitmap != 0 || item.itemData != 0 || item.submenuHandle != 0 {
		t.Fatalf("string item = %+v", item)
	}
	rootBefore := menus[1].items[0]
	if modifyMenuItem(menus, 1, 0, true, 0x10, 4, 0, "nested") || !reflect.DeepEqual(menus[1].items[0], rootBefore) {
		t.Fatal("accepted replacement with a descendant of the old submenu")
	}
	if !modifyMenuItem(menus, 1, 0, true, mftBitmap|0x0008, 22, 0x1234, "ignored") {
		t.Fatal("bitmap modification failed")
	}
	root := &menus[1].items[0]
	if root.bitmap != 0x1234 || root.text != "" || root.flags&mftBitmap == 0 || root.flags&0x0008 == 0 {
		t.Fatalf("bitmap item = %+v", root)
	}
	if menus[2] != nil {
		t.Fatal("popup-to-bitmap modification left the old submenu alive")
	}
	before := *root
	if modifyMenuItem(menus, 1, 0, true, 0x10, 99, 0, "") || !reflect.DeepEqual(*root, before) {
		t.Fatal("invalid popup modification was not atomic")
	}
	if !modifyMenuItem(menus, 1, 0, true, 0x10, 3, 0, "popup") {
		t.Fatal("popup modification failed")
	}
	if root.submenuHandle != 3 || root.submenuData != replacement || root.flags&0x10 == 0 {
		t.Fatalf("popup item = %+v", root)
	}
	if !modifyMenuItem(menus, 1, 0, true, mftSeparator|0x1000, 0, 0, "") {
		t.Fatal("separator modification failed")
	}
	if root.flags&mftSeparator == 0 || root.flags&0x0003 != 0x0003 || root.flags&0x1000 != 0 {
		t.Fatalf("separator flags = %#x", root.flags)
	}
}

func TestInsertLegacyMenuItemUsesPositionCommandAndKinds(t *testing.T) {
	child := &menuData{items: []menuItem{{id: 20, text: "target"}}}
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{id: 10}, {flags: 0x10, submenuHandle: 2, submenuData: child}}},
		2: child,
	}
	if !insertLegacyMenuItem(menus, 1, 0, true, 0, 11, 0, "first") || menus[1].items[0].id != 11 {
		t.Fatal("position insertion failed")
	}
	if !insertLegacyMenuItem(menus, 1, 20, false, mftOwnerDraw, 19, 0x1234, "") {
		t.Fatal("nested command insertion failed")
	}
	if child.items[0].id != 19 || child.items[0].itemData != 0x1234 || child.items[0].flags&mftOwnerDraw == 0 {
		t.Fatalf("owner-draw item = %+v", child.items[0])
	}
	if !insertLegacyMenuItem(menus, 1, 99, false, mftSeparator|0x1000, 30, 0, "") {
		t.Fatal("missing command append failed")
	}
	last := menus[1].items[len(menus[1].items)-1]
	if last.id != 30 || last.flags&mftSeparator == 0 || last.flags&0x0003 != 0x0003 || last.flags&0x1000 != 0 {
		t.Fatalf("separator item = %+v", last)
	}
	if insertLegacyMenuItem(menus, 99, 0, true, 0, 1, 0, "") {
		t.Fatal("accepted missing menu")
	}
}

func TestInsertLegacyPopupMaterializesInlineOwnerAndRejectsCycles(t *testing.T) {
	popup := &menuData{items: []menuItem{{id: 30}}}
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenu: []menuItem{{id: 20}}}}},
		3: popup,
	}
	if !insertLegacyMenuItem(menus, 1, 20, false, 0x10, 3, 0, "popup") {
		t.Fatal("inline popup insertion failed")
	}
	root := &menus[1].items[0]
	if root.submenuHandle == 0 || root.submenuData == nil || len(root.submenuData.items) != 2 {
		t.Fatalf("inline owner was not materialized: %+v", root)
	}
	inserted := root.submenuData.items[0]
	if inserted.submenuHandle != 3 || inserted.submenuData != popup || inserted.flags&0x10 == 0 {
		t.Fatalf("inserted popup = %+v", inserted)
	}
	before := len(menus[1].items)
	if insertLegacyMenuItem(menus, 1, 0, true, 0x10, 1, 0, "cycle") || len(menus[1].items) != before {
		t.Fatal("accepted cyclic popup insertion")
	}
}

func TestInsertLegacyPopupRollsBackCommandMaterializationOnCycle(t *testing.T) {
	menus := map[uint64]*menuData{
		1: {items: []menuItem{{flags: 0x10, submenu: []menuItem{{id: 20}}}}},
	}

	if insertLegacyMenuItem(menus, 1, 20, false, 0x10, 1, 0, "cycle") {
		t.Fatal("accepted cyclic popup insertion")
	}
	if len(menus) != 1 {
		t.Fatalf("materialized menu handles remain after rollback: %v", menus)
	}
	root := menus[1].items[0]
	if root.flags != 0x10 || root.submenuHandle != 0 || root.submenuData != nil {
		t.Fatalf("inline owner changed after rollback: %+v", root)
	}
	if len(root.submenu) != 1 || root.submenu[0].id != 20 {
		t.Fatalf("inline submenu changed after rollback: %+v", root.submenu)
	}
}

func TestChangeLegacyMenuItemRoutesOperations(t *testing.T) {
	reader := func(flags uint32, data uint64) (uint32, string, bool) {
		return flags, "item", data != 0xdead
	}

	t.Run("append", func(t *testing.T) {
		menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}}}}
		if !changeLegacyMenuItem(menus, 1, 99, 0x1234, 20, 0x0100, reader) {
			t.Fatal("append failed")
		}
		if got := menus[1].items; len(got) != 2 || got[1].id != 20 || got[1].text != "item" {
			t.Fatalf("append result = %+v", got)
		}
	})

	t.Run("delete by position destroys submenu", func(t *testing.T) {
		child := &menuData{items: []menuItem{{id: 30}}}
		menus := map[uint64]*menuData{
			1: {items: []menuItem{{id: 10}, {flags: 0x10, submenuHandle: 2, submenuData: child}}},
			2: child,
		}
		if !changeLegacyMenuItem(menus, 1, 1, 0, 99, 0x0200|0x0400, reader) {
			t.Fatal("delete failed")
		}
		if len(menus[1].items) != 1 || menus[2] != nil {
			t.Fatalf("delete result = %+v", menus)
		}
	})

	t.Run("change by position", func(t *testing.T) {
		menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10, text: "old"}}}}
		if !changeLegacyMenuItem(menus, 1, 0, 0x1234, 20, 0x0080|0x0400, reader) {
			t.Fatal("change failed")
		}
		if got := menus[1].items[0]; got.id != 20 || got.text != "item" {
			t.Fatalf("changed item = %+v", got)
		}
	})

	t.Run("remove by command uses new item id", func(t *testing.T) {
		menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}, {id: 20}}}}
		if !changeLegacyMenuItem(menus, 1, 999, 0, 20, 0x1000, reader) {
			t.Fatal("remove failed")
		}
		if got := menus[1].items; len(got) != 1 || got[0].id != 10 {
			t.Fatalf("remove result = %+v", got)
		}
	})

	t.Run("insert and read failure", func(t *testing.T) {
		menus := map[uint64]*menuData{1: {items: []menuItem{{id: 10}}}}
		if !changeLegacyMenuItem(menus, 1, 0, 0x1234, 20, 0x0400, reader) {
			t.Fatal("insert failed")
		}
		if got := menus[1].items; len(got) != 2 || got[0].id != 20 {
			t.Fatalf("insert result = %+v", got)
		}
		if changeLegacyMenuItem(menus, 1, 0, 0xdead, 30, 0x0400, reader) || len(menus[1].items) != 2 {
			t.Fatal("failed read mutated the menu")
		}
	})
}
