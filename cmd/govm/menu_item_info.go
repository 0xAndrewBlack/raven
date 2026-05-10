//go:build guest_windows

package main

import (
	"fmt"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"golang.org/x/text/encoding/charmap"
)

const (
	menuItemStateMask = uint32(0x0000108B)
	menuItemTypeMask  = uint32(0x00006B64)
	miimState         = uint32(0x00000001)
	miimID            = uint32(0x00000002)
	miimSubmenu       = uint32(0x00000004)
	miimCheckmarks    = uint32(0x00000008)
	miimType          = uint32(0x00000010)
	miimData          = uint32(0x00000020)
	miimString        = uint32(0x00000040)
	miimBitmap        = uint32(0x00000080)
	miimFType         = uint32(0x00000100)
	mftBitmap         = uint32(0x00000004)
	mftOwnerDraw      = uint32(0x00000100)
	mftSeparator      = uint32(0x00000800)
)

type menuItemInfoLayout struct {
	legacySize          uint32
	currentSize         uint32
	hSubMenuOffset      uint64
	hbmpCheckedOffset   uint64
	hbmpUncheckedOffset uint64
	dwItemDataOffset    uint64
	dwTypeDataOffset    uint64
	cchOffset           uint64
	hbmpItemOffset      uint64
}

func menuItemInfoLayoutFor(is32 bool) menuItemInfoLayout {
	if is32 {
		return menuItemInfoLayout{
			legacySize: 44, currentSize: 48,
			hSubMenuOffset: 20, hbmpCheckedOffset: 24, hbmpUncheckedOffset: 28,
			dwItemDataOffset: 32, dwTypeDataOffset: 36, cchOffset: 40, hbmpItemOffset: 44,
		}
	}
	return menuItemInfoLayout{
		legacySize: 72, currentSize: 80,
		hSubMenuOffset: 24, hbmpCheckedOffset: 32, hbmpUncheckedOffset: 40,
		dwItemDataOffset: 48, dwTypeDataOffset: 56, cchOffset: 64, hbmpItemOffset: 72,
	}
}

func (layout menuItemInfoLayout) validSize(size uint32) bool {
	return size == layout.legacySize || size == layout.currentSize
}

func readGuestPointer(mem *mmu.MMU, address uint64, is32 bool) (uint64, error) {
	if is32 {
		value, err := mem.Read32(address)
		return uint64(value), err
	}
	return mem.Read64(address)
}

func writeGuestPointer(mem *mmu.MMU, address, value uint64, is32 bool) error {
	if is32 {
		return mem.Write32(address, uint32(value))
	}
	return mem.Write64(address, value)
}

func encodeMenuANSI(value string) ([]byte, error) {
	encoded := make([]byte, 0, len(value))
	for _, char := range value {
		value, ok := charmap.Windows1252.EncodeRune(char)
		if !ok {
			value = '?'
		}
		encoded = append(encoded, value)
	}
	return encoded, nil
}

func decodeMenuANSI(value []byte) (string, error) {
	decoded, err := charmap.Windows1252.NewDecoder().Bytes(value)
	if err != nil {
		return "", fmt.Errorf("decode Windows-1252 menu text: %w", err)
	}
	return string(decoded), nil
}

func ensureMenuItemSubmenu(hmenu uint64, index int, item *menuItem, menus map[uint64]*menuData) uint64 {
	if item == nil || (len(item.submenuItems()) == 0 && item.submenuHandle == 0) {
		return 0
	}
	if item.submenuHandle == 0 {
		candidate := uint64(0x90000)
		for menus[candidate] != nil {
			candidate++
		}
		item.submenuHandle = candidate
	}
	if item.submenuData == nil {
		item.submenuData = menus[item.submenuHandle]
	}
	if item.submenuData == nil && len(item.submenu) > 0 {
		item.submenuData = &menuData{items: item.submenu}
		item.submenu = nil
	}
	if item.submenuData != nil {
		menus[item.submenuHandle] = item.submenuData
	}
	return item.submenuHandle
}

func menuSubmenuWouldCycle(menus map[uint64]*menuData, parent, child uint64) bool {
	if child == 0 {
		return false
	}
	visited := make(map[uint64]struct{})
	var reachesParent func(uint64) bool
	reachesParent = func(handle uint64) bool {
		if handle == parent {
			return true
		}
		if _, seen := visited[handle]; seen {
			return false
		}
		visited[handle] = struct{}{}
		menu := menus[handle]
		if menu == nil {
			return false
		}
		for index := range menu.items {
			if reachesParent(menu.items[index].submenuHandle) {
				return true
			}
		}
		return false
	}
	return reachesParent(child)
}

func findMenuItemRecursive(menu *menuData, item uint64, byPosition bool) *menuItem {
	if menu == nil {
		return nil
	}
	if byPosition {
		index := int(item)
		if index >= 0 && index < len(menu.items) {
			return &menu.items[index]
		}
		return nil
	}
	visited := make(map[*menuData]struct{})
	var find func(*[]menuItem, *menuData) *menuItem
	find = func(items *[]menuItem, current *menuData) *menuItem {
		if current != nil {
			if _, seen := visited[current]; seen {
				return nil
			}
			visited[current] = struct{}{}
		}
		var fallback *menuItem
		for index := range *items {
			entry := &(*items)[index]
			if entry.submenuData != nil {
				if found := find(&entry.submenuData.items, entry.submenuData); found != nil {
					return found
				}
			} else if len(entry.submenu) > 0 {
				if found := find(&entry.submenu, nil); found != nil {
					return found
				}
			}
			if entry.id == item {
				if entry.flags&0x0010 == 0 {
					return entry
				}
				fallback = entry
			}
		}
		return fallback
	}
	return find(&menu.items, menu)
}

func locateMenuItem(menus map[uint64]*menuData, hmenu, item uint64, byPosition bool) (*menuItem, uint64) {
	menu := menus[hmenu]
	if menu == nil {
		return nil, 0
	}
	if byPosition {
		index := int(item)
		if index >= 0 && index < len(menu.items) {
			return &menu.items[index], hmenu
		}
		return nil, 0
	}
	visited := make(map[*menuData]struct{})
	var find func(*menuData, uint64) (*menuItem, uint64)
	find = func(current *menuData, currentHandle uint64) (*menuItem, uint64) {
		if current == nil {
			return nil, 0
		}
		if _, seen := visited[current]; seen {
			return nil, 0
		}
		visited[current] = struct{}{}
		var fallback *menuItem
		for index := range current.items {
			entry := &current.items[index]
			if entry.submenuData != nil || len(entry.submenu) > 0 {
				childHandle := ensureMenuItemSubmenu(currentHandle, index, entry, menus)
				if found, owner := find(entry.submenuData, childHandle); found != nil {
					return found, owner
				}
			}
			if entry.id == item {
				if entry.flags&0x0010 == 0 {
					return entry, currentHandle
				}
				fallback = entry
			}
		}
		return fallback, currentHandle
	}
	return find(menu, hmenu)
}

func withLocatedMenuItem(menus map[uint64]*menuData, hmenu, item uint64, byPosition bool, action func(*menuItem, uint64) bool) bool {
	type itemSnapshot struct {
		item  *menuItem
		value menuItem
	}
	items := make([]itemSnapshot, 0)
	visited := make(map[*menuData]struct{})
	var captureItems func(*[]menuItem)
	var capture func(*menuData)
	capture = func(menu *menuData) {
		if menu == nil {
			return
		}
		if _, seen := visited[menu]; seen {
			return
		}
		visited[menu] = struct{}{}
		captureItems(&menu.items)
	}
	captureItems = func(entries *[]menuItem) {
		for index := range *entries {
			entry := &(*entries)[index]
			items = append(items, itemSnapshot{item: entry, value: *entry})
			if entry.submenuData != nil {
				capture(entry.submenuData)
			} else if len(entry.submenu) > 0 {
				captureItems(&entry.submenu)
			}
		}
	}
	capture(menus[hmenu])
	handles := make(map[uint64]struct{}, len(menus))
	for handle := range menus {
		handles[handle] = struct{}{}
	}
	restore := func() {
		for index := len(items) - 1; index >= 0; index-- {
			*items[index].item = items[index].value
		}
		for handle := range menus {
			if _, existed := handles[handle]; !existed {
				delete(menus, handle)
			}
		}
	}
	found, owner := locateMenuItem(menus, hmenu, item, byPosition)
	if found == nil || action == nil || !action(found, owner) {
		restore()
		return false
	}
	return true
}

func setMenuItemBitmaps(menus map[uint64]*menuData, hmenu, item uint64, byPosition bool, unchecked, checked uint64) bool {
	found := findMenuItemRecursive(menus[hmenu], item, byPosition)
	if found == nil {
		return false
	}
	found.uncheckedBitmap = unchecked
	found.checkedBitmap = checked
	return true
}

func writeMenuString(mem *mmu.MMU, address uint64, capacity int, text string, wide bool) (uint32, bool) {
	if wide {
		units := utf16.Encode([]rune(text))
		if address == 0 || capacity <= 0 {
			return uint32(len(units)), true
		}
		if len(units) >= capacity {
			units = units[:capacity-1]
		}
		size := uint64(len(units)+1) * 2
		if !guestRangeAccessible(mem, address, size, mmu.PermWrite) {
			return 0, false
		}
		for index, unit := range units {
			if mem.Write16(address+uint64(index)*2, unit) != nil {
				return 0, false
			}
		}
		if mem.Write16(address+uint64(len(units))*2, 0) != nil {
			return 0, false
		}
		return uint32(len(units)), true
	}
	encoded, err := encodeMenuANSI(text)
	if err != nil {
		return 0, false
	}
	if address == 0 || capacity <= 0 {
		return uint32(len(encoded)), true
	}
	if len(encoded) >= capacity {
		encoded = encoded[:capacity-1]
	}
	if !guestRangeAccessible(mem, address, uint64(len(encoded)+1), mmu.PermWrite) {
		return 0, false
	}
	if err := mem.WriteBytes(address, append(encoded, 0)); err != nil {
		return 0, false
	}
	return uint32(len(encoded)), true
}

func destroyMenuSubtree(menus map[uint64]*menuData, handle uint64) {
	if handle == 0 {
		return
	}
	destroyed := make(map[uint64]struct{})
	var destroy func(uint64)
	destroy = func(current uint64) {
		if current == 0 {
			return
		}
		if _, seen := destroyed[current]; seen {
			return
		}
		destroyed[current] = struct{}{}
		if menu := menus[current]; menu != nil {
			for index := range menu.items {
				destroy(menu.items[index].submenuHandle)
			}
		}
		delete(menus, current)
	}
	destroy(handle)
	visitedMenus := make(map[*menuData]struct{})
	var invalidate func(*menuData)
	invalidate = func(menu *menuData) {
		if menu == nil {
			return
		}
		if _, seen := visitedMenus[menu]; seen {
			return
		}
		visitedMenus[menu] = struct{}{}
		for index := range menu.items {
			entry := &menu.items[index]
			if _, removed := destroyed[entry.submenuHandle]; removed {
				entry.bindSubmenu(0, nil)
				continue
			}
			invalidate(entry.submenuData)
		}
	}
	for _, menu := range menus {
		invalidate(menu)
	}
}

func menuSubtreeContainsHandle(menus map[uint64]*menuData, root, target uint64) bool {
	visited := make(map[uint64]struct{})
	var contains func(uint64) bool
	contains = func(handle uint64) bool {
		if handle == target {
			return true
		}
		if handle == 0 {
			return false
		}
		if _, seen := visited[handle]; seen {
			return false
		}
		visited[handle] = struct{}{}
		if menu := menus[handle]; menu != nil {
			for index := range menu.items {
				if contains(menu.items[index].submenuHandle) {
					return true
				}
			}
		}
		return false
	}
	return contains(root)
}

func removeMenuItem(menus map[uint64]*menuData, hmenu, item uint64, byPosition, destroySubmenu bool) bool {
	root := menus[hmenu]
	if root == nil {
		return false
	}
	type location struct {
		items *[]menuItem
		index int
	}
	var found *location
	if byPosition {
		index := int(item)
		if index >= 0 && index < len(root.items) {
			found = &location{items: &root.items, index: index}
		}
	} else {
		visited := make(map[*menuData]struct{})
		var find func(*[]menuItem, *menuData) *location
		find = func(items *[]menuItem, current *menuData) *location {
			if current != nil {
				if _, seen := visited[current]; seen {
					return nil
				}
				visited[current] = struct{}{}
			}
			var fallback *location
			for index := range *items {
				entry := &(*items)[index]
				var child *[]menuItem
				if entry.submenuData != nil {
					child = &entry.submenuData.items
				} else if len(entry.submenu) > 0 {
					child = &entry.submenu
				}
				if child != nil {
					if nested := find(child, entry.submenuData); nested != nil {
						return nested
					}
				}
				if entry.id == item {
					candidate := &location{items: items, index: index}
					if entry.flags&0x0010 == 0 {
						return candidate
					}
					fallback = candidate
				}
			}
			return fallback
		}
		found = find(&root.items, root)
	}
	if found == nil {
		return false
	}
	removed := (*found.items)[found.index]
	*found.items = append((*found.items)[:found.index], (*found.items)[found.index+1:]...)
	if destroySubmenu && removed.submenuHandle != 0 {
		destroyMenuSubtree(menus, removed.submenuHandle)
	}
	return true
}

func modifyMenuItem(menus map[uint64]*menuData, hmenu, item uint64, byPosition bool, flags uint32, newItem, itemData uint64, text string) bool {
	const mfPopup = uint32(0x0010)
	if flags&mftSeparator != 0 {
		flags |= 0x0003
	}
	flags &^= 0x1000
	return withLocatedMenuItem(menus, hmenu, item, byPosition, func(found *menuItem, owner uint64) bool {
		oldSubmenu := found.submenuHandle
		updated := *found
		updated.flags = flags & (menuItemStateMask | menuItemTypeMask | mfPopup)
		updated.id = newItem
		updated.text = ""
		updated.itemData = 0
		updated.bitmap = 0
		if flags&mfPopup != 0 {
			submenu := menus[newItem]
			if submenu == nil || menuSubmenuWouldCycle(menus, owner, newItem) ||
				oldSubmenu != 0 && oldSubmenu != newItem && menuSubtreeContainsHandle(menus, oldSubmenu, newItem) {
				return false
			}
			updated.bindSubmenu(newItem, submenu)
		} else {
			updated.bindSubmenu(0, nil)
		}
		switch {
		case flags&mftBitmap != 0:
			updated.bitmap = itemData
		case flags&mftOwnerDraw != 0:
			updated.itemData = itemData
		case flags&mftSeparator == 0:
			updated.text = text
		}
		*found = updated
		if oldSubmenu != 0 && oldSubmenu != updated.submenuHandle {
			destroyMenuSubtree(menus, oldSubmenu)
		}
		return true
	})
}

func insertLegacyMenuItem(menus map[uint64]*menuData, hmenu, item uint64, byPosition bool, flags uint32, newItem, itemData uint64, text string) bool {
	menu := menus[hmenu]
	if menu == nil {
		return false
	}
	target := &menu.items
	owner := hmenu
	index := len(*target)
	rollback := func() {}
	if byPosition {
		if item != uint64(^uint32(0)) && item != ^uint64(0) && item < uint64(len(*target)) {
			index = int(item)
		}
	} else {
		type materializedSubmenu struct {
			item  *menuItem
			value menuItem
		}
		materialized := make([]materializedSubmenu, 0)
		existingHandles := make(map[uint64]struct{}, len(menus))
		for handle := range menus {
			existingHandles[handle] = struct{}{}
		}
		rollback = func() {
			for position := len(materialized) - 1; position >= 0; position-- {
				*materialized[position].item = materialized[position].value
			}
			for handle := range menus {
				if _, existed := existingHandles[handle]; !existed {
					delete(menus, handle)
				}
			}
		}
		type location struct {
			items *[]menuItem
			owner uint64
			index int
			popup bool
		}
		visited := make(map[*menuData]struct{})
		var find func(*[]menuItem, *menuData, uint64) *location
		find = func(items *[]menuItem, current *menuData, currentHandle uint64) *location {
			if current != nil {
				if _, seen := visited[current]; seen {
					return nil
				}
				visited[current] = struct{}{}
			}
			var fallback *location
			for candidate := range *items {
				entry := &(*items)[candidate]
				if entry.submenuData == nil && len(entry.submenu) > 0 {
					materialized = append(materialized, materializedSubmenu{item: entry, value: *entry})
					ensureMenuItemSubmenu(currentHandle, candidate, entry, menus)
				}
				if entry.submenuData != nil {
					if nested := find(&entry.submenuData.items, entry.submenuData, entry.submenuHandle); nested != nil {
						return nested
					}
				}
				if entry.id == item {
					found := &location{items: items, owner: currentHandle, index: candidate, popup: entry.flags&0x0010 != 0}
					if !found.popup {
						return found
					}
					fallback = found
				}
			}
			return fallback
		}
		if found := find(&menu.items, menu, hmenu); found != nil {
			target, owner, index = found.items, found.owner, found.index
		} else {
			rollback()
		}
	}
	const mfPopup = uint32(0x0010)
	if flags&mftSeparator != 0 {
		flags |= 0x0003
	}
	flags &^= 0x1000 | 0x0400
	inserted := menuItem{flags: flags & (menuItemStateMask | menuItemTypeMask), id: newItem}
	if flags&mfPopup != 0 {
		submenu := menus[newItem]
		if submenu != nil {
			if menuSubmenuWouldCycle(menus, owner, newItem) {
				rollback()
				return false
			}
			inserted.bindSubmenu(newItem, submenu)
		}
	}
	switch {
	case flags&mftBitmap != 0:
		inserted.bitmap = itemData
	case flags&mftOwnerDraw != 0:
		inserted.itemData = itemData
	case flags&mftSeparator == 0:
		inserted.text = text
	}
	*target = append(*target, menuItem{})
	copy((*target)[index+1:], (*target)[index:])
	(*target)[index] = inserted
	return true
}

func changeLegacyMenuItem(menus map[uint64]*menuData, hmenu, position, itemData, newItem uint64, flags uint32, readItem func(uint32, uint64) (uint32, string, bool)) bool {
	switch {
	case flags&0x0100 != 0: // MF_APPEND
		itemFlags, text, readable := readItem(flags&^0x0100|0x0400, itemData)
		return readable && insertLegacyMenuItem(menus, hmenu, ^uint64(0), true, itemFlags, newItem, itemData, text)
	case flags&0x0200 != 0: // MF_DELETE
		return removeMenuItem(menus, hmenu, position, flags&0x0400 != 0, true)
	case flags&0x0080 != 0: // MF_CHANGE
		itemFlags, text, readable := readItem(flags&^0x0080, itemData)
		return readable && modifyMenuItem(menus, hmenu, position, itemFlags&0x0400 != 0, itemFlags, newItem, itemData, text)
	case flags&0x1000 != 0: // MF_REMOVE
		target := newItem
		if flags&0x0400 != 0 {
			target = position
		}
		return removeMenuItem(menus, hmenu, target, flags&0x0400 != 0, false)
	default: // MF_INSERT
		itemFlags, text, readable := readItem(flags, itemData)
		return readable && insertLegacyMenuItem(menus, hmenu, position, itemFlags&0x0400 != 0, itemFlags, newItem, itemData, text)
	}
}

func insertMenuItem(mem *mmu.MMU, address uint64, is32, wide bool, hmenu, item uint64, byPosition bool, menus map[uint64]*menuData) bool {
	menu := menus[hmenu]
	if menu == nil {
		return false
	}
	target := &menu.items
	targetMenu := hmenu
	index := len(*target)
	if byPosition {
		if item != uint64(^uint32(0)) && item != ^uint64(0) {
			if item < uint64(len(*target)) {
				index = int(item)
			}
		}
	} else {
		type materializedSubmenu struct {
			item    *menuItem
			submenu []menuItem
			flags   uint32
		}
		materialized := make([]materializedSubmenu, 0)
		visited := make(map[*menuData]struct{})
		var findTarget func(*[]menuItem, *menuData, uint64) (*[]menuItem, uint64, int, bool)
		findTarget = func(items *[]menuItem, current *menuData, handle uint64) (*[]menuItem, uint64, int, bool) {
			if current != nil {
				if _, seen := visited[current]; seen {
					return nil, 0, -1, false
				}
				visited[current] = struct{}{}
			}
			fallback := -1
			for candidate := range *items {
				entry := &(*items)[candidate]
				if entry.submenuData == nil && len(entry.submenu) > 0 {
					materialized = append(materialized, materializedSubmenu{item: entry, submenu: entry.submenu, flags: entry.flags})
					ensureMenuItemSubmenu(handle, candidate, entry, menus)
				}
				if entry.submenuData != nil {
					if nested, nestedHandle, position, found := findTarget(&entry.submenuData.items, entry.submenuData, entry.submenuHandle); found {
						return nested, nestedHandle, position, true
					}
				}
				if entry.id == item {
					if entry.flags&0x0010 == 0 {
						return items, handle, candidate, true
					}
					fallback = candidate
				}
			}
			if fallback >= 0 {
				return items, handle, fallback, true
			}
			return nil, 0, -1, false
		}
		if foundTarget, foundMenu, foundIndex, found := findTarget(&menu.items, menu, hmenu); found {
			target, targetMenu, index = foundTarget, foundMenu, foundIndex
		}
		defer func() {
			if target != nil {
				return
			}
			for materializedIndex := len(materialized) - 1; materializedIndex >= 0; materializedIndex-- {
				entry := materialized[materializedIndex]
				delete(menus, entry.item.submenuHandle)
				entry.item.submenuHandle = 0
				entry.item.submenuData = nil
				entry.item.submenu = entry.submenu
				entry.item.flags = entry.flags
			}
		}()
	}
	inserted := menuItem{}
	if !setMenuItemInfo(mem, address, is32, wide, targetMenu, &inserted, menus) {
		target = nil
		return false
	}
	*target = append(*target, menuItem{})
	copy((*target)[index+1:], (*target)[index:])
	(*target)[index] = inserted
	return true
}

func validMenuItemInfoMask(mask uint32) bool {
	return mask&miimType == 0 || mask&(miimFType|miimString|miimBitmap) == 0
}

func readMenuText(mem *mmu.MMU, address uint64, wide bool) (string, error) {
	if address == 0 {
		return "", nil
	}
	if wide {
		chars := make([]uint16, 0, 64)
		for index := uint64(0); index < 32768; index++ {
			char, err := mem.Read16(address + index*2)
			if err != nil {
				return "", err
			}
			if char == 0 {
				return string(utf16.Decode(chars)), nil
			}
			chars = append(chars, char)
		}
		return "", fmt.Errorf("unterminated Unicode menu text")
	}
	bytes := make([]byte, 0, 64)
	for index := uint64(0); index < 32768; index++ {
		char, err := mem.Read8(address + index)
		if err != nil {
			return "", err
		}
		if char == 0 {
			return decodeMenuANSI(bytes)
		}
		bytes = append(bytes, char)
	}
	return "", fmt.Errorf("unterminated ANSI menu text")
}

func writeMenuText(mem *mmu.MMU, address uint64, capacity uint32, value string, wide bool) (uint32, error) {
	if wide {
		encoded := utf16.Encode([]rune(value))
		if address != 0 && capacity > 0 {
			count := len(encoded)
			if count >= int(capacity) {
				count = int(capacity) - 1
			}
			if !guestRangeAccessible(mem, address, uint64(count+1)*2, mmu.PermWrite) {
				return 0, fmt.Errorf("Unicode menu output is not writable")
			}
			for index := 0; index < count; index++ {
				if err := mem.Write16(address+uint64(index)*2, encoded[index]); err != nil {
					return 0, err
				}
			}
			if err := mem.Write16(address+uint64(count)*2, 0); err != nil {
				return 0, err
			}
		}
		return uint32(len(encoded)), nil
	}
	encoded, err := encodeMenuANSI(value)
	if err != nil {
		return 0, err
	}
	if address != 0 && capacity > 0 {
		count := len(encoded)
		if count >= int(capacity) {
			count = int(capacity) - 1
		}
		if !guestRangeAccessible(mem, address, uint64(count+1), mmu.PermWrite) {
			return 0, fmt.Errorf("ANSI menu output is not writable")
		}
		if err := mem.WriteBytes(address, encoded[:count]); err != nil {
			return 0, err
		}
		if err := mem.Write8(address+uint64(count), 0); err != nil {
			return 0, err
		}
	}
	return uint32(len(encoded)), nil
}

func getMenuItemInfo(mem *mmu.MMU, address uint64, is32, wide bool, hmenu uint64, item *menuItem, menus map[uint64]*menuData) bool {
	if item == nil {
		return false
	}
	layout := menuItemInfoLayoutFor(is32)
	if !guestRangeAccessible(mem, address, 8, mmu.PermRead) {
		return false
	}
	size, err := mem.Read32(address)
	if err != nil || !layout.validSize(size) || !guestRangeAccessible(mem, address, uint64(size), mmu.PermRead|mmu.PermWrite) {
		return false
	}
	mask, err := mem.Read32(address + 4)
	if err != nil || !validMenuItemInfoMask(mask) {
		return false
	}
	var textAddress uint64
	var textCapacity uint32
	if mask&(miimType|miimString) != 0 && (mask&miimType == 0 || item.flags&(mftBitmap|mftOwnerDraw|mftSeparator) == 0) {
		textAddress, err = readGuestPointer(mem, address+layout.dwTypeDataOffset, is32)
		if err != nil {
			return false
		}
		textCapacity, err = mem.Read32(address + layout.cchOffset)
		if err != nil {
			return false
		}
		if textAddress != 0 && textCapacity > 0 {
			units := uint64(len(utf16.Encode([]rune(item.text))))
			unitSize := uint64(2)
			if !wide {
				encoded, encodeErr := encodeMenuANSI(item.text)
				if encodeErr != nil {
					return false
				}
				units, unitSize = uint64(len(encoded)), 1
			}
			if units >= uint64(textCapacity) {
				units = uint64(textCapacity) - 1
			}
			if !guestRangeAccessible(mem, textAddress, (units+1)*unitSize, mmu.PermWrite) {
				return false
			}
		}
	}
	write32 := func(offset uint64, value uint32) bool { return mem.Write32(address+offset, value) == nil }
	writePtr := func(offset, value uint64) bool { return writeGuestPointer(mem, address+offset, value, is32) == nil }
	if mask&miimState != 0 && !write32(12, item.flags&menuItemStateMask) {
		return false
	}
	if mask&(miimType|miimFType) != 0 {
		if !write32(8, item.flags&menuItemTypeMask) {
			return false
		}
	}
	if mask&miimID != 0 && !write32(16, uint32(item.id)) {
		return false
	}
	if mask&miimSubmenu != 0 {
		index := -1
		if menu := menus[hmenu]; menu != nil {
			for candidate := range menu.items {
				if &menu.items[candidate] == item {
					index = candidate
					break
				}
			}
		}
		if index < 0 || !writePtr(layout.hSubMenuOffset, ensureMenuItemSubmenu(hmenu, index, item, menus)) {
			return false
		}
	}
	if mask&miimCheckmarks != 0 && (!writePtr(layout.hbmpCheckedOffset, item.checkedBitmap) || !writePtr(layout.hbmpUncheckedOffset, item.uncheckedBitmap)) {
		return false
	}
	if mask&miimData != 0 && !writePtr(layout.dwItemDataOffset, item.itemData) {
		return false
	}
	if mask&miimBitmap != 0 {
		if size != layout.currentSize || !writePtr(layout.hbmpItemOffset, item.bitmap) {
			return false
		}
	}
	if mask&(miimType|miimString) != 0 {
		if mask&miimType != 0 && item.flags&(mftBitmap|mftOwnerDraw|mftSeparator) != 0 {
			legacyData := uint64(0)
			if item.flags&mftBitmap != 0 {
				legacyData = item.bitmap
			} else if item.flags&mftOwnerDraw != 0 {
				legacyData = item.itemData
			}
			if !writePtr(layout.dwTypeDataOffset, legacyData) || !write32(layout.cchOffset, 0) {
				return false
			}
		} else {
			length, err := writeMenuText(mem, textAddress, textCapacity, item.text, wide)
			if err != nil || !write32(layout.cchOffset, length) {
				return false
			}
		}
	}
	return true
}

func setMenuItemInfo(mem *mmu.MMU, address uint64, is32, wide bool, hmenu uint64, item *menuItem, menus map[uint64]*menuData) bool {
	if item == nil {
		return false
	}
	destination := item
	updated := *item
	item = &updated
	layout := menuItemInfoLayoutFor(is32)
	if !guestRangeAccessible(mem, address, 8, mmu.PermRead) {
		return false
	}
	size, err := mem.Read32(address)
	if err != nil || !layout.validSize(size) || !guestRangeAccessible(mem, address, uint64(size), mmu.PermRead) {
		return false
	}
	mask, err := mem.Read32(address + 4)
	if err != nil || !validMenuItemInfoMask(mask) {
		return false
	}
	readPtr := func(offset uint64) (uint64, bool) {
		value, err := readGuestPointer(mem, address+offset, is32)
		return value, err == nil
	}
	if mask&miimState != 0 {
		value, err := mem.Read32(address + 12)
		if err != nil {
			return false
		}
		item.flags = (item.flags &^ menuItemStateMask) | (value & menuItemStateMask)
	}
	if mask&(miimType|miimFType) != 0 {
		value, err := mem.Read32(address + 8)
		if err != nil || mask&miimFType != 0 && value&mftBitmap != 0 {
			return false
		}
		item.flags = (item.flags &^ menuItemTypeMask) | (value & menuItemTypeMask)
	}
	if mask&miimID != 0 {
		value, err := mem.Read32(address + 16)
		if err != nil {
			return false
		}
		item.id = uint64(value)
	}
	if mask&miimSubmenu != 0 {
		value, ok := readPtr(layout.hSubMenuOffset)
		if !ok {
			return false
		}
		if value != 0 && (menus[value] == nil || menuSubmenuWouldCycle(menus, hmenu, value)) {
			return false
		}
		item.bindSubmenu(value, menus[value])
	}
	if mask&miimCheckmarks != 0 {
		checked, ok := readPtr(layout.hbmpCheckedOffset)
		if !ok {
			return false
		}
		unchecked, ok := readPtr(layout.hbmpUncheckedOffset)
		if !ok {
			return false
		}
		item.checkedBitmap, item.uncheckedBitmap = checked, unchecked
	}
	if mask&miimData != 0 {
		value, ok := readPtr(layout.dwItemDataOffset)
		if !ok {
			return false
		}
		item.itemData = value
	}
	if mask&miimBitmap != 0 {
		if size != layout.currentSize {
			return false
		}
		value, ok := readPtr(layout.hbmpItemOffset)
		if !ok {
			return false
		}
		item.bitmap = value
	}
	if mask&(miimType|miimString) != 0 {
		value, ok := readPtr(layout.dwTypeDataOffset)
		if !ok {
			return false
		}
		if mask&miimType != 0 && item.flags&(mftBitmap|mftOwnerDraw|mftSeparator) != 0 {
			if item.flags&mftBitmap != 0 {
				item.bitmap = value
			} else if item.flags&mftOwnerDraw != 0 {
				item.itemData = value
			}
		} else if value != 0 {
			text, err := readMenuText(mem, value, wide)
			if err != nil {
				return false
			}
			item.text = text
		}
	}
	*destination = updated
	return true
}
