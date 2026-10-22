//go:build guest_windows

// SPDX-License-Identifier: MIT AND LGPL-2.1-or-later AND GPL-2.0-or-later
// Copyright (C) 2003 ReactOS Team
// Derived from ReactOS win32ss/user/user32/windows/nonclient.c and windows/defwnd.c.
// Upstream: https://github.com/reactos/reactos/tree/dacf2a6c47fa562799f9c8a41ab6d5c558556558

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/mirkobrombin/Raven/pkg/arch"
	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/win32"
	"github.com/mirkobrombin/Raven/pkg/wl"
	"golang.org/x/sys/unix"
)

func resolveWindowText(hwnd uint64, children map[uint64]*controlState, titles map[uint64]string) string {
	if cs, ok := children[hwnd]; ok {
		return cs.text
	}
	return titles[hwnd]
}

type accelEntry struct {
	fVirt byte
	key   uint16
	cmd   uint16
}

type ownedDialogDCState struct {
	target *wl.Window
	cpu    arch.CPU
}

type sentMessagePumpCall struct {
	originalSP    uint64
	returnAddress uint64
	argumentCount int
	is32          bool
	arguments     [5]uint64
	resume        func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	waitDeadline  time.Time
}

type sentMessageInFlight struct {
	request *synchronousSendRequest
	pump    *sentMessagePumpCall
}

type crossThreadSendWait struct {
	request       *synchronousSendRequest
	originalSP    uint64
	returnAddress uint64
	is32          bool
}

func sentMessageLoopPump(loopSP, loopPC uint64, is32 bool) *sentMessagePumpCall {
	wordSize := uint64(8)
	if is32 {
		wordSize = 4
	}
	if loopSP < wordSize || loopPC == 0 {
		return nil
	}
	return &sentMessagePumpCall{
		originalSP:    loopSP - wordSize,
		returnAddress: loopPC,
		is32:          is32,
		resume: func(*ntapi.TrapContext, *sentMessagePumpCall) uint32 {
			return 0
		},
	}
}

const maxAcceleratorEntries = 0x10000

func guestRangeAccessible(mem *mmu.MMU, addr, size uint64, perms uint8) bool {
	if size == 0 || addr+size < addr {
		return false
	}
	end := addr + size
	for current := addr; current < end; {
		if _, _, err := mem.LookupRead(current, perms); err != nil {
			return false
		}
		next := (current + mmu.PageSize) &^ (mmu.PageSize - 1)
		if next <= current || next >= end {
			break
		}
		current = next
	}
	return true
}

func readAcceleratorEntries(mem *mmu.MMU, addr uint64, count int) ([]accelEntry, bool) {
	if addr == 0 || count <= 0 || count > maxAcceleratorEntries {
		return nil, false
	}
	if !guestRangeAccessible(mem, addr, uint64(count)*6, mmu.PermRead) {
		return nil, false
	}
	entries := make([]accelEntry, 0, count)
	for i := 0; i < count; i++ {
		base := addr + uint64(i)*6
		fVirt, err := mem.Read8(base)
		if err != nil {
			return nil, false
		}
		key, err := mem.Read16(base + 2)
		if err != nil {
			return nil, false
		}
		cmd, err := mem.Read16(base + 4)
		if err != nil {
			return nil, false
		}
		entries = append(entries, accelEntry{fVirt: fVirt, key: key, cmd: cmd})
	}
	return entries, true
}

func writeAcceleratorEntries(mem *mmu.MMU, addr uint64, entries []accelEntry) bool {
	if addr == 0 {
		return false
	}
	if !guestRangeAccessible(mem, addr, uint64(len(entries))*6, mmu.PermWrite) {
		return false
	}
	for i, entry := range entries {
		base := addr + uint64(i)*6
		if err := mem.Write8(base, entry.fVirt); err != nil {
			return false
		}
		if err := mem.Write8(base+1, 0); err != nil {
			return false
		}
		if err := mem.Write16(base+2, entry.key); err != nil {
			return false
		}
		if err := mem.Write16(base+4, entry.cmd); err != nil {
			return false
		}
	}
	return true
}

func findResourceDirectoryEntry(mem *mmu.MMU, dirAddr, resourceBase uint64, id uint32, name string) (uint32, bool) {
	const (
		maxResourceDirectoryEntries = 65536
		maxResourceNameUnits        = 4096
		maxResourceNameWork         = 1 << 20
	)
	namedCount, err := mem.Read16(dirAddr + 12)
	if err != nil {
		return 0, false
	}
	idCount, err := mem.Read16(dirAddr + 14)
	if err != nil {
		return 0, false
	}
	total := uint64(namedCount) + uint64(idCount)
	if total > maxResourceDirectoryEntries {
		return 0, false
	}
	wantName := utf16Encode(name)
	if len(wantName) > maxResourceNameUnits {
		return 0, false
	}
	if len(wantName) > 0 && total > uint64(maxResourceNameWork/len(wantName)) {
		return 0, false
	}
	for i := uint64(0); i < total; i++ {
		entry := dirAddr + 16 + i*8
		nameField, err := mem.Read32(entry)
		if err != nil {
			return 0, false
		}
		offset, err := mem.Read32(entry + 4)
		if err != nil {
			return 0, false
		}
		if name == "" {
			if nameField == id {
				return offset, true
			}
			continue
		}
		if nameField&0x80000000 == 0 {
			continue
		}
		nameAddr := resourceBase + uint64(nameField&0x7fffffff)
		length, err := mem.Read16(nameAddr)
		if err != nil || int(length) != len(wantName) || length > maxResourceNameUnits {
			continue
		}
		resourceName := make([]uint16, length)
		matched := true
		for j := range resourceName {
			got, err := mem.Read16(nameAddr + 2 + uint64(j)*2)
			if err != nil {
				matched = false
				break
			}
			resourceName[j] = got
		}
		if matched && strings.EqualFold(string(utf16.Decode(resourceName)), name) {
			return offset, true
		}
	}
	return 0, false
}

func loadNamedResource(mem *mmu.MMU, moduleBase uint64, resourceRVA, typeID uint32, name string) (uint64, uint32, bool) {
	if moduleBase == 0 || resourceRVA == 0 || name == "" {
		return 0, 0, false
	}
	resourceBase := moduleBase + uint64(resourceRVA)
	typeOffset, ok := findResourceDirectoryEntry(mem, resourceBase, resourceBase, typeID, "")
	if !ok || typeOffset&0x80000000 == 0 {
		return 0, 0, false
	}
	typeDir := resourceBase + uint64(typeOffset&0x7fffffff)
	nameOffset, ok := findResourceDirectoryEntry(mem, typeDir, resourceBase, 0, name)
	if !ok || nameOffset&0x80000000 == 0 {
		return 0, 0, false
	}
	languageDir := resourceBase + uint64(nameOffset&0x7fffffff)
	namedCount, err := mem.Read16(languageDir + 12)
	if err != nil {
		return 0, 0, false
	}
	idCount, err := mem.Read16(languageDir + 14)
	if err != nil || namedCount+idCount == 0 {
		return 0, 0, false
	}
	dataOffset, err := mem.Read32(languageDir + 20)
	if err != nil || dataOffset&0x80000000 != 0 {
		return 0, 0, false
	}
	dataEntry := resourceBase + uint64(dataOffset)
	dataRVA, err := mem.Read32(dataEntry)
	if err != nil {
		return 0, 0, false
	}
	dataSize, err := mem.Read32(dataEntry + 4)
	if err != nil || dataRVA == 0 || dataSize == 0 {
		return 0, 0, false
	}
	dataAddr := moduleBase + uint64(dataRVA)
	if !guestRangeAccessible(mem, dataAddr, uint64(dataSize), mmu.PermRead) {
		return 0, 0, false
	}
	return dataAddr, dataSize, true
}

func destroyAcceleratorTable(tables map[uint64][]accelEntry, mu *sync.RWMutex, handle uint64) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := tables[handle]; !ok {
		return false
	}
	delete(tables, handle)
	return true
}

func dialogTabItems(children map[uint64]*controlState, order []uint64, dialog uint64) []uint64 {
	const (
		wsTabStop         = uint32(0x00010000)
		wsDisabled        = uint32(0x08000000)
		wsExControlParent = uint32(0x00010000)
	)
	items := make([]uint64, 0)
	var visit func(uint64)
	visit = func(parent uint64) {
		for _, hwnd := range order {
			control := children[hwnd]
			if control == nil || control.parentHWND != parent || !control.visible || control.style&wsDisabled != 0 {
				continue
			}
			if control.style&wsTabStop != 0 {
				items = append(items, hwnd)
			}
			if control.exStyle&wsExControlParent != 0 {
				visit(hwnd)
			}
		}
	}
	visit(dialog)
	return items
}

func nextDialogTabItem(children map[uint64]*controlState, order []uint64, dialog, current uint64, previous bool) uint64 {
	items := dialogTabItems(children, order, dialog)
	if len(items) == 0 {
		return 0
	}
	index := -1
	for i, hwnd := range items {
		if hwnd == current {
			index = i
			break
		}
	}
	if previous {
		if index <= 0 {
			return items[len(items)-1]
		}
		return items[index-1]
	}
	if index < 0 || index+1 == len(items) {
		return items[0]
	}
	return items[index+1]
}

func dialogGroupMembers(children map[uint64]*controlState, order []uint64, dialog, current uint64) []uint64 {
	const (
		wsGroup           = uint32(0x00020000)
		wsDisabled        = uint32(0x08000000)
		wsExControlParent = uint32(0x00010000)
	)
	ordered := make([]uint64, 0)
	var visit func(uint64)
	visit = func(parent uint64) {
		for _, hwnd := range order {
			control := children[hwnd]
			if control == nil || control.parentHWND != parent {
				continue
			}
			ordered = append(ordered, hwnd)
			if control.visible && control.style&wsDisabled == 0 && control.exStyle&wsExControlParent != 0 {
				visit(hwnd)
			}
		}
	}
	visit(dialog)
	if len(ordered) == 0 {
		return nil
	}
	index := 0
	for i, hwnd := range ordered {
		if hwnd == current {
			index = i
			break
		}
	}
	start := index
	for start > 0 && children[ordered[start]].style&wsGroup == 0 {
		start--
	}
	end := start + 1
	for end < len(ordered) && children[ordered[end]].style&wsGroup == 0 {
		end++
	}
	return append([]uint64(nil), ordered[start:end]...)
}

func dialogGroupItems(children map[uint64]*controlState, order []uint64, dialog, current uint64) []uint64 {
	members := dialogGroupMembers(children, order, dialog, current)
	items := make([]uint64, 0, len(members))
	for _, hwnd := range members {
		if dialogControlAvailable(children, hwnd, dialog) {
			items = append(items, hwnd)
		}
	}
	return items
}

func dialogGroupTraversalItems(children map[uint64]*controlState, order []uint64, dialog uint64) []uint64 {
	const wsExControlParent = uint32(0x00010000)
	items := make([]uint64, 0)
	var visit func(uint64)
	visit = func(parent uint64) {
		for _, hwnd := range order {
			control := children[hwnd]
			if control == nil || control.parentHWND != parent || !dialogControlAvailable(children, hwnd, dialog) {
				continue
			}
			items = append(items, hwnd)
			if control.exStyle&wsExControlParent != 0 {
				visit(hwnd)
			}
		}
	}
	visit(dialog)
	return items
}

func nextDialogGroupItem(children map[uint64]*controlState, order []uint64, dialog, current uint64, previous bool) uint64 {
	if current == 0 {
		items := dialogGroupTraversalItems(children, order, dialog)
		if len(items) == 0 {
			return 0
		}
		if previous {
			return items[len(items)-1]
		}
		return items[0]
	}
	if !windowBelongsToDialog(children, current, dialog) {
		return 0
	}
	members := dialogGroupMembers(children, order, dialog, current)
	index := -1
	for i, hwnd := range members {
		if hwnd == current {
			index = i
			break
		}
	}
	if index < 0 {
		return 0
	}
	step := 1
	if previous {
		step = -1
	}
	for offset := 1; offset <= len(members); offset++ {
		candidateIndex := (index + step*offset) % len(members)
		if candidateIndex < 0 {
			candidateIndex += len(members)
		}
		candidate := members[candidateIndex]
		if dialogControlAvailable(children, candidate, dialog) {
			return candidate
		}
	}
	return current
}

func selectAutoRadioButton(children map[uint64]*controlState, order []uint64, dialog, selected uint64) bool {
	control := children[selected]
	if control == nil || !strings.EqualFold(control.className, "button") || control.style&0x0f != 9 {
		return false
	}
	for _, hwnd := range dialogGroupMembers(children, order, dialog, selected) {
		candidate := children[hwnd]
		if candidate != nil && strings.EqualFold(candidate.className, "button") && (candidate.style&0x0f == 4 || candidate.style&0x0f == 9) {
			candidate.checkState = 0
		}
	}
	control.checkState = 1
	return true
}

func windowBelongsToDialog(children map[uint64]*controlState, hwnd, dialog uint64) bool {
	for hwnd != 0 {
		if hwnd == dialog {
			return true
		}
		control := children[hwnd]
		if control == nil || control.parentHWND == hwnd {
			return false
		}
		hwnd = control.parentHWND
	}
	return false
}

func dialogControlAvailable(children map[uint64]*controlState, hwnd, dialog uint64) bool {
	const wsDisabled = uint32(0x08000000)
	for hwnd != 0 && hwnd != dialog {
		control := children[hwnd]
		if control == nil || !control.visible || control.style&wsDisabled != 0 {
			return false
		}
		hwnd = control.parentHWND
	}
	return hwnd == dialog
}

func dialogControlWantsKey(control *controlState, vk uint32) bool {
	if control == nil {
		return false
	}
	className := strings.ToLower(control.className)
	switch className {
	case "button", "combobox", "listbox", "static", "edit", "richedit", "richedit20a", "richedit20w":
		if (className == "edit" || strings.HasPrefix(className, "richedit")) && vk == 0x0d {
			const (
				esMultiline  = uint32(0x0004)
				esWantReturn = uint32(0x1000)
			)
			return control.style&(esMultiline|esWantReturn) == esMultiline|esWantReturn
		}
		return false
	default:
		return true
	}
}

func reorderWindow(order []uint64, hwnd, insertAfter uint64) []uint64 {
	reordered, _ := reorderWindowGrouped(order, hwnd, insertAfter, nil)
	return reordered
}

func insertZOrderAt(order []uint64, index int, hwnd uint64) []uint64 {
	order = append(order, 0)
	copy(order[index+1:], order[index:])
	order[index] = hwnd
	return order
}

func reorderWindowGrouped(order []uint64, hwnd, insertAfter uint64, topmost map[uint64]bool) ([]uint64, bool) {
	index := -1
	for i, candidate := range order {
		if candidate == hwnd {
			index = i
			break
		}
	}
	if index < 0 {
		return order, false
	}
	const (
		hwndTop    = uint64(0)
		hwndBottom = uint64(1)
	)
	hwndTopmost := insertAfter == ^uint64(0) || insertAfter == uint64(^uint32(0))
	hwndNotTopmost := insertAfter == ^uint64(1) || insertAfter == uint64(^uint32(1))
	if insertAfter != hwndTop && insertAfter != hwndBottom && !hwndTopmost && !hwndNotTopmost {
		found := insertAfter == hwnd
		for _, candidate := range order {
			if candidate == insertAfter {
				found = true
				break
			}
		}
		if !found {
			return order, false
		}
	}
	order = append(order[:index], order[index+1:]...)
	if topmost == nil {
		topmost = make(map[uint64]bool)
	}
	if insertAfter == hwndBottom {
		topmost[hwnd] = false
		return append(order, hwnd), true
	}
	if hwndTopmost {
		topmost[hwnd] = true
		return insertZOrderAt(order, 0, hwnd), true
	}
	topmostEnd := 0
	for topmostEnd < len(order) && topmost[order[topmostEnd]] {
		topmostEnd++
	}
	if hwndNotTopmost {
		topmost[hwnd] = false
		return insertZOrderAt(order, topmostEnd, hwnd), true
	}
	if insertAfter == hwndTop || insertAfter == hwnd {
		target := 0
		if !topmost[hwnd] {
			target = topmostEnd
		}
		return insertZOrderAt(order, target, hwnd), true
	}
	for i, candidate := range order {
		if candidate == insertAfter {
			target := i + 1
			if topmost[hwnd] && !topmost[candidate] {
				target = topmostEnd
			} else if !topmost[hwnd] && topmost[candidate] && target < topmostEnd {
				target = topmostEnd
			}
			return insertZOrderAt(order, target, hwnd), true
		}
	}
	return order, false
}

func writeMessageMetadata(mem *mmu.MMU, pMsg uint64, is32 bool, messageTime uint32, x, y int32) bool {
	timeOffset := uint64(32)
	if is32 {
		timeOffset = 16
	}
	if !guestRangeAccessible(mem, pMsg+timeOffset, 12, mmu.PermWrite) {
		return false
	}
	if err := mem.Write32(pMsg+timeOffset, messageTime); err != nil {
		return false
	}
	if err := mem.Write32(pMsg+timeOffset+4, uint32(x)); err != nil {
		return false
	}
	return mem.Write32(pMsg+timeOffset+8, uint32(y)) == nil
}

func packMessagePos(x, y int32) uint32 {
	return uint32(uint16(x)) | uint32(uint16(y))<<16
}

func writeQueuedMessage(mem *mmu.MMU, pMsg uint64, is32 bool, msg queuedMsg) bool {
	// MSG includes the private field after POINT in both Win32 layouts.
	structSize := uint64(48)
	if is32 {
		structSize = 32
	}
	if !guestRangeAccessible(mem, pMsg, structSize, mmu.PermWrite) {
		return false
	}
	if is32 {
		return mem.Write32(pMsg, uint32(msg.hwnd)) == nil &&
			mem.Write32(pMsg+4, msg.message) == nil &&
			mem.Write32(pMsg+8, uint32(msg.wParam)) == nil &&
			mem.Write32(pMsg+12, uint32(msg.lParam)) == nil &&
			writeMessageMetadata(mem, pMsg, true, msg.time, msg.x, msg.y) &&
			mem.Write32(pMsg+28, 0) == nil
	}
	return mem.Write64(pMsg, msg.hwnd) == nil &&
		mem.Write32(pMsg+8, msg.message) == nil &&
		mem.Write32(pMsg+12, 0) == nil &&
		mem.Write64(pMsg+16, msg.wParam) == nil &&
		mem.Write64(pMsg+24, msg.lParam) == nil &&
		writeMessageMetadata(mem, pMsg, false, msg.time, msg.x, msg.y) &&
		mem.Write32(pMsg+44, 0) == nil
}

func win32MessageMatches(message uint32, hwnd, hwndFilter uint64, minMessage, maxMessage uint32, isDescendant func(uint64, uint64) bool) bool {
	if message == 0x0012 { // WM_QUIT bypasses message and window filters.
		return true
	}
	if hwndFilter == ^uint64(0) || hwndFilter == uint64(^uint32(0)) {
		if hwnd != 0 {
			return false
		}
	} else if hwndFilter != 0 && hwnd != hwndFilter && (isDescendant == nil || !isDescendant(hwnd, hwndFilter)) {
		return false
	}
	if minMessage == 0 && maxMessage == 0 {
		return true
	}
	return message >= minMessage && message <= maxMessage
}

func builtinMessageNeedsCommit(message uint32) bool {
	return message == 0x000F || message == 0x0014 || message == 0x0085
}

func windowPosNeedsRepaint(flags uint32, visible bool) bool {
	const swpNoRedraw = 0x0008
	return visible && flags&swpNoRedraw == 0
}

func windowPosParentNeedsRepaint(flags uint32, wasVisible, visible bool) bool {
	const swpNoRedraw = 0x0008
	return (wasVisible || visible) && flags&swpNoRedraw == 0
}

type leftClickTracker struct {
	hwnd uint64
	x    int32
	y    int32
	at   time.Time
}

func (t *leftClickTracker) press(now time.Time, hwnd uint64, x, y int32, classStyle uint32, interval time.Duration) uint32 {
	const (
		csDblClks       = 0x0008
		wmLButtonDown   = 0x0201
		wmLButtonDblClk = 0x0203
	)
	isDoubleClick := classStyle&csDblClks != 0 &&
		t.hwnd == hwnd &&
		now.Sub(t.at) <= interval &&
		abs32(x-t.x) <= 2 &&
		abs32(y-t.y) <= 2
	if isDoubleClick {
		*t = leftClickTracker{}
		return wmLButtonDblClk
	}
	*t = leftClickTracker{hwnd: hwnd, x: x, y: y, at: now}
	return wmLButtonDown
}

func abs32(value int32) int32 {
	if value < 0 {
		return -value
	}
	return value
}

func normalizeDoubleClickTime(value uint32) uint32 {
	if value == 0 {
		return 500
	}
	if value > 5000 {
		return 5000
	}
	return value
}

const (
	cwpSkipInvisible          = uint32(0x0001)
	cwpSkipDisabled           = uint32(0x0002)
	cwpSkipTransparent        = uint32(0x0004)
	cwpSkipHitTestTransparent = uint32(0x80000000)
	cwpReturnHitTestFallback  = uint32(0x40000000)
	cwpSkipStatic             = uint32(0x20000000)
)

func decodePointArgs(first, second uint64, is32 bool) (int32, int32) {
	if is32 {
		return int32(uint32(first)), int32(uint32(second))
	}
	return int32(uint32(first)), int32(uint32(first >> 32))
}

func orderedChildWindows(children map[uint64]*controlState, order []uint64, parent uint64) []uint64 {
	result := make([]uint64, 0)
	seen := make(map[uint64]bool, len(order))
	for _, hwnd := range order {
		seen[hwnd] = true
		child := children[hwnd]
		if child != nil && child.parentHWND == parent {
			result = append(result, hwnd)
		}
	}
	var unordered []uint64
	for hwnd, child := range children {
		if !seen[hwnd] && child != nil && child.parentHWND == parent {
			unordered = append(unordered, hwnd)
		}
	}
	sort.Slice(unordered, func(i, j int) bool { return unordered[i] > unordered[j] })
	return append(result, unordered...)
}

func backToFrontChildWindows(children map[uint64]*controlState, order []uint64, parent uint64) []uint64 {
	result := orderedChildWindows(children, order, parent)
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func childPaintOrder(children map[uint64]*controlState, order []uint64, parent uint64) []uint64 {
	return backToFrontChildWindows(children, order, parent)
}

func childWindowAtPoint(children map[uint64]*controlState, order []uint64, parent uint64, x, y int32, flags uint32) uint64 {
	var fallback uint64
	for _, hwnd := range orderedChildWindows(children, order, parent) {
		child := children[hwnd]
		if child.w <= 0 || child.h <= 0 {
			continue
		}
		if flags&cwpSkipInvisible != 0 && !child.visible {
			continue
		}
		if flags&cwpSkipDisabled != 0 && child.style&0x08000000 != 0 {
			continue
		}
		if flags&cwpSkipTransparent != 0 && child.exStyle&0x00000020 != 0 {
			continue
		}
		if x < child.x || x >= child.x+child.w || y < child.y || y >= child.y+controlHitHeight(child) {
			continue
		}
		if flags&cwpSkipStatic != 0 && strings.EqualFold(child.className, "static") {
			continue
		}
		if flags&cwpSkipHitTestTransparent != 0 &&
			strings.EqualFold(child.className, "button") && child.style&0x0f == 7 {
			if flags&cwpReturnHitTestFallback != 0 && fallback == 0 {
				fallback = hwnd
			}
			continue
		}
		return hwnd
	}
	return fallback
}

func deepestVisibleWindowAtPoint(children map[uint64]*controlState, order []uint64, parent uint64, x, y int32) uint64 {
	for _, hwnd := range orderedChildWindows(children, order, parent) {
		child := children[hwnd]
		if !child.visible || child.style&win32.WS_DISABLED != 0 || child.w <= 0 || child.h <= 0 ||
			x < child.x || x >= child.x+child.w || y < child.y || y >= child.y+controlHitHeight(child) {
			continue
		}
		deepest := deepestVisibleWindowAtPoint(children, order, hwnd, x, y)
		transparent := strings.EqualFold(child.className, "static") ||
			strings.EqualFold(child.className, "button") && child.style&0x0f == 7
		if deepest != hwnd || !transparent {
			return deepest
		}
	}
	return parent
}

func windowClientGeometry(children map[uint64]*controlState, hwnd uint64) (x, y, width, height int32) {
	if wnd := win32.Global.Get(hwnd); wnd != nil {
		return wnd.RcClient.Left, wnd.RcClient.Top, wnd.RcClient.Width(), wnd.RcClient.Height()
	}
	if state := children[hwnd]; state != nil {
		return state.x, state.y, state.w, state.h
	}
	return 0, 0, 0, 0
}

func windowFromPoint(children map[uint64]*controlState, order []uint64, main uint64, mainRect win32.Rect, x, y int32) uint64 {
	seen := make(map[uint64]bool, len(order))
	hit := func(hwnd uint64) bool {
		seen[hwnd] = true
		state := children[hwnd]
		wnd := win32.Global.Get(hwnd)
		style := uint32(0)
		visible := false
		rect := win32.Rect{}
		if state != nil {
			style = state.style
			visible = state.visible
			rect = win32.Rect{Left: state.x, Top: state.y, Right: state.x + state.w, Bottom: state.y + state.h}
			if wnd != nil {
				rect = wnd.RcWindow
			}
		} else if wnd != nil {
			style = wnd.Style
			visible = style&win32.WS_VISIBLE != 0
			rect = wnd.RcWindow
		} else if hwnd == main {
			style = win32.WS_VISIBLE
			visible = true
			rect = mainRect
		}
		if style&win32.WS_CHILD != 0 || !visible || style&win32.WS_DISABLED != 0 || rect.Empty() {
			return false
		}
		return x >= rect.Left && x < rect.Right && y >= rect.Top && y < rect.Bottom
	}
	for _, hwnd := range order {
		if hit(hwnd) {
			return deepestVisibleWindowAtPoint(children, order, hwnd, x, y)
		}
	}
	var unordered []uint64
	for hwnd := range children {
		if !seen[hwnd] {
			unordered = append(unordered, hwnd)
			seen[hwnd] = true
		}
	}
	for _, hwnd := range win32.Global.AllWindows() {
		if !seen[hwnd] {
			unordered = append(unordered, hwnd)
			seen[hwnd] = true
		}
	}
	if main != 0 && !seen[main] {
		unordered = append(unordered, main)
	}
	sort.Slice(unordered, func(i, j int) bool { return unordered[i] > unordered[j] })
	for _, hwnd := range unordered {
		if hit(hwnd) {
			return deepestVisibleWindowAtPoint(children, order, hwnd, x, y)
		}
	}
	return 0
}

func writeComboBoxInfo(mem *mmu.MMU, pInfo, hwnd uint64, is32 bool, width, height int32, comboType uint32, dropped bool) bool {
	if pInfo == 0 {
		return false
	}
	structSize := uint32(64)
	handleSize := uint64(8)
	if is32 {
		structSize = 52
		handleSize = 4
	}
	cbSize, err := mem.Read32(pInfo)
	if err != nil || cbSize < structSize {
		return false
	}
	if width < 0 {
		width = 0
	}
	if height < 0 {
		height = 0
	}
	closedHeight := height
	if closedHeight > 24 {
		closedHeight = 24
	}
	buttonWidth := int32(17)
	if comboType == 1 {
		buttonWidth = 0
	}
	if buttonWidth > width {
		buttonWidth = width
	}
	itemRight := width - buttonWidth

	for offset, value := range map[uint64]int32{
		4:  0,
		8:  0,
		12: itemRight,
		16: closedHeight,
		20: itemRight,
		24: 0,
		28: width,
		32: closedHeight,
	} {
		if err := mem.Write32(pInfo+offset, uint32(value)); err != nil {
			return false
		}
	}
	buttonState := uint32(0)
	if comboType == 1 {
		buttonState = 0x00008000 // STATE_SYSTEM_INVISIBLE
	} else if dropped {
		buttonState = 0x00000008 // STATE_SYSTEM_PRESSED
	}
	if err := mem.Write32(pInfo+36, buttonState); err != nil {
		return false
	}
	if is32 {
		if err := mem.Write32(pInfo+40, uint32(hwnd)); err != nil {
			return false
		}
	} else if err := mem.Write64(pInfo+40, hwnd); err != nil {
		return false
	}
	for offset := uint64(40) + handleSize; offset < uint64(structSize); offset += handleSize {
		if is32 {
			if err := mem.Write32(pInfo+offset, uint32(hwnd)); err != nil {
				return false
			}
		} else if err := mem.Write64(pInfo+offset, hwnd); err != nil {
			return false
		}
	}
	return true
}

func writeComboBoxInfoForTrap(ctx *ntapi.TrapContext, pInfo, hwnd uint64, width, height int32, comboType uint32, dropped bool) bool {
	return writeComboBoxInfo(ctx.Mem, pInfo, hwnd, ctx.State != nil && ctx.State.Is32, width, height, comboType, dropped)
}

const desktopWindowHandle = uint64(0x00050000)

type windowDisabledRegistry struct {
	mu     sync.RWMutex
	values map[uint64]bool
}

func (r *windowDisabledRegistry) get(hwnd uint64) (bool, bool) {
	r.mu.RLock()
	disabled, ok := r.values[hwnd]
	r.mu.RUnlock()
	return disabled, ok
}

func (r *windowDisabledRegistry) set(hwnd uint64, disabled bool) {
	r.mu.Lock()
	if r.values == nil {
		r.values = make(map[uint64]bool)
	}
	r.values[hwnd] = disabled
	r.mu.Unlock()
}

func (r *windowDisabledRegistry) remove(hwnd uint64) {
	r.mu.Lock()
	delete(r.values, hwnd)
	r.mu.Unlock()
}

func isRegisteredWindow(hwnd, mainHWND uint64) bool {
	if hwnd == 0 {
		return false
	}
	if hwnd == desktopWindowHandle || hwnd == mainHWND {
		return true
	}
	return win32.Global.Get(hwnd) != nil
}

func windowCleanupHandles(root uint64, children map[uint64]*controlState) []uint64 {
	if root == 0 {
		return nil
	}
	handles := []uint64{root}
	for hwnd := range children {
		if hwnd != root && isControlDescendant(children, hwnd, root) {
			handles = append(handles, hwnd)
		}
	}
	return handles
}

func pruneDestroyedWindowMessages(queue *messageQueue, root uint64, children map[uint64]*controlState) {
	if queue == nil || root == 0 {
		return
	}
	queue.mu.Lock()
	kept := queue.items[:0]
	for _, message := range queue.items {
		if message.hwnd != root && !isControlDescendant(children, message.hwnd, root) {
			kept = append(kept, message)
		}
	}
	queue.items = kept
	queue.mu.Unlock()
}

func windowOrAncestorDestroyPending(hwnd uint64, pending map[uint64]bool, children map[uint64]*controlState) bool {
	for hwnd != 0 {
		if pending[hwnd] {
			return true
		}
		state := children[hwnd]
		if state == nil || state.parentHWND == hwnd {
			return false
		}
		hwnd = state.parentHWND
	}
	return false
}

func windowHierarchyVisible(hwnd uint64, children map[uint64]*controlState) bool {
	for hwnd != 0 {
		state := children[hwnd]
		if state == nil {
			return true
		}
		if !state.visible {
			return false
		}
		if state.parentHWND == hwnd {
			return false
		}
		hwnd = state.parentHWND
	}
	return true
}

func windowIsDescendantOrSelf(hwnd, root uint64, children map[uint64]*controlState) bool {
	for hwnd != 0 {
		if hwnd == root {
			return true
		}
		state := children[hwnd]
		if state == nil || state.parentHWND == hwnd {
			return false
		}
		hwnd = state.parentHWND
	}
	return false
}

func isHostBuiltinControlClass(className string) bool {
	className = strings.ToLower(className)
	switch className {
	case "button", "edit", "static", "listbox", "combobox", "comboboxex32",
		"scrollbar", "mdiclient", "tooltips_class32", "toolbarwindow32",
		"rebarwindow32", "sysheader32", "syslistview32", "systabcontrol32",
		"msctls_statusbar32", "msctls_progress32", "msctls_trackbar32",
		"richedit", "richedit20a", "richedit20w", "richedit50w":
		return true
	}
	return strings.HasPrefix(className, "msctls_")
}

func overlappingGuestSiblings(
	hwnd uint64,
	children map[uint64]*controlState,
	wndProcs map[uint64]uint64,
	order []uint64,
) []uint64 {
	state := children[hwnd]
	if state == nil || !isHostBuiltinControlClass(state.className) ||
		state.style&win32.WS_CLIPSIBLINGS == 0 {
		return nil
	}
	var result []uint64
	for _, siblingHWND := range orderedChildWindows(children, order, state.parentHWND) {
		if siblingHWND == hwnd {
			break
		}
		sibling := children[siblingHWND]
		if sibling == nil ||
			isHostBuiltinControlClass(sibling.className) || wndProcs[siblingHWND] == 0 ||
			!windowHierarchyVisible(siblingHWND, children) {
			continue
		}
		if state.x < sibling.x+sibling.w && state.x+state.w > sibling.x &&
			state.y < sibling.y+sibling.h && state.y+state.h > sibling.y {
			result = append(result, siblingHWND)
		}
	}
	return result
}

func childScrollbarRects(state *controlState) (vertical, horizontal, corner win32.Rect, hasVertical, hasHorizontal bool) {
	if state == nil || state.w <= 0 || state.h <= 0 {
		return
	}
	hasVertical = state.style&win32.WS_VSCROLL != 0
	hasHorizontal = state.style&win32.WS_HSCROLL != 0
	if !hasVertical && !hasHorizontal {
		return
	}
	right := state.x + state.w
	bottom := state.y + state.h
	clientRight := right
	clientBottom := bottom
	if hasVertical {
		clientRight -= win32.GetSystemMetrics(win32.SM_CXVSCROLL)
	}
	if hasHorizontal {
		clientBottom -= win32.GetSystemMetrics(win32.SM_CYHSCROLL)
	}
	if clientRight < state.x {
		clientRight = state.x
	}
	if clientBottom < state.y {
		clientBottom = state.y
	}
	if hasVertical {
		vertical = win32.Rect{Left: clientRight, Top: state.y, Right: right, Bottom: clientBottom}
	}
	if hasHorizontal {
		horizontal = win32.Rect{Left: state.x, Top: clientBottom, Right: clientRight, Bottom: bottom}
	}
	if hasVertical && hasHorizontal {
		corner = win32.Rect{Left: clientRight, Top: clientBottom, Right: right, Bottom: bottom}
	}
	return
}

func isControlDescendant(children map[uint64]*controlState, hwnd, root uint64) bool {
	for hwnd != 0 {
		state := children[hwnd]
		if state == nil {
			return false
		}
		hwnd = state.parentHWND
		if hwnd == root {
			return true
		}
	}
	return false
}

func cleanupWindowRegistration(hwnd uint64, disabled *windowDisabledRegistry) {
	disabled.remove(hwnd)
	win32.Global.Destroy(hwnd)
}

func cleanupHandlerWindowState(hctx *HandlerCtx, hwnd uint64) {
	if hctx == nil {
		return
	}
	if hctx.ReleaseDialogPaintDC != nil {
		hctx.ReleaseDialogPaintDC(hwnd)
	}
	hctx.clearWindowCPU(hwnd)
	if hctx.ClearSubclasses != nil {
		hctx.ClearSubclasses(hwnd)
	}
	clearDarkModeWindowState(hwnd)
	clearOwnedDialogColor(hwnd)
	hctx.removeZOrder(hwnd)
	delete(hctx.HwndChildren, hwnd)
	delete(hctx.HwndWndProc, hwnd)
	delete(hctx.HwndTitle, hwnd)
	delete(hctx.HwndExplicitlyHidden, hwnd)
	delete(hctx.WindowLongPtr, hwnd)
	delete(hctx.HwndClassAtom, hwnd)
	delete(hctx.WindowProps, hwnd)
	delete(hctx.WinErasePending, hwnd)
	delete(hctx.WinInvalid, hwnd)
	delete(win32uWindowRgns, hwnd)
	delete(win32uLayeredWindows, hwnd)
	win32.Global.Destroy(hwnd)
}

func registerGlobalWindow(hwnd uint64, state *controlState) bool {
	if state == nil || win32.Global.Get(hwnd) != nil {
		return false
	}
	win32.Global.Create(hwnd, state.className, state.x, state.y, state.w, state.h,
		state.style, state.exStyle, state.parentHWND)
	return true
}

func dispatchGuestWindowMessage(hctx *HandlerCtx, hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
	if hctx == nil || hwnd == 0 {
		return 0, false
	}
	wndProc := hctx.HwndWndProc[hwnd]
	if wndProc == 0 {
		if atom, ok := hctx.HwndClassAtom[hwnd]; ok {
			wndProc = hctx.AtomWndProc[atom]
			if wndProc != 0 {
				hctx.HwndWndProc[hwnd] = wndProc
			}
		}
	}
	cpu := hctx.windowCPU(hwnd)
	if cpu == nil {
		cpu = hctx.GetCurrentCPU()
	}
	if wndProc == 0 || cpu == nil || hctx.GuestCallTrampoline == nil {
		return 0, false
	}
	result, err := ntapi.CallGuestFunction(cpu, hctx.Mem, hctx.GuestCallTrampoline, wndProc,
		[]uint64{hwnd, uint64(msg), wParam, lParam}, false)
	return result, err == nil
}

func clearGuestStruct(mem *mmu.MMU, addr, size uint64) {
	for offset := uint64(0); offset < size; offset += 4 {
		_ = mem.Write32(addr+offset, 0)
	}
}

func writeCustomDrawStruct(
	hctx *HandlerCtx,
	addr, hwnd, hdc uint64,
	stage uint32,
	item, itemParam uint64,
	state uint32,
	rect [4]int32,
) {
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	layout := customDrawOffsets(is32)
	className := ""
	if control := hctx.HwndChildren[hwnd]; control != nil {
		className = control.className
	}
	clearGuestStruct(hctx.Mem, addr, customDrawStructureSize(className, is32))
	if is32 {
		hctx.Mem.Write32(addr, uint32(hwnd))
		hctx.Mem.Write32(addr+4, uint32(hctx.HwndChildren[hwnd].ctrlID))
		hctx.Mem.Write32(addr+8, nmCustomDraw)
		hctx.Mem.Write32(addr+layout.hdc, uint32(hdc))
		hctx.Mem.Write32(addr+layout.itemSpec, uint32(item))
		hctx.Mem.Write32(addr+layout.itemParam, uint32(itemParam))
	} else {
		hctx.Mem.Write64(addr, hwnd)
		hctx.Mem.Write64(addr+8, hctx.HwndChildren[hwnd].ctrlID)
		hctx.Mem.Write32(addr+16, nmCustomDraw)
		hctx.Mem.Write64(addr+layout.hdc, hdc)
		hctx.Mem.Write64(addr+layout.itemSpec, item)
		hctx.Mem.Write64(addr+layout.itemParam, itemParam)
	}
	hctx.Mem.Write32(addr+layout.drawStage, stage)
	for i := range rect {
		hctx.Mem.Write32(addr+layout.rect+uint64(i*4), uint32(rect[i]))
	}
	hctx.Mem.Write32(addr+layout.itemState, state)
}

type hostCustomDrawItem struct {
	key   uint64
	spec  uint64
	param uint64
	state uint32
	rect  [4]int32
}

func hostCustomDrawItems(state *controlState) []hostCustomDrawItem {
	if state == nil {
		return nil
	}
	switch strings.ToLower(state.className) {
	case "toolbarwindow32":
		if state.toolbar == nil {
			return nil
		}
		buttonHeight := state.tbBtnH
		if buttonHeight <= 0 {
			buttonHeight = 22
		}
		if buttonHeight > state.h-2 {
			buttonHeight = state.h - 2
		}
		geometry := layoutToolbarButtons(state.toolbar, state.tbBtnW)
		items := make([]hostCustomDrawItem, 0, len(state.toolbar.buttons))
		for index, button := range state.toolbar.buttons {
			itemGeometry := geometry[index]
			if !itemGeometry.visible {
				continue
			}
			itemState := uint32(0)
			if button.state&0x04 == 0 {
				itemState |= 0x0004 // CDIS_DISABLED
			}
			if button.state&0x01 != 0 {
				itemState |= 0x0008 // CDIS_CHECKED
			}
			if button.state&0x02 != 0 {
				itemState |= 0x0001 // CDIS_SELECTED
			}
			items = append(items, hostCustomDrawItem{
				key:   uint64(index),
				spec:  uint64(uint32(button.id)),
				param: button.param,
				state: itemState,
				rect:  [4]int32{itemGeometry.left, 2, itemGeometry.right, 2 + buttonHeight},
			})
		}
		return items
	case "msctls_statusbar32":
		items := make([]hostCustomDrawItem, 0, len(state.sbParts))
		left := int32(0)
		for index, right := range state.sbParts {
			if right < 0 || right > state.w {
				right = state.w
			}
			items = append(items, hostCustomDrawItem{
				key:  uint64(index),
				spec: uint64(index),
				rect: [4]int32{left, 0, right, state.h},
			})
			left = right
		}
		return items
	case "systabcontrol32":
		if state.tab == nil {
			return nil
		}
		items := make([]hostCustomDrawItem, 0, len(state.tab.items))
		left := int32(2)
		for index, tab := range state.tab.items {
			width := tabControlItemWidth(tab.text)
			itemState := uint32(0)
			if index == state.tab.curSel {
				itemState = 0x0001 // CDIS_SELECTED
			}
			items = append(items, hostCustomDrawItem{
				key:   uint64(index),
				spec:  uint64(index),
				param: tab.param,
				state: itemState,
				rect:  [4]int32{left, 2, left + width, 24},
			})
			left += width
		}
		return items
	case "sysheader32":
		if state.header != nil {
			items := make([]hostCustomDrawItem, 0, len(state.header.items))
			left := int32(0)
			for index, header := range state.header.items {
				width := header.width
				if width <= 0 {
					width = 80
				}
				items = append(items, hostCustomDrawItem{
					key:   uint64(index),
					spec:  uint64(index),
					param: header.param,
					state: header.state,
					rect:  [4]int32{left, 0, left + width, state.h},
				})
				left += width
			}
			return items
		}
	case "syslistview32":
		if state.listView == nil {
			return nil
		}
		count := len(state.listView.items)
		if state.listView.style&0x1000 != 0 {
			count = state.listView.virtualCount
		}
		items := make([]hostCustomDrawItem, 0, count)
		const (
			rowTop    = int32(24)
			rowHeight = int32(18)
		)
		for index := 0; index < count; index++ {
			top := rowTop + int32(index)*rowHeight
			if top+rowHeight > state.h-1 {
				break
			}
			item := hostCustomDrawItem{
				key:  uint64(index),
				spec: uint64(index),
				rect: [4]int32{2, top, state.w - 2, top + rowHeight},
			}
			if index < len(state.listView.items) {
				listItem := state.listView.items[index]
				item.param = listItem.param
				if listItem.state&0x0002 != 0 {
					item.state = 0x0001 // CDIS_SELECTED
				}
			}
			items = append(items, item)
		}
		return items
	case "systreeview32":
		if state.treeView == nil || state.treeView.root == nil {
			return nil
		}
		items := make([]hostCustomDrawItem, 0, len(state.treeViewIndex))
		top := int32(2)
		const itemHeight = int32(18)
		var appendVisible func([]*tvItem)
		appendVisible = func(treeItems []*tvItem) {
			for _, treeItem := range treeItems {
				if treeItem == nil || top+itemHeight > state.h-1 {
					continue
				}
				itemState := uint32(0)
				if state.treeView.selected == treeItem || treeItem.state&0x0002 != 0 {
					itemState = 0x0001 // CDIS_SELECTED
				}
				items = append(items, hostCustomDrawItem{
					key:   treeItem.handle,
					spec:  treeItem.handle,
					param: treeItem.param,
					state: itemState,
					rect:  [4]int32{2, top, state.w - 2, top + itemHeight},
				})
				top += itemHeight
				if treeItem.expanded {
					appendVisible(treeItem.children)
				}
			}
		}
		appendVisible(state.treeView.root.children)
		return items
	}
	return nil
}

type hostCustomDrawSession struct {
	hctx   *HandlerCtx
	parent uint64
	child  uint64
	addr   uint64
	hdc    uint64
	post   bool
	items  []hostCustomDrawItem
	skip   map[uint64]struct{}
}

func beginHostCustomDraw(hctx *HandlerCtx, hwnd uint64, state *controlState) (*hostCustomDrawSession, bool) {
	if hctx == nil || state == nil || state.parentHWND == 0 || hctx.ScratchAlloc == nil || hctx.AllocScreenDC == nil {
		return nil, false
	}
	switch strings.ToLower(state.className) {
	case "toolbarwindow32", "rebarwindow32", "msctls_statusbar32", "systabcontrol32",
		"sysheader32", "syslistview32", "systreeview32":
	default:
		return nil, false
	}
	hdc, _ := hctx.AllocScreenDC(state.x, state.y)
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	addr := hctx.ScratchAlloc(customDrawStructureSize(state.className, is32))
	fullRect := [4]int32{0, 0, state.w, state.h}
	writeCustomDrawStruct(hctx, addr, hwnd, hdc, cddsPrePaint, 0, 0, 0, fullRect)
	result, _ := dispatchGuestWindowMessage(hctx, state.parentHWND, 0x004E, state.ctrlID, addr)
	session := &hostCustomDrawSession{
		hctx: hctx, parent: state.parentHWND, child: hwnd, addr: addr, hdc: hdc,
		post: result&cdrfNotifyPostPaint != 0,
	}
	skip := result&cdrfSkipDefault != 0
	if result&cdrfNotifyItemDraw != 0 {
		for _, item := range hostCustomDrawItems(state) {
			writeCustomDrawStruct(hctx, addr, hwnd, hdc, cddsItem|cddsPrePaint,
				item.spec, item.param, item.state, item.rect)
			itemResult, _ := dispatchGuestWindowMessage(hctx, state.parentHWND, 0x004E, state.ctrlID, addr)
			if itemResult&cdrfSkipDefault != 0 {
				if session.skip == nil {
					session.skip = make(map[uint64]struct{})
				}
				session.skip[item.key] = struct{}{}
			}
			if itemResult&cdrfNotifyPostPaint != 0 {
				session.items = append(session.items, item)
			}
		}
	}
	return session, skip
}

func (session *hostCustomDrawSession) finish(state *controlState) {
	if session == nil {
		return
	}
	defer state.setCustomDrawSkipped(nil)
	for _, item := range session.items {
		writeCustomDrawStruct(session.hctx, session.addr, session.child, session.hdc,
			cddsItem|cddsPostPaint, item.spec, item.param, item.state, item.rect)
		_, _ = dispatchGuestWindowMessage(session.hctx, session.parent, 0x004E, state.ctrlID, session.addr)
	}
	if session.post {
		writeCustomDrawStruct(session.hctx, session.addr, session.child, session.hdc,
			cddsPostPaint, 0, 0, 0, [4]int32{0, 0, state.w, state.h})
		_, _ = dispatchGuestWindowMessage(session.hctx, session.parent, 0x004E, state.ctrlID, session.addr)
	}
	session.hctx.GdiMgr.DeleteDC(session.hdc)
}

type hostCtlColor struct {
	hdc   uint64
	dc    *gdi.DC
	brush uint64
}

func beginHostCtlColor(hctx *HandlerCtx, hwnd uint64, state *controlState) *hostCtlColor {
	message := ctlColorMessageForClass(state.className)
	if message == 0 || state.parentHWND == 0 || hctx.AllocScreenDC == nil {
		return nil
	}
	hdc, dc := hctx.AllocScreenDC(state.x, state.y)
	dc.SetClipRect(state.x, state.y, state.x+state.w, state.y+state.h)
	brush, _ := dispatchGuestWindowMessage(hctx, state.parentHWND, message, hdc, hwnd)
	return &hostCtlColor{hdc: hdc, dc: dc, brush: brush}
}

func (paint *hostCtlColor) finish(hctx *HandlerCtx, state *controlState) {
	if paint == nil {
		return
	}
	if paint.brush != 0 {
		fillRectUsingBrushHandle(paint.dc, hctx.GdiMgr, paint.brush, hctx.SysColors, 0, 0, state.w, state.h)
		switch strings.ToLower(state.className) {
		case "static":
			paint.dc.TextOut(2, 2, dialogLabel(state.text), false)
		case "edit", "richedit20w", "richedit50w":
			paint.dc.TextOut(4, 4, state.text, false)
		}
	}
	hctx.GdiMgr.DeleteDC(paint.hdc)
}

func remapWaylandRectForDarkMode(win *wl.Window, left, top, right, bottom int32) {
	if win == nil {
		return
	}
	surface := gdi.WrapPix(win.Pix, win.Width, win.Height+win.TitleBarH, win.Stride)
	dc := gdi.NewScreenDC(surface)
	remapDCRectForDarkMode(dc, left, top, right, bottom)
}

func waylandRectColorCount(win *wl.Window, left, top, right, bottom int32) int {
	if win == nil {
		return 0
	}
	if left < 0 {
		left = 0
	}
	if top < 0 {
		top = 0
	}
	if right > win.Width {
		right = win.Width
	}
	if bottom > win.Height+win.TitleBarH {
		bottom = win.Height + win.TitleBarH
	}
	colors := make(map[uint32]struct{})
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			offset := int(y*win.Width+x) * 4
			if offset+3 >= len(win.Pix) {
				continue
			}
			color := uint32(win.Pix[offset]) |
				uint32(win.Pix[offset+1])<<8 |
				uint32(win.Pix[offset+2])<<16 |
				uint32(win.Pix[offset+3])<<24
			colors[color] = struct{}{}
		}
	}
	return len(colors)
}

func repaintAfterSurfaceResize(hctx *HandlerCtx, hwnd uint64, mainWindow bool, queuePaint func(uint64)) {
	if hctx == nil {
		return
	}
	if mainWindow {
		hctx.RepaintBuiltin = true
	}
	if queuePaint != nil {
		queuePaint(hwnd)
	}
}

func prepareMainSurfacePaintCommit(hctx *HandlerCtx, hwnd uint64) {
	if hctx == nil || !hctx.HasBaseFrame {
		return
	}
	if hwnd != hctx.MainHWND {
		hctx.RepaintBuiltin = true
	}
	hctx.FrameReady = true
}

func writeUAHMenuStruct(hctx *HandlerCtx, addr, menu, hdc uint64) {
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	layout := uahMenuOffsets(is32)
	clearGuestStruct(hctx.Mem, addr, layout.size)
	if is32 {
		hctx.Mem.Write32(addr, uint32(menu))
		hctx.Mem.Write32(addr+layout.hdc, uint32(hdc))
		return
	}
	hctx.Mem.Write64(addr, menu)
	hctx.Mem.Write64(addr+layout.hdc, hdc)
}

func writeUAHDrawItemStruct(
	hctx *HandlerCtx,
	addr, hwnd, hdc uint64,
	item *menuItem,
	itemIndex uint32,
	left, top, right, bottom int32,
) {
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	layout := uahDrawItemOffsets(is32)
	clearGuestStruct(hctx.Mem, addr, layout.size)
	hctx.Mem.Write32(addr, 1) // ODT_MENU
	hctx.Mem.Write32(addr+8, itemIndex)
	if item != nil {
		hctx.Mem.Write32(addr+4, uint32(item.id))
		hctx.Mem.Write32(addr+12, item.flags)
		if is32 {
			hctx.Mem.Write32(addr+layout.itemData, uint32(item.itemData))
		} else {
			hctx.Mem.Write64(addr+layout.itemData, item.itemData)
		}
	}
	if is32 {
		hctx.Mem.Write32(addr+layout.hwndItem, uint32(hwnd))
		hctx.Mem.Write32(addr+layout.hdc, uint32(hdc))
	} else {
		hctx.Mem.Write64(addr+layout.hwndItem, hwnd)
		hctx.Mem.Write64(addr+layout.hdc, hdc)
	}
	hctx.Mem.Write32(addr+layout.rect, uint32(left))
	hctx.Mem.Write32(addr+layout.rect+4, uint32(top))
	hctx.Mem.Write32(addr+layout.rect+8, uint32(right))
	hctx.Mem.Write32(addr+layout.rect+12, uint32(bottom))
}

func dispatchUAHMenuMessages(hctx *HandlerCtx, owner, menu uint64, popup *popupMenuState) {
	if hctx == nil || owner == 0 || menu == 0 || hctx.ScratchAlloc == nil || hctx.AllocScreenDC == nil {
		return
	}
	hdc, _ := hctx.AllocScreenDC(0, 0)
	defer hctx.GdiMgr.DeleteDC(hdc)
	is32 := hctx.ProcState != nil && hctx.ProcState.Is32
	menuLayout := uahMenuOffsets(is32)
	menuAddr := hctx.ScratchAlloc(menuLayout.size)
	writeUAHMenuStruct(hctx, menuAddr, menu, hdc)
	_, _ = dispatchGuestWindowMessage(hctx, owner, wmUAHInitMenu, menu, 0)
	_, _ = dispatchGuestWindowMessage(hctx, owner, wmUAHDrawMenu, 0, menuAddr)
	if popup == nil {
		return
	}
	itemLayout := uahDrawItemOffsets(is32)
	itemAddr := hctx.ScratchAlloc(itemLayout.size)
	for index := range popup.Items {
		top := popup.Y + int32(index)*popup.ItemHeight
		writeUAHDrawItemStruct(hctx, itemAddr, menu, hdc, &popup.Items[index], uint32(index),
			popup.X, top, popup.X+popup.Width, top+popup.ItemHeight)
		_, _ = dispatchGuestWindowMessage(hctx, owner, wmUAHDrawMenuItem, 0, itemAddr)
	}
}

func changeWindowEnabled(
	hwnd uint64,
	enabled, notify bool,
	setDisabled func(uint64, bool) (bool, bool),
	send func(uint64, uint32, uint64),
) (bool, bool) {
	wasDisabled, present := setDisabled(hwnd, !enabled)
	if !present {
		return false, false
	}
	if notify && wasDisabled == enabled {
		if !enabled {
			send(hwnd, 0x001F, 0) // WM_CANCELMODE
		}
		wParam := uint64(0)
		if enabled {
			wParam = 1
		}
		send(hwnd, 0x000A, wParam) // WM_ENABLE
	}
	return wasDisabled, true
}

type rebarPaintRect struct {
	left, top, right, bottom int32
}

func subtractRebarPaintRect(regions []rebarPaintRect, cover rebarPaintRect) []rebarPaintRect {
	result := make([]rebarPaintRect, 0, len(regions)+3)
	for _, region := range regions {
		left := max(region.left, cover.left)
		top := max(region.top, cover.top)
		right := min(region.right, cover.right)
		bottom := min(region.bottom, cover.bottom)
		if left >= right || top >= bottom {
			result = append(result, region)
			continue
		}
		if region.top < top {
			result = append(result, rebarPaintRect{region.left, region.top, region.right, top})
		}
		if bottom < region.bottom {
			result = append(result, rebarPaintRect{region.left, bottom, region.right, region.bottom})
		}
		if region.left < left {
			result = append(result, rebarPaintRect{region.left, top, left, bottom})
		}
		if right < region.right {
			result = append(result, rebarPaintRect{right, top, region.right, bottom})
		}
	}
	return result
}

func paintRebarUncoveredArea(hctx *HandlerCtx, hwnd uint64, state *controlState, color uint32) {
	if hctx == nil || hctx.WlWindow == nil || state == nil {
		return
	}
	regions := []rebarPaintRect{{
		left: state.x, top: state.y,
		right: state.x + state.w, bottom: state.y + state.h,
	}}
	for _, candidate := range hctx.HwndChildren {
		if candidate == nil || !candidate.visible || !strings.EqualFold(candidate.className, "toolbarwindow32") {
			continue
		}
		if candidate.parentHWND != hwnd && candidate.parentHWND != state.parentHWND {
			continue
		}
		regions = subtractRebarPaintRect(regions, rebarPaintRect{
			left: candidate.x, top: candidate.y,
			right: candidate.x + candidate.w, bottom: candidate.y + candidate.h,
		})
	}
	for _, region := range regions {
		hctx.WlWindow.DrawRectAbs(region.left, region.top, region.right, region.bottom, color)
	}
}

func registerUser32Handlers(hctx *HandlerCtx) {
	allocScreenDC := hctx.AllocScreenDC
	bitmapHandles := hctx.BitmapHandles
	setUserLastError := func(ctx *ntapi.TrapContext, value uint32) {
		if ctx.State == nil {
			return
		}
		offset := uint64(ntapi.TebLastErrorValue)
		if ctx.State.Is32 {
			offset = ntapi.Teb32LastErrorValue
		}
		ctx.Mem.Write32(ctx.State.TEBAddr+offset, value)
	}
	baseBuiltinWndProc := hctx.BuiltinWndProc
	builtinWndProc := func(hwnd uint64, msg uint32, wParam, lParam uint64) (uint64, bool) {
		if baseBuiltinWndProc == nil {
			return 0, false
		}
		state := hctx.HwndChildren[hwnd]
		if msg != 0x000F || state == nil {
			if state != nil && msg == 0x0005 {
				if root, target, ownedDialog := topLevelDialogTarget(hctx, hwnd); ownedDialog && target != nil {
					if normalizeOwnedStatusBar(state, hctx.HwndChildren[root], target.Width, target.Height) {
						if wnd := win32.Global.Get(hwnd); wnd != nil {
							win32.Global.UpdatePos(wnd, state.x, state.y, state.w, state.h)
						}
						return 0, true
					}
				}
			}
			return baseBuiltinWndProc(hwnd, msg, wParam, lParam)
		}
		if root, target, ownedDialog := topLevelDialogTarget(hctx, hwnd); ownedDialog && target != nil {
			if normalizeOwnedStatusBar(state, hctx.HwndChildren[root], target.Width, target.Height) {
				if wnd := win32.Global.Get(hwnd); wnd != nil {
					win32.Global.UpdatePos(wnd, state.x, state.y, state.w, state.h)
				}
			}
			return baseBuiltinWndProc(hwnd, msg, wParam, lParam)
		}

		dark := effectiveDarkModeForWindow(hwnd, hctx.HwndChildren)
		if strings.EqualFold(state.className, "rebarwindow32") {
			background := hctx.SysColors[15]
			if dark {
				background = darkPalette.Control
			}
			paintRebarUncoveredArea(hctx, hwnd, state, background)
		}
		var ctlColor *hostCtlColor
		var customDraw *hostCustomDrawSession
		skipDefault := false
		if dark {
			ctlColor = beginHostCtlColor(hctx, hwnd, state)
		}
		customDraw, skipDefault = beginHostCustomDraw(hctx, hwnd, state)
		if customDraw != nil {
			state.setCustomDrawSkipped(customDraw.skip)
		}
		result, handled := uint64(0), true
		if skipDefault {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
		} else {
			result, handled = baseBuiltinWndProc(hwnd, msg, wParam, lParam)
		}
		traceToolbar := os.Getenv("RAVEN_TRACE_TOOLBAR") != "" &&
			strings.EqualFold(state.className, "toolbarwindow32")
		if traceToolbar {
			ravelog.Logf("[toolbar-paint-stage] base colors=%d\n",
				waylandRectColorCount(hctx.WlWindow, state.x, state.y, state.x+state.w, state.y+state.h))
		}
		if handled && dark && !strings.EqualFold(state.className, "toolbarwindow32") {
			remapWaylandRectForDarkMode(hctx.WlWindow, state.x, state.y, state.x+state.w, state.y+state.h)
		}
		if traceToolbar {
			ravelog.Logf("[toolbar-paint-stage] remap colors=%d\n",
				waylandRectColorCount(hctx.WlWindow, state.x, state.y, state.x+state.w, state.y+state.h))
		}
		ctlColor.finish(hctx, state)
		customDraw.finish(state)
		if traceToolbar {
			ravelog.Logf("[toolbar-paint-stage] finish colors=%d\n",
				waylandRectColorCount(hctx.WlWindow, state.x, state.y, state.x+state.w, state.y+state.h))
		}
		return result, handled
	}
	hctx.BuiltinWndProc = builtinWndProc
	clientAreaOrigin := hctx.ClientAreaOrigin
	commitIfDone := hctx.CommitIfDone
	d := hctx.Disp
	decodeDIBSlots := hctx.DecodeDIBSlots
	dibDimensions := func(address uint64) (int, int) {
		widthValue, widthErr := hctx.Mem.Read32(address + 4)
		heightValue, heightErr := hctx.Mem.Read32(address + 8)
		if widthErr != nil || heightErr != nil {
			return 0, 0
		}
		width, height := int(int32(widthValue)), int(int32(heightValue))
		if width < 0 {
			width = -width
		}
		if height < 0 {
			height = -height
		}
		return width, height
	}
	gdiAlloc := hctx.GdiAlloc
	gdiMgr := hctx.GdiMgr
	getDC := hctx.GetDCFn
	getSysColor := hctx.GetSysColor
	hwndAlloc := hctx.HwndAlloc
	hwndChildren := hctx.HwndChildren
	hwndExplicitlyHidden := hctx.HwndExplicitlyHidden
	hwndMenuBar := hctx.HwndMenuBar
	hwndTitle := hctx.HwndTitle
	hwndWndProc := hctx.HwndWndProc
	var leftClicks leftClickTracker
	doubleClickTime := uint32(500)
	paintedThroughHiddenAncestor := make(map[uint64]bool)
	mainModule := hctx.MainModule
	mem := hctx.Mem
	menuStripAmpersand := hctx.MenuStripAmpersand
	menus := hctx.Menus
	ncDrawText := hctx.NcDrawText
	paintTree := hctx.PaintTree
	peLoadMenuResource := hctx.PeLoadMenuResource
	peLoadRawResource := hctx.PeLoadRawResource
	peLoadStringW := hctx.PeLoadStringW
	loadResourceIcon := func(resourceID uint32, desiredWidth, desiredHeight int32) *iconHandleData {
		decodeResource := func(resourceType, id uint32) *iconHandleData {
			address, size, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, resourceType, id)
			if !ok || size == 0 || size > 64<<20 {
				return nil
			}
			data, err := mem.ReadBytes(address, int(size))
			if err != nil {
				return nil
			}
			icon, ok := decodeIconResource(data)
			if !ok {
				return nil
			}
			icon.pixels = scaleIconPixels(icon, desiredWidth, desiredHeight)
			if desiredWidth > 0 {
				icon.width = desiredWidth
			}
			if desiredHeight > 0 {
				icon.height = desiredHeight
			}
			return icon
		}
		groupAddress, groupSize, hasGroup := peLoadRawResource(
			mainModule.BaseAddr, mainModule.ResourceDirRVA, 14, resourceID,
		)
		if hasGroup && groupSize > 0 && groupSize <= 1<<20 {
			if groupData, err := mem.ReadBytes(groupAddress, int(groupSize)); err == nil {
				if iconID := selectGroupIconResource(groupData, desiredWidth, desiredHeight); iconID != 0 {
					if icon := decodeResource(3, iconID); icon != nil {
						return icon
					}
				}
			}
		}
		return decodeResource(3, resourceID)
	}
	queuePaint := hctx.QueuePaint
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestUTF16N := hctx.ReadGuestUTF16N
	scratchAlloc := hctx.ScratchAlloc
	syncScreenSurface := hctx.SyncScreenSurface
	windowLongPtr := hctx.WindowLongPtr
	windowProps := hctx.WindowProps
	destroyPending := make(map[uint64]bool)
	destroyDelivered := make(map[uint64]bool)
	ownedDCWindows := make(map[uint64]ownedDialogDCState)
	var ownedDCWindowsMu sync.Mutex
	ownedPaintCPUs := make(map[uint64][]arch.CPU)
	var ownedPaintCPUsMu sync.Mutex
	wlDisplay := hctx.WlDisplay
	wlWindow := hctx.WlWindow
	normalizeOwnedStatusGeometry := func(hwnd uint64) {
		state := hwndChildren[hwnd]
		if state == nil {
			return
		}
		root, target, owned := topLevelDialogTarget(hctx, hwnd)
		if !owned || target == nil ||
			!normalizeOwnedStatusBar(state, hwndChildren[root], target.Width, target.Height) {
			return
		}
		if wnd := win32.Global.Get(hwnd); wnd != nil {
			win32.Global.UpdatePos(wnd, state.x, state.y, state.w, state.h)
		}
	}
	baseDrawMenuOverlay := hctx.DrawMenuOverlay
	hctx.DrawMenuOverlay = func() {
		if baseDrawMenuOverlay == nil {
			return
		}
		baseDrawMenuOverlay()
		popup := hctx.ActivePopupMenu
		if popup == nil || !effectiveDarkModeForWindow(popup.OwnerHWND, hctx.HwndChildren) {
			return
		}
		remapWaylandRectForDarkMode(hctx.WlWindow, popup.X, popup.Y,
			popup.X+popup.Width+2, popup.Y+popup.Height+2)
		dispatchUAHMenuMessages(hctx, popup.OwnerHWND, popup.Menu, popup)
	}
	baseDrawDialogOverlay := hctx.DrawDialogOverlay
	hctx.DrawDialogOverlay = func() {
		if baseDrawDialogOverlay == nil {
			return
		}
		baseDrawDialogOverlay()
		if !hctx.DialogActive || !effectiveDarkModeForWindow(hctx.MainHWND, hctx.HwndChildren) ||
			hctx.WlWindow == nil {
			return
		}
		const width, height = int32(340), int32(180)
		left := (hctx.WlWindow.Width - width) / 2
		top := (hctx.WlWindow.Height + hctx.WlWindow.TitleBarH - height) / 2
		remapWaylandRectForDarkMode(hctx.WlWindow, left, top, left+width, top+height)
	}

	var hwndDisabled windowDisabledRegistry
	var hwndLifecycleMu sync.Mutex
	hasWindowSubclass := func(hwnd uint64) bool {
		return hctx.HasWindowSubclass != nil && hctx.HasWindowSubclass(hwnd)
	}
	isKnownWindow := func(hwnd uint64) bool {
		return isRegisteredWindow(hwnd, hctx.MainHWND)
	}
	isWindowDisabled := func(hwnd uint64) bool {
		disabled, overridden := hwndDisabled.get(hwnd)
		if overridden {
			return disabled
		}
		return win32.Global.GetLong(hwnd, win32.GWL_STYLE)&win32.WS_DISABLED != 0
	}
	applyWindowEnabledStyle := func(hwnd uint64, index int32, value uint64) uint64 {
		if index != win32.GWL_STYLE {
			return value
		}
		disabled, overridden := hwndDisabled.get(hwnd)
		if !overridden {
			return value
		}
		if disabled {
			return value | uint64(win32.WS_DISABLED)
		}
		return value &^ uint64(win32.WS_DISABLED)
	}
	setWindowDisabled := func(hwnd uint64, disabled bool) (bool, bool) {
		wasDisabled, present := win32.Global.SetDisabled(hwnd, disabled)
		if !present {
			if !isKnownWindow(hwnd) {
				return false, false
			}
			wasDisabled = isWindowDisabled(hwnd)
		}
		hwndDisabled.set(hwnd, disabled)
		return wasDisabled, true
	}
	hwndWindowRgn := make(map[uint64]uint64)
	windowCompositionAttributes := make(map[uint64]map[uint32][]byte)
	var keyState [256]byte
	keyTransition := make(map[uint32]bool)
	pendingKeyChars := make(map[uint32]rune)
	var currentCursorHandle uint64 = 32512 // IDC_ARROW default
	const wsVisible = uint32(0x10000000)
	const builtinControlWndProcID uint32 = 0x3FFC
	builtinControlWndProc := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	mem.Write8(builtinControlWndProc, 0xB8) // MOV EAX, imm32
	mem.Write32(builtinControlWndProc+1, builtinControlWndProcID)
	mem.Write8(builtinControlWndProc+5, 0x0F) // VMCALL
	mem.Write8(builtinControlWndProc+6, 0x01)
	mem.Write8(builtinControlWndProc+7, 0xC1)
	mem.Write8(builtinControlWndProc+8, 0xC3) // RET
	d.RegisterHandler(builtinControlWndProcID, "builtinControlWndProc", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
			ctx.SetReturn(result)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	isBuiltinControl := func(hwnd uint64) bool {
		state := hwndChildren[hwnd]
		if state == nil {
			return false
		}
		switch strings.ToLower(state.className) {
		case "button", "edit", "static", "listbox", "combobox", "comboboxex32",
			"systabcontrol32", "msctls_trackbar32", "msctls_statusbar32",
			"toolbarwindow32", "rebarwindow32", "tooltips_class32":
			return true
		}
		return false
	}
	syncWindowVisibleStyle := func(hwnd uint64, visible bool) {
		style := uint32(win32.Global.GetLong(hwnd, -16))
		if m := windowLongPtr[hwnd]; m != nil && m[-16] != 0 {
			style = uint32(m[-16])
		}
		if cs := hwndChildren[hwnd]; cs != nil {
			style = cs.style
		}
		if visible {
			style |= wsVisible
		} else {
			style &^= wsVisible
		}
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		m[-16] = uint64(style)
		win32.Global.SetLong(hwnd, -16, uint64(style))
		if cs := hwndChildren[hwnd]; cs != nil {
			cs.style = style
		}
	}

	dialogVisible := func(info *dlgInfo, modal bool) bool {
		if modal {
			return true
		}
		return info != nil && info.style&wsVisible != 0
	}
	cursorPosX, cursorPosY := int32(0), int32(0)
	isBuiltinWindowClassName := func(name string) bool {
		switch strings.ToLower(name) {
		case "button", "edit", "static", "listbox", "combobox", "comboboxex32",
			"scrollbar", "mdiclient", "tooltips_class32", "toolbarwindow32",
			"rebarwindow32", "sysheader32", "syslistview32", "systabcontrol32",
			"msctls_statusbar32", "msctls_progress32", "msctls_trackbar32",
			"richedit", "richedit20a", "richedit20w", "richedit50w":
			return true
		}
		return strings.HasPrefix(strings.ToLower(name), "msctls_")
	}

	// Shared timer-expiry check: posts WM_TIMER for each expired timer.
	// Called from GetMessageA/W and PeekMessageA/W.
	checkTimers := func(cpu arch.CPU) {
		now := time.Now()
		for _, timer := range hctx.Timers.expire(cpu, now) {
			if hctx.MsgQueue.contains(func(message queuedMsg) bool {
				return messageOwnedBy(message, cpu) &&
					message.message == 0x0113 &&
					message.hwnd == timer.hwnd &&
					message.wParam == timer.id
			}) {
				continue
			}
			hctx.enqueueMessage(cpu, newQueuedMsg(hctx, timer.hwnd, 0x0113, timer.id, timer.proc))
		}
	}

	var requestCommit func(bool)
	const (
		sentMessageResumeTrampolineID uint32 = 0x3FF8
		sentMessageWaitTrampolineID   uint32 = 0x3FF7
	)
	sentMessageResumeTrampoline := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	sentMessageWaitTrampoline := sentMessageResumeTrampoline + 32
	is32Process := hctx.ProcState != nil && hctx.ProcState.Is32
	if is32Process {
		mem.Write8(sentMessageResumeTrampoline+0, 0x50) // PUSH EAX
		mem.Write8(sentMessageResumeTrampoline+1, 0xB8)
		mem.Write32(sentMessageResumeTrampoline+2, sentMessageResumeTrampolineID)
		mem.Write8(sentMessageResumeTrampoline+6, 0x0F)
		mem.Write8(sentMessageResumeTrampoline+7, 0x01)
		mem.Write8(sentMessageResumeTrampoline+8, 0xC1)
		mem.Write8(sentMessageResumeTrampoline+9, 0x83) // ADD ESP, 4
		mem.Write8(sentMessageResumeTrampoline+10, 0xC4)
		mem.Write8(sentMessageResumeTrampoline+11, 0x04)
		mem.Write8(sentMessageResumeTrampoline+12, 0xC3)
	} else {
		mem.Write8(sentMessageResumeTrampoline+0, 0x50) // PUSH RAX
		mem.Write8(sentMessageResumeTrampoline+1, 0xB8)
		mem.Write32(sentMessageResumeTrampoline+2, sentMessageResumeTrampolineID)
		mem.Write8(sentMessageResumeTrampoline+6, 0x0F)
		mem.Write8(sentMessageResumeTrampoline+7, 0x01)
		mem.Write8(sentMessageResumeTrampoline+8, 0xC1)
		mem.Write8(sentMessageResumeTrampoline+9, 0x48) // ADD RSP, 8
		mem.Write8(sentMessageResumeTrampoline+10, 0x83)
		mem.Write8(sentMessageResumeTrampoline+11, 0xC4)
		mem.Write8(sentMessageResumeTrampoline+12, 0x08)
		mem.Write8(sentMessageResumeTrampoline+13, 0xC3)
	}
	mem.Write8(sentMessageWaitTrampoline+0, 0xB8)
	mem.Write32(sentMessageWaitTrampoline+1, sentMessageWaitTrampolineID)
	mem.Write8(sentMessageWaitTrampoline+5, 0x0F)
	mem.Write8(sentMessageWaitTrampoline+6, 0x01)
	mem.Write8(sentMessageWaitTrampoline+7, 0xC1)
	mem.Write8(sentMessageWaitTrampoline+8, 0xEB)
	mem.Write8(sentMessageWaitTrampoline+9, 0xF6)

	var sentMessageMu sync.Mutex
	sentMessagesInFlight := make(map[arch.CPU][]sentMessageInFlight)
	sentMessageWaits := make(map[arch.CPU][]crossThreadSendWait)
	pushSentMessage := func(cpu arch.CPU, inFlight sentMessageInFlight) {
		sentMessageMu.Lock()
		sentMessagesInFlight[cpu] = append(sentMessagesInFlight[cpu], inFlight)
		sentMessageMu.Unlock()
	}
	popSentMessage := func(cpu arch.CPU) (sentMessageInFlight, bool) {
		sentMessageMu.Lock()
		defer sentMessageMu.Unlock()
		stack := sentMessagesInFlight[cpu]
		if len(stack) == 0 {
			return sentMessageInFlight{}, false
		}
		inFlight := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if len(stack) == 0 {
			delete(sentMessagesInFlight, cpu)
		} else {
			sentMessagesInFlight[cpu] = stack
		}
		return inFlight, true
	}
	currentSentMessage := func(cpu arch.CPU) (*synchronousSendRequest, bool) {
		sentMessageMu.Lock()
		defer sentMessageMu.Unlock()
		stack := sentMessagesInFlight[cpu]
		if len(stack) == 0 {
			return nil, false
		}
		return stack[len(stack)-1].request, true
	}
	pushSentMessageWait := func(cpu arch.CPU, wait crossThreadSendWait) {
		sentMessageMu.Lock()
		sentMessageWaits[cpu] = append(sentMessageWaits[cpu], wait)
		sentMessageMu.Unlock()
	}
	currentSentMessageWait := func(cpu arch.CPU) (crossThreadSendWait, bool) {
		sentMessageMu.Lock()
		defer sentMessageMu.Unlock()
		stack := sentMessageWaits[cpu]
		if len(stack) == 0 {
			return crossThreadSendWait{}, false
		}
		return stack[len(stack)-1], true
	}
	popSentMessageWait := func(cpu arch.CPU) (crossThreadSendWait, bool) {
		sentMessageMu.Lock()
		defer sentMessageMu.Unlock()
		stack := sentMessageWaits[cpu]
		if len(stack) == 0 {
			return crossThreadSendWait{}, false
		}
		index := len(stack) - 1
		wait := stack[index]
		if index == 0 {
			delete(sentMessageWaits, cpu)
		} else {
			sentMessageWaits[cpu] = stack[:index]
		}
		return wait, true
	}
	hctx.CancelSentMessages = func(cpu arch.CPU) {
		hctx.MsgQueue.cancelSynchronousSender(cpu)
		sentMessageMu.Lock()
		stack := sentMessagesInFlight[cpu]
		waits := sentMessageWaits[cpu]
		delete(sentMessagesInFlight, cpu)
		delete(sentMessageWaits, cpu)
		sentMessageMu.Unlock()
		for _, inFlight := range stack {
			inFlight.request.complete(0)
		}
		for _, wait := range waits {
			wait.request.complete(0)
		}
	}

	captureSentMessagePump := func(
		ctx *ntapi.TrapContext,
		arguments [5]uint64,
		argumentCount int,
		resume func(*ntapi.TrapContext, *sentMessagePumpCall) uint32,
	) *sentMessagePumpCall {
		call := &sentMessagePumpCall{
			originalSP:    ctx.CPU.GetSP(),
			argumentCount: argumentCount,
			is32:          ctx.State != nil && ctx.State.Is32,
			arguments:     arguments,
			resume:        resume,
		}
		if call.is32 {
			returnAddress, _ := mem.Read32(call.originalSP)
			call.returnAddress = uint64(returnAddress)
		} else {
			call.returnAddress, _ = mem.Read64(call.originalSP)
		}
		return call
	}
	resolveSentWndProc := func(hwnd uint64) uint64 {
		if wndProc := hwndWndProc[hwnd]; wndProc != 0 {
			return wndProc
		}
		if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
			if wndProc := hctx.AtomWndProc[atom]; wndProc != 0 {
				hwndWndProc[hwnd] = wndProc
				return wndProc
			}
		}
		return 0
	}
	var dispatchPendingSentMessage func(*ntapi.TrapContext, *sentMessagePumpCall) bool
	dispatchPendingSentMessage = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) bool {
		for {
			request, ok := hctx.MsgQueue.takeSynchronous(ctx.CPU)
			if !ok {
				return false
			}
			if hctx.windowCPU(request.hwnd) != ctx.CPU {
				request.complete(0)
				continue
			}
			if !hasWindowSubclass(request.hwnd) {
				if result, handled := builtinWndProc(
					request.hwnd, request.message, request.wParam, request.lParam,
				); handled {
					if builtinMessageNeedsCommit(request.message) {
						requestCommit(true)
					}
					request.complete(result)
					continue
				}
			}
			wndProc := resolveSentWndProc(request.hwnd)
			if wndProc == 0 || hctx.SyncCallWndProc == nil {
				request.complete(0)
				continue
			}
			pushSentMessage(ctx.CPU, sentMessageInFlight{request: request, pump: pump})
			if pump != nil {
				ctx.CPU.SetSP(pump.originalSP)
			}
			if traceEnqueue {
				ravelog.Logf("[send-sync] dispatch owner=%p hwnd=0x%x msg=0x%x wndProc=0x%x sync=0x%x resume=0x%x pumpSP=0x%x return=0x%x\n",
					ctx.CPU, request.hwnd, request.message, wndProc, hctx.SyncTrampoline,
					sentMessageResumeTrampoline, pump.originalSP, pump.returnAddress)
			}
			syncStack := hctx.syncStack(ctx)
			*syncStack = append(*syncStack, syncDispatchFrame{
				retAddr:             sentMessageResumeTrampoline,
				hwnd:                request.hwnd,
				returnWndProcResult: true,
			})
			hctx.SyncCallWndProc(
				ctx, wndProc, request.hwnd, request.message,
				request.wParam, request.lParam, hctx.SyncTrampoline,
			)
			if traceEnqueue {
				ravelog.Logf("[send-sync] redirected pc=0x%x sp=0x%x pcRedirected=%t returnOverridden=%t\n",
					ctx.CPU.GetPC(), ctx.CPU.GetSP(), ctx.PCRedirected, ctx.ReturnOverridden)
			}
			return true
		}
	}
	d.RegisterHandler(sentMessageResumeTrampolineID, "sentMessageResumeTrampoline", func(ctx *ntapi.TrapContext) uint32 {
		var result uint64
		if ctx.State != nil && ctx.State.Is32 {
			value, _ := mem.Read32(ctx.CPU.GetSP())
			result = uint64(value)
		} else {
			result, _ = mem.Read64(ctx.CPU.GetSP())
		}
		inFlight, ok := popSentMessage(ctx.CPU)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		inFlight.request.complete(result)
		if traceEnqueue {
			ravelog.Logf("[send-sync] complete owner=%p hwnd=0x%x result=0x%x resumeSP=0x%x\n",
				ctx.CPU, inFlight.request.hwnd, result, ctx.CPU.GetSP())
		}
		if inFlight.pump == nil || inFlight.pump.resume == nil {
			ctx.SetReturn(0)
			return 0
		}

		pump := inFlight.pump
		ctx.CPU.SetSP(pump.originalSP)
		status := pump.resume(ctx, pump)
		if ctx.PCRedirected {
			return status
		}

		returnSlot := pump.originalSP
		wordSize := uint64(8)
		if pump.is32 {
			wordSize = 4
			returnSlot += uint64(pump.argumentCount) * 4
			mem.Write32(returnSlot, uint32(pump.returnAddress))
		} else {
			mem.Write64(returnSlot, pump.returnAddress)
		}
		ctx.CPU.SetSP(returnSlot - wordSize)
		if traceEnqueue {
			ravelog.Logf("[send-sync] resume owner=%p originalSP=0x%x returnSlot=0x%x return=0x%x result=0x%x\n",
				ctx.CPU, pump.originalSP, returnSlot, pump.returnAddress, ctx.CPU.SyscallNum())
		}
		return status
	})
	d.RegisterHandler(sentMessageWaitTrampolineID, "sentMessageWaitTrampoline", func(ctx *ntapi.TrapContext) uint32 {
		wait, ok := currentSentMessageWait(ctx.CPU)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		finish := func(result uint64) uint32 {
			_, _ = popSentMessageWait(ctx.CPU)
			ctx.SetReturn(result)
			wordSize := uint64(8)
			argumentBytes := uint64(0)
			if wait.is32 {
				wordSize = 4
				argumentBytes = 16
			}
			ctx.CPU.SetSP(wait.originalSP + wordSize + argumentBytes)
			ctx.CPU.SetPC(wait.returnAddress)
			ctx.PCRedirected = true
			return 0
		}
		if result, ready := wait.request.waitTimeout(0); ready {
			return finish(result)
		}
		pump := sentMessageLoopPump(wait.originalSP, sentMessageWaitTrampoline, wait.is32)
		if dispatchPendingSentMessage(ctx, pump) {
			return 0
		}
		if result, ready := wait.request.waitTimeout(time.Millisecond); ready {
			return finish(result)
		}
		ctx.CPU.SetPC(sentMessageWaitTrampoline)
		ctx.PCRedirected = true
		return 0
	})
	beginCrossThreadSend := func(ctx *ntapi.TrapContext, request *synchronousSendRequest) bool {
		if ctx == nil || ctx.CPU == nil || request == nil {
			return false
		}
		originalSP := ctx.CPU.GetSP()
		is32 := ctx.State != nil && ctx.State.Is32
		var returnAddress uint64
		var err error
		if is32 {
			var value uint32
			value, err = mem.Read32(originalSP)
			returnAddress = uint64(value)
		} else {
			returnAddress, err = mem.Read64(originalSP)
		}
		if err != nil || returnAddress == 0 {
			return false
		}
		pushSentMessageWait(ctx.CPU, crossThreadSendWait{
			request:       request,
			originalSP:    originalSP,
			returnAddress: returnAddress,
			is32:          is32,
		})
		ctx.CPU.SetPC(sentMessageWaitTrampoline)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return true
	}

	mapCursorHandle := func(hCursor uint64) (uint32, string) {
		switch hCursor {
		case 32512:
			return wl.CursorDefault, "default"
		case 32513:
			return wl.CursorText, "text"
		case 32514:
			return wl.CursorWait, "wait"
		case 32515:
			return wl.CursorCrosshair, "crosshair"
		case 32644:
			return wl.CursorResizeEW, "ew-resize"
		case 32645:
			return wl.CursorResizeNS, "ns-resize"
		case 32646:
			return wl.CursorResizeAll, "all-scroll"
		case 32648:
			return wl.CursorNotAllowed, "not-allowed"
		case 32649:
			return wl.CursorPointer, "pointer"
		default:
			return wl.CursorDefault, "default"
		}
	}
	setKeyDown := func(vk uint32, down bool) {
		if vk >= uint32(len(keyState)) {
			return
		}
		if down {
			keyState[vk] |= 0x80
			keyTransition[vk] = true
		} else {
			keyState[vk] &^= 0x80
		}
	}
	keyStateValue := func(vk uint32, consume bool) uint16 {
		if vk >= uint32(len(keyState)) {
			return 0
		}
		var state uint16
		if keyState[vk]&0x80 != 0 {
			state |= 0x8000
		}
		if keyTransition[vk] {
			state |= 0x0001
			if consume {
				delete(keyTransition, vk)
			}
		}
		return state
	}
	makeKeyLParam := func(scanCode uint32, extended, keyDown bool, wasDown bool) uint64 {
		lParam := uint64(1) | (uint64(scanCode&0xFF) << 16)
		if extended {
			lParam |= 1 << 24
		}
		if wasDown {
			lParam |= 1 << 30
		}
		if !keyDown {
			lParam |= 1 << 31
		}
		return lParam
	}
	absWindowOffset := func(hwnd uint64) (int32, int32) {
		if hwnd == 0 {
			return 0, 0
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			return cs.x, cs.y
		}
		return clientAreaOrigin(hwnd)
	}
	absoluteClientRect := func(hwnd uint64) (int32, int32, int32, int32) {
		ox, oy := absWindowOffset(hwnd)
		if cs, ok := hwndChildren[hwnd]; ok {
			return ox, oy, ox + cs.w, oy + cs.h
		}
		if wlWindow != nil && hwnd == hctx.MainHWND {
			w := wlWindow.Width
			h := wlWindow.Height
			if _, hasMenu := hwndMenuBar[hwnd]; hasMenu && h > win32.GetSystemMetrics(win32.SM_CYMENU) {
				h -= win32.GetSystemMetrics(win32.SM_CYMENU)
			}
			return ox, oy, ox + w, oy + h
		}
		return ox, oy, ox, oy
	}
	makeClientLParam := func(hwnd uint64, sx, sy int32) uint64 {
		ox, oy := absWindowOffset(hwnd)
		return uint64(uint16(sx-ox)) | (uint64(uint16(sy-oy)) << 16)
	}
	const (
		cwUseDefault          = ^int32(0x7fffffff)
		maxWindowCoordinate   = 0x7FFF
		defaultTopLevelWidth  = int32(800)
		defaultTopLevelHeight = int32(600)
	)
	readCreateWindowIntArg := func(ctx *ntapi.TrapContext, n int) int32 {
		if ctx.State != nil && ctx.State.Is32 {
			sp := ctx.CPU.GetSP()
			val, err := mem.Read32(sp + 4 + uint64(n)*4)
			if err != nil {
				return 0
			}
			return int32(val)
		}
		return int32(ctx.Arg(n))
	}
	resolveTopLevelCreateWindowSize := func(ctx *ntapi.TrapContext) (int32, int32) {
		w, h := defaultTopLevelWidth, defaultTopLevelHeight
		nw := readCreateWindowIntArg(ctx, 6)
		nh := readCreateWindowIntArg(ctx, 7)
		if nw == cwUseDefault {
			return w, h
		}
		if nw > 0 && nw < maxWindowCoordinate {
			w = nw
		}
		if nh == cwUseDefault {
			return w, h
		}
		if nh > 0 && nh < maxWindowCoordinate {
			h = nh
		}
		return w, h
	}
	findDeepestChildAt := func(parent uint64, sx, sy int32) (uint64, uint64) {
		for h, cs := range hwndChildren {
			if !cs.visible || (!cs.comboDropped && cs.style&3 != 1) || (cs.className != "combobox" && cs.className != "comboboxex32") {
				continue
			}
			ancestor := cs.parentHWND
			for ancestor != 0 && ancestor != parent {
				state := hwndChildren[ancestor]
				if state == nil || !state.visible {
					ancestor = 0
					break
				}
				ancestor = state.parentHWND
			}
			if ancestor != parent {
				continue
			}
			rows := len(cs.comboItems) - cs.comboTopIndex
			maxRows := 8
			if cs.style&3 == 1 {
				maxRows = int((cs.h - 28) / 18)
				if maxRows < 1 {
					maxRows = 1
				}
			}
			if rows > maxRows {
				rows = maxRows
			}
			if rows <= 0 {
				continue
			}
			popupY := cs.y + 24
			popupH := int32(rows*18 + 4)
			cs.comboPopupAbove = false
			if root := hwndChildren[parent]; root != nil && cs.style&3 != 1 && popupY+popupH > root.y+root.h && cs.y-popupH >= root.y {
				popupY = cs.y - popupH
				cs.comboPopupAbove = true
			}
			if sx >= cs.x && sx < cs.x+cs.w && sy >= popupY && sy < popupY+popupH {
				relY := sy - popupY + 24
				return h, uint64(uint16(sx-cs.x)) | (uint64(uint16(relY)) << 16)
			}
		}
		var (
			best      uint64
			bestParam uint64
			bestArea  int64 = 1<<62 - 1
		)
		for h, cs := range hwndChildren {
			if !cs.visible {
				continue
			}
			ancestor := cs.parentHWND
			hiddenAncestor := false
			for ancestor != 0 && ancestor != parent {
				state := hwndChildren[ancestor]
				if state == nil {
					ancestor = 0
					break
				}
				hiddenAncestor = hiddenAncestor || !state.visible
				ancestor = state.parentHWND
			}
			if ancestor != parent || (hiddenAncestor && !paintedThroughHiddenAncestor[h]) {
				continue
			}
			hitHeight := controlHitHeight(cs)
			if sx < cs.x || sx >= cs.x+cs.w || sy < cs.y || sy >= cs.y+hitHeight {
				continue
			}
			area := int64(cs.w) * int64(hitHeight)
			if best == 0 || area < bestArea || (area == bestArea && h > best) {
				best = h
				bestArea = area
				bestParam = makeClientLParam(h, sx, sy)
			}
		}
		return best, bestParam
	}

	// findMenuItem locates a menu item by position or command ID.
	findMenuItem := func(hMenu uint64, uID uint64, uFlags uint32) *menuItem {
		const mfByPosition = 0x0400
		return findMenuItemRecursive(menus[hMenu], uID, uFlags&mfByPosition != 0)
	}

	getClientScrollbarSizes := func(hwnd uint64) (int32, int32) {
		wnd := win32.Global.Get(hwnd)
		if wnd == nil {
			return 0, 0
		}
		var vW, hH int32
		if wnd.Style&win32.WS_VSCROLL != 0 {
			vW = win32.GetSystemMetrics(win32.SM_CXVSCROLL)
		}
		if wnd.Style&win32.WS_HSCROLL != 0 {
			hH = win32.GetSystemMetrics(win32.SM_CYHSCROLL)
		}
		return vW, hH
	}
	getMenuClientTop := func(hwnd uint64) int32 {
		top := int32(0)
		if wlWindow != nil {
			top = wlWindow.TitleBarH
		}
		if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
			top += win32.GetSystemMetrics(win32.SM_CYMENU)
		}
		return top
	}
	requestCommit = func(repaintBuiltin bool) {
		if wlWindow == nil {
			return
		}
		if hctx.HasBaseFrame {
			if repaintBuiltin {
				hctx.RepaintBuiltin = true
			}
			hctx.FrameReady = true
			commitIfDone()
			return
		}
		wlWindow.Commit()
	}
	var shiftChildWindows func(uint64, int32, int32)
	shiftChildWindows = func(parent uint64, dx, dy int32) {
		if dx == 0 && dy == 0 {
			return
		}
		for childHWND, child := range hwndChildren {
			if child.parentHWND != parent {
				continue
			}
			_, geometry := child.mutateGeometry(func(geometry *controlGeometry) {
				geometry.x += dx
				geometry.y += dy
			})
			if wnd := win32.Global.Get(childHWND); wnd != nil {
				win32.Global.UpdatePos(wnd, geometry.x, geometry.y, geometry.w, geometry.h)
			}
			shiftChildWindows(childHWND, dx, dy)
		}
	}
	getTopLevelClientSize := func(hwnd uint64) (int32, int32) {
		if wlWindow == nil {
			return 0, 0
		}
		w := wlWindow.Width
		h := wlWindow.Height
		if _, hasMenu := hwndMenuBar[hwnd]; hasMenu && h > win32.GetSystemMetrics(win32.SM_CYMENU) {
			h -= win32.GetSystemMetrics(win32.SM_CYMENU)
		}
		vW, hH := getClientScrollbarSizes(hwnd)
		if w > vW {
			w -= vW
		}
		if h > hH {
			h -= hH
		}
		if w < 0 {
			w = 0
		}
		if h < 0 {
			h = 0
		}
		return w, h
	}
	resolveMenuItems := func(item menuItem) []menuItem {
		subItems := item.submenuItems()
		if len(subItems) == 0 && item.flags&0x0010 != 0 {
			handle := item.submenuHandle
			if handle == 0 {
				handle = item.id
			}
			if sub, ok := menus[handle]; ok {
				subItems = sub.items
			}
		}
		return subItems
	}
	menuBarItemBounds := func(hwnd uint64, idx int) (*menuItem, uint64, int32, int32, bool) {
		menuH, ok := hwndMenuBar[hwnd]
		if !ok {
			return nil, 0, 0, 0, false
		}
		md, ok := menus[menuH]
		if !ok {
			return nil, 0, 0, 0, false
		}
		x := int32(4)
		for i := range md.items {
			item := &md.items[i]
			if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
				continue
			}
			label, _ := menuTextParts(menuStripAmpersand(item.text))
			if label == "" || label == "-" || !menuHasRenderableText(label) {
				continue
			}
			tw := menuTextWidth(label) + 12
			if i == idx {
				return item, menuH, x, tw, true
			}
			x += tw
		}
		return nil, 0, 0, 0, false
	}
	showPopupMenu := func(hMenu, owner uint64, x, y int32) {
		m, ok := menus[hMenu]
		if !ok || len(m.items) == 0 {
			hctx.ActivePopupMenu = nil
			return
		}
		boundW, boundH := int32(0), int32(0)
		if wlWindow != nil {
			boundW = wlWindow.Width
			boundH = wlWindow.Height + wlWindow.TitleBarH
		}
		layout := menuPopupLayout(m.items, x, y, boundW, boundH, menuStripAmpersand)
		layout.Menu = hMenu
		layout.OwnerHWND = owner
		if hctx.MenuBehind == nil && wlWindow != nil {
			hctx.MenuBehind = wlWindow.SnapshotPixels()
		}
		hctx.ActivePopupMenu = &layout
	}
	showMenuBarPopup := func(hwnd uint64, idx int) {
		item, menuH, x, _, ok := menuBarItemBounds(hwnd, idx)
		if !ok || wlWindow == nil {
			hctx.ActivePopupMenu = nil
			return
		}
		ensureMenuItemSubmenu(menuH, idx, item, menus)
		subItems := resolveMenuItems(*item)
		if len(subItems) == 0 {
			hctx.ActivePopupMenu = nil
			return
		}
		layout := menuPopupLayout(subItems, x, wlWindow.TitleBarH+win32.GetSystemMetrics(win32.SM_CYMENU), wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH, menuStripAmpersand)
		layout.Menu = item.submenuHandle
		layout.OwnerHWND = hwnd
		if hctx.MenuBehind == nil {
			hctx.MenuBehind = wlWindow.SnapshotPixels()
		}
		hctx.ActivePopupMenu = &layout
	}
	closePopupMenus := func() {
		hctx.ActivePopupMenu = nil
		hctx.OpenMenuIdx = -1
		hctx.OpenMenuHwnd = 0
		// Restore the content the menu covered so no fragments remain.
		if hctx.MenuBehind != nil && wlWindow != nil {
			if wlWindow.RestorePixels(hctx.MenuBehind) {
				wlWindow.Commit()
			}
			hctx.MenuBehind = nil
		}
	}
	ensureOwnedDialogWindow := func(hwnd uint64) *wl.Window {
		hwndLifecycleMu.Lock()
		state := hwndChildren[hwnd]
		const wsChild = uint32(0x40000000)
		if state == nil || !state.visible || strings.ToLower(state.className) != "dialog" || hwnd == hctx.MainHWND || state.style&wsChild != 0 {
			hwndLifecycleMu.Unlock()
			return nil
		}
		registered := registerGlobalWindow(hwnd, state)
		if win := hctx.WlWindows[hwnd]; win != nil {
			if state.w > 0 && state.h > 0 {
				win.Resize(state.w, state.h)
			}
			wlDisplay.SetWindowTitle(win, state.text)
			hwndLifecycleMu.Unlock()
			return win
		}
		if wlDisplay == nil || wlWindow == nil || state.w <= 0 || state.h <= 0 {
			if registered {
				cleanupWindowRegistration(hwnd, &hwndDisabled)
			}
			hwndLifecycleMu.Unlock()
			return nil
		}
		owner := wlWindow
		for parent := state.parentHWND; parent != 0; {
			if parentWin := hctx.WlWindows[parent]; parentWin != nil {
				owner = parentWin
				break
			}
			parentState := hwndChildren[parent]
			if parentState == nil {
				break
			}
			parent = parentState.parentHWND
		}
		win, err := wlDisplay.CreateOwnedWindow(state.text, state.w, state.h, 0, owner)
		if err != nil {
			if registered {
				cleanupWindowRegistration(hwnd, &hwndDisabled)
			}
			ravelog.Logf("[dialog-window] create hwnd=0x%x failed: %v\n", hwnd, err)
			hwndLifecycleMu.Unlock()
			return nil
		}
		hctx.WlWindows[hwnd] = win
		hctx.WlWindowHWND[win] = hwnd
		cpu := hctx.windowCPU(hwnd)
		width, height, title := state.w, state.h, state.text
		hwndLifecycleMu.Unlock()
		renderOwnedDialog(hctx, hwnd, cpu, win)
		queuePaint(hctx.MainHWND)
		ravelog.Logf("[dialog-window] created hwnd=0x%x size=%dx%d title=%q\n", hwnd, width, height, title)
		return win
	}
	destroyOwnedDialogWindowForCPU := func(hwnd uint64, cpu arch.CPU) {
		hwndLifecycleMu.Lock()
		win := hctx.WlWindows[hwnd]
		hwndLifecycleMu.Unlock()
		if win == nil {
			return
		}
		if cpu == nil {
			cpu = hctx.windowCPU(hwnd)
		}
		if cpu == nil {
			cpu = hctx.GetCurrentCPU()
		}
		hctx.DialogSurfaceMu.Lock(cpu)
		defer hctx.DialogSurfaceMu.Unlock(cpu)
		hwndLifecycleMu.Lock()
		if hctx.WlWindows[hwnd] != win {
			hwndLifecycleMu.Unlock()
			return
		}

		ownedDCWindowsMu.Lock()
		for hdc, state := range ownedDCWindows {
			if state.target != win {
				continue
			}
			delete(ownedDCWindows, hdc)
			gdiMgr.DeleteDC(hdc)
			hctx.DialogSurfaceMu.Unlock(cpu)
		}
		ownedDCWindowsMu.Unlock()

		destroyedHandles := make(map[uint64]bool)
		for _, handle := range windowCleanupHandles(hwnd, hwndChildren) {
			destroyedHandles[handle] = true
		}
		ownedPaintCPUsMu.Lock()
		for handle, cpus := range ownedPaintCPUs {
			if !destroyedHandles[handle] {
				continue
			}
			delete(ownedPaintCPUs, handle)
			for range cpus {
				hctx.DialogSurfaceMu.Unlock(cpu)
			}
		}
		ownedPaintCPUsMu.Unlock()

		delete(hctx.WlWindowHWND, win)
		delete(hctx.WlWindows, hwnd)
		win.Destroy()
		cleanupWindowRegistration(hwnd, &hwndDisabled)
		hwndLifecycleMu.Unlock()
		queuePaint(hctx.MainHWND)
		ravelog.Logf("[dialog-window] destroyed hwnd=0x%x\n", hwnd)
	}
	destroyOwnedDialogWindow := func(hwnd uint64) {
		destroyOwnedDialogWindowForCPU(hwnd, nil)
	}
	cleanupWindowState := func(root uint64) {
		handles := windowCleanupHandles(root, hwndChildren)
		for _, hwnd := range handles {
			hwndLifecycleMu.Lock()
			cleanupHandlerWindowState(hctx, hwnd)
			hwndDisabled.remove(hwnd)
			hwndLifecycleMu.Unlock()
		}
		if hctx.FocusHwnd != 0 {
			for _, hwnd := range handles {
				if hctx.FocusHwnd == hwnd {
					hctx.FocusHwnd = hctx.MainHWND
					break
				}
			}
		}
	}
	flushDestroyedWindows := func() {
		for hwnd := range destroyDelivered {
			cleanupWindowState(hwnd)
			delete(destroyDelivered, hwnd)
			delete(destroyPending, hwnd)
		}
	}
	destroyWindow := func(hwnd uint64, cpu arch.CPU) bool {
		if destroyPending[hwnd] || (hwndChildren[hwnd] == nil && win32.Global.Get(hwnd) == nil) {
			return false
		}
		handles := windowCleanupHandles(hwnd, hwndChildren)
		destroyOwnedDialogWindowForCPU(hwnd, cpu)
		pruneDestroyedWindowMessages(&hctx.MsgQueue, hwnd, hwndChildren)
		for _, handle := range handles {
			if state := hwndChildren[handle]; state != nil {
				state.visible = false
			}
			hctx.WinInvalid[handle] = false
			delete(hctx.WinErasePending, handle)
			win32.Global.Validate(handle)
		}
		if _, hasWP := hwndWndProc[hwnd]; hasWP {
			destroyPending[hwnd] = true
			hctx.enqueueMessage(nil,
				newQueuedMsg(hctx, hwnd, 0x0002, 0, 0),
				newQueuedMsg(hctx, hwnd, 0x0082, 0, 0),
			)
		} else {
			cleanupWindowState(hwnd)
		}
		return true
	}
	requestWindowRepaint := func(hwnd uint64) {
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		dialogRoot := uint64(0)
		if root, _, isDialog := topLevelDialogTarget(hctx, hwnd); isDialog {
			dialogRoot = root
		}
		if win := ensureOwnedDialogWindow(dialogRoot); win != nil {
			if repaintHostManagedDialog(hctx, dialogRoot, hctx.windowCPU(dialogRoot), win) {
				return
			}
			queuePaint(dialogRoot)
			return
		}
		if hwnd == hctx.MainHWND && wlWindow != nil && hctx.HasBaseFrame {
			hctx.RepaintBuiltin = true
			hctx.FrameReady = true
			commitIfDone()
			return
		}
		queuePaint(hwnd)
	}
	hctx.RequestWindowRepaint = requestWindowRepaint
	hctx.DestroyOwnedDialog = destroyOwnedDialogWindowForCPU
	drawAbsHLine := func(x0, x1, y int32, color uint32) {
		if wlWindow == nil || x1 <= x0 {
			return
		}
		wlWindow.DrawRectAbs(x0, y, x1, y+1, color)
	}
	drawAbsVLine := func(x, y0, y1 int32, color uint32) {
		if wlWindow == nil || y1 <= y0 {
			return
		}
		wlWindow.DrawRectAbs(x, y0, x+1, y1, color)
	}
	drawPopupArrow := func(x, y int32, vertical bool, dir int32, color uint32) {
		if wlWindow == nil {
			return
		}
		if vertical {
			for row := int32(0); row < 5; row++ {
				width := row*2 + 1
				if dir > 0 {
					drawAbsHLine(x-width/2, x-width/2+width, y+row, color)
				} else {
					drawAbsHLine(x-width/2, x-width/2+width, y+4-row, color)
				}
			}
			return
		}
		for col := int32(0); col < 5; col++ {
			height := col*2 + 1
			if dir > 0 {
				drawAbsVLine(x+col, y-height/2, y-height/2+height, color)
			} else {
				drawAbsVLine(x+4-col, y-height/2, y-height/2+height, color)
			}
		}
	}
	drawScrollBar := func(rect win32.Rect, vertical bool, si win32.ScrollInfo) {
		if wlWindow == nil {
			return
		}
		btnSize := win32.GetSystemMetrics(win32.SM_CXVSCROLL)
		if !vertical {
			btnSize = win32.GetSystemMetrics(win32.SM_CYHSCROLL)
		}
		bg := uint32(0xF0F0F0)
		border := uint32(0xA0A0A0)
		thumb := uint32(0xCDCDCD)
		wlWindow.DrawRectAbs(rect.Left, rect.Top, rect.Right, rect.Bottom, bg)
		drawAbsHLine(rect.Left, rect.Right, rect.Top, border)
		drawAbsHLine(rect.Left, rect.Right, rect.Bottom-1, border)
		drawAbsVLine(rect.Left, rect.Top, rect.Bottom, border)
		drawAbsVLine(rect.Right-1, rect.Top, rect.Bottom, border)
		if vertical {
			wlWindow.DrawRectAbs(rect.Left+1, rect.Top+1, rect.Right-1, rect.Top+btnSize, bg)
			wlWindow.DrawRectAbs(rect.Left+1, rect.Bottom-btnSize, rect.Right-1, rect.Bottom-1, bg)
			drawPopupArrow(rect.Left+(rect.Right-rect.Left)/2, rect.Top+6, true, -1, 0x404040)
			drawPopupArrow(rect.Left+(rect.Right-rect.Left)/2, rect.Bottom-btnSize+6, true, 1, 0x404040)
			trackTop := rect.Top + btnSize
			trackBottom := rect.Bottom - btnSize
			if trackBottom > trackTop {
				wlWindow.DrawRectAbs(rect.Left+1, trackTop, rect.Right-1, trackBottom, bg)
				trackH := trackBottom - trackTop
				thumbH := int32(24)
				rangeSpan := si.Max - si.Min + 1
				if rangeSpan < 1 {
					rangeSpan = 1
				}
				if si.Page > 0 {
					thumbH = int32(si.Page) * trackH / rangeSpan
					if thumbH < 20 {
						thumbH = 20
					}
					if thumbH > trackH {
						thumbH = trackH
					}
				}
				thumbTop := trackTop
				movable := trackH - thumbH
				denom := si.Max - si.Min - int32(si.Page) + 1
				if denom < 1 {
					denom = si.Max - si.Min
				}
				if denom > 0 && movable > 0 {
					thumbTop += (si.Pos - si.Min) * movable / denom
				}
				wlWindow.DrawRectAbs(rect.Left+2, thumbTop, rect.Right-2, thumbTop+thumbH, thumb)
				drawAbsHLine(rect.Left+2, rect.Right-2, thumbTop, border)
				drawAbsHLine(rect.Left+2, rect.Right-2, thumbTop+thumbH-1, border)
				drawAbsVLine(rect.Left+2, thumbTop, thumbTop+thumbH, border)
				drawAbsVLine(rect.Right-3, thumbTop, thumbTop+thumbH, border)
			}
		} else {
			wlWindow.DrawRectAbs(rect.Left+1, rect.Top+1, rect.Left+btnSize, rect.Bottom-1, bg)
			wlWindow.DrawRectAbs(rect.Right-btnSize, rect.Top+1, rect.Right-1, rect.Bottom-1, bg)
			drawPopupArrow(rect.Left+6, rect.Top+(rect.Bottom-rect.Top)/2, false, -1, 0x404040)
			drawPopupArrow(rect.Right-btnSize+6, rect.Top+(rect.Bottom-rect.Top)/2, false, 1, 0x404040)
			trackLeft := rect.Left + btnSize
			trackRight := rect.Right - btnSize
			if trackRight > trackLeft {
				wlWindow.DrawRectAbs(trackLeft, rect.Top+1, trackRight, rect.Bottom-1, bg)
				trackW := trackRight - trackLeft
				thumbW := int32(24)
				rangeSpan := si.Max - si.Min + 1
				if rangeSpan < 1 {
					rangeSpan = 1
				}
				if si.Page > 0 {
					thumbW = int32(si.Page) * trackW / rangeSpan
					if thumbW < 20 {
						thumbW = 20
					}
					if thumbW > trackW {
						thumbW = trackW
					}
				}
				thumbLeft := trackLeft
				movable := trackW - thumbW
				denom := si.Max - si.Min - int32(si.Page) + 1
				if denom < 1 {
					denom = si.Max - si.Min
				}
				if denom > 0 && movable > 0 {
					thumbLeft += (si.Pos - si.Min) * movable / denom
				}
				wlWindow.DrawRectAbs(thumbLeft, rect.Top+2, thumbLeft+thumbW, rect.Bottom-2, thumb)
				drawAbsHLine(thumbLeft, thumbLeft+thumbW, rect.Top+2, border)
				drawAbsHLine(thumbLeft, thumbLeft+thumbW, rect.Bottom-3, border)
				drawAbsVLine(thumbLeft, rect.Top+2, rect.Bottom-2, border)
				drawAbsVLine(thumbLeft+thumbW-1, rect.Top+2, rect.Bottom-2, border)
			}
		}
	}
	paintChildScrollbars := func(root uint64) {
		if wlWindow == nil {
			return
		}
		for hwnd, state := range hwndChildren {
			if hwnd == hctx.MainHWND || state == nil || !windowHierarchyVisible(hwnd, hwndChildren) ||
				!windowIsDescendantOrSelf(hwnd, root, hwndChildren) {
				continue
			}
			if _, _, owned := topLevelDialogTarget(hctx, hwnd); owned {
				continue
			}
			vertical, horizontal, corner, hasVertical, hasHorizontal := childScrollbarRects(state)
			if hasVertical && vertical.Right > vertical.Left && vertical.Bottom > vertical.Top {
				info := win32.ScrollInfo{}
				win32.GetScrollInfo(hwnd, win32.SB_VERT, &info, win32.SIF_ALL)
				drawScrollBar(vertical, true, info)
			}
			if hasHorizontal && horizontal.Right > horizontal.Left && horizontal.Bottom > horizontal.Top {
				info := win32.ScrollInfo{}
				win32.GetScrollInfo(hwnd, win32.SB_HORZ, &info, win32.SIF_ALL)
				drawScrollBar(horizontal, false, info)
			}
			if hasVertical && hasHorizontal {
				wlWindow.DrawRectAbs(corner.Left, corner.Top, corner.Right, corner.Bottom, hctx.SysColors[15])
			}
			if effectiveDarkModeForWindow(hwnd, hwndChildren) {
				if hasVertical {
					remapWaylandRectForDarkMode(wlWindow, vertical.Left, vertical.Top, vertical.Right, vertical.Bottom)
				}
				if hasHorizontal {
					remapWaylandRectForDarkMode(wlWindow, horizontal.Left, horizontal.Top, horizontal.Right, horizontal.Bottom)
				}
				if hasVertical && hasHorizontal {
					remapWaylandRectForDarkMode(wlWindow, corner.Left, corner.Top, corner.Right, corner.Bottom)
				}
			}
		}
	}

	user32, ok := hctx.SynthByName["user32.dll"]
	if !ok {
		return
	}
	_ = user32

	// LoadStringW: load string resource from PE
	d.RegisterAutoStubHandler(user32, "LoadStringW", func(ctx *ntapi.TrapContext) uint32 {
		uID := uint32(ctx.Arg(1))
		lpBuffer := ctx.Arg(2)
		cchBufferMax := int(int32(ctx.Arg(3)))
		s, guestAddr, slen := peLoadStringW(uID)
		if s == "" && os.Getenv("RAVEN_TRACE_RESOURCES") != "" {
			ravelog.Logf("[loadstr] missing id=%d module=0x%x\n", uID, ctx.Arg(0))
		}
		if s != "" {
			ravelog.Logf("[loadstr] id=%d -> %q\n", uID, s)
		}
		if s == "" || lpBuffer == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// When cchBufferMax == 0, return a read-only pointer to the resource string
		if cchBufferMax == 0 {
			mem.Write64(lpBuffer, guestAddr)
			ctx.SetReturn(uint64(slen))
			return 0
		}
		runes := []rune(s)
		n := len(runes)
		if n >= cchBufferMax {
			n = cchBufferMax - 1
		}
		for i := 0; i < n; i++ {
			mem.Write16(lpBuffer+uint64(i)*2, uint16(runes[i]))
		}
		mem.Write16(lpBuffer+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextLengthW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok && cs.text != "" {
			ctx.SetReturn(uint64(len([]rune(cs.text))))
		} else if hwnd == hctx.MainHWND && hctx.MainTitle != "" {
			ctx.SetReturn(uint64(len([]rune(hctx.MainTitle))))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromRect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xD0000001) // fake monitor handle
		return 0
	})
	accelTables := map[uint64][]accelEntry{}
	var accelMu sync.RWMutex
	var nextAccelTable uint64 = 0xac000

	loadAccelerators := func(ctx *ntapi.TrapContext, wide bool) uint32 {
		lpTableName := ctx.Arg(1)
		var resID uint16
		var resName string
		if lpTableName < 0x10000 {
			resID = uint16(lpTableName)
		} else {
			resName = readGuestString(lpTableName)
			if wide {
				resName = readGuestUTF16(lpTableName)
			}
		}
		{
			hInstance := ctx.Arg(0)
			if mainModule == nil {
				ctx.SetReturn(0)
				return 0
			}
			moduleBase := hInstance
			resourceRVA := uint32(0)
			if moduleBase == 0 || moduleBase == mainModule.BaseAddr {
				moduleBase = mainModule.BaseAddr
				resourceRVA = mainModule.ResourceDirRVA
			} else {
				resourceRVA = hctx.moduleResourceRVA(moduleBase)
			}
			if resourceRVA == 0 {
				ctx.SetReturn(0)
				return 0
			}
			var addr uint64
			var size uint32
			var ok bool
			if resName != "" {
				addr, size, ok = loadNamedResource(mem, moduleBase, resourceRVA, 9, resName)
			} else if resID != 0 {
				addr, size, ok = peLoadRawResource(moduleBase, resourceRVA, 9, uint32(resID))
			}
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			if size < 8 || uint64(size)/8 > maxAcceleratorEntries {
				ctx.SetReturn(0)
				return 0
			}
			entries := make([]accelEntry, 0, size/8)
			for offset := uint64(0); offset+8 <= uint64(size); offset += 8 {
				flags, _ := mem.Read16(addr + offset)
				key, _ := mem.Read16(addr + offset + 2)
				cmd, _ := mem.Read16(addr + offset + 4)
				entries = append(entries, accelEntry{fVirt: byte(flags) &^ 0x80, key: key, cmd: cmd})
				if flags&0x80 != 0 {
					break
				}
			}
			if len(entries) == 0 {
				ctx.SetReturn(0)
				return 0
			}
			accelMu.Lock()
			nextAccelTable++
			h := nextAccelTable
			accelTables[h] = entries
			accelMu.Unlock()
			ctx.SetReturn(h)
			return 0
		}
	}
	d.RegisterAutoStubHandler(user32, "LoadAcceleratorsW", func(ctx *ntapi.TrapContext) uint32 {
		return loadAccelerators(ctx, true)
	})
	d.RegisterAutoStubHandler(user32, "LoadAcceleratorsA", func(ctx *ntapi.TrapContext) uint32 {
		return loadAccelerators(ctx, false)
	})
	// wsprintfW(lpOut, lpFmt, ...) - varargs format, returns char count
	d.RegisterAutoStubHandler(user32, "wsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		fmtStr := readGuestUTF16(lpFmt)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := formatString(mem, fmtStr, args, true)
		for i, r := range result {
			mem.Write16(lpOut+uint64(i)*2, uint16(r))
		}
		mem.Write16(lpOut+uint64(len([]rune(result)))*2, 0)
		ctx.SetReturn(uint64(len([]rune(result))))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "wsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		fmtStr := readGuestString(lpFmt)
		var args []uint64
		for i := 2; i < 10; i++ {
			args = append(args, ctx.Arg(i))
		}
		result := formatString(mem, fmtStr, args, false)
		ravelog.Logf("[wise] wsprintfA fmt=%q result=%q\n", fmtStr, result)
		for i := range result {
			mem.Write8(lpOut+uint64(i), result[i])
		}
		mem.Write8(lpOut+uint64(len(result)), 0)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassW", func(ctx *ntapi.TrapContext) uint32 {
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			var style uint32
			var wndProc, hInst, hIcon, hCursor, hBrush, lpMenuName, lpName uint64
			var cbClsExtra, cbWndExtra uint32
			if ctx.State != nil && ctx.State.Is32 {
				// WNDCLASSW x86: style(4), lpfnWndProc(4), cbClsExtra(4), cbWndExtra(4),
				//   hInstance(4), hIcon(4), hCursor(4), hbrBackground(4), lpszMenuName(4), lpszClassName(4)
				style, _ = mem.Read32(pClass)
				v, _ := mem.Read32(pClass + 4)
				wndProc = uint64(v)
				cbClsExtra, _ = mem.Read32(pClass + 8)
				cbWndExtra, _ = mem.Read32(pClass + 12)
				v, _ = mem.Read32(pClass + 16)
				hInst = uint64(v)
				v, _ = mem.Read32(pClass + 20)
				hIcon = uint64(v)
				v, _ = mem.Read32(pClass + 24)
				hCursor = uint64(v)
				v, _ = mem.Read32(pClass + 28)
				hBrush = uint64(v)
				v, _ = mem.Read32(pClass + 32)
				lpMenuName = uint64(v)
				v, _ = mem.Read32(pClass + 36)
				lpName = uint64(v)
			} else {
				// WNDCLASSW x64: style(4)+pad(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
				//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8)
				style, _ = mem.Read32(pClass)
				wndProc, _ = mem.Read64(pClass + 8)
				cbClsExtra, _ = mem.Read32(pClass + 16)
				cbWndExtra, _ = mem.Read32(pClass + 20)
				hInst, _ = mem.Read64(pClass + 24)
				hIcon, _ = mem.Read64(pClass + 32)
				hCursor, _ = mem.Read64(pClass + 40)
				hBrush, _ = mem.Read64(pClass + 48)
				lpMenuName, _ = mem.Read64(pClass + 56)
				lpName, _ = mem.Read64(pClass + 64)
			}
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestUTF16(lpName)
			if name != "" {
				hctx.ClassNameAtom[strings.ToLower(name)] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				Atom: a,
			}
			if lpMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpMenuName < 0x10000 {
					menuID = uint32(lpMenuName)
				} else {
					menuName := readGuestUTF16(lpMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassW %q atom=0x%x wndProc=0x%x brush=%d\n", name, a, wndProc, hBrush)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassExW", func(ctx *ntapi.TrapContext) uint32 {
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			var style uint32
			var wndProc, hInst, hIcon, hCursor, hBrush, lpszMenuName, lpName, hIconSm uint64
			var cbClsExtra, cbWndExtra uint32
			if ctx.State != nil && ctx.State.Is32 {
				// WNDCLASSEXW x86: cbSize(4), style(4), lpfnWndProc(4), cbClsExtra(4), cbWndExtra(4),
				//   hInstance(4), hIcon(4), hCursor(4), hbrBackground(4), lpszMenuName(4), lpszClassName(4), hIconSm(4)
				style, _ = mem.Read32(pClass + 4)
				v, _ := mem.Read32(pClass + 8)
				wndProc = uint64(v)
				cbClsExtra, _ = mem.Read32(pClass + 12)
				cbWndExtra, _ = mem.Read32(pClass + 16)
				v, _ = mem.Read32(pClass + 20)
				hInst = uint64(v)
				v, _ = mem.Read32(pClass + 24)
				hIcon = uint64(v)
				v, _ = mem.Read32(pClass + 28)
				hCursor = uint64(v)
				v, _ = mem.Read32(pClass + 32)
				hBrush = uint64(v)
				v, _ = mem.Read32(pClass + 36)
				lpszMenuName = uint64(v)
				v, _ = mem.Read32(pClass + 40)
				lpName = uint64(v)
				v, _ = mem.Read32(pClass + 44)
				hIconSm = uint64(v)
			} else {
				// WNDCLASSEXW x64: cbSize(4)+style(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
				//   hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8), hIconSm(8)
				style, _ = mem.Read32(pClass + 4)
				wndProc, _ = mem.Read64(pClass + 8)
				cbClsExtra, _ = mem.Read32(pClass + 16)
				cbWndExtra, _ = mem.Read32(pClass + 20)
				hInst, _ = mem.Read64(pClass + 24)
				hIcon, _ = mem.Read64(pClass + 32)
				hCursor, _ = mem.Read64(pClass + 40)
				hBrush, _ = mem.Read64(pClass + 48)
				lpszMenuName, _ = mem.Read64(pClass + 56)
				lpName, _ = mem.Read64(pClass + 64)
				hIconSm, _ = mem.Read64(pClass + 72)
			}
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			var name string
			if lpName != 0 && lpName < 0x10000 {
				name = fmt.Sprintf("atom:0x%x", lpName)
			} else {
				name = readGuestUTF16(lpName)
			}
			if name != "" {
				hctx.ClassNameAtom[strings.ToLower(name)] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpszMenuName, ClassName: name,
				HIconSm: hIconSm, Atom: a,
			}
			if lpszMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpszMenuName < 0x10000 {
					menuID = uint32(lpszMenuName)
				} else {
					menuName := readGuestUTF16(lpszMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassExW name=%q lpName=0x%x atom=0x%x wndProc=0x%x brush=%d\n", name, lpName, a, wndProc, hBrush)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterWindowMessageW", func(ctx *ntapi.TrapContext) uint32 {
		name := ""
		if p := ctx.Arg(0); p != 0 {
			name = readGuestUTF16(p)
		}
		if name != "" {
			if existing, ok := hctx.RegisteredMsgNames[name]; ok {
				ctx.SetReturn(uint64(existing))
				return 0
			}
		}
		id := hctx.NextMsgID
		hctx.NextMsgID++
		if name != "" {
			hctx.RegisteredMsgNames[name] = id
		}
		ctx.SetReturn(uint64(id))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateWindowExW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		lpClassName := ctx.Arg(1)
		style := uint32(ctx.Arg(3))

		// Associate HWND with WndProc via class name or atom
		var className string
		var classAtomForHwnd uint16
		if lpClassName != 0 && lpClassName < 0x10000 {
			// Integer atom
			classAtomForHwnd = uint16(lpClassName)
			if wp, ok := hctx.AtomWndProc[classAtomForHwnd]; ok {
				hwndWndProc[hwnd] = wp
			}
			className = fmt.Sprintf("atom:0x%x", lpClassName)
		} else if lpClassName != 0 {
			className = readGuestUTF16(lpClassName)
			if a, ok := hctx.ClassNameAtom[strings.ToLower(className)]; ok {
				classAtomForHwnd = a
				if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
					hwndWndProc[hwnd] = wp
				}
			}
			// Fallback only for app-defined classes. Predefined/common-control class names
			// like "edit" must not inherit the app's single registered top-level WndProc.
			if classAtomForHwnd == 0 && len(hctx.ClassNameAtom) == 1 && !isBuiltinWindowClassName(className) {
				for _, a := range hctx.ClassNameAtom {
					classAtomForHwnd = a
					if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
						hwndWndProc[hwnd] = wp
					}
				}
			}
		}
		if classAtomForHwnd != 0 {
			hctx.HwndClassAtom[hwnd] = classAtomForHwnd
		}
		wp := hwndWndProc[hwnd]
		parentHwndLog := ctx.Arg(8)
		ravelog.Logf("[wndclass] CreateWindowExW class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x hMenu=0x%x\n", className, hwnd, parentHwndLog, wp, style, ctx.Arg(9))

		const wsChild = 0x40000000
		// Track child windows (built-in classes like Edit, Static, Button)
		if style&wsChild != 0 {
			cx := readCreateWindowIntArg(ctx, 4)
			cy := readCreateWindowIntArg(ctx, 5)
			cw := readCreateWindowIntArg(ctx, 6)
			ch := readCreateWindowIntArg(ctx, 7)
			parentHwnd := ctx.Arg(8) // hWndParent
			if cx < 0 || cx > maxWindowCoordinate {
				cx = 0
			}
			if cy < 0 || cy > maxWindowCoordinate {
				cy = 0
			}
			var defW, defH int32 = 800, 600
			if wlWindow != nil {
				defW, defH = wlWindow.Width, wlWindow.Height
			}
			// Child windows with invalid/zero dimensions start at 0×0.
			// They will be sized by the parent's WM_SIZE/MoveWindow calls.
			if cw < 0 || cw > maxWindowCoordinate {
				cw = 0
			}
			if ch < 0 || ch > maxWindowCoordinate {
				ch = 0
			}
			lClassName := strings.ToLower(className)
			// Statusbar: auto-position at bottom of parent (absolute)
			if lClassName == "msctls_statusbar32" {
				const sbHeight int32 = 20
				cx, cy = 0, defH-sbHeight
				cw, ch = defW, sbHeight
			} else {
				// Convert from parent-relative to absolute coordinates
				ox, oy := clientAreaOrigin(parentHwnd)
				cx += ox
				cy += oy
			}
			windowName := readGuestUTF16(ctx.Arg(2))
			dwExStyle := uint32(ctx.Arg(0))
			hMenu := ctx.Arg(9) // for child windows, this is the control ID
			hwndChildren[hwnd] = &controlState{
				className:  lClassName,
				parentHWND: parentHwnd,
				ctrlID:     hMenu,
				x:          cx, y: cy, w: cw, h: ch,
				style:   style,
				exStyle: dwExStyle,
				text:    windowName,
				visible: style&0x10000000 != 0, // WS_VISIBLE
			}
			initBuiltinControlState(hwndChildren[hwnd])
			if lClassName == "msctls_progress32" {
				syncProgressBarCompat(hwndChildren[hwnd])
			}
			// Initialise GWL_STYLE / GWL_EXSTYLE so GetWindowLong returns correct values.
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(dwExStyle)}
			win32.Global.Create(hwnd, lClassName, cx, cy, cw, ch, style, dwExStyle, parentHwnd)
			hctx.placeNewChildAtBottom(hwnd)
			// Auto-focus first edit control
			if lClassName == "edit" && hctx.FocusHwnd == 0 {
				hctx.FocusHwnd = hwnd
			}
		}

		if style&wsChild == 0 && win32.Global.Get(hwnd) == nil {
			x := readCreateWindowIntArg(ctx, 4)
			y := readCreateWindowIntArg(ctx, 5)
			if x < 0 || x > maxWindowCoordinate {
				x = 0
			}
			if y < 0 || y > maxWindowCoordinate {
				y = 0
			}
			w, h := resolveTopLevelCreateWindowSize(ctx)
			exStyle := uint32(ctx.Arg(0))
			classForGlobal := className
			if classForGlobal == "" && lpClassName != 0 && lpClassName >= 0x10000 {
				classForGlobal = readGuestUTF16(lpClassName)
			}
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
			win32.Global.Create(hwnd, strings.ToLower(classForGlobal), x, y, w, h, style, exStyle, 0)
		}

		// Create a real or headless framebuffer window for the first top-level window.
		if wlWindow == nil && style&wsChild == 0 {
			title := readGuestUTF16(ctx.Arg(2))
			if title == "" {
				title = "govm"
			}
			w, h := resolveTopLevelCreateWindowSize(ctx)
			ncTop := int32(0)
			if wlDisplay == nil || wlDisplay.HasNoSSD() {
				var r win32.Rect
				exStyle := uint32(ctx.Arg(0))
				win32.AdjustWindowRectEx(&r, style, false, exStyle)
				ncTop = -r.Top
				if ncTop < 0 {
					ncTop = 0
				}
			}
			if wlDisplay != nil {
				if win, err := wlDisplay.CreateWindow(title, w, h, ncTop); err == nil {
					wlWindow = win
					hctx.WlWindow = win
					if hctx.OnWlWindowSet != nil {
						hctx.OnWlWindowSet(win)
					}
					hctx.MainHWND = hwnd
					hctx.MainTitle = title
					// Initialise GWL_STYLE / GWL_EXSTYLE for the main window.
					exStyle := uint32(ctx.Arg(0))
					windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
					// Register the main window in win32.Global so NC paint and other lookups work.
					gx := readCreateWindowIntArg(ctx, 4)
					gy := readCreateWindowIntArg(ctx, 5)
					if gx < 0 || gx > maxWindowCoordinate {
						gx = 0
					}
					if gy < 0 || gy > maxWindowCoordinate {
						gy = 0
					}
					win32.Global.Create(hwnd, strings.ToLower(readGuestUTF16(lpClassName)), gx, gy, w, h+ncTop, style, exStyle, 0)
					ravelog.Logf("[wl] window created: %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
					// Attach menu bar: first check hMenu parameter, then class menu
					hMenu := ctx.Arg(9)
					ravelog.Logf("[menu] CreateWindowExW hMenu=0x%x menus_has=%v\n", hMenu, menus[hMenu] != nil)
					if hMenu != 0 {
						if _, ok := menus[hMenu]; ok {
							hwndMenuBar[hwnd] = hMenu
						}
					}
					if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
						var classAtom uint16
						if lpClassName < 0x10000 {
							classAtom = uint16(lpClassName)
						} else {
							cn := readGuestUTF16(lpClassName)
							classAtom = hctx.ClassNameAtom[strings.ToLower(cn)]
						}
						if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
							hwndMenuBar[hwnd] = mh
							ravelog.Logf("[menu] attached class menu hmenu=0x%x to hwnd=0x%x\n", mh, hwnd)
						}
					}
				} else {
					ravelog.Logf("[wl] CreateWindow failed: %v\n", err)
				}
			} else if hctx.RenderSnapshot != nil {
				win := wl.NewHeadlessWindow(title, w, h, ncTop)
				wlWindow = win
				hctx.WlWindow = win
				if hctx.OnWlWindowSet != nil {
					hctx.OnWlWindowSet(win)
				}
				hctx.MainHWND = hwnd
				hctx.MainTitle = title
				exStyle := uint32(ctx.Arg(0))
				windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
				gx := readCreateWindowIntArg(ctx, 4)
				gy := readCreateWindowIntArg(ctx, 5)
				if gx < 0 || gx > maxWindowCoordinate {
					gx = 0
				}
				if gy < 0 || gy > maxWindowCoordinate {
					gy = 0
				}
				win32.Global.Create(hwnd, strings.ToLower(className), gx, gy, w, h+ncTop, style, exStyle, 0)
				hMenu := ctx.Arg(9)
				if hMenu != 0 {
					if _, ok := menus[hMenu]; ok {
						hwndMenuBar[hwnd] = hMenu
					}
				}
				if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
					var classAtom uint16
					if lpClassName < 0x10000 {
						classAtom = uint16(lpClassName)
					} else {
						cn := readGuestUTF16(lpClassName)
						classAtom = hctx.ClassNameAtom[strings.ToLower(cn)]
					}
					if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
						hwndMenuBar[hwnd] = mh
					}
				}
				ravelog.Logf("[wl] headless window created: %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
			}
		}
		// Dispatch WM_NCCREATE + WM_CREATE synchronously for windows with a WndProc
		if wp, hasWP := hwndWndProc[hwnd]; hasWP && wp != 0 {
			is32 := ctx.State != nil && ctx.State.Is32
			var cs uint64
			if is32 {
				// x86 CREATESTRUCT (48 bytes, 4-byte pointers):
				//  0: lpCreateParams(4) 4: hInstance(4) 8: hMenu(4) 12: hwndParent(4)
				// 16: cy(4) 20: cx(4) 24: y(4) 28: x(4)
				// 32: style(4) 36: lpszName(4) 40: lpszClass(4) 44: dwExStyle(4)
				cs = scratchAlloc(48)
				mem.Write32(cs+0, uint32(ctx.Arg(11))) // lpCreateParams
				mem.Write32(cs+4, uint32(ctx.Arg(10))) // hInstance
				mem.Write32(cs+8, uint32(ctx.Arg(9)))  // hMenu
				mem.Write32(cs+12, uint32(ctx.Arg(8))) // hwndParent
				mem.Write32(cs+16, uint32(ctx.Arg(7))) // cy (nHeight)
				mem.Write32(cs+20, uint32(ctx.Arg(6))) // cx (nWidth)
				mem.Write32(cs+24, uint32(ctx.Arg(5))) // y
				mem.Write32(cs+28, uint32(ctx.Arg(4))) // x
				mem.Write32(cs+32, style)              // style
				mem.Write32(cs+36, uint32(ctx.Arg(2))) // lpszName
				mem.Write32(cs+40, uint32(ctx.Arg(1))) // lpszClass
				mem.Write32(cs+44, uint32(ctx.Arg(0))) // dwExStyle
			} else {
				// x64 CREATESTRUCT (80 bytes, 8-byte pointers):
				cs = scratchAlloc(80)
				mem.Write64(cs+0, ctx.Arg(11))         // lpCreateParams
				mem.Write64(cs+8, ctx.Arg(10))         // hInstance
				mem.Write64(cs+16, ctx.Arg(9))         // hMenu
				mem.Write64(cs+24, ctx.Arg(8))         // hwndParent
				mem.Write32(cs+32, uint32(ctx.Arg(7))) // cy (nHeight)
				mem.Write32(cs+36, uint32(ctx.Arg(6))) // cx (nWidth)
				mem.Write32(cs+40, uint32(ctx.Arg(5))) // y
				mem.Write32(cs+44, uint32(ctx.Arg(4))) // x
				mem.Write32(cs+48, style)              // style
				mem.Write32(cs+52, 0)                  // padding
				mem.Write64(cs+56, ctx.Arg(2))         // lpszName
				mem.Write64(cs+64, ctx.Arg(1))         // lpszClass
				mem.Write32(cs+72, uint32(ctx.Arg(0))) // dwExStyle
			}

			// Synchronous dispatch via trampoline:
			// Queue WM_CREATE (dispatched second), then set up WM_NCCREATE (dispatched first).
			rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
			if ok2 {
				// Save original return address and push a new sync frame.
				// For PE32, the stub's doStdcallCleanup is skipped (ReturnOverridden=true),
				// so we must manually account for stdcall arg cleanup.
				rsp := rr.ReadReg(4)
				var retAddr uint64
				if is32 {
					v, _ := mem.Read32(rsp)
					retAddr = uint64(v)
					// PE32 stdcall cleanup: skip retAddr (4) + 12 args (48)
					rsp += 4 + 12*4
				} else {
					retAddr, _ = mem.Read64(rsp)
				}
				syncStack := hctx.syncStack(ctx)
				*syncStack = append(*syncStack, syncDispatchFrame{
					queue:   []syncDispatch{{wndProc: wp, hwnd: hwnd, msg: 0x0001, wParam: 0, lParam: cs}},
					retAddr: retAddr,
					hwnd:    hwnd,
				})
				ctx.CPU.(ntapi.RegisterWriter).WriteReg(4, rsp)
				hctx.SyncCallWndProc(ctx, wp, hwnd, 0x0081, 0, cs, hctx.SyncTrampoline)
				return 0
			}
			// Fallback: queue messages if register access unavailable
			hctx.enqueueMessage(nil,
				newQueuedMsg(hctx, hwnd, 0x0081, 0, cs),
				newQueuedMsg(hctx, hwnd, 0x0001, 0, cs),
			)
		}

		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[destroy] DestroyWindow hwnd=0x%x\n", hwnd)
		if destroyWindow(hwnd, ctx.CPU) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nCmdShow := ctx.Arg(1)
		ravelog.Logf("[show] ShowWindow hwnd=0x%x nCmdShow=%d\n", hwnd, nCmdShow)
		wnd := win32.Global.Get(hwnd)
		cs, isChild := hwndChildren[hwnd]
		if wnd == nil && !isChild {
			ctx.SetReturn(0)
			return 0
		}
		wasVisible := false
		if isChild {
			wasVisible = cs.visible
		} else {
			wasVisible = uint32(win32.Global.GetLong(hwnd, -16))&wsVisible != 0
		}
		if hctx.MainHWND == 0 && nCmdShow != 0 {
			if wnd != nil && wnd.Parent == 0 && wnd.ClassName != "tooltips_class32" {
				hctx.MainHWND = hwnd
			}
		}
		if hwnd == hctx.MainHWND && nCmdShow != 0 && wlWindow != nil {
			// ReactOS co_WinPosSendSizeMove: WM_SIZE lParam = MAKELONG(clientW, clientH).
			cw, ch := getTopLevelClientSize(hwnd)
			sw := uint64(cw)
			sh := uint64(ch)
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, (sh<<16)|sw)) // WM_SIZE
			// WM_ACTIVATEAPP(TRUE): sent before WM_ACTIVATE when app gains focus.
			// Many DirectX games (DXBall etc.) use this to track active state.
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x001C, 1, 0)) // WM_ACTIVATEAPP
			// WM_ACTIVATE(WA_ACTIVE=1): NPP's WndProc calls SetFocus(scintilla) here.
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0006, 1, 0)) // WM_ACTIVATE
			queuePaint(hwnd)                                                 // WM_PAINT
			// Win32: ShowWindow on a parent cascades visibility only to children that
			// were created with WS_VISIBLE (0x10000000). Windows created without
			// WS_VISIBLE are intentionally hidden and must be shown explicitly.
			for h, child := range hwndChildren {
				if !child.visible && !hwndExplicitlyHidden[h] && child.style&wsVisible != 0 {
					child.visible = true
					if wp, ok2 := hwndWndProc[h]; ok2 && wp != 0 {
						queuePaint(h)
					}
				}
			}
			requestWindowRepaint(hwnd)
		}
		if isChild {
			firstShow := !cs.showCalled
			cs.showCalled = true
			cs.visible = nCmdShow != 0 // SW_HIDE = 0
			if nCmdShow == 0 {
				for candidate, child := range hwndChildren {
					ancestor := child.parentHWND
					for ancestor != 0 && ancestor != hwnd {
						state := hwndChildren[ancestor]
						if state == nil {
							ancestor = 0
							break
						}
						ancestor = state.parentHWND
					}
					if ancestor == hwnd {
						delete(paintedThroughHiddenAncestor, candidate)
					}
				}
				destroyOwnedDialogWindowForCPU(hwnd, ctx.CPU)
				// Only mark explicitly hidden if the window was actually visible.
				// SW_HIDE on a never-shown window is a no-op for cascade/auto-show
				// purposes: a subsequent MoveWindow should still be able to auto-show it.
				if wasVisible {
					hwndExplicitlyHidden[hwnd] = true
				}
			} else {
				delete(hwndExplicitlyHidden, hwnd)
			}
			// Queue WM_PAINT when a window with a guest WndProc becomes visible
			if cs.visible && (!wasVisible || firstShow) {
				if wp, ok2 := hwndWndProc[hwnd]; ok2 && wp != 0 {
					hctx.WinErasePending[hwnd] = true
					queuePaint(hwnd)
				}
			}
		}
		syncWindowVisibleStyle(hwnd, nCmdShow != 0)
		if isChild && cs.visible {
			requestWindowRepaint(hwnd)
		}
		if hwnd == hctx.MainHWND && nCmdShow != 0 && hctx.RenderSnapshot != nil && wlWindow == nil {
			hctx.RenderSnapshot()
		}
		if wasVisible {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UpdateWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		if hwnd == hctx.MainHWND && wlWindow != nil {
			queuePaint(hwnd)
		} else if cs, ok := hwndChildren[hwnd]; ok && cs.visible {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsChild", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		child := ctx.Arg(1)
		if isChildWindow(hwndChildren, parent, child) {
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowW", func(ctx *ntapi.TrapContext) uint32 {
		// FindWindowW(lpClassName, lpWindowName) - search all known HWNDs
		wantClass := strings.ToLower(readGuestUTF16(ctx.Arg(0)))
		wantTitle := readGuestUTF16(ctx.Arg(1))
		for h, cs := range hwndChildren {
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		// Check main window
		if wantClass == "" || wantClass == "notepad++" {
			if wantTitle == "" || hwndTitle[hctx.MainHWND] == wantTitle {
				ctx.SetReturn(hctx.MainHWND)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowExW", func(ctx *ntapi.TrapContext) uint32 {
		// FindWindowExW(hwndParent, hwndChildAfter, lpClassName, lpWindowName)
		parent := ctx.Arg(0)
		childAfter := ctx.Arg(1)
		wantClass := strings.ToLower(readGuestUTF16(ctx.Arg(2)))
		wantTitle := readGuestUTF16(ctx.Arg(3))
		found := childAfter == 0 // if childAfter==0, match first; else skip until we see childAfter
		for h, cs := range hwndChildren {
			if parent != 0 && cs.parentHWND != parent {
				continue
			}
			if !found {
				if h == childAfter {
					found = true
				}
				continue
			}
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FindWindowExA", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		childAfter := ctx.Arg(1)
		wantClass := strings.ToLower(readGuestString(ctx.Arg(2)))
		wantTitle := readGuestString(ctx.Arg(3))
		found := childAfter == 0
		for h, cs := range hwndChildren {
			if parent != 0 && cs.parentHWND != parent {
				continue
			}
			if !found {
				if h == childAfter {
					found = true
				}
				continue
			}
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		root, target, owned := topLevelDialogTarget(hctx, hwnd)
		if owned && target != nil {
			hctx.DialogSurfaceMu.Lock(ctx.CPU)
		}
		var h uint64
		var dc *gdi.DC
		if owned && target != nil {
			oldScreen := gdiMgr.Screen
			gdiMgr.Screen = gdi.WrapPix(target.Pix, target.Width, target.Height+target.TitleBarH, target.Stride)
			if rootState := hwndChildren[root]; rootState != nil {
				ox -= rootState.x
				oy -= rootState.y
			}
			h, dc = gdiMgr.AllocScreenDC()
			dc.Mgr = nil
			gdiMgr.Screen = oldScreen
		} else {
			h, dc = allocScreenDC(ox, oy)
		}
		dc.OriginX = ox
		dc.OriginY = oy
		if owned && target != nil {
			ownedDCWindowsMu.Lock()
			ownedDCWindows[h] = ownedDialogDCState{target: target, cpu: ctx.CPU}
			ownedDCWindowsMu.Unlock()
		}
		x0, y0, x1, y1 := absoluteClientRect(hwnd)
		if owned {
			if rootState := hwndChildren[root]; rootState != nil {
				x0 -= rootState.x
				y0 -= rootState.y
				x1 -= rootState.x
				y1 -= rootState.y
			}
		}
		dc.SetClipRect(x0, y0, x1, y1)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReleaseDC", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(1)
		dc := gdiMgr.GetDC(hdc)
		dirtyScreen := dc != nil && dc.IsScreen && dc.Dirty
		ownedDCWindowsMu.Lock()
		ownedState, owned := ownedDCWindows[hdc]
		delete(ownedDCWindows, hdc)
		ownedDCWindowsMu.Unlock()
		if owned {
			defer hctx.DialogSurfaceMu.Unlock(ownedState.cpu)
		}
		gdiMgr.DeleteDC(hdc)
		if dirtyScreen {
			if ownedState.target != nil {
				ownedState.target.Commit()
			} else {
				requestCommit(false)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSystemMetrics", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		ctx.SetReturn(uint64(win32.GetSystemMetrics(idx)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSysColor", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(getSysColor(uint32(ctx.Arg(0)))))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadCursorW", func(ctx *ntapi.TrapContext) uint32 {
		// Return IDC_ value as handle so SetCursor can map it back.
		// IDC_ARROW=32512, IDC_IBEAM=32513, etc.
		lpCursorName := ctx.Arg(1)
		if lpCursorName < 0x10000 && lpCursorName != 0 {
			ctx.SetReturn(lpCursorName) // atom -> return as-is
		} else {
			ctx.SetReturn(0x00010001) // default dummy
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadIconW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if hInst == 0 && nameArg >= 32512 && nameArg <= 32522 {
			ctx.SetReturn(0x00020000 + nameArg) // system icon
			return 0
		}
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			_, _, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 14, uint32(nameArg))
			if ok {
				handle := 0x00020000 + nameArg
				if icon := loadResourceIcon(uint32(nameArg), 32, 32); icon != nil {
					hctx.storeIcon(handle, icon)
				}
				ctx.SetReturn(handle)
				return 0
			}
		}
		ctx.SetReturn(0x00020001) // dummy icon handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadImageW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		imgType := ctx.Arg(2)
		fuLoad := ctx.Arg(5)
		_ = fuLoad

		fromModule := mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0)
		isIntResource := nameArg < 0x10000

		switch imgType {
		case 0: // IMAGE_BITMAP
			if isIntResource && fromModule {
				resID := uint32(nameArg)
				addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
				if ok2 {
					slots := decodeDIBSlots(addr, sz, 0, 0)
					h := hctx.NextBitmapHandle
					hctx.NextBitmapHandle += 2
					bitCount, _ := mem.Read16(addr + 14)
					width, height := dibDimensions(addr)
					bd := &bitmapHandleData{slots: slots, w: width, h: height, monochrome: bitCount == 1}
					bitmapHandles[h] = bd
					ravelog.Logf("[loadimage] LoadImageW IMAGE_BITMAP resID=0x%x -> handle=0x%x slots=%d\n", resID, h, len(slots))
					ctx.SetReturn(h)
					return 0
				}
			}
		case 1: // IMAGE_ICON
			if isIntResource && fromModule {
				resID := uint32(nameArg)
				_, _, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 14 /*RT_GROUP_ICON*/, resID)
				if ok2 {
					handle := 0x00020000 + uint64(resID)
					if icon := loadResourceIcon(resID, int32(ctx.Arg(3)), int32(ctx.Arg(4))); icon != nil {
						hctx.storeIcon(handle, icon)
					}
					ctx.SetReturn(handle)
					return 0
				}
				_, _, ok3 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 3 /*RT_ICON*/, resID)
				if ok3 {
					handle := 0x00020000 + uint64(resID)
					if icon := loadResourceIcon(resID, int32(ctx.Arg(3)), int32(ctx.Arg(4))); icon != nil {
						hctx.storeIcon(handle, icon)
					}
					ctx.SetReturn(handle)
					return 0
				}
			}
			if hInst == 0 && isIntResource && nameArg >= 32512 && nameArg <= 32522 {
				ctx.SetReturn(0x00020000 + nameArg) // system icon
				return 0
			}
			ctx.SetReturn(0x00020001) // dummy icon
			return 0
		case 2: // IMAGE_CURSOR
			if hInst == 0 && isIntResource && nameArg >= 32512 {
				ctx.SetReturn(0x00010000 + nameArg) // system cursor
				return 0
			}
			ctx.SetReturn(0x00010001) // dummy cursor
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		flags := uint32(ctx.Arg(6))
		const swpNoZOrder = 0x0004
		if flags&swpNoZOrder == 0 {
			if !hctx.reorderZOrder(hwnd, ctx.Arg(1)) {
				if ctx.State != nil {
					offset := uint64(ntapi.TebLastErrorValue)
					if ctx.State.Is32 {
						offset = ntapi.Teb32LastErrorValue
					}
					ctx.Mem.Write32(ctx.State.TEBAddr+offset, 1400) // ERROR_INVALID_WINDOW_HANDLE
				}
				ctx.SetReturn(0)
				return 0
			}
		}
		// Handle main (top-level) window resize - updates the Wayland window
		if hwnd == hctx.MainHWND && wlWindow != nil {
			const swpNoSize = 0x0001
			const swpNoMove = 0x0002
			prevW, prevH := wlWindow.Width, wlWindow.Height
			mainX, mainY := int32(0), int32(0)
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				mainX = wnd.RcWindow.Left
				mainY = wnd.RcWindow.Top
			}
			if flags&swpNoSize == 0 {
				w := int32(ctx.Arg(4))
				h := int32(ctx.Arg(5))
				if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
					if wlWindow.Resize(w, h) {
						syncScreenSurface()
						ravelog.Logf("[setpos] hctx.MainHWND resize -> %dx%d\n", w, h)
					}
					// ReactOS: WM_SIZE lParam = MAKELONG(clientW, clientH).
					clientW, clientH := getTopLevelClientSize(hwnd)
					lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, lParam))
					queuePaint(hwnd)
				}
			}
			if flags&swpNoMove == 0 {
				// Wayland top-level position is compositor-managed; track for GetWindowRect
				mainX = int32(ctx.Arg(2))
				mainY = int32(ctx.Arg(3))
				if mainX < 0 || mainX >= 0x7FFF {
					mainX = 0
				}
				if mainY < 0 || mainY >= 0x7FFF {
					mainY = 0
				}
			}
			// Keep win32.Global in sync for GetWindowRect/GetClientRect
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, mainX, mainY, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH)
			}
			if wlWindow.Width != prevW || wlWindow.Height != prevH {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0003, uint64(uint16(mainX))|(uint64(uint16(mainY))<<16), 0))
			}
			ctx.SetReturn(1)
			return 0
		}
		if ci, ok := hwndChildren[hwnd]; ok {
			const swpNoMove = 0x0002
			const swpNoSize = 0x0001
			const swpShowWindow = 0x0040
			const swpHideWindow = 0x0080
			ox, oy := clientAreaOrigin(ci.parentHWND)
			before, geometry := ci.mutateGeometry(func(geometry *controlGeometry) {
				if flags&swpNoMove == 0 {
					x := int32(ctx.Arg(2))
					y := int32(ctx.Arg(3))
					if x >= 0 && x < 0x7FFF {
						geometry.x = x + ox
					}
					if y >= 0 && y < 0x7FFF {
						geometry.y = y + oy
					}
				}
				if flags&swpNoSize == 0 {
					w := int32(ctx.Arg(4))
					h := int32(ctx.Arg(5))
					if w > 0 && w < 0x7FFF {
						geometry.w = w
					}
					if h > 0 && h < 0x7FFF {
						geometry.h = h
					}
				}
			})
			prevX, prevY := before.x, before.y
			prevW, prevH := before.w, before.h
			if flags&swpShowWindow != 0 {
				ci.visible = true
				syncWindowVisibleStyle(hwnd, true)
				delete(hwndExplicitlyHidden, hwnd)
			}
			if flags&swpHideWindow != 0 {
				ci.visible = false
				syncWindowVisibleStyle(hwnd, false)
				hwndExplicitlyHidden[hwnd] = true
				destroyOwnedDialogWindowForCPU(hwnd, ctx.CPU)
			}
			// Auto-show only when the size was explicitly set in this call (SWP_NOSIZE not
			// set) and the resulting size is non-zero, and the guest never hid the window.
			if flags&swpNoSize == 0 && geometry.w > 0 && geometry.h > 0 && ci.style&wsVisible != 0 && !hwndExplicitlyHidden[hwnd] {
				ci.visible = true
			}
			ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x -> %d,%d %dx%d visible=%v\n", hwnd, ci.className, flags, geometry.x, geometry.y, geometry.w, geometry.h, ci.visible)
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, geometry.x, geometry.y, geometry.w, geometry.h)
			}
			// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
			shiftChildWindows(hwnd, geometry.x-prevX, geometry.y-prevY)
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				if geometry.w != prevW || geometry.h != prevH {
					lParam := uint64(uint16(geometry.w)) | (uint64(uint16(geometry.h)) << 16)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, lParam))
				}
				if geometry.x != prevX || geometry.y != prevY {
					// WM_MOVE lParam = MAKELPARAM(x, y) in client-relative coords
					relX := geometry.x - ox
					relY := geometry.y - oy
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0003, 0, uint64(uint16(relX))|(uint64(uint16(relY))<<16)))
				}
			}
			if ci.visible {
				requestWindowRepaint(hwnd)
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// DeferWindowPos batch positioning
	type deferredPos struct {
		hwnd        uint64
		insertAfter uint64
		x, y        int32
		w, h        int32
		flags       uint32
	}
	deferredBatches := map[uint64][]deferredPos{}
	var deferredMu sync.Mutex
	var nextDWPHandle uint64 = 0xDEF00000

	d.RegisterAutoStubHandler(user32, "BeginDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		const maxDeferredWindows = uint64(65536)
		capacity := ctx.Arg(0)
		if capacity > maxDeferredWindows {
			capacity = maxDeferredWindows
		}
		deferredMu.Lock()
		nextDWPHandle++
		handle := nextDWPHandle
		deferredBatches[handle] = make([]deferredPos, 0, int(capacity))
		deferredMu.Unlock()
		ctx.SetReturn(handle)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		hdwp := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		insertAfter := ctx.Arg(2)
		x := int32(ctx.Arg(3))
		y := int32(ctx.Arg(4))
		cx := int32(ctx.Arg(5))
		cy := int32(ctx.Arg(6))
		flags := uint32(ctx.Arg(7))
		ravelog.Logf("[defer] DeferWindowPos hwnd=0x%x x=%d y=%d w=%d h=%d flags=0x%x\n", hwnd, x, y, cx, cy, flags)
		deferredMu.Lock()
		positions, ok := deferredBatches[hdwp]
		_, childExists := hwndChildren[hwnd]
		windowExists := childExists || hwnd == hctx.MainHWND || win32.Global.Get(hwnd) != nil
		if ok && windowExists {
			deferredBatches[hdwp] = append(positions, deferredPos{
				hwnd: hwnd, insertAfter: insertAfter, x: x, y: y, w: cx, h: cy, flags: flags,
			})
		} else if ok {
			delete(deferredBatches, hdwp)
		}
		deferredMu.Unlock()
		if !ok || !windowExists {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(hdwp)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EndDeferWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		const swpNoMove = 0x0002
		const swpNoSize = 0x0001
		const swpNoZOrder = 0x0004
		const swpShowWindow = 0x0040
		const swpHideWindow = 0x0080
		hdwp := ctx.Arg(0)
		deferredMu.Lock()
		deferredPositions, ok := deferredBatches[hdwp]
		if ok {
			delete(deferredBatches, hdwp)
		}
		deferredMu.Unlock()
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		repaintParentSeen := map[uint64]bool{}
		var repaintParents []uint64
		for _, dp := range deferredPositions {
			ci, ok := hwndChildren[dp.hwnd]
			if !ok {
				continue
			}
			if dp.flags&swpNoZOrder == 0 {
				if !hctx.reorderZOrder(dp.hwnd, dp.insertAfter) {
					ctx.SetReturn(0)
					return 0
				}
			}
			ox, oy := clientAreaOrigin(ci.parentHWND)
			before, geometry := ci.mutateGeometry(func(geometry *controlGeometry) {
				if dp.flags&swpNoMove == 0 {
					geometry.x = dp.x + ox
					geometry.y = dp.y + oy
				}
				if dp.flags&swpNoSize == 0 {
					geometry.w = dp.w
					if geometry.w < 0 {
						geometry.w = 0
					}
					geometry.h = dp.h
					if geometry.h < 0 {
						geometry.h = 0
					}
				}
			})
			prevX, prevY := before.x, before.y
			prevW, prevH := before.w, before.h
			wasVisible := ci.visible
			ravelog.Logf("[setpos] hwnd=0x%x class=%q flags=0x%x -> %d,%d %dx%d\n", dp.hwnd, ci.className, dp.flags, geometry.x, geometry.y, geometry.w, geometry.h)
			// Auto-show: sized non-zero -> implicitly visible
			if dp.flags&swpShowWindow != 0 {
				ci.visible = true
				syncWindowVisibleStyle(dp.hwnd, true)
				delete(hwndExplicitlyHidden, dp.hwnd)
			}
			if dp.flags&swpHideWindow != 0 {
				ci.visible = false
				syncWindowVisibleStyle(dp.hwnd, false)
				hwndExplicitlyHidden[dp.hwnd] = true
			}
			if dp.flags&swpNoSize == 0 && geometry.w > 0 && geometry.h > 0 && ci.style&wsVisible != 0 && !hwndExplicitlyHidden[dp.hwnd] {
				ci.visible = true
			}
			if wnd := win32.Global.Get(dp.hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, geometry.x, geometry.y, geometry.w, geometry.h)
			}
			// Dispatch WM_SIZE / WM_MOVE to children with guest WndProcs
			shiftChildWindows(dp.hwnd, geometry.x-prevX, geometry.y-prevY)
			if wp, ok2 := hwndWndProc[dp.hwnd]; ok2 && wp != 0 {
				if geometry.w != prevW || geometry.h != prevH {
					lParam := uint64(uint16(geometry.w)) | (uint64(uint16(geometry.h)) << 16)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, dp.hwnd, 0x0005, 0, lParam))
				}
				if geometry.x != prevX || geometry.y != prevY {
					relX := geometry.x - ox
					relY := geometry.y - oy
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, dp.hwnd, 0x0003, 0, uint64(uint16(relX))|(uint64(uint16(relY))<<16)))
				}
			}
			if windowPosNeedsRepaint(dp.flags, ci.visible) {
				requestWindowRepaint(dp.hwnd)
			}
			if windowPosParentNeedsRepaint(dp.flags, wasVisible, ci.visible) {
				if parent := ci.parentHWND; parent != 0 && !repaintParentSeen[parent] {
					repaintParentSeen[parent] = true
					repaintParents = append(repaintParents, parent)
				}
			}
		}
		for _, parent := range repaintParents {
			requestWindowRepaint(parent)
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(user32, "MoveWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		newX, newY := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		newW, newH := int32(ctx.Arg(3)), int32(ctx.Arg(4))
		bRepaint := ctx.Arg(5)
		ravelog.Logf("[move] MoveWindow hwnd=0x%x x=%d y=%d w=%d h=%d repaint=%d\n", hwnd, newX, newY, newW, newH, bRepaint)
		// Handle main window resize
		if hwnd == hctx.MainHWND && wlWindow != nil {
			prevW, prevH := wlWindow.Width, wlWindow.Height
			if newW > 0 && newW < 0x7FFF && newH > 0 && newH < 0x7FFF {
				if wlWindow.Resize(newW, newH) {
					syncScreenSurface()
				}
				clientW, clientH := getTopLevelClientSize(hwnd)
				lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, lParam))
				if bRepaint != 0 {
					queuePaint(hwnd)
				}
			}
			// Keep win32.Global in sync
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, 0, 0, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH)
			}
			if wlWindow.Width != prevW || wlWindow.Height != prevH {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0003, 0, 0))
			}
			ctx.SetReturn(1)
			return 0
		}
		if ci, ok := hwndChildren[hwnd]; ok {
			ox, oy := clientAreaOrigin(ci.parentHWND)
			before, geometry := ci.mutateGeometry(func(geometry *controlGeometry) {
				geometry.x = newX + ox
				geometry.y = newY + oy
				if newW > 0 {
					geometry.w = newW
				}
				if newH > 0 {
					geometry.h = newH
				}
			})
			prevX, prevY := before.x, before.y
			prevW, prevH := before.w, before.h
			sizeChanged := geometry.w != prevW || geometry.h != prevH
			// Auto-show only if size actually changed to non-zero, and guest never hid it.
			if sizeChanged && geometry.w > 0 && geometry.h > 0 && ci.style&wsVisible != 0 && !hwndExplicitlyHidden[hwnd] {
				ci.visible = true
			}
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				win32.Global.UpdatePos(wnd, geometry.x, geometry.y, geometry.w, geometry.h)
			}
			shiftChildWindows(hwnd, geometry.x-prevX, geometry.y-prevY)
			// Queue WM_SIZE / WM_MOVE for windows with a guest WndProc
			if wp, ok := hwndWndProc[hwnd]; ok && wp != 0 {
				if sizeChanged {
					lParam := uint64(uint16(geometry.w)) | (uint64(uint16(geometry.h)) << 16)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, lParam))
				}
				if geometry.x != prevX || geometry.y != prevY {
					relX := geometry.x - ox
					relY := geometry.y - oy
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0003, 0, uint64(uint16(relX))|(uint64(uint16(relY))<<16)))
				}
			}
			// Only repaint if size changed to a valid value (not just a position update).
			if bRepaint != 0 && sizeChanged && geometry.w > 0 && geometry.h > 0 {
				hctx.WinErasePending[hwnd] = true
				queuePaint(hwnd)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		text := readGuestUTF16(ctx.Arg(1))
		if hwnd == hctx.MainHWND && text != "" {
			hctx.MainTitle = text
			if wlWindow != nil {
				if wlDisplay != nil {
					wlDisplay.SetWindowTitle(wlWindow, text)
				} else {
					wlWindow.SetTitleText(text)
				}
			}
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.text = text
		}
		hwndTitle[hwnd] = text
		if win := hctx.WlWindows[hwnd]; win != nil && wlDisplay != nil {
			wlDisplay.SetWindowTitle(win, text)
			requestWindowRepaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		if old == 0 {
			old = win32.Global.GetLong(hwnd, index)
		}
		m[index] = newVal
		// GWLP_WNDPROC (-4): sync with hwndWndProc dispatch map
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			if old == 0 && isBuiltinControl(hwnd) {
				old = builtinControlWndProc
			}
			hwndWndProc[hwnd] = newVal
		}
		win32.Global.SetLong(hwnd, index, newVal)
		ravelog.Logf("[wndlong] SetWindowLongPtrW hwnd=0x%x index=%d val=0x%x\n", hwnd, index, newVal)
		// GWL_STYLE (-16): sync cs.style and cs.visible from WS_VISIBLE bit.
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		if val == 0 {
			val = win32.Global.GetLong(hwnd, index)
		}
		val = applyWindowEnabledStyle(hwnd, index, val)
		// GWLP_WNDPROC (-4): fall back to hwndWndProc dispatch map
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
			if val == 0 && isBuiltinControl(hwnd) {
				val = builtinControlWndProc
			}
		}
		ravelog.Logf("[wndlong] GetWindowLongPtrW hwnd=0x%x index=%d -> 0x%x\n", hwnd, index, val)
		ctx.SetReturn(val)
		return 0
	})
	// SetWindowLongPtrA: ANSI version mirrors SetWindowLongPtrW
	d.RegisterAutoStubHandler(user32, "SetWindowLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		if old == 0 {
			old = win32.Global.GetLong(hwnd, index)
		}
		m[index] = newVal
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			if old == 0 && isBuiltinControl(hwnd) {
				old = builtinControlWndProc
			}
			hwndWndProc[hwnd] = newVal
		}
		win32.Global.SetLong(hwnd, index, newVal)
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ravelog.Logf("[wndlong] SetWindowLongPtrA hwnd=0x%x index=%d val=0x%x\n", hwnd, index, newVal)
		ctx.SetReturn(old)
		return 0
	})
	// GetWindowLongPtrA: ANSI version mirrors GetWindowLongPtrW
	d.RegisterAutoStubHandler(user32, "GetWindowLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		if val == 0 {
			val = win32.Global.GetLong(hwnd, index)
		}
		val = applyWindowEnabledStyle(hwnd, index, val)
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
			if val == 0 && isBuiltinControl(hwnd) {
				val = builtinControlWndProc
			}
		}
		ravelog.Logf("[wndlong] GetWindowLongPtrA hwnd=0x%x index=%d -> 0x%x\n", hwnd, index, val)
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		if old == 0 {
			old = win32.Global.GetLong(hwnd, index)
		}
		m[index] = newVal
		win32.Global.SetLong(hwnd, index, newVal)
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			if old == 0 && isBuiltinControl(hwnd) {
				old = builtinControlWndProc
			}
			hwndWndProc[hwnd] = newVal
		}
		if index == -16 {
			if cs, ok := hwndChildren[hwnd]; ok {
				const wsVisible = uint32(0x10000000)
				cs.style = uint32(newVal)
				nowVisible := cs.style&wsVisible != 0
				if nowVisible && !cs.visible {
					cs.visible = true
					delete(hwndExplicitlyHidden, hwnd)
				} else if !nowVisible && cs.visible {
					cs.visible = false
				}
			}
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		if index >= 0 {
			if atom := hctx.HwndClassAtom[hwnd]; atom != 0 {
				if ci := hctx.ClassInfo[atom]; ci != nil && index >= ci.WndExtra {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		if val == 0 {
			val = win32.Global.GetLong(hwnd, index)
		}
		val = applyWindowEnabledStyle(hwnd, index, val)
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
			if val == 0 && isBuiltinControl(hwnd) {
				val = builtinControlWndProc
			}
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetPropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		hData := ctx.Arg(2)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		m := windowProps[hwnd]
		if m == nil {
			m = make(map[string]uint64)
			windowProps[hwnd] = m
		}
		m[name] = hData
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			ctx.SetReturn(m[name])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RemovePropW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestUTF16(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			old := m[name]
			delete(m, name)
			ctx.SetReturn(old)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClientRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			normalizeOwnedStatusGeometry(hwnd)
			var left, top, right, bottom int32
			if ci, ok := hwndChildren[hwnd]; ok {
				right, bottom = ci.w, ci.h
				if ci.style&win32.WS_VSCROLL != 0 {
					right -= win32.GetSystemMetrics(win32.SM_CXVSCROLL)
				}
				if ci.style&win32.WS_HSCROLL != 0 {
					bottom -= win32.GetSystemMetrics(win32.SM_CYHSCROLL)
				}
			} else if hwnd == hctx.MainHWND {
				right, bottom = getTopLevelClientSize(hwnd)
			} else if wnd := win32.Global.Get(hwnd); wnd != nil {
				// Window registered in global table but not yet in hwndChildren
				right = wnd.RcClient.Width()
				bottom = wnd.RcClient.Height()
			} else {
				right, bottom = 800, 600
				if wlWindow != nil {
					right, bottom = wlWindow.Width, wlWindow.Height
				}
			}
			ravelog.Logf("[getrect] GetClientRect hwnd=0x%x -> %d,%d,%d,%d\n", hwnd, left, top, right, bottom)
			ctx.Mem.Write32(pRect, uint32(left))
			ctx.Mem.Write32(pRect+4, uint32(top))
			ctx.Mem.Write32(pRect+8, uint32(right))
			ctx.Mem.Write32(pRect+12, uint32(bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if pRect != 0 {
			if wnd := win32.Global.Get(hwnd); wnd != nil {
				// Use the pre-computed screen-absolute window rect from win32.Global
				ctx.Mem.Write32(pRect, uint32(wnd.RcWindow.Left))
				ctx.Mem.Write32(pRect+4, uint32(wnd.RcWindow.Top))
				ctx.Mem.Write32(pRect+8, uint32(wnd.RcWindow.Right))
				ctx.Mem.Write32(pRect+12, uint32(wnd.RcWindow.Bottom))
			} else if ci, ok := hwndChildren[hwnd]; ok {
				// Fallback: child window stored absolute coords
				ctx.Mem.Write32(pRect, uint32(ci.x))
				ctx.Mem.Write32(pRect+4, uint32(ci.y))
				ctx.Mem.Write32(pRect+8, uint32(ci.x+ci.w))
				ctx.Mem.Write32(pRect+12, uint32(ci.y+ci.h))
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, uint32(wlWindow.Width))
				ctx.Mem.Write32(pRect+12, uint32(wlWindow.Height+wlWindow.TitleBarH))
			} else {
				var fw, fh int32 = 800, 600
				if wlWindow != nil {
					fw, fh = wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH
				}
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, uint32(fw))
				ctx.Mem.Write32(pRect+12, uint32(fh))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		ownerCPU := hctx.windowCPU(hwnd)
		if ownerCPU != nil && ownerCPU != ctx.CPU {
			request := newSynchronousSendRequest(hwnd, msg, wParam, lParam)
			request.sender = ctx.CPU
			if !hctx.MsgQueue.enqueueSynchronous(ownerCPU, request) {
				ctx.SetReturn(0)
				return 0
			}
			if !beginCrossThreadSend(ctx, request) {
				ctx.SetReturn(request.wait())
			}
			return 0
		}
		// Built-in controls first
		if !hasWindowSubclass(hwnd) {
			if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				if builtinMessageNeedsCommit(msg) {
					requestCommit(true)
				}
				ctx.SetReturn(result)
				return 0
			}
		}
		// For guest WndProcs: dispatch synchronously via hctx.SyncStack
		wp, hasWP := hwndWndProc[hwnd]
		if !hasWP || wp == 0 {
			// Fallback: recover WndProc via class atom (same logic as DispatchMessageW).
			if atom, hasAtom := hctx.HwndClassAtom[hwnd]; hasAtom {
				if recovered, ok := hctx.AtomWndProc[atom]; ok && recovered != 0 {
					wp = recovered
					hasWP = true
					hwndWndProc[hwnd] = wp
				}
			}
		}
		if !hasWP || wp == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okW && okR {
			is32 := ctx.State != nil && ctx.State.Is32
			rsp := rr.ReadReg(4)
			var retAddr uint64
			if is32 {
				r32, _ := mem.Read32(rsp)
				retAddr = uint64(r32)
			} else {
				retAddr, _ = mem.Read64(rsp)
			}
			// Validate retAddr: must be a plausible code address (>= 16MB).
			// Values below 0x1000000 are HWNDs or other small handles stored on the
			// stack (e.g., as shadow space), not valid return addresses. Using such a
			// value as a return target after WndProc would crash the CPU.
			if retAddr < 0x1000000 {
				ctx.SetReturn(0)
				return 0
			}
			syncStack := hctx.syncStack(ctx)
			*syncStack = append(*syncStack, syncDispatchFrame{
				queue:               []syncDispatch{},
				retAddr:             retAddr,
				hwnd:                hwnd,
				returnWndProcResult: true,
			})
			if is32 {
				// PE32 stdcall: manually clean up SendMessageW's 4 args + retAddr
				rsp += 4 + 4*4 // skip retAddr + 4 args
				rw.WriteReg(4, rsp)
				hctx.SyncCallWndProc(ctx, wp, hwnd, msg, wParam, lParam, hctx.SyncTrampoline)
			} else {
				rsp -= 48
				mem.Write64(rsp, hctx.SyncTrampoline)
				rw.WriteReg(4, rsp)
				rw.WriteReg(1, hwnd)
				rw.WriteReg(2, uint64(msg))
				rw.WriteReg(8, wParam)
				rw.WriteReg(9, lParam)
				ctx.CPU.SetPC(wp)
				ctx.ReturnOverridden = true
				ctx.PCRedirected = true
			}
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PostMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		// Route into our message queue so guest WndProcs see it
		if hwnd == 0 {
			hctx.enqueueMessage(ctx.CPU, newQueuedMsg(hctx, 0, msg, wParam, lParam))
		} else if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, msg, wParam, lParam))
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, msg, wParam, lParam))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	defWindowProcFn := func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)

		// WM_PAINT: draw non-client area (NC paint + menu bar), erase background, paint children
		if msg == 0x000F && wlWindow != nil {
			// DefWindowProc validates the update region through its internal
			// BeginPaint/EndPaint path, even when the application does not.
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			if hwnd == hctx.MainHWND {
				if wlWindow.ResizeIfNeeded() {
					syncScreenSurface()
				}
				w := wlWindow.Width

				// Trigger NC paint first (draws frame + caption + client edge)
				if wlWindow.TitleBarH > 0 {
					ncPaintCtx := *ctx // shallow copy for re-entrant dispatch
					_ = ncPaintCtx
					// Directly invoke our WM_NCPAINT handler logic
					wnd := win32.Global.Get(hwnd)
					if wnd != nil {
						ncStyle := wnd.Style
						ncExStyle := wnd.ExStyle
						winW := wlWindow.Width
						winH := wlWindow.Height + wlWindow.TitleBarH
						syncScreenSurface()
						_, ncDC := gdiMgr.AllocScreenDC()
						ncDC.OriginX = 0
						ncDC.OriginY = 0
						curL, curT, curR, curB := int32(0), int32(0), winW, winH

						if win32.UserHasWindowEdge(ncStyle, ncExStyle) {
							ncDC.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, hctx.SysColors)
							curL += 2
							curT += 2
							curR -= 2
							curB -= 2
						}
						if ncStyle&0x00040000 != 0 && ncStyle&0x20000000 == 0 {
							fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
								win32.GetSystemMetrics(win32.SM_CXBORDER)
							fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
								win32.GetSystemMetrics(win32.SM_CYBORDER)
							borderColor := hctx.SysColors[10]
							if !hctx.MainActive {
								borderColor = hctx.SysColors[11]
							}
							ncDC.FillRect(curL, curT, curR, curT+fH, borderColor)
							ncDC.FillRect(curL, curT, curL+fW, curB, borderColor)
							ncDC.FillRect(curL, curB-fH, curR, curB, borderColor)
							ncDC.FillRect(curR-fW, curT, curR, curB, borderColor)
							curL += fW
							curT += fH
							curR -= fW
							curB -= fH
						}
						if ncStyle&(0x00400000|0x00800000) != 0 || ncExStyle&0x00000001 != 0 {
							bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
							bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
							var brushColor uint32
							if ncExStyle&(0x00000001|0x00000200) != 0 {
								brushColor = hctx.SysColors[15]
							} else if ncExStyle&0x00020000 != 0 {
								brushColor = hctx.SysColors[6]
							} else if ncStyle&(0x00400000|0x00040000) != 0 {
								brushColor = hctx.SysColors[15]
							} else {
								brushColor = hctx.SysColors[6]
							}
							ncDC.FillRect(curL, curT, curR, curT+bH, brushColor)
							ncDC.FillRect(curL, curT, curL+bW, curB, brushColor)
							ncDC.FillRect(curL, curB-bH, curR, curB, brushColor)
							ncDC.FillRect(curR-bW, curT, curR, curB, brushColor)
							curL += bW
							curT += bH
							curR -= bW
							curB -= bH
						}
						if ncStyle&0x00C00000 == 0x00C00000 {
							captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
							if ncExStyle&0x00000080 != 0 {
								captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
							}
							captionBottom := curT + captionH
							flags := uint32(0x0020 | 0x0008)
							if hctx.MainActive {
								flags |= 0x0001
							}
							ncDC.DrawCaption(curL, curT, curR, captionBottom-1, hctx.MainTitle, flags, hctx.SysColors)
							btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
							btnH := captionH - 2
							if ncStyle&0x00080000 != 0 {
								ncDC.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, hctx.SysColors)
								if ncExStyle&0x00000080 == 0 && ncStyle&(0x00020000|0x00010000) != 0 {
									ncDC.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, hctx.SysColors)
									ncDC.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, hctx.SysColors)
								}
							}
							lineColor := hctx.SysColors[15]
							ncDC.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)
							curT = captionBottom
						}
						if ncExStyle&0x00000200 != 0 {
							ncDC.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, hctx.SysColors)
						}
					}
				}

				clientTop := wlWindow.TitleBarH
				ravelog.Logf("[paint] DefWndProc WM_PAINT hctx.MainHWND w=%d h=%d\n", wlWindow.Width, wlWindow.Height)

				// Non-client area: draw menu bar
				menuH, menuOk := hwndMenuBar[hwnd]
				if menuOk {
					md, ok2 := menus[menuH]
					if ok2 && len(md.items) > 0 {
						menuBarH := win32.GetSystemMetrics(win32.SM_CYMENU)
						clientTop = wlWindow.TitleBarH + menuBarH
						wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, hctx.SysColors[15])
						wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, hctx.SysColors[16])
						x := int32(4)
						for i, item := range md.items {
							if item.flags&0x0800 != 0 {
								continue
							}
							// Only show popup items in menu bar (items with submenus)
							if item.flags&0x0010 == 0 {
								continue
							}
							label, _ := menuTextParts(menuStripAmpersand(item.text))
							if label == "" || label == "-" {
								continue
							}
							if !menuHasRenderableText(label) {
								continue
							}
							tw := menuTextWidth(label) + 12
							if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hwnd {
								wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, hctx.SysColors[20])
								ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[20], true, 12)
							} else {
								ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[15], true, 12)
							}
							x += tw
						}
						if effectiveDarkModeForWindow(hwnd, hwndChildren) {
							remapWaylandRectForDarkMode(wlWindow, 0, wlWindow.TitleBarH, w, clientTop)
						}
						dispatchUAHMenuMessages(hctx, hwnd, menuH, nil)

						// Dropdown overlay drawn later in commitIfDone (after paintTree).
					}
				}

				// Fill entire client area with background color.
				// Builtin children will paint on top via paintTree.
				// Guest-drawn children (Scintilla) repaint in their own
				// WM_PAINT pass and trigger a re-commit.
				totalH := wlWindow.Height + wlWindow.TitleBarH
				vScrollW, hScrollH := getClientScrollbarSizes(hwnd)
				clientRight := w - vScrollW
				clientBottom := totalH - hScrollH
				if clientRight < 0 {
					clientRight = 0
				}
				if clientBottom < clientTop {
					clientBottom = clientTop
				}
				wlWindow.DrawRectAbs(0, clientTop, clientRight, clientBottom, hctx.SysColors[5])
				if vScrollW > 0 {
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_VERT, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   clientRight,
						Top:    clientTop,
						Right:  w,
						Bottom: clientBottom,
					}, true, si)
				}
				if hScrollH > 0 {
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_HORZ, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   0,
						Top:    clientBottom,
						Right:  clientRight,
						Bottom: totalH,
					}, false, si)
				}
				if vScrollW > 0 && hScrollH > 0 {
					wlWindow.DrawRectAbs(clientRight, clientBottom, w, totalH, hctx.SysColors[15])
				}

				// Recursively paint built-in descendant windows (builtinWndProc skips app-defined children)
				paintTree(hwnd)
				// Signal that the base frame is ready; all subsequent EndPaints can trigger re-commits.
				hctx.HasBaseFrame = true
				hctx.RepaintBuiltin = true
				// Always commit the base frame immediately. Guest-wndproc children
				// (e.g. Scintilla) will re-commit when their EndPaint fires.
				// Previously we deferred waiting for their EndPaint, but child
				// WM_PAINT sits behind WM_SIZE/WM_MOVE in the FIFO queue and
				// under emulation the delay is unbounded -> permanently gray window.
				hctx.FrameReady = true
				commitIfDone()
				// Queue WM_PAINT for guest children so they repaint on top.
				for h, cs := range hwndChildren {
					if cs.parentHWND == hctx.MainHWND && cs.visible && cs.w > 0 && cs.h > 0 {
						wp := hwndWndProc[h]
						if wp == 0 {
							if atom, ok2 := hctx.HwndClassAtom[h]; ok2 {
								if recovered, ok3 := hctx.AtomWndProc[atom]; ok3 && recovered != 0 {
									wp = recovered
									hwndWndProc[h] = wp
								}
							}
						}
						if wp != 0 {
							queuePaint(h)
						}
					}
				}
			}
			// For non-hctx.MainHWND: ReactOS DefWindowProc just calls BeginPaint+EndPaint
			// In our model, the child is painted by paintTree from the parent
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCCALCSIZE (0x0083): compute client rect from window rect.
		// Ported from ReactOS nonclient.c NC_HandleNCCalcSize.
		if msg == 0x0083 && wlWindow != nil {
			wnd := win32.Global.Get(hwnd)
			if wnd != nil {
				style := wnd.Style
				exStyle := wnd.ExStyle
				if style&0x20000000 == 0 { // !WS_MINIMIZE
					// Read the proposed RECT from guest memory (lParam).
					// For wParam==0 lParam -> single RECT.
					// For wParam==1 lParam -> NCCALCSIZE_PARAMS (first RECT is the new window rect).
					rAddr := lParam
					rL, _ := mem.Read32(rAddr)
					rT, _ := mem.Read32(rAddr + 4)
					rR, _ := mem.Read32(rAddr + 8)
					rBot, _ := mem.Read32(rAddr + 12)
					left := int32(rL)
					top := int32(rT)
					right := int32(rR)
					bottom := int32(rBot)

					// Deflate by border
					if win32.UserHasWindowEdge(style, exStyle) {
						bx, by := win32.BorderSize(style, exStyle)
						left += bx
						top += by
						right -= bx
						bottom -= by
					} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						left++
						top++
						right--
						bottom--
					} else if style&0x00800000 != 0 { // WS_BORDER
						left++
						top++
						right--
						bottom--
					}

					// Subtract caption
					if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
						if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
							top += win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
						} else {
							top += win32.GetSystemMetrics(win32.SM_CYCAPTION)
						}
					}

					// Subtract menu bar
					if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
						top += win32.GetSystemMetrics(win32.SM_CYMENU)
					}

					if style&win32.WS_VSCROLL != 0 {
						right -= win32.GetSystemMetrics(win32.SM_CXVSCROLL)
					}
					if style&win32.WS_HSCROLL != 0 {
						bottom -= win32.GetSystemMetrics(win32.SM_CYHSCROLL)
					}

					// Subtract client edge
					if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
						bw := win32.GetSystemMetrics(win32.SM_CXBORDER)
						bh := win32.GetSystemMetrics(win32.SM_CYBORDER)
						left += 2 * bw
						top += 2 * bh
						right -= 2 * bw
						bottom -= 2 * bh
					}

					if top > bottom {
						bottom = top
					}
					if left > right {
						right = left
					}

					// Write back
					mem.Write32(rAddr, uint32(left))
					mem.Write32(rAddr+4, uint32(top))
					mem.Write32(rAddr+8, uint32(right))
					mem.Write32(rAddr+12, uint32(bottom))
				}
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCPAINT (0x0085): draw the non-client area.
		// Ported from ReactOS nonclient.c NC_DoNCPaint.
		if msg == 0x0085 && wlWindow != nil && hwnd == hctx.MainHWND {
			wnd := win32.Global.Get(hwnd)
			if wnd != nil {
				style := wnd.Style
				exStyle := wnd.ExStyle
				winW := wlWindow.Width
				winH := wlWindow.Height + wlWindow.TitleBarH
				// Create a window DC (origin 0,0 covering full surface including NC)
				syncScreenSurface()
				hDC, dc := gdiMgr.AllocScreenDC()
				dc.OriginX = 0
				dc.OriginY = 0
				// Current rect tracks the shrinking paint area
				curL, curT, curR, curB := int32(0), int32(0), winW, winH

				// 1. Draw outer edge (EDGE_RAISED)
				if win32.UserHasWindowEdge(style, exStyle) {
					dc.DrawEdge(curL, curT, curR, curB, 0x0005, 0x000F, hctx.SysColors) // EDGE_RAISED|BF_RECT
					curL += 2
					curT += 2
					curR -= 2
					curB -= 2 // BF_ADJUST
				} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
					dc.FillRect(curL, curT, curR, curT+1, hctx.SysColors[16]) // top
					dc.FillRect(curL, curT, curL+1, curB, hctx.SysColors[16]) // left
					dc.FillRect(curL, curB-1, curR, curB, hctx.SysColors[20]) // bottom
					dc.FillRect(curR-1, curT, curR, curB, hctx.SysColors[20]) // right
					curL++
					curT++
					curR--
					curB--
				}

				// 2. Draw frame (NC_DrawFrame from ReactOS)
				if style&0x00040000 != 0 && style&0x20000000 == 0 { // WS_THICKFRAME && !WS_MINIMIZE
					fW := (win32.GetSystemMetrics(win32.SM_CXFRAME) - win32.GetSystemMetrics(win32.SM_CXDLGFRAME)) *
						win32.GetSystemMetrics(win32.SM_CXBORDER)
					fH := (win32.GetSystemMetrics(win32.SM_CYFRAME) - win32.GetSystemMetrics(win32.SM_CYDLGFRAME)) *
						win32.GetSystemMetrics(win32.SM_CYBORDER)
					borderColor := hctx.SysColors[10] // COLOR_ACTIVEBORDER
					if !hctx.MainActive {
						borderColor = hctx.SysColors[11] // COLOR_INACTIVEBORDER
					}
					dc.FillRect(curL, curT, curR, curT+fH, borderColor)
					dc.FillRect(curL, curT, curL+fW, curB, borderColor)
					dc.FillRect(curL, curB-fH, curR, curB, borderColor)
					dc.FillRect(curR-fW, curT, curR, curB, borderColor)
					curL += fW
					curT += fH
					curR -= fW
					curB -= fH
				}
				// Inner border
				if style&(0x00400000|0x00800000) != 0 || exStyle&0x00000001 != 0 { // WS_DLGFRAME|WS_BORDER|WS_EX_DLGMODALFRAME
					bW := win32.GetSystemMetrics(win32.SM_CXBORDER)
					bH := win32.GetSystemMetrics(win32.SM_CYBORDER)
					var brushColor uint32
					if exStyle&(0x00000001|0x00000200) != 0 { // WS_EX_DLGMODALFRAME|WS_EX_CLIENTEDGE
						brushColor = hctx.SysColors[15] // COLOR_3DFACE
					} else if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
						brushColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					} else if style&(0x00400000|0x00040000) != 0 { // WS_DLGFRAME|WS_THICKFRAME
						brushColor = hctx.SysColors[15] // COLOR_3DFACE
					} else {
						brushColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					}
					dc.FillRect(curL, curT, curR, curT+bH, brushColor)
					dc.FillRect(curL, curT, curL+bW, curB, brushColor)
					dc.FillRect(curL, curB-bH, curR, curB, brushColor)
					dc.FillRect(curR-bW, curT, curR, curB, brushColor)
					curL += bW
					curT += bH
					curR -= bW
					curB -= bH
				}

				// 3. Draw caption
				if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
					captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
					if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
						captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
					}
					captionBottom := curT + captionH
					// Draw caption bar with gradient
					flags := uint32(0x0020 | 0x0008) // DC_GRADIENT | DC_TEXT
					if hctx.MainActive {
						flags |= 0x0001 // DC_ACTIVE
					}
					dc.DrawCaption(curL, curT, curR, captionBottom-1, hctx.MainTitle, flags, hctx.SysColors)

					// Draw caption buttons (ReactOS UserDrawCaptionButton)
					btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
					btnH := captionH - 2
					if style&0x00080000 != 0 { // WS_SYSMENU
						// Close button (rightmost)
						dc.DrawFrameControl(curR-btnW, curT, curR, curT+btnH, 1, 0, hctx.SysColors) // DFC_CAPTION, DFCS_CAPTIONCLOSE
						// Min/Max if not tool window
						if exStyle&0x00000080 == 0 {
							if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
								dc.DrawFrameControl(curR-2*btnW, curT, curR-btnW, curT+btnH, 1, 2, hctx.SysColors)   // DFCS_CAPTIONMAX
								dc.DrawFrameControl(curR-3*btnW, curT, curR-2*btnW, curT+btnH, 1, 1, hctx.SysColors) // DFCS_CAPTIONMIN
							}
						}
					}

					// Line under caption (ReactOS: IntSetDCPenColor + LineTo)
					lineColor := hctx.SysColors[15]                               // COLOR_3DFACE
					if exStyle&(0x00020000|0x00000200|0x00000001) == 0x00020000 { // only WS_EX_STATICEDGE
						lineColor = hctx.SysColors[6] // COLOR_WINDOWFRAME
					}
					dc.FillRect(curL, captionBottom-1, curR, captionBottom, lineColor)

					curT = captionBottom
				}

				if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
					menuBarH := win32.GetSystemMetrics(win32.SM_CYMENU)
					dc.FillRect(curL, curT, curR, curT+menuBarH, hctx.SysColors[30])
					dc.FillRect(curL, curT+menuBarH-1, curR, curT+menuBarH, hctx.SysColors[16])
					curT += menuBarH
				}

				if style&win32.WS_VSCROLL != 0 {
					sbW := win32.GetSystemMetrics(win32.SM_CXVSCROLL)
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_VERT, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   curR - sbW,
						Top:    curT,
						Right:  curR,
						Bottom: curB,
					}, true, si)
					curR -= sbW
				}
				if style&win32.WS_HSCROLL != 0 {
					sbH := win32.GetSystemMetrics(win32.SM_CYHSCROLL)
					si := win32.ScrollInfo{}
					win32.GetScrollInfo(hwnd, win32.SB_HORZ, &si, win32.SIF_ALL)
					drawScrollBar(win32.Rect{
						Left:   curL,
						Top:    curB - sbH,
						Right:  curR,
						Bottom: curB,
					}, false, si)
					curB -= sbH
				}
				if style&win32.WS_VSCROLL != 0 && style&win32.WS_HSCROLL != 0 {
					wlWindow.DrawRectAbs(curR, curB, winW, winH, hctx.SysColors[15])
				}

				// 5. Client edge
				if exStyle&0x00000200 != 0 { // WS_EX_CLIENTEDGE
					dc.DrawEdge(curL, curT, curR, curB, 0x000A, 0x000F, hctx.SysColors) // EDGE_SUNKEN|BF_RECT
				}

				if effectiveDarkModeForWindow(hwnd, hwndChildren) {
					remapDCRectForDarkMode(dc, 0, 0, winW, curT)
				}
				gdiMgr.DeleteDC(hDC)
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_NCACTIVATE (0x0086): redraw caption with active/inactive state.
		if msg == 0x0086 && wlWindow != nil && hwnd == hctx.MainHWND {
			hctx.MainActive = wParam != 0
			// Queue WM_NCPAINT so the caption redraws with correct active/inactive colours.
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0085, 1, 0))
			ctx.SetReturn(1) // return TRUE = allow activation change
			return 0
		}
		// WM_NCHITTEST (0x0084): hit-test the non-client area.
		// Ported from ReactOS nonclient.c DefWndNCHitTest.
		if msg == 0x0084 && wlWindow != nil && hwnd == hctx.MainHWND {
			// lParam contains POINT: x = LOWORD, y = HIWORD (signed)
			px := int32(int16(lParam & 0xFFFF))
			py := int32(int16((lParam >> 16) & 0xFFFF))
			wnd := win32.Global.Get(hwnd)
			if wnd == nil {
				ctx.SetReturn(1) // HTCLIENT
				return 0
			}
			style := wnd.Style
			exStyle := wnd.ExStyle
			winW := wlWindow.Width
			winH := wlWindow.Height + wlWindow.TitleBarH
			// Window rect in screen coords (we use 0,0 origin for top-level)
			wr := win32.Rect{Left: 0, Top: 0, Right: winW, Bottom: winH}
			if !win32.PtInRect(&wr, px, py) {
				ctx.SetReturn(0) // HTNOWHERE
				return 0
			}

			// Deflate by border
			if win32.UserHasWindowEdge(style, exStyle) {
				bx, by := win32.BorderSize(style, exStyle)
				win32.InflateRect(&wr, -bx, -by)
				if !win32.PtInRect(&wr, px, py) {
					// In the border area - determine which border
					xSize := win32.GetSystemMetrics(win32.SM_CXSIZE) * win32.GetSystemMetrics(win32.SM_CXBORDER)
					ySize := win32.GetSystemMetrics(win32.SM_CYSIZE) * win32.GetSystemMetrics(win32.SM_CYBORDER)
					thickFrame := style&0x00040000 != 0 // WS_THICKFRAME
					if py < wr.Top {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						} // HTBORDER
						if px < wr.Left+xSize {
							ctx.SetReturn(13)
							return 0
						} // HTTOPLEFT
						if px >= wr.Right-xSize {
							ctx.SetReturn(14)
							return 0
						} // HTTOPRIGHT
						ctx.SetReturn(12)
						return 0 // HTTOP
					}
					if py >= wr.Bottom {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if px < wr.Left+xSize {
							ctx.SetReturn(16)
							return 0
						} // HTBOTTOMLEFT
						if px >= wr.Right-xSize {
							ctx.SetReturn(17)
							return 0
						} // HTBOTTOMRIGHT
						ctx.SetReturn(15)
						return 0 // HTBOTTOM
					}
					if px < wr.Left {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if py < wr.Top+ySize {
							ctx.SetReturn(13)
							return 0
						} // HTTOPLEFT
						if py >= wr.Bottom-ySize {
							ctx.SetReturn(16)
							return 0
						} // HTBOTTOMLEFT
						ctx.SetReturn(10)
						return 0 // HTLEFT
					}
					if px >= wr.Right {
						if !thickFrame {
							ctx.SetReturn(18)
							return 0
						}
						if py < wr.Top+ySize {
							ctx.SetReturn(14)
							return 0
						} // HTTOPRIGHT
						if py >= wr.Bottom-ySize {
							ctx.SetReturn(17)
							return 0
						} // HTBOTTOMRIGHT
						ctx.SetReturn(11)
						return 0 // HTRIGHT
					}
				}
			} else {
				if exStyle&0x00020000 != 0 { // WS_EX_STATICEDGE
					win32.InflateRect(&wr, -1, -1)
				}
				if !win32.PtInRect(&wr, px, py) {
					ctx.SetReturn(18) // HTBORDER
					return 0
				}
			}
			// Check caption area
			if style&0x00C00000 == 0x00C00000 { // WS_CAPTION
				captionH := win32.GetSystemMetrics(win32.SM_CYCAPTION)
				if exStyle&0x00000080 != 0 { // WS_EX_TOOLWINDOW
					captionH = win32.GetSystemMetrics(win32.SM_CYSMCAPTION)
				}
				wr.Top += captionH
				if !win32.PtInRect(&wr, px, py) {
					// In caption - check for sysmenu, close, min, max
					if style&0x00080000 != 0 { // WS_SYSMENU
						btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
						if exStyle&0x00000080 == 0 { // not tool window
							// System menu icon area
							wr.Left += btnW
						}
						wr.Right -= btnW // close button
					}
					if px < wr.Left {
						ctx.SetReturn(3)
						return 0
					} // HTSYSMENU
					if px >= wr.Right+win32.GetSystemMetrics(win32.SM_CXSIZE)-win32.GetSystemMetrics(win32.SM_CXSIZE) {
						// We already subtracted close button space
					}
					if px >= wr.Right {
						ctx.SetReturn(20)
						return 0
					} // HTCLOSE
					if style&(0x00020000|0x00010000) != 0 { // WS_MINIMIZEBOX|WS_MAXIMIZEBOX
						btnW := win32.GetSystemMetrics(win32.SM_CXSIZE)
						wr.Right -= btnW // max button
						if px >= wr.Right {
							ctx.SetReturn(9)
							return 0
						} // HTMAXBUTTON
						if style&0x00020000 != 0 { // WS_MINIMIZEBOX
							wr.Right -= btnW // min button
							if px >= wr.Right {
								ctx.SetReturn(8)
								return 0
							} // HTMINBUTTON
						}
					}
					ctx.SetReturn(2) // HTCAPTION
					return 0
				}
			}
			// Check menu area
			if _, hasMenu := hwndMenuBar[hwnd]; hasMenu {
				wr.Top += win32.GetSystemMetrics(win32.SM_CYMENU)
				if !win32.PtInRect(&wr, px, py) {
					ctx.SetReturn(5) // HTMENU
					return 0
				}
			}
			ctx.SetReturn(1) // HTCLIENT
			return 0
		}
		// WM_NCCREATE: must return TRUE for window creation to proceed
		if msg == 0x0081 {
			ctx.SetReturn(1)
			return 0
		}
		// WM_NCLBUTTONDOWN (0x00A1): handle clicks in non-client area.
		// Ported from ReactOS nonclient.c NC_HandleNCLButtonDown.
		if msg == 0x00A1 && wlWindow != nil && hwnd == hctx.MainHWND {
			hitTest := wParam
			switch hitTest {
			case 2: // HTCAPTION - initiate window move via WM_SYSCOMMAND SC_MOVE
				// Post WM_SYSCOMMAND SC_MOVE+HTCAPTION (0xF012)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0112, 0xF012, lParam))
			case 3: // HTSYSMENU - double-click closes, single opens system menu
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0112, 0xF060, lParam)) // SC_CLOSE
			case 8: // HTMINBUTTON - SC_MINIMIZE (0xF020)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0112, 0xF020, lParam))
			case 9: // HTMAXBUTTON - SC_MAXIMIZE (0xF030)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0112, 0xF030, lParam))
			case 20: // HTCLOSE - SC_CLOSE (0xF060)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, 0x0112, 0xF060, lParam))
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_SYSCOMMAND (0x0112): handle system commands (close, minimize, maximize, move).
		// Ported from ReactOS defwnd.c DefWndHandleSysCommand.
		if msg == 0x0112 && wlWindow != nil {
			cmd := wParam & 0xFFF0
			switch cmd {
			case 0xF060: // SC_CLOSE
				ravelog.Logf("[syscmd] SC_CLOSE hwnd=0x%x\n", hwnd)
				// Send WM_CLOSE to the window
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0010, 0, 0))
			case 0xF020: // SC_MINIMIZE
				ravelog.Logf("[syscmd] SC_MINIMIZE hwnd=0x%x\n", hwnd)
				// Minimize via xdg_toplevel.set_minimized
				if wlWindow != nil {
					wlWindow.Minimize()
				}
			case 0xF030: // SC_MAXIMIZE
				ravelog.Logf("[syscmd] SC_MAXIMIZE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.Maximize()
				}
			case 0xF120: // SC_RESTORE
				ravelog.Logf("[syscmd] SC_RESTORE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.Restore()
				}
			case 0xF012: // SC_MOVE + HTCAPTION
				ravelog.Logf("[syscmd] SC_MOVE hwnd=0x%x\n", hwnd)
				if wlWindow != nil {
					wlWindow.StartMove()
				}
			case 0xF000: // SC_SIZE
				ravelog.Logf("[syscmd] SC_SIZE hwnd=0x%x\n", hwnd)
			}
			ctx.SetReturn(0)
			return 0
		}
		// WM_CLOSE (0x0010): destroy the window.
		if msg == 0x0010 {
			ravelog.Logf("[wm] WM_CLOSE hwnd=0x%x\n", hwnd)
			destroyWindow(hwnd, ctx.CPU)
			ctx.SetReturn(0)
			return 0
		}
		// Applications post WM_QUIT themselves after destroying their main window.
		if msg == 0x0002 {
			ravelog.Logf("[wm] WM_DESTROY hwnd=0x%x\n", hwnd)
			ctx.SetReturn(0)
			return 0
		}
		// WM_ERASEBKGND: fill with class background brush (ReactOS: defwnd.c)
		if msg == 0x0014 {
			_, _, owned := topLevelDialogTarget(hctx, hwnd)
			if owned {
				hctx.DialogSurfaceMu.Lock(ctx.CPU)
				defer hctx.DialogSurfaceMu.Unlock(ctx.CPU)
			}
			bgColor := hctx.SysColors[5] // default COLOR_WINDOW
			if a, ok := hctx.HwndClassAtom[hwnd]; ok {
				if brushIdx, ok2 := hctx.ClassBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(hctx.SysColors) {
					bgColor = hctx.SysColors[brushIdx-1]
				}
			}
			if cs, ok := hwndChildren[hwnd]; ok {
				if dc := gdiMgr.GetDC(wParam); dc != nil {
					dc.FillRect(0, 0, cs.w, cs.h, bgColor)
				} else if wlWindow != nil {
					wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
				}
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				clientTop := getMenuClientTop(hwnd)
				w := wlWindow.Width
				h := wlWindow.Height + wlWindow.TitleBarH
				vScrollW, hScrollH := getClientScrollbarSizes(hwnd)
				wlWindow.DrawRectAbs(0, clientTop, w-vScrollW, h-hScrollH, bgColor)
			}
			ctx.SetReturn(1)
			return 0
		}
		_ = wParam
		ctx.SetReturn(0)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "DefWindowProcW", defWindowProcFn)
	writeMsg := func(ctx *ntapi.TrapContext, pMsg uint64, msg queuedMsg) bool {
		if !writeQueuedMessage(mem, pMsg, ctx.State != nil && ctx.State.Is32, msg) {
			return false
		}
		hctx.MessageMetadata.delivered(ctx.CPU, msg)
		return true
	}
	// readMsg reads a Win32 MSG struct from guest memory.
	readMsg := func(ctx *ntapi.TrapContext, pMsg uint64) (hwnd uint64, message uint32, wParam, lParam uint64) {
		if ctx.State != nil && ctx.State.Is32 {
			v, _ := mem.Read32(pMsg)
			hwnd = uint64(v)
			message, _ = mem.Read32(pMsg + 4)
			v, _ = mem.Read32(pMsg + 8)
			wParam = uint64(v)
			v, _ = mem.Read32(pMsg + 12)
			lParam = uint64(v)
		} else {
			hwnd, _ = mem.Read64(pMsg)
			message, _ = mem.Read32(pMsg + 8)
			wParam, _ = mem.Read64(pMsg + 16)
			lParam, _ = mem.Read64(pMsg + 24)
		}
		return
	}
	isDescendantWindow := func(hwnd, ancestor uint64) bool {
		return isChildWindow(hwndChildren, ancestor, hwnd)
	}
	messageMatches := func(hwndFilter uint64, minMessage, maxMessage uint32) func(queuedMsg) bool {
		return func(message queuedMsg) bool {
			return win32MessageMatches(message.message, message.hwnd, hwndFilter, minMessage, maxMessage, isDescendantWindow)
		}
	}
	pruneValidatedPaintMessages := func(cpu arch.CPU) {
		hctx.MsgQueue.prune(cpu, func(message queuedMsg) bool {
			return message.message != 0x000F || hctx.WinInvalid[message.hwnd]
		})
	}
	validMessageFilter := func(hwnd uint64) bool {
		if hwnd == 0 || hwnd == ^uint64(0) || hwnd == uint64(^uint32(0)) || hwnd == hctx.MainHWND {
			return true
		}
		if _, ok := hwndChildren[hwnd]; ok {
			return true
		}
		return win32.Global.Get(hwnd) != nil
	}
	// GetMessageW: drain message queue first, then block on Wayland events
	// dispatchWl is shared with PeekMessageW - defined as a package-level var so both can access it.
	var dispatchWl func(evt wl.EventType)
	hwndForWaylandWindow := func(win *wl.Window) uint64 {
		return waylandWindowHWND(wlWindow, hctx.MainHWND, hctx.WlWindowHWND, win)
	}
	dispatchWaylandClose := func() {
		target := hwndForWaylandWindow(wlDisplay.LastEventWindow())
		if target == 0 {
			ravelog.Logf("[wl] ignoring close for unknown Wayland window\n")
			return
		}
		ravelog.Logf("[wl] EventClose target=0x%x\n", target)
		if hctx.PrintDialog != nil && target == hctx.PrintDialog.DlgHWND {
			hctx.PrintDialog.Result = 2
			return
		}
		if state := hwndChildren[target]; state != nil &&
			(strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770")) {
			control, id := dialogCloseControl(hwndChildren, target)
			if control != 0 {
				ravelog.Logf("[wl] dialog close target=0x%x -> WM_COMMAND id=%d control=0x%x\n", target, id, control)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0111, id, control))
				return
			}
		}
		hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0010, 0, 0))
	}
	var runGetMessageW func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runGetMessageW = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		flushDestroyedWindows()
		pMsg := pump.arguments[0]
		hwndFilter := pump.arguments[1]
		minMessage := uint32(pump.arguments[2])
		maxMessage := uint32(pump.arguments[3])
		if pMsg == 0 || !validMessageFilter(hwndFilter) {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if dispatchPendingSentMessage(ctx, pump) {
			return 0
		}

		// Save message loop entry point for crash recovery
		if msgLoopSP == 0 {
			if ctx.State != nil && ctx.State.Is32 {
				retAddr32, _ := mem.Read32(ctx.CPU.GetSP())
				msgLoopPC = uint64(retAddr32)
				msgLoopSP = ctx.CPU.GetSP() + 4
			} else {
				retAddr, _ := mem.Read64(ctx.CPU.GetSP())
				msgLoopPC = retAddr
				msgLoopSP = ctx.CPU.GetSP() + 8
			}
		}

		// Helper: convert a Wayland event into Win32 messages.
		dispatchWl = func(evt wl.EventType) {
			if evt == wl.EventClose {
				dispatchWaylandClose()
				return
			}
			if evt == wl.EventConfigure {
				win := wlDisplay.LastEventWindow()
				target := hwndForWaylandWindow(win)
				if win == nil || target == 0 {
					return
				}
				// Compositor resized the window - resize buffer and post WM_SIZE to guest.
				// Buffer recreation clears every pixel, so the next completed paint must
				// also re-composite host-rendered controls.
				resized := win.ResizeIfNeeded()
				if resized && win == wlWindow {
					syncScreenSurface()
				}
				w := win.Width
				h := win.Height
				if target == hctx.MainHWND && hctx.LastPostedMainW == w && hctx.LastPostedMainH == h {
					if resized {
						repaintAfterSurfaceResize(hctx, target, true, queuePaint)
					}
					return
				}
				if target == hctx.MainHWND {
					hctx.LastPostedMainW, hctx.LastPostedMainH = w, h
				}
				// Keep RcWindow/RcClient in sync so GetWindowRect returns correct values.
				if wnd := win32.Global.Get(target); wnd != nil {
					win32.Global.UpdatePos(wnd, wnd.RcWindow.Left, wnd.RcWindow.Top, w, h+win.TitleBarH)
				}
				// ReactOS co_WinPosSendSizeMove: WM_SIZE lParam = MAKELONG(clientW, clientH).
				// Client height excludes the menu bar (NC area in Win32).
				clientW, clientH := getTopLevelClientSize(target)
				lParam := uint64(uint16(clientW)) | (uint64(uint16(clientH)) << 16)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0005, 0, lParam)) // WM_SIZE
				if resized {
					repaintAfterSurfaceResize(hctx, target, target == hctx.MainHWND, queuePaint)
				}
				return
			}
			if evt == wl.EventKey {
				for {
					ke, ok := wlDisplay.PollKey()
					if !ok {
						break
					}
					if ke.Pressed && hctx.ActivePopupMenu != nil {
						pm := hctx.ActivePopupMenu
						switch ke.VK {
						case 0x28: // VK_DOWN
							pm.Selected = popupMenuNextSelectable(pm.Items, pm.Selected, 1)
							requestWindowRepaint(hctx.MainHWND)
							continue
						case 0x26: // VK_UP
							start := pm.Selected
							if start < 0 {
								start = 0
							}
							pm.Selected = popupMenuNextSelectable(pm.Items, start, -1)
							requestWindowRepaint(hctx.MainHWND)
							continue
						case 0x0D: // VK_RETURN
							if pm.Selected >= 0 && pm.Selected < len(pm.Items) {
								si := &pm.Items[pm.Selected]
								ensureMenuItemSubmenu(pm.Menu, pm.Selected, si, menus)
								subItems := resolveMenuItems(*si)
								if len(subItems) > 0 && wlWindow != nil {
									layout := menuPopupLayout(subItems, pm.X+pm.Width, pm.Y+int32(pm.Selected)*pm.ItemHeight, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH, menuStripAmpersand)
									layout.Menu = si.submenuHandle
									layout.OwnerHWND = pm.OwnerHWND
									hctx.ActivePopupMenu = &layout
								} else if si.id != 0 {
									target := pm.OwnerHWND
									if target == 0 {
										target = hctx.MainHWND
									}
									hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0111, si.id, 0))
									closePopupMenus()
								}
								requestWindowRepaint(hctx.MainHWND)
							}
							continue
						}
					}
					// ESC closes open menu dropdown
					if ke.Pressed && (ke.VK == 0x1B) && (hctx.OpenMenuIdx >= 0 || hctx.ActivePopupMenu != nil) {
						closePopupMenus()
						requestWindowRepaint(hctx.MainHWND)
						continue
					}
					// Built-in print dialog keyboard handling.
					if ke.Pressed && hctx.PrintDialog != nil {
						pd := hctx.PrintDialog
						eventRoot := hwndForWaylandWindow(ke.Window)
						if eventRoot != pd.DlgHWND {
							continue
						}
						switch ke.VK {
						case 0x0D:
							pd.Result = 1
						case 0x1B:
							pd.Result = 2
						case 0x26:
							if pd.Copies < 999 {
								pd.Copies++
								requestWindowRepaint(pd.DlgHWND)
							}
						case 0x28:
							if pd.Copies > 1 {
								pd.Copies--
								requestWindowRepaint(pd.DlgHWND)
							}
						}
						continue
					}
					// FindDialog keyboard intercept: route printable chars to overlay
					if ke.Pressed && hctx.FindDialog != nil && hwndForWaylandWindow(ke.Window) == hctx.FindDialog.DlgHWND {
						fd := hctx.FindDialog
						switch {
						case ke.VK == 0x1B: // ESC -> close dialog
							sendFindMessage(hctx, mem, 0x0040 /*FR_DIALOGTERM*/)
							destroyOwnedDialogWindow(fd.DlgHWND)
							hctx.FindDialog = nil
							continue
						case ke.VK == 0x0D: // Enter -> Find Next
							sendFindMessage(hctx, mem, 0x0008 /*FR_FINDNEXT*/)
							continue
						case ke.VK == 0x08: // Backspace
							if !fd.FocusOnReplace {
								if len(fd.FindText) > 0 {
									fd.FindText = fd.FindText[:len([]rune(fd.FindText))-1]
								}
							} else {
								if len(fd.ReplaceText) > 0 {
									fd.ReplaceText = fd.ReplaceText[:len([]rune(fd.ReplaceText))-1]
								}
							}
							requestWindowRepaint(fd.DlgHWND)
							continue
						case ke.Char >= 0x20:
							ch := string(rune(ke.Char))
							if !fd.FocusOnReplace {
								fd.FindText += ch
							} else {
								fd.ReplaceText += ch
							}
							requestWindowRepaint(fd.DlgHWND)
							continue
						}
					}
					target := hctx.FocusHwnd
					eventRoot := hwndForWaylandWindow(ke.Window)
					if eventRoot == 0 {
						continue
					}
					if target == 0 || (target != eventRoot && !isDescendantWindow(target, eventRoot)) {
						target = eventRoot
					}
					scanCode := ke.ScanCode
					if scanCode == 0 {
						scanCode = ke.Keycode & 0xFF
					}
					wasDown := keyState[ke.VK]&0x80 != 0
					setKeyDown(ke.VK, ke.Pressed)
					if ke.Pressed {
						lParam := makeKeyLParam(scanCode, ke.Extended, true, wasDown)
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0100, uint64(ke.VK), lParam))
						if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
							pendingKeyChars[ke.VK] = ke.Char
						}
					} else {
						lParam := makeKeyLParam(scanCode, ke.Extended, false, wasDown)
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0101, uint64(ke.VK), lParam))
					}
					break
				}
			}
			if evt == wl.EventMouse {
				for {
					me, ok := wlDisplay.PollMouse()
					if !ok {
						break
					}
					eventWindow := me.Window
					eventRoot := hwndForWaylandWindow(eventWindow)
					if eventRoot == 0 {
						continue
					}
					if hctx.PrintDialog != nil && eventRoot != hctx.PrintDialog.DlgHWND {
						continue
					}
					cursorPosX, cursorPosY = me.X, me.Y
					hctx.CursorPosX, hctx.CursorPosY = cursorPosX, cursorPosY
					ravelog.Logf("[mouse] kind=%d x=%d y=%d button=%d pressed=%v\n", me.Kind, me.X, me.Y, me.Button, me.Pressed)
					// Our custom title bar occupies y=[0, TitleBarH).
					// Menu bar occupies y=[TitleBarH, TitleBarH+menuBarHeight).
					// Client area starts at y=TitleBarH+menuBarHeight.
					var (
						ncTitleTop = int32(0)
						ncMenuTop  int32
						clientTop  = int32(0)
					)
					if eventWindow != nil {
						ncMenuTop = eventWindow.TitleBarH
						clientTop = getMenuClientTop(eventRoot)
					}
					// Client-relative coordinates for WM_LBUTTON* messages
					clientX := me.X
					clientY := me.Y - clientTop

					// routeMouseToChild routes a mouse message to child or hctx.MainHWND.
					// Returns true if routed to a child builtin (no need to queue).
					routeMouseMsg := func(msg uint32, wp uint64, sx, sy int32) {
						targetHWND := hctx.MouseCapture
						var relParam uint64
						if targetHWND == 0 {
							hitX, hitY := sx, sy
							if rootState := hwndChildren[eventRoot]; rootState != nil {
								hitX += rootState.x
								hitY += rootState.y
							}
							targetHWND, relParam = findDeepestChildAt(eventRoot, hitX, hitY)
						} else {
							captureX, captureY := sx, sy
							if rootState := hwndChildren[eventRoot]; rootState != nil {
								captureX += rootState.x
								captureY += rootState.y
							}
							relParam = makeClientLParam(targetHWND, captureX, captureY)
						}
						if targetHWND != 0 {
							_, handled := builtinWndProc(targetHWND, msg, wp, relParam)
							if !handled {
								hctx.enqueueMessage(nil, newQueuedMsg(hctx, targetHWND, msg, wp, relParam))
							}
						} else {
							// Fall back to hctx.MainHWND with client-relative coords
							mcp := makeClientLParam(eventRoot, sx, sy)
							hctx.enqueueMessage(nil, newQueuedMsg(hctx, eventRoot, msg, wp, mcp))
						}
					}

					switch me.Kind {
					case 0: // WM_MOUSEMOVE
						if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop && hctx.OpenMenuIdx >= 0 {
							// Hovering menu bar while a menu is open - switch item
							if menuH, ok2 := hwndMenuBar[hctx.MainHWND]; ok2 {
								if md, ok3 := menus[menuH]; ok3 {
									x := int32(4)
									for i, item := range md.items {
										if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
											continue
										}
										label, _ := menuTextParts(menuStripAmpersand(item.text))
										if label == "" {
											continue
										}
										if !menuHasRenderableText(label) {
											continue
										}
										tw := menuTextWidth(label) + 12
										if me.X >= x && me.X < x+tw && i != hctx.OpenMenuIdx {
											hctx.OpenMenuIdx = i
											hctx.OpenMenuHwnd = hctx.MainHWND
											showMenuBarPopup(hctx.MainHWND, i)
											requestWindowRepaint(hctx.MainHWND)
										}
										x += tw
									}
								}
							}
						} else if hctx.ActivePopupMenu != nil {
							pm := hctx.ActivePopupMenu
							if me.X < pm.X || me.X >= pm.X+pm.Width || me.Y < pm.Y || me.Y >= pm.Y+pm.Height {
								// outside popup; leave state unchanged until click
							} else {
								selected := int((me.Y - pm.Y) / pm.ItemHeight)
								if selected >= 0 && selected < len(pm.Items) && pm.Items[selected].flags&0x0800 == 0 && pm.Selected != selected {
									pm.Selected = selected
									requestWindowRepaint(hctx.MainHWND)
								}
							}
						} else if me.Y >= clientTop {
							// Client area mouse move - route to captured/child/hctx.MainHWND
							routeMouseMsg(0x0200, 0, me.X, me.Y)
						}
					case 1: // button press/release
						const btnLeft, btnRight, btnMiddle = 272, 273, 274
						switch me.Button {
						case btnLeft:
							if me.Pressed {
								ravelog.Logf("[click] left press x=%d y=%d ncMenuTop=%d clientTop=%d\n", me.X, me.Y, ncMenuTop, clientTop)

								if hctx.PrintDialog != nil {
									pd := hctx.PrintDialog
									if eventRoot != pd.DlgHWND {
										break
									}
									x, y := me.X, me.Y
									switch {
									case x >= pd.PrintBtnX && x < pd.PrintBtnX+pd.PrintBtnW && y >= pd.PrintBtnY && y < pd.PrintBtnY+pd.PrintBtnH:
										pd.Result = 1
									case x >= pd.CancelBtnX && x < pd.CancelBtnX+pd.CancelBtnW && y >= pd.CancelBtnY && y < pd.CancelBtnY+pd.CancelBtnH:
										pd.Result = 2
									case x >= pd.AllPagesX && x < pd.AllPagesX+120 && y >= pd.AllPagesY && y < pd.AllPagesY+20:
										pd.AllPages = true
										requestWindowRepaint(pd.DlgHWND)
									case pd.AllowPageRange && x >= pd.PagesX && x < pd.PagesX+80 && y >= pd.PagesY && y < pd.PagesY+20:
										pd.AllPages = false
										requestWindowRepaint(pd.DlgHWND)
									case pd.AllowPageRange && x >= pd.FromMinusX && x < pd.FromMinusX+28 && y >= pd.RangeButtonsY && y < pd.RangeButtonsY+24:
										pd.AllPages = false
										if pd.FromPage > pd.MinPage {
											pd.FromPage--
											if pd.ToPage < pd.FromPage {
												pd.ToPage = pd.FromPage
											}
										}
										requestWindowRepaint(pd.DlgHWND)
									case pd.AllowPageRange && x >= pd.FromPlusX && x < pd.FromPlusX+28 && y >= pd.RangeButtonsY && y < pd.RangeButtonsY+24:
										pd.AllPages = false
										if pd.FromPage < pd.MaxPage {
											pd.FromPage++
											if pd.ToPage < pd.FromPage {
												pd.ToPage = pd.FromPage
											}
										}
										requestWindowRepaint(pd.DlgHWND)
									case pd.AllowPageRange && x >= pd.ToMinusX && x < pd.ToMinusX+28 && y >= pd.RangeButtonsY && y < pd.RangeButtonsY+24:
										pd.AllPages = false
										if pd.ToPage > pd.FromPage {
											pd.ToPage--
										}
										requestWindowRepaint(pd.DlgHWND)
									case pd.AllowPageRange && x >= pd.ToPlusX && x < pd.ToPlusX+28 && y >= pd.RangeButtonsY && y < pd.RangeButtonsY+24:
										pd.AllPages = false
										if pd.ToPage < pd.MaxPage {
											pd.ToPage++
										}
										requestWindowRepaint(pd.DlgHWND)
									case x >= pd.CopiesMinusX && x < pd.CopiesMinusX+28 && y >= pd.CopiesY && y < pd.CopiesY+24:
										if pd.Copies > 1 {
											pd.Copies--
											requestWindowRepaint(pd.DlgHWND)
										}
									case x >= pd.CopiesPlusX && x < pd.CopiesPlusX+28 && y >= pd.CopiesY && y < pd.CopiesY+24:
										if pd.Copies < 999 {
											pd.Copies++
											requestWindowRepaint(pd.DlgHWND)
										}
									}
									break
								}

								// Find/Replace modeless dialog intercept
								if hctx.FindDialog != nil && eventRoot == hctx.FindDialog.DlgHWND {
									fd := hctx.FindDialog
									x, y := me.X, me.Y
									// Find edit field
									if x >= fd.FindEditX && x < fd.FindEditX+fd.FindEditW &&
										y >= fd.FindEditY && y < fd.FindEditY+fd.FindEditH {
										fd.FocusOnReplace = false
										requestWindowRepaint(fd.DlgHWND)
										break
									}
									// Replace edit field
									if fd.IsReplace && x >= fd.ReplEditX && x < fd.ReplEditX+fd.ReplEditW &&
										y >= fd.ReplEditY && y < fd.ReplEditY+fd.ReplEditH {
										fd.FocusOnReplace = true
										requestWindowRepaint(fd.DlgHWND)
										break
									}
									// Find Next button
									if x >= fd.FindNextBtnX && x < fd.FindNextBtnX+fd.FindNextBtnW &&
										y >= fd.FindNextBtnY && y < fd.FindNextBtnY+fd.FindNextBtnH {
										sendFindMessage(hctx, mem, 0x0008 /*FR_FINDNEXT*/)
										break
									}
									// Replace button
									if fd.IsReplace && x >= fd.ReplaceBtnX && x < fd.ReplaceBtnX+fd.ReplaceBtnW &&
										y >= fd.ReplaceBtnY && y < fd.ReplaceBtnY+fd.ReplaceBtnH {
										sendFindMessage(hctx, mem, 0x0010 /*FR_REPLACE*/)
										break
									}
									// Replace All button
									if fd.IsReplace && x >= fd.ReplAllBtnX && x < fd.ReplAllBtnX+fd.ReplAllBtnW &&
										y >= fd.ReplAllBtnY && y < fd.ReplAllBtnY+fd.ReplAllBtnH {
										sendFindMessage(hctx, mem, 0x0020 /*FR_REPLACEALL*/)
										break
									}
									// Cancel button
									if x >= fd.CancelBtnX && x < fd.CancelBtnX+fd.CancelBtnW &&
										y >= fd.CancelBtnY && y < fd.CancelBtnY+fd.CancelBtnH {
										sendFindMessage(hctx, mem, 0x0040 /*FR_DIALOGTERM*/)
										destroyOwnedDialogWindow(fd.DlgHWND)
										hctx.FindDialog = nil
										break
									}
									// Click inside dialog body (but not a button) -> just absorb
									if x >= fd.X && x < fd.X+fd.W && y >= fd.Y && y < fd.Y+fd.H {
										break
									}
									// Click outside dialog -> fall through to normal handling
								}

								// Modal dialog intercept: all clicks go to dialog when active
								if hctx.DialogActive {
									bx, by := hctx.DialogBtnX, hctx.DialogBtnY
									bw, bh := hctx.DialogBtnW, hctx.DialogBtnH
									if me.X >= bx && me.X < bx+bw && me.Y >= by && me.Y < by+bh {
										ravelog.Logf("[dialog] OK button clicked, dismissing dialog\n")
										hctx.DialogActive = false
										if wlWindow != nil && hctx.HasBaseFrame {
											hctx.RepaintBuiltin = true
											hctx.FrameReady = true
											commitIfDone()
										} else {
											queuePaint(hctx.MainHWND)
										}
									}
									// Swallow all clicks while dialog is active (modal)
									break
								}

								if wlWindow != nil && me.Y >= ncMenuTop && me.Y < clientTop {
									// ── Menu bar click (non-client) ──
									// Intercept here instead of routing via DefWindowProcW.
									ravelog.Logf("[click] menu bar hit, looking for item\n")
									if menuH, ok2 := hwndMenuBar[hctx.MainHWND]; ok2 {
										if md, ok3 := menus[menuH]; ok3 {
											x := int32(4)
											handled := false
											for i, item := range md.items {
												if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
													continue
												}
												label, _ := menuTextParts(menuStripAmpersand(item.text))
												if label == "" {
													continue
												}
												if !menuHasRenderableText(label) {
													continue
												}
												tw := menuTextWidth(label) + 12
												ravelog.Logf("[click] item i=%d label=%q x=%d..%d\n", i, label, x, x+tw)
												if me.X >= x && me.X < x+tw {
													if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hctx.MainHWND {
														closePopupMenus()
													} else {
														hctx.OpenMenuIdx = i
														hctx.OpenMenuHwnd = hctx.MainHWND
														showMenuBarPopup(hctx.MainHWND, i)
													}
													requestWindowRepaint(hctx.MainHWND)
													handled = true
													break
												}
												x += tw
											}
											_ = md
											if !handled {
												closePopupMenus()
												requestWindowRepaint(hctx.MainHWND)
											}
										}
									}
								} else if wlWindow != nil && me.Y >= ncTitleTop && me.Y < ncMenuTop {
									// ── Title bar click (non-client) ── ignore or handle drag
								} else {
									// ── Client area click ──
									clParam := uint64(uint16(clientX)) | (uint64(uint16(clientY)) << 16)
									dropHit := false
									if pm := hctx.ActivePopupMenu; pm != nil {
										if me.X >= pm.X && me.X < pm.X+pm.Width && me.Y >= pm.Y && me.Y < pm.Y+pm.Height {
											itemIdx := int((me.Y - pm.Y) / pm.ItemHeight)
											if itemIdx >= 0 && itemIdx < len(pm.Items) {
												si := &pm.Items[itemIdx]
												if os.Getenv("RAVEN_TRACE_CLICK") != "" {
													ravelog.Logf("[click] popup item index=%d id=%d text=%q flags=0x%x\n",
														itemIdx, si.id, menuStripAmpersand(si.text), si.flags)
												}
												if si.flags&0x0800 != 0 || si.flags&0x0003 != 0 {
													dropHit = true
												} else {
													ensureMenuItemSubmenu(pm.Menu, itemIdx, si, menus)
													subItems := resolveMenuItems(*si)
													cmd := si.id
													if len(subItems) > 0 && wlWindow != nil {
														layout := menuPopupLayout(subItems, pm.X+pm.Width, pm.Y+int32(itemIdx)*pm.ItemHeight, wlWindow.Width, wlWindow.Height+wlWindow.TitleBarH, menuStripAmpersand)
														layout.Menu = si.submenuHandle
														layout.OwnerHWND = pm.OwnerHWND
														hctx.ActivePopupMenu = &layout
													} else if cmd != 0 {
														target := pm.OwnerHWND
														if target == 0 {
															target = hctx.MainHWND
														}
														hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0111, cmd, 0))
														closePopupMenus()
													}
													dropHit = true
													requestWindowRepaint(hctx.MainHWND)
												}
											}
										}
										if !dropHit {
											closePopupMenus()
											requestWindowRepaint(hctx.MainHWND)
										}
									}
									if !dropHit {
										// Route the click within the Wayland window that received it.
										hitX, hitY := me.X, me.Y
										if rootState := hwndChildren[eventRoot]; rootState != nil {
											hitX += rootState.x
											hitY += rootState.y
										}
										hitChild, hitRelParam := findDeepestChildAt(eventRoot, hitX, hitY)
										if os.Getenv("RAVEN_TRACE_CLICK") != "" {
											cls := ""
											if st := hwndChildren[hitChild]; st != nil {
												cls = st.className
											}
											ravelog.Logf("[click] eventRoot=0x%x hit=(%d,%d) hitChild=0x%x class=%q relParam=0x%x\n",
												eventRoot, hitX, hitY, hitChild, cls, hitRelParam)
										}
										for comboHWND, combo := range hwndChildren {
											if comboHWND == hitChild || !combo.comboDropped || combo.style&3 == 1 || (combo.className != "combobox" && combo.className != "comboboxex32") {
												continue
											}
											combo.comboDropped = false
											combo.comboPressedIndex = 0
											if combo.parentHWND != 0 {
												hctx.enqueueMessage(nil,
													newQueuedMsg(hctx, combo.parentHWND, 0x0111, (uint64(10)<<16)|(combo.ctrlID&0xFFFF), comboHWND),
													newQueuedMsg(hctx, combo.parentHWND, 0x0111, (uint64(8)<<16)|(combo.ctrlID&0xFFFF), comboHWND),
												)
											}
										}
										if hitChild != 0 {
											// Update focus to clicked child
											if hctx.FocusHwnd != hitChild {
												if hctx.FocusHwnd != 0 {
													hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.FocusHwnd, 0x0008, uint64(hitChild), 0))
												}
												hctx.FocusHwnd = hitChild
												hctx.enqueueMessage(nil, newQueuedMsg(hctx, hitChild, 0x0007, 0, 0))
											}
											classStyle := uint32(0)
											if atom := hctx.HwndClassAtom[hitChild]; atom != 0 {
												if classInfo := hctx.ClassInfo[atom]; classInfo != nil {
													classStyle = classInfo.Style
												}
											}
											clickTime := me.When
											if clickTime.IsZero() {
												clickTime = time.Now()
											}
											mouseMessage := leftClicks.press(clickTime, hitChild, hitX, hitY, classStyle, time.Duration(doubleClickTime)*time.Millisecond)
											if mouseMessage == 0x0203 {
												className := ""
												if state := hwndChildren[hitChild]; state != nil {
													className = state.className
												}
												ravelog.Logf("[mouse] double click hwnd=0x%x class=%q\n", hitChild, className)
											}
											_, handled := builtinWndProc(hitChild, mouseMessage, 0x0001, hitRelParam)
											if !handled {
												hctx.enqueueMessage(nil, newQueuedMsg(hctx, hitChild, mouseMessage, 0x0001, hitRelParam))
											}
										} else {
											hctx.enqueueMessage(nil, newQueuedMsg(hctx, eventRoot, 0x0201, 0x0001, clParam))
										}
									}
								}
							} else {
								// Left button release - route to captured window or hit-test
								if me.Y >= clientTop || wlWindow == nil || hctx.MouseCapture != 0 {
									routeMouseMsg(0x0202, 0, me.X, me.Y)
								}
							}
						case btnRight:
							if me.Y >= clientTop || wlWindow == nil {
								if me.Pressed {
									routeMouseMsg(0x0204, 0x0002, me.X, me.Y)
								} else {
									routeMouseMsg(0x0205, 0, me.X, me.Y)
								}
							}
						case btnMiddle:
							if me.Y >= clientTop || wlWindow == nil {
								if me.Pressed {
									routeMouseMsg(0x0207, 0x0010, me.X, me.Y)
								} else {
									routeMouseMsg(0x0208, 0, me.X, me.Y)
								}
							}
						}
					case 2: // scroll wheel
						routeMouseMsg(0x020A, uint64(int16(me.AxisVal*-120))<<16, me.X, me.Y)
					}
				}
			}
		}
		pumpWaylandFailures := 0
		hctx.PumpWaylandOnce = func() bool {
			if wlDisplay == nil || dispatchWl == nil {
				return false
			}
			if wlDisplay.HasPendingInput() {
				dispatchWl(wl.EventMouse)
				dispatchWl(wl.EventKey)
				return true
			}
			evt, err := wlDisplay.Poll()
			if err != nil {
				pumpWaylandFailures++
				ravelog.Logf("[wayland] modal poll failed (%d): %v\n", pumpWaylandFailures, err)
				return pumpWaylandFailures < 3
			}
			pumpWaylandFailures = 0
			if evt != wl.EventNone {
				dispatchWl(evt)
				return true
			}
			wlFd := wlDisplay.Fd()
			var rfds unix.FdSet
			rfds.Set(wlFd)
			tv := unix.Timeval{Usec: 16000}
			n, err := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
			if err != nil {
				if err == unix.EINTR {
					return true
				}
				ravelog.Logf("[wayland] modal select failed: %v\n", err)
				return false
			}
			if n > 0 {
				evt, err = wlDisplay.Dispatch()
				if err != nil {
					pumpWaylandFailures++
					ravelog.Logf("[wayland] modal dispatch failed (%d): %v\n", pumpWaylandFailures, err)
					return pumpWaylandFailures < 3
				}
				pumpWaylandFailures = 0
				if evt != wl.EventNone {
					dispatchWl(evt)
				}
			}
			return true
		}

		dequeueMsg := func() bool {
			if dispatchPendingSentMessage(ctx, pump) {
				return true
			}
			found := false
			m, delivered := hctx.MsgQueue.deliver(ctx.CPU,
				messageMatches(hwndFilter, minMessage, maxMessage),
				func(queuedMsg) bool { return true },
				func(msg queuedMsg) bool {
					found = true
					return writeMsg(ctx, pMsg, msg)
				})
			if !delivered {
				if !found {
					return false
				}
				ctx.SetReturn(^uint64(0))
				return true
			}
			if m.message == 0x0012 { // WM_QUIT - GetMessage returns FALSE to end the message loop
				ctx.SetReturn(0)
			} else {
				ctx.SetReturn(1)
			}
			return true
		}

		var lastSyntheticFrameNs int64
		queueSyntheticPaints := func() bool {
			nowNs := time.Now().UnixNano()
			if nowNs-lastSyntheticFrameNs < 16_000_000 {
				return false
			}
			lastSyntheticFrameNs = nowNs
			var childPaints []uint64
			for h, cs := range hwndChildren {
				if hwndWndProc[h] != 0 && cs.visible && hctx.WinInvalid[h] {
					childPaints = append(childPaints, h)
				}
			}
			if !hctx.WinInvalid[hctx.MainHWND] && len(childPaints) == 0 {
				return false
			}
			sort.Slice(childPaints, func(i, j int) bool { return childPaints[i] < childPaints[j] })
			if hctx.WinInvalid[hctx.MainHWND] {
				queuePaint(hctx.MainHWND)
			}
			for _, h := range childPaints {
				queuePaint(h)
			}
			return true
		}

		if wlDisplay == nil {
			if !hctx.KeepHeadlessAlive {
				if !writeMsg(ctx, pMsg, newQueuedMsg(hctx, hctx.MainHWND, 0x0012, 0, 0)) {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				ctx.SetReturn(0)
				return 0
			}
			for {
				checkTimers(ctx.CPU)
				if dequeueMsg() {
					return 0
				}
				if queueSyntheticPaints() {
					if dequeueMsg() {
						return 0
					}
				}
				waitFor := hctx.Timers.nextDelay(ctx.CPU, time.Now(), 16*time.Millisecond)
				hctx.MsgQueue.wait(ctx.CPU, waitFor)
			}
		}

		for {
			// 1. Drain already-queued messages.
			checkTimers(ctx.CPU)
			if dequeueMsg() {
				return 0
			}

			// 2. Non-blocking poll of Wayland socket.
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone {
				dispatchWl(evt)
				checkTimers(ctx.CPU)
				if dequeueMsg() {
					return 0
				}
			}

			// 3. Nothing ready - compute timeout until next timer (or 16ms frame).
			timeoutUs := int64(16000) // 16ms default (60fps synthetic WM_PAINT)
			now := time.Now()
			timeoutUs = hctx.Timers.nextDelay(ctx.CPU, now, time.Duration(timeoutUs)*time.Microsecond).Microseconds()

			// 4. Block on Wayland fd until timeout.
			wlFd := wlDisplay.Fd()
			var rfds unix.FdSet
			rfds.Set(wlFd)
			tv := unix.Timeval{Sec: timeoutUs / 1_000_000, Usec: timeoutUs % 1_000_000}
			n, _ := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
			if n > 0 {
				evt2, _ := wlDisplay.Dispatch()
				dispatchWl(evt2)
			}

			// 5. Check timers again after sleep, then post WM_PAINT if queue still empty.
			checkTimers(ctx.CPU)

			// 5b. Drain any injected input events (from -auto script).
			if wlDisplay.HasPendingInput() {
				dispatchWl(wl.EventKey)
				dispatchWl(wl.EventMouse)
			}

			if dequeueMsg() {
				return 0
			}

			// 6. Synthetic WM_PAINT frame - rate-limited to ~60fps.
			// hctx.MainHWND paints first (fills background), children paint on top.
			// This matches Win32 WS_CLIPCHILDREN ordering: parent -> children.
			if queueSyntheticPaints() {
				if dequeueMsg() {
					return 0
				}
			}
		}
	}
	d.RegisterAutoStubHandler(user32, "GetMessageW", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)}
		pump := captureSentMessagePump(ctx, arguments, 4, runGetMessageW)
		return runGetMessageW(ctx, pump)
	})

	var runPeekMessageW func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runPeekMessageW = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		flushDestroyedWindows()
		pMsg := pump.arguments[0]
		hwndFilter := pump.arguments[1]
		minMessage := uint32(pump.arguments[2])
		maxMessage := uint32(pump.arguments[3])
		remove := pump.arguments[4]&0x1 != 0 // PM_REMOVE = 0x0001
		if dispatchPendingSentMessage(ctx, pump) {
			return 0
		}

		checkTimers(ctx.CPU) // fire any expired timers before checking the queue

		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone && dispatchWl != nil {
				dispatchWl(evt)
			} else if evt == wl.EventClose {
				dispatchWaylandClose()
			}
		}

		pruneValidatedPaintMessages(ctx.CPU)
		_, delivered := hctx.MsgQueue.deliver(ctx.CPU,
			messageMatches(hwndFilter, minMessage, maxMessage),
			func(msg queuedMsg) bool { return remove && msg.message != 0x000F },
			func(msg queuedMsg) bool { return pMsg != 0 && writeMsg(ctx, pMsg, msg) })
		if !delivered {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "PeekMessageW", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)}
		pump := captureSentMessagePump(ctx, arguments, 5, runPeekMessageW)
		return runPeekMessageW(ctx, pump)
	})
	d.RegisterAutoStubHandler(user32, "TranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		hwnd, message, wParam, lParam := readMsg(ctx, pMsg)
		if message != 0x0100 && message != 0x0104 {
			ctx.SetReturn(0)
			return 0
		}
		vk := uint32(wParam)
		ch, ok := pendingKeyChars[vk]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		delete(pendingKeyChars, vk)
		charMessage := uint32(0x0102)
		if message == 0x0104 {
			charMessage = 0x0106
		}
		hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, charMessage, uint64(ch), lParam))
		ctx.SetReturn(1)
		return 0
	})
	dispatchTimerCallback := func(ctx *ntapi.TrapContext, pMsg, hwnd uint64, message uint32, timerID, timerProc uint64) bool {
		if message != 0x0113 || timerProc == 0 {
			return false
		}
		timeOffset := uint64(32)
		if ctx.State != nil && ctx.State.Is32 {
			timeOffset = 16
		}
		messageTime, _ := mem.Read32(pMsg + timeOffset)
		if ctx.State != nil && ctx.State.Is32 {
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			if !okR || !okW {
				ctx.SetReturn(0)
				return true
			}
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read32(rsp)
			rsp += 8
			rw.WriteReg(4, rsp)
			hctx.SyncCallWndProc(ctx, timerProc, hwnd, message, timerID, uint64(messageTime), uint64(retAddr))
			return true
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			ctx.SetReturn(0)
			return true
		}
		rw.WriteReg(1, hwnd)
		rw.WriteReg(2, uint64(message))
		rw.WriteReg(8, timerID)
		rw.WriteReg(9, uint64(messageTime))
		ctx.CPU.SetPC(timerProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return true
	}
	d.RegisterAutoStubHandler(user32, "DispatchMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		hwnd, message, wParam, lParam := readMsg(ctx, pMsg)
		if dispatchTimerCallback(ctx, pMsg, hwnd, message, wParam, lParam) {
			return 0
		}
		if (message == 0x000F || message == 0x0014) &&
			!windowHierarchyVisible(hwnd, hwndChildren) {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			ctx.SetReturn(0)
			return 0
		}
		if message != 0x0002 && message != 0x0082 &&
			windowOrAncestorDestroyPending(hwnd, destroyPending, hwndChildren) {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			ctx.SetReturn(0)
			return 0
		}

		// Try built-in control first
		if _, isChild := hwndChildren[hwnd]; isChild && !hasWindowSubclass(hwnd) {
			result, handled := builtinWndProc(hwnd, message, wParam, lParam)
			if os.Getenv("RAVEN_TRACE_CLICK") != "" && message == 0x004E {
				ravelog.Logf("[notify-dispatch-W] hwnd=0x%x WM_NOTIFY builtinHandled=%v\n", hwnd, handled)
			}
			if handled {
				if builtinMessageNeedsCommit(message) {
					requestCommit(true)
				}
				ctx.SetReturn(result)
				return 0
			}
		}

		wndProc, ok := hwndWndProc[hwnd]
		if os.Getenv("RAVEN_TRACE_CLICK") != "" && message == 0x004E {
			ravelog.Logf("[notify-dispatch-W] hwnd=0x%x WM_NOTIFY -> wndProc=0x%x ok=%v\n", hwnd, wndProc, ok)
		}
		if !ok || wndProc == 0 {
			// Fallback: look up WndProc from the window's registered class atom.
			// This handles cases where hwndWndProc was not populated at CreateWindowExW
			// (e.g., class registered by atom only, or late subclass initialization).
			if atom, hasAtom := hctx.HwndClassAtom[hwnd]; hasAtom {
				if wp, hasWP := hctx.AtomWndProc[atom]; hasWP && wp != 0 {
					wndProc = wp
					ok = true
					hwndWndProc[hwnd] = wndProc // cache for future dispatches
				}
			}
		}
		if !ok || wndProc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if message == 0x0082 && destroyPending[hwnd] {
			destroyDelivered[hwnd] = true
		}

		if os.Getenv("RAVEN_TRACE_CLICK") != "" && message == 0x004E {
			hf, _ := mem.Read64(lParam)
			idf, _ := mem.Read64(lParam + 8)
			code, _ := mem.Read32(lParam + 16)
			ravelog.Logf("[nmhdr-read] hwnd=0x%x lParam=0x%x hwndFrom=0x%x idFrom=0x%x code=0x%x (TCN_SELCHANGE=0xfffffde9) -> wndProc=0x%x\n",
				hwnd, lParam, hf, idf, code, wndProc)
		}
		is32 := ctx.State != nil && ctx.State.Is32
		if is32 {
			// PE32 stdcall: manually clean up DispatchMessageW's 1 arg (pMsg),
			// then set up WndProc call with args on stack.
			rr := ctx.CPU.(ntapi.RegisterReader)
			rw := ctx.CPU.(ntapi.RegisterWriter)
			rsp := rr.ReadReg(4)
			retAddr32, _ := mem.Read32(rsp)
			rsp += 4 + 1*4 // skip retAddr + 1 arg (pMsg)
			rw.WriteReg(4, rsp)
			hctx.SyncCallWndProc(ctx, wndProc, hwnd, message, wParam, lParam, uint64(retAddr32))
		} else {
			rw, ok := ctx.CPU.(ntapi.RegisterWriter)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			// x64: Stack is already correct: [RSP] = caller's return address.
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(message))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
			ctx.CPU.SetPC(wndProc)
			ctx.ReturnOverridden = true
			ctx.PCRedirected = true
		}
		return 0
	})
	// Accelerator table tracking
	// ReactOS: NtUserCreateAcceleratorTable
	translateAccelerator := func(ctx *ntapi.TrapContext) uint32 {
		// BOOL TranslateAcceleratorW(HWND, HACCEL, LPMSG)
		// ReactOS: win32ss/user/ntuser/accelerator.c NtUserTranslateAccelerator
		// Read MSG: {hwnd(8), message(4), wParam(8), lParam(8), time(4), pt.x(4), pt.y(4)}
		targetHWND := ctx.Arg(0)
		hAccel := ctx.Arg(1)
		pMsg := ctx.Arg(2)
		if pMsg == 0 || hAccel == 0 {
			ctx.SetReturn(0)
			return 0
		}
		accelMu.RLock()
		entries := append([]accelEntry(nil), accelTables[hAccel]...)
		accelMu.RUnlock()
		if len(entries) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		_, msgID, wParam, _ := readMsg(ctx, pMsg)
		key := uint16(wParam & 0xFFFF)
		const (
			WM_KEYDOWN    = 0x0100
			WM_SYSKEYDOWN = 0x0104
			FVIRTKEY      = 0x01
			FCONTROL      = 0x08
			FALT          = 0x10
			FSHIFT        = 0x04
			// VK constants for modifier keys
			VK_SHIFT   = 0x10
			VK_CONTROL = 0x11
			VK_MENU    = 0x12 // Alt
		)
		if msgID != WM_KEYDOWN && msgID != WM_SYSKEYDOWN {
			ctx.SetReturn(0)
			return 0
		}
		ctrlDown := keyState[VK_CONTROL]&0x80 != 0
		altDown := keyState[VK_MENU]&0x80 != 0
		shiftDown := keyState[VK_SHIFT]&0x80 != 0
		for _, ae := range entries {
			modifierMask := byte(FCONTROL | FALT | FSHIFT)
			isPlainTextKey := (key >= '0' && key <= '9') || (key >= 'A' && key <= 'Z')
			if isPlainTextKey && ae.fVirt&modifierMask == 0 {
				continue
			}
			if ae.fVirt&FVIRTKEY != 0 {
				if ae.key != key {
					continue
				}
			} else {
				if uint16(ae.key) != key {
					continue
				}
			}
			// Check modifier requirements
			if ae.fVirt&FCONTROL != 0 && !ctrlDown {
				continue
			}
			if ae.fVirt&FALT != 0 && !altDown {
				continue
			}
			if ae.fVirt&FSHIFT != 0 && !shiftDown {
				continue
			}
			// Accelerator matched post WM_COMMAND(HIWORD=1, LOWORD=cmdID) to target window.
			// ReactOS: IntTranslateKbdMessage posts WM_COMMAND with 1 in HIWORD (accelerator source).
			cmdID := uint64(ae.cmd)
			wp := cmdID | (1 << 16) // MAKEWPARAM(cmdID, 1)
			hw := targetHWND
			if hw == 0 {
				hw = hctx.MainHWND
			}
			ravelog.Logf("[accel] TranslateAcceleratorW key=0x%x -> WM_COMMAND cmd=0x%x hwnd=0x%x\n", key, cmdID, hw)
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hw, 0x0111, wp, 0))
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "TranslateAcceleratorW", translateAccelerator)
	d.RegisterAutoStubHandler(user32, "TranslateAcceleratorA", translateAccelerator)
	d.RegisterAutoStubHandler(user32, "TranslateAccelerator", translateAccelerator)
	createAcceleratorTable := func(ctx *ntapi.TrapContext) uint32 {
		pAccel := ctx.Arg(0)
		nEntries := int(ctx.Arg(1))
		entries, ok := readAcceleratorEntries(mem, pAccel, nEntries)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		accelMu.Lock()
		nextAccelTable++
		h := nextAccelTable
		accelTables[h] = entries
		accelMu.Unlock()
		ctx.SetReturn(h)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "CreateAcceleratorTableW", createAcceleratorTable)
	d.RegisterAutoStubHandler(user32, "CreateAcceleratorTableA", createAcceleratorTable)
	copyAcceleratorTable := func(ctx *ntapi.TrapContext) uint32 {
		hAccel := ctx.Arg(0)
		pAccel := ctx.Arg(1)
		capacity := int(ctx.Arg(2))
		accelMu.RLock()
		entries, ok := accelTables[hAccel]
		entries = append([]accelEntry(nil), entries...)
		accelMu.RUnlock()
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		if pAccel == 0 {
			ctx.SetReturn(uint64(len(entries)))
			return 0
		}
		if capacity < 0 {
			capacity = 0
		}
		if capacity < len(entries) {
			entries = entries[:capacity]
		}
		if len(entries) > 0 && !writeAcceleratorEntries(mem, pAccel, entries) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(len(entries)))
		return 0
	}
	d.RegisterAutoStubHandler(user32, "CopyAcceleratorTableW", copyAcceleratorTable)
	d.RegisterAutoStubHandler(user32, "CopyAcceleratorTableA", copyAcceleratorTable)
	// DestroyAcceleratorTable
	d.RegisterAutoStubHandler(user32, "DestroyAcceleratorTable", func(ctx *ntapi.TrapContext) uint32 {
		hAccel := ctx.Arg(0)
		ok := destroyAcceleratorTable(accelTables, &accelMu, hAccel)
		ravelog.Logf("[user32] DestroyAcceleratorTable hAccel=0x%x", hAccel)
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// IsClipboardFormatAvailable - duplicate registration handled later in the clipboard section
	// LoadBitmapW - load bitmap from PE resource, return HBITMAP
	d.RegisterAutoStubHandler(user32, "LoadBitmapW", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if nameArg < 0x10000 && mainModule != nil &&
			(hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bitCount, _ := mem.Read16(addr + 14)
				width, height := dibDimensions(addr)
				bitmapHandles[h] = &bitmapHandleData{slots: slots, w: width, h: height, monochrome: bitCount == 1}
				ravelog.Logf("[loadbitmap] LoadBitmapW resID=0x%x -> handle=0x%x slots=%d\n", resID, h, len(slots))
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0) // NULL
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c IntGetForegroundWindow
		if hctx.FocusHwnd != 0 {
			ctx.SetReturn(hctx.FocusHwnd)
		} else {
			ctx.SetReturn(hctx.MainHWND)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c co_IntSetForegroundWindow
		hctx.FocusHwnd = ctx.Arg(0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowVisible", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			if cs.visible {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		}
		// Main window or unknown: assume visible
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserIsWindow
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0x00050000 {
			ctx.SetReturn(1)
			return 0
		}
		if _, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetFocus", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.FocusHwnd
		newFocus := ctx.Arg(0)
		if newFocus == prev {
			ctx.SetReturn(prev)
			return 0
		}
		// ReactOS co_UserSetFocus: send WM_KILLFOCUS to old window, WM_SETFOCUS to new.
		// Use class-atom fallback to find WndProc in case hwndWndProc wasn't populated at creation time.
		hasGuestWndProc := func(h uint64) bool {
			if wp := hwndWndProc[h]; wp != 0 {
				return true
			}
			if atom, ok := hctx.HwndClassAtom[h]; ok {
				if wp, ok2 := hctx.AtomWndProc[atom]; ok2 && wp != 0 {
					hwndWndProc[h] = wp // cache for future
					return true
				}
			}
			return false
		}
		if prev != 0 {
			if hasGuestWndProc(prev) {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, prev, 0x0008, newFocus, 0)) // WM_KILLFOCUS
			}
		}
		hctx.FocusHwnd = newFocus
		if newFocus != 0 {
			if hasGuestWndProc(newFocus) {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, newFocus, 0x0007, prev, 0)) // WM_SETFOCUS
			}
		}
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetFocus", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.FocusHwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCapture", func(ctx *ntapi.TrapContext) uint32 {
		prev := hctx.MouseCapture
		hctx.MouseCapture = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
		hctx.MouseCapture = 0
		ctx.SetReturn(1)
		return 0
	})
	updateWindowEnabled := func(hwnd uint64, enabled, notify bool) (bool, bool) {
		hwndLifecycleMu.Lock()
		defer hwndLifecycleMu.Unlock()
		return changeWindowEnabled(hwnd, enabled, notify, setWindowDisabled,
			func(target uint64, message uint32, wParam uint64) {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, message, wParam, 0))
			})
	}
	d.RegisterAutoStubHandler(user32, "EnableWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		wasDisabled, _ := updateWindowEnabled(hwnd, ctx.Arg(1) != 0, true)
		// Return TRUE if the window was previously disabled
		if wasDisabled {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetTimer", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := ctx.Arg(1)
		elapse := ctx.Arg(2)
		proc := ctx.Arg(3)
		if elapse < 10 {
			elapse = 10
		}
		owner := ctx.CPU
		if hwnd != 0 {
			if windowOwner := hctx.windowCPU(hwnd); windowOwner != nil {
				owner = windowOwner
			}
		}
		if id == 0 || hwnd == 0 && !hctx.Timers.has(owner, 0, id) {
			id = hctx.Timers.allocateID()
		}
		ravelog.Logf("[wise] SetTimer hwnd=0x%x id=%d interval=%dms proc=0x%x\n", hwnd, id, elapse, proc)
		hctx.Timers.set(&win32Timer{
			id:         id,
			hwnd:       hwnd,
			intervalMs: elapse,
			proc:       proc,
			deadline:   time.Now().Add(time.Duration(elapse) * time.Millisecond),
			cpu:        owner,
		})
		ctx.SetReturn(id)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "KillTimer", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := ctx.Arg(1)
		owner := ctx.CPU
		if hwnd != 0 {
			if windowOwner := hctx.windowCPU(hwnd); windowOwner != nil {
				owner = windowOwner
			}
		}
		killed := hctx.Timers.kill(owner, hwnd, id)
		ravelog.Logf("[wise] KillTimer hwnd=0x%x id=%d (have=%v)\n", hwnd, id, killed)
		if killed {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InvalidateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Route WM_PAINT to the actual window, not always hctx.MainHWND.
		// Routing Scintilla's own InvalidateRect to hctx.MainHWND causes an infinite
		// repaint loop: hctx.MainHWND erases Scintilla -> Scintilla redraws ->
		// Scintilla calls InvalidateRect -> hctx.MainHWND erases again -> loop.
		var rect *win32.Rect
		if pRect := ctx.Arg(1); pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rect = &win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
		}
		target := hctx.MainHWND
		visible := true
		if hwnd != 0 && hwnd != hctx.MainHWND {
			cs, ok := hwndChildren[hwnd]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			target = hwnd
			visible = cs.visible
		}
		win32.Global.Invalidate(target, rect)
		hctx.WinInvalid[target] = true
		if ctx.Arg(2) != 0 {
			hctx.WinErasePending[target] = true
		}
		if visible {
			queuePaint(target)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InvalidateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		target := hctx.MainHWND
		visible := true
		if hwnd != 0 && hwnd != hctx.MainHWND {
			cs, ok := hwndChildren[hwnd]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			target = hwnd
			visible = cs.visible
		}
		win32.Global.Invalidate(target, nil)
		hctx.WinInvalid[target] = true
		if ctx.Arg(2) != 0 {
			hctx.WinErasePending[target] = true
		}
		if visible {
			queuePaint(target)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ValidateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		hctx.WinInvalid[hwnd] = false
		delete(hctx.WinErasePending, hwnd)
		win32.Global.Validate(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ValidateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		hctx.WinInvalid[hwnd] = false
		delete(hctx.WinErasePending, hwnd)
		win32.Global.Validate(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hrgn := ctx.Arg(1)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		if !hctx.WinInvalid[hwnd] {
			ctx.SetReturn(0) // NULLREGION
			return 0
		}
		// Fill the region with the window's client rect and return SIMPLEREGION
		if hrgn != 0 {
			if cs, ok := hwndChildren[hwnd]; ok {
				gdiMgr.SetRectRgn(hrgn, 0, 0, cs.w, cs.h)
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				gdiMgr.SetRectRgn(hrgn, 0, 0, wlWindow.Width, wlWindow.Height)
			} else {
				gdiMgr.SetRectRgn(hrgn, 0, 0, 800, 600)
			}
		}
		ctx.SetReturn(2) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetUpdateRect", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pRect := ctx.Arg(1)
		if hwnd == 0 {
			hwnd = hctx.MainHWND
		}
		dirtyRect, dirty := win32.Global.GetUpdateRect(hwnd)
		if !dirty && !hctx.WinInvalid[hwnd] {
			if pRect != 0 {
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, 0)
				ctx.Mem.Write32(pRect+12, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		if pRect != 0 {
			if dirty {
				ctx.Mem.Write32(pRect, uint32(dirtyRect.Left))
				ctx.Mem.Write32(pRect+4, uint32(dirtyRect.Top))
				ctx.Mem.Write32(pRect+8, uint32(dirtyRect.Right))
				ctx.Mem.Write32(pRect+12, uint32(dirtyRect.Bottom))
			} else {
				var w, h int32 = 800, 600
				if cs, ok := hwndChildren[hwnd]; ok {
					w, h = cs.w, cs.h
				} else if wlWindow != nil {
					w, h = wlWindow.Width, wlWindow.Height
				}
				ctx.Mem.Write32(pRect, 0)
				ctx.Mem.Write32(pRect+4, 0)
				ctx.Mem.Write32(pRect+8, uint32(w))
				ctx.Mem.Write32(pRect+12, uint32(h))
			}
		}
		ctx.SetReturn(1) // update region is non-empty
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PrintWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PrintWindow(HWND hwnd, HDC hdcBlt, UINT nFlags)
		hwnd := ctx.Arg(0)
		hdcBlt := ctx.Arg(1)
		nFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] PrintWindow hwnd=0x%x hdc=0x%x flags=0x%x", hwnd, hdcBlt, nFlags)
		ctx.SetReturn(1)
		return 0
	})
	// DrawEdge/DrawFrameControl/DrawFocusRect in user32
	d.RegisterAutoStubHandler(user32, "DrawEdge", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		edge := uint32(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawEdge(int32(l), int32(t), int32(r), int32(b), edge, flags, hctx.SysColors)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawFrameControl", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		uType := uint32(ctx.Arg(2))
		uState := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawFrameControl(int32(l), int32(t), int32(r), int32(b), uType, uState, hctx.SysColors)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawFocusRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawFocusRect(int32(l), int32(t), int32(r), int32(b))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InvertRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.InvertRect(int32(l), int32(t), int32(r), int32(b))
		}
		ctx.SetReturn(1)
		return 0
	})
	// DrawText/DrawTextEx
	d.RegisterAutoStubHandler(user32, "DrawTextW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestUTF16(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			b, _ := mem.Read32(lpRect + 12)
			// DT_CALCRECT=0x400 - just return text height
			if uFormat&0x400 != 0 {
				f := dc.Font
				if f == nil {
					f = gdi.DefaultFont()
				}
				ctx.Mem.Write32(lpRect+12, uint32(int32(t)+f.CellHeight))
				ctx.SetReturn(uint64(f.CellHeight))
				return 0
			}
			// Center horizontally (DT_CENTER=1) or right (DT_RIGHT=2)
			x := int32(l) + 2
			y := int32(t)
			f := dc.Font
			if f == nil {
				f = gdi.DefaultFont()
			}
			w := int32(r) - int32(l)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			if uFormat&0x1 != 0 {
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x2 != 0 {
				x = int32(r) - tw - 2
			}
			// DT_VCENTER=4: vertically center
			if uFormat&0x4 != 0 {
				h := int32(b) - int32(t)
				y = int32(t) + (h-f.CellHeight)/2
			}
			// ETO_CLIPPED on the rect
			oldClip := [4]int32{dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1}
			dc.ClipX0 = int32(l) + dc.OriginX
			dc.ClipY0 = int32(t) + dc.OriginY
			dc.ClipX1 = int32(r) + dc.OriginX
			dc.ClipY1 = int32(b) + dc.OriginY
			dc.TextOut(x, y, text, false)
			dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1 = oldClip[0], oldClip[1], oldClip[2], oldClip[3]
			ctx.SetReturn(uint64(f.CellHeight))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawTextExW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		// Delegate to DrawTextW implementation (same first 4 args + format)
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestUTF16(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			x := int32(l) + 2
			y := int32(t)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			w := int32(r) - int32(l)
			if uFormat&0x1 != 0 {
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x2 != 0 {
				x = int32(r) - tw - 2
			}
			dc.TextOut(x, y, text, false)
			ctx.SetReturn(uint64(f.CellHeight))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TabbedTextOutW", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(0)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		lpStr := ctx.Arg(3)
		nCount := int(ctx.Arg(4))
		text := readGuestUTF16(lpStr)
		if nCount > 0 && nCount < len(text) {
			text = text[:nCount]
		}
		dc.TextOut(x, y, text, false)
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		w := int32(len([]rune(text))) * f.AveCharWidth
		ctx.SetReturn(uint64(uint32(f.CellHeight)<<16 | uint32(w)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GrayStringW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GrayStringW(HDC hDC, HBRUSH hBrush, GRAYSTRINGPROC lpOutputFunc, LPARAM lpData, int nCount, int X, int Y, int nWidth, int nHeight)
		hdc := ctx.Arg(0)
		lpData := ctx.Arg(3)
		nCount := int32(ctx.Arg(4))
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil && lpData != 0 && nCount > 0 {
			txt := readGuestUTF16N(lpData, int(nCount))
			oldColor := dc.TextColor
			dc.TextColor = 0x808080
			dc.TextOut(x, y, txt, false)
			dc.TextColor = oldColor
		}
		ctx.SetReturn(1)
		return 0
	})
	// Scroll bars
	d.RegisterAutoStubHandler(user32, "GetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		psi := ctx.Arg(2)
		if psi == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := mem.Read32(psi)
		if cbSize < 28 {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(psi + 4)
		si := win32.ScrollInfo{}
		win32.GetScrollInfo(hwnd, nBar, &si, uint32(fMask))
		if uint32(fMask)&win32.SIF_RANGE != 0 {
			ctx.Mem.Write32(psi+8, uint32(si.Min))
			ctx.Mem.Write32(psi+12, uint32(si.Max))
		}
		if uint32(fMask)&win32.SIF_PAGE != 0 {
			ctx.Mem.Write32(psi+16, si.Page)
		}
		if uint32(fMask)&win32.SIF_POS != 0 {
			ctx.Mem.Write32(psi+20, uint32(si.Pos))
		}
		if uint32(fMask)&win32.SIF_TRACKPOS != 0 {
			ctx.Mem.Write32(psi+24, uint32(si.TrackPos))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		psi := ctx.Arg(2)
		if psi == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cbSize, _ := mem.Read32(psi)
		if cbSize < 28 {
			ctx.SetReturn(0)
			return 0
		}
		fMask, _ := mem.Read32(psi + 4)
		si := win32.ScrollInfo{}
		min32, _ := mem.Read32(psi + 8)
		si.Min = int32(min32)
		max32, _ := mem.Read32(psi + 12)
		si.Max = int32(max32)
		page32, _ := mem.Read32(psi + 16)
		si.Page = page32
		pos32, _ := mem.Read32(psi + 20)
		si.Pos = int32(pos32)
		pos := win32.SetScrollInfo(hwnd, nBar, &si, uint32(fMask))
		requestWindowRepaint(hwnd)
		ctx.SetReturn(uint64(pos))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		ctx.SetReturn(uint64(win32.GetScrollPos(hwnd, nBar)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollPos", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		pos := int32(ctx.Arg(2))
		prev := win32.SetScrollPos(hwnd, nBar, pos)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		pMin := ctx.Arg(2)
		pMax := ctx.Arg(3)
		mn, mx := win32.GetScrollRange(hwnd, nBar)
		if pMin != 0 {
			ctx.Mem.Write32(pMin, uint32(mn))
		}
		if pMax != 0 {
			ctx.Mem.Write32(pMax, uint32(mx))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetScrollRange", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		nBar := int(ctx.Arg(1))
		mn := int32(ctx.Arg(2))
		mx := int32(ctx.Arg(3))
		win32.SetScrollRange(hwnd, nBar, mn, mx)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		wBar := int32(ctx.Arg(1))
		bShow := ctx.Arg(2) != 0
		ravelog.Logf("[user32] ShowScrollBar hwnd=0x%x bar=%d show=%v\n", hwnd, wBar, bShow)
		requestWindowRepaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnableScrollBar", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		wSBflags := uint32(ctx.Arg(1))
		wArrows := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] EnableScrollBar hwnd=0x%x flags=0x%x arrows=0x%x\n", hwnd, wSBflags, wArrows)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/scrollex.c co_UserScrollWindowEx
		hwnd := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		lpRect := ctx.Arg(3)
		lpClipRect := ctx.Arg(4)

		if wlWindow != nil && (dx != 0 || dy != 0) {
			syncScreenSurface()
			var left, top, right, bottom int32
			if lpRect != 0 {
				v, _ := mem.Read32(lpRect)
				left = int32(v)
				v, _ = mem.Read32(lpRect + 4)
				top = int32(v)
				v, _ = mem.Read32(lpRect + 8)
				right = int32(v)
				v, _ = mem.Read32(lpRect + 12)
				bottom = int32(v)
			} else if cs, ok := hwndChildren[hwnd]; ok {
				left, top = 0, 0
				right, bottom = cs.w, cs.h
			} else {
				right, bottom = wlWindow.Width, wlWindow.Height
			}
			if lpClipRect != 0 {
				v, _ := mem.Read32(lpClipRect)
				cl := int32(v)
				v, _ = mem.Read32(lpClipRect + 4)
				ct := int32(v)
				v, _ = mem.Read32(lpClipRect + 8)
				cr := int32(v)
				v, _ = mem.Read32(lpClipRect + 12)
				cb := int32(v)
				if cl > left {
					left = cl
				}
				if ct > top {
					top = ct
				}
				if cr < right {
					right = cr
				}
				if cb < bottom {
					bottom = cb
				}
			}
			if right > left && bottom > top && gdiMgr.Screen != nil {
				ox, oy := absWindowOffset(hwnd)
				gdiMgr.Screen.BitBlt(ox+left+dx, oy+top+dy, gdiMgr.Screen, ox+left, oy+top, right-left, bottom-top)
			}
		}
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollWindowEx", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/scrollex.c NtUserScrollWindowEx
		hwnd := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		prcScroll := ctx.Arg(3) // nullable RECT
		prcClip := ctx.Arg(4)   // nullable RECT
		// hrgnUpdate := ctx.Arg(5)
		prcUpdate := ctx.Arg(6)
		if wlWindow != nil && (dx != 0 || dy != 0) {
			syncScreenSurface()
			left, top, right, bottom := int32(0), int32(0), int32(0), int32(0)
			if cs, ok := hwndChildren[hwnd]; ok {
				right, bottom = cs.w, cs.h
			} else if hwnd == hctx.MainHWND {
				right, bottom = wlWindow.Width, wlWindow.Height
			}
			if prcScroll != 0 {
				l, _ := mem.Read32(prcScroll)
				t, _ := mem.Read32(prcScroll + 4)
				r, _ := mem.Read32(prcScroll + 8)
				b, _ := mem.Read32(prcScroll + 12)
				left, top, right, bottom = int32(l), int32(t), int32(r), int32(b)
			}
			if prcClip != 0 {
				l, _ := mem.Read32(prcClip)
				t, _ := mem.Read32(prcClip + 4)
				r, _ := mem.Read32(prcClip + 8)
				b, _ := mem.Read32(prcClip + 12)
				if int32(l) > left {
					left = int32(l)
				}
				if int32(t) > top {
					top = int32(t)
				}
				if int32(r) < right {
					right = int32(r)
				}
				if int32(b) < bottom {
					bottom = int32(b)
				}
			}
			if right > left && bottom > top && gdiMgr.Screen != nil {
				ox, oy := absWindowOffset(hwnd)
				gdiMgr.Screen.BitBlt(ox+left+dx, oy+top+dy, gdiMgr.Screen, ox+left, oy+top, right-left, bottom-top)
			}
		}
		if prcUpdate != 0 {
			if cs, ok := hwndChildren[hwnd]; ok {
				mem.Write32(prcUpdate, 0)
				mem.Write32(prcUpdate+4, 0)
				mem.Write32(prcUpdate+8, uint32(cs.w))
				mem.Write32(prcUpdate+12, uint32(cs.h))
			} else if hwnd == hctx.MainHWND && wlWindow != nil {
				mem.Write32(prcUpdate, 0)
				mem.Write32(prcUpdate+4, 0)
				mem.Write32(prcUpdate+8, uint32(wlWindow.Width))
				mem.Write32(prcUpdate+12, uint32(wlWindow.Height))
			}
		}
		win32.Global.Invalidate(hwnd, nil)
		queuePaint(hwnd)
		ctx.SetReturn(1) // SIMPLEREGION
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScrollDC", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/scrollex.c NtUserScrollDC
		hDC := ctx.Arg(0)
		dx := int32(ctx.Arg(1))
		dy := int32(ctx.Arg(2))
		lprcScroll := ctx.Arg(3)
		lprcClip := ctx.Arg(4)
		// arg5 = hrgnUpdate (ignored)
		lprcUpdate := ctx.Arg(6)

		dc := getDC(hDC)
		if dc != nil && (dx != 0 || dy != 0) {
			// Get the live surface (screen DCs use Mgr.Screen for live buffer)
			var surf *gdi.Surface
			if dc.IsScreen && dc.Mgr != nil && dc.Mgr.Screen != nil {
				surf = dc.Mgr.Screen
			} else {
				surf = dc.Target
			}
			if surf != nil && surf.Pix != nil {
				var left, top, right, bottom int32
				if lprcScroll != 0 {
					v, _ := mem.Read32(lprcScroll)
					left = int32(v)
					v, _ = mem.Read32(lprcScroll + 4)
					top = int32(v)
					v, _ = mem.Read32(lprcScroll + 8)
					right = int32(v)
					v, _ = mem.Read32(lprcScroll + 12)
					bottom = int32(v)
				} else {
					left, top = 0, 0
					right = dc.ClipX1 - dc.OriginX
					bottom = dc.ClipY1 - dc.OriginY
				}
				if lprcClip != 0 {
					v, _ := mem.Read32(lprcClip)
					cl := int32(v)
					v, _ = mem.Read32(lprcClip + 4)
					ct := int32(v)
					v, _ = mem.Read32(lprcClip + 8)
					cr := int32(v)
					v, _ = mem.Read32(lprcClip + 12)
					cb := int32(v)
					if cl > left {
						left = cl
					}
					if ct > top {
						top = ct
					}
					if cr < right {
						right = cr
					}
					if cb < bottom {
						bottom = cb
					}
				}
				if right > left && bottom > top {
					ax := dc.OriginX + left
					ay := dc.OriginY + top
					w := right - left
					h := bottom - top
					surf.BitBlt(ax+dx, ay+dy, surf, ax, ay, w, h)
				}
			}
		}
		if lprcUpdate != 0 {
			mem.Write32(lprcUpdate, 0)
			mem.Write32(lprcUpdate+4, 0)
			mem.Write32(lprcUpdate+8, 0)
			mem.Write32(lprcUpdate+12, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	// Window region
	d.RegisterAutoStubHandler(user32, "SetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/winpos.c co_WinPosSetWindowRgn
		hwnd := ctx.Arg(0)
		hRgn := ctx.Arg(1)
		if hRgn != 0 {
			hwndWindowRgn[hwnd] = hRgn
		} else {
			delete(hwndWindowRgn, hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRgn", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0 // ERROR - no window region set
	})
	d.RegisterAutoStubHandler(user32, "GetWindowRgnBox", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lprc := ctx.Arg(1)
		if _, ok := hwndWindowRgn[hwnd]; ok && lprc != 0 {
			if cs, ok2 := hwndChildren[hwnd]; ok2 {
				mem.Write32(lprc, 0)
				mem.Write32(lprc+4, 0)
				mem.Write32(lprc+8, uint32(cs.w))
				mem.Write32(lprc+12, uint32(cs.h))
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	// Caret - ReactOS: win32ss/user/ntuser/caret.c
	d.RegisterAutoStubHandler(user32, "CreateCaret", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hBitmap := ctx.Arg(1)
		w := int32(ctx.Arg(2))
		h := int32(ctx.Arg(3))
		if w == 0 {
			w = 1 // SM_CXBORDER
		}
		if h == 0 {
			h = 20
		}
		_ = hBitmap
		hctx.CaretHwnd = hwnd
		hctx.CaretWidth = w
		hctx.CaretHeight = h
		hctx.CaretX = 0
		hctx.CaretY = 0
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretHwnd = 0
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretVisible = true
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "HideCaret", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretVisible = false
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(hctx.CaretX))
			ctx.Mem.Write32(p+4, uint32(hctx.CaretY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCaretPos", func(ctx *ntapi.TrapContext) uint32 {
		hctx.CaretX = int32(ctx.Arg(0))
		hctx.CaretY = int32(ctx.Arg(1))
		ctx.SetReturn(1)
		return 0
	})
	caretBlinkTime := uint32(530)
	d.RegisterAutoStubHandler(user32, "GetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(caretBlinkTime))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCaretBlinkTime", func(ctx *ntapi.TrapContext) uint32 {
		newTime := uint32(ctx.Arg(0))
		if newTime > 0 {
			caretBlinkTime = newTime
		}
		ctx.SetReturn(1)
		return 0
	})
	// Window geometry helpers
	d.RegisterAutoStubHandler(user32, "AdjustWindowRect", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, 0)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AdjustWindowRectEx", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		exStyle := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "WindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		x, y := decodePointArgs(ctx.Arg(0), ctx.Arg(1), ctx.State != nil && ctx.State.Is32)
		mainRect := win32.Rect{}
		if wlWindow != nil {
			mainRect.Right = wlWindow.Width
			mainRect.Bottom = wlWindow.Height + wlWindow.TitleBarH
		}
		ctx.SetReturn(windowFromPoint(hwndChildren, hctx.snapshotZOrder(), hctx.MainHWND, mainRect, x, y))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		is32 := ctx.State != nil && ctx.State.Is32
		x, y := decodePointArgs(ctx.Arg(1), ctx.Arg(2), is32)
		ox, oy, pw, ph := windowClientGeometry(hwndChildren, parent)
		if x < 0 || y < 0 || x >= pw || y >= ph {
			ctx.SetReturn(0)
			return 0
		}
		child := childWindowAtPoint(hwndChildren, hctx.snapshotZOrder(), parent, ox+x, oy+y, 0)
		if child == 0 {
			child = parent
		}
		ctx.SetReturn(child)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChildWindowFromPointEx", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		is32 := ctx.State != nil && ctx.State.Is32
		x, y := decodePointArgs(ctx.Arg(1), ctx.Arg(2), is32)
		ox, oy, pw, ph := windowClientGeometry(hwndChildren, parent)
		if x < 0 || y < 0 || x >= pw || y >= ph {
			ctx.SetReturn(0)
			return 0
		}
		flagsArg := 2
		if is32 {
			flagsArg = 3
		}
		child := childWindowAtPoint(hwndChildren, hctx.snapshotZOrder(), parent, ox+x, oy+y, uint32(ctx.Arg(flagsArg)))
		if child == 0 {
			child = parent
		}
		ctx.SetReturn(child)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RealChildWindowFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		parent := ctx.Arg(0)
		x, y := decodePointArgs(ctx.Arg(1), ctx.Arg(2), ctx.State != nil && ctx.State.Is32)
		ox, oy, pw, ph := windowClientGeometry(hwndChildren, parent)
		if x < 0 || y < 0 || x >= pw || y >= ph {
			ctx.SetReturn(0)
			return 0
		}
		child := childWindowAtPoint(hwndChildren, hctx.snapshotZOrder(), parent, ox+x, oy+y,
			cwpSkipInvisible|cwpSkipHitTestTransparent|cwpReturnHitTestFallback)
		if child == 0 {
			child = parent
		}
		ctx.SetReturn(child)
		return 0
	})
	// childrenOf returns HWND slice of children whose parent matches p, sorted ascending.
	childrenOf := func(p uint64) []uint64 {
		var out []uint64
		for h, cs := range hwndChildren {
			if cs.parentHWND == p {
				out = append(out, h)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}

	d.RegisterAutoStubHandler(user32, "GetNextWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: GetNextWindow is GetWindow(hwnd, cmd)
		// GW_HWNDNEXT=2, GW_HWNDPREV=3
		hwnd := ctx.Arg(0)
		cmd := ctx.Arg(1)
		cs, ok := hwndChildren[hwnd]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		siblings := childrenOf(cs.parentHWND)
		idx := -1
		for i, h := range siblings {
			if h == hwnd {
				idx = i
				break
			}
		}
		if idx < 0 {
			ctx.SetReturn(0)
			return 0
		}
		switch cmd {
		case 2: // GW_HWNDNEXT
			if idx+1 < len(siblings) {
				ctx.SetReturn(siblings[idx+1])
			} else {
				ctx.SetReturn(0)
			}
		case 3: // GW_HWNDPREV
			if idx > 0 {
				ctx.SetReturn(siblings[idx-1])
			} else {
				ctx.SetReturn(0)
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetTopWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetTopWindow
		// Returns the first child window (top of Z-order) of the given parent.
		// If hwnd==0, use the desktop window.
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			hwnd = 0x00050000 // desktop
		}
		kids := childrenOf(hwnd)
		// Also treat MainHWND's children as top-level for desktop queries.
		if len(kids) == 0 && (hwnd == 0x00050000 || hwnd == hctx.MainHWND) {
			kids = childrenOf(hctx.MainHWND)
		}
		if len(kids) > 0 {
			ctx.SetReturn(kids[0])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetWindow
		hwnd := ctx.Arg(0)
		cmd := ctx.Arg(1)
		const (
			gwHWNDFIRST = 0
			gwHWNDLAST  = 1
			gwHWNDNEXT  = 2
			gwHWNDPREV  = 3
			gwOWNER     = 4
			gwCHILD     = 5
		)
		switch cmd {
		case gwCHILD:
			kids := childrenOf(hwnd)
			if len(kids) > 0 {
				ctx.SetReturn(kids[0])
			} else {
				ctx.SetReturn(0)
			}
		case gwOWNER:
			// For child windows, the owner is the parent. For top-level, 0.
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
		case gwHWNDNEXT, gwHWNDPREV, gwHWNDFIRST, gwHWNDLAST:
			cs, ok := hwndChildren[hwnd]
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			siblings := childrenOf(cs.parentHWND)
			idx := -1
			for i, h := range siblings {
				if h == hwnd {
					idx = i
					break
				}
			}
			if idx < 0 {
				ctx.SetReturn(0)
				return 0
			}
			switch cmd {
			case gwHWNDNEXT:
				if idx+1 < len(siblings) {
					ctx.SetReturn(siblings[idx+1])
				} else {
					ctx.SetReturn(0)
				}
			case gwHWNDPREV:
				if idx > 0 {
					ctx.SetReturn(siblings[idx-1])
				} else {
					ctx.SetReturn(0)
				}
			case gwHWNDFIRST:
				ctx.SetReturn(siblings[0])
			case gwHWNDLAST:
				ctx.SetReturn(siblings[len(siblings)-1])
			}
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumChildWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam)
		// ReactOS: win32ss/user/ntuser/window.c NtUserBuildHwndList
		// Callback: BOOL CALLBACK EnumChildProc(HWND, LPARAM) -> RCX=hwnd, RDX=lParam
		hWndParent := ctx.Arg(0)
		lpEnumFunc := ctx.Arg(1)
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		parent := hWndParent
		if parent == 0 {
			parent = hctx.MainHWND
		}
		kids := win32.Global.ChildrenOf(parent)
		if len(kids) == 0 {
			ctx.SetReturn(1) // no children = success
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		// Build dispatch queue: each entry calls lpEnumFunc(child_hwnd, lParam)
		queue := make([]syncDispatch, len(kids))
		for i, kid := range kids {
			queue[i] = syncDispatch{
				wndProc: lpEnumFunc,
				hwnd:    kid,
				msg:     lParam,
			}
		}
		syncStack := hctx.syncStack(ctx)
		*syncStack = append(*syncStack, syncDispatchFrame{
			queue:   queue,
			retAddr: retAddr,
			hwnd:    1, // return TRUE
		})
		// Start first dispatch
		sd := queue[0]
		(*syncStack)[len(*syncStack)-1].queue = queue[1:]
		rsp -= 48
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, sd.hwnd)
		rw.WriteReg(2, uint64(sd.msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(sd.wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
		// ReactOS: NtUserBuildHwndList (all top-level windows)
		lpEnumFunc := ctx.Arg(0)
		lParam := ctx.Arg(1)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		all := win32.Global.AllWindows()
		// Filter to top-level only (Parent == 0 or MainHWND)
		var topLevel []uint64
		for _, h := range all {
			wnd := win32.Global.Get(h)
			if wnd != nil && (wnd.Parent == 0 || h == hctx.MainHWND) {
				topLevel = append(topLevel, h)
			}
		}
		if len(topLevel) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		queue := make([]syncDispatch, len(topLevel))
		for i, h := range topLevel {
			queue[i] = syncDispatch{wndProc: lpEnumFunc, hwnd: h, msg: lParam}
		}
		syncStack := hctx.syncStack(ctx)
		*syncStack = append(*syncStack, syncDispatchFrame{
			queue:   queue[1:],
			retAddr: retAddr,
			hwnd:    1,
		})
		rsp -= 48
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, queue[0].hwnd)
		rw.WriteReg(2, uint64(queue[0].msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(queue[0].wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})
	lockedUpdateHwnd := uint64(0)
	d.RegisterAutoStubHandler(user32, "LockWindowUpdate", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hwnd == 0 {
			lockedUpdateHwnd = 0
		} else {
			if lockedUpdateHwnd != 0 && lockedUpdateHwnd != hwnd {
				ctx.SetReturn(0)
				return 0
			}
			lockedUpdateHwnd = hwnd
		}
		ctx.SetReturn(1)
		return 0
	})
	// Dialog functions

	var modalDialogs modalDialogRegistry
	var modalOwners modalOwnerRegistry
	disableModalOwner := func(hwnd uint64) {
		modalOwners.acquire(hwnd, func() bool {
			return isWindowDisabled(hwnd)
		}, func() {
			_, _ = updateWindowEnabled(hwnd, false, true)
		})
	}
	restoreModalOwner := func(entry modalDlgEntry) {
		modalOwners.release(entry.parent, func() {
			_, _ = updateWindowEnabled(entry.parent, true, true)
		})
	}
	isDisabledInput := func(hwnd uint64, message uint32, modalRoot uint64) bool {
		if !isModalInputMessage(message) {
			return false
		}
		return disabledWindowInHierarchy(hwnd, modalRoot, isWindowDisabled, win32.Global.Parent)
	}
	traceModalDialog := os.Getenv("RAVEN_TRACE_MODAL_DIALOG") != ""
	traceModalObject := func(prefix string, entry modalDlgEntry, messageHWND uint64, message uint32) {
		if !traceModalDialog {
			return
		}
		userData := windowLongPtr[entry.hwnd][-21]
		vtable := uint64(0)
		if userData != 0 {
			vtable, _ = mem.Read64(userData)
		}
		ravelog.Logf("[dialog-trace] %s dialog=0x%x hwnd=0x%x msg=0x%x retRSP=0x%x pumpSP=0x%x userData=0x%x vtable=0x%x\n",
			prefix, entry.hwnd, messageHWND, message, entry.retRSP, entry.pumpSP, userData, vtable)
	}
	finishModalDialog := func(ctx *ntapi.TrapContext, hDlg uint64) bool {
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return false
		}
		entry, ok := modalDialogs.takeEnded(ctx.CPU, hDlg)
		if !ok {
			return false
		}
		destroyOwnedDialogWindowForCPU(hDlg, ctx.CPU)
		cleanupWindowState(hDlg)
		restoreModalOwner(entry)
		hctx.FocusHwnd = entry.previousFocus
		hctx.ActiveHwnd = entry.previousActive

		syncStack := hctx.syncStack(ctx)
		if entry.syncDepth < len(*syncStack) {
			*syncStack = (*syncStack)[:entry.syncDepth]
		}

		is32 := ctx.State != nil && ctx.State.Is32
		if is32 {
			rsp := entry.retRSP - 4
			mem.Write32(rsp, uint32(entry.retAddr))
			rw.WriteReg(4, rsp)
		} else {
			rsp := entry.retRSP - 8
			mem.Write64(rsp, entry.retAddr)
			rw.WriteReg(4, rsp)
		}
		restoreGuestNonvolatileRegisters(rw, entry.callee)
		ctx.SetReturn(entry.result)
		retOffset := uint64(19)
		if is32 {
			retOffset = 13
		}
		ctx.CPU.SetPC(hctx.SyncTrampoline + retOffset)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		ravelog.Logf("[dialog] completed hwnd=0x%x result=%d retAddr=0x%x retRSP=0x%x\n",
			hDlg, entry.result, entry.retAddr, entry.retRSP)
		return true
	}
	hctx.FinishModalDialog = finishModalDialog
	type messageBoxOwnerState struct {
		count       int
		wasDisabled bool
	}
	var messageBoxMu sync.Mutex
	var messageBoxPumpMu sync.Mutex
	messageBoxStacks := make(map[arch.CPU][]*messageBoxRuntime)
	messageBoxOwners := make(map[uint64]messageBoxOwnerState)
	messageBoxesByHWND := make(map[uint64]*messageBoxRuntime)

	pushMessageBox := func(cpu arch.CPU, box *messageBoxRuntime) {
		messageBoxMu.Lock()
		messageBoxStacks[cpu] = append(messageBoxStacks[cpu], box)
		messageBoxesByHWND[box.hwnd] = box
		ownerState := messageBoxOwners[box.owner]
		if ownerState.count == 0 {
			ownerState.wasDisabled = isWindowDisabled(box.owner)
		}
		ownerState.count++
		messageBoxOwners[box.owner] = ownerState
		messageBoxMu.Unlock()
	}
	activeMessageBox := func(cpu arch.CPU) *messageBoxRuntime {
		messageBoxMu.Lock()
		defer messageBoxMu.Unlock()
		stack := messageBoxStacks[cpu]
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	popMessageBox := func(cpu arch.CPU, box *messageBoxRuntime) bool {
		messageBoxMu.Lock()
		defer messageBoxMu.Unlock()
		stack := messageBoxStacks[cpu]
		if len(stack) == 0 || stack[len(stack)-1] != box {
			return false
		}
		stack = stack[:len(stack)-1]
		if len(stack) == 0 {
			delete(messageBoxStacks, cpu)
		} else {
			messageBoxStacks[cpu] = stack
		}
		delete(messageBoxesByHWND, box.hwnd)
		ownerState := messageBoxOwners[box.owner]
		if ownerState.count > 0 {
			ownerState.count--
		}
		if ownerState.count == 0 {
			delete(messageBoxOwners, box.owner)
			if !ownerState.wasDisabled {
				return true
			}
		} else {
			messageBoxOwners[box.owner] = ownerState
		}
		return false
	}
	messageBoxForHWND := func(hwnd uint64) *messageBoxRuntime {
		messageBoxMu.Lock()
		defer messageBoxMu.Unlock()
		return messageBoxesByHWND[hwnd]
	}
	messageBoxIsActive := func(box *messageBoxRuntime) bool {
		messageBoxMu.Lock()
		defer messageBoxMu.Unlock()
		for _, stack := range messageBoxStacks {
			if len(stack) != 0 && stack[len(stack)-1] == box {
				return true
			}
		}
		return false
	}
	messageBoxInputWindows := func() []*wl.Window {
		messageBoxMu.Lock()
		defer messageBoxMu.Unlock()
		windows := make([]*wl.Window, 0, len(messageBoxesByHWND)*2)
		seen := make(map[*wl.Window]bool, len(messageBoxesByHWND)*2)
		for _, box := range messageBoxesByHWND {
			for _, hwnd := range []uint64{box.hwnd, box.owner} {
				window := hctx.WlWindows[hwnd]
				if hwnd == hctx.MainHWND {
					window = wlWindow
				}
				if window != nil && !seen[window] {
					seen[window] = true
					windows = append(windows, window)
				}
			}
		}
		return windows
	}
	finishMessageBoxCall := func(ctx *ntapi.TrapContext, box *messageBoxRuntime) bool {
		syncStack := hctx.syncStack(ctx)
		if box.syncDepth <= len(*syncStack) {
			*syncStack = (*syncStack)[:box.syncDepth]
		} else {
			*syncStack = (*syncStack)[:0]
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return false
		}
		restoreGuestNonvolatileRegisters(rw, box.callee)
		if ctx.State != nil && ctx.State.Is32 {
			rsp := box.retRSP - 4
			mem.Write32(rsp, uint32(box.retAddr))
			rw.WriteReg(4, rsp)
		} else {
			rsp := box.retRSP - 8
			mem.Write64(rsp, box.retAddr)
			rw.WriteReg(4, rsp)
		}
		ctx.SetReturn(box.result)
		retOffset := uint64(19)
		if ctx.State != nil && ctx.State.Is32 {
			retOffset = 13
		}
		ctx.CPU.SetPC(hctx.SyncTrampoline + retOffset)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return true
	}

	// loadDlgTemplate tries to read a DLGTEMPLATE from the process's .rsrc
	// section for the given template specifier (integer ID or name string).
	// hInstance (0 = use main module) selects which module to search first;
	// falls back to the main module if the resource is not found there.
	// Returns nil if the resource cannot be found or parsed.
	loadDlgTemplate := func(hInstance, lpTemplate uint64) *dlgInfo {
		if hctx.PeLoadRawResource == nil {
			return nil
		}
		var resID uint32
		if lpTemplate < 0x10000 {
			resID = uint32(lpTemplate)
		}
		if resID == 0 {
			return nil // named templates not supported yet
		}
		// Try the specified module first (e.g. a dynamically loaded DLL).
		if hInstance != 0 {
			if resRVA := hctx.moduleResourceRVA(hInstance); resRVA != 0 {
				if dataAddr, dataSize, ok3 := hctx.PeLoadRawResource(hInstance, resRVA, 5 /*RT_DIALOG*/, resID); ok3 && dataAddr != 0 && dataSize != 0 {
					if raw, err := mem.ReadBytes(dataAddr, int(dataSize)); err == nil && len(raw) > 0 {
						if info, err2 := parseDLGTEMPLATE(raw); err2 == nil {
							return info
						} else {
							ravelog.Logf("[dialog] parseDLGTEMPLATE (vfs module 0x%x) error: %v\n", hInstance, err2)
						}
					}
				}
			}
		}
		// Fall back to main module.
		if mainModule == nil {
			return nil
		}
		dataAddr, dataSize, ok := hctx.PeLoadRawResource(
			mainModule.BaseAddr, mainModule.ResourceDirRVA,
			5 /*RT_DIALOG*/, resID)
		if !ok || dataAddr == 0 || dataSize == 0 {
			return nil
		}
		raw, err := mem.ReadBytes(dataAddr, int(dataSize))
		if err != nil || len(raw) == 0 {
			return nil
		}
		info, err := parseDLGTEMPLATE(raw)
		if err != nil {
			ravelog.Logf("[dialog] parseDLGTEMPLATE error: %v\n", err)
			return nil
		}
		return info
	}

	applyDialogBounds := func(state *controlState, parent uint64, info *dlgInfo) {
		x := int32(info.x) * 2
		y := int32(info.y) * 2
		if parentState := hwndChildren[parent]; parentState != nil {
			x += parentState.x
			y += parentState.y
		}
		state.mutateGeometry(func(geometry *controlGeometry) {
			geometry.x = x
			geometry.y = y
			geometry.w = int32(info.cx) * 2
			geometry.h = int32(info.cy) * 2
		})
	}

	registerDialogState := func(hwnd uint64, state *controlState) {
		hwndChildren[hwnd] = state
		windowLongPtr[hwnd] = map[int32]uint64{
			-16: uint64(state.style),
			-20: uint64(state.exStyle),
		}
		win32.Global.Create(hwnd, state.className, state.x, state.y, state.w, state.h, state.style, state.exStyle, state.parentHWND)
		if state.style&win32.WS_CHILD != 0 {
			hctx.placeNewChildAtBottom(hwnd)
		}
	}

	// createDlgControls instantiates child controlState entries for every item
	// described in info.  The dialog HWND itself must already exist in hwndChildren.
	createDlgControls := func(dlgHwnd uint64, info *dlgInfo) {
		ravelog.Logf("[dialog] createDlgControls dlg=0x%x title=%q items=%d\n", dlgHwnd, info.title, len(info.items))
		dialogX, dialogY := int32(0), int32(0)
		if dialogState := hwndChildren[dlgHwnd]; dialogState != nil {
			dialogX, dialogY = dialogState.x, dialogState.y
		}
		for _, item := range info.items {
			px, py, pcx, pcy := dlgUnitsToPixels(item.x, item.y, item.cx, item.cy)
			px += dialogX
			py += dialogY
			ravelog.Logf("[dialog]   item class=%q id=%d title=%q style=0x%x at(%d,%d %dx%d)\n", item.class, item.id, item.title, item.style, px, py, pcx, pcy)
			child := hwndAlloc()
			hwndChildren[child] = &controlState{
				className:  strings.ToLower(item.class),
				parentHWND: dlgHwnd,
				ctrlID:     uint64(item.id),
				x:          px,
				y:          py,
				w:          pcx,
				h:          pcy,
				style:      item.style,
				exStyle:    item.extStyle,
				text:       item.title,
				visible:    item.style&wsVisible != 0,
			}
			windowLongPtr[child] = map[int32]uint64{
				-16: uint64(item.style),
				-20: uint64(item.extStyle),
			}
			win32.Global.Create(child, strings.ToLower(item.class), px, py, pcx, pcy, item.style, item.extStyle, dlgHwnd)
			hctx.placeNewChildAtBottom(child)
			if item.title != "" {
				hwndTitle[child] = item.title
			}
		}
	}

	// dispatchWmInitDialog sets up a syncDispatch trampoline call to
	// dlgProc(dlgHwnd, WM_INITDIALOG, 0, dwInitParam).
	// isModal controls whether the syncTrampoline redirects to the message loop
	// afterwards (true) or returns immediately (false).
	dispatchWmInitDialog := func(ctx *ntapi.TrapContext, dlgHwnd, lpDialogFunc, dwInitParam uint64, isModal bool) bool {
		rr, ok := ctx.CPU.(ntapi.RegisterReader)
		if !ok {
			return false
		}
		rsp := rr.ReadReg(4)
		var retAddr uint64
		if ctx.State != nil && ctx.State.Is32 {
			v, _ := mem.Read32(rsp)
			retAddr = uint64(v)
		} else {
			retAddr, _ = mem.Read64(rsp)
		}
		syncStack := hctx.syncStack(ctx)
		frame := syncDispatchFrame{
			queue:               nil,
			retAddr:             retAddr,
			hwnd:                2, // IDCANCEL (fallback if modal redirect is unavailable)
			returnWndProcResult: false,
			IsModalDialog:       isModal,
			ModalDlgHwnd:        dlgHwnd,
		}
		if isModal {
			var dialogRSP uint64
			if entry, ok := modalDialogs.top(ctx.CPU); ok {
				dialogRSP = entry.pumpSP
			}
			frame.ModalLoopSP, frame.ModalLoopPC = modalDialogLoopTarget(
				dialogRSP,
				hctx.ModalPumpTrampoline,
				msgLoopSP,
				msgLoopPC,
			)
		}
		*syncStack = append(*syncStack, frame)
		// SyncCallWndProc handles PE32 vs PE64 stack/register setup internally.
		hctx.SyncCallWndProc(ctx, lpDialogFunc, dlgHwnd, 0x0110, 0, dwInitParam, hctx.SyncTrampoline)
		return true
	}

	// modalPumpTrampoline: synthetic message pump for modal dialogs that are
	// opened before GetMessageA/W (e.g. installer wizards in WinMain).
	// After WM_INITDIALOG returns, syncDispatchTrampoline redirects here instead
	// of returning immediately.  This handler pumps Wayland events and
	// dispatches queued messages to the active modal dialog proc.
	// Each invocation dispatches at most one message, then the RET at the end
	// of the stub re-enters this handler (via msgLoopPC pointing here).
	// modalPumpLoopBack re-arms the modal pump loop: it writes the trampoline
	// address back at [msgLoopSP-4] and adjusts ESP so the final RET in the
	// stub lands on the trampoline again rather than consuming stack garbage.
	// Must be called whenever the handler returns without dispatching a message.
	modalPumpLoopBack := func(ctx *ntapi.TrapContext) {
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return
		}
		loopSP, loopPC := msgLoopSP, msgLoopPC
		if box := activeMessageBox(ctx.CPU); box != nil {
			loopSP = box.pumpSP
			loopPC = hctx.ModalPumpTrampoline
		} else {
			var dialogRSP uint64
			if entry, ok := modalDialogs.top(ctx.CPU); ok {
				dialogRSP = entry.pumpSP
			}
			loopSP, loopPC = modalDialogLoopTarget(
				dialogRSP,
				hctx.ModalPumpTrampoline,
				loopSP,
				loopPC,
			)
		}
		if loopSP == 0 || loopPC == 0 {
			return
		}
		pe32 := ctx.State != nil && ctx.State.Is32
		if pe32 {
			rsp := loopSP - 4
			mem.Write32(rsp, uint32(loopPC))
			rw.WriteReg(4, rsp)
		} else {
			rsp := loopSP - 8
			mem.Write64(rsp, loopPC)
			rw.WriteReg(4, rsp)
		}
	}

	setMessageBoxResult := func(box *messageBoxRuntime, result uint64) {
		if box == nil || box.result != 0 || result == 0 {
			return
		}
		box.result = result
		ravelog.Logf("[messagebox] selected hwnd=0x%x result=%d\n", box.hwnd, result)
	}
	dispatchMessageBoxEvent := func(box *messageBoxRuntime, evt wl.EventType) bool {
		boxWindow := hctx.WlWindows[box.hwnd]
		ownerWindow := hctx.WlWindows[box.owner]
		if box.owner == hctx.MainHWND {
			ownerWindow = wlWindow
		}
		switch evt {
		case wl.EventClose:
			target := hwndForWaylandWindow(wlDisplay.LastEventWindow())
			if targetBox := messageBoxForHWND(target); targetBox != nil && messageBoxIsActive(targetBox) {
				setMessageBoxResult(targetBox, targetBox.escapeID)
			} else if targetBox != nil {
				return true
			} else if target != box.owner {
				return false
			}
		case wl.EventConfigure:
			win := wlDisplay.LastEventWindow()
			target := hwndForWaylandWindow(win)
			if targetBox := messageBoxForHWND(target); targetBox != nil && win != nil {
				win.ResizeIfNeeded()
				renderOwnedDialog(hctx, targetBox.hwnd, hctx.windowCPU(targetBox.hwnd), win)
			} else {
				return false
			}
		case wl.EventKey:
			for {
				event, ok := wlDisplay.PollKeyForWindows(boxWindow, ownerWindow)
				if !ok {
					break
				}
				if !event.Pressed || hwndForWaylandWindow(event.Window) != box.hwnd {
					continue
				}
				switch event.VK {
				case 0x0d:
					setMessageBoxResult(box, box.defaultID)
				case 0x1b:
					setMessageBoxResult(box, box.escapeID)
				}
			}
		case wl.EventMouse:
			for {
				event, ok := wlDisplay.PollMouseForWindows(boxWindow, ownerWindow)
				if !ok {
					break
				}
				if !event.Pressed || event.Button != 272 || hwndForWaylandWindow(event.Window) != box.hwnd {
					continue
				}
				setMessageBoxResult(box, messageBoxButtonAt(hwndChildren, box.hwnd, event.X, event.Y))
			}
		}
		return true
	}
	dispatchUnblockedMessageBoxInput := func() {
		if wlDisplay == nil || dispatchWl == nil || !wlDisplay.HasPendingInput() {
			return
		}
		protected := messageBoxInputWindows()
		wlDisplay.WithInputForWindowsSuspended(protected, func() {
			dispatchWl(wl.EventMouse)
			dispatchWl(wl.EventKey)
		})
	}
	pumpMessageBoxEvent := func(box *messageBoxRuntime, block bool) {
		if wlDisplay == nil {
			return
		}
		boxWindow := hctx.WlWindows[box.hwnd]
		ownerWindow := hctx.WlWindows[box.owner]
		if box.owner == hctx.MainHWND {
			ownerWindow = wlWindow
		}
		if wlDisplay.HasPendingInputForWindows(boxWindow, ownerWindow) {
			dispatchMessageBoxEvent(box, wl.EventMouse)
			dispatchMessageBoxEvent(box, wl.EventKey)
			dispatchUnblockedMessageBoxInput()
			return
		}
		event, _ := wlDisplay.Poll()
		if event != wl.EventNone {
			if !dispatchMessageBoxEvent(box, event) && dispatchWl != nil {
				dispatchWl(event)
			}
			dispatchUnblockedMessageBoxInput()
			return
		}
		if !block {
			return
		}
		fd := wlDisplay.Fd()
		var readFDs unix.FdSet
		readFDs.Set(fd)
		timeout := unix.Timeval{Usec: 16000}
		ready, _ := unix.Select(fd+1, &readFDs, nil, nil, &timeout)
		if ready <= 0 {
			return
		}
		event, _ = wlDisplay.Dispatch()
		if !dispatchMessageBoxEvent(box, event) && dispatchWl != nil {
			dispatchWl(event)
		}
		dispatchUnblockedMessageBoxInput()
	}

	d.RegisterHandler(modalPumpTrampolineID, "modalPumpTrampoline", func(ctx *ntapi.TrapContext) uint32 {
		loopSP, loopPC := msgLoopSP, msgLoopPC
		if box := activeMessageBox(ctx.CPU); box != nil {
			loopSP = box.pumpSP
			loopPC = hctx.ModalPumpTrampoline
		} else if entry, ok := modalDialogs.top(ctx.CPU); ok {
			loopSP, loopPC = modalDialogLoopTarget(
				entry.pumpSP,
				hctx.ModalPumpTrampoline,
				loopSP,
				loopPC,
			)
		}
		if pump := sentMessageLoopPump(loopSP, loopPC, ctx.State != nil && ctx.State.Is32); pump != nil {
			if dispatchPendingSentMessage(ctx, pump) {
				return 0
			}
		}
		if box := activeMessageBox(ctx.CPU); box != nil {
			messageBoxPumpMu.Lock()
			defer messageBoxPumpMu.Unlock()
			pumpMessageBoxEvent(box, false)
			if box.result == 0 {
				checkTimers(ctx.CPU)
				message, ok := hctx.MsgQueue.take(ctx.CPU, func(message queuedMsg) bool {
					proc := hwndWndProc[message.hwnd]
					return proc != 0 && message.hwnd != box.hwnd
				})
				if ok {
					proc := hwndWndProc[message.hwnd]
					syncStack := hctx.syncStack(ctx)
					*syncStack = append(*syncStack, syncDispatchFrame{
						hwnd:          message.hwnd,
						IsModalDialog: true,
						ModalDlgHwnd:  box.hwnd,
						ModalLoopSP:   box.pumpSP,
						ModalLoopPC:   hctx.ModalPumpTrampoline,
					})
					hctx.SyncCallWndProc(ctx, proc, message.hwnd, uint32(message.message), message.wParam, message.lParam, hctx.SyncTrampoline)
					return 0
				}
				pumpMessageBoxEvent(box, true)
			}
			if box.result == 0 {
				modalPumpLoopBack(ctx)
				return 0
			}

			result := box.result
			destroyOwnedDialogWindowForCPU(box.hwnd, ctx.CPU)
			cleanupWindowState(box.hwnd)
			if popMessageBox(ctx.CPU, box) {
				_, _ = updateWindowEnabled(box.owner, true, true)
			}
			hctx.FocusHwnd = box.previousFocus
			hctx.ActiveHwnd = box.owner
			if finishMessageBoxCall(ctx, box) {
				ravelog.Logf("[messagebox] closed hwnd=0x%x result=%d\n", box.hwnd, result)
				return 0
			}
			ctx.SetReturn(result)
			return 0
		}
		entry, ok := modalDialogs.top(ctx.CPU)
		if !ok {
			modalPumpLoopBack(ctx)
			return 0
		}
		if entry.ended && finishModalDialog(ctx, entry.hwnd) {
			return 0
		}
		dialogProc := hwndWndProc[entry.hwnd]

		// Pump Wayland events into the message queue.
		if wlDisplay != nil {
			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone && dispatchWl != nil {
				dispatchWl(evt)
			}
			if wlDisplay.HasPendingInput() && dispatchWl != nil {
				dispatchWl(wl.EventMouse)
				dispatchWl(wl.EventKey)
			}
		}

		// Check expired timers.
		checkTimers(ctx.CPU)

		// Dispatch the first queued message.
		if m, ok := hctx.MsgQueue.take(ctx.CPU, nil); ok {
			if isDisabledInput(m.hwnd, m.message, entry.hwnd) {
				modalPumpLoopBack(ctx)
				return 0
			}
			proc := modalMessageWndProc(entry.hwnd, dialogProc, m.hwnd, hwndWndProc)
			if proc == 0 {
				modalPumpLoopBack(ctx)
				return 0
			}
			traceModalObject("dispatch", entry, m.hwnd, m.message)
			if m.message == 0x000F {
				// For WM_PAINT of the dialog window: do a Go-side background fill
				// + paintTree before calling the dialog proc. This mirrors what
				// DefDlgProc does and ensures the dialog renders even when the
				// dialog proc returns FALSE (not handled).
				if wlWindow != nil {
					if cs, ok := hwndChildren[m.hwnd]; ok {
						bgColor := hctx.SysColors[5]
						if a, ok2 := hctx.HwndClassAtom[m.hwnd]; ok2 {
							if brushIdx, ok3 := hctx.ClassBrush[a]; ok3 && brushIdx > 0 && int(brushIdx-1) < len(hctx.SysColors) {
								bgColor = hctx.SysColors[brushIdx-1]
							}
						}
						wlWindow.DrawRectAbs(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h, bgColor)
					}
					paintTree(m.hwnd)
					hctx.WinInvalid[m.hwnd] = false
					delete(hctx.WinErasePending, m.hwnd)
					win32.Global.Validate(m.hwnd)
					hctx.HasBaseFrame = true
					hctx.FrameReady = true
					hctx.CommitIfDone()
					if wlDisplay == nil {
						// Headless runs cannot interact with modal controls. Prefer
						// "No" over "OK" so unattended installers do not retry.
						const wmCommand = 0x0111
						var pickHWND uint64
						var pickCtrlID uint64
						var pickTitle string
						foundNo := false
						for btnHWND, ch := range hwndChildren {
							if ch.parentHWND != m.hwnd || !strings.EqualFold(ch.className, "button") || !ch.visible {
								continue
							}
							isNo := strings.EqualFold(ch.text, "no") || strings.EqualFold(ch.text, "&no")
							if isNo && !foundNo {
								pickHWND, pickCtrlID, pickTitle = btnHWND, ch.ctrlID, ch.text
								foundNo = true
							} else if pickCtrlID == 0 {
								pickHWND, pickCtrlID, pickTitle = btnHWND, ch.ctrlID, ch.text
							}
						}
						if pickCtrlID != 0 {
							wParam := pickCtrlID & 0xFFFF
							ravelog.Logf("[dialog] auto-dismiss: WM_COMMAND ctrlID=%d title=%q hwnd=0x%x\n", pickCtrlID, pickTitle, m.hwnd)
							hctx.enqueueMessage(nil, newQueuedMsg(hctx, m.hwnd, wmCommand, wParam, pickHWND))
						}
					}
				}
			}
			// Push a modal SyncStack frame so syncDispatchTrampoline can
			// redirect back to the modal pump when the WndProc returns.
			syncStack := hctx.syncStack(ctx)
			*syncStack = append(*syncStack, syncDispatchFrame{
				queue:               nil,
				retAddr:             0,
				hwnd:                m.hwnd,
				returnWndProcResult: false,
				IsModalDialog:       true,
				ModalDlgHwnd:        entry.hwnd,
				ModalLoopSP:         entry.pumpSP,
				ModalLoopPC:         hctx.ModalPumpTrampoline,
			})
			hctx.SyncCallWndProc(ctx, proc, m.hwnd, uint32(m.message), m.wParam, m.lParam, hctx.SyncTrampoline)
			return 0
		}

		// No message ready: block briefly on Wayland fd (up to 16ms) to avoid
		// burning CPU while the user hasn't interacted yet.
		if wlDisplay != nil {
			wlFd := wlDisplay.Fd()
			var rfds unix.FdSet
			rfds.Set(wlFd)
			tv := unix.Timeval{Usec: 16000}
			n, _ := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
			if n > 0 {
				evt2, _ := wlDisplay.Dispatch()
				if dispatchWl != nil {
					dispatchWl(evt2)
				}
			}

			// Post a synthetic WM_PAINT to keep the dialog redrawn.
			if hctx.WinInvalid[entry.hwnd] {
				queuePaint(entry.hwnd)
			} else if hctx.WinInvalid[hctx.MainHWND] {
				queuePaint(hctx.MainHWND)
			}
		} else {
			// Headless: yield briefly to avoid spinning at 100% CPU.
			time.Sleep(16 * time.Millisecond)
		}

		// Re-arm the loop: write the trampoline address so the final RET
		// in the stub jumps back here instead of consuming stack garbage.
		modalPumpLoopBack(ctx)
		return 0
	})

	// Loads and parses the DLGTEMPLATE resource, creates child controls, sends
	// WM_INITDIALOG, then enters a modal message loop through SyncStack. EndDialog
	// marks the dialog complete; the callback trampoline finishes DialogBox after
	// the dialog procedure returns.
	d.RegisterAutoStubHandler(user32, "DialogBoxParamW", func(ctx *ntapi.TrapContext) uint32 {
		hInstance := ctx.Arg(0)
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)

		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestUTF16(lpTemplate)
		}
		ravelog.Logf("[dialog] DialogBoxParamW template=%s parent=0x%x dlgProc=0x%x initParam=0x%x\n",
			templateName, hWndParent, lpDialogFunc, dwInitParam)

		if lpDialogFunc == 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}

		// Allocate the dialog HWND
		dlgHwnd := hwndAlloc()
		hctx.setWindowCPU(dlgHwnd, ctx.CPU)
		cs := &controlState{
			className:  "dialog",
			parentHWND: hWndParent,
			visible:    true,
		}

		// Load and parse the DLGTEMPLATE resource
		if info := loadDlgTemplate(hInstance, lpTemplate); info != nil {
			applyDialogBounds(cs, hWndParent, info)
			cs.text = info.title
			cs.style = info.style
			cs.exStyle = info.extStyle
			cs.visible = dialogVisible(info, true)
			if info.title != "" {
				hwndTitle[dlgHwnd] = info.title
			}
			registerDialogState(dlgHwnd, cs)
			createDlgControls(dlgHwnd, info)
		} else {
			registerDialogState(dlgHwnd, cs)
		}
		hwndWndProc[dlgHwnd] = lpDialogFunc

		// Save call-site state so DialogBox can return after EndDialog completes.
		// For PE32 stdcall(5 args): retRSP = rsp + 4(retAddr) + 20(5 args) = rsp+24.
		// For PE64: retRSP = rsp + 8 (no args on stack after Microsoft ABI).
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okR {
			rsp := rr.ReadReg(4)
			var retAddr uint64
			var retRSP uint64
			is32 := ctx.State != nil && ctx.State.Is32
			if is32 {
				v, _ := mem.Read32(rsp)
				retAddr = uint64(v)
				retRSP = rsp + 24 // 4 (retAddr) + 5*4 (stdcall args)
			} else {
				retAddr, _ = mem.Read64(rsp)
				retRSP = rsp + 8
			}
			syncStack := hctx.syncStack(ctx)
			entry := modalDlgEntry{
				hwnd:           dlgHwnd,
				retAddr:        retAddr,
				retRSP:         retRSP,
				pumpSP:         modalPumpEntrySP(rsp, is32),
				callee:         captureGuestNonvolatileRegisters(rr, is32),
				syncDepth:      len(*syncStack),
				parent:         hWndParent,
				previousFocus:  hctx.FocusHwnd,
				previousActive: hctx.ActiveHwnd,
			}
			disableModalOwner(hWndParent)
			modalDialogs.push(ctx.CPU, entry)
			hctx.FocusHwnd = dlgHwnd
			hctx.ActiveHwnd = dlgHwnd
			traceModalObject("created", entry, dlgHwnd, 0x0110)
			// If no GetMessageA/W loop exists yet, establish the modal pump
			// as the message loop so syncDispatchTrampoline can redirect there.
			if msgLoopSP == 0 && hctx.ModalPumpTrampoline != 0 {
				msgLoopSP = modalPumpEntrySP(rsp, is32)
				msgLoopPC = hctx.ModalPumpTrampoline
			}
		}

		// Dispatch WM_INITDIALOG; syncTrampoline will redirect to message loop
		if dispatchWmInitDialog(ctx, dlgHwnd, lpDialogFunc, dwInitParam, true) {
			return 0
		}

		// Fallback: DialogBox reports creation failure as -1.
		ctx.SetReturn(^uint64(0))
		return 0
	})

	readIndirectDialogTemplate := func(pTemplate uint64) (*dlgInfo, error) {
		const maxTemplateSize = 65536
		raw := make([]byte, 0, 4096)
		for len(raw) < maxTemplateSize {
			address := pTemplate + uint64(len(raw))
			chunkSize := int(mmu.PageSize - (address & (mmu.PageSize - 1)))
			if remaining := maxTemplateSize - len(raw); chunkSize > remaining {
				chunkSize = remaining
			}
			chunk, err := mem.ReadBytes(address, chunkSize)
			if err != nil {
				if len(raw) == 0 {
					return nil, err
				}
				break
			}
			raw = append(raw, chunk...)
			if info, parseErr := parseDLGTEMPLATE(raw); parseErr == nil {
				return info, nil
			}
		}
		return parseDLGTEMPLATE(raw)
	}
	dialogBoxIndirectParam := func(ctx *ntapi.TrapContext, apiName string) uint32 {
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)
		pTemplate := ctx.Arg(1)

		if pTemplate == 0 || lpDialogFunc == 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}

		// DLGTEMPLATE uses UTF-16 fields for both the A and W entry points.
		info, err := readIndirectDialogTemplate(pTemplate)
		if err != nil {
			ravelog.Logf("[dialog] %s template parse failed: %v\n", apiName, err)
			ctx.SetReturn(^uint64(0))
			return 0
		}

		dlgHwnd := hwndAlloc()
		hctx.setWindowCPU(dlgHwnd, ctx.CPU)
		cs := &controlState{
			className:  "dialog",
			parentHWND: hWndParent,
			visible:    true,
		}
		applyDialogBounds(cs, hWndParent, info)
		cs.text = info.title
		cs.style = info.style
		cs.exStyle = info.extStyle
		cs.visible = dialogVisible(info, true)
		if info.title != "" {
			hwndTitle[dlgHwnd] = info.title
		}
		registerDialogState(dlgHwnd, cs)
		createDlgControls(dlgHwnd, info)
		hwndWndProc[dlgHwnd] = lpDialogFunc
		queuePaint(dlgHwnd)

		rr, ok := ctx.CPU.(ntapi.RegisterReader)
		if !ok {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		rsp := rr.ReadReg(4)
		var retAddr uint64
		var retRSP uint64
		is32 := ctx.State != nil && ctx.State.Is32
		if is32 {
			value, _ := mem.Read32(rsp)
			retAddr = uint64(value)
			retRSP = rsp + 24
		} else {
			retAddr, _ = mem.Read64(rsp)
			retRSP = rsp + 8
		}
		syncStack := hctx.syncStack(ctx)
		entry := modalDlgEntry{
			hwnd:           dlgHwnd,
			retAddr:        retAddr,
			retRSP:         retRSP,
			pumpSP:         modalPumpEntrySP(rsp, is32),
			callee:         captureGuestNonvolatileRegisters(rr, is32),
			syncDepth:      len(*syncStack),
			parent:         hWndParent,
			previousFocus:  hctx.FocusHwnd,
			previousActive: hctx.ActiveHwnd,
		}
		disableModalOwner(hWndParent)
		modalDialogs.push(ctx.CPU, entry)
		hctx.FocusHwnd = dlgHwnd
		hctx.ActiveHwnd = dlgHwnd
		traceModalObject("created", entry, dlgHwnd, 0x0110)
		if msgLoopSP == 0 && hctx.ModalPumpTrampoline != 0 {
			msgLoopSP = modalPumpEntrySP(rsp, is32)
			msgLoopPC = hctx.ModalPumpTrampoline
		}
		ravelog.Logf("[dialog] %s -> hwnd=0x%x\n", apiName, dlgHwnd)
		if dispatchWmInitDialog(ctx, dlgHwnd, lpDialogFunc, dwInitParam, true) {
			return 0
		}
		ctx.SetReturn(^uint64(0))
		return 0
	}
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
		return dialogBoxIndirectParam(ctx, "DialogBoxIndirectParamW")
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamA", func(ctx *ntapi.TrapContext) uint32 {
		return dialogBoxIndirectParam(ctx, "DialogBoxIndirectParamA")
	})

	d.RegisterAutoStubHandler(user32, "CreateDialogParamW", func(ctx *ntapi.TrapContext) uint32 {
		// HWND CreateDialogParamW(hInstance, lpTemplate, hWndParent, lpDialogFunc, dwInitParam)
		// Modeless dialog: create controls, send WM_INITDIALOG, return HWND immediately.
		hInstance := ctx.Arg(0)
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)

		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestUTF16(lpTemplate)
		}

		dlgHwnd := hwndAlloc()
		hctx.setWindowCPU(dlgHwnd, ctx.CPU)
		cs := &controlState{
			className:  "dialog",
			parentHWND: hWndParent,
			visible:    true,
		}

		if info := loadDlgTemplate(hInstance, lpTemplate); info != nil {
			applyDialogBounds(cs, hWndParent, info)
			cs.text = info.title
			cs.style = info.style
			cs.exStyle = info.extStyle
			cs.visible = dialogVisible(info, false)
			if info.title != "" {
				hwndTitle[dlgHwnd] = info.title
			}
			registerDialogState(dlgHwnd, cs)
			createDlgControls(dlgHwnd, info)
		} else {
			registerDialogState(dlgHwnd, cs)
		}
		if lpDialogFunc != 0 {
			hwndWndProc[dlgHwnd] = lpDialogFunc
		}

		ravelog.Logf("[dialog] CreateDialogParamW template=%s parent=0x%x dlgProc=0x%x -> hwnd=0x%x\n",
			templateName, hWndParent, lpDialogFunc, dlgHwnd)

		// Send WM_INITDIALOG for modeless dialog (not modal - return HWND immediately after)
		if lpDialogFunc != 0 {
			dispatchWmInitDialog(ctx, dlgHwnd, lpDialogFunc, dwInitParam, false)
			// dispatchWmInitDialog sets ReturnOverridden; set return value to dlgHwnd
			// via the syncStack frame's hwnd field (it gets returned after WM_INITDIALOG)
			syncStack := hctx.syncStack(ctx)
			if len(*syncStack) > 0 {
				(*syncStack)[len(*syncStack)-1].hwnd = dlgHwnd
			}
			return 0
		}
		ctx.SetReturn(dlgHwnd)
		return 0
	})

	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamW", func(ctx *ntapi.TrapContext) uint32 {
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)
		pTemplate := ctx.Arg(1)

		dlgHwnd := hwndAlloc()
		hctx.setWindowCPU(dlgHwnd, ctx.CPU)
		cs := &controlState{
			className:  "dialog",
			parentHWND: hWndParent,
			visible:    true,
		}
		registerDialogState(dlgHwnd, cs)

		if pTemplate != 0 {
			raw, err := mem.ReadBytes(pTemplate, 65536)
			if err == nil {
				if info, err2 := parseDLGTEMPLATE(raw); err2 == nil {
					applyDialogBounds(cs, hWndParent, info)
					cs.text = info.title
					cs.style = info.style
					cs.exStyle = info.extStyle
					cs.visible = dialogVisible(info, false)
					if info.title != "" {
						hwndTitle[dlgHwnd] = info.title
					}
					createDlgControls(dlgHwnd, info)
				}
			}
		}
		if lpDialogFunc != 0 {
			hwndWndProc[dlgHwnd] = lpDialogFunc
			dispatchWmInitDialog(ctx, dlgHwnd, lpDialogFunc, dwInitParam, false)
			syncStack := hctx.syncStack(ctx)
			if len(*syncStack) > 0 {
				(*syncStack)[len(*syncStack)-1].hwnd = dlgHwnd
			}
			return 0
		}
		ravelog.Logf("[dialog] CreateDialogIndirectParamW -> hwnd=0x%x\n", dlgHwnd)
		ctx.SetReturn(dlgHwnd)
		return 0
	})

	d.RegisterAutoStubHandler(user32, "EndDialog", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EndDialog(HWND hDlg, INT_PTR nResult)
		hDlg := ctx.Arg(0)
		nResult := ctx.Arg(1)
		ravelog.Logf("[dialog] EndDialog hwnd=0x%x result=%d\n", hDlg, nResult)
		if modalDialogs.markEnded(ctx.CPU, hDlg, nResult) {
			if cs, ok := hwndChildren[hDlg]; ok {
				cs.visible = false
			}
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItem", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		// Search child windows of hDlg for matching control ID
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgCtrlID", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(cs.ctrlID)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendDlgItemMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)
		// Find child HWND by control ID, then SendMessage to it
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				if result, handled := builtinWndProc(h, msg, wParam, lParam); handled {
					ctx.SetReturn(result)
					return 0
				}
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapDialogRect", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL MapDialogRect(HWND hDlg, LPRECT lpRect)
		// ReactOS: win32ss/user/user32/windows/dialog.c
		// Converts dialog units to pixels using font metrics
		// Default: 1 DLU horizontal = avg char width / 4
		//          1 DLU vertical = char height / 8
		// Using 8x16 as default system font metrics
		lpRect := ctx.Arg(1)
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			b, _ := mem.Read32(lpRect + 12)
			baseX := uint32(8)  // avg char width
			baseY := uint32(16) // char height
			mem.Write32(lpRect, l*baseX/4)
			mem.Write32(lpRect+4, t*baseY/8)
			mem.Write32(lpRect+8, r*baseX/4)
			mem.Write32(lpRect+12, b*baseY/8)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpString := ctx.Arg(2)
		nMaxCount := ctx.Arg(3)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				text := cs.text
				runes := []rune(text)
				maxChars := int(nMaxCount) - 1
				if maxChars < 0 {
					maxChars = 0
				}
				if len(runes) > maxChars {
					runes = runes[:maxChars]
				}
				for i, r := range runes {
					mem.Write16(lpString+uint64(i)*2, uint16(r))
				}
				mem.Write16(lpString+uint64(len(runes))*2, 0)
				ctx.SetReturn(uint64(len(runes)))
				_ = h
				return 0
			}
		}
		if lpString != 0 && nMaxCount > 0 {
			mem.Write16(lpString, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemTextW", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpString := ctx.Arg(2)
		text := readGuestUTF16(lpString)
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				cs.text = text
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		lpTranslated := ctx.Arg(2)
		bSigned := ctx.Arg(3) != 0
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				var n int64
				_, err := fmt.Sscan(cs.text, &n)
				ravelog.Logf("[dialog] GetDlgItemInt hwnd=0x%x id=%d text=%q value=%d valid=%v\n", hDlg, nID, cs.text, n, err == nil)
				if lpTranslated != 0 {
					if err == nil {
						mem.Write32(lpTranslated, 1)
					} else {
						mem.Write32(lpTranslated, 0)
					}
				}
				if bSigned {
					ctx.SetReturn(uint64(int32(n)))
				} else {
					ctx.SetReturn(uint64(uint32(n)))
				}
				return 0
			}
		}
		if lpTranslated != 0 {
			mem.Write32(lpTranslated, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemInt", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		val := ctx.Arg(2)
		bSigned := ctx.Arg(3) != 0
		var s string
		if bSigned {
			s = fmt.Sprintf("%d", int32(val))
		} else {
			s = fmt.Sprintf("%d", uint32(val))
		}
		for _, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				cs.text = s
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsDlgButtonChecked", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				_ = h
				ravelog.Logf("[dialog] IsDlgButtonChecked hwnd=0x%x id=%d state=%d\n", hDlg, nID, cs.checkState)
				ctx.SetReturn(uint64(cs.checkState))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckDlgButton", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nID := ctx.Arg(1)
		uCheck := uint32(ctx.Arg(2))
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nID {
				_ = h
				cs.checkState = uCheck
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckRadioButton", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDFirst := ctx.Arg(1)
		nIDLast := ctx.Arg(2)
		nIDCheck := ctx.Arg(3)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID >= nIDFirst && cs.ctrlID <= nIDLast {
				_ = h
				if cs.ctrlID == nIDCheck {
					cs.checkState = 1
				} else {
					cs.checkState = 0
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// Icons/cursors
	d.RegisterAutoStubHandler(user32, "DrawIconEx", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawIconEx(HDC, int x, int y, HICON, int cxWidth, int cyWidth, UINT istepAnim, HBRUSH flicker, UINT flags)
		// ReactOS: win32ss/user/ntuser/cursoricon.c NtUserDrawIconEx
		// We don't have full icon pixel data, but draw a small filled rect as placeholder.
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		cxWidth := int32(ctx.Arg(4))
		cyWidth := int32(ctx.Arg(5))
		if cxWidth == 0 {
			cxWidth = 32 // SM_CXICON default
		}
		if cyWidth == 0 {
			cyWidth = 32 // SM_CYICON default
		}
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			dc.Target.FillRect(x, y, x+cxWidth, y+cyWidth, 0x808080) // gray placeholder
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawIcon(HDC hDC, int X, int Y, HICON hIcon)
		// ReactOS: win32ss/user/ntuser/cursoricon.c - calls DrawIconEx internally
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(1))
		y := int32(ctx.Arg(2))
		// hIcon := ctx.Arg(3)
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			dc.Target.FillRect(x, y, x+32, y+32, 0x808080) // gray placeholder
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DestroyIcon(HICON hIcon)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		hIcon := ctx.Arg(0)
		ravelog.Logf("[user32] DestroyIcon hIcon=0x%x\n", hIcon)
		hctx.deleteIcon(hIcon)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DestroyCursor", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DestroyCursor(HCURSOR hCursor)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		hCursor := ctx.Arg(0)
		ravelog.Logf("[user32] DestroyCursor hCursor=0x%x\n", hCursor)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CopyIcon", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetIconInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ICONINFO: fIcon(BOOL 4), xHotspot(DWORD 4), yHotspot(DWORD 4), hbmMask(HBITMAP 8), hbmColor(HBITMAP 8)
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			mem.Write32(pInfo, 1)    // fIcon = TRUE
			mem.Write32(pInfo+4, 0)  // xHotspot
			mem.Write32(pInfo+8, 0)  // yHotspot
			mem.Write64(pInfo+16, 0) // hbmMask (NULL)
			mem.Write64(pInfo+24, 0) // hbmColor (NULL)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIconIndirect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x8001)
		return 0
	})
	// Misc UI
	d.RegisterAutoStubHandler(user32, "DrawStateW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DrawStateW(HDC hdc, HBRUSH hbrFore, DRAWSTATEPROC qfnCallBack,
		//   LPARAM lData, WPARAM wData, int x, int y, int cx, int cy, UINT uFlags)
		// ReactOS: win32ss/user/user32/windows/draw.c
		hdc := ctx.Arg(0)
		_ = hdc
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		ravelog.Logf("[user32] DrawStateW hdc=0x%x x=%d y=%d\n", hdc, x, y)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		color := uint32(0xD4D0C8)
		if idx >= 0 && idx < len(hctx.SysColors) {
			color = hctx.SysColors[idx]
		}
		ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "FrameRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(ctx.Arg(0))
		pRect := ctx.Arg(1)
		hbr := ctx.Arg(2)
		color := gdiMgr.BrushColor(hbr, hctx.SysColors)
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			dc.DrawBorder(int32(l), int32(t), int32(r), int32(b), color)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PaintDesktop", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL PaintDesktop(HDC hdc) - fills with desktop color (COLOR_DESKTOP)
		// ReactOS: win32ss/user/ntuser/painting.c
		hdc := ctx.Arg(0)
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil {
			desktopColor := uint32(0x004E6A) // default teal
			if len(hctx.SysColors) > 1 {
				desktopColor = hctx.SysColors[1] // COLOR_DESKTOP=1
			}
			dc.Target.FillRect(0, 0, dc.Target.Width, dc.Target.Height, desktopColor)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetSystemColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := int(ctx.Arg(0))
		color := uint32(0xD4D0C8)
		if idx >= 0 && idx < len(hctx.SysColors) {
			color = hctx.SysColors[idx]
		}
		ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pBuf := ctx.Arg(1)
		nMax := int(ctx.Arg(2))
		title := resolveWindowText(hwnd, hwndChildren, hwndTitle)
		if pBuf != 0 && nMax > 0 {
			runes := []rune(title)
			n := len(runes)
			if n >= nMax {
				n = nMax - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(runes[i]))
			}
			ctx.Mem.Write16(pBuf+uint64(n)*2, 0)
			ctx.SetReturn(uint64(n))
		} else {
			ctx.SetReturn(uint64(len([]rune(title))))
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "BeginPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPaint := ctx.Arg(1)
		normalizeOwnedStatusGeometry(hwnd)
		dirtyRect, dirty := win32.Global.GetUpdateRect(hwnd)
		if hwnd != 0 {
			hctx.WinInvalid[hwnd] = false
			win32.Global.Validate(hwnd)
		}
		ox, oy := clientAreaOrigin(hwnd)
		if cs, ok := hwndChildren[hwnd]; ok {
			ancestor := cs.parentHWND
			hiddenAncestor := false
			for ancestor != 0 {
				state := hwndChildren[ancestor]
				if state == nil {
					break
				}
				hiddenAncestor = hiddenAncestor || !state.visible
				ancestor = state.parentHWND
			}
			if hiddenAncestor {
				paintedThroughHiddenAncestor[hwnd] = true
			} else {
				delete(paintedThroughHiddenAncestor, hwnd)
			}
			ravelog.Logf("[paint] BeginPaint hwnd=0x%x class=%q x=%d y=%d w=%d h=%d\n", hwnd, cs.className, cs.x, cs.y, cs.w, cs.h)
		} else {
			ravelog.Logf("[paint] BeginPaint hwnd=0x%x (hctx.MainHWND)\n", hwnd)
		}
		ownedRoot, ownedTarget, owned := topLevelDialogTarget(hctx, hwnd)
		if owned && ownedTarget != nil {
			hctx.DialogSurfaceMu.Lock(ctx.CPU)
			ownedPaintCPUsMu.Lock()
			ownedPaintCPUs[hwnd] = append(ownedPaintCPUs[hwnd], ctx.CPU)
			ownedPaintCPUsMu.Unlock()
		}
		var hdc uint64
		var dc *gdi.DC
		if owned && ownedTarget != nil {
			if ownedTarget.ResizeIfNeeded() {
				repaintAfterSurfaceResize(hctx, ownedRoot, false, nil)
			}
			oldScreen := gdiMgr.Screen
			gdiMgr.Screen = gdi.WrapPix(ownedTarget.Pix, ownedTarget.Width, ownedTarget.Height+ownedTarget.TitleBarH, ownedTarget.Stride)
			if rootState := hwndChildren[ownedRoot]; rootState != nil {
				ox -= rootState.x
				oy -= rootState.y
			}
			hdc, dc = gdiMgr.AllocScreenDC()
			dc.Mgr = nil
			gdiMgr.Screen = oldScreen
		} else {
			if wlWindow != nil && wlWindow.ResizeIfNeeded() {
				repaintAfterSurfaceResize(hctx, hctx.MainHWND, true, nil)
			}
			syncScreenSurface()
			hdc, dc = allocScreenDC(ox, oy)
		}
		dc.OriginX = ox
		dc.OriginY = oy
		ravelog.Logf("[paint] BeginPaint hwnd=0x%x -> hdc=0x%x ox=%d oy=%d\n", hwnd, hdc, ox, oy)

		var rcLeft, rcTop, rcRight, rcBottom int32
		erase := hctx.WinErasePending[hwnd]
		delete(hctx.WinErasePending, hwnd)
		if dirty {
			rcLeft, rcTop, rcRight, rcBottom = dirtyRect.Left, dirtyRect.Top, dirtyRect.Right, dirtyRect.Bottom
		}

		if wlWindow != nil && hwnd == hctx.MainHWND {
			syncScreenSurface()
			w, h := wlWindow.Width, wlWindow.Height
			_ = h
			clientTop := wlWindow.TitleBarH

			// Ensure HasBaseFrame is set when any BeginPaint fires for the
			// main window.  Apps that handle WM_PAINT directly (WINMINE, etc.)
			// never invoke DefWindowProcW's WM_PAINT path, so HasBaseFrame
			// would never be set and EndPaint would never commit the frame.
			if !hctx.HasBaseFrame {
				hctx.HasBaseFrame = true
			}

			// Non-client area: draw menu bar (same filter/width as click-handler and drawMenuOverlay).
			if menuH, ok := hwndMenuBar[hwnd]; ok {
				if md, ok2 := menus[menuH]; ok2 && len(md.items) > 0 {
					clientTop = getMenuClientTop(hwnd)
					wlWindow.DrawRectAbs(0, wlWindow.TitleBarH, w, clientTop, hctx.SysColors[15])
					wlWindow.DrawRectAbs(0, clientTop-1, w, clientTop, hctx.SysColors[16])
					x := int32(4)
					for i, item := range md.items {
						if item.flags&0x0800 != 0 || item.flags&0x0010 == 0 {
							continue // separator or non-popup
						}
						label, _ := menuTextParts(menuStripAmpersand(item.text))
						if label == "" || label == "-" {
							continue
						}
						if !menuHasRenderableText(label) {
							continue
						}
						tw := menuTextWidth(label) + 12
						if hctx.OpenMenuIdx == i && hctx.OpenMenuHwnd == hwnd {
							wlWindow.DrawRectAbs(x, wlWindow.TitleBarH, x+tw, clientTop-1, hctx.SysColors[20])
							ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[20], true, 12)
						} else {
							ncDrawText(x+4, wlWindow.TitleBarH+3, label, 0x000000, hctx.SysColors[15], true, 12)
						}
						x += tw
					}
					if effectiveDarkModeForWindow(hwnd, hwndChildren) {
						remapWaylandRectForDarkMode(wlWindow, 0, wlWindow.TitleBarH, w, clientTop)
					}
					dispatchUAHMenuMessages(hctx, hwnd, menuH, nil)
				}
			}

			// Do NOT fill the full client area - child windows cover it entirely.
			// Filling here wipes Scintilla/children that painted first in the message queue.
			// ReactOS WM_ERASEBKGND only fills uncovered (non-child) regions.
			if rcRight <= rcLeft || rcBottom <= rcTop {
				rcLeft, rcTop = 0, 0
				rcRight, rcBottom = w, h
			}
			dc.SetClipRect(0, clientTop, w, h+wlWindow.TitleBarH)
		} else if cs, ok := hwndChildren[hwnd]; ok && wlWindow != nil {
			// Preserve an application-painted background unless invalidation asked
			// BeginPaint to erase the child with its class brush.
			bgColor := hctx.SysColors[5]
			darkScintilla := false
			if a, ok := hctx.HwndClassAtom[hwnd]; ok {
				if brushIdx, ok2 := hctx.ClassBrush[a]; ok2 && brushIdx > 0 && int(brushIdx-1) < len(hctx.SysColors) {
					bgColor = hctx.SysColors[brushIdx-1]
				}
			}
			if effectiveDarkModeForWindow(hwnd, hwndChildren) {
				if strings.EqualFold(cs.className, "scintilla") {
					bgColor = darkPalette.Background
					darkScintilla = true
				} else {
					bgColor = darkPalette.Control
				}
			}
			fillTarget := wlWindow
			fillX, fillY := cs.x, cs.y
			if owned && ownedTarget != nil {
				fillTarget = ownedTarget
				if rootState := hwndChildren[ownedRoot]; rootState != nil {
					fillX -= rootState.x
					fillY -= rootState.y
				}
			}
			if erase || darkScintilla {
				fillTarget.DrawRectAbs(fillX, fillY, fillX+cs.w, fillY+cs.h, bgColor)
			}
			// Always give child windows the full client rect as rcPaint.
			// Scintilla and other smart controls use rcPaint to determine what to redraw;
			// giving them a partial dirty rect (e.g. 14px for one cursor line) causes
			// them to only render a tiny strip instead of the full window.
			// GDI ops are already clipped to absoluteClientRect so over-reporting is safe.
			rcLeft, rcTop = 0, 0
			rcRight, rcBottom = cs.w, cs.h
			// Clip all GDI drawing to this child's client rect, including parent chain offset.
			x0, y0, x1, y1 := absoluteClientRect(hwnd)
			if owned {
				if rootState := hwndChildren[ownedRoot]; rootState != nil {
					x0 -= rootState.x
					y0 -= rootState.y
					x1 -= rootState.x
					y1 -= rootState.y
				}
			}
			dc.SetClipRect(x0, y0, x1, y1)
			// For Scintilla windows: record sciThis for diagnostics only.
			// Do NOT patch Scintilla internal state - offsets are version-specific
			// and writing wrong fields corrupts state (e.g. sets paintState=painting,
			// making SetPaintState return abandoned and skip all rendering).
		} else {
			rcRight, rcBottom = 800, 600
			if wlWindow != nil {
				rcRight, rcBottom = wlWindow.Width, wlWindow.Height
			}
		}

		if pPaint != 0 {
			// PE32 PAINTSTRUCT: hdc(4) fErase(4) rcPaint(16) ...
			// PE64 PAINTSTRUCT: hdc(8) fErase(4) rcPaint(16) ...
			is32 := ctx.State != nil && ctx.State.Is32
			eraseVal := uint32(0)
			if erase {
				eraseVal = 1
			}
			if is32 {
				ctx.Mem.Write32(pPaint, uint32(hdc))         // hdc (4 bytes)
				ctx.Mem.Write32(pPaint+4, eraseVal)          // fErase
				ctx.Mem.Write32(pPaint+8, uint32(rcLeft))    // rcPaint.left
				ctx.Mem.Write32(pPaint+12, uint32(rcTop))    // rcPaint.top
				ctx.Mem.Write32(pPaint+16, uint32(rcRight))  // rcPaint.right
				ctx.Mem.Write32(pPaint+20, uint32(rcBottom)) // rcPaint.bottom
			} else {
				ctx.Mem.Write64(pPaint, hdc)                 // hdc (8 bytes)
				ctx.Mem.Write32(pPaint+8, eraseVal)          // fErase
				ctx.Mem.Write32(pPaint+12, uint32(rcLeft))   // rcPaint.left
				ctx.Mem.Write32(pPaint+16, uint32(rcTop))    // rcPaint.top
				ctx.Mem.Write32(pPaint+20, uint32(rcRight))  // rcPaint.right
				ctx.Mem.Write32(pPaint+24, uint32(rcBottom)) // rcPaint.bottom
			}
		}
		ctx.SetReturn(hdc)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EndPaint", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[paint] EndPaint hwnd=0x%x\n", hwnd)
		var paintCPU arch.CPU
		paintLocked := false
		ownedPaintCPUsMu.Lock()
		if stack := ownedPaintCPUs[hwnd]; len(stack) != 0 {
			paintCPU = stack[len(stack)-1]
			paintLocked = true
			if len(stack) == 1 {
				delete(ownedPaintCPUs, hwnd)
			} else {
				ownedPaintCPUs[hwnd] = stack[:len(stack)-1]
			}
		}
		ownedPaintCPUsMu.Unlock()
		if paintLocked {
			defer hctx.DialogSurfaceMu.Unlock(paintCPU)
		}
		if root, target, owned := topLevelDialogTarget(hctx, hwnd); owned && target != nil {
			if !paintLocked {
				hctx.DialogSurfaceMu.Lock(ctx.CPU)
				defer hctx.DialogSurfaceMu.Unlock(ctx.CPU)
			}
			if state := hwndChildren[hwnd]; state != nil && hwndWndProc[hwnd] != 0 {
				captureOwnedControlPaint(state, hwndChildren[root], target)
			}
			if !hctx.RenderingDialogCustom {
				target.Commit()
			}
			ctx.SetReturn(1)
			return 0
		}
		if wlWindow != nil {
			paintTree(hwnd)
			paintChildScrollbars(hwnd)
			for _, sibling := range overlappingGuestSiblings(
				hwnd, hwndChildren, hwndWndProc, hctx.snapshotZOrder(),
			) {
				queuePaint(sibling)
			}
			prepareMainSurfacePaintCommit(hctx, hwnd)
			commitIfDone()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadCursorA", func(ctx *ntapi.TrapContext) uint32 {
		lpCursorName := ctx.Arg(1)
		if lpCursorName < 0x10000 && lpCursorName != 0 {
			ctx.SetReturn(lpCursorName)
		} else {
			ctx.SetReturn(32512)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDesktopWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00050000) // desktop window handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetParent", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(cs.parentHWND)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetParent", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		newParent := ctx.Arg(1)
		oldParent, ok := reparentControl(hwndChildren, hwnd, newParent)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		win32.Global.SetParent(hwnd, newParent)
		ravelog.Logf("[parent] SetParent hwnd=0x%x old=0x%x new=0x%x\n", hwnd, oldParent, newParent)
		requestWindowRepaint(oldParent)
		requestWindowRepaint(newParent)
		ctx.SetReturn(oldParent)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if h, ok := hwndMenuBar[hwnd]; ok {
			ctx.SetReturn(h)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hMenu := ctx.Arg(1)
		if hMenu == 0 {
			delete(hwndMenuBar, hwnd)
		} else {
			hwndMenuBar[hwnd] = hMenu
		}
		if hwnd == hctx.MainHWND {
			requestWindowRepaint(hwnd)
		}
		_ = menus[hMenu]
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateMenu", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiAlloc()
		menus[h] = &menuData{}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreatePopupMenu", func(ctx *ntapi.TrapContext) uint32 {
		h := gdiAlloc()
		menus[h] = &menuData{}
		ctx.SetReturn(h)
		return 0
	})
	readLegacyMenuItem := func(flags uint32, data uint64, wide bool) (uint32, string, bool) {
		if flags&(mftBitmap|mftOwnerDraw|mftSeparator) != 0 {
			return flags, "", true
		}
		if data == 0 {
			return flags | mftSeparator, "", true
		}
		text, err := readMenuText(mem, data, wide)
		return flags, text, err == nil
	}
	insertLegacyMenu := func(ctx *ntapi.TrapContext, wide, appendItem bool) uint32 {
		hMenu := ctx.Arg(0)
		position, flags, idNewItem, data := ctx.Arg(1), uint32(ctx.Arg(2)), ctx.Arg(3), ctx.Arg(4)
		if appendItem {
			flags, idNewItem, data = uint32(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3)
			position = ^uint64(0)
			flags |= 0x0400
		}
		flags, text, readable := readLegacyMenuItem(flags, data, wide)
		if readable && insertLegacyMenuItem(menus, hMenu, position, flags&0x0400 != 0, flags, idNewItem, data, text) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	}
	d.RegisterAutoStubHandler(user32, "AppendMenuW", func(ctx *ntapi.TrapContext) uint32 {
		return insertLegacyMenu(ctx, true, true)
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuW", func(ctx *ntapi.TrapContext) uint32 {
		return insertLegacyMenu(ctx, true, false)
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuItemW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPosition := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3) // MENUITEMINFOW*
		if insertMenuItem(mem, lpmii, ctx.State != nil && ctx.State.Is32, true, hMenu, item, byPosition, menus) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawMenuBar", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c NtUserDrawMenuBar
		// Invalidate the menu bar area to trigger a repaint on next WM_PAINT.
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0 {
			requestWindowRepaint(hctx.MainHWND)
		}
		ctx.SetReturn(1)
		return 0
	})
	messageBoxHandler := func(wide bool) ntapi.TrapHandler {
		return func(ctx *ntapi.TrapContext) uint32 {
			text := readGuestString(ctx.Arg(1))
			caption := readGuestString(ctx.Arg(2))
			if wide {
				text = readGuestUTF16(ctx.Arg(1))
				caption = readGuestUTF16(ctx.Arg(2))
			}
			if caption == "" {
				caption = "Error"
			}
			uType := uint32(ctx.Arg(3))
			spec := resolveMessageBoxSpec(uType)
			ravelog.Logf("[messagebox] open caption=%q text=%q type=0x%x\n", caption, text, uType)

			rr, canRead := ctx.CPU.(ntapi.RegisterReader)
			rw, canWrite := ctx.CPU.(ntapi.RegisterWriter)
			if !canRead || !canWrite || wlDisplay == nil || wlWindow == nil || hctx.ModalPumpTrampoline == 0 {
				ctx.SetReturn(0)
				return 0
			}
			messageBoxPumpMu.Lock()
			defer messageBoxPumpMu.Unlock()
			owner := ctx.Arg(0)
			if owner == 0 || (owner != hctx.MainHWND && hwndChildren[owner] == nil) {
				owner = hctx.MainHWND
			}
			lines := wrapMessageBoxText(text, 68)
			width := int32(360)
			for _, line := range lines {
				lineWidth := int32(len([]rune(line))*8 + 48)
				if lineWidth > width {
					width = lineWidth
				}
			}
			if width > 620 {
				width = 620
			}
			height := int32(96 + len(lines)*20)
			if height < 150 {
				height = 150
			}

			dialog := hwndAlloc()
			hctx.setWindowCPU(dialog, ctx.CPU)
			root := &controlState{
				className:  "dialog",
				parentHWND: owner,
				w:          width,
				h:          height,
				style:      wsVisible | 0x00c80000,
				text:       caption,
				visible:    true,
			}
			registerDialogState(dialog, root)
			hwndTitle[dialog] = caption
			for index, line := range lines {
				child := hwndAlloc()
				registerDialogState(child, &controlState{
					className:  "static",
					parentHWND: dialog,
					ctrlID:     uint64(100 + index),
					x:          root.x + 24,
					y:          root.y + 22 + int32(index*20),
					w:          width - 48,
					h:          20,
					style:      wsVisible,
					text:       line,
					visible:    true,
				})
			}
			const buttonWidth, buttonHeight, buttonGap = int32(90), int32(28), int32(10)
			buttonsWidth := int32(len(spec.buttons))*buttonWidth + int32(len(spec.buttons)-1)*buttonGap
			buttonX := (width - buttonsWidth) / 2
			buttonY := height - 48
			defaultHWND := uint64(0)
			for _, button := range spec.buttons {
				style := uint32(wsVisible | 0x00010000)
				if button.id == spec.defaultID {
					style |= 1
				}
				child := hwndAlloc()
				registerDialogState(child, &controlState{
					className:  "button",
					parentHWND: dialog,
					ctrlID:     button.id,
					x:          root.x + buttonX,
					y:          root.y + buttonY,
					w:          buttonWidth,
					h:          buttonHeight,
					style:      style,
					text:       button.label,
					visible:    true,
				})
				if button.id == spec.defaultID {
					defaultHWND = child
				}
				buttonX += buttonWidth + buttonGap
			}
			if ensureOwnedDialogWindow(dialog) == nil {
				cleanupWindowState(dialog)
				ctx.SetReturn(0)
				return 0
			}

			rsp := rr.ReadReg(4)
			var retAddr, retRSP uint64
			is32 := ctx.State != nil && ctx.State.Is32
			if is32 {
				value, _ := mem.Read32(rsp)
				retAddr = uint64(value)
				retRSP = rsp + 20
			} else {
				retAddr, _ = mem.Read64(rsp)
				retRSP = rsp + 8
			}
			syncStack := hctx.syncStack(ctx)
			box := &messageBoxRuntime{
				hwnd:          dialog,
				owner:         owner,
				defaultID:     spec.defaultID,
				escapeID:      spec.escapeID,
				previousFocus: hctx.FocusHwnd,
				retAddr:       retAddr,
				retRSP:        retRSP,
				pumpSP:        modalPumpEntrySP(rsp, is32),
				callee:        captureGuestNonvolatileRegisters(rr, is32),
				syncDepth:     len(*syncStack),
			}
			pushMessageBox(ctx.CPU, box)
			_, _ = updateWindowEnabled(owner, false, true)
			hctx.FocusHwnd = defaultHWND
			hctx.ActiveHwnd = dialog

			if is32 {
				targetRSP := box.pumpSP - 4
				mem.Write32(targetRSP, uint32(hctx.ModalPumpTrampoline))
				rw.WriteReg(4, targetRSP)
			} else {
				targetRSP := box.pumpSP - 8
				mem.Write64(targetRSP, hctx.ModalPumpTrampoline)
				rw.WriteReg(4, targetRSP)
			}
			ctx.SetReturn(0)
			return 0
		}
	}
	messageBoxAHandler := messageBoxHandler(false)
	messageBoxWHandler := messageBoxHandler(true)
	d.RegisterAutoStubHandler(user32, "MessageBoxA", messageBoxAHandler)
	d.RegisterAutoStubHandler(user32, "MessageBoxW", messageBoxWHandler)
	d.RegisterAutoStubHandler(user32, "SetCursor", func(ctx *ntapi.TrapContext) uint32 {
		hCursor := ctx.Arg(0)
		prevCursor := currentCursorHandle
		currentCursorHandle = hCursor
		shape, _ := mapCursorHandle(hCursor)
		if wlDisplay != nil {
			wlDisplay.SetCursorShape(shape)
		}
		ctx.SetReturn(prevCursor)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, uint32(cursorPosX))
			ctx.Mem.Write32(p+4, uint32(cursorPosY))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ScreenToClient", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPt := ctx.Arg(1)
		if pPt == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rx, _ := mem.Read32(pPt)
		ry, _ := mem.Read32(pPt + 4)
		x, y := int32(rx), int32(ry)
		if cs, ok := hwndChildren[hwnd]; ok {
			// cs.x/cs.y are surface (absolute) coordinates of the child's top-left.
			x -= cs.x
			y -= cs.y
		} else if hwnd == hctx.MainHWND && wlWindow != nil {
			// hctx.MainHWND client area starts below the NC area (TitleBarH + menuBar).
			y -= getMenuClientTop(hwnd)
		}
		ctx.Mem.Write32(pPt, uint32(x))
		ctx.Mem.Write32(pPt+4, uint32(y))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ClientToScreen", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		pPt := ctx.Arg(1)
		if pPt == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rx, _ := mem.Read32(pPt)
		ry, _ := mem.Read32(pPt + 4)
		x, y := int32(rx), int32(ry)
		if cs, ok := hwndChildren[hwnd]; ok {
			x += cs.x
			y += cs.y
		} else if hwnd == hctx.MainHWND && wlWindow != nil {
			y += getMenuClientTop(hwnd)
		}
		ctx.Mem.Write32(pPt, uint32(x))
		ctx.Mem.Write32(pPt+4, uint32(y))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapWindowPoints", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: winpos.c MapWindowPoints
		// Maps nCount points from fromHwnd's client coords to toHwnd's client coords.
		// fromHwnd==0 -> screen coords as source; toHwnd==0 -> screen coords as dest.
		// clientOrigin returns the surface (absolute) coordinate of a window's client top-left.
		clientOrigin := func(h uint64) (int32, int32) {
			if h == 0 {
				return 0, 0
			}
			if cs, ok := hwndChildren[h]; ok {
				return cs.x, cs.y
			}
			if h == hctx.MainHWND && wlWindow != nil {
				return 0, getMenuClientTop(h)
			}
			return 0, 0
		}
		fromHwnd := ctx.Arg(0)
		toHwnd := ctx.Arg(1)
		pPts := ctx.Arg(2)
		nPts := int(ctx.Arg(3))
		if pPts == 0 || nPts == 0 {
			ctx.SetReturn(0)
			return 0
		}
		fromX, fromY := clientOrigin(fromHwnd)
		toX, toY := clientOrigin(toHwnd)
		dx := fromX - toX
		dy := fromY - toY
		for i := 0; i < nPts; i++ {
			off := pPts + uint64(i)*8
			px, _ := mem.Read32(off)
			py, _ := mem.Read32(off + 4)
			ctx.Mem.Write32(off, uint32(int32(px)+dx))
			ctx.Mem.Write32(off+4, uint32(int32(py)+dy))
		}
		// Return value: low word = dx, high word = dy (signed)
		ret := (uint64(uint16(dx)) & 0xFFFF) | ((uint64(uint16(dy)) & 0xFFFF) << 16)
		ctx.SetReturn(ret)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00040001) // dummy monitor handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMonitorInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			cbSize, _ := ctx.Mem.Read32(pInfo)
			if cbSize >= 40 {
				sw := int32(1920)
				sh := int32(1080)
				if wlWindow != nil {
					sw = wlWindow.Width
					sh = wlWindow.Height
				}
				ctx.Mem.Write32(pInfo+4, 0)           // rcMonitor.left
				ctx.Mem.Write32(pInfo+8, 0)           // rcMonitor.top
				ctx.Mem.Write32(pInfo+12, uint32(sw)) // rcMonitor.right
				ctx.Mem.Write32(pInfo+16, uint32(sh)) // rcMonitor.bottom
				ctx.Mem.Write32(pInfo+20, 0)          // rcWork.left
				ctx.Mem.Write32(pInfo+24, 0)          // rcWork.top
				ctx.Mem.Write32(pInfo+28, uint32(sw)) // rcWork.right
				ctx.Mem.Write32(pInfo+32, uint32(sh)) // rcWork.bottom
				ctx.Mem.Write32(pInfo+36, 1)          // dwFlags = MONITORINFOF_PRIMARY
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMonitorInfoA", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			cbSize, _ := ctx.Mem.Read32(pInfo)
			if cbSize >= 40 {
				sw := int32(1920)
				sh := int32(1080)
				if wlWindow != nil {
					sw = wlWindow.Width
					sh = wlWindow.Height
				}
				ctx.Mem.Write32(pInfo+4, 0)           // rcMonitor.left
				ctx.Mem.Write32(pInfo+8, 0)           // rcMonitor.top
				ctx.Mem.Write32(pInfo+12, uint32(sw)) // rcMonitor.right
				ctx.Mem.Write32(pInfo+16, uint32(sh)) // rcMonitor.bottom
				ctx.Mem.Write32(pInfo+20, 0)          // rcWork.left
				ctx.Mem.Write32(pInfo+24, 0)          // rcWork.top
				ctx.Mem.Write32(pInfo+28, uint32(sw)) // rcWork.right
				ctx.Mem.Write32(pInfo+32, uint32(sh)) // rcWork.bottom
				ctx.Mem.Write32(pInfo+36, 1)          // dwFlags = MONITORINFOF_PRIMARY
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	systemParametersInfoWHandler := func(ctx *ntapi.TrapContext) uint32 {
		uiAction := ctx.Arg(0)
		pvParam := ctx.Arg(2)
		w := int32(1920)
		h := int32(1080)
		if wlWindow != nil {
			w = int32(wlWindow.Width)
			h = int32(wlWindow.Height)
		}
		// writeLogFont writes a complete LOGFONTW (92 bytes) at pvParam+off.
		writeLogFont := func(off uint64, name string, height int32) {
			ctx.Mem.Write32(pvParam+off+0, uint32(height)) // lfHeight
			ctx.Mem.Write32(pvParam+off+4, 0)              // lfWidth
			ctx.Mem.Write32(pvParam+off+8, 0)              // lfEscapement
			ctx.Mem.Write32(pvParam+off+12, 0)             // lfOrientation
			ctx.Mem.Write32(pvParam+off+16, 400)           // lfWeight = FW_NORMAL
			ctx.Mem.Write8(pvParam+off+20, 0)              // lfItalic
			ctx.Mem.Write8(pvParam+off+21, 0)              // lfUnderline
			ctx.Mem.Write8(pvParam+off+22, 0)              // lfStrikeOut
			ctx.Mem.Write8(pvParam+off+23, 1)              // lfCharSet = DEFAULT_CHARSET
			ctx.Mem.Write8(pvParam+off+24, 0)              // lfOutPrecision
			ctx.Mem.Write8(pvParam+off+25, 0)              // lfClipPrecision
			ctx.Mem.Write8(pvParam+off+26, 5)              // lfQuality = CLEARTYPE_QUALITY
			ctx.Mem.Write8(pvParam+off+27, 0x22)           // lfPitchAndFamily
			ws := utf16Encode(name)
			for i, wc := range ws {
				ctx.Mem.Write16(pvParam+off+28+uint64(i)*2, wc)
			}
			ctx.Mem.Write16(pvParam+off+28+uint64(len(ws))*2, 0) // null terminator
		}
		switch uiAction {
		case 0x0026: // SPI_GETDRAGFULLWINDOWS
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1) // TRUE
			}
		case 0x0029: // SPI_GETNONCLIENTMETRICS - fill NONCLIENTMETRICSW (504 bytes)
			if pvParam != 0 {
				// NONCLIENTMETRICSW layout (Vista+, 504 bytes):
				// +0x00 cbSize=504, +0x04 iBorderWidth=1, +0x08 iScrollWidth=17, +0x0C iScrollHeight=17
				// +0x10 iCaptionWidth=36, +0x14 iCaptionHeight=36
				// +0x18 lfCaptionFont (92 bytes)
				// +0x74 iSmCaptionWidth=36, +0x78 iSmCaptionHeight=36
				// +0x7C lfSmCaptionFont (92 bytes)
				// +0xD8 iMenuWidth=36, +0xDC iMenuHeight=36
				// +0xE0 lfMenuFont (92 bytes)
				// +0x13C lfStatusFont (92 bytes)
				// +0x198 lfMessageFont (92 bytes)
				// +0x1F4 iPaddedBorderWidth=4
				ctx.Mem.Write32(pvParam+0, 504)    // cbSize
				ctx.Mem.Write32(pvParam+4, 1)      // iBorderWidth
				ctx.Mem.Write32(pvParam+8, 17)     // iScrollWidth
				ctx.Mem.Write32(pvParam+12, 17)    // iScrollHeight
				ctx.Mem.Write32(pvParam+16, 36)    // iCaptionWidth
				ctx.Mem.Write32(pvParam+20, 36)    // iCaptionHeight
				writeLogFont(24, "Segoe UI", -12)  // lfCaptionFont
				ctx.Mem.Write32(pvParam+116, 36)   // iSmCaptionWidth
				ctx.Mem.Write32(pvParam+120, 36)   // iSmCaptionHeight
				writeLogFont(124, "Segoe UI", -12) // lfSmCaptionFont
				ctx.Mem.Write32(pvParam+216, 36)   // iMenuWidth
				ctx.Mem.Write32(pvParam+220, 36)   // iMenuHeight
				writeLogFont(224, "Segoe UI", -12) // lfMenuFont
				writeLogFont(316, "Segoe UI", -12) // lfStatusFont
				writeLogFont(408, "Segoe UI", -12) // lfMessageFont
				ctx.Mem.Write32(pvParam+500, 4)    // iPaddedBorderWidth
			}
		case 0x002B: // SPI_GETMINIMIZEDMETRICS - MINIMIZEDMETRICS (20 bytes)
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam+0, 20)  // cbSize
				ctx.Mem.Write32(pvParam+4, 160) // iWidth
				ctx.Mem.Write32(pvParam+8, 0)   // iHorzGap
				ctx.Mem.Write32(pvParam+12, 0)  // iVertGap
				ctx.Mem.Write32(pvParam+16, 0)  // iArrange
			}
		case 0x001F: // SPI_GETICONTITLELOGFONT - LOGFONTW (92 bytes)
			if pvParam != 0 {
				writeLogFont(0, "Segoe UI", -12)
			}
		case 0x0030: // SPI_GETWORKAREA
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam+0, 0)
				ctx.Mem.Write32(pvParam+4, 0)
				ctx.Mem.Write32(pvParam+8, uint32(w))
				ctx.Mem.Write32(pvParam+12, uint32(h))
			}
		case 0x0048: // SPI_GETANIMATION - ANIMATIONINFO{cbSize=8, iMinAnimate=0}
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 8)
				ctx.Mem.Write32(pvParam+4, 0)
			}
		case 0x004A: // SPI_GETFONTSMOOTHING
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1)
			}
		case 0x0042: // SPI_GETHIGHCONTRAST - fill HIGHCONTRAST {cbSize=12, dwFlags=0, lpszDefaultScheme=NULL}
			if pvParam != 0 {
				size := uint32(16)
				if ctx.State != nil && ctx.State.Is32 {
					size = 12
				}
				ctx.Mem.Write32(pvParam+0, size) // cbSize
				ctx.Mem.Write32(pvParam+4, 0)    // dwFlags = 0 (high contrast off)
				if ctx.State != nil && ctx.State.Is32 {
					ctx.Mem.Write32(pvParam+8, 0)
				} else {
					ctx.Mem.Write64(pvParam+8, 0)
				}
			}
		case 0x009C: // SPI_GETSMOOTHEDGES
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1)
			}
		case 0x0067: // SPI_GETMOUSETRAILS
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 0)
			}
		case 0x001A: // SPI_GETDESKWALLPAPER
			if pvParam != 0 {
				ctx.Mem.Write16(pvParam, 0)
			}
		case 0x0068: // SPI_GETWHEELSCROLLLINES
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 3)
			}
		case 0x006A: // SPI_GETMENUSHOWDELAY
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 400)
			}
		case 0x006C: // SPI_GETWHEELSCROLLCHARS
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 3)
			}
		case 0x1020: // SPI_GETMOUSEVANISH
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1)
			}
		case 0x200A: // SPI_GETFONTSMOOTHINGTYPE
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 2) // FE_FONTSMOOTHINGCLEARTYPE
			}
		case 0x200C: // SPI_GETFONTSMOOTHINGCONTRAST
			if pvParam != 0 {
				ctx.Mem.Write32(pvParam, 1400)
			}
		default:
			ravelog.Logf("[spi] SystemParametersInfoW unknown uiAction=0x%x pvParam=0x%x\n", uiAction, pvParam)
		}
		ctx.SetReturn(1)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "SystemParametersInfoW", systemParametersInfoWHandler)
	systemParametersInfoForDPIHandler := func(ctx *ntapi.TrapContext) uint32 {
		uiAction := uint32(ctx.Arg(0))
		_ = ctx.Arg(1)
		pvParam := ctx.Arg(2)
		_ = ctx.Arg(3)
		dpi := uint32(ctx.Arg(4))
		if pvParam == 0 || dpi == 0 {
			ctx.SetReturn(0)
			return 0
		}
		requiredSize := 0
		switch uiAction {
		case 0x001F:
			requiredSize = 92
		case 0x0029:
			requiredSize = 504
		case 0x002D:
			requiredSize = 108
		default:
			ctx.SetReturn(0)
			return 0
		}
		if !guestRangeAccessible(mem, pvParam, uint64(requiredSize), mmu.PermRead|mmu.PermWrite) {
			ctx.SetReturn(0)
			return 0
		}
		scaleField := func(offset uint64) {
			raw, err := mem.Read32(pvParam + offset)
			if err != nil {
				return
			}
			mem.Write32(pvParam+offset, uint32(win32.ScaleForDPI(int32(raw), dpi)))
		}
		switch uiAction {
		case 0x001F: // SPI_GETICONTITLELOGFONT
			systemParametersInfoWHandler(ctx)
			scaleField(0)
		case 0x0029: // SPI_GETNONCLIENTMETRICS
			systemParametersInfoWHandler(ctx)
			for _, offset := range []uint64{4, 8, 12, 16, 20, 116, 120, 216, 220, 500} {
				scaleField(offset)
			}
			for _, offset := range []uint64{24, 124, 224, 316, 408} {
				scaleField(offset)
			}
		case 0x002D: // SPI_GETICONMETRICS
			cbSize, err := mem.Read32(pvParam)
			if err != nil || cbSize < 108 {
				ctx.SetReturn(0)
				return 0
			}
			mem.Write32(pvParam+4, uint32(win32.ScaleForDPI(75, dpi)))
			mem.Write32(pvParam+8, uint32(win32.ScaleForDPI(75, dpi)))
			mem.Write32(pvParam+12, 1)
			for offset := uint64(16); offset < 108; offset++ {
				mem.Write8(pvParam+offset, 0)
			}
			mem.Write32(pvParam+16, uint32(win32.ScaleForDPI(-12, dpi)))
			mem.Write32(pvParam+32, 400)
			mem.Write8(pvParam+39, 1)
			mem.Write8(pvParam+42, 5)
			mem.Write8(pvParam+43, 0x22)
			name := utf16Encode("Segoe UI")
			for index, char := range name {
				mem.Write16(pvParam+44+uint64(index)*2, char)
			}
			mem.Write16(pvParam+44+uint64(len(name))*2, 0)
			ctx.SetReturn(1)
		}
		return 0
	}
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x04090409) // en-US
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MapVirtualKeyW", func(ctx *ntapi.TrapContext) uint32 {
		code := uint32(ctx.Arg(0))
		mapType := uint32(ctx.Arg(1))
		var result uint32
		switch mapType {
		case 0: // MAPVK_VK_TO_VSC
			// Common VK -> scan code mappings
			vkToScan := map[uint32]uint32{
				0x08: 0x0E, 0x09: 0x0F, 0x0D: 0x1C, 0x10: 0x2A, 0x11: 0x1D, 0x12: 0x38,
				0x14: 0x3A, 0x1B: 0x01, 0x20: 0x39,
				0x25: 0x4B, 0x26: 0x48, 0x27: 0x4D, 0x28: 0x50, // arrows
				0x2D: 0x52, 0x2E: 0x53, 0x24: 0x47, 0x23: 0x4F, 0x21: 0x49, 0x22: 0x51,
			}
			// A-Z
			for vk := uint32(0x41); vk <= 0x5A; vk++ {
				aToZ := []uint32{0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C}
				vkToScan[vk] = aToZ[vk-0x41]
			}
			// 0-9
			for vk := uint32(0x30); vk <= 0x39; vk++ {
				vkToScan[vk] = vk - 0x30 + 0x0B
				if vk == 0x30 {
					vkToScan[vk] = 0x0B
				}
			}
			result = vkToScan[code]
		case 1: // MAPVK_VSC_TO_VK
			result = code // simplified
		case 2: // MAPVK_VK_TO_CHAR
			if code >= 0x41 && code <= 0x5A {
				result = code // A-Z -> 'A'-'Z'
			} else if code >= 0x30 && code <= 0x39 {
				result = code // 0-9
			} else if code == 0x20 {
				result = 0x20 // space
			}
		}
		ctx.SetReturn(uint64(result))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyState", func(ctx *ntapi.TrapContext) uint32 {
		vk := ctx.Arg(0) & 0xFF
		switch vk {
		case 0x10:
			if hctx.WlDisplay != nil && hctx.WlDisplay.ShiftDown() {
				keyState[vk] |= 0x80
			} else {
				keyState[vk] &^= 0x80
			}
		case 0x11:
			if hctx.WlDisplay != nil && hctx.WlDisplay.CtrlDown() {
				keyState[vk] |= 0x80
			} else {
				keyState[vk] &^= 0x80
			}
		case 0x12:
			if hctx.WlDisplay != nil && hctx.WlDisplay.AltDown() {
				keyState[vk] |= 0x80
			} else {
				keyState[vk] &^= 0x80
			}
		}
		value := keyStateValue(uint32(vk), true)
		ctx.SetReturn(uint64(uint16(value)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetAsyncKeyState", func(ctx *ntapi.TrapContext) uint32 {
		vk := ctx.Arg(0) & 0xFF
		ctx.SetReturn(uint64(uint16(keyStateValue(uint32(vk), false) & 0x8000)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowsHookExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00060001) // dummy hook handle
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWindowsHookEx", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnhookWindowsHookEx(HHOOK hhk)
		// ReactOS: win32ss/user/ntuser/hook.c NtUserUnhookWindowsHookEx
		hhk := ctx.Arg(0)
		ravelog.Logf("[user32] UnhookWindowsHookEx hhk=0x%x\n", hhk)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDpiForWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(96) // standard DPI
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AdjustWindowRectExForDpi", func(ctx *ntapi.TrapContext) uint32 {
		pRect := ctx.Arg(0)
		style := uint32(ctx.Arg(1))
		hasMenu := ctx.Arg(2) != 0
		exStyle := uint32(ctx.Arg(3))
		if pRect != 0 {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			rc := win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
			win32.AdjustWindowRectEx(&rc, style, hasMenu, exStyle)
			ctx.Mem.Write32(pRect, uint32(rc.Left))
			ctx.Mem.Write32(pRect+4, uint32(rc.Top))
			ctx.Mem.Write32(pRect+8, uint32(rc.Right))
			ctx.Mem.Write32(pRect+12, uint32(rc.Bottom))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntCheckMenuItem
		const mfChecked = 0x0008
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		prev := item.flags & mfChecked
		if uint32(ctx.Arg(2))&mfChecked != 0 {
			item.flags |= mfChecked
		} else {
			item.flags &^= mfChecked
		}
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpwndpl := ctx.Arg(1)
		if lpwndpl != 0 && wlWindow != nil {
			// WINDOWPLACEMENT layout (all int32):
			// offset 0: length (uint32)
			// offset 4: flags (uint32)
			// offset 8: showCmd (uint32)
			// offset 12: ptMinPosition.x, offset 16: ptMinPosition.y
			// offset 20: ptMaxPosition.x, offset 24: ptMaxPosition.y
			// offset 28: rcNormalPosition.left, offset 32: top, offset 36: right, offset 40: bottom
			readI32 := func(off uint64) int32 {
				v, _ := mem.Read32(lpwndpl + off)
				return int32(v)
			}
			left := readI32(28)
			top := readI32(32)
			right := readI32(36)
			bottom := readI32(40)
			w := right - left
			h := bottom - top
			if w > 0 && w < 0x7FFF && h > 0 && h < 0x7FFF {
				ravelog.Logf("[placement] SetWindowPlacement hwnd=0x%x -> %d,%d %dx%d\n", hwnd, left, top, w, h)
				if hwnd == hctx.MainHWND {
					if wlWindow.Resize(w, h) {
						syncScreenSurface()
					}
					lParam := uint64(uint16(w)) | (uint64(uint16(h)) << 16)
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, 0x0005, 0, lParam))
					queuePaint(hwnd)
				} else if ci, ok := hwndChildren[hwnd]; ok {
					ci.mutateGeometry(func(geometry *controlGeometry) {
						geometry.w = w
						geometry.h = h
					})
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RedrawWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Route WM_PAINT to the actual window, not always hctx.MainHWND.
		// Same reasoning as InvalidateRect: routing child RedrawWindow to hctx.MainHWND
		// creates a paint loop when Scintilla redraws itself.
		if hwnd == 0 || hwnd == hctx.MainHWND {
			queuePaint(hctx.MainHWND)
		} else if cs, ok := hwndChildren[hwnd]; ok && cs.visible {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})

	// LoadMenuW: load menu from PE resources (same as LoadMenuIndirectW essentially)
	d.RegisterAutoStubHandler(user32, "LoadMenuW", func(ctx *ntapi.TrapContext) uint32 {
		menuName := ctx.Arg(1)
		if menuName == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// menuName can be an integer resource ID (MAKEINTRESOURCE) or string pointer
		var resID uint32
		if menuName < 0x10000 {
			resID = uint32(menuName)
		} else {
			// It's a string - try reading it as an integer name
			ctx.SetReturn(0)
			return 0
		}
		menu := peLoadMenuResource(resID)
		if menu == nil {
			ravelog.Logf("[menu] LoadMenuW resID=%d -> nil\n", resID)
			ctx.SetReturn(0)
			return 0
		}
		hmenu := uint64(0x60000 + resID)
		menus[hmenu] = menu
		ravelog.Logf("[menu] LoadMenuW resID=%d -> hmenu=0x%x items=%d\n", resID, hmenu, len(menu.items))
		for i, item := range menu.items {
			ravelog.Logf("[menu]   [%d] %q flags=0x%x submenu=%d\n", i, item.text, item.flags, len(item.submenuItems()))
		}
		ctx.SetReturn(hmenu)
		return 0
	})

	// RegisterClipboardFormatW/A: maintain name->id map for consistent IDs
	clipFmtByName := make(map[string]uint64)
	var nextClipFmtID uint64 = 0xC000
	registerClipFmt := func(name string) uint64 {
		name = strings.ToLower(name)
		if id, ok := clipFmtByName[name]; ok {
			return id
		}
		nextClipFmtID++
		clipFmtByName[name] = nextClipFmtID
		return nextClipFmtID
	}
	d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		ctx.SetReturn(registerClipFmt(name))
		return 0
	})

	// DestroyMenu
	d.RegisterAutoStubHandler(user32, "DestroyMenu", func(ctx *ntapi.TrapContext) uint32 {
		hmenu := ctx.Arg(0)
		delete(menus, hmenu)
		ctx.SetReturn(1)
		return 0
	})

	// EnableMenuItem
	d.RegisterAutoStubHandler(user32, "EnableMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntEnableMenuItem
		const (
			mfGrayed   = 0x0001
			mfDisabled = 0x0002
		)
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		prev := item.flags & (mfGrayed | mfDisabled)
		item.flags &^= (mfGrayed | mfDisabled)
		item.flags |= uint32(ctx.Arg(2)) & (mfGrayed | mfDisabled)
		ctx.SetReturn(uint64(prev))
		return 0
	})

	// GetMenu / SetMenu
	d.RegisterAutoStubHandler(user32, "GetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if hm, ok := hwndMenuBar[hwnd]; ok {
			ctx.SetReturn(hm)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hmenu := ctx.Arg(1)
		if hmenu != 0 {
			hwndMenuBar[hwnd] = hmenu
		} else {
			delete(hwndMenuBar, hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetSubMenu
	d.RegisterAutoStubHandler(user32, "GetSubMenu", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntGetSubMenu
		hmenu := ctx.Arg(0)
		pos := int(ctx.Arg(1))
		m, ok := menus[hmenu]
		if !ok || pos < 0 || pos >= len(m.items) {
			ctx.SetReturn(0)
			return 0
		}
		item := &m.items[pos]
		subH := ensureMenuItemSubmenu(hmenu, pos, item, menus)
		ctx.SetReturn(subH)
		return 0
	})

	modifyMenu := func(ctx *ntapi.TrapContext, wide bool) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		idNewItem := ctx.Arg(3)
		lpNewItem := ctx.Arg(4)
		text := ""
		if flags&(mftBitmap|mftOwnerDraw|mftSeparator) == 0 {
			if lpNewItem == 0 {
				flags |= mftSeparator
			} else {
				value, err := readMenuText(mem, lpNewItem, wide)
				if err != nil {
					ctx.SetReturn(0)
					return 0
				}
				text = value
			}
		}
		if modifyMenuItem(menus, hMenu, idPos, flags&0x0400 != 0, flags, idNewItem, lpNewItem, text) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	}
	d.RegisterAutoStubHandler(user32, "ModifyMenuW", func(ctx *ntapi.TrapContext) uint32 {
		return modifyMenu(ctx, true)
	})
	// DeleteMenu: remove a menu item by position or ID
	d.RegisterAutoStubHandler(user32, "DeleteMenu", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		if removeMenuItem(menus, hMenu, idPos, flags&0x0400 != 0, true) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// GetMenuItemInfoW: fill MENUITEMINFOW for a valid item
	d.RegisterAutoStubHandler(user32, "GetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if withLocatedMenuItem(menus, hMenu, item, byPos, func(found *menuItem, owner uint64) bool {
			return getMenuItemInfo(ctx.Mem, lpmii, ctx.State != nil && ctx.State.Is32, true, owner, found, menus)
		}) {
			ctx.SetReturn(1)
		} else {
			cbSize, _ := ctx.Mem.Read32(lpmii)
			mask, _ := ctx.Mem.Read32(lpmii + 4)
			ravelog.Logf("[menuinfo] GetMenuItemInfoW failed menu=0x%x item=%d byPos=%v cb=%d mask=0x%x\n", hMenu, item, byPos, cbSize, mask)
			ctx.SetReturn(0)
		}
		return 0
	})

	// GetMenuState returns flags for menu item (by position or ID)
	d.RegisterAutoStubHandler(user32, "GetMenuState", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/menu.c IntGetMenuState
		item := findMenuItem(ctx.Arg(0), ctx.Arg(1), uint32(ctx.Arg(2)))
		if item == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		flags := item.flags
		if submenu := item.submenuItems(); len(submenu) > 0 {
			flags |= uint32(len(submenu)) << 8
		}
		ctx.SetReturn(uint64(flags))
		return 0
	})

	// GetMenuItemCount returns number of items in a menu
	d.RegisterAutoStubHandler(user32, "GetMenuItemCount", func(ctx *ntapi.TrapContext) uint32 {
		hmenu := ctx.Arg(0)
		if m, ok := menus[hmenu]; ok {
			ctx.SetReturn(uint64(len(m.items)))
		} else {
			ctx.SetReturn(0xffffffffffffffff) // -1 on error
		}
		return 0
	})

	// SetMenuItemInfoW - reads MENUITEMINFOW and updates menu item data
	d.RegisterAutoStubHandler(user32, "SetMenuItemInfoW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if withLocatedMenuItem(menus, hMenu, item, byPos, func(found *menuItem, owner uint64) bool {
			return setMenuItemInfo(mem, lpmii, ctx.State != nil && ctx.State.Is32, true, owner, found, menus)
		}) {
			ctx.SetReturn(1)
		} else {
			cbSize, _ := mem.Read32(lpmii)
			mask, _ := mem.Read32(lpmii + 4)
			ravelog.Logf("[menuinfo] SetMenuItemInfoW failed menu=0x%x item=%d byPos=%v cb=%d mask=0x%x\n", hMenu, item, byPos, cbSize, mask)
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMenuItemInfoA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if withLocatedMenuItem(menus, hMenu, item, byPos, func(found *menuItem, owner uint64) bool {
			return setMenuItemInfo(mem, lpmii, ctx.State != nil && ctx.State.Is32, false, owner, found, menus)
		}) {
			ctx.SetReturn(1)
		} else {
			cbSize, _ := mem.Read32(lpmii)
			mask, _ := mem.Read32(lpmii + 4)
			ravelog.Logf("[menuinfo] SetMenuItemInfoA failed menu=0x%x item=%d byPos=%v cb=%d mask=0x%x\n", hMenu, item, byPos, cbSize, mask)
			ctx.SetReturn(0)
		}
		return 0
	})

	// GetSystemMenu
	d.RegisterAutoStubHandler(user32, "GetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
		sysMenu := uint64(0x80000)
		if _, ok := menus[sysMenu]; !ok {
			menus[sysMenu] = &menuData{}
		}
		ctx.SetReturn(sysMenu)
		return 0
	})
	// GetSysColorBrush: return a solid brush for the given system colour index
	d.RegisterAutoStubHandler(user32, "GetSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		idx := ctx.Arg(0)
		h := gdiMgr.CreateSolidBrush(getSysColor(uint32(idx)))
		ctx.SetReturn(h)
		return 0
	})
	// FillRect (user32 export, same semantics as gdi32.FillRect)
	d.RegisterAutoStubHandler(user32, "FillRect", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hDC := ctx.Arg(0)
		lpRect := ctx.Arg(1)
		hBrush := ctx.Arg(2)
		if lpRect == 0 {
			ctx.SetReturn(1)
			return 0
		}
		dc := getDC(hDC)
		left, _ := mem.Read32(lpRect)
		top, _ := mem.Read32(lpRect + 4)
		right, _ := mem.Read32(lpRect + 8)
		bottom, _ := mem.Read32(lpRect + 12)
		fillRectUsingBrushHandle(dc, gdiMgr, hBrush, hctx.SysColors,
			int32(left), int32(top), int32(right), int32(bottom))
		ctx.SetReturn(1)
		return 0
	})
	// SetMenuItemBitmaps: associate bitmaps with menu items
	d.RegisterAutoStubHandler(user32, "SetMenuItemBitmaps", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetMenuItemBitmaps(HMENU hMenu, UINT uPosition, UINT uFlags, HBITMAP hBitmapUnchecked, HBITMAP hBitmapChecked)
		// ReactOS: win32ss/user/ntuser/menu.c
		hMenu := ctx.Arg(0)
		uPosition := ctx.Arg(1)
		uFlags := uint32(ctx.Arg(2))
		hBitmapUnchecked := ctx.Arg(3)
		hBitmapChecked := ctx.Arg(4)
		ravelog.Logf("[user32] SetMenuItemBitmaps menu=0x%x pos=%d flags=0x%x\n", hMenu, uPosition, uFlags)
		if setMenuItemBitmaps(menus, hMenu, uPosition, uFlags&0x0400 != 0, hBitmapUnchecked, hBitmapChecked) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// RemoveMenu: remove a menu item by position or ID
	d.RegisterAutoStubHandler(user32, "RemoveMenu", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idPos := ctx.Arg(1)
		flags := uint32(ctx.Arg(2))
		if removeMenuItem(menus, hMenu, idPos, flags&0x0400 != 0, false) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// GetMenuStringW: copy menu item text into caller's buffer
	d.RegisterAutoStubHandler(user32, "GetMenuStringW", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		idItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		nMaxCount := int(ctx.Arg(3))
		flags := uint32(ctx.Arg(4))
		item := findMenuItem(hMenu, idItem, flags)
		if item == nil || item.flags&(mftBitmap|mftOwnerDraw|mftSeparator) != 0 {
			ctx.SetReturn(0)
			return 0
		}
		written, ok := writeMenuString(mem, lpStr, nMaxCount, item.text, true)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(written))
		return 0
	})

	// FindWindowA: ANSI wrapper - convert strings, return NULL (not found)
	d.RegisterAutoStubHandler(user32, "FindWindowA", func(ctx *ntapi.TrapContext) uint32 {
		wantClass := strings.ToLower(readGuestString(ctx.Arg(0)))
		wantTitle := readGuestString(ctx.Arg(1))
		for h, cs := range hwndChildren {
			if wantClass != "" && strings.ToLower(cs.className) != wantClass {
				continue
			}
			if wantTitle != "" {
				title := cs.text
				if t, ok := hwndTitle[h]; ok {
					title = t
				}
				if title != wantTitle {
					continue
				}
			}
			ctx.SetReturn(h)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})

	// GetDoubleClickTime/SetDoubleClickTime with mutable state
	d.RegisterAutoStubHandler(user32, "GetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(doubleClickTime))
		return 0
	})

	// GetMessageA: full blocking message loop - mirrors GetMessageW exactly.
	// The ANSI/Unicode distinction doesn't matter since our queue stores Win32
	// message structs with already-resolved strings.
	var runGetMessageA func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runGetMessageA = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		flushDestroyedWindows()
		pMsg := pump.arguments[0]
		hwndFilter := pump.arguments[1]
		minMessage := uint32(pump.arguments[2])
		maxMessage := uint32(pump.arguments[3])
		if pMsg == 0 || !validMessageFilter(hwndFilter) {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if dispatchPendingSentMessage(ctx, pump) {
			return 0
		}

		// Save message loop entry point (same logic as GetMessageW).
		if msgLoopSP == 0 {
			if ctx.State != nil && ctx.State.Is32 {
				retAddr32, _ := mem.Read32(ctx.CPU.GetSP())
				msgLoopPC = uint64(retAddr32)
				msgLoopSP = ctx.CPU.GetSP() + 4
				ravelog.Logf("[msg] GetMessageA first call from 0x%x (pMsg=0x%x)\n", retAddr32, pMsg)
			} else {
				retAddr, _ := mem.Read64(ctx.CPU.GetSP())
				msgLoopPC = retAddr
				msgLoopSP = ctx.CPU.GetSP() + 8
				ravelog.Logf("[msg] GetMessageA first call from 0x%x (pMsg=0x%x)\n", retAddr, pMsg)
			}
		}

		dequeueA := func() bool {
			if dispatchPendingSentMessage(ctx, pump) {
				return true
			}
			found := false
			m, delivered := hctx.MsgQueue.deliver(ctx.CPU,
				messageMatches(hwndFilter, minMessage, maxMessage),
				func(queuedMsg) bool { return true },
				func(msg queuedMsg) bool {
					found = true
					return writeMsg(ctx, pMsg, msg)
				})
			if !delivered {
				if !found {
					return false
				}
				ctx.SetReturn(^uint64(0))
				return true
			}
			if m.message == 0x0012 {
				ctx.SetReturn(0)
			} else {
				ctx.SetReturn(1)
			}
			return true
		}

		var lastSyntheticFrameNs int64
		queueSyntheticPaintsA := func() bool {
			nowNs := time.Now().UnixNano()
			if nowNs-lastSyntheticFrameNs < 16_000_000 {
				return false
			}
			lastSyntheticFrameNs = nowNs
			var childPaints []uint64
			for h, cs := range hwndChildren {
				if hwndWndProc[h] != 0 && cs.visible && hctx.WinInvalid[h] {
					childPaints = append(childPaints, h)
				}
			}
			if !hctx.WinInvalid[hctx.MainHWND] && len(childPaints) == 0 {
				return false
			}
			sort.Slice(childPaints, func(i, j int) bool { return childPaints[i] < childPaints[j] })
			if hctx.WinInvalid[hctx.MainHWND] {
				queuePaint(hctx.MainHWND)
			}
			for _, h := range childPaints {
				queuePaint(h)
			}
			return true
		}

		if wlDisplay == nil {
			if !hctx.KeepHeadlessAlive {
				if !writeMsg(ctx, pMsg, newQueuedMsg(hctx, hctx.MainHWND, 0x0012, 0, 0)) {
					ctx.SetReturn(^uint64(0))
					return 0
				}
				ctx.SetReturn(0)
				return 0
			}
			for {
				checkTimers(ctx.CPU)
				if dequeueA() {
					return 0
				}
				if queueSyntheticPaintsA() {
					if dequeueA() {
						return 0
					}
				}
				waitFor := hctx.Timers.nextDelay(ctx.CPU, time.Now(), 16*time.Millisecond)
				hctx.MsgQueue.wait(ctx.CPU, waitFor)
			}
		}

		for {
			checkTimers(ctx.CPU)
			if dequeueA() {
				return 0
			}

			evt, _ := wlDisplay.Poll()
			if evt != wl.EventNone {
				if dispatchWl != nil {
					dispatchWl(evt)
				}
				checkTimers(ctx.CPU)
				if dequeueA() {
					return 0
				}
			}

			timeoutUs := int64(16000)
			now := time.Now()
			timeoutUs = hctx.Timers.nextDelay(ctx.CPU, now, time.Duration(timeoutUs)*time.Microsecond).Microseconds()

			wlFd := wlDisplay.Fd()
			var rfds unix.FdSet
			rfds.Set(wlFd)
			tv := unix.Timeval{Sec: timeoutUs / 1_000_000, Usec: timeoutUs % 1_000_000}
			n, _ := unix.Select(wlFd+1, &rfds, nil, nil, &tv)
			if n > 0 {
				evt2, _ := wlDisplay.Dispatch()
				if dispatchWl != nil {
					dispatchWl(evt2)
				}
			}

			checkTimers(ctx.CPU)

			if wlDisplay.HasPendingInput() && dispatchWl != nil {
				dispatchWl(wl.EventKey)
				dispatchWl(wl.EventMouse)
			}

			if dequeueA() {
				return 0
			}

			if queueSyntheticPaintsA() {
				if dequeueA() {
					return 0
				}
			}
		}
	}
	d.RegisterAutoStubHandler(user32, "GetMessageA", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)}
		pump := captureSentMessagePump(ctx, arguments, 4, runGetMessageA)
		return runGetMessageA(ctx, pump)
	})

	// LoadCursorA: ANSI wrapper - same as LoadCursorW
	// SetWindowsHookExA: ANSI wrapper - return dummy hook handle
	d.RegisterAutoStubHandler(user32, "SetWindowsHookExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00060001) // dummy hook handle
		return 0
	})

	// -------------------------------------------------------
	// RECT operations - delegate to pkg/win32/rect.go
	// -------------------------------------------------------
	readRect := func(p uint64) win32.Rect {
		l, _ := mem.Read32(p)
		t, _ := mem.Read32(p + 4)
		r, _ := mem.Read32(p + 8)
		b, _ := mem.Read32(p + 12)
		return win32.Rect{Left: int32(l), Top: int32(t), Right: int32(r), Bottom: int32(b)}
	}
	writeRect := func(p uint64, rc win32.Rect) {
		ctx2 := rc // local copy to avoid capture issues
		_ = ctx2
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
	}
	_ = writeRect
	_ = readRect
	d.RegisterAutoStubHandler(user32, "CopyRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc := ctx.Arg(0), ctx.Arg(1)
		if pDst == 0 || pSrc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rc := readRect(pSrc)
		mem.Write32(pDst, uint32(rc.Left))
		mem.Write32(pDst+4, uint32(rc.Top))
		mem.Write32(pDst+8, uint32(rc.Right))
		mem.Write32(pDst+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EqualRect", func(ctx *ntapi.TrapContext) uint32 {
		r1, r2 := readRect(ctx.Arg(0)), readRect(ctx.Arg(1))
		if win32.EqualRect(&r1, &r2) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InflateRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		rc := readRect(p)
		win32.InflateRect(&rc, dx, dy)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IntersectRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		ok := win32.IntersectRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
		rc := readRect(ctx.Arg(0))
		if win32.IsRectEmpty(&rc) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OffsetRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		dx, dy := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		rc := readRect(p)
		win32.OffsetRect(&rc, dx, dy)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PtInRect", func(ctx *ntapi.TrapContext) uint32 {
		rc := readRect(ctx.Arg(0))
		x, y := int32(ctx.Arg(1)), int32(ctx.Arg(2))
		if win32.PtInRect(&rc, x, y) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetRect", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		l, t, r, b := int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)), int32(ctx.Arg(4))
		rc := win32.Rect{Left: l, Top: t, Right: r, Bottom: b}
		win32.SetRect(&rc, l, t, r, b)
		mem.Write32(p, uint32(rc.Left))
		mem.Write32(p+4, uint32(rc.Top))
		mem.Write32(p+8, uint32(rc.Right))
		mem.Write32(p+12, uint32(rc.Bottom))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetRectEmpty", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		mem.Write32(p, 0)
		mem.Write32(p+4, 0)
		mem.Write32(p+8, 0)
		mem.Write32(p+12, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SubtractRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		ok := win32.SubtractRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnionRect", func(ctx *ntapi.TrapContext) uint32 {
		pDst, pSrc1, pSrc2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		r1, r2 := readRect(pSrc1), readRect(pSrc2)
		dst := win32.Rect{}
		win32.UnionRect(&dst, &r1, &r2)
		mem.Write32(pDst, uint32(dst.Left))
		mem.Write32(pDst+4, uint32(dst.Top))
		mem.Write32(pDst+8, uint32(dst.Right))
		mem.Write32(pDst+12, uint32(dst.Bottom))
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Char / string operations
	// -------------------------------------------------------
	// Helper: read ANSI string from guest
	readAnsi := func(p uint64) string {
		var b []byte
		for i := uint64(0); i < 1024; i++ {
			ch, _ := mem.Read8(p + i)
			if ch == 0 {
				break
			}
			b = append(b, ch)
		}
		return string(b)
	}
	_ = readAnsi
	d.RegisterAutoStubHandler(user32, "CharUpperW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x10000 {
			ctx.SetReturn(uint64(unicode.ToUpper(rune(p))))
		} else {
			for off := uint64(0); ; off += 2 {
				lo, _ := mem.Read16(p + off)
				if lo == 0 {
					break
				}
				up := uint16(unicode.ToUpper(rune(lo)))
				ctx.Mem.Write16(p+off, up)
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x100 {
			ctx.SetReturn(uint64(unicode.ToUpper(rune(p & 0xFF))))
		} else {
			for off := uint64(0); ; off++ {
				b, _ := mem.Read8(p + off)
				if b == 0 {
					break
				}
				ctx.Mem.Write8(p+off, byte(unicode.ToUpper(rune(b))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x10000 {
			ctx.SetReturn(uint64(unicode.ToLower(rune(p))))
		} else {
			for off := uint64(0); ; off += 2 {
				lo, _ := mem.Read16(p + off)
				if lo == 0 {
					break
				}
				ctx.Mem.Write16(p+off, uint16(unicode.ToLower(rune(lo))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p < 0x100 {
			ctx.SetReturn(uint64(unicode.ToLower(rune(p & 0xFF))))
		} else {
			for off := uint64(0); ; off++ {
				b, _ := mem.Read8(p + off)
				if b == 0 {
					break
				}
				ctx.Mem.Write8(p+off, byte(unicode.ToLower(rune(b))))
			}
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperBuffW", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			lo, _ := mem.Read16(p + i*2)
			ctx.Mem.Write16(p+i*2, uint16(unicode.ToUpper(rune(lo))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharUpperBuffA", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			b, _ := mem.Read8(p + i)
			ctx.Mem.Write8(p+i, byte(unicode.ToUpper(rune(b))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerBuffW", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			lo, _ := mem.Read16(p + i*2)
			ctx.Mem.Write16(p+i*2, uint16(unicode.ToLower(rune(lo))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharLowerBuffA", func(ctx *ntapi.TrapContext) uint32 {
		p, n := ctx.Arg(0), ctx.Arg(1)
		for i := uint64(0); i < n; i++ {
			b, _ := mem.Read8(p + i)
			ctx.Mem.Write8(p+i, byte(unicode.ToLower(rune(b))))
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		lo, _ := mem.Read16(p)
		if lo != 0 {
			ctx.SetReturn(p + 2)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		b, _ := mem.Read8(p)
		if b != 0 {
			ctx.SetReturn(p + 1)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharNextExA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1) // (codePage, pCurrentChar, flags)
		b, _ := mem.Read8(p)
		if b != 0 {
			ctx.SetReturn(p + 1)
		} else {
			ctx.SetReturn(p)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevW", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(0), ctx.Arg(1)
		if cur > start+2 {
			ctx.SetReturn(cur - 2)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevA", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(0), ctx.Arg(1)
		if cur > start {
			ctx.SetReturn(cur - 1)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CharPrevExA", func(ctx *ntapi.TrapContext) uint32 {
		start, cur := ctx.Arg(1), ctx.Arg(2)
		if cur > start {
			ctx.SetReturn(cur - 1)
		} else {
			ctx.SetReturn(start)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLetter(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaA", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0) & 0xFF)
		if unicode.IsLetter(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericW", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0))
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharAlphaNumericA", func(ctx *ntapi.TrapContext) uint32 {
		c := rune(ctx.Arg(0) & 0xFF)
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharLowerW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLower(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharLowerA", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLower(rune(ctx.Arg(0) & 0xFF)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharUpperW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsUpper(rune(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsCharUpperA", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsUpper(rune(ctx.Arg(0) & 0xFF)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// OEM ↔ char: identity in Unicode mode
	for _, fn := range []string{"OemToCharA", "OemToCharW", "CharToOemA", "CharToOemW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			src, dst := ctx.Arg(0), ctx.Arg(1)
			if src != 0 && dst != 0 {
				for off := uint64(0); off < 1024; off++ {
					b, _ := mem.Read8(src + off)
					ctx.Mem.Write8(dst+off, b)
					if b == 0 {
						break
					}
				}
			}
			ctx.SetReturn(1)
			return 0
		})
	}
	for _, fn := range []string{"OemToCharBuffA", "OemToCharBuffW", "CharToOemBuffA", "CharToOemBuffW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			src, dst, n := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
			for i := uint64(0); i < n; i++ {
				b, _ := mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
			}
			ctx.SetReturn(1)
			return 0
		})
	}

	// -------------------------------------------------------
	// Clipboard - guest-side store
	// clipStore[format] = HGLOBAL (guest mmap address)
	// clipFormats tracks insertion order for EnumClipboardFormats
	// -------------------------------------------------------
	clipStore := make(map[uint32]uint64) // format -> HGLOBAL
	var clipFormats []uint32             // ordered list of stored formats
	clipSeq := uint32(1)
	clipboardViewerHwnd := uint64(0)
	syncClipboardFromHost := func() {
		out, err := exec.Command("wl-paste", "--no-newline").Output()
		if err != nil || len(out) == 0 {
			// wl-paste not available or clipboard empty - try xclip as fallback
			out, err = exec.Command("xclip", "-selection", "clipboard", "-o").Output()
			if err != nil || len(out) == 0 {
				return
			}
		}
		const cfUnicodeText = 13
		// Properly encode UTF-8 text from host to UTF-16LE for the guest.
		ws := utf16Encode(string(out))
		wide := make([]byte, (len(ws)+1)*2) // +1 for null terminator
		for i, w := range ws {
			wide[i*2] = byte(w)
			wide[i*2+1] = byte(w >> 8)
		}
		addr := hctx.HeapAlloc(uint64(len(wide)), true)
		for i, b := range wide {
			mem.Write8(addr+uint64(i), b)
		}
		if _, exists := clipStore[cfUnicodeText]; !exists {
			clipFormats = append(clipFormats, cfUnicodeText)
		}
		clipStore[cfUnicodeText] = addr
		// Also expose CF_TEXT (1) as ANSI - just the raw UTF-8 bytes null-terminated.
		const cfText = 1
		ansi := make([]byte, len(out)+1)
		copy(ansi, out)
		ansiAddr := hctx.HeapAlloc(uint64(len(ansi)), true)
		for i, b := range ansi {
			mem.Write8(ansiAddr+uint64(i), b)
		}
		if _, exists := clipStore[cfText]; !exists {
			clipFormats = append(clipFormats, cfText)
		}
		clipStore[cfText] = ansiAddr
	}
	pushClipboardToHost := func(hMem uint64, format uint32) {
		if hMem == 0 {
			return
		}
		var text []byte
		switch format {
		case 13: // CF_UNICODETEXT - read null-terminated UTF-16LE from guest
			var ws []uint16
			for off := uint64(0); off < 1<<20; off += 2 {
				w, _ := mem.Read16(hMem + off)
				if w == 0 {
					break
				}
				ws = append(ws, w)
			}
			if len(ws) == 0 {
				return
			}
			text = utf16Decode(ws) // utf16Decode is defined in main.go
		case 1: // CF_TEXT - read null-terminated ANSI string from guest
			var buf bytes.Buffer
			for off := uint64(0); off < 1<<20; off++ {
				b, _ := mem.Read8(hMem + off)
				if b == 0 {
					break
				}
				buf.WriteByte(b)
			}
			if buf.Len() == 0 {
				return
			}
			text = buf.Bytes()
		default:
			return
		}
		cmd := exec.Command("wl-copy")
		cmd.Stdin = bytes.NewReader(text)
		if err := cmd.Run(); err != nil {
			// fallback to xclip
			xc := exec.Command("xclip", "-selection", "clipboard")
			xc.Stdin = bytes.NewReader(text)
			_ = xc.Run()
		}
	}

	d.RegisterAutoStubHandler(user32, "OpenClipboard", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		// Force-close any previous open; the emulated process is always its own clipboard owner.
		win32.CloseClipboard()
		win32.OpenClipboard(hwnd)
		syncClipboardFromHost()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CloseClipboard", func(ctx *ntapi.TrapContext) uint32 {
		win32.CloseClipboard()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EmptyClipboard", func(ctx *ntapi.TrapContext) uint32 {
		clipStore = make(map[uint32]uint64)
		clipFormats = nil
		clipSeq++
		win32.EmptyClipboard()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		hMem := ctx.Arg(1)
		if hMem != 0 {
			if _, exists := clipStore[format]; !exists {
				clipFormats = append(clipFormats, format)
			}
			clipStore[format] = hMem
			clipSeq++
			pushClipboardToHost(hMem, format)
		}
		ctx.SetReturn(hMem)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardData", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		syncClipboardFromHost()
		if h, ok := clipStore[format]; ok {
			ctx.SetReturn(h)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CountClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
		n := len(clipStore)
		if n == 0 {
			n = int(win32.CountClipboardFormats())
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsClipboardFormatAvailable", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		if _, ok := clipStore[format]; ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardOwner", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(win32.GetClipboardOwner())
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetOpenClipboardWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(win32.GetOpenClipboardWindow())
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(clipboardViewerHwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClipboardViewer", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		prev := clipboardViewerHwnd
		clipboardViewerHwnd = hwnd
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ChangeClipboardChain", func(ctx *ntapi.TrapContext) uint32 {
		hWndRemove := ctx.Arg(0)
		hWndNewNext := ctx.Arg(1)
		if clipboardViewerHwnd == hWndRemove {
			clipboardViewerHwnd = hWndNewNext
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "EnumClipboardFormats", func(ctx *ntapi.TrapContext) uint32 {
		prev := uint32(ctx.Arg(0))
		if len(clipFormats) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if prev == 0 {
			ctx.SetReturn(uint64(clipFormats[0]))
			return 0
		}
		for i, f := range clipFormats {
			if f == prev && i+1 < len(clipFormats) {
				ctx.SetReturn(uint64(clipFormats[i+1]))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameA", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		buf := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		name := clipFormatName(format)
		if buf == 0 || cchMax <= 0 || name == "" {
			ctx.SetReturn(0)
			return 0
		}
		b := []byte(name)
		if len(b) >= cchMax {
			b = b[:cchMax-1]
		}
		for i, c := range b {
			ctx.Mem.Write8(buf+uint64(i), c)
		}
		ctx.Mem.Write8(buf+uint64(len(b)), 0)
		ctx.SetReturn(uint64(len(b)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardFormatNameW", func(ctx *ntapi.TrapContext) uint32 {
		format := uint32(ctx.Arg(0))
		buf := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		name := clipFormatName(format)
		if buf == 0 || cchMax <= 0 || name == "" {
			ctx.SetReturn(0)
			return 0
		}
		ws := utf16Encode(name)
		n := len(ws)
		if n >= cchMax {
			n = cchMax - 1
		}
		for i := 0; i < n; i++ {
			ctx.Mem.Write16(buf+uint64(i)*2, ws[i])
		}
		ctx.Mem.Write16(buf+uint64(n)*2, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipboardSequenceNumber", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(clipSeq))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPriorityClipboardFormat", func(ctx *ntapi.TrapContext) uint32 {
		// pPriorityList = arg0 array of UINT formats, cFormats = arg1
		pList := ctx.Arg(0)
		cFormats := int(ctx.Arg(1))
		for i := 0; i < cFormats; i++ {
			f, _ := ctx.Mem.Read32(pList + uint64(i)*4)
			if _, ok := clipStore[uint32(f)]; ok {
				ctx.SetReturn(uint64(f))
				return 0
			}
		}
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1 = no matching format
	})
	d.RegisterAutoStubHandler(user32, "RegisterClipboardFormatA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		ctx.SetReturn(registerClipFmt(name))
		return 0
	})

	// -------------------------------------------------------
	// Keyboard / input
	// -------------------------------------------------------
	keyboardState := make([]byte, 256)
	d.RegisterAutoStubHandler(user32, "GetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		for i := uint64(0); i < 256; i++ {
			ctx.Mem.Write8(p+i, keyboardState[i])
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetKeyboardState", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetKeyboardState(LPBYTE lpKeyState)
		// ReactOS: win32ss/user/ntuser/input.c
		p := ctx.Arg(0)
		if p != 0 {
			for i := uint64(0); i < 256; i++ {
				b, _ := ctx.Mem.Read8(p + i)
				keyboardState[i] = b
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardType", func(ctx *ntapi.TrapContext) uint32 {
		switch ctx.Arg(0) {
		case 0:
			ctx.SetReturn(4) // enhanced keyboard
		case 1:
			ctx.SetReturn(0) // subtype
		case 2:
			ctx.SetReturn(101) // function keys
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutList", func(ctx *ntapi.TrapContext) uint32 {
		n := ctx.Arg(0)
		p := ctx.Arg(1)
		if p != 0 && n >= 1 {
			ctx.Mem.Write64(p, 0x04090409)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			layout := "00000409"
			for i, ch := range layout {
				ctx.Mem.Write8(p+uint64(i), byte(ch))
			}
			ctx.Mem.Write8(p+8, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyboardLayoutNameW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			layout := "00000409"
			for i, ch := range layout {
				ctx.Mem.Write16(p+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(p+16, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ActivateKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x04090409)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnloadKeyboardLayout", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnloadKeyboardLayout(HKL hkl)
		// ReactOS: win32ss/user/ntuser/kbdlayout.c
		hkl := ctx.Arg(0)
		ravelog.Logf("[user32] UnloadKeyboardLayout hkl=0x%x\n", hkl)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"LoadKeyboardLayoutA", "LoadKeyboardLayoutW", "LoadKeyboardLayoutEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x04090409)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetKBCodePage", func(ctx *ntapi.TrapContext) uint32 {
		// UINT GetKBCodePage(void)
		// ReactOS: win32ss/user/user32/misc/misc.c
		// Returns the OEM code page for the system
		ctx.SetReturn(1252) // Windows-1252 Western European
		return 0
	})
	// VkKeyScan: map ASCII char to VK | (shiftState << 8)
	vkKeyScanChar := func(c rune) uint64 {
		if c >= '0' && c <= '9' {
			return uint64(c)
		}
		if c >= 'a' && c <= 'z' {
			return uint64(c - 32)
		} // VK_A..VK_Z = 0x41..0x5A
		if c >= 'A' && c <= 'Z' {
			return uint64(c) | (1 << 8)
		} // shifted
		return uint64(0xFFFF) // not found
	}
	d.RegisterAutoStubHandler(user32, "VkKeyScanA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFF)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "VkKeyScanExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkKeyScanChar(rune(ctx.Arg(0) & 0xFFFF)))
		return 0
	})
	for _, fn := range []string{"MapVirtualKeyA", "MapVirtualKeyExA", "MapVirtualKeyExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetKeyNameTextA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write8(p, 'K')
			ctx.Mem.Write8(p+1, 'e')
			ctx.Mem.Write8(p+2, 'y')
			ctx.Mem.Write8(p+3, 0)
		}
		ctx.SetReturn(3)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetKeyNameTextW", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(1)
		if p != 0 {
			ctx.Mem.Write16(p, 'K')
			ctx.Mem.Write16(p+2, 'e')
			ctx.Mem.Write16(p+4, 'y')
			ctx.Mem.Write16(p+6, 0)
		}
		ctx.SetReturn(3)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OemKeyScan", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0) & 0xFF)
		return 0
	})
	for _, fn := range []string{"ToAscii", "ToAsciiEx", "ToUnicode", "ToUnicodeEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "keybd_event", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "mouse_event", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendInput", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})

	// -------------------------------------------------------
	// Message / queue
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "PostQuitMessage", func(ctx *ntapi.TrapContext) uint32 {
		exitCode := ctx.Arg(0)
		ravelog.Logf("[user32] PostQuitMessage(%d)\n", exitCode)
		hctx.enqueueMessage(ctx.CPU, newQueuedMsg(hctx, 0, 0x0012, exitCode, 0)) // WM_QUIT
		return 0
	})
	for _, fn := range []string{"GetInputState", "GetQueueStatus"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "InSendMessage", func(ctx *ntapi.TrapContext) uint32 {
		_, active := currentSentMessage(ctx.CPU)
		if active {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "InSendMessageEx", func(ctx *ntapi.TrapContext) uint32 {
		request, active := currentSentMessage(ctx.CPU)
		if !active {
			ctx.SetReturn(0) // ISMEX_NOSEND
		} else if request.replied.Load() {
			ctx.SetReturn(0x9) // ISMEX_SEND | ISMEX_REPLIED
		} else {
			ctx.SetReturn(0x1) // ISMEX_SEND
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ReplyMessage", func(ctx *ntapi.TrapContext) uint32 {
		request, active := currentSentMessage(ctx.CPU)
		if !active {
			ctx.SetReturn(0)
			return 0
		}
		request.reply(ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "QuerySendMessage", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented - returns 0 if not in a SendMessage
		ctx.SetReturn(0)
		return 0
	})
	runMsgWait := func(
		ctx *ntapi.TrapContext,
		pump *sentMessagePumpCall,
		nCount, pHandles, milliseconds, wakeMask uint64,
		waitAll, alertable, inputAvailableFlag bool,
	) uint32 {
		const (
			waitObject0      = uint64(0)
			waitTimeout      = uint64(0x102)
			waitIOCompletion = uint64(0xC0)
			waitFailed       = uint64(0xFFFFFFFF)
		)
		if nCount > 63 || nCount > 0 && pHandles == 0 {
			setUserLastError(ctx, 87) // ERROR_INVALID_PARAMETER
			ctx.SetReturn(waitFailed)
			return 0
		}
		values := []ntapi.Handle{}
		if nCount > 0 {
			values = readWin32HandleArray(ctx.Mem, pHandles, nCount, ctx.State != nil && ctx.State.Is32)
			if len(values) != int(nCount) {
				setUserLastError(ctx, 87)
				ctx.SetReturn(waitFailed)
				return 0
			}
			for _, handle := range values {
				if hctx.Handles.Get(handle) == nil {
					setUserLastError(ctx, 6) // ERROR_INVALID_HANDLE
					ctx.SetReturn(waitFailed)
					return 0
				}
			}
		}
		tid := uint32(1)
		if hctx.TMPtr != nil && *hctx.TMPtr != nil {
			tid = uint32((*hctx.TMPtr).GetTID(ctx.CPU))
		}
		timeout := msToTimeout(milliseconds)
		if timeout >= 0 && pump.waitDeadline.IsZero() {
			pump.waitDeadline = time.Now().Add(timeout)
		}
		remaining := func() time.Duration {
			if timeout < 0 {
				return -1
			}
			value := time.Until(pump.waitDeadline)
			if value < 0 {
				return 0
			}
			return value
		}
		pollHandles := func() uint64 {
			if len(values) == 0 {
				return waitTimeout
			}
			return waitMultipleFallbackWin32(hctx.Handles, values, tid, waitAll, 0)
		}
		for {
			if dispatchPendingSentMessage(ctx, pump) {
				return 0
			}
			if alertable {
				result, apcs := ntapi.ObjMgr.WaitEx(nil, false, uint64(tid), 0, true)
				if uint64(result) == waitIOCompletion {
					dispatchAlertableAPCs(tid, apcs)
					ctx.SetReturn(waitIOCompletion)
					return 0
				}
			}
			waylandInput := false
			if wlDisplay != nil {
				evt, _ := wlDisplay.Poll()
				if evt != wl.EventNone {
					if dispatchWl != nil {
						dispatchWl(evt)
					} else {
						waylandInput = true
					}
				}
			}
			inputAvailable := hctx.MsgQueue.hasWakeMask(
				ctx.CPU, uint32(wakeMask), inputAvailableFlag,
			) || wakeMask != 0 && waylandInput
			if !waitAll {
				result := pollHandles()
				if result != waitTimeout {
					if result == waitFailed {
						setUserLastError(ctx, 6) // ERROR_INVALID_HANDLE
					}
					ctx.SetReturn(result)
					return 0
				}
				if inputAvailable {
					hctx.MsgQueue.markWakeMaskSeen(ctx.CPU, uint32(wakeMask))
					ctx.SetReturn(waitObject0 + nCount)
					return 0
				}
			} else if inputAvailable {
				if nCount == 0 {
					hctx.MsgQueue.markWakeMaskSeen(ctx.CPU, uint32(wakeMask))
					ctx.SetReturn(waitObject0)
					return 0
				}
				result := pollHandles()
				if result == waitObject0 {
					hctx.MsgQueue.markWakeMaskSeen(ctx.CPU, uint32(wakeMask))
					ctx.SetReturn(waitObject0)
					return 0
				}
				if result != waitTimeout {
					if result == waitFailed {
						setUserLastError(ctx, 6)
					}
					ctx.SetReturn(result)
					return 0
				}
			}
			waitFor := remaining()
			if waitFor == 0 {
				ctx.SetReturn(waitTimeout)
				return 0
			}
			if waitFor < 0 || waitFor > time.Millisecond {
				waitFor = time.Millisecond
			}
			hctx.MsgQueue.waitWakeMask(
				ctx.CPU, uint32(wakeMask), inputAvailableFlag, waitFor,
			)
		}
	}
	var runMsgWaitForMultipleObjects func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runMsgWaitForMultipleObjects = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		// Args: nCount, pHandles, fWaitAll, dwMilliseconds, dwWakeMask
		return runMsgWait(
			ctx, pump,
			pump.arguments[0], pump.arguments[1], pump.arguments[3], pump.arguments[4],
			pump.arguments[2] != 0, false, false,
		)
	}
	d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)}
		pump := captureSentMessagePump(ctx, arguments, 5, runMsgWaitForMultipleObjects)
		return runMsgWaitForMultipleObjects(ctx, pump)
	})
	var runMsgWaitForMultipleObjectsEx func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runMsgWaitForMultipleObjectsEx = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		// Args: nCount, pHandles, dwMilliseconds, dwWakeMask, dwFlags
		flags := pump.arguments[4]
		return runMsgWait(
			ctx, pump,
			pump.arguments[0], pump.arguments[1], pump.arguments[2], pump.arguments[3],
			flags&0x1 != 0, flags&0x2 != 0, flags&0x4 != 0,
		)
	}
	d.RegisterAutoStubHandler(user32, "MsgWaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)}
		pump := captureSentMessagePump(ctx, arguments, 5, runMsgWaitForMultipleObjectsEx)
		return runMsgWaitForMultipleObjectsEx(ctx, pump)
	})
	d.RegisterAutoStubHandler(user32, "WaitMessage", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL WaitMessage(void) - blocks until message available
		if hctx.queueCount(ctx.CPU) > 0 {
			ctx.SetReturn(1)
			return 0
		}
		if wlDisplay != nil {
			if event, _ := wlDisplay.Poll(); event != wl.EventNone && dispatchWl != nil {
				dispatchWl(event)
			}
		}
		if hctx.queueCount(ctx.CPU) == 0 {
			hctx.MsgQueue.wait(ctx.CPU, 16*time.Millisecond)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "WaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD WaitForInputIdle(HANDLE hProcess, DWORD dwMilliseconds)
		// ReactOS: win32ss/user/ntuser/input.c
		// 0 = wait satisfied, WAIT_TIMEOUT=258
		// Since we're single-process, the app is always "idle"
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMessagePos", func(ctx *ntapi.TrapContext) uint32 {
		state := hctx.MessageMetadata.get(ctx.CPU)
		ctx.SetReturn(uint64(packMessagePos(state.x, state.y)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMessageTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(hctx.MessageMetadata.get(ctx.CPU).messageTime))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMessageExtraInfo", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.MessageMetadata.get(ctx.CPU).extraInfo)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetMessageExtraInfo", func(ctx *ntapi.TrapContext) uint32 {
		// LPARAM SetMessageExtraInfo(LPARAM lParam) - returns previous value
		ctx.SetReturn(hctx.MessageMetadata.setExtraInfo(ctx.CPU, ctx.Arg(0)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "PostMessageA", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/message.c NtUserPostMessage
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		if hwnd == 0 {
			hctx.enqueueMessage(ctx.CPU, newQueuedMsg(hctx, 0, msg, wParam, lParam))
		} else if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, msg, wParam, lParam))
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, msg, wParam, lParam))
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"PostThreadMessageA", "PostThreadMessageW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			tid := int(ctx.Arg(0))
			message := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			if hctx.TMPtr == nil || *hctx.TMPtr == nil {
				ctx.SetReturn(0)
				return 0
			}
			targetCPU, ok := (*hctx.TMPtr).GetCPU(tid)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			hctx.enqueueMessage(targetCPU, newQueuedMsg(hctx, 0, message, wParam, lParam))
			ctx.SetReturn(1)
			return 0
		})
	}
	var peekACount int
	var peekACaller uint32
	// autoClickAt tracks how many "advance" clicks we've injected into the
	// installer's spin loop. Each click index corresponds to a Wise wizard page.
	// Injected when the queue has been empty for a sustained stretch.
	var autoClickAt int    // index of next click to inject
	var peekEmptyRun int   // consecutive empty-queue returns
	var wiseTimerFires int // WM_TIMER dispatches seen (need ≥3 before injecting)
	// Wait for enough WM_TIMER fires (≥3) before auto-clicking so the Wise engine
	// fully initializes before we advance the wizard. Fire #3 happens at ~2.5M
	// empty PeekMessageA calls; after that use a smaller idle gap per click.
	const autoClickIdleFirst = 500_000 // idle gap before 1st click (post-timers)
	const autoClickIdleNext = 200_000  // idle gap between subsequent clicks
	var runPeekMessageA func(*ntapi.TrapContext, *sentMessagePumpCall) uint32
	runPeekMessageA = func(ctx *ntapi.TrapContext, pump *sentMessagePumpCall) uint32 {
		flushDestroyedWindows()
		// PeekMessageA: identical to PeekMessageW - our messages are internal, no A/W distinction
		pMsg := pump.arguments[0]
		hwndFilter := pump.arguments[1]
		minMessage := uint32(pump.arguments[2])
		maxMessage := uint32(pump.arguments[3])
		remove := pump.arguments[4]&0x1 != 0
		if dispatchPendingSentMessage(ctx, pump) {
			return 0
		}
		peekACount++
		// Dump a stack slice once to find who is calling the drain repeatedly
		if peekACount == 10 && ctx.State != nil && ctx.State.Is32 {
			rsp := ctx.CPU.GetSP()
			retAddr, _ := mem.Read32(rsp)
			peekACaller = retAddr
			ebxNow := uint64(0)
			if rrx, okr := ctx.CPU.(ntapi.RegisterReader); okr {
				ebxNow = rrx.ReadReg(3)
			}
			ravelog.Logf("[msg] PeekMessageA steady-state caller=0x%x rsp=0x%x EBX=0x%x\n", retAddr, rsp, ebxNow)
			// Print 32 stack words to find the full call chain
			for i := uint64(0); i < 32; i++ {
				v, _ := mem.Read32(rsp + i*4)
				ravelog.Logf("[stack] [rsp+%d]=0x%08x\n", i*4, v)
			}
			// Dump the guest code around the caller and its callers, so the
			// spinning main loop can be disassembled offline to find the real
			// render gate. RAVEN_DUMP_LOOP gates this diagnostic.
			if os.Getenv("RAVEN_DUMP_LOOP") != "" {
				dumpTargets := []uint64{uint64(retAddr)}
				for i := uint64(0); i < 32; i++ {
					v, _ := mem.Read32(rsp + i*4)
					if v >= 0x400000 && v < 0x820000 { // guest code range
						dumpTargets = append(dumpTargets, uint64(v))
					}
				}
				seen := map[uint64]bool{}
				for _, t := range dumpTargets {
					base := t &^ 0xF
					if base < 0x80 || seen[base] {
						continue
					}
					seen[base] = true
					lo := base - 0x80
					for off := uint64(0); off < 0x120; off += 16 {
						var bs [16]byte
						for j := range bs {
							bs[j], _ = mem.Read8(lo + off + uint64(j))
						}
						ravelog.Logf("[code-dump] 0x%x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
							lo+off, bs[0], bs[1], bs[2], bs[3], bs[4], bs[5], bs[6], bs[7], bs[8], bs[9], bs[10], bs[11], bs[12], bs[13], bs[14], bs[15])
					}
				}
			}
		}
		if peekACount%500 == 0 {
			ravelog.Logf("[msg] PeekMessageA call #%d (queue=%d) caller=0x%x\n", peekACount, hctx.queueCount(ctx.CPU), peekACaller)
		}
		_ = peekACaller

		checkTimers(ctx.CPU) // fire any expired timers before checking the queue

		if wlDisplay != nil {
			evt, err := wlDisplay.Poll()
			if err != nil {
				ravelog.Logf("[wl] Poll error: %v\n", err)
			}
			if evt == wl.EventClose {
				dispatchWaylandClose()
			} else if evt != wl.EventNone {
				for {
					ke, ok := wlDisplay.PollKey()
					if !ok {
						break
					}
					target := hctx.FocusHwnd
					if target == 0 {
						target = hctx.MainHWND
					}
					if ke.Pressed {
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0100, uint64(ke.VK), 0))
						if ke.Char >= 0x20 || ke.Char == '\r' || ke.Char == '\b' || ke.Char == '\t' {
							hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0102, uint64(ke.Char), 0))
						}
					} else {
						hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, 0x0101, uint64(ke.VK), 0))
					}
				}
			}
			if evt == wl.EventMouse {
				if dispatchWl != nil {
					dispatchWl(evt)
				}
			}
		}

		pruneValidatedPaintMessages(ctx.CPU)
		match := messageMatches(hwndFilter, minMessage, maxMessage)
		if hctx.MsgQueue.count(ctx.CPU) != 0 && !hctx.MsgQueue.contains(func(message queuedMsg) bool {
			return messageOwnedBy(message, ctx.CPU) && match(message)
		}) {
			peekEmptyRun = 0
			ctx.SetReturn(0)
			return 0
		}
		if !hctx.MsgQueue.contains(func(message queuedMsg) bool {
			return messageOwnedBy(message, ctx.CPU) && match(message)
		}) {
			// Count consecutive empty-queue returns. Once the Wise engine has fully
			// initialized (≥3 WM_TIMER fires), inject "Next page" events to advance
			// the wizard without user interaction.
			peekEmptyRun++
			idleThreshold := autoClickIdleFirst
			if autoClickAt > 0 {
				idleThreshold = autoClickIdleNext
			}
			if wiseTimerFires >= 3 && peekEmptyRun >= idleThreshold && autoClickAt < 12 {
				peekEmptyRun = 0
				autoClickAt++
				hw := hctx.MainHWND
				// WM_USER+1 (0x401) is the Wise engine "Next page" signal.
				// Also send WM_LBUTTONDOWN/UP at a typical "Next >" button position
				// (660, 550) as a fallback for installers that use hit-testing.
				const (
					wmUser1       = 0x0401
					wmLButtonDown = 0x0201
					wmLButtonUp   = 0x0202
					wmCommand     = 0x0111
				)
				lp := uint64((550 << 16) | 660) // MAKELPARAM(660, 550)
				ravelog.Logf("[auto] inject page-advance #%d -> WM_USER+1 + WM_LBUTTONDOWN(660,550) hwnd=0x%x\n",
					autoClickAt, hw)
				hctx.enqueueMessage(nil,
					newQueuedMsg(hctx, hw, wmUser1, 0, 0),
					newQueuedMsg(hctx, hw, wmLButtonDown, 1, lp),
					newQueuedMsg(hctx, hw, wmLButtonUp, 0, lp),
				)
				// On the 4th wizard page ("Ready to Install"), the user would normally
				// click the "Install" button which sends WM_COMMAND(IDOK=1). Inject this
				// explicitly so the Wise engine sets its install-confirmed flag, which
				// the script checks after the admin-rights test before extracting files.
				if autoClickAt == 4 {
					ravelog.Logf("[auto] inject WM_COMMAND(IDOK=1) for Install button -> hwnd=0x%x\n", hw)
					hctx.enqueueMessage(nil,
						newQueuedMsg(hctx, hw, wmCommand, 1, 0),
					)
				}
			}
			ctx.SetReturn(0)
			return 0
		}
		peekEmptyRun = 0
		_, delivered := hctx.MsgQueue.deliver(ctx.CPU, match,
			func(msg queuedMsg) bool { return remove && msg.message != 0x000F },
			func(msg queuedMsg) bool { return pMsg != 0 && writeMsg(ctx, pMsg, msg) })
		if !delivered {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	}
	d.RegisterAutoStubHandler(user32, "PeekMessageA", func(ctx *ntapi.TrapContext) uint32 {
		arguments := [5]uint64{ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)}
		pump := captureSentMessagePump(ctx, arguments, 5, runPeekMessageA)
		return runPeekMessageA(ctx, pump)
	})
	d.RegisterAutoStubHandler(user32, "DispatchMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// MSG layout: use arch-aware readMsg
		hwnd, message, wParam, lParam := readMsg(ctx, pMsg)
		if dispatchTimerCallback(ctx, pMsg, hwnd, message, wParam, lParam) {
			return 0
		}
		if (message == 0x000F || message == 0x0014) &&
			!windowHierarchyVisible(hwnd, hwndChildren) {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			ctx.SetReturn(0)
			return 0
		}
		if message != 0x0002 && message != 0x0082 &&
			windowOrAncestorDestroyPending(hwnd, destroyPending, hwndChildren) {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			win32.Global.Validate(hwnd)
			ctx.SetReturn(0)
			return 0
		}

		// Try built-in control first
		if _, isChild := hwndChildren[hwnd]; isChild && !hasWindowSubclass(hwnd) {
			result, handled := builtinWndProc(hwnd, message, wParam, lParam)
			if os.Getenv("RAVEN_TRACE_CLICK") != "" && message == 0x004E {
				ravelog.Logf("[notify-dispatch] DispatchMessageA hwnd=0x%x WM_NOTIFY builtinHandled=%v (handled swallows it before NPP proc)\n", hwnd, handled)
			}
			if handled {
				if builtinMessageNeedsCommit(message) {
					requestCommit(true)
				}
				ctx.SetReturn(result)
				return 0
			}
		}

		wndProc, ok := hwndWndProc[hwnd]
		if !ok || wndProc == 0 {
			// Fallback: recover WndProc via class atom.
			if atom, hasAtom := hctx.HwndClassAtom[hwnd]; hasAtom {
				if recovered, okA := hctx.AtomWndProc[atom]; okA && recovered != 0 {
					wndProc = recovered
					ok = true
					hwndWndProc[hwnd] = wndProc
				}
			}
		}
		if !ok || wndProc == 0 {
			ravelog.Logf("[dispatch] DispatchMessageA: no WndProc for hwnd=0x%x msg=0x%x\n", hwnd, message)
			ctx.SetReturn(0)
			return 0
		}
		if message == 0x0082 && destroyPending[hwnd] {
			destroyDelivered[hwnd] = true
		}

		is32 := ctx.State != nil && ctx.State.Is32
		ravelog.Logf("[dispatch] DispatchMessageA: hwnd=0x%x msg=0x%x -> WndProc=0x%x is32=%v\n", hwnd, message, wndProc, is32)
		if message == 0x0113 { // WM_TIMER dispatched to guest WndProc
			wiseTimerFires++
			ravelog.Logf("[wise] WM_TIMER dispatch #%d\n", wiseTimerFires)
		}
		if is32 {
			rr := ctx.CPU.(ntapi.RegisterReader)
			rw := ctx.CPU.(ntapi.RegisterWriter)
			rsp := rr.ReadReg(4)
			retAddr32, _ := mem.Read32(rsp)
			ravelog.Logf("[dispatch] DispatchMessageA PE32: rsp=0x%x retAddr=0x%x -> SyncCallWndProc\n", rsp, retAddr32)
			rsp += 4 + 1*4 // skip retAddr + 1 arg (pMsg)
			rw.WriteReg(4, rsp)
			hctx.SyncCallWndProc(ctx, wndProc, hwnd, message, wParam, lParam, uint64(retAddr32))
			return 0
		}

		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		rw.WriteReg(1, hwnd)            // RCX
		rw.WriteReg(2, uint64(message)) // RDX
		rw.WriteReg(8, wParam)          // R8
		rw.WriteReg(9, lParam)          // R9

		ctx.CPU.SetPC(wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SendMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		ownerCPU := hctx.windowCPU(hwnd)
		if ownerCPU != nil && ownerCPU != ctx.CPU {
			request := newSynchronousSendRequest(hwnd, msg, wParam, lParam)
			request.sender = ctx.CPU
			if !hctx.MsgQueue.enqueueSynchronous(ownerCPU, request) {
				ctx.SetReturn(0)
				return 0
			}
			if !beginCrossThreadSend(ctx, request) {
				ctx.SetReturn(request.wait())
			}
			return 0
		}
		if !hasWindowSubclass(hwnd) {
			if result, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				if builtinMessageNeedsCommit(msg) {
					requestCommit(true)
				}
				ctx.SetReturn(result)
				return 0
			}
		}
		wp, hasWP := hwndWndProc[hwnd]
		if !hasWP || wp == 0 {
			// Fallback: recover WndProc via class atom.
			if atom, hasAtom := hctx.HwndClassAtom[hwnd]; hasAtom {
				if recovered, ok := hctx.AtomWndProc[atom]; ok && recovered != 0 {
					wp = recovered
					hasWP = true
					hwndWndProc[hwnd] = wp
				}
			}
		}
		if !hasWP || wp == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okW && okR {
			rsp := rr.ReadReg(4)
			retAddr, _ := mem.Read64(rsp)
			syncStack := hctx.syncStack(ctx)
			*syncStack = append(*syncStack, syncDispatchFrame{
				queue: []syncDispatch{}, retAddr: retAddr,
				hwnd: hwnd, returnWndProcResult: true,
			})
			rsp -= 48
			mem.Write64(rsp, hctx.SyncTrampoline)
			rw.WriteReg(4, rsp)
			rw.WriteReg(1, hwnd)
			rw.WriteReg(2, uint64(msg))
			rw.WriteReg(8, wParam)
			rw.WriteReg(9, lParam)
			ctx.CPU.SetPC(wp)
			ctx.ReturnOverridden = true
			ctx.PCRedirected = true
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	// SendMessageTimeoutA/W - ReactOS: win32ss/user/ntuser/message.c co_IntSendMessageTimeout
	// Signature: LRESULT SendMessageTimeoutW(HWND,UINT,WPARAM,LPARAM,UINT fuFlags,UINT uTimeout,PDWORD_PTR lpdwResult)
	sendMsgTimeoutImpl := func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		hwnd := ctx.Arg(0)
		msg := uint32(ctx.Arg(1))
		wParam := ctx.Arg(2)
		lParam := ctx.Arg(3)
		// Arg(4) = fuFlags, Arg(5) = uTimeout (ignored - we dispatch synchronously)
		lpdwResult := ctx.Arg(6)

		var result uint64
		if !hasWindowSubclass(hwnd) {
			if res, handled := builtinWndProc(hwnd, msg, wParam, lParam); handled {
				result = res
			} else if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, msg, wParam, lParam))
			} else if _, ok := hwndChildren[hwnd]; ok {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, msg, wParam, lParam))
			}
		} else if hwnd == hctx.MainHWND || hwnd == 0xFFFF || hwnd == 0xFFFFFFFFFFFFFFFF {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hctx.MainHWND, msg, wParam, lParam))
		} else if _, ok := hwndChildren[hwnd]; ok {
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, msg, wParam, lParam))
		}
		if lpdwResult != 0 {
			mem.Write64(lpdwResult, result)
		}
		ctx.SetReturn(1) // nonzero = success
		return 0
	}
	d.RegisterAutoStubHandler(user32, "SendMessageTimeoutA", sendMsgTimeoutImpl)
	d.RegisterAutoStubHandler(user32, "SendMessageTimeoutW", sendMsgTimeoutImpl)
	for _, fn := range []string{
		"SendMessageCallbackA", "SendMessageCallbackW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SendNotifyMessageA", "SendNotifyMessageW"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			msg := uint32(ctx.Arg(1))
			wParam := ctx.Arg(2)
			lParam := ctx.Arg(3)
			target := hwnd
			if target == 0 || target == 0xFFFF || target == 0xFFFFFFFFFFFFFFFF {
				target = hctx.MainHWND
			}
			if target == hctx.MainHWND || hwndChildren[target] != nil {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, msg, wParam, lParam))
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "SendDlgItemMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hctx.SetCurrentCPU(ctx.CPU)
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				if result, handled := builtinWndProc(h, msg, wParam, lParam); handled {
					ctx.SetReturn(result)
					return 0
				}
				if wp, ok := hwndWndProc[h]; ok && wp != 0 {
					hctx.enqueueMessage(nil, newQueuedMsg(hctx, h, msg, wParam, lParam))
				}
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TranslateMessageEx", func(ctx *ntapi.TrapContext) uint32 {
		pMsg := ctx.Arg(0)
		if pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		hwnd, message, wParam, lParam := readMsg(ctx, pMsg)
		if message != 0x0100 && message != 0x0104 {
			ctx.SetReturn(0)
			return 0
		}
		vk := uint32(wParam)
		ch, ok := pendingKeyChars[vk]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		delete(pendingKeyChars, vk)
		charMessage := uint32(0x0102)
		if message == 0x0104 {
			charMessage = 0x0106
		}
		hctx.enqueueMessage(nil, newQueuedMsg(hctx, hwnd, charMessage, uint64(ch), lParam))
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"BroadcastSystemMessage", "BroadcastSystemMessageA",
		"BroadcastSystemMessageW", "BroadcastSystemMessageExA", "BroadcastSystemMessageExW",
		"CsrBroadcastSystemMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}

	// -------------------------------------------------------
	// Window state / info
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "IsIconic", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		var style uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			style = m[-16]
		}
		if style&0x20000000 != 0 { // WS_MINIMIZE
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsZoomed", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		var style uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			style = m[-16]
		}
		if style&0x01000000 != 0 { // WS_MAXIMIZE
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowEnabled", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if !isKnownWindow(hwnd) {
			ctx.SetReturn(0)
			return 0
		}
		if isWindowDisabled(hwnd) {
			ctx.SetReturn(0)
		} else {
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowUnicode", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserIsWindowUnicode
		// We register all classes as Unicode, so return TRUE for any valid HWND.
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwnd == 0x00050000 {
			ctx.SetReturn(1)
			return 0
		}
		if _, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsMenu", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsGUIThread", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsGUIThread(BOOL bConvert)
		// ReactOS: NtUserGetThreadState(12)
		// We always run in a GUI context.
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsHungAppWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsHungAppWindow(HWND)
		// ReactOS: NtUserQueryWindow -> IsHungAppWindow
		// Our app is never hung (single-threaded, synchronous execution).
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWindowInDestroy", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Returns TRUE if the window is being destroyed.
		// Check if the HWND still exists in the window manager.
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) == nil && hwnd != 0 {
			ctx.SetReturn(1) // window not in table -> likely being destroyed
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsServerSideWindow", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. We never use server-side windows.
		_ = ctx.Arg(0) // hWnd
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsSETEnabled", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Software Enhancement Technology - always disabled.
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AnyPopup", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AnyPopup() - returns TRUE if any visible popup/owned window exists
		// ReactOS: win32ss/user/ntuser/window.c
		found := false
		for _, h := range win32.Global.AllWindows() {
			wnd := win32.Global.Get(h)
			if wnd != nil && wnd.Parent != 0 && wnd.Style&0x10000000 != 0 { // WS_VISIBLE
				found = true
				break
			}
		}
		if found {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c IntGetActiveWindow
		if hctx.ActiveHwnd != 0 {
			ctx.SetReturn(hctx.ActiveHwnd)
		} else {
			ctx.SetReturn(hctx.MainHWND)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetActiveWindow", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/focus.c co_IntSetActiveWindow
		prev := hctx.ActiveHwnd
		if prev == 0 {
			prev = hctx.MainHWND
		}
		hctx.ActiveHwnd = ctx.Arg(0)
		ctx.SetReturn(prev)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCapture", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/msgqueue.c IntGetCapture
		ctx.SetReturn(hctx.MouseCapture)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetLastActivePopup", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetAncestor", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, gaFlags := ctx.Arg(0), ctx.Arg(1)
		switch gaFlags {
		case 2, 3:
			ctx.SetReturn(hctx.MainHWND) // GA_ROOT / GA_ROOTOWNER
		default:
			if cs, ok := hwndChildren[hwnd]; ok {
				ctx.SetReturn(cs.parentHWND)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CloseWindow", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL CloseWindow(HWND) - minimizes the specified window.
		// ReactOS: NtUserShowWindow(hwnd, SW_MINIMIZE)
		// We don't implement minimization, but we can mark it as valid.
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "OpenIcon", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL OpenIcon(HWND) - restores a minimized window.
		// ReactOS: NtUserShowWindow(hwnd, SW_RESTORE)
		hwnd := ctx.Arg(0)
		if win32.Global.Get(hwnd) != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "BringWindowToTop", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL BringWindowToTop(HWND hWnd) - equivalent to SetWindowPos(SWP_NOMOVE|SWP_NOSIZE)
		// ReactOS: win32ss/user/ntuser/winpos.c
		hwnd := ctx.Arg(0)
		if hwnd == hctx.MainHWND || hwndChildren[hwnd] != nil {
			hctx.reorderZOrder(hwnd, 0)
			hctx.ActiveHwnd = hwnd
			queuePaint(hwnd)
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowWindowAsync", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ShowWindowAsync(HWND hWnd, int nCmdShow)
		// ReactOS: posts message instead of synchronous ShowWindow
		hwnd := ctx.Arg(0)
		nCmd := uint32(ctx.Arg(1))
		ravelog.Logf("[user32] ShowWindowAsync hwnd=0x%x cmd=%d\n", hwnd, nCmd)
		if win32.Global.Get(hwnd) == nil && hwndChildren[hwnd] == nil {
			ctx.SetReturn(0)
			return 0
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.visible = nCmd != 0 // SW_HIDE=0
		}
		syncWindowVisibleStyle(hwnd, nCmd != 0)
		if nCmd != 0 {
			queuePaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ShowOwnedPopups", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ShowOwnedPopups(HWND hWndOwner, BOOL fShow)
		// ReactOS: win32ss/user/ntuser/window.c
		owner := ctx.Arg(0)
		fShow := ctx.Arg(1) != 0
		for _, h := range win32.Global.AllWindows() {
			wnd := win32.Global.Get(h)
			if wnd != nil && wnd.Parent == owner {
				if fShow {
					wnd.Style |= 0x10000000 // WS_VISIBLE
				} else {
					wnd.Style &^= 0x10000000
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowThreadProcessId", func(ctx *ntapi.TrapContext) uint32 {
		pPid := ctx.Arg(1)
		if pPid != 0 {
			ctx.Mem.Write32(pPid, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var text string
		if cs, ok := hwndChildren[hwnd]; ok {
			text = cs.text
		} else if hwnd == hctx.MainHWND {
			text = hctx.MainTitle
		}
		if pBuf != 0 && nMax > 0 {
			bs := []byte(text)
			if len(bs) >= nMax {
				bs = bs[:nMax-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(pBuf+uint64(i), b)
			}
			ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
		}
		ctx.SetReturn(uint64(len(text)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowTextLengthA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		if cs, ok := hwndChildren[hwnd]; ok {
			ctx.SetReturn(uint64(len(cs.text)))
			return 0
		}
		if hwnd == hctx.MainHWND {
			ctx.SetReturn(uint64(len(hctx.MainTitle)))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowTextA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, p := ctx.Arg(0), ctx.Arg(1)
		text := readAnsi(p)
		ravelog.Logf("[user32] SetWindowTextA hwnd=0x%x text=%q\n", hwnd, text)
		if hwnd == hctx.MainHWND {
			hctx.MainTitle = text
		}
		if cs, ok := hwndChildren[hwnd]; ok {
			cs.text = text
		}
		hwndTitle[hwnd] = text
		if win := hctx.WlWindows[hwnd]; win != nil && wlDisplay != nil {
			wlDisplay.SetWindowTitle(win, text)
			requestWindowRepaint(hwnd)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		if val == 0 {
			val = win32.Global.GetLong(hwnd, index)
		}
		val = applyWindowEnabledStyle(hwnd, index, val)
		if index == -4 && val == 0 {
			val = hwndWndProc[hwnd]
			if val == 0 && isBuiltinControl(hwnd) {
				val = builtinControlWndProc
			}
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowLongA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index]
		if old == 0 {
			old = win32.Global.GetLong(hwnd, index)
		}
		m[index] = newVal
		win32.Global.SetLong(hwnd, index, newVal)
		if index == -4 {
			if old == 0 {
				old = hwndWndProc[hwnd]
			}
			if old == 0 && isBuiltinControl(hwnd) {
				old = builtinControlWndProc
			}
			hwndWndProc[hwnd] = newVal
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		var val uint64
		if m, ok := windowLongPtr[hwnd]; ok {
			val = m[index]
		}
		ctx.SetReturn(val & 0xFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowWord", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		index := int32(ctx.Arg(1))
		newVal := ctx.Arg(2) & 0xFFFF
		m := windowLongPtr[hwnd]
		if m == nil {
			m = make(map[int32]uint64)
			windowLongPtr[hwnd] = m
		}
		old := m[index] & 0xFFFF
		m[index] = (m[index] & 0xFFFF0000) | newVal
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassNameA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var name string
		if cs, ok := hwndChildren[hwnd]; ok {
			name = cs.className
		}
		if pBuf != 0 && nMax > 0 {
			bs := []byte(name)
			if len(bs) >= nMax {
				bs = bs[:nMax-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(pBuf+uint64(i), b)
			}
			ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassNameW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var name string
		if cs, ok := hwndChildren[hwnd]; ok {
			name = cs.className
		}
		if pBuf != 0 && nMax > 0 {
			rs := []rune(name)
			if len(rs) >= nMax {
				rs = rs[:nMax-1]
			}
			for i, r := range rs {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
		}
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	for _, fn := range []string{"RealGetWindowClass", "RealGetWindowClassA", "RealGetWindowClassW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
			var name string
			if cs, ok := hwndChildren[hwnd]; ok {
				name = cs.className
			}
			if pBuf != 0 && nMax > 0 {
				bs := []byte(name)
				if len(bs) >= nMax {
					bs = bs[:nMax-1]
				}
				for i, b := range bs {
					ctx.Mem.Write8(pBuf+uint64(i), b)
				}
				ctx.Mem.Write8(pBuf+uint64(len(bs)), 0)
			}
			ctx.SetReturn(uint64(len(name)))
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "InternalGetWindowText", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pBuf, nMax := ctx.Arg(0), ctx.Arg(1), int(ctx.Arg(2))
		var text string
		if cs, ok := hwndChildren[hwnd]; ok {
			text = cs.text
		} else if hwnd == hctx.MainHWND {
			text = hctx.MainTitle
		}
		if pBuf != 0 && nMax > 0 {
			rs := []rune(text)
			if len(rs) >= nMax {
				rs = rs[:nMax-1]
			}
			for i, r := range rs {
				ctx.Mem.Write16(pBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(pBuf+uint64(len(rs))*2, 0)
		}
		ctx.SetReturn(uint64(len(text)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/window.c NtUserGetWindowInfo
		hwnd, pWI := ctx.Arg(0), ctx.Arg(1)
		if pWI == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// WINDOWINFO: cbSize(4)+rcWindow(16)+rcClient(16)+dwStyle(4)+dwExStyle(4)+
		//   dwWindowStatus(4)+cxWindowBorders(4)+cyWindowBorders(4)+atomWindowType(2)+wCreatorVersion(2)
		cbSize, _ := mem.Read32(pWI)
		if cbSize < 60 {
			ctx.SetReturn(0)
			return 0
		}
		var x, y, w, h int32
		var style, exStyle uint32
		if cs, ok := hwndChildren[hwnd]; ok {
			x, y, w, h = cs.x, cs.y, cs.w, cs.h
			style, exStyle = cs.style, cs.exStyle
		} else if wlWindow != nil {
			w, h = wlWindow.Width, wlWindow.Height
			style = 0x00CF0000 // WS_OVERLAPPEDWINDOW
		}
		// rcWindow
		ctx.Mem.Write32(pWI+4, uint32(x))
		ctx.Mem.Write32(pWI+8, uint32(y))
		ctx.Mem.Write32(pWI+12, uint32(x+w))
		ctx.Mem.Write32(pWI+16, uint32(y+h))
		// rcClient
		ctx.Mem.Write32(pWI+20, uint32(x))
		ctx.Mem.Write32(pWI+24, uint32(y))
		ctx.Mem.Write32(pWI+28, uint32(x+w))
		ctx.Mem.Write32(pWI+32, uint32(y+h))
		// dwStyle
		ctx.Mem.Write32(pWI+36, style)
		// dwExStyle
		ctx.Mem.Write32(pWI+40, exStyle)
		// dwWindowStatus: WS_ACTIVECAPTION (1) if foreground
		var winStatus uint32
		if hwnd == hctx.MainHWND || hwnd == hctx.FocusHwnd {
			winStatus = 1
		}
		ctx.Mem.Write32(pWI+44, winStatus)
		// cxWindowBorders, cyWindowBorders
		ctx.Mem.Write32(pWI+48, 1)
		ctx.Mem.Write32(pWI+52, 1)
		// atomWindowType
		var atom uint16
		if a, ok := hctx.HwndClassAtom[hwnd]; ok {
			atom = a
		}
		ctx.Mem.Write16(pWI+56, atom)
		// wCreatorVersion (Windows Vista = 0x0600)
		ctx.Mem.Write16(pWI+58, 0x0600)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetWindowDC", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[user32] GetWindowDC hwnd=0x%x\n", hwnd)
		// Window DC covers the full surface (NC + client), so origin is (0,0) for the main window.
		var ox, oy int32
		if cs, ok := hwndChildren[hwnd]; ok {
			// Child window: origin at the child top-left (no extra NC offset)
			ox, oy = cs.x, cs.y
			h, dc := allocScreenDC(ox, oy)
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
			ctx.SetReturn(h)
			return 0
		}
		// Main window: origin (0,0) covers full surface including NC area
		h, _ := allocScreenDC(ox, oy)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetDCEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ox, oy := clientAreaOrigin(hwnd)
		h, dc := allocScreenDC(ox, oy)
		if cs, ok := hwndChildren[hwnd]; ok {
			dc.SetClipRect(cs.x, cs.y, cs.x+cs.w, cs.y+cs.h)
		}
		ctx.SetReturn(h)
		return 0
	})
	helpIdMap := map[uint64]uint32{}
	d.RegisterAutoStubHandler(user32, "GetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD GetWindowContextHelpId(HWND hWnd)
		// ReactOS: win32ss/user/ntuser/window.c
		hwnd := ctx.Arg(0)
		ctx.SetReturn(uint64(helpIdMap[hwnd]))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowContextHelpId", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetWindowContextHelpId(HWND hWnd, DWORD dwContextHelpId)
		hwnd := ctx.Arg(0)
		helpID := uint32(ctx.Arg(1))
		helpIdMap[hwnd] = helpID
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"GetWindowModuleFileName", "GetWindowModuleFileNameA", "GetWindowModuleFileNameW"} {
		fn := fn
		isW := fn == "GetWindowModuleFileNameW"
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			pBuf := ctx.Arg(1)
			nMax := int(ctx.Arg(2))
			path := hctx.ImagePath
			if pBuf != 0 && nMax > 0 {
				if isW {
					rs := []rune(path)
					if len(rs) >= nMax {
						rs = rs[:nMax-1]
					}
					for i, r := range rs {
						mem.Write16(pBuf+uint64(i)*2, uint16(r))
					}
					mem.Write16(pBuf+uint64(len(rs))*2, 0)
					ctx.SetReturn(uint64(len(rs)))
				} else {
					bs := []byte(path)
					if len(bs) >= nMax {
						bs = bs[:nMax-1]
					}
					for i, b := range bs {
						mem.Write8(pBuf+uint64(i), b)
					}
					mem.Write8(pBuf+uint64(len(bs)), 0)
					ctx.SetReturn(uint64(len(bs)))
				}
			} else {
				ctx.SetReturn(0)
			}
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetWindowPlacement", func(ctx *ntapi.TrapContext) uint32 {
		hwnd, pWP := ctx.Arg(0), ctx.Arg(1)
		if pWP == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// WINDOWPLACEMENT: length(4)+flags(4)+showCmd(4)+ptMinPos(8)+ptMaxPos(8)+rcNormalPos(16)
		ctx.Mem.Write32(pWP, 44) // length
		ctx.Mem.Write32(pWP+4, 0)
		ctx.Mem.Write32(pWP+8, 1) // SW_SHOWNORMAL
		var x, y, w, h int32
		if cs, ok := hwndChildren[hwnd]; ok {
			x, y, w, h = cs.x, cs.y, cs.w, cs.h
		} else if wlWindow != nil {
			w, h = wlWindow.Width, wlWindow.Height
		}
		ctx.Mem.Write32(pWP+28, uint32(x))
		ctx.Mem.Write32(pWP+32, uint32(y))
		ctx.Mem.Write32(pWP+36, uint32(x+w))
		ctx.Mem.Write32(pWP+40, uint32(y+h))
		ctx.SetReturn(1)
		return 0
	})
	// ─── GetClassInfo/GetClassLong ─────────────────────────────────────
	d.RegisterAutoStubHandler(user32, "GetClassInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2) // WNDCLASSEXW
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestUTF16(lpClassName)
			atom = hctx.ClassNameAtom[strings.ToLower(name)]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0) // class not found
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, 80)                     // cbSize
			mem.Write32(pOut+4, ci.Style)             // style
			mem.Write64(pOut+8, ci.WndProc)           // lpfnWndProc
			mem.Write32(pOut+16, uint32(ci.ClsExtra)) // cbClsExtra
			mem.Write32(pOut+20, uint32(ci.WndExtra)) // cbWndExtra
			mem.Write64(pOut+24, ci.HInstance)        // hInstance
			mem.Write64(pOut+32, ci.HIcon)            // hIcon
			mem.Write64(pOut+40, ci.HCursor)          // hCursor
			mem.Write64(pOut+48, ci.HbrBG)            // hbrBackground
			mem.Write64(pOut+56, ci.MenuName)         // lpszMenuName
			mem.Write64(pOut+64, 0)                   // lpszClassName (pointer; set to 0)
			mem.Write64(pOut+72, ci.HIconSm)          // hIconSm
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestString(lpClassName)
			atom = hctx.ClassNameAtom[strings.ToLower(name)]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, 80)
			mem.Write32(pOut+4, ci.Style)
			mem.Write64(pOut+8, ci.WndProc)
			mem.Write32(pOut+16, uint32(ci.ClsExtra))
			mem.Write32(pOut+20, uint32(ci.WndExtra))
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
			mem.Write64(pOut+72, ci.HIconSm)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoW", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2) // WNDCLASSW (no cbSize/hIconSm)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestUTF16(lpClassName)
			atom = hctx.ClassNameAtom[strings.ToLower(name)]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, ci.Style)               // style
			mem.Write64(pOut+8, ci.WndProc)           // lpfnWndProc
			mem.Write32(pOut+16, uint32(ci.ClsExtra)) // cbClsExtra
			mem.Write32(pOut+20, uint32(ci.WndExtra)) // cbWndExtra
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassInfoA", func(ctx *ntapi.TrapContext) uint32 {
		lpClassName := ctx.Arg(1)
		pOut := ctx.Arg(2)
		var atom uint16
		if lpClassName < 0x10000 {
			atom = uint16(lpClassName)
		} else {
			name := readGuestString(lpClassName)
			atom = hctx.ClassNameAtom[strings.ToLower(name)]
		}
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		if pOut != 0 {
			mem.Write32(pOut, ci.Style)
			mem.Write64(pOut+8, ci.WndProc)
			mem.Write32(pOut+16, uint32(ci.ClsExtra))
			mem.Write32(pOut+20, uint32(ci.WndExtra))
			mem.Write64(pOut+24, ci.HInstance)
			mem.Write64(pOut+32, ci.HIcon)
			mem.Write64(pOut+40, ci.HCursor)
			mem.Write64(pOut+48, ci.HbrBG)
			mem.Write64(pOut+56, ci.MenuName)
			mem.Write64(pOut+64, 0)
		}
		ctx.SetReturn(uint64(atom))
		return 0
	})
	// GetClassLongPtrW/A - ReactOS: NtUserGetClassLongPtr
	d.RegisterAutoStubHandler(user32, "GetClassLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var val uint64
		switch idx {
		case -26: // GCL_STYLE
			val = uint64(ci.Style)
		case -24: // GCL_WNDPROC / GCLP_WNDPROC
			val = ci.WndProc
		case -20: // GCL_CBCLSEXTRA
			val = uint64(uint32(ci.ClsExtra))
		case -18: // GCL_CBWNDEXTRA
			val = uint64(uint32(ci.WndExtra))
		case -16: // GCL_HMODULE / GCLP_HMODULE
			val = ci.HInstance
		case -14: // GCL_HICON / GCLP_HICON
			val = ci.HIcon
		case -12: // GCL_HCURSOR / GCLP_HCURSOR
			val = ci.HCursor
		case -10: // GCL_HBRBACKGROUND / GCLP_HBRBACKGROUND
			val = ci.HbrBG
		case -8: // GCL_MENUNAME / GCLP_MENUNAME
			val = ci.MenuName
		case -34: // GCL_HICONSM / GCLP_HICONSM
			val = ci.HIconSm
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClassLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var val uint64
		switch idx {
		case -26:
			val = uint64(ci.Style)
		case -24:
			val = ci.WndProc
		case -20:
			val = uint64(uint32(ci.ClsExtra))
		case -18:
			val = uint64(uint32(ci.WndExtra))
		case -16:
			val = ci.HInstance
		case -14:
			val = ci.HIcon
		case -12:
			val = ci.HCursor
		case -10:
			val = ci.HbrBG
		case -8:
			val = ci.MenuName
		case -34:
			val = ci.HIconSm
		}
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClassLongPtrW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var old uint64
		switch idx {
		case -26:
			old = uint64(ci.Style)
			ci.Style = uint32(newVal)
		case -24:
			old = ci.WndProc
			ci.WndProc = newVal
			hctx.AtomWndProc[atom] = newVal
		case -14:
			old = ci.HIcon
			ci.HIcon = newVal
		case -12:
			old = ci.HCursor
			ci.HCursor = newVal
		case -10:
			old = ci.HbrBG
			ci.HbrBG = newVal
		case -34:
			old = ci.HIconSm
			ci.HIconSm = newVal
		}
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetClassLongPtrA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		idx := int32(ctx.Arg(1))
		newVal := ctx.Arg(2)
		atom := hctx.HwndClassAtom[hwnd]
		ci := hctx.ClassInfo[atom]
		if ci == nil {
			ctx.SetReturn(0)
			return 0
		}
		var old uint64
		switch idx {
		case -26:
			old = uint64(ci.Style)
			ci.Style = uint32(newVal)
		case -24:
			old = ci.WndProc
			ci.WndProc = newVal
			hctx.AtomWndProc[atom] = newVal
		case -14:
			old = ci.HIcon
			ci.HIcon = newVal
		case -12:
			old = ci.HCursor
			ci.HCursor = newVal
		case -10:
			old = ci.HbrBG
			ci.HbrBG = newVal
		case -34:
			old = ci.HIconSm
			ci.HIconSm = newVal
		}
		ctx.SetReturn(old)
		return 0
	})
	for _, fn := range []string{"GetClassLongA", "GetClassLongW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			idx := int32(ctx.Arg(1))
			atom := hctx.HwndClassAtom[hwnd]
			ci := hctx.ClassInfo[atom]
			if ci == nil {
				ctx.SetReturn(0)
				return 0
			}
			var val uint64
			switch idx {
			case -26:
				val = uint64(ci.Style)
			case -24:
				val = ci.WndProc
			case -20:
				val = uint64(uint32(ci.ClsExtra))
			case -18:
				val = uint64(uint32(ci.WndExtra))
			}
			ctx.SetReturn(val)
			return 0
		})
	}
	for _, fn := range []string{"SetClassLongA", "SetClassLongW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hwnd := ctx.Arg(0)
			idx := int32(ctx.Arg(1))
			newVal := ctx.Arg(2)
			atom := hctx.HwndClassAtom[hwnd]
			ci := hctx.ClassInfo[atom]
			if ci == nil {
				ctx.SetReturn(0)
				return 0
			}
			var old uint64
			switch idx {
			case -26:
				old = uint64(ci.Style)
				ci.Style = uint32(newVal)
			case -24:
				old = ci.WndProc
				ci.WndProc = newVal
				hctx.AtomWndProc[atom] = newVal
			}
			ctx.SetReturn(old)
			return 0
		})
	}
	for _, fn := range []string{"GetClassWord", "SetClassWord"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "WindowFromDC", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(hctx.MainHWND)
		return 0
	})

	// -------------------------------------------------------
	// Cursor / display
	// -------------------------------------------------------
	showCursorCount := int32(0)
	d.RegisterAutoStubHandler(user32, "ShowCursor", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 {
			showCursorCount--
		} else {
			showCursorCount++
		}
		ctx.SetReturn(uint64(int64(showCursorCount)))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCursorPos", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetCursorPos(int X, int Y)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		cursorPosX = int32(ctx.Arg(0))
		cursorPosY = int32(ctx.Arg(1))
		hctx.CursorPosX, hctx.CursorPosY = cursorPosX, cursorPosY
		ravelog.Logf("[user32] SetCursorPos x=%d y=%d\n", cursorPosX, cursorPosY)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, 20)  // cbSize
			ctx.Mem.Write32(p+4, 1) // flags = CURSOR_SHOWING
			ctx.Mem.Write64(p+8, currentCursorHandle)
			ctx.Mem.Write32(p+16, uint32(cursorPosX))
			ctx.Mem.Write32(p+20, uint32(cursorPosY))
		}
		ctx.SetReturn(1)
		return 0
	})
	var clipCursorRect *[4]int32
	d.RegisterAutoStubHandler(user32, "ClipCursor", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL ClipCursor(const RECT *lpRect)
		// ReactOS: win32ss/user/ntuser/cursoricon.c
		pRect := ctx.Arg(0)
		if pRect == 0 {
			clipCursorRect = nil // release clip
		} else {
			l, _ := mem.Read32(pRect)
			t, _ := mem.Read32(pRect + 4)
			r, _ := mem.Read32(pRect + 8)
			b, _ := mem.Read32(pRect + 12)
			clipCursorRect = &[4]int32{int32(l), int32(t), int32(r), int32(b)}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetClipCursor", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			if clipCursorRect != nil {
				ctx.Mem.Write32(p, uint32(clipCursorRect[0]))
				ctx.Mem.Write32(p+4, uint32(clipCursorRect[1]))
				ctx.Mem.Write32(p+8, uint32(clipCursorRect[2]))
				ctx.Mem.Write32(p+12, uint32(clipCursorRect[3]))
			} else {
				var w, h int32 = 1920, 1080
				if wlWindow != nil {
					w, h = wlWindow.Width, wlWindow.Height
				}
				ctx.Mem.Write32(p, 0)
				ctx.Mem.Write32(p+4, 0)
				ctx.Mem.Write32(p+8, uint32(w))
				ctx.Mem.Write32(p+12, uint32(h))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursor", func(ctx *ntapi.TrapContext) uint32 {
		// HCURSOR GetCursor(void)
		// ReactOS: NtUserGetCursor
		ctx.SetReturn(currentCursorHandle)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetCursorFrameInfo", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented. Returns HCURSOR of animation frame.
		// hCursor := ctx.Arg(0)
		// istep := ctx.Arg(1)  // animation step pointer
		// We don't support animated cursors - return NULL
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetCursorContents", func(ctx *ntapi.TrapContext) uint32 {
		// Undocumented NtUserSetCursorContents
		// hCursor := ctx.Arg(0)
		// pInfo := ctx.Arg(1)
		ravelog.Logf("[user32] SetCursorContents (stub)\n")
		ctx.SetReturn(1)
		return 0
	})
	mouseSwapped := false
	d.RegisterAutoStubHandler(user32, "SwapMouseButton", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SwapMouseButton(BOOL fSwap) - returns previous state
		// ReactOS: win32ss/user/ntuser/misc.c
		prev := mouseSwapped
		mouseSwapped = ctx.Arg(0) != 0
		if prev {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "TrackMouseEvent", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: win32ss/user/ntuser/mouse.c NtUserTrackMouseEvent
		pTME := ctx.Arg(0)
		if pTME == 0 {
			ctx.SetReturn(0)
			return 0
		}
		flags, _ := mem.Read32(pTME + 4)
		hwnd, _ := mem.Read64(pTME + 8)
		// TME_QUERY (0x40000000) - return current tracking info
		if flags&0x40000000 != 0 {
			ctx.SetReturn(1)
			return 0
		}
		// TME_CANCEL (0x80000000) - cancel tracking
		if flags&0x80000000 != 0 {
			delete(hctx.TrackMouseHwnds, hwnd)
			ctx.SetReturn(1)
			return 0
		}
		// TME_LEAVE (0x02) or TME_HOVER (0x01) - record for future delivery
		hctx.TrackMouseHwnds[hwnd] = flags
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMouseMovePointsEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1
	})
	d.RegisterAutoStubHandler(user32, "GetLastInputInfo", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		if p != 0 {
			ctx.Mem.Write32(p, 8)
			ctx.Mem.Write32(p+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MonitorFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00040001)
		return 0
	})

	// -------------------------------------------------------
	// Display / monitor
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "EnumDisplayMonitors", func(ctx *ntapi.TrapContext) uint32 {
		// hdc := ctx.Arg(0), lprcClip := ctx.Arg(1), lpfnEnum := ctx.Arg(2), dwData := ctx.Arg(3)
		// Would need callback trampoline to call lpfnEnum - return TRUE (no monitors enumerated)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"EnumDisplayDevicesA", "EnumDisplayDevicesW",
		"EnumDisplaySettingsA", "EnumDisplaySettingsW", "EnumDisplaySettingsExA", "EnumDisplaySettingsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"ChangeDisplaySettingsA", "ChangeDisplaySettingsW",
		"ChangeDisplaySettingsExA", "ChangeDisplaySettingsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0)
			return 0 // DISP_CHANGE_SUCCESSFUL
		})
	}

	// -------------------------------------------------------
	// Hooks / WinEvents
	// -------------------------------------------------------
	// ReactOS: win32ss/user/ntuser/hook.c
	// Hook chain: map from HHOOK -> {hookType, proc, hMod, threadId}
	type hookEntry struct {
		hookType int32
		proc     uint64
		hMod     uint64
		threadID uint64
	}
	hookTable := map[uint64]*hookEntry{}
	var nextHookHandle uint64 = 0x00070000

	type winEventEntry struct {
		eventMin uint32
		eventMax uint32
		proc     uint64
		hMod     uint64
		threadID uint32
		flags    uint32
	}
	winEventTable := map[uint64]*winEventEntry{}
	var nextWinEventHandle uint64 = 0x00080000

	d.RegisterAutoStubHandler(user32, "SetWindowsHookA", func(ctx *ntapi.TrapContext) uint32 {
		// HHOOK SetWindowsHookA(int idHook, HOOKPROC lpfn)
		// Old-style: no hMod/threadId params (thread-local only)
		idHook := int32(ctx.Arg(0))
		lpfn := ctx.Arg(1)
		nextHookHandle++
		h := nextHookHandle
		hookTable[h] = &hookEntry{hookType: idHook, proc: lpfn}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWindowsHookW", func(ctx *ntapi.TrapContext) uint32 {
		idHook := int32(ctx.Arg(0))
		lpfn := ctx.Arg(1)
		nextHookHandle++
		h := nextHookHandle
		hookTable[h] = &hookEntry{hookType: idHook, proc: lpfn}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetWinEventHook", func(ctx *ntapi.TrapContext) uint32 {
		// HWINEVENTHOOK SetWinEventHook(DWORD eventMin, DWORD eventMax,
		//   HMODULE hmod, WINEVENTPROC pfn, DWORD pid, DWORD tid, DWORD flags)
		eventMin := uint32(ctx.Arg(0))
		eventMax := uint32(ctx.Arg(1))
		hmod := ctx.Arg(2)
		pfn := ctx.Arg(3)
		tid := uint32(ctx.Arg(5))
		flags := uint32(ctx.Arg(6))
		nextWinEventHandle++
		h := nextWinEventHandle
		winEventTable[h] = &winEventEntry{
			eventMin: eventMin, eventMax: eventMax,
			proc: pfn, hMod: hmod, threadID: tid, flags: flags,
		}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "NotifyWinEvent", func(ctx *ntapi.TrapContext) uint32 {
		// void NotifyWinEvent(DWORD event, HWND, LONG idObject, LONG idChild)
		// We don't invoke callbacks yet, but the API is void - nothing to return.
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWinEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		if _, ok := winEventTable[h]; ok {
			delete(winEventTable, h)
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnhookWindowsHook", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL UnhookWindowsHook(int nCode, HOOKPROC pfnFilterProc)
		// Old-style unhook by type+proc. Find and remove.
		nCode := int32(ctx.Arg(0))
		pfn := ctx.Arg(1)
		removed := false
		for h, entry := range hookTable {
			if entry.hookType == nCode && entry.proc == pfn {
				delete(hookTable, h)
				removed = true
				break
			}
		}
		if removed {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CallNextHookEx", func(ctx *ntapi.TrapContext) uint32 {
		// LRESULT CallNextHookEx(HHOOK hhk, int nCode, WPARAM, LPARAM)
		// We have only one hook per type, so "next" is the system default -> return 0.
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "IsWinEventHookInstalled", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL IsWinEventHookInstalled(DWORD event)
		event := uint32(ctx.Arg(0))
		for _, we := range winEventTable {
			if event >= we.eventMin && event <= we.eventMax {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[user32] RegisterShellHookWindow hwnd=0x%x", hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DeregisterShellHookWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		ravelog.Logf("[user32] DeregisterShellHookWindow hwnd=0x%x", hwnd)
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Properties
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "SetPropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		hData := ctx.Arg(2)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		m := windowProps[hwnd]
		if m == nil {
			m = make(map[string]uint64)
			windowProps[hwnd] = m
		}
		m[name] = hData
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetPropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			ctx.SetReturn(m[name])
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RemovePropA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		lpString := ctx.Arg(1)
		var name string
		if lpString < 0x10000 {
			name = fmt.Sprintf("atom:%d", lpString)
		} else {
			name = readGuestString(lpString)
		}
		if m, ok := windowProps[hwnd]; ok {
			old := m[name]
			delete(m, name)
			ctx.SetReturn(old)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	for _, fn := range []string{"EnumPropsA", "EnumPropsW", "EnumPropsExA", "EnumPropsExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Dialog
	// -------------------------------------------------------
	for _, fn := range []string{"DefDlgProcA", "DefDlgProcW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	isDialogMessage := func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		pMsg := ctx.Arg(1)
		if hDlg == 0 || pMsg == 0 {
			ctx.SetReturn(0)
			return 0
		}
		msgHWND, msgID, wParam, _ := readMsg(ctx, pMsg)
		if !windowBelongsToDialog(hwndChildren, msgHWND, hDlg) {
			ctx.SetReturn(0)
			return 0
		}
		if msgID != 0x0100 {
			ctx.SetReturn(0)
			return 0
		}
		vk := uint32(wParam & 0xff)
		if dialogControlWantsKey(hwndChildren[msgHWND], vk) {
			ctx.SetReturn(0)
			return 0
		}
		switch vk {
		case 0x09: // VK_TAB
			previous := keyState[0x10]&0x80 != 0 // VK_SHIFT
			next := nextDialogTabItem(hwndChildren, hctx.HwndOrder, hDlg, hctx.FocusHwnd, previous)
			if next == 0 {
				ctx.SetReturn(0)
				return 0
			}
			old := hctx.FocusHwnd
			hctx.FocusHwnd = next
			if old != 0 && hwndWndProc[old] != 0 {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, old, 0x0008, next, 0))
			}
			if hwndWndProc[next] != 0 {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, next, 0x0007, old, 0))
			}
			ravelog.Logf("[dialog] tab focus hwnd=0x%x previous=%v\n", next, previous)
			ctx.SetReturn(1)
			return 0
		case 0x25, 0x26, 0x27, 0x28: // VK_LEFT, VK_UP, VK_RIGHT, VK_DOWN
			focused := hwndChildren[msgHWND]
			if focused == nil || !strings.EqualFold(focused.className, "button") || (focused.style&0x0f != 4 && focused.style&0x0f != 9) {
				ctx.SetReturn(0)
				return 0
			}
			previous := vk == 0x25 || vk == 0x26
			next := nextDialogGroupItem(hwndChildren, hctx.HwndOrder, hDlg, msgHWND, previous)
			if next == 0 || next == msgHWND {
				ctx.SetReturn(0)
				return 0
			}
			old := hctx.FocusHwnd
			hctx.FocusHwnd = next
			if old != 0 && hwndWndProc[old] != 0 {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, old, 0x0008, next, 0))
			}
			if hwndWndProc[next] != 0 {
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, next, 0x0007, old, 0))
			}
			control := hwndChildren[next]
			if control != nil && strings.EqualFold(control.className, "button") && (control.style&0x0f == 4 || control.style&0x0f == 9) {
				selectAutoRadioButton(hwndChildren, hctx.HwndOrder, hDlg, next)
				requestWindowRepaint(control.parentHWND)
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, control.parentHWND, 0x0111, control.ctrlID, next))
			}
			ravelog.Logf("[dialog] group focus hwnd=0x%x previous=%v\n", next, previous)
			ctx.SetReturn(1)
			return 0
		case 0x0d, 0x1b: // VK_RETURN, VK_ESCAPE
			controlID := uint64(2)
			var controlHWND uint64
			if vk == 0x0d {
				if focused := hwndChildren[hctx.FocusHwnd]; focused != nil && strings.EqualFold(focused.className, "button") && focused.style&0x0f <= 1 && dialogControlAvailable(hwndChildren, hctx.FocusHwnd, hDlg) {
					controlHWND = hctx.FocusHwnd
					controlID = focused.ctrlID
				}
				if controlHWND == 0 {
					for _, hwnd := range hctx.HwndOrder {
						control := hwndChildren[hwnd]
						if control != nil && strings.EqualFold(control.className, "button") && control.style&0x0f == 1 && dialogControlAvailable(hwndChildren, hwnd, hDlg) {
							controlHWND = hwnd
							controlID = control.ctrlID
							break
						}
					}
				}
				if controlHWND == 0 {
					controlID = 1
				}
			}
			if controlHWND == 0 {
				for _, hwnd := range hctx.HwndOrder {
					control := hwndChildren[hwnd]
					if control != nil && control.ctrlID == controlID && dialogControlAvailable(hwndChildren, hwnd, hDlg) {
						controlHWND = hwnd
						break
					}
				}
			}
			if controlHWND == 0 && vk != 0x1b {
				ctx.SetReturn(0)
				return 0
			}
			hctx.enqueueMessage(nil, newQueuedMsg(hctx, hDlg, 0x0111, controlID, controlHWND))
			ravelog.Logf("[dialog] key command id=%d hwnd=0x%x\n", controlID, controlHWND)
			ctx.SetReturn(1)
			return 0
		default:
			ctx.SetReturn(0)
			return 0
		}
	}
	d.RegisterAutoStubHandler(user32, "IsDialogMessage", isDialogMessage)
	d.RegisterAutoStubHandler(user32, "IsDialogMessageA", isDialogMessage)
	d.RegisterAutoStubHandler(user32, "IsDialogMessageW", isDialogMessage)
	d.RegisterAutoStubHandler(user32, "GetDialogBaseUnits", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00080004)
		return 0 // MAKELONG(4,8)
	})
	d.RegisterAutoStubHandler(user32, "GetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		nMaxCount := int(ctx.Arg(3))
		var text string
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				text = hwndChildren[h].text
				break
			}
		}
		written := 0
		if lpStr != 0 && nMaxCount > 0 {
			bs := []byte(text)
			if len(bs) >= nMaxCount {
				bs = bs[:nMaxCount-1]
			}
			for i, b := range bs {
				ctx.Mem.Write8(lpStr+uint64(i), b)
				written++
			}
			ctx.Mem.Write8(lpStr+uint64(written), 0)
		}
		ctx.SetReturn(uint64(written))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDlgItemTextA", func(ctx *ntapi.TrapContext) uint32 {
		hDlg := ctx.Arg(0)
		nIDDlgItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		text := readGuestString(lpStr)
		for h, cs := range hwndChildren {
			if cs.parentHWND == hDlg && cs.ctrlID == nIDDlgItem {
				hwndChildren[h].text = text
				break
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetNextDlgTabItem", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(nextDialogTabItem(hwndChildren, hctx.HwndOrder, ctx.Arg(0), ctx.Arg(1), ctx.Arg(2) != 0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetNextDlgGroupItem", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(nextDialogGroupItem(hwndChildren, hctx.HwndOrder, ctx.Arg(0), ctx.Arg(1), ctx.Arg(2) != 0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogParamA", func(ctx *ntapi.TrapContext) uint32 {
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestString(lpTemplate)
		}
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		registerDialogState(hwnd, &controlState{
			className:  "dialogbox",
			parentHWND: hWndParent,
			visible:    true,
		})
		ravelog.Logf("[dialog] CreateDialogParamA template=%s parent=0x%x dlgProc=0x%x -> hwnd=0x%x\n",
			templateName, hWndParent, lpDialogFunc, hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamA", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		registerDialogState(hwnd, &controlState{
			className: "dialogbox",
			visible:   true,
		})
		ravelog.Logf("[dialog] CreateDialogIndirectParamA -> hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateDialogIndirectParamAorW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		registerDialogState(hwnd, &controlState{
			className: "dialogbox",
			visible:   true,
		})
		ravelog.Logf("[dialog] CreateDialogIndirectParamAorW -> hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxParamA", func(ctx *ntapi.TrapContext) uint32 {
		hInstance := ctx.Arg(0)
		lpTemplate := ctx.Arg(1)
		hWndParent := ctx.Arg(2)
		lpDialogFunc := ctx.Arg(3)
		dwInitParam := ctx.Arg(4)

		templateName := ""
		if lpTemplate < 0x10000 {
			templateName = fmt.Sprintf("#%d", lpTemplate)
		} else {
			templateName = readGuestString(lpTemplate)
		}
		// Log the return address (= call site in guest code) to help trace error origins
		var retAddr uint32
		if ctx.State != nil && ctx.State.Is32 {
			retAddr, _ = mem.Read32(ctx.CPU.GetSP())
		}
		ravelog.Logf("[dialog] DialogBoxParamA template=%s hInstance=0x%x parent=0x%x dlgProc=0x%x initParam=0x%x callSite=0x%x\n",
			templateName, hInstance, hWndParent, lpDialogFunc, dwInitParam, retAddr)

		if lpDialogFunc == 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}

		dlgHwnd := hwndAlloc()
		hctx.setWindowCPU(dlgHwnd, ctx.CPU)
		cs := &controlState{
			className:  "dialog",
			parentHWND: hWndParent,
			visible:    true,
		}

		// Load and parse the DLGTEMPLATE resource from hInstance module.
		if info := loadDlgTemplate(hInstance, lpTemplate); info != nil {
			applyDialogBounds(cs, hWndParent, info)
			cs.text = info.title
			cs.style = info.style
			cs.exStyle = info.extStyle
			cs.visible = dialogVisible(info, true)
			if info.title != "" {
				hwndTitle[dlgHwnd] = info.title
			}
			registerDialogState(dlgHwnd, cs)
			createDlgControls(dlgHwnd, info)
		} else {
			registerDialogState(dlgHwnd, cs)
		}
		hwndWndProc[dlgHwnd] = lpDialogFunc
		// Mark the new dialog as needing a paint so the modal pump dispatches
		// WM_PAINT after WM_INITDIALOG completes.
		queuePaint(dlgHwnd)

		// Save call-site state so DialogBox can return after EndDialog completes.
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if okR {
			rsp := rr.ReadReg(4)
			var retAddr uint64
			var retRSP uint64
			is32 := ctx.State != nil && ctx.State.Is32
			if is32 {
				v, _ := mem.Read32(rsp)
				retAddr = uint64(v)
				retRSP = rsp + 24 // 4 (retAddr) + 5*4 (stdcall args)
			} else {
				retAddr, _ = mem.Read64(rsp)
				retRSP = rsp + 8
			}
			syncStack := hctx.syncStack(ctx)
			entry := modalDlgEntry{
				hwnd:           dlgHwnd,
				retAddr:        retAddr,
				retRSP:         retRSP,
				pumpSP:         modalPumpEntrySP(rsp, is32),
				callee:         captureGuestNonvolatileRegisters(rr, is32),
				syncDepth:      len(*syncStack),
				parent:         hWndParent,
				previousFocus:  hctx.FocusHwnd,
				previousActive: hctx.ActiveHwnd,
			}
			disableModalOwner(hWndParent)
			modalDialogs.push(ctx.CPU, entry)
			hctx.FocusHwnd = dlgHwnd
			hctx.ActiveHwnd = dlgHwnd
			if msgLoopSP == 0 && hctx.ModalPumpTrampoline != 0 {
				msgLoopSP = modalPumpEntrySP(rsp, is32)
				msgLoopPC = hctx.ModalPumpTrampoline
			}
		}

		// Dispatch WM_INITDIALOG; syncTrampoline will redirect to message loop.
		if dispatchWmInitDialog(ctx, dlgHwnd, lpDialogFunc, dwInitParam, true) {
			return 0
		}

		// Fallback: DialogBox reports creation failure as -1.
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DialogBoxIndirectParamAorW", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		registerDialogState(hwnd, &controlState{
			className: "dialogbox",
			visible:   true,
		})
		ravelog.Logf("[dialog] DialogBoxIndirectParamAorW -> hwnd=0x%x\n", hwnd)
		ctx.SetReturn(hwnd)
		return 0
	})
	for _, fn := range []string{"DlgDirListA", "DlgDirListW", "DlgDirListComboBoxA",
		"DlgDirListComboBoxW", "DlgDirSelectExA", "DlgDirSelectExW",
		"DlgDirSelectComboBoxExA", "DlgDirSelectComboBoxExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Menu (A variants + extensions)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "InsertMenuItemA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPosition := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if insertMenuItem(mem, lpmii, ctx.State != nil && ctx.State.Is32, false, hMenu, item, byPosition, menus) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "AppendMenuA", func(ctx *ntapi.TrapContext) uint32 {
		return insertLegacyMenu(ctx, false, true)
	})
	d.RegisterAutoStubHandler(user32, "InsertMenuA", func(ctx *ntapi.TrapContext) uint32 {
		return insertLegacyMenu(ctx, false, false)
	})
	d.RegisterAutoStubHandler(user32, "ModifyMenuA", func(ctx *ntapi.TrapContext) uint32 {
		return modifyMenu(ctx, false)
	})
	changeMenu := func(ctx *ntapi.TrapContext, wide bool) uint32 {
		hMenu, position, data, idNewItem := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		flags := uint32(ctx.Arg(4))
		ok := changeLegacyMenuItem(menus, hMenu, position, data, idNewItem, flags, func(itemFlags uint32, itemData uint64) (uint32, string, bool) {
			return readLegacyMenuItem(itemFlags, itemData, wide)
		})
		if ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	}
	d.RegisterAutoStubHandler(user32, "ChangeMenuA", func(ctx *ntapi.TrapContext) uint32 {
		return changeMenu(ctx, false)
	})
	d.RegisterAutoStubHandler(user32, "ChangeMenuW", func(ctx *ntapi.TrapContext) uint32 {
		return changeMenu(ctx, true)
	})
	d.RegisterAutoStubHandler(user32, "GetMenuStringA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		uIDItem := ctx.Arg(1)
		lpStr := ctx.Arg(2)
		cchMax := int(ctx.Arg(3))
		uFlags := uint32(ctx.Arg(4))
		item := findMenuItem(hMenu, uIDItem, uFlags)
		if item == nil || item.flags&(mftBitmap|mftOwnerDraw|mftSeparator) != 0 {
			ctx.SetReturn(0)
			return 0
		}
		written, ok := writeMenuString(ctx.Mem, lpStr, cchMax, item.text, false)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(written))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuItemID", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		nPos := int(ctx.Arg(1))
		m, ok := menus[hMenu]
		if !ok || nPos < 0 || nPos >= len(m.items) {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		ctx.SetReturn(m.items[nPos].id)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuCheckMarkDimensions", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x000D000D)
		return 0 // MAKELONG(13,13)
	})
	for _, fn := range []string{"GetMenuContextHelpId", "GetMenuDefaultItem"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(0xFFFFFFFF))
			return 0 // -1
		})
	}
	for _, fn := range []string{"SetMenuContextHelpId", "SetMenuDefaultItem"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetMenuBarInfo", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(3) // MENUBARINFO
		if pInfo != 0 {
			// MENUBARINFO: cbSize(4)+rcBar(16)+hMenu(8)+hwndMenu(8)+fBarFocused:1+fFocused:1
			mem.Write32(pInfo, 48)   // cbSize
			mem.Write32(pInfo+4, 0)  // rcBar.left
			mem.Write32(pInfo+8, 0)  // rcBar.top
			mem.Write32(pInfo+12, 0) // rcBar.right
			mem.Write32(pInfo+16, 0) // rcBar.bottom
			mem.Write64(pInfo+24, 0) // hMenu
			mem.Write64(pInfo+32, 0) // hwndMenu
			mem.Write32(pInfo+40, 0) // flags
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetMenuItemInfoA", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		item := ctx.Arg(1)
		byPos := ctx.Arg(2) != 0
		lpmii := ctx.Arg(3)
		if lpmii == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if withLocatedMenuItem(menus, hMenu, item, byPos, func(found *menuItem, owner uint64) bool {
			return getMenuItemInfo(mem, lpmii, ctx.State != nil && ctx.State.Is32, false, owner, found, menus)
		}) {
			ctx.SetReturn(1)
		} else {
			cbSize, _ := mem.Read32(lpmii)
			mask, _ := mem.Read32(lpmii + 4)
			ravelog.Logf("[menuinfo] GetMenuItemInfoA failed menu=0x%x item=%d byPos=%v cb=%d mask=0x%x\n", hMenu, item, byPos, cbSize, mask)
			ctx.SetReturn(0)
		}
		return 0
	})
	for _, fn := range []string{"GetMenuInfo", "GetMenuItemRect"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "SetMenuInfo", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetMenuInfo(HMENU, LPCMENUINFO)
		// ReactOS: NtUserThunkedMenuInfo
		// MENUINFO: cbSize, fMask, dwStyle, cyMax, hbrBack, dwContextHelpID, dwMenuData
		hMenu := ctx.Arg(0)
		pInfo := ctx.Arg(1)
		if hMenu == 0 || pInfo == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Read fMask to know which fields to apply
		fMask, _ := mem.Read32(pInfo + 4)
		_ = fMask // We accept the call but don't change internal state yet
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "HiliteMenuItem", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(1)
		uIDItem := ctx.Arg(2)
		uHilite := uint32(ctx.Arg(3))
		item := findMenuItem(hMenu, uIDItem, uHilite)
		if item != nil {
			if uHilite&0x0080 != 0 { // MF_HILITE
				item.flags |= 0x0080
			} else {
				item.flags &^= 0x0080
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CheckMenuRadioItem", func(ctx *ntapi.TrapContext) uint32 {
		hMenu := ctx.Arg(0)
		first := uint32(ctx.Arg(1))
		last := uint32(ctx.Arg(2))
		check := uint32(ctx.Arg(3))
		flags := uint32(ctx.Arg(4))
		m, ok := menus[hMenu]
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		const mfChecked = 0x0008
		for _, item := range m.items {
			id := uint32(item.id)
			if flags&0x0400 != 0 { // MF_BYPOSITION - skip for now
				continue
			}
			if id >= first && id <= last {
				if id == check {
					item.flags |= mfChecked | 0x0200
				} else {
					item.flags &^= mfChecked | 0x0200
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "MenuItemFromPoint", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(0xFFFFFFFF))
		return 0 // -1
	})
	for _, fn := range []string{"TrackPopupMenu", "TrackPopupMenuEx"} {
		fn := fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			hMenu := ctx.Arg(0)
			uFlags := uint32(ctx.Arg(1))
			x := int32(ctx.Arg(2))
			y := int32(ctx.Arg(3))
			hwndOwner := ctx.Arg(5)
			if fn == "TrackPopupMenuEx" {
				hwndOwner = ctx.Arg(4)
			}
			const (
				TPM_RETURNCMD = 0x0100
				MF_SEPARATOR  = 0x0800
				MF_GRAYED     = 0x0001
				MF_DISABLED   = 0x0002
				MF_POPUP      = 0x0010
				WM_COMMAND    = 0x0111
			)
			if hwndOwner == 0 {
				hwndOwner = hctx.MainHWND
			}
			if wlWindow != nil {
				showPopupMenu(hMenu, hwndOwner, x, y)
				requestWindowRepaint(hwndOwner)
			}
			selected := uint64(0)
			if m, ok := menus[hMenu]; ok {
				for _, item := range m.items {
					if item.flags&(MF_SEPARATOR|MF_GRAYED|MF_DISABLED) != 0 {
						continue
					}
					if submenu := item.submenuItems(); item.flags&MF_POPUP != 0 && len(submenu) > 0 {
						for _, sub := range submenu {
							if sub.flags&(MF_SEPARATOR|MF_GRAYED|MF_DISABLED) == 0 && sub.id != 0 {
								selected = sub.id
								break
							}
						}
					} else if item.id != 0 {
						selected = item.id
					}
					if selected != 0 {
						break
					}
				}
			}
			if uFlags&TPM_RETURNCMD != 0 {
				closePopupMenus()
				ctx.SetReturn(selected)
				return 0
			}
			if selected != 0 {
				target := hwndOwner
				hctx.enqueueMessage(nil, newQueuedMsg(hctx, target, WM_COMMAND, selected, 0))
			}
			closePopupMenus()
			ctx.SetReturn(1)
			return 0
		})
	}
	for _, fn := range []string{"PaintMenuBar", "DrawMenuBarTemp", "CalcMenuBar",
		"MenuWindowProcA", "MenuWindowProcW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "EndMenu", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[user32] EndMenu\n")
		closePopupMenus()
		requestWindowRepaint(hctx.MainHWND)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetSystemMenu", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hMenu := ctx.Arg(1)
		ravelog.Logf("[user32] SetSystemMenu hwnd=0x%x menu=0x%x", hwnd, hMenu)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"LoadMenuA", "LoadMenuIndirectA", "LoadMenuIndirectW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// SystemParametersInfoA
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "SystemParametersInfoA", func(ctx *ntapi.TrapContext) uint32 {
		uiAction := ctx.Arg(0)
		pvParam := ctx.Arg(2)
		w := int32(1920)
		h := int32(1080)
		if wlWindow != nil {
			w = int32(wlWindow.Width)
			h = int32(wlWindow.Height)
		}
		writeLogFontA := func(off uint64, name string, height int32) {
			mem.Write32(pvParam+off+0, uint32(height))
			mem.Write32(pvParam+off+4, 0)
			mem.Write32(pvParam+off+8, 0)
			mem.Write32(pvParam+off+12, 0)
			mem.Write32(pvParam+off+16, 400) // lfWeight = FW_NORMAL
			mem.Write8(pvParam+off+20, 0)    // lfItalic
			mem.Write8(pvParam+off+21, 0)    // lfUnderline
			mem.Write8(pvParam+off+22, 0)    // lfStrikeOut
			mem.Write8(pvParam+off+23, 1)    // lfCharSet = DEFAULT_CHARSET
			mem.Write8(pvParam+off+24, 0)    // lfOutPrecision
			mem.Write8(pvParam+off+25, 0)    // lfClipPrecision
			mem.Write8(pvParam+off+26, 5)    // lfQuality = CLEARTYPE_QUALITY
			mem.Write8(pvParam+off+27, 0x22) // lfPitchAndFamily
			// LOGFONTA: lfFaceName is 32 bytes of ANSI chars at +28
			for i, ch := range name {
				mem.Write8(pvParam+off+28+uint64(i), uint8(ch))
			}
			mem.Write8(pvParam+off+28+uint64(len(name)), 0)
		}
		switch uiAction {
		case 0x0026: // SPI_GETDRAGFULLWINDOWS
			if pvParam != 0 {
				mem.Write32(pvParam, 1)
			}
		case 0x0029: // SPI_GETNONCLIENTMETRICS - NONCLIENTMETRICSA (500 bytes: no iPaddedBorderWidth pre-Vista)
			if pvParam != 0 {
				mem.Write32(pvParam+0, 500) // cbSize
				mem.Write32(pvParam+4, 1)   // iBorderWidth
				mem.Write32(pvParam+8, 17)  // iScrollWidth
				mem.Write32(pvParam+12, 17) // iScrollHeight
				mem.Write32(pvParam+16, 36) // iCaptionWidth
				mem.Write32(pvParam+20, 36) // iCaptionHeight
				writeLogFontA(24, "Segoe UI", -12)
				mem.Write32(pvParam+84, 36) // iSmCaptionWidth (+0x54)
				mem.Write32(pvParam+88, 36) // iSmCaptionHeight (+0x58)
				writeLogFontA(92, "Segoe UI", -12)
				mem.Write32(pvParam+152, 36) // iMenuWidth (+0x98)
				mem.Write32(pvParam+156, 36) // iMenuHeight (+0x9C)
				writeLogFontA(160, "Segoe UI", -12)
				writeLogFontA(220, "Segoe UI", -12) // lfStatusFont
				writeLogFontA(280, "Segoe UI", -12) // lfMessageFont
			}
		case 0x002B: // SPI_GETMINIMIZEDMETRICS
			if pvParam != 0 {
				mem.Write32(pvParam+0, 20)
				mem.Write32(pvParam+4, 160)
				mem.Write32(pvParam+8, 0)
				mem.Write32(pvParam+12, 0)
				mem.Write32(pvParam+16, 0)
			}
		case 0x001F: // SPI_GETICONTITLELOGFONT - LOGFONTA (60 bytes)
			if pvParam != 0 {
				writeLogFontA(0, "Segoe UI", -12)
			}
		case 0x0030: // SPI_GETWORKAREA
			if pvParam != 0 {
				mem.Write32(pvParam+0, 0)
				mem.Write32(pvParam+4, 0)
				mem.Write32(pvParam+8, uint32(w))
				mem.Write32(pvParam+12, uint32(h))
			}
		case 0x0048: // SPI_GETANIMATION
			if pvParam != 0 {
				mem.Write32(pvParam, 8)
				mem.Write32(pvParam+4, 0)
			}
		case 0x004A: // SPI_GETFONTSMOOTHING
			if pvParam != 0 {
				mem.Write32(pvParam, 1)
			}
		case 0x006A: // SPI_GETMENUSHOWDELAY
			if pvParam != 0 {
				mem.Write32(pvParam, 400)
			}
		case 0x006C: // SPI_GETWHEELSCROLLCHARS
			if pvParam != 0 {
				mem.Write32(pvParam, 3)
			}
		case 0x1020: // SPI_GETMOUSEVANISH
			if pvParam != 0 {
				mem.Write32(pvParam, 1)
			}
		case 0x200A: // SPI_GETFONTSMOOTHINGTYPE
			if pvParam != 0 {
				mem.Write32(pvParam, 2) // FE_FONTSMOOTHINGCLEARTYPE
			}
		case 0x200C: // SPI_GETFONTSMOOTHINGCONTRAST
			if pvParam != 0 {
				mem.Write32(pvParam, 1400)
			}
		default:
			ravelog.Logf("[spi] SystemParametersInfoA unknown uiAction=0x%x pvParam=0x%x\n", uiAction, pvParam)
		}
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// Drawing (A variants)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "DrawTextA", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		// Convert ANSI to UTF-16 and draw via existing DC
		pStr, nCount := ctx.Arg(1), int(int32(ctx.Arg(2)))
		var bs []byte
		for i := 0; i < 4096; i++ {
			b, _ := mem.Read8(ctx.Arg(1) + uint64(i))
			if b == 0 && (nCount < 0 || i >= nCount) {
				break
			}
			if nCount >= 0 && i >= nCount {
				break
			}
			bs = append(bs, b)
			_ = pStr
		}
		_ = bs
		// Fallback: just return a valid height
		ctx.SetReturn(16)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawTextExA", func(ctx *ntapi.TrapContext) uint32 {
		if wlWindow == nil {
			ctx.SetReturn(1)
			return 0
		}
		hdc := ctx.Arg(0)
		lpStr := ctx.Arg(1)
		nCount := int(int32(ctx.Arg(2)))
		lpRect := ctx.Arg(3)
		uFormat := uint32(ctx.Arg(4))
		dc := getDC(hdc)
		text := readGuestString(lpStr)
		if nCount >= 0 && nCount < len(text) {
			text = text[:nCount]
		}
		f := dc.Font
		if f == nil {
			f = gdi.DefaultFont()
		}
		lineH := f.Height
		if lineH == 0 {
			lineH = 16
		}
		if lpRect != 0 {
			l, _ := mem.Read32(lpRect)
			t, _ := mem.Read32(lpRect + 4)
			r, _ := mem.Read32(lpRect + 8)
			x := int32(l) + 2
			y := int32(t)
			tw := int32(len([]rune(text))) * f.AveCharWidth
			w := int32(r) - int32(l)
			if uFormat&0x1 != 0 { // DT_CENTER
				x = int32(l) + (w-tw)/2
			}
			if uFormat&0x4 != 0 { // DT_VCENTER
				if b, err := mem.Read32(lpRect + 12); err == nil {
					y = int32(t) + (int32(b)-int32(t)-lineH)/2
				}
			}
			dc.TextOut(x, y, text, false)
		}
		ctx.SetReturn(uint64(lineH))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DrawStateA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		ravelog.Logf("[user32] DrawStateA hdc=0x%x x=%d y=%d", hdc, x, y)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"DrawCaption", "DrawCaptionTempA", "DrawCaptionTempW",
		"DrawFrame", "DrawAnimatedRects"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GrayStringA", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		lpData := ctx.Arg(3)
		nCount := int32(ctx.Arg(4))
		x := int32(ctx.Arg(5))
		y := int32(ctx.Arg(6))
		dc := getDC(hdc)
		if dc != nil && dc.Target != nil && lpData != 0 {
			var txt string
			if nCount > 0 {
				// Read nCount bytes from guest as ANSI string
				bs := make([]byte, nCount)
				for i := int32(0); i < nCount; i++ {
					b, _ := ctx.Mem.Read8(lpData + uint64(i))
					bs[i] = b
				}
				txt = string(bs)
			} else {
				txt = readGuestString(lpData)
			}
			oldColor := dc.TextColor
			dc.TextColor = 0x808080
			dc.TextOut(x, y, txt, false)
			dc.TextColor = oldColor
		}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"TabbedTextOutA", "GetTabbedTextExtentA", "GetTabbedTextExtentW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "ExcludeUpdateRgn", func(ctx *ntapi.TrapContext) uint32 {
		// int ExcludeUpdateRgn(HDC hDC, HWND hWnd) - returns SIMPLEREGION
		_ = ctx.Arg(0)   // hDC
		_ = ctx.Arg(1)   // hWnd
		ctx.SetReturn(1) // SIMPLEREGION
		return 0
	})

	// -------------------------------------------------------
	// Misc utility
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "MessageBeep", func(ctx *ntapi.TrapContext) uint32 {
		uType := uint32(ctx.Arg(0))
		ravelog.Logf("[user32] MessageBeep type=0x%x", uType)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"MessageBoxExA", "MessageBoxExW",
		"MessageBoxIndirectA", "MessageBoxIndirectW",
		"MessageBoxTimeoutA", "MessageBoxTimeoutW", "SoftModalMessageBox"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0 // IDOK
		})
	}
	d.RegisterAutoStubHandler(user32, "LoadStringA", func(ctx *ntapi.TrapContext) uint32 {
		uID := uint32(ctx.Arg(1))
		lpBuffer := ctx.Arg(2)
		cchBufferMax := int(int32(ctx.Arg(3)))
		s, _, _ := peLoadStringW(uID)
		if s == "" || lpBuffer == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if cchBufferMax == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ansi := []byte(s)
		n := len(ansi)
		if n >= cchBufferMax {
			n = cchBufferMax - 1
		}
		mem.WriteBytes(lpBuffer, ansi[:n])
		mem.Write8(lpBuffer+uint64(n), 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterWindowMessageA", func(ctx *ntapi.TrapContext) uint32 {
		p := ctx.Arg(0)
		name := mem.ReadCString(p, 256)
		if name != "" {
			if existing, ok := hctx.RegisteredMsgNames[name]; ok {
				ctx.SetReturn(uint64(existing))
				return 0
			}
		}
		id := hctx.NextMsgID
		hctx.NextMsgID++
		if name != "" {
			hctx.RegisteredMsgNames[name] = id
		}
		ctx.SetReturn(uint64(id))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "ExitWindowsEx", func(ctx *ntapi.TrapContext) uint32 {
		uFlags := uint32(ctx.Arg(0))
		dwReason := uint32(ctx.Arg(1))
		ravelog.Logf("[user32] ExitWindowsEx flags=0x%x reason=0x%x (ignored)", uFlags, dwReason)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"FlashWindow", "FlashWindowEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "AnimateWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		dwTime := uint32(ctx.Arg(1))
		dwFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[user32] AnimateWindow hwnd=0x%x time=%d flags=0x%x", hwnd, dwTime, dwFlags)
		queuePaint(hwnd)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LockWorkStation", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[user32] LockWorkStation (ignored)\n")
		ctx.SetReturn(1)
		return 0
	})
	// Layered window attributes tracking.
	// ReactOS: win32ss/user/ntuser/layered.c
	type layeredAttrs struct {
		colorKey uint32
		alpha    uint8
		flags    uint32
	}
	layeredWindows := map[uint64]*layeredAttrs{}

	d.RegisterAutoStubHandler(user32, "SetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		colorKey := uint32(ctx.Arg(1))
		alpha := uint8(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		layeredWindows[hwnd] = &layeredAttrs{colorKey: colorKey, alpha: alpha, flags: flags}
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"UpdateLayeredWindow", "UpdateLayeredWindowIndirect"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "GetLayeredWindowAttributes", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetLayeredWindowAttributes(HWND, COLORREF*, BYTE*, DWORD*)
		hwnd := ctx.Arg(0)
		pColorKey := ctx.Arg(1)
		pAlpha := ctx.Arg(2)
		pFlags := ctx.Arg(3)
		la, ok := layeredWindows[hwnd]
		if !ok {
			ctx.SetReturn(0) // not a layered window
			return 0
		}
		if pColorKey != 0 {
			mem.Write32(pColorKey, la.colorKey)
		}
		if pAlpha != 0 {
			mem.Write8(pAlpha, la.alpha)
		}
		if pFlags != 0 {
			mem.Write32(pFlags, la.flags)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DisableProcessWindowsGhosting", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetGuiResources", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD GetGuiResources(HANDLE hProcess, DWORD uiFlags)
		uiFlags := uint32(ctx.Arg(1))
		count := uint32(len(hwndChildren))
		if uiFlags == 1 { // GR_GDIOBJECTS
			count = 50
		}
		ctx.SetReturn(uint64(count))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetGUIThreadInfo", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetGUIThreadInfo(DWORD idThread, PGUITHREADINFO pgui)
		pgui := ctx.Arg(1)
		if pgui != 0 {
			mem.Write32(pgui, 48)                // cbSize
			mem.Write32(pgui+4, 0)               // flags
			mem.Write64(pgui+8, hctx.ActiveHwnd) // hwndActive
			mem.Write64(pgui+16, hctx.FocusHwnd) // hwndFocus
			mem.Write64(pgui+24, 0)              // hwndCapture
			mem.Write64(pgui+32, 0)              // hwndMenuOwner
			mem.Write64(pgui+40, 0)              // hwndMoveSize
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "GetComboBoxInfo", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		state := hwndChildren[hwnd]
		if state == nil || (state.className != "combobox" && state.className != "comboboxex32") {
			ctx.SetReturn(0)
			return 0
		}
		if writeComboBoxInfoForTrap(ctx, ctx.Arg(1), hwnd, state.w, state.h, state.style&3, state.comboDropped) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	for _, fn := range []string{"GetListBoxInfo", "GetScrollBarInfo", "GetTitleBarInfo"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"AllowSetForegroundWindow", "LockSetForegroundWindow"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "ShowStartGlass", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	for _, fn := range []string{"ArrangeIconicWindows", "CascadeChildWindows",
		"CascadeWindows", "TileChildWindows", "TileWindows"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "RegisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := int32(ctx.Arg(1))
		fsModifiers := uint32(ctx.Arg(2))
		vk := uint32(ctx.Arg(3))
		ravelog.Logf("[user32] RegisterHotKey hwnd=0x%x id=%d mod=0x%x vk=0x%x", hwnd, id, fsModifiers, vk)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "UnregisterHotKey", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		id := int32(ctx.Arg(1))
		ravelog.Logf("[user32] UnregisterHotKey hwnd=0x%x id=%d", hwnd, id)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"RegisterDeviceNotificationA", "RegisterDeviceNotificationW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x00090001)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "UnregisterDeviceNotification", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		ravelog.Logf("[user32] UnregisterDeviceNotification handle=0x%x", handle)
		ctx.SetReturn(1)
		return 0
	})
	for _, fn := range []string{"TranslateMDISysAccel"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "AttachThreadInput", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach)
		// ReactOS: NtUserAttachThreadInput
		// We run single-threaded, so all threads share one input queue already.
		ctx.SetReturn(1) // success
		return 0
	})
	var inputBlocked bool
	d.RegisterAutoStubHandler(user32, "BlockInput", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL BlockInput(BOOL fBlockIt)
		// ReactOS: NtUserBlockInput
		fBlock := ctx.Arg(0) != 0
		if fBlock == inputBlocked {
			ctx.SetReturn(0) // already in requested state
		} else {
			inputBlocked = fBlock
			ctx.SetReturn(1)
		}
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DragDetect", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL DragDetect(HWND hwnd, POINT pt)
		_ = ctx.Arg(0)   // hwnd
		_ = ctx.Arg(1)   // pt packed as POINT
		ctx.SetReturn(0) // no drag detected
		return 0
	})
	d.RegisterAutoStubHandler(user32, "DragObject", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD DragObject(HWND hwndParent, HWND hwndFrom, UINT fmt, ULONG_PTR data, HCURSOR hcur)
		_ = ctx.Arg(0)
		_ = ctx.Arg(1)
		ravelog.Logf("[user32] DragObject (stub)\n")
		ctx.SetReturn(0)
		return 0
	})

	// -------------------------------------------------------
	// Window class (ANSI registration)
	// -------------------------------------------------------
	d.RegisterAutoStubHandler(user32, "RegisterClassA", func(ctx *ntapi.TrapContext) uint32 {
		// WNDCLASSA layout is identical to WNDCLASSW but lpszMenuName/lpszClassName are ANSI
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			var style uint32
			var wndProc, hInst, hIcon, hCursor, hBrush, lpMenuName, lpName uint64
			var cbClsExtra, cbWndExtra uint32
			if pClass < 0x100000000 {
				// WNDCLASSA x86: style(4), lpfnWndProc(4), cbClsExtra(4), cbWndExtra(4),
				// hInstance(4), hIcon(4), hCursor(4), hbrBackground(4), lpszMenuName(4), lpszClassName(4)
				style, _ = mem.Read32(pClass)
				v, _ := mem.Read32(pClass + 4)
				wndProc = uint64(v)
				cbClsExtra, _ = mem.Read32(pClass + 8)
				cbWndExtra, _ = mem.Read32(pClass + 12)
				v, _ = mem.Read32(pClass + 16)
				hInst = uint64(v)
				v, _ = mem.Read32(pClass + 20)
				hIcon = uint64(v)
				v, _ = mem.Read32(pClass + 24)
				hCursor = uint64(v)
				v, _ = mem.Read32(pClass + 28)
				hBrush = uint64(v)
				v, _ = mem.Read32(pClass + 32)
				lpMenuName = uint64(v)
				v, _ = mem.Read32(pClass + 36)
				lpName = uint64(v)
			} else {
				// WNDCLASSA x64: style(4)+pad(4), lpfnWndProc(8), cbClsExtra(4)+cbWndExtra(4),
				// hInstance(8), hIcon(8), hCursor(8), hbrBackground(8), lpszMenuName(8), lpszClassName(8)
				style, _ = mem.Read32(pClass)
				wndProc, _ = mem.Read64(pClass + 8)
				cbClsExtra, _ = mem.Read32(pClass + 16)
				cbWndExtra, _ = mem.Read32(pClass + 20)
				hInst, _ = mem.Read64(pClass + 24)
				hIcon, _ = mem.Read64(pClass + 32)
				hCursor, _ = mem.Read64(pClass + 40)
				hBrush, _ = mem.Read64(pClass + 48)
				lpMenuName, _ = mem.Read64(pClass + 56)
				lpName, _ = mem.Read64(pClass + 64)
			}
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestString(lpName)
			if name != "" {
				hctx.ClassNameAtom[strings.ToLower(name)] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				Atom: a,
			}
			if lpMenuName != 0 && mainModule != nil {
				var menuID uint32
				if lpMenuName < 0x10000 {
					menuID = uint32(lpMenuName)
				} else {
					menuName := readGuestString(lpMenuName)
					if id, err := strconv.ParseUint(menuName, 10, 32); err == nil {
						menuID = uint32(id)
					}
				}
				if menuID != 0 {
					if md := peLoadMenuResource(menuID); md != nil {
						h := gdiAlloc()
						menus[h] = md
						hctx.ClassMenuHandle[a] = h
					}
				}
			}
			ravelog.Logf("[wndclass] RegisterClassA %q atom=0x%x wndProc=0x%x\n", name, a, wndProc)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "RegisterClassExA", func(ctx *ntapi.TrapContext) uint32 {
		pClass := ctx.Arg(0)
		a := hctx.NextAtom
		hctx.NextAtom++
		if pClass != 0 {
			var style uint32
			var wndProc, hInst, hIcon, hCursor, hBrush, lpMenuName, lpName, hIconSm uint64
			var cbClsExtra, cbWndExtra uint32
			if pClass < 0x100000000 {
				// PE32: WNDCLASSEXA - all pointer fields are 4 bytes
				style, _ = mem.Read32(pClass + 4)
				v, _ := mem.Read32(pClass + 8)
				wndProc = uint64(v)
				cbClsExtra, _ = mem.Read32(pClass + 12)
				cbWndExtra, _ = mem.Read32(pClass + 16)
				v, _ = mem.Read32(pClass + 20)
				hInst = uint64(v)
				v, _ = mem.Read32(pClass + 24)
				hIcon = uint64(v)
				v, _ = mem.Read32(pClass + 28)
				hCursor = uint64(v)
				v, _ = mem.Read32(pClass + 32)
				hBrush = uint64(v)
				v, _ = mem.Read32(pClass + 36)
				lpMenuName = uint64(v)
				v, _ = mem.Read32(pClass + 40)
				lpName = uint64(v)
				v, _ = mem.Read32(pClass + 44)
				hIconSm = uint64(v)
			} else {
				// PE64: WNDCLASSEXA - pointer fields are 8 bytes
				style, _ = mem.Read32(pClass + 4)
				wndProc, _ = mem.Read64(pClass + 8)
				cbClsExtra, _ = mem.Read32(pClass + 16)
				cbWndExtra, _ = mem.Read32(pClass + 20)
				hInst, _ = mem.Read64(pClass + 24)
				hIcon, _ = mem.Read64(pClass + 32)
				hCursor, _ = mem.Read64(pClass + 40)
				hBrush, _ = mem.Read64(pClass + 48)
				lpMenuName, _ = mem.Read64(pClass + 56)
				lpName, _ = mem.Read64(pClass + 64)
				hIconSm, _ = mem.Read64(pClass + 72)
			}
			hctx.AtomWndProc[a] = wndProc
			if hBrush > 0 && hBrush <= 30 {
				hctx.ClassBrush[a] = uint32(hBrush)
			}
			name := readGuestString(lpName)
			if name != "" {
				hctx.ClassNameAtom[strings.ToLower(name)] = a
			}
			hctx.ClassInfo[a] = &registeredClassInfo{
				Style: style, WndProc: wndProc,
				ClsExtra: int32(cbClsExtra), WndExtra: int32(cbWndExtra),
				HInstance: hInst, HIcon: hIcon, HCursor: hCursor,
				HbrBG: hBrush, MenuName: lpMenuName, ClassName: name,
				HIconSm: hIconSm, Atom: a,
			}
			ravelog.Logf("[wndclass] RegisterClassExA %q atom=0x%x wndProc=0x%x\n", name, a, wndProc)
		}
		ctx.SetReturn(uint64(a))
		return 0
	})
	for _, fn := range []string{"UnregisterClassA", "UnregisterClassW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "CreateWindowExA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateWindowExA: convert ANSI class/window name to UTF-16, then delegate to CreateWindowExW logic.
		// ReactOS: win32ss/user/user32/windows/window.c CreateWindowExA -> CreateWindowExW
		hwnd := hwndAlloc()
		hctx.setWindowCPU(hwnd, ctx.CPU)
		lpClassName := ctx.Arg(1)
		style := uint32(ctx.Arg(3))

		var className string
		var classAtomForHwnd uint16
		if lpClassName != 0 && lpClassName < 0x10000 {
			classAtomForHwnd = uint16(lpClassName)
			if wp, ok := hctx.AtomWndProc[classAtomForHwnd]; ok {
				hwndWndProc[hwnd] = wp
			}
			className = fmt.Sprintf("atom:0x%x", lpClassName)
		} else if lpClassName != 0 {
			className = readGuestString(lpClassName)
			if a, ok := hctx.ClassNameAtom[strings.ToLower(className)]; ok {
				classAtomForHwnd = a
				if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
					hwndWndProc[hwnd] = wp
				}
			}
			// Fallback only for app-defined classes. Predefined/common-control class names
			// like "edit" must not inherit the app's single registered top-level WndProc.
			if classAtomForHwnd == 0 && len(hctx.ClassNameAtom) == 1 && !isBuiltinWindowClassName(className) {
				for _, a := range hctx.ClassNameAtom {
					classAtomForHwnd = a
					if wp, ok2 := hctx.AtomWndProc[a]; ok2 {
						hwndWndProc[hwnd] = wp
					}
				}
			}
		}
		if classAtomForHwnd != 0 {
			hctx.HwndClassAtom[hwnd] = classAtomForHwnd
		}
		wp := hwndWndProc[hwnd]
		parentHwndLog := ctx.Arg(8)
		if rrx, okr := ctx.CPU.(ntapi.RegisterReader); okr {
			ravelog.Logf("[wndclass] CreateWindowExA class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x EBX_at_create=0x%x\n", className, hwnd, parentHwndLog, wp, style, rrx.ReadReg(3))
		} else {
			ravelog.Logf("[wndclass] CreateWindowExA class=%q hwnd=0x%x parent=0x%x wndProc=0x%x style=0x%x\n", className, hwnd, parentHwndLog, wp, style)
		}

		// Diagnostic: dump the unpacked guest code around the known main-loop
		// pump (0x8053a1) and the WndProc, so the render gate can be
		// disassembled offline. Fires at window creation (code already
		// unpacked) instead of waiting ~15 min for the pump. RAVEN_DUMP_LOOP.
		if os.Getenv("RAVEN_DUMP_LOOP") != "" {
			for _, region := range []uint64{0x805340, 0x8053a1, 0x805440, wp} {
				lo := region &^ 0xF
				if lo < 0x100 {
					continue
				}
				lo -= 0x40
				for off := uint64(0); off < 0x100; off += 16 {
					var b [16]byte
					for j := range b {
						b[j], _ = mem.Read8(lo + off + uint64(j))
					}
					ravelog.Logf("[code-dump] 0x%x: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
						lo+off, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
				}
			}
		}

		const wsChild = 0x40000000
		if style&wsChild != 0 {
			cx := readCreateWindowIntArg(ctx, 4)
			cy := readCreateWindowIntArg(ctx, 5)
			cw := readCreateWindowIntArg(ctx, 6)
			ch := readCreateWindowIntArg(ctx, 7)
			parentHwnd := ctx.Arg(8)
			if cx < 0 || cx > maxWindowCoordinate {
				cx = 0
			}
			if cy < 0 || cy > maxWindowCoordinate {
				cy = 0
			}
			var defW, defH int32 = 800, 600
			if wlWindow != nil {
				defW, defH = wlWindow.Width, wlWindow.Height
			}
			if cw < 0 || cw > maxWindowCoordinate {
				cw = 0
			}
			if ch < 0 || ch > maxWindowCoordinate {
				ch = 0
			}
			lClassName := strings.ToLower(className)
			if lClassName == "msctls_statusbar32" {
				const sbHeight int32 = 20
				cx, cy = 0, defH-sbHeight
				cw, ch = defW, sbHeight
			} else {
				ox, oy := clientAreaOrigin(parentHwnd)
				cx += ox
				cy += oy
			}
			windowName := readGuestString(ctx.Arg(2))
			dwExStyle := uint32(ctx.Arg(0))
			hMenu := ctx.Arg(9)
			hwndChildren[hwnd] = &controlState{
				className:  lClassName,
				parentHWND: parentHwnd,
				ctrlID:     hMenu,
				x:          cx, y: cy, w: cw, h: ch,
				style:   style,
				exStyle: dwExStyle,
				text:    windowName,
				visible: style&0x10000000 != 0,
			}
			initBuiltinControlState(hwndChildren[hwnd])
			if lClassName == "msctls_progress32" {
				syncProgressBarCompat(hwndChildren[hwnd])
			}
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(dwExStyle)}
			win32.Global.Create(hwnd, lClassName, cx, cy, cw, ch, style, dwExStyle, parentHwnd)
			hctx.placeNewChildAtBottom(hwnd)
			if lClassName == "edit" && hctx.FocusHwnd == 0 {
				hctx.FocusHwnd = hwnd
			}
		}

		if style&wsChild == 0 && win32.Global.Get(hwnd) == nil {
			x := readCreateWindowIntArg(ctx, 4)
			y := readCreateWindowIntArg(ctx, 5)
			if x < 0 || x > maxWindowCoordinate {
				x = 0
			}
			if y < 0 || y > maxWindowCoordinate {
				y = 0
			}
			w, h := resolveTopLevelCreateWindowSize(ctx)
			exStyle := uint32(ctx.Arg(0))
			windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
			win32.Global.Create(hwnd, strings.ToLower(className), x, y, w, h, style, exStyle, 0)
		}

		// Create Wayland or headless window for first top-level.
		if wlWindow == nil && style&wsChild == 0 {
			title := readGuestString(ctx.Arg(2))
			if title == "" {
				title = "govm"
			}
			w, h := resolveTopLevelCreateWindowSize(ctx)
			ncTop := int32(0)
			if wlDisplay == nil || wlDisplay.HasNoSSD() {
				var r win32.Rect
				exStyle := uint32(ctx.Arg(0))
				win32.AdjustWindowRectEx(&r, style, false, exStyle)
				ncTop = -r.Top
				if ncTop < 0 {
					ncTop = 0
				}
			}
			if wlDisplay != nil {
				if win, err := wlDisplay.CreateWindow(title, w, h, ncTop); err == nil {
					wlWindow = win
					hctx.WlWindow = win
					if hctx.OnWlWindowSet != nil {
						hctx.OnWlWindowSet(win)
					}
					hctx.MainHWND = hwnd
					hctx.MainTitle = title
					exStyle := uint32(ctx.Arg(0))
					windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
					gx := readCreateWindowIntArg(ctx, 4)
					gy := readCreateWindowIntArg(ctx, 5)
					if gx < 0 || gx > maxWindowCoordinate {
						gx = 0
					}
					if gy < 0 || gy > maxWindowCoordinate {
						gy = 0
					}
					win32.Global.Create(hwnd, strings.ToLower(className), gx, gy, w, h+ncTop, style, exStyle, 0)
					ravelog.Logf("[wl] window created (A): %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
					hMenu := ctx.Arg(9)
					if hMenu != 0 {
						if _, ok := menus[hMenu]; ok {
							hwndMenuBar[hwnd] = hMenu
						}
					}
					if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
						var classAtom uint16
						if lpClassName < 0x10000 {
							classAtom = uint16(lpClassName)
						} else {
							classAtom = hctx.ClassNameAtom[readGuestString(lpClassName)]
						}
						if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
							hwndMenuBar[hwnd] = mh
						}
					}
				}
			} else if hctx.RenderSnapshot != nil {
				win := wl.NewHeadlessWindow(title, w, h, ncTop)
				wlWindow = win
				hctx.WlWindow = win
				if hctx.OnWlWindowSet != nil {
					hctx.OnWlWindowSet(win)
				}
				hctx.MainHWND = hwnd
				hctx.MainTitle = title
				exStyle := uint32(ctx.Arg(0))
				windowLongPtr[hwnd] = map[int32]uint64{-16: uint64(style), -20: uint64(exStyle)}
				gx := readCreateWindowIntArg(ctx, 4)
				gy := readCreateWindowIntArg(ctx, 5)
				if gx < 0 || gx > maxWindowCoordinate {
					gx = 0
				}
				if gy < 0 || gy > maxWindowCoordinate {
					gy = 0
				}
				win32.Global.Create(hwnd, strings.ToLower(className), gx, gy, w, h+ncTop, style, exStyle, 0)
				hMenu := ctx.Arg(9)
				if hMenu != 0 {
					if _, ok := menus[hMenu]; ok {
						hwndMenuBar[hwnd] = hMenu
					}
				}
				if _, hasMenu := hwndMenuBar[hwnd]; !hasMenu && lpClassName != 0 {
					var classAtom uint16
					if lpClassName < 0x10000 {
						classAtom = uint16(lpClassName)
					} else {
						classAtom = hctx.ClassNameAtom[strings.ToLower(readGuestString(lpClassName))]
					}
					if mh, ok := hctx.ClassMenuHandle[classAtom]; ok {
						hwndMenuBar[hwnd] = mh
					}
				}
				ravelog.Logf("[wl] headless window created (A): %q %dx%d hwnd=0x%x ncTop=%d\n", title, w, h, hwnd, ncTop)
			}
		}
		// Sync dispatch WM_NCCREATE + WM_CREATE via SyncCallWndProc (handles PE32/PE64)
		if wp, hasWP := hwndWndProc[hwnd]; hasWP && wp != 0 {
			is32 := ctx.State != nil && ctx.State.Is32
			cs := scratchAlloc(80)
			// CREATESTRUCTA layout (same byte layout as CREATESTRUCTW for all non-string fields)
			if is32 {
				mem.Write32(cs+0, uint32(ctx.Arg(11))) // lpCreateParams
				mem.Write32(cs+4, uint32(ctx.Arg(10))) // hInstance
				mem.Write32(cs+8, uint32(ctx.Arg(9)))  // hMenu
				mem.Write32(cs+12, uint32(ctx.Arg(8))) // hwndParent
				mem.Write32(cs+16, uint32(ctx.Arg(7))) // cy
				mem.Write32(cs+20, uint32(ctx.Arg(6))) // cx
				mem.Write32(cs+24, uint32(ctx.Arg(5))) // y
				mem.Write32(cs+28, uint32(ctx.Arg(4))) // x
				mem.Write32(cs+32, style)              // style
				mem.Write32(cs+36, 0)                  // padding / dwExStyle
				mem.Write32(cs+40, uint32(ctx.Arg(2))) // lpszName
				mem.Write32(cs+44, uint32(ctx.Arg(1))) // lpszClass
				mem.Write32(cs+48, uint32(ctx.Arg(0))) // dwExStyle
			} else {
				mem.Write64(cs+0, ctx.Arg(11))
				mem.Write64(cs+8, ctx.Arg(10))
				mem.Write64(cs+16, ctx.Arg(9))
				mem.Write64(cs+24, ctx.Arg(8))
				mem.Write32(cs+32, uint32(ctx.Arg(7)))
				mem.Write32(cs+36, uint32(ctx.Arg(6)))
				mem.Write32(cs+40, uint32(ctx.Arg(5)))
				mem.Write32(cs+44, uint32(ctx.Arg(4)))
				mem.Write32(cs+48, style)
				mem.Write32(cs+52, 0)
				mem.Write64(cs+56, ctx.Arg(2))
				mem.Write64(cs+64, ctx.Arg(1))
				mem.Write32(cs+72, uint32(ctx.Arg(0)))
			}

			rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
			if ok2 {
				rsp := rr.ReadReg(4)
				var retAddr uint64
				if is32 {
					v, _ := mem.Read32(rsp)
					retAddr = uint64(v)
					rsp += 4 + 12*4 // stdcall cleanup: retAddr + 12 DWORD args
					ctx.CPU.(ntapi.RegisterWriter).WriteReg(4, rsp)
				} else {
					retAddr, _ = mem.Read64(rsp)
				}
				// WM_CREATE, then (for a top-level WS_VISIBLE window that never
				// calls ShowWindow, e.g. kkrieger/Werkkzeug) the activation
				// sequence Windows auto-generates on show. It must be dispatched
				// SYNCHRONOUSLY to the WndProc, not queued: such games pump with a
				// non-zero PeekMessage filter that would never retrieve queued
				// activation, so the "window active/ready" flag their loop waits on
				// would never flip. This mirrors the ShowWindow handler.
				syncQueue := []syncDispatch{{wndProc: wp, hwnd: hwnd, msg: 0x0001, wParam: 0, lParam: cs}}
				parentArg := ctx.Arg(8)
				if parentArg == 0 && style&0x10000000 != 0 { // top-level && WS_VISIBLE
					cw, ch := getTopLevelClientSize(hwnd)
					sizeLP := (uint64(uint16(ch)) << 16) | uint64(uint16(cw))
					syncQueue = append(syncQueue,
						syncDispatch{wndProc: wp, hwnd: hwnd, msg: 0x0005, wParam: 0, lParam: sizeLP}, // WM_SIZE
						syncDispatch{wndProc: wp, hwnd: hwnd, msg: 0x001C, wParam: 1, lParam: 0},      // WM_ACTIVATEAPP(TRUE)
						syncDispatch{wndProc: wp, hwnd: hwnd, msg: 0x0086, wParam: 1, lParam: 0},      // WM_NCACTIVATE(TRUE)
						syncDispatch{wndProc: wp, hwnd: hwnd, msg: 0x0006, wParam: 1, lParam: 0},      // WM_ACTIVATE(WA_ACTIVE)
						syncDispatch{wndProc: wp, hwnd: hwnd, msg: 0x0007, wParam: 0, lParam: 0},      // WM_SETFOCUS
					)
					queuePaint(hwnd) // WM_PAINT (async, validated separately)
				}
				// Capture the game's callee-saved registers so the injected
				// WM_NCCREATE/WM_CREATE/activation dispatch is register-transparent
				// (a non-ABI-compliant guest WndProc otherwise corrupts them, e.g.
				// leaving EBX != 0, which breaks the game's later message pump).
				frame := syncDispatchFrame{
					queue:              syncQueue,
					retAddr:            retAddr,
					hwnd:               hwnd,
					hasSavedCalleeRegs: true,
				}
				if rrx, ok3 := ctx.CPU.(ntapi.RegisterReader); ok3 {
					frame.savedCalleeRegs = [4]uint64{rrx.ReadReg(3), rrx.ReadReg(5), rrx.ReadReg(6), rrx.ReadReg(7)} // EBX,EBP,ESI,EDI
				}
				syncStack := hctx.syncStack(ctx)
				*syncStack = append(*syncStack, frame)
				hctx.SyncCallWndProc(ctx, wp, hwnd, 0x0081, 0, cs, hctx.SyncTrampoline)
				return 0
			}
			// Fallback: queue messages
			hctx.enqueueMessage(nil,
				newQueuedMsg(hctx, hwnd, 0x0081, 0, cs),
				newQueuedMsg(hctx, hwnd, 0x0001, 0, cs),
			)
		}
		ctx.SetReturn(hwnd)
		return 0
	})

	// -------------------------------------------------------
	// DDE (all stub -> 0)
	// -------------------------------------------------------
	for _, fn := range []string{"DdeAbandonTransaction", "DdeAccessData", "DdeAddData",
		"DdeClientTransaction", "DdeCmpStringHandles", "DdeConnect", "DdeConnectList",
		"DdeCreateDataHandle", "DdeCreateStringHandleA", "DdeCreateStringHandleW",
		"DdeDisconnect", "DdeDisconnectList", "DdeEnableCallback", "DdeFreeDataHandle",
		"DdeFreeStringHandle", "DdeGetData", "DdeGetLastError", "DdeGetQualityOfService",
		"DdeImpersonateClient", "DdeInitializeA", "DdeInitializeW", "DdeKeepStringHandle",
		"DdeNameService", "DdePostAdvise", "DdeQueryConvInfo", "DdeQueryNextServer",
		"DdeQueryStringA", "DdeQueryStringW", "DdeReconnect", "DdeSetQualityOfService",
		"DdeSetUserHandle", "DdeUnaccessData", "DdeUninitialize",
		"FreeDDElParam", "PackDDElParam", "ReuseDDElParam", "UnpackDDElParam",
		"ImpersonateDdeClientWindow"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Desktop / WindowStation (all stub)
	// -------------------------------------------------------
	for _, fn := range []string{"CloseDesktop", "CloseWindowStation", "CreateDesktopA",
		"CreateDesktopW", "CreateWindowStationA", "CreateWindowStationW",
		"GetInputDesktop", "GetProcessWindowStation", "GetThreadDesktop",
		"GetUserObjectInformationA", "GetUserObjectInformationW", "GetUserObjectSecurity",
		"LockWindowStation", "OpenDesktopA", "OpenDesktopW", "OpenInputDesktop",
		"OpenWindowStationA", "OpenWindowStationW", "SetProcessWindowStation",
		"SetThreadDesktop", "SetUserObjectInformationA", "SetUserObjectInformationW",
		"SetUserObjectSecurity", "SwitchDesktop", "UnlockWindowStation",
		"EnumDesktopsA", "EnumDesktopsW", "EnumDesktopWindows",
		"EnumWindowStationsA", "EnumWindowStationsW", "GetWinStationInfo"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Raw input (all stub)
	// -------------------------------------------------------
	for _, fn := range []string{"GetRawInputBuffer", "GetRawInputData",
		"GetRawInputDeviceInfoA", "GetRawInputDeviceInfoW", "GetRawInputDeviceList",
		"GetRegisteredRawInputDevices", "RegisterRawInputDevices", "DefRawInputProc"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// IME / WINNLS / misc internal
	// -------------------------------------------------------
	for _, fn := range []string{"IMPGetIMEA", "IMPGetIMEW", "IMPQueryIMEA", "IMPQueryIMEW",
		"IMPSetIMEA", "IMPSetIMEW", "CliImmSetHotKey",
		"WINNLSEnableIME", "WINNLSGetEnableStatus", "WINNLSGetIMEHotkey"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SendIMEMessageExA", "SendIMEMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Accelerators / icons (stubs)
	// -------------------------------------------------------
	// ─── Icon/Image/Cursor loading ───────────────────────────────────────
	d.RegisterAutoStubHandler(user32, "LoadIconA", func(ctx *ntapi.TrapContext) uint32 {
		// Same logic as LoadIconW - return dummy icon handle
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if hInst == 0 && nameArg >= 32512 && nameArg <= 32522 {
			// System icon (IDI_APPLICATION etc.)
			ctx.SetReturn(0x00020000 + nameArg)
			return 0
		}
		// App icon from PE resource
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			_, _, ok := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 14 /*RT_GROUP_ICON*/, uint32(nameArg))
			if ok {
				handle := 0x00020000 + nameArg
				if icon := loadResourceIcon(uint32(nameArg), 32, 32); icon != nil {
					hctx.storeIcon(handle, icon)
				}
				ctx.SetReturn(handle)
				return 0
			}
		}
		ctx.SetReturn(0x00020001) // dummy icon
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadImageA", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		imgType := ctx.Arg(2)
		// IMAGE_BITMAP=0: try to load from PE resource (same as LoadImageW)
		if imgType == 0 && nameArg < 0x10000 && mainModule != nil &&
			(hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2 /*RT_BITMAP*/, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bitCount, _ := mem.Read16(addr + 14)
				width, height := dibDimensions(addr)
				bd := &bitmapHandleData{slots: slots, w: width, h: height, monochrome: bitCount == 1}
				bitmapHandles[h] = bd
				ravelog.Logf("[loadimage] LoadImageA IMAGE_BITMAP resID=0x%x -> handle=0x%x\n", resID, h)
				ctx.SetReturn(h)
				return 0
			}
		}
		// IMAGE_ICON=1: return dummy icon handle
		if imgType == 1 {
			if nameArg < 0x10000 {
				handle := 0x00020000 + nameArg
				if mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
					if icon := loadResourceIcon(uint32(nameArg), int32(ctx.Arg(3)), int32(ctx.Arg(4))); icon != nil {
						hctx.storeIcon(handle, icon)
					}
				}
				ctx.SetReturn(handle)
			} else {
				ctx.SetReturn(0x00020001)
			}
			return 0
		}
		// IMAGE_CURSOR=2: return dummy cursor handle
		if imgType == 2 {
			ctx.SetReturn(0x00010001)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadBitmapA", func(ctx *ntapi.TrapContext) uint32 {
		hInst := ctx.Arg(0)
		nameArg := ctx.Arg(1)
		if nameArg < 0x10000 && mainModule != nil && (hInst == mainModule.BaseAddr || hInst == 0) {
			resID := uint32(nameArg)
			addr, sz, ok2 := peLoadRawResource(mainModule.BaseAddr, mainModule.ResourceDirRVA, 2, resID)
			if ok2 {
				slots := decodeDIBSlots(addr, sz, 0, 0)
				h := hctx.NextBitmapHandle
				hctx.NextBitmapHandle += 2
				bitCount, _ := mem.Read16(addr + 14)
				width, height := dibDimensions(addr)
				bd := &bitmapHandleData{slots: slots, w: width, h: height, monochrome: bitCount == 1}
				bitmapHandles[h] = bd
				ctx.SetReturn(h)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CopyImage", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		ctx.SetReturn(h) // return same handle (shallow copy)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIconFromResourceEx", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIconFromResourceEx(PBYTE presbits, DWORD dwResSize, BOOL fIcon,
		//   DWORD dwVer, int cxDesired, int cyDesired, UINT Flags)
		fIcon := ctx.Arg(2) != 0
		cxDesired := int32(ctx.Arg(4))
		cyDesired := int32(ctx.Arg(5))
		if cxDesired == 0 {
			cxDesired = 32
		}
		if cyDesired == 0 {
			cyDesired = 32
		}
		var decoded *iconHandleData
		if data, err := mem.ReadBytes(ctx.Arg(0), int(ctx.Arg(1))); err == nil {
			if icon, ok := decodeIconResource(data); ok {
				icon.pixels = scaleIconPixels(icon, cxDesired, cyDesired)
				icon.width, icon.height = cxDesired, cyDesired
				decoded = icon
			}
		}
		h := hctx.allocIcon(decoded)
		ravelog.Logf("[user32] CreateIconFromResourceEx handle=0x%x icon=%v size=%dx%d\n",
			h, fIcon, cxDesired, cyDesired)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIconFromResource", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIconFromResource(PBYTE presbits, DWORD dwResSize, BOOL fIcon, DWORD dwVer)
		fIcon := ctx.Arg(2) != 0
		var decoded *iconHandleData
		if data, err := mem.ReadBytes(ctx.Arg(0), int(ctx.Arg(1))); err == nil {
			if icon, ok := decodeIconResource(data); ok {
				decoded = icon
			}
		}
		h := hctx.allocIcon(decoded)
		ravelog.Logf("[user32] CreateIconFromResource handle=0x%x icon=%v\n", h, fIcon)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateCursor", func(ctx *ntapi.TrapContext) uint32 {
		// HCURSOR CreateCursor(HINSTANCE, int xHot, int yHot, int nWidth, int nHeight,
		//   const VOID *pvANDPlane, const VOID *pvXORPlane)
		nw := int32(ctx.Arg(3))
		nh := int32(ctx.Arg(4))
		h := hctx.allocIcon(&iconHandleData{width: nw, height: nh})
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CreateIcon", func(ctx *ntapi.TrapContext) uint32 {
		// HICON CreateIcon(HINSTANCE, int nWidth, int nHeight, BYTE cPlanes, BYTE cBitsPixel,
		//   const BYTE *lpbANDbits, const BYTE *lpbXORbits)
		nw := int32(ctx.Arg(1))
		nh := int32(ctx.Arg(2))
		h := hctx.allocIcon(&iconHandleData{width: nw, height: nh})
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LookupIconIdFromDirectory", func(ctx *ntapi.TrapContext) uint32 {
		// int LookupIconIdFromDirectory(PBYTE presbits, BOOL fIcon)
		// ReactOS: LookupIconIdFromDirectoryEx with default sizes
		// Parse GRPICONDIR: idReserved(2), idType(2), idCount(2), then GRPICONDIRENTRY[idCount]
		presbits := ctx.Arg(0)
		if presbits == 0 {
			ctx.SetReturn(0)
			return 0
		}
		idCount, _ := mem.Read16(presbits + 4)
		if idCount == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Return the nID of the first entry (offset 12 in GRPICONDIRENTRY, at presbits+6+0*14+12)
		nID, _ := mem.Read16(presbits + 6 + 12)
		ctx.SetReturn(uint64(nID))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LookupIconIdFromDirectoryEx", func(ctx *ntapi.TrapContext) uint32 {
		// int LookupIconIdFromDirectoryEx(PBYTE presBits, BOOL fIcon, int cxDesired, int cyDesired, UINT Flags)
		// ReactOS: win32ss/user/user32/windows/cursoricon.c
		presBits := ctx.Arg(0)
		fIcon := ctx.Arg(1) != 0
		cxDesired := int32(ctx.Arg(2))
		cyDesired := int32(ctx.Arg(3))
		ravelog.Logf("[user32] LookupIconIdFromDirectoryEx bits=0x%x icon=%v cx=%d cy=%d\n",
			presBits, fIcon, cxDesired, cyDesired)
		ctx.SetReturn(1) // first resource ID
		return 0
	})
	for _, fn := range []string{"PrivateExtractIconExA", "PrivateExtractIconExW",
		"PrivateExtractIconsA", "PrivateExtractIconsW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // no icons extracted
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "LoadCursorFromFileA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00010001)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "LoadCursorFromFileW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x00010001)
		return 0
	})

	// -------------------------------------------------------
	// MDI / misc window management
	// -------------------------------------------------------
	for _, fn := range []string{"CreateMDIWindowA", "CreateMDIWindowW",
		"DefFrameProcA", "DefFrameProcW", "DefMDIChildProcA", "DefMDIChildProcW",
		"TranslateMDISysAccel"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "DefWindowProcA", defWindowProcFn)
	d.RegisterAutoStubHandler(user32, "CallWindowProcA", func(ctx *ntapi.TrapContext) uint32 {
		lpPrevWndFunc := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)

		ravelog.Logf("[callwndproc] CallWindowProcA prev=0x%x hwnd=0x%x msg=0x%x\n", lpPrevWndFunc, hwnd, msg)

		if lpPrevWndFunc == builtinControlWndProc {
			hctx.CallBuiltinControl = true
			result, handled := builtinWndProc(hwnd, msg, wParam, lParam)
			hctx.CallBuiltinControl = false
			if handled {
				ctx.SetReturn(result)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		}

		// Dispatch synchronously to the specified WndProc (same as SendMessageW pattern)
		if lpPrevWndFunc != 0 {
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4) // RSP
				retAddr, _ := mem.Read64(rsp)
				if retAddr >= 0x1000000 {
					syncStack := hctx.syncStack(ctx)
					*syncStack = append(*syncStack, syncDispatchFrame{
						queue:               []syncDispatch{},
						retAddr:             retAddr,
						hwnd:                hwnd,
						returnWndProcResult: true,
					})
					rsp -= 48
					mem.Write64(rsp, hctx.SyncTrampoline)
					rw.WriteReg(4, rsp)
					rw.WriteReg(1, hwnd)
					rw.WriteReg(2, uint64(msg))
					rw.WriteReg(8, wParam)
					rw.WriteReg(9, lParam)
					ctx.CPU.SetPC(lpPrevWndFunc)
					ctx.ReturnOverridden = true
					ctx.PCRedirected = true
					return 0
				}
			}
		}

		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(user32, "CallWindowProcW", func(ctx *ntapi.TrapContext) uint32 {
		lpPrevWndFunc := ctx.Arg(0)
		hwnd := ctx.Arg(1)
		msg := uint32(ctx.Arg(2))
		wParam := ctx.Arg(3)
		lParam := ctx.Arg(4)

		ravelog.Logf("[callwndproc] CallWindowProcW prev=0x%x hwnd=0x%x msg=0x%x\n", lpPrevWndFunc, hwnd, msg)

		if lpPrevWndFunc == builtinControlWndProc {
			hctx.CallBuiltinControl = true
			result, handled := builtinWndProc(hwnd, msg, wParam, lParam)
			hctx.CallBuiltinControl = false
			if handled {
				ctx.SetReturn(result)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		}

		// Dispatch synchronously to the specified WndProc (same as SendMessageW pattern)
		if lpPrevWndFunc != 0 {
			rw, okW := ctx.CPU.(ntapi.RegisterWriter)
			rr, okR := ctx.CPU.(ntapi.RegisterReader)
			if okW && okR {
				rsp := rr.ReadReg(4) // RSP
				retAddr, _ := mem.Read64(rsp)
				if retAddr >= 0x1000000 {
					syncStack := hctx.syncStack(ctx)
					*syncStack = append(*syncStack, syncDispatchFrame{
						queue:               []syncDispatch{},
						retAddr:             retAddr,
						hwnd:                hwnd,
						returnWndProcResult: true,
					})
					rsp -= 48
					mem.Write64(rsp, hctx.SyncTrampoline)
					rw.WriteReg(4, rsp)
					rw.WriteReg(1, hwnd)
					rw.WriteReg(2, uint64(msg))
					rw.WriteReg(8, wParam)
					rw.WriteReg(9, lParam)
					ctx.CPU.SetPC(lpPrevWndFunc)
					ctx.ReturnOverridden = true
					ctx.PCRedirected = true
					return 0
				}
			}
		}

		ctx.SetReturn(0)
		return 0
	})
	for _, fn := range []string{"CallMsgFilter", "CallMsgFilterA", "CallMsgFilterW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "EnumThreadWindows", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumThreadWindows(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam)
		// ReactOS: NtUserBuildHwndList
		// Since we're single-threaded, enumerate all top-level windows.
		lpEnumFunc := ctx.Arg(1)
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		all := win32.Global.AllWindows()
		if len(all) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, ok := ctx.CPU.(ntapi.RegisterWriter)
		rr, ok2 := ctx.CPU.(ntapi.RegisterReader)
		if !ok || !ok2 {
			ctx.SetReturn(1)
			return 0
		}
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		queue := make([]syncDispatch, len(all))
		for i, h := range all {
			queue[i] = syncDispatch{wndProc: lpEnumFunc, hwnd: h, msg: lParam}
		}
		syncStack := hctx.syncStack(ctx)
		*syncStack = append(*syncStack, syncDispatchFrame{
			queue:   queue[1:],
			retAddr: retAddr,
			hwnd:    1,
		})
		rsp -= 48
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(4, rsp)
		rw.WriteReg(1, queue[0].hwnd)
		rw.WriteReg(2, uint64(queue[0].msg))
		rw.WriteReg(8, 0)
		rw.WriteReg(9, 0)
		ctx.CPU.SetPC(queue[0].wndProc)
		ctx.ReturnOverridden = true
		ctx.PCRedirected = true
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SwitchToThisWindow", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(user32, "SetDoubleClickTime", func(ctx *ntapi.TrapContext) uint32 {
		doubleClickTime = normalizeDoubleClickTime(uint32(ctx.Arg(0)))
		ctx.SetReturn(1)
		return 0
	})

	// -------------------------------------------------------
	// WinHelp / string conversion helpers
	// -------------------------------------------------------
	for _, fn := range []string{"WinHelpA", "WinHelpW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(user32, "wvsprintfW", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		vaList := ctx.Arg(2)
		result := formatString(mem, readGuestUTF16(lpFmt), collectVAList(mem, vaList, 24, ctx.State != nil && ctx.State.Is32), true)
		writeUTF16(mem, lpOut, result, -1)
		ctx.SetReturn(uint64(len([]rune(result))))
		return 0
	})
	d.RegisterAutoStubHandler(user32, "wvsprintfA", func(ctx *ntapi.TrapContext) uint32 {
		lpOut := ctx.Arg(0)
		lpFmt := ctx.Arg(1)
		vaList := ctx.Arg(2)
		result := formatString(mem, readGuestString(lpFmt), collectVAList(mem, vaList, 24, ctx.State != nil && ctx.State.Is32), false)
		writeCString(mem, lpOut, result, -1)
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	for _, fn := range []string{"MB_GetString",
		"MBToWCSEx", "WCSToMBEx"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"AlignRects", "BuildReasonArray", "DestroyReasons",
		"ReasonCodeNeedsBugID", "ReasonCodeNeedsComment", "RecordShutdownReason",
		"GetReasonTitleFromReasonCode", "DisplayExitWindowsWarnings"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}

	// -------------------------------------------------------
	// Internal / undocumented
	// -------------------------------------------------------
	for _, fn := range []string{"UserClientDllInitialize", "User32InitializeImmEntryTable",
		"ClientThreadSetup", "CtxInitUser32", "CreateSystemThreads",
		"InitializeLpkHooks", "InitializeWin32EntryTable",
		"UserHandleGrantAccess", "UserLpkPSMTextOut", "UserLpkTabbedTextOut",
		"UserRealizePalette", "UserRegisterWowHandlers",
		"UpdatePerUserSystemParameters", "Win32PoolAllocationStats",
		"AllowForegroundActivation", "DeviceEventWorker",
		"EnterReaderModeHelper", "GetAppCompatFlags", "GetAppCompatFlags2",
		"GetAltTabInfo", "GetAltTabInfoA", "GetAltTabInfoW",
		"GetInputDesktop", "GetInternalWindowPos", "SetInternalWindowPos",
		"GetProgmanWindow", "SetProgmanWindow", "GetShellWindow",
		"SetShellWindow", "SetShellWindowEx", "GetTaskmanWindow", "SetTaskmanWindow",
		"SetLogonNotifyWindow", "RegisterLogonProcess", "RegisterServicesProcess",
		"RegisterSystemThread", "RegisterTasklist", "RegisterMessagePumpHook",
		"UnregisterMessagePumpHook", "RegisterUserApiHook", "UnregisterUserApiHook",
		"SetConsoleReserveKeys", "SetDebugErrorLevel", "SetLastErrorEx",
		"SetDeskWallpaper", "SetKeyboardState", "SetMessageQueue",
		"SetProcessDefaultLayout", "GetProcessDefaultLayout",
		"SetWindowStationUser", "LoadLocalFonts", "LoadRemoteFonts",
		"KillSystemTimer", "SetSystemTimer",
		"ScrollChildren", "EndTask", "IsWinEventHookInstalled",
		"GetAltTabInfo", "EditWndProc",
		"ClientThreadSetup", "CsrBroadcastSystemMessageExW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(0)
			return 0
		})
	}
	for _, fn := range []string{"SetSysColors", "SetSysColorsTemp", "SetSystemCursor"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(user32, fn, func(ctx *ntapi.TrapContext) uint32 {
			p0, p1, p2, p3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
			ravelog.Logf("[user32] %s(0x%x, 0x%x, 0x%x, 0x%x)\n", fn, p0, p1, p2, p3)
			ctx.SetReturn(1)
			return 0
		})
	}

	// DPI-aware functions (Win10+) - apps resolve at runtime via GetProcAddress.
	// Using RegisterDynamicHandler to make them discoverable.
	nextDynID := uint32(ntapi.DynExportIDBase)
	d.RegisterDynamicHandler(mem, user32, "MessageBoxA", nextDynID, messageBoxAHandler)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "MessageBoxW", nextDynID, messageBoxWHandler)
	nextDynID++
	dpiStub96 := func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(96) // standard DPI
		return 0
	}
	d.RegisterDynamicHandler(mem, user32, "GetDpiForSystem", nextDynID, dpiStub96)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetDpiForWindow", nextDynID, dpiStub96)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetSystemMetricsForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		index := int(ctx.Arg(0))
		dpi := uint32(ctx.Arg(1))
		ctx.SetReturn(uint64(win32.GetSystemMetricsForDPI(index, dpi)))
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "AdjustWindowRectExForDpi", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SetThreadDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0)) // return previous context = same as requested
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetThreadDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xFFFFFFFFFFFFFFFD) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-3)
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "GetWindowDpiAwarenessContext", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0xFFFFFFFFFFFFFFFD) // DPI_AWARENESS_CONTEXT_SYSTEM_AWARE (-3)
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "AreDpiAwarenessContextsEqual", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == ctx.Arg(1) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "ChangeWindowMessageFilterEx", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SetCoalescableTimer", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		// Delegate to SetTimer behavior - return a timer ID
		ctx.SetReturn(ctx.Arg(1)) // nIDEvent
		return 0
	})
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SystemParametersInfoForDpi", nextDynID, systemParametersInfoForDPIHandler)
	nextDynID++
	d.RegisterDynamicHandler(mem, user32, "SetWindowCompositionAttribute", nextDynID, func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		data := ctx.Arg(1)
		if hwnd == 0 || data == 0 ||
			(hwnd != hctx.MainHWND && hwnd != 0x00050000 && hwndChildren[hwnd] == nil) {
			ctx.SetReturn(0)
			return 0
		}
		structSize := 20
		if ctx.State != nil && ctx.State.Is32 {
			structSize = 12
		}
		if _, err := mem.ReadBytes(data, structSize); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		attribute, err := mem.Read32(data)
		if err != nil || attribute == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var valuePtr uint64
		var valueSize uint32
		if ctx.State != nil && ctx.State.Is32 {
			raw, readErr := mem.Read32(data + 4)
			if readErr != nil {
				ctx.SetReturn(0)
				return 0
			}
			valuePtr = uint64(raw)
			valueSize, err = mem.Read32(data + 8)
		} else {
			valuePtr, err = mem.Read64(data + 8)
			if err == nil {
				valueSize, err = mem.Read32(data + 16)
			}
		}
		if err != nil || valuePtr == 0 || valueSize == 0 || valueSize > 4096 {
			ctx.SetReturn(0)
			return 0
		}
		value, err := mem.ReadBytes(valuePtr, int(valueSize))
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		attributes := windowCompositionAttributes[hwnd]
		if attributes == nil {
			attributes = make(map[uint32][]byte)
			windowCompositionAttributes[hwnd] = attributes
		}
		attributes[attribute] = append([]byte(nil), value...)
		ravelog.Logf("[user32] SetWindowCompositionAttribute hwnd=0x%x attribute=%d data=0x%x size=%d\n",
			hwnd, attribute, valuePtr, valueSize)
		ctx.SetReturn(1)
		return 0
	})
	nextDynID++
	_ = nextDynID
}

// sendFindMessage writes the current FindDialog text into the guest FINDREPLACEW
// struct and posts the FINDMSGSTRING message to the owner window.
// flags: FR_FINDNEXT=0x08, FR_REPLACE=0x10, FR_REPLACEALL=0x20, FR_DIALOGTERM=0x40
func sendFindMessage(hctx *HandlerCtx, mem *mmu.MMU, flags uint32) {
	fd := hctx.FindDialog
	if fd == nil {
		return
	}
	// Write find text into guest buffer.
	if fd.LpstrFindWhat != 0 {
		writeGuestUTF16StringN(mem, fd.LpstrFindWhat, fd.FindText, int(fd.FindWhatLen))
	}
	// Write replace text for replace operations.
	if fd.IsReplace && fd.LpstrReplaceWith != 0 {
		writeGuestUTF16StringN(mem, fd.LpstrReplaceWith, fd.ReplaceText, int(fd.ReplaceWithLen))
	}
	// Build FR flags: preserve direction and case-sensitive bits.
	var fr uint32 = flags
	if fd.SearchDown {
		fr |= 0x0001 // FR_DOWN
	}
	if fd.CaseSensitive {
		fr |= 0x0004 // FR_MATCHCASE
	}
	if fd.WholeWord {
		fr |= 0x0002 // FR_WHOLEWORD
	}
	// Write flags into FINDREPLACEW.Flags (+24)
	if fd.PFR != 0 {
		mem.Write32(fd.PFR+24, fr)
	}
	// Post message to owner window.
	hctx.enqueueMessage(nil, newQueuedMsg(hctx, fd.OwnerHWND, uint32(fd.MsgID), 0, fd.PFR))
	ravelog.Logf("[FindDialog] sendFindMessage flags=0x%x text=%q\n", flags, fd.FindText)
}
