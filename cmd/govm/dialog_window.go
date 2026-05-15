//go:build guest_windows

package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

type dialogTextPainter struct {
	dc *gdi.DC
}

type ownedDialogControlPalette struct {
	dialog        uint32
	surface       uint32
	inactive      uint32
	border        uint32
	frame         uint32
	button        uint32
	text          uint32
	highlight     uint32
	highlightText uint32
}

type dialogRenderState struct {
	mu        sync.Mutex
	rendering bool
	pending   bool
}

func (hctx *HandlerCtx) beginDialogRender(root uint64) (*dialogRenderState, bool) {
	hctx.DialogRenderMu.Lock()
	if hctx.DialogRenders == nil {
		hctx.DialogRenders = make(map[uint64]*dialogRenderState)
	}
	state := hctx.DialogRenders[root]
	if state == nil {
		state = &dialogRenderState{}
		hctx.DialogRenders[root] = state
	}
	hctx.DialogRenderMu.Unlock()

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.rendering {
		state.pending = true
		return state, false
	}
	state.rendering = true
	return state, true
}

func (state *dialogRenderState) finishPass() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pending {
		state.pending = false
		return true
	}
	state.rendering = false
	return false
}

func (state *dialogRenderState) release() {
	state.mu.Lock()
	state.rendering = false
	state.mu.Unlock()
}

func ownedDialogPalette(dark bool) ownedDialogControlPalette {
	if dark {
		return ownedDialogControlPalette{
			dialog:        darkPalette.Control,
			surface:       darkPalette.Background,
			inactive:      darkPalette.Input,
			border:        darkPalette.Border,
			frame:         darkPalette.Border,
			button:        darkPalette.Control,
			text:          darkPalette.Text,
			highlight:     darkPalette.Highlight,
			highlightText: darkPalette.HighlightText,
		}
	}
	return ownedDialogControlPalette{
		dialog:        0xF0F0F0,
		surface:       0xFFFFFF,
		inactive:      0xE1E1E1,
		border:        0xA0A0A0,
		frame:         0x7A7A7A,
		button:        0xE1E1E1,
		text:          0x000000,
		highlight:     0x0078D7,
		highlightText: 0xFFFFFF,
	}
}

func captureOwnedControlPaint(state, root *controlState, target *wl.Window) {
	if state == nil || root == nil || target == nil {
		return
	}
	state.guestPaintMu.Lock()
	defer state.guestPaintMu.Unlock()
	x, y := state.x-root.x, state.y-root.y
	w, h := state.w, state.h
	if w <= 0 || h <= 0 || x < 0 || y < 0 || x+w > target.Width || y+h > target.Height || target.Stride <= 0 {
		return
	}
	rowBytes := int(w * 4)
	pixels := make([]byte, rowBytes*int(h))
	for row := int32(0); row < h; row++ {
		source := int((y+row)*target.Stride + x*4)
		copy(pixels[int(row)*rowBytes:], target.Pix[source:source+rowBytes])
	}
	state.guestPaintX = x
	state.guestPaintY = y
	state.guestPaintW = w
	state.guestPaintH = h
	state.guestPaintPixels = pixels
	state.guestPainted = true
}

func restoreOwnedControlPaint(state, root *controlState, target *wl.Window) {
	if state == nil || root == nil || target == nil {
		return
	}
	state.guestPaintMu.Lock()
	defer state.guestPaintMu.Unlock()
	x, y := state.guestPaintX, state.guestPaintY
	w, h := state.guestPaintW, state.guestPaintH
	if !state.guestPainted || w <= 0 || h <= 0 || len(state.guestPaintPixels) != int(w*h*4) {
		return
	}
	if state.x-root.x != x || state.y-root.y != y || state.w != w || state.h != h {
		return
	}
	if x < 0 || y < 0 || x+w > target.Width || y+h > target.Height || target.Stride <= 0 {
		return
	}
	rowBytes := int(w * 4)
	for row := int32(0); row < h; row++ {
		destination := int((y+row)*target.Stride + x*4)
		copy(target.Pix[destination:destination+rowBytes], state.guestPaintPixels[int(row)*rowBytes:int(row+1)*rowBytes])
	}
}

func hasOwnedControlPaint(state *controlState) bool {
	if state == nil {
		return false
	}
	state.guestPaintMu.RLock()
	defer state.guestPaintMu.RUnlock()
	return state.guestPainted && len(state.guestPaintPixels) != 0
}

func hostRendersOwnedControlInDarkMode(state *controlState) bool {
	if state == nil {
		return false
	}
	switch strings.ToLower(state.className) {
	case "dialog", "#32770",
		"static",
		"edit", "richedit20w", "richedit50w",
		"combobox", "comboboxex32",
		"listbox":
		return true
	case "button":
		return state.ctrlID != 0 && state.style&0x0F != 11
	case "msctls_trackbar32",
		"systabcontrol32", "systreeview32", "syslistview32":
		return true
	default:
		return false
	}
}

type ownedDialogColorState struct {
	brush     uint64
	textColor uint32
	bkColor   uint32
}

var ownedDialogColors = struct {
	sync.RWMutex
	values      map[uint64]ownedDialogColorState
	customPaint map[uint64][]ownedDialogCustomPaintState
}{
	values:      make(map[uint64]ownedDialogColorState),
	customPaint: make(map[uint64][]ownedDialogCustomPaintState),
}

type ownedDialogCustomPaintState struct {
	hwnd, parent        uint64
	x, y, width, height int32
	visible, showCalled bool
	wndProc             uint64
}

func clearOwnedDialogColor(hwnd uint64) {
	ownedDialogColors.Lock()
	delete(ownedDialogColors.values, hwnd)
	delete(ownedDialogColors.customPaint, hwnd)
	ownedDialogColors.Unlock()
}

func shouldPrimeOwnedDialogCustomPaint(hctx *HandlerCtx, root uint64) bool {
	if hctx == nil || hctx.RenderDialogCustom == nil {
		return false
	}
	var handles []uint64
	for hwnd := range hctx.HwndChildren {
		if hwnd != root && isDialogDescendant(hctx, hwnd, root) {
			handles = append(handles, hwnd)
		}
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	current := make([]ownedDialogCustomPaintState, 0, len(handles))
	for _, hwnd := range handles {
		state := hctx.HwndChildren[hwnd]
		if state == nil {
			continue
		}
		current = append(current, ownedDialogCustomPaintState{
			hwnd:       hwnd,
			parent:     state.parentHWND,
			x:          state.x,
			y:          state.y,
			width:      state.w,
			height:     state.h,
			visible:    state.visible,
			showCalled: state.showCalled,
			wndProc:    hctx.HwndWndProc[hwnd],
		})
	}

	ownedDialogColors.Lock()
	previous, ok := ownedDialogColors.customPaint[root]
	changed := !ok || len(previous) != len(current)
	if !changed {
		for i := range current {
			if previous[i] != current[i] {
				changed = true
				break
			}
		}
	}
	if changed {
		ownedDialogColors.customPaint[root] = current
	}
	ownedDialogColors.Unlock()
	return changed
}

func normalizeOwnedStatusBar(state, root *controlState, width, height int32) bool {
	if state == nil || root == nil || !strings.EqualFold(state.className, "msctls_statusbar32") {
		return false
	}
	const statusHeight = int32(20)
	if width <= 0 {
		width = root.w
	}
	if height <= 0 {
		height = root.h
	}
	state.mutateGeometry(func(geometry *controlGeometry) {
		geometry.x = root.x
		geometry.y = root.y + height - statusHeight
		geometry.w = width
		geometry.h = statusHeight
	})
	return true
}

func waylandWindowHWND(primary *wl.Window, mainHWND uint64, owned map[*wl.Window]uint64, win *wl.Window) uint64 {
	if win == nil {
		return 0
	}
	if win == primary {
		return mainHWND
	}
	return owned[win]
}

func dialogCancelControl(children map[uint64]*controlState, dialog uint64) uint64 {
	for hwnd, state := range children {
		if state != nil && state.parentHWND == dialog && state.ctrlID == 2 {
			return hwnd
		}
	}
	return 0
}

func dialogCloseControl(children map[uint64]*controlState, dialog uint64) (uint64, uint64) {
	if cancel := dialogCancelControl(children, dialog); cancel != 0 {
		return cancel, 2
	}
	var closeHandles []uint64
	var okHandles []uint64
	for hwnd, state := range children {
		if state == nil || state.parentHWND != dialog || !strings.EqualFold(state.className, "button") {
			continue
		}
		label := strings.TrimSpace(dialogLabel(state.text))
		if strings.EqualFold(label, "close") || strings.EqualFold(label, "cancel") {
			closeHandles = append(closeHandles, hwnd)
		} else if state.ctrlID == 1 && strings.EqualFold(label, "ok") {
			okHandles = append(okHandles, hwnd)
		}
	}
	handles := closeHandles
	if len(handles) == 0 {
		handles = okHandles
	}
	if len(handles) == 0 {
		return 0, 0
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	hwnd := handles[0]
	return hwnd, children[hwnd].ctrlID
}

func newDialogTextPainter(win *wl.Window) *dialogTextPainter {
	surface := gdi.WrapPix(win.Pix, win.Width, win.Height+win.TitleBarH, win.Stride)
	dc := gdi.NewScreenDC(surface)
	dc.Font = gdi.DefaultGUIFont()
	dc.BkMode = 1
	return &dialogTextPainter{dc: dc}
}

func remapDialogForDarkMode(win *wl.Window) {
	if win == nil {
		return
	}
	surface := gdi.WrapPix(win.Pix, win.Width, win.Height+win.TitleBarH, win.Stride)
	dc := gdi.NewScreenDC(surface)
	remapDCRectForDarkMode(dc, 0, 0, win.Width, win.Height+win.TitleBarH)
}

func dispatchOwnedDialogColors(hctx *HandlerCtx, root uint64, renderCPU arch.CPU, win *wl.Window) {
	if hctx == nil || win == nil || hctx.GdiMgr == nil {
		return
	}
	if !effectiveDarkModeForWindow(root, hctx.HwndChildren) {
		return
	}
	rootState := hctx.HwndChildren[root]
	if rootState == nil {
		return
	}
	surface := gdi.WrapPix(win.Pix, win.Width, win.Height+win.TitleBarH, win.Stride)
	for hwnd, state := range hctx.HwndChildren {
		if !visibleOwnedDialogDescendant(hctx, hwnd, root) {
			continue
		}
		message := ctlColorMessageForClass(state.className)
		if message == 0 {
			continue
		}
		hdc, dc := hctx.GdiMgr.AllocTargetDC(surface)
		x := state.x - rootState.x
		y := state.y - rootState.y
		dc.OriginX = x
		dc.OriginY = y
		dc.SetClipRect(x, y, x+state.w, y+state.h)
		ownedDialogColors.RLock()
		colors, cached := ownedDialogColors.values[hwnd]
		ownedDialogColors.RUnlock()
		if hctx.WinInvalid[hwnd] || hctx.WinErasePending[hwnd] || !cached {
			hctx.WinInvalid[hwnd] = false
			delete(hctx.WinErasePending, hwnd)
			callbackCPU := hctx.windowCPU(state.parentHWND)
			if callbackCPU == nil {
				callbackCPU = renderCPU
			}
			switchedCPU := callbackCPU != renderCPU
			if switchedCPU {
				hctx.DialogSurfaceMu.Transfer(renderCPU, callbackCPU)
			}
			brush, dispatched := dispatchGuestWindowMessage(hctx, state.parentHWND, message, hdc, hwnd)
			if switchedCPU {
				hctx.DialogSurfaceMu.Transfer(callbackCPU, renderCPU)
			}
			if dispatched {
				colors = ownedDialogColorState{
					brush: brush, textColor: dc.TextColor, bkColor: dc.BkColor,
				}
				ownedDialogColors.Lock()
				ownedDialogColors.values[hwnd] = colors
				ownedDialogColors.Unlock()
				cached = true
			}
		}
		if cached {
			dc.TextColor = colors.textColor
			dc.BkColor = colors.bkColor
		}
		if cached && colors.brush != 0 {
			switch strings.ToLower(state.className) {
			case "static":
				fillRectUsingBrushHandle(dc, hctx.GdiMgr, colors.brush, hctx.SysColors, 0, 0, state.w, state.h)
				dc.TextOut(2, 2, dialogLabel(state.text), false)
			case "edit", "richedit20w", "richedit50w":
				fillRectUsingBrushHandle(dc, hctx.GdiMgr, colors.brush, hctx.SysColors, 0, 0, state.w, state.h)
				dc.TextOut(4, 4, state.text, false)
			}
		}
		hctx.GdiMgr.DeleteDC(hdc)
	}
}

func (p *dialogTextPainter) draw(x, y, right, bottom int32, text string, fg uint32) {
	if p == nil || p.dc == nil || text == "" || x >= right || y >= bottom {
		return
	}
	oldX0, oldY0, oldX1, oldY1 := p.dc.ClipX0, p.dc.ClipY0, p.dc.ClipX1, p.dc.ClipY1
	p.dc.ClipX0, p.dc.ClipY0, p.dc.ClipX1, p.dc.ClipY1 = x, y, right, bottom
	p.dc.TextColor = fg
	p.dc.TextOut(x, y, text, false)
	p.dc.ClipX0, p.dc.ClipY0, p.dc.ClipX1, p.dc.ClipY1 = oldX0, oldY0, oldX1, oldY1
}

func (p *dialogTextPainter) measure(text string) (int32, int32) {
	if p == nil || p.dc == nil {
		return int32(len([]rune(text)) * 8), 16
	}
	return p.dc.TextExtentStr(text)
}

func dialogLabel(text string) string {
	var label strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '&' {
			label.WriteByte(text[i])
			continue
		}
		if i+1 < len(text) && text[i+1] == '&' {
			label.WriteByte('&')
			i++
		}
	}
	return label.String()
}

func controlHitHeight(state *controlState) int32 {
	if state == nil {
		return 0
	}
	if (state.className == "combobox" || state.className == "comboboxex32") && state.style&3 != 1 && state.h > 24 {
		return 24
	}
	return state.h
}

func listBoxItemHeight(state *controlState, index int) int32 {
	if state != nil && index >= 0 && index < len(state.listItemHeights) && state.listItemHeights[index] > 0 {
		return state.listItemHeights[index]
	}
	if state != nil && state.listItemHeight > 0 {
		return state.listItemHeight
	}
	if state != nil && state.style&0x0030 != 0 {
		return 18
	}
	return 18
}

func listBoxItemRect(state *controlState, index int) (int32, int32, int32, int32, bool) {
	if state == nil || index < 0 || index >= len(state.listItems) {
		return 0, 0, 0, 0, false
	}
	if state.style&0x0200 != 0 {
		itemHeight := listBoxItemHeight(state, index)
		columnWidth := state.listColumnWidth
		if columnWidth <= 0 {
			columnWidth = state.w - 4
		}
		rows := int((state.h - 4) / itemHeight)
		if rows < 1 {
			rows = 1
		}
		row := index % rows
		column := index / rows
		left := int32(column) * columnWidth
		top := int32(row) * itemHeight
		return left, top, left + columnWidth, top + itemHeight, true
	}
	top := int32(3)
	if state.style&0x0030 != 0 {
		top = 0
	}
	for item := 0; item < index; item++ {
		top += listBoxItemHeight(state, item)
	}
	bottom := top + listBoxItemHeight(state, index)
	return 0, top, state.w, bottom, true
}

func listBoxItemFromPoint(state *controlState, x, y int32) (int, bool) {
	if state == nil || len(state.listItems) == 0 {
		return -1, true
	}
	outside := x < 0 || y < 0 || x >= state.w || y >= state.h
	for index := range state.listItems {
		left, top, right, bottom, visible := listBoxItemRect(state, index)
		if visible && x >= left && x < right && y >= top && y < bottom {
			return index, outside
		}
	}
	if y < 0 || x < 0 {
		return 0, true
	}
	return len(state.listItems) - 1, outside
}

func drawOwnedDialogTab(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, palette ownedDialogControlPalette) {
	if state.tab != nil {
		syncTabCompat(state)
	}
	const tabHeight = int32(22)
	bodyHeight := h - 20
	if bodyHeight > 0 {
		drawDialogFrame(win, x, y+20, w, bodyHeight, palette.border, palette.dialog)
	}
	tabX := x
	for i, title := range state.tabTitles {
		textW, textH := painter.measure(title)
		tabW := textW + 20
		if tabW < 40 {
			tabW = 40
		}
		if tabX+tabW > x+w {
			tabW = x + w - tabX
		}
		if tabW <= 0 {
			break
		}
		if state.customDrawItemSkipped(uint64(i)) {
			tabX += tabW
			continue
		}
		background := palette.inactive
		if i == state.tabCurSel {
			background = palette.dialog
		}
		drawDialogFrame(win, tabX, y, tabW, tabHeight, palette.border, background)
		painter.draw(tabX+8, y+(tabHeight-textH)/2, tabX+tabW-4, y+tabHeight, title, palette.text)
		tabX += tabW
	}
}

func drawOwnedDialogTree(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, palette ownedDialogControlPalette) {
	drawDialogFrame(win, x, y, w, h, palette.border, palette.surface)
	if state.treeView == nil {
		return
	}
	const rowHeight = int32(18)
	rowY := y + 2
	for _, item := range treeViewVisibleItems(state.treeView) {
		if rowY+rowHeight > y+h-1 {
			break
		}
		if state.customDrawItemSkipped(item.handle) {
			rowY += rowHeight
			continue
		}
		depth := 0
		for parent := item.parent; parent != nil && parent != state.treeView.root; parent = parent.parent {
			depth++
		}
		selected := state.treeView.selected == item || item.state&0x0002 != 0
		textColor := palette.text
		if selected {
			win.DrawRectAbs(x+2, rowY, x+w-2, rowY+rowHeight, palette.highlight)
			textColor = palette.highlightText
		}
		markerX := x + 7 + int32(depth)*16
		if len(item.children) != 0 {
			markerY := rowY + 5
			drawDialogFrame(win, markerX, markerY, 9, 9, palette.border, palette.surface)
			win.DrawRectAbs(markerX+2, markerY+4, markerX+7, markerY+5, palette.text)
			if !item.expanded {
				win.DrawRectAbs(markerX+4, markerY+2, markerX+5, markerY+7, palette.text)
			}
		}
		painter.draw(markerX+13, rowY+1, x+w-3, rowY+rowHeight, item.text, textColor)
		rowY += rowHeight
	}
}

func drawOwnedDialogListView(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, palette ownedDialogControlPalette) {
	drawDialogFrame(win, x, y, w, h, palette.border, palette.surface)
	if state.listView == nil {
		return
	}
	syncListViewCompat(state)
	const (
		headerHeight = int32(22)
		rowHeight    = int32(18)
		lvsNoHeader  = uint32(0x4000)
	)
	rowY := y + 2
	showHeader := len(state.listView.columns) != 0 && state.listView.style&lvsNoHeader == 0
	if showHeader {
		win.DrawRectAbs(x+1, y+1, x+w-1, y+headerHeight, palette.inactive)
		columnX := x + 2
		for _, column := range state.listView.columns {
			columnWidth := int32(column.width)
			if columnWidth <= 0 {
				columnWidth = 100
			}
			right := min(columnX+columnWidth, x+w-1)
			painter.draw(columnX+4, y+3, right-2, y+headerHeight, column.text, palette.text)
			if right < x+w-1 {
				win.DrawRectAbs(right-1, y+1, right, y+headerHeight, palette.border)
			}
			columnX = right
			if columnX >= x+w-1 {
				break
			}
		}
		win.DrawRectAbs(x+1, y+headerHeight, x+w-1, y+headerHeight+1, palette.border)
		rowY = y + headerHeight + 2
	}
	for index, item := range state.listView.items {
		if rowY+rowHeight > y+h-1 {
			break
		}
		if state.customDrawItemSkipped(uint64(index)) {
			rowY += rowHeight
			continue
		}
		selected := state.listView.selectedIdx == index || item.state&0x0002 != 0
		textColor := palette.text
		if selected {
			win.DrawRectAbs(x+2, rowY, x+w-2, rowY+rowHeight, palette.highlight)
			textColor = palette.highlightText
		}
		columnX := x + 6
		right := x + w - 3
		if len(state.listView.columns) != 0 {
			width := int32(state.listView.columns[0].width)
			if width > 0 {
				right = min(columnX+width-6, right)
			}
		}
		painter.draw(columnX, rowY+1, right, rowY+rowHeight, item.text, textColor)
		for subIndex, subItem := range item.subItems {
			columnIndex := subIndex + 1
			if columnIndex >= len(state.listView.columns) {
				break
			}
			width := int32(state.listView.columns[subIndex].width)
			if width <= 0 {
				width = 100
			}
			columnX += width
			nextWidth := int32(state.listView.columns[columnIndex].width)
			if nextWidth <= 0 {
				nextWidth = 100
			}
			right = min(columnX+nextWidth-4, x+w-3)
			painter.draw(columnX+4, rowY+1, right, rowY+rowHeight, subItem, textColor)
		}
		rowY += rowHeight
	}
}

func renderOwnedDialog(hctx *HandlerCtx, root uint64, renderCPU arch.CPU, win *wl.Window) {
	if hctx == nil || win == nil {
		return
	}
	state, acquired := hctx.beginDialogRender(root)
	if !acquired {
		return
	}
	defer func() {
		if acquired {
			state.release()
		}
	}()
	for {
		renderOwnedDialogPass(hctx, root, renderCPU, win)
		if !state.finishPass() {
			acquired = false
			return
		}
	}
}

func renderOwnedDialogPass(hctx *HandlerCtx, root uint64, renderCPU arch.CPU, win *wl.Window) {
	if renderCPU == nil {
		renderCPU = hctx.windowCPU(root)
	}
	if renderCPU == nil {
		renderCPU = hctx.GetCurrentCPU()
	}
	hctx.DialogSurfaceMu.Lock(renderCPU)
	defer hctx.DialogSurfaceMu.Unlock(renderCPU)
	rootState := hctx.HwndChildren[root]
	if rootState == nil {
		return
	}
	textPainter := newDialogTextPainter(win)
	if hctx.FindDialog != nil && hctx.FindDialog.DlgHWND == root {
		drawFindDialogWindow(hctx, win)
		if effectiveDarkModeForWindow(root, hctx.HwndChildren) {
			remapDialogForDarkMode(win)
		}
		dispatchOwnedDialogColors(hctx, root, renderCPU, win)
		win.Commit()
		return
	}
	if hctx.PrintDialog != nil && hctx.PrintDialog.DlgHWND == root {
		drawPrintDialogWindow(hctx, win, textPainter)
		if effectiveDarkModeForWindow(root, hctx.HwndChildren) {
			remapDialogForDarkMode(win)
		}
		dispatchOwnedDialogColors(hctx, root, renderCPU, win)
		win.Commit()
		return
	}

	dark := effectiveDarkModeForWindow(root, hctx.HwndChildren)
	palette := ownedDialogPalette(dark)
	win.DrawRectAbs(0, 0, win.Width, win.Height, palette.dialog)
	explicitPage := false
	for _, state := range hctx.HwndChildren {
		if state.parentHWND == root && (strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770")) && state.style&0x40000000 != 0 && state.showCalled {
			explicitPage = true
			break
		}
	}
	children := ownedDialogPaintOrder(hctx, root)
	filtered := children[:0]
	for _, hwnd := range children {
		if explicitPage {
			if page := dialogPageFor(hctx, hwnd, root); page != 0 {
				pageState := hctx.HwndChildren[page]
				if pageState == nil || !pageState.showCalled || !pageState.visible {
					continue
				}
			}
		}
		filtered = append(filtered, hwnd)
	}
	children = filtered

	rendered := 0
	for _, hwnd := range children {
		state := hctx.HwndChildren[hwnd]
		if hasOwnedControlPaint(state) && hctx.HwndWndProc[hwnd] != 0 &&
			(!dark || !hostRendersOwnedControlInDarkMode(state)) {
			continue
		}
		x := state.x - rootState.x
		y := state.y - rootState.y
		w, h := state.w, state.h
		if w <= 0 || h <= 0 {
			continue
		}
		rendered++
		text := dialogLabel(state.text)
		switch strings.ToLower(state.className) {
		case "dialog", "#32770":
			win.DrawRectAbs(x, y, x+w, y+h, palette.dialog)
		case "static":
			drawDialogStatic(win, textPainter, state, x, y, w, h, text, palette.text)
		case "edit", "richedit20w", "richedit50w":
			drawDialogFrame(win, x, y, w, h, palette.frame, palette.surface)
			if text != "" {
				_, textH := textPainter.measure(text)
				textPainter.draw(x+4, y+(h-textH)/2, x+w-2, y+h-2, text, palette.text)
			}
		case "combobox", "comboboxex32":
			comboType := state.style & 3
			closedH := h
			if closedH > 24 {
				closedH = 24
			}
			drawDialogFrame(win, x, y, w, closedH, palette.frame, palette.surface)
			textRight := x + w - 20
			if comboType == 1 {
				textRight = x + w - 2
			} else {
				arrowW := int32(18)
				win.DrawRectAbs(x+w-arrowW, y+1, x+w-1, y+closedH-1, palette.inactive)
				midX, midY := x+w-arrowW/2, y+closedH/2
				win.DrawRectAbs(midX-3, midY-1, midX+4, midY, palette.text)
				win.DrawRectAbs(midX-2, midY, midX+3, midY+1, palette.text)
			}
			comboText := text
			if comboText == "" && state.comboCurSel >= 0 && state.comboCurSel < len(state.comboItems) {
				comboText = state.comboItems[state.comboCurSel]
			}
			if comboText != "" {
				_, textH := textPainter.measure(comboText)
				textPainter.draw(x+4, y+(closedH-textH)/2, textRight, y+closedH-2, comboText, palette.text)
			}
		case "listbox":
			drawDialogFrame(win, x, y, w, h, palette.border, palette.surface)
			rowY := y + 3
			for i, item := range state.listItems {
				if rowY+16 > y+h-2 {
					break
				}
				bg := palette.surface
				fg := palette.text
				if i == state.listCurSel {
					bg = palette.highlight
					fg = palette.highlightText
					win.DrawRectAbs(x+2, rowY, x+w-2, rowY+16, bg)
				}
				textPainter.draw(x+5, rowY+1, x+w-3, rowY+16, item, fg)
				rowY += 18
			}
		case "button":
			drawDialogButton(win, textPainter, state, x, y, w, h, text, palette)
		case "msctls_trackbar32":
			drawDialogTrackbar(win, state, x, y, w, h, palette)
		case "systabcontrol32":
			drawOwnedDialogTab(win, textPainter, state, x, y, w, h, palette)
		case "systreeview32":
			drawOwnedDialogTree(win, textPainter, state, x, y, w, h, palette)
		case "syslistview32":
			drawOwnedDialogListView(win, textPainter, state, x, y, w, h, palette)
		}
	}
	for _, hwnd := range children {
		state := hctx.HwndChildren[hwnd]
		if state != nil && hasOwnedControlPaint(state) && hctx.HwndWndProc[hwnd] != 0 &&
			(!dark || !hostRendersOwnedControlInDarkMode(state)) {
			restoreOwnedControlPaint(state, rootState, win)
			if dark {
				x := state.x - rootState.x
				y := state.y - rootState.y
				remapWaylandRectForDarkMode(win, x, y, x+state.w, y+state.h)
			}
		}
	}
	for _, hwnd := range children {
		state := hctx.HwndChildren[hwnd]
		if state == nil || (!state.comboDropped && state.style&3 != 1) || (state.className != "combobox" && state.className != "comboboxex32") {
			continue
		}
		x := state.x - rootState.x
		y := state.y - rootState.y + 24
		visibleRows := len(state.comboItems) - state.comboTopIndex
		maxRows := 8
		if state.style&3 == 1 {
			maxRows = int((state.h - 28) / 18)
			if maxRows < 1 {
				maxRows = 1
			}
		}
		if visibleRows > maxRows {
			visibleRows = maxRows
		}
		if visibleRows <= 0 {
			continue
		}
		popupH := int32(visibleRows*18 + 4)
		state.comboPopupAbove = state.style&3 != 1 && y+popupH > win.Height && y-24-popupH >= 0
		if state.comboPopupAbove {
			y -= 24 + popupH
		}
		drawDialogFrame(win, x, y, state.w, popupH, palette.border, palette.surface)
		for row := 0; row < visibleRows; row++ {
			i := state.comboTopIndex + row
			rowY := y + 2 + int32(row*18)
			bg := palette.surface
			fg := palette.text
			if i == state.comboCurSel {
				bg = palette.highlight
				fg = palette.highlightText
				win.DrawRectAbs(x+2, rowY, x+state.w-2, rowY+18, bg)
			}
			textPainter.draw(x+5, rowY+2, x+state.w-3, rowY+18, state.comboItems[i], fg)
		}
	}
	if shouldPrimeOwnedDialogCustomPaint(hctx, root) {
		wasRendering := hctx.RenderingDialogCustom
		hctx.RenderingDialogCustom = true
		hctx.RenderDialogCustom(root, win)
		hctx.RenderingDialogCustom = wasRendering
	}
	dispatchOwnedDialogColors(hctx, root, renderCPU, win)
	win.Commit()
	ravelog.Logf("[dialog-window] rendered hwnd=0x%x controls=%d candidates=%d\n", root, rendered, len(children))
}

func repaintHostManagedDialog(hctx *HandlerCtx, root uint64, renderCPU arch.CPU, win *wl.Window) bool {
	if hctx == nil || win == nil {
		return false
	}
	isFind := hctx.FindDialog != nil && hctx.FindDialog.DlgHWND == root
	isPrint := hctx.PrintDialog != nil && hctx.PrintDialog.DlgHWND == root
	if !isFind && !isPrint {
		return false
	}
	renderOwnedDialog(hctx, root, renderCPU, win)
	return true
}

func drawDialogStatic(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, text string, fg uint32) {
	if win == nil || state == nil || text == "" || w <= 0 || h <= 0 {
		return
	}
	textWidth, textHeight := painter.measure(text)
	textX := x + 2
	switch state.style & 0x1f {
	case 1: // SS_CENTER
		textX = x + (w-textWidth)/2
	case 2: // SS_RIGHT
		textX = x + w - textWidth - 2
	}
	if textX < x {
		textX = x
	}
	textY := y
	if h > textHeight {
		textY += (h - textHeight) / 2
	}
	painter.draw(textX, textY, x+w, y+h, text, fg)
}

func drawPrintDialogWindow(hctx *HandlerCtx, win *wl.Window, painter *dialogTextPainter) {
	pd := hctx.PrintDialog
	if pd == nil || win == nil {
		return
	}
	win.DrawRectAbs(0, 0, win.Width, win.Height, 0xF0F0F0)
	painter.draw(24, 22, win.Width-24, 40, "Printer", 0x000000)
	drawDialogFrame(win, 20, 44, win.Width-20, 112, 0xA0A0A0, 0xFFFFFF)
	painter.draw(36, 58, 108, 76, "Name:", 0x000000)
	painter.draw(112, 58, win.Width-32, 76, "Raven Virtual Printer", 0x000000)
	painter.draw(36, 84, 108, 102, "Output:", 0x000000)
	painter.draw(112, 84, win.Width-32, 102, pd.OutputPath, 0x000000)

	painter.draw(24, 132, win.Width-24, 150, "Page range", 0x000000)
	drawDialogFrame(win, 20, 154, win.Width-20, 224, 0xA0A0A0, 0xFFFFFF)
	pd.AllPagesX, pd.AllPagesY = 38, 174
	pd.PagesX, pd.PagesY = 38, 202
	drawPrintRadio(win, painter, pd.AllPagesX, pd.AllPagesY, pd.AllPages, "All")
	if pd.AllowPageRange {
		drawPrintRadio(win, painter, pd.PagesX, pd.PagesY, !pd.AllPages, "Pages")
		pd.FromMinusX, pd.FromPlusX = 126, 174
		pd.ToMinusX, pd.ToPlusX = 294, 342
		pd.RangeButtonsY = 198
		drawPrintSmallButton(win, painter, pd.FromMinusX, pd.RangeButtonsY, "-")
		painter.draw(158, 204, 174, 222, fmt.Sprintf("%d", pd.FromPage), 0x000000)
		drawPrintSmallButton(win, painter, pd.FromPlusX, pd.RangeButtonsY, "+")
		painter.draw(220, 204, 250, 222, "to", 0x000000)
		drawPrintSmallButton(win, painter, pd.ToMinusX, pd.RangeButtonsY, "-")
		painter.draw(326, 204, 342, 222, fmt.Sprintf("%d", pd.ToPage), 0x000000)
		drawPrintSmallButton(win, painter, pd.ToPlusX, pd.RangeButtonsY, "+")
	} else {
		painter.draw(pd.PagesX+24, pd.PagesY+1, win.Width-32, pd.PagesY+19, "Pages unavailable", 0x808080)
	}

	painter.draw(24, 244, win.Width-24, 262, "Copies", 0x000000)
	drawDialogFrame(win, 20, 266, 250, 318, 0xA0A0A0, 0xFFFFFF)
	pd.CopiesMinusX, pd.CopiesPlusX, pd.CopiesY = 106, 188, 280
	drawPrintSmallButton(win, painter, pd.CopiesMinusX, pd.CopiesY, "-")
	painter.draw(148, 286, 188, 304, fmt.Sprintf("%d", pd.Copies), 0x000000)
	drawPrintSmallButton(win, painter, pd.CopiesPlusX, pd.CopiesY, "+")

	pd.PrintBtnX, pd.PrintBtnY, pd.PrintBtnW, pd.PrintBtnH = win.Width-206, win.Height-46, 86, 30
	pd.CancelBtnX, pd.CancelBtnY, pd.CancelBtnW, pd.CancelBtnH = win.Width-108, win.Height-46, 86, 30
	palette := ownedDialogPalette(false)
	drawDialogButton(win, painter, &controlState{text: "Print", visible: true}, pd.PrintBtnX, pd.PrintBtnY, pd.PrintBtnW, pd.PrintBtnH, "Print", palette)
	drawDialogButton(win, painter, &controlState{text: "Cancel", visible: true}, pd.CancelBtnX, pd.CancelBtnY, pd.CancelBtnW, pd.CancelBtnH, "Cancel", palette)
}

func drawPrintRadio(win *wl.Window, painter *dialogTextPainter, x, y int32, checked bool, label string) {
	drawDialogFrame(win, x, y, 16, 16, 0x707070, 0xFFFFFF)
	if checked {
		win.DrawRectAbs(x+4, y+4, x+12, y+12, 0x202020)
	}
	painter.draw(x+24, y+1, win.Width, y+18, label, 0x000000)
}

func drawPrintSmallButton(win *wl.Window, painter *dialogTextPainter, x, y int32, label string) {
	drawDialogButton(win, painter, &controlState{text: label, visible: true}, x, y, 28, 24, label, ownedDialogPalette(false))
}

func drawDialogTrackbar(win *wl.Window, state *controlState, x, y, w, h int32, palette ownedDialogControlPalette) {
	vertical := state.style&0x0002 != 0
	rangeSize := state.trackMax - state.trackMin
	pos := state.trackPos - state.trackMin
	if rangeSize <= 0 {
		rangeSize = 1
	}
	if pos < 0 {
		pos = 0
	} else if pos > rangeSize {
		pos = rangeSize
	}
	if vertical {
		trackX := x + w/2
		win.DrawRectAbs(trackX-2, y+6, trackX+2, y+h-6, palette.border)
		thumbY := y + 6 + (h-12)*pos/rangeSize
		drawDialogFrame(win, trackX-7, thumbY-5, 14, 10, palette.frame, palette.button)
		return
	}
	trackY := y + h/2
	win.DrawRectAbs(x+6, trackY-2, x+w-6, trackY+2, palette.border)
	thumbX := x + 6 + (w-12)*pos/rangeSize
	drawDialogFrame(win, thumbX-5, trackY-7, 10, 14, palette.frame, palette.button)
}

func dialogPageFor(hctx *HandlerCtx, hwnd, root uint64) uint64 {
	for hwnd != 0 && hwnd != root {
		state := hctx.HwndChildren[hwnd]
		if state == nil {
			return 0
		}
		if state.parentHWND == root && (strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770")) && state.style&0x40000000 != 0 {
			return hwnd
		}
		hwnd = state.parentHWND
	}
	return 0
}

func ownedDialogPaintOrder(hctx *HandlerCtx, root uint64) []uint64 {
	if hctx == nil {
		return nil
	}
	zOrder := hctx.snapshotZOrder()
	var result []uint64
	var appendChildren func(uint64)
	appendChildren = func(parent uint64) {
		for _, hwnd := range backToFrontChildWindows(hctx.HwndChildren, zOrder, parent) {
			if !visibleOwnedDialogDescendant(hctx, hwnd, root) {
				continue
			}
			result = append(result, hwnd)
			appendChildren(hwnd)
		}
	}
	appendChildren(root)
	return result
}

func isDialogDescendant(hctx *HandlerCtx, hwnd, root uint64) bool {
	for hwnd != 0 {
		state := hctx.HwndChildren[hwnd]
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

func visibleOwnedDialogDescendant(hctx *HandlerCtx, hwnd, root uint64) bool {
	if hctx == nil || hwnd == root || hctx.HwndChildren[hwnd] == nil {
		return false
	}
	return isDialogDescendant(hctx, hwnd, root) &&
		windowHierarchyVisible(hwnd, hctx.HwndChildren)
}

func topLevelDialogTarget(hctx *HandlerCtx, hwnd uint64) (uint64, *wl.Window, bool) {
	const wsChild = uint32(0x40000000)
	for hwnd != 0 {
		state := hctx.HwndChildren[hwnd]
		if state == nil {
			return 0, nil, false
		}
		if strings.EqualFold(state.className, "dialog") && state.style&wsChild == 0 {
			return hwnd, hctx.WlWindows[hwnd], true
		}
		hwnd = state.parentHWND
	}
	return 0, nil, false
}

func drawDialogFrame(win *wl.Window, x, y, w, h int32, border, fill uint32) {
	win.DrawRectAbs(x, y, x+w, y+h, fill)
	win.DrawRectAbs(x, y, x+w, y+1, border)
	win.DrawRectAbs(x, y, x+1, y+h, border)
	win.DrawRectAbs(x, y+h-1, x+w, y+h, border)
	win.DrawRectAbs(x+w-1, y, x+w, y+h, border)
}

func drawDialogButton(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, text string, palette ownedDialogControlPalette) {
	buttonType := state.style & 0x0F
	switch buttonType {
	case 11:
		drawDialogFrame(win, x, y, w, h, palette.frame, palette.button)
	case 2, 3, 4, 5, 6, 9:
		boxY := y + (h-13)/2
		drawDialogFrame(win, x, boxY, 13, 13, palette.frame, palette.surface)
		if state.checkState != 0 {
			win.DrawRectAbs(x+3, boxY+5, x+6, boxY+8, palette.text)
			win.DrawRectAbs(x+6, boxY+3, x+10, boxY+6, palette.text)
		}
		_, textH := painter.measure(text)
		painter.draw(x+18, y+(h-textH)/2, x+w, y+h, text, palette.text)
	case 7:
		win.DrawRectAbs(x, y+8, x+w, y+9, palette.border)
		win.DrawRectAbs(x, y+8, x+1, y+h, palette.border)
		win.DrawRectAbs(x, y+h-1, x+w, y+h, palette.border)
		win.DrawRectAbs(x+w-1, y+8, x+w, y+h, palette.border)
		if text != "" {
			textW, textH := painter.measure(text)
			win.DrawRectAbs(x+8, y+2, x+12+textW, y+2+textH, palette.dialog)
			painter.draw(x+10, y+2, x+w, y+h, text, palette.text)
		}
	default:
		drawDialogFrame(win, x, y, w, h, palette.frame, palette.button)
		textW, textH := painter.measure(text)
		painter.draw(x+(w-textW)/2, y+(h-textH)/2, x+w-2, y+h-2, text, palette.text)
	}
}
