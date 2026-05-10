//go:build guest_windows

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

type dialogTextPainter struct {
	dc *gdi.DC
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

func renderOwnedDialog(hctx *HandlerCtx, root uint64, win *wl.Window) {
	if hctx == nil || win == nil {
		return
	}
	if !hctx.DialogRendering.CompareAndSwap(false, true) {
		return
	}
	defer hctx.DialogRendering.Store(false)
	rootState := hctx.HwndChildren[root]
	if rootState == nil {
		return
	}
	textPainter := newDialogTextPainter(win)
	if hctx.FindDialog != nil && hctx.FindDialog.DlgHWND == root {
		drawFindDialogWindow(hctx, win)
		win.Commit()
		return
	}
	if hctx.PrintDialog != nil && hctx.PrintDialog.DlgHWND == root {
		drawPrintDialogWindow(hctx, win, textPainter)
		win.Commit()
		return
	}

	win.DrawRectAbs(0, 0, win.Width, win.Height, 0xF0F0F0)
	explicitPage := false
	for _, state := range hctx.HwndChildren {
		if state.parentHWND == root && (strings.EqualFold(state.className, "dialog") || strings.EqualFold(state.className, "#32770")) && state.style&0x40000000 != 0 && state.showCalled {
			explicitPage = true
			break
		}
	}
	var children []uint64
	for hwnd, state := range hctx.HwndChildren {
		if hwnd == root || !state.visible || !isDialogDescendant(hctx, hwnd, root) {
			continue
		}
		if explicitPage {
			if page := dialogPageFor(hctx, hwnd, root); page != 0 {
				pageState := hctx.HwndChildren[page]
				if pageState == nil || !pageState.showCalled || !pageState.visible {
					continue
				}
			}
		}
		children = append(children, hwnd)
	}
	sort.Slice(children, func(i, j int) bool {
		left := dialogRenderLayer(hctx.HwndChildren[children[i]])
		right := dialogRenderLayer(hctx.HwndChildren[children[j]])
		if left != right {
			return left < right
		}
		return children[i] < children[j]
	})

	rendered := 0
	for _, hwnd := range children {
		state := hctx.HwndChildren[hwnd]
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
			win.DrawRectAbs(x, y, x+w, y+h, 0xF0F0F0)
		case "static":
			drawDialogStatic(win, textPainter, state, x, y, w, h, text)
		case "edit", "richedit20w", "richedit50w":
			drawDialogFrame(win, x, y, w, h, 0x7A7A7A, 0xFFFFFF)
			if text != "" {
				_, textH := textPainter.measure(text)
				textPainter.draw(x+4, y+(h-textH)/2, x+w-2, y+h-2, text, 0x000000)
			}
		case "combobox", "comboboxex32":
			comboType := state.style & 3
			closedH := h
			if closedH > 24 {
				closedH = 24
			}
			drawDialogFrame(win, x, y, w, closedH, 0x7A7A7A, 0xFFFFFF)
			textRight := x + w - 20
			if comboType == 1 {
				textRight = x + w - 2
			} else {
				arrowW := int32(18)
				win.DrawRectAbs(x+w-arrowW, y+1, x+w-1, y+closedH-1, 0xE1E1E1)
				midX, midY := x+w-arrowW/2, y+closedH/2
				win.DrawRectAbs(midX-3, midY-1, midX+4, midY, 0x202020)
				win.DrawRectAbs(midX-2, midY, midX+3, midY+1, 0x202020)
			}
			comboText := text
			if comboText == "" && state.comboCurSel >= 0 && state.comboCurSel < len(state.comboItems) {
				comboText = state.comboItems[state.comboCurSel]
			}
			if comboText != "" {
				_, textH := textPainter.measure(comboText)
				textPainter.draw(x+4, y+(closedH-textH)/2, textRight, y+closedH-2, comboText, 0x000000)
			}
		case "listbox":
			drawDialogFrame(win, x, y, w, h, 0x7A7A7A, 0xFFFFFF)
			rowY := y + 3
			for i, item := range state.listItems {
				if rowY+16 > y+h-2 {
					break
				}
				bg := uint32(0xFFFFFF)
				fg := uint32(0x000000)
				if i == state.listCurSel {
					bg = 0x0078D7
					fg = 0xFFFFFF
					win.DrawRectAbs(x+2, rowY, x+w-2, rowY+16, bg)
				}
				textPainter.draw(x+5, rowY+1, x+w-3, rowY+16, item, fg)
				rowY += 18
			}
		case "button":
			drawDialogButton(win, textPainter, state, x, y, w, h, text)
		case "msctls_trackbar32":
			drawDialogTrackbar(win, state, x, y, w, h)
		case "systabcontrol32":
			drawDialogFrame(win, x, y+20, w, h-20, 0xA0A0A0, 0xF0F0F0)
			tabX := x
			for i, title := range state.tabTitles {
				textW, textH := textPainter.measure(title)
				tabW := textW + 20
				bg := uint32(0xE1E1E1)
				if i == state.tabCurSel {
					bg = 0xF0F0F0
				}
				drawDialogFrame(win, tabX, y, tabW, 22, 0xA0A0A0, bg)
				textPainter.draw(tabX+8, y+(22-textH)/2, tabX+tabW-4, y+22, title, 0x000000)
				tabX += tabW
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
		drawDialogFrame(win, x, y, state.w, popupH, 0x7A7A7A, 0xFFFFFF)
		for row := 0; row < visibleRows; row++ {
			i := state.comboTopIndex + row
			rowY := y + 2 + int32(row*18)
			bg := uint32(0xFFFFFF)
			fg := uint32(0x000000)
			if i == state.comboCurSel {
				bg = 0x0078D7
				fg = 0xFFFFFF
				win.DrawRectAbs(x+2, rowY, x+state.w-2, rowY+18, bg)
			}
			textPainter.draw(x+5, rowY+2, x+state.w-3, rowY+18, state.comboItems[i], fg)
		}
	}
	if hctx.RenderDialogCustom != nil {
		wasRendering := hctx.RenderingDialogCustom
		hctx.RenderingDialogCustom = true
		hctx.RenderDialogCustom(root, win)
		hctx.RenderingDialogCustom = wasRendering
	}
	win.Commit()
	ravelog.Logf("[dialog-window] rendered hwnd=0x%x controls=%d candidates=%d\n", root, rendered, len(children))
}

func drawDialogStatic(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, text string) {
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
	painter.draw(textX, textY, x+w, y+h, text, 0x000000)
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
	drawDialogButton(win, painter, &controlState{text: "Print", visible: true}, pd.PrintBtnX, pd.PrintBtnY, pd.PrintBtnW, pd.PrintBtnH, "Print")
	drawDialogButton(win, painter, &controlState{text: "Cancel", visible: true}, pd.CancelBtnX, pd.CancelBtnY, pd.CancelBtnW, pd.CancelBtnH, "Cancel")
}

func drawPrintRadio(win *wl.Window, painter *dialogTextPainter, x, y int32, checked bool, label string) {
	drawDialogFrame(win, x, y, 16, 16, 0x707070, 0xFFFFFF)
	if checked {
		win.DrawRectAbs(x+4, y+4, x+12, y+12, 0x202020)
	}
	painter.draw(x+24, y+1, win.Width, y+18, label, 0x000000)
}

func drawPrintSmallButton(win *wl.Window, painter *dialogTextPainter, x, y int32, label string) {
	drawDialogButton(win, painter, &controlState{text: label, visible: true}, x, y, 28, 24, label)
}

func drawDialogTrackbar(win *wl.Window, state *controlState, x, y, w, h int32) {
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
		win.DrawRectAbs(trackX-2, y+6, trackX+2, y+h-6, 0x808080)
		thumbY := y + 6 + (h-12)*pos/rangeSize
		drawDialogFrame(win, trackX-7, thumbY-5, 14, 10, 0x606060, 0xE1E1E1)
		return
	}
	trackY := y + h/2
	win.DrawRectAbs(x+6, trackY-2, x+w-6, trackY+2, 0x808080)
	thumbX := x + 6 + (w-12)*pos/rangeSize
	drawDialogFrame(win, thumbX-5, trackY-7, 10, 14, 0x606060, 0xE1E1E1)
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

func dialogRenderLayer(state *controlState) int {
	if state == nil {
		return 0
	}
	className := strings.ToLower(state.className)
	if className == "dialog" || className == "#32770" || className == "systabcontrol32" {
		return 0
	}
	if className == "button" && state.style&0x0F == 7 {
		return 1
	}
	return 2
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

func drawDialogButton(win *wl.Window, painter *dialogTextPainter, state *controlState, x, y, w, h int32, text string) {
	buttonType := state.style & 0x0F
	switch buttonType {
	case 11:
		drawDialogFrame(win, x, y, w, h, 0x7A7A7A, 0xE1E1E1)
	case 2, 3, 4, 5, 6, 9:
		boxY := y + (h-13)/2
		drawDialogFrame(win, x, boxY, 13, 13, 0x7A7A7A, 0xFFFFFF)
		if state.checkState != 0 {
			win.DrawRectAbs(x+3, boxY+5, x+6, boxY+8, 0x202020)
			win.DrawRectAbs(x+6, boxY+3, x+10, boxY+6, 0x202020)
		}
		_, textH := painter.measure(text)
		painter.draw(x+18, y+(h-textH)/2, x+w, y+h, text, 0x000000)
	case 7:
		win.DrawRectAbs(x, y+8, x+w, y+9, 0xA0A0A0)
		win.DrawRectAbs(x, y+8, x+1, y+h, 0xA0A0A0)
		win.DrawRectAbs(x, y+h-1, x+w, y+h, 0xA0A0A0)
		win.DrawRectAbs(x+w-1, y+8, x+w, y+h, 0xA0A0A0)
		if text != "" {
			textW, textH := painter.measure(text)
			win.DrawRectAbs(x+8, y+2, x+12+textW, y+2+textH, 0xF0F0F0)
			painter.draw(x+10, y+2, x+w, y+h, text, 0x000000)
		}
	default:
		drawDialogFrame(win, x, y, w, h, 0x7A7A7A, 0xE1E1E1)
		textW, textH := painter.measure(text)
		painter.draw(x+(w-textW)/2, y+(h-textH)/2, x+w-2, y+h-2, text, 0x000000)
	}
}
