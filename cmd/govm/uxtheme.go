//go:build guest_windows

package main

import (
	"sort"
	"strings"
	"sync"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type themeState struct {
	mu         sync.Mutex
	nextHandle uint32
	themes     map[uint32]*themeData
}

type themeData struct {
	className string
	hwnd      uint64
}

var themeGlobal = themeState{nextHandle: 0x5000, themes: make(map[uint32]*themeData)}

type preferredAppMode uint32

const (
	preferredAppModeDefault preferredAppMode = iota
	preferredAppModeAllowDark
	preferredAppModeForceDark
	preferredAppModeForceLight
	preferredAppModeMax
)

const (
	dwmwaUseImmersiveDarkModeBefore20H1 uint32 = 19
	dwmwaUseImmersiveDarkMode           uint32 = 20
)

type windowThemeSelection struct {
	SubAppName string
	SubIDList  string
}

type darkModeState struct {
	mu                 sync.RWMutex
	preferredMode      preferredAppMode
	legacyAppAllowed   bool
	appsUseDark        bool
	systemUsesDark     bool
	windowAllowed      map[uint64]bool
	windowThemes       map[uint64]windowThemeSelection
	windowImmersiveDWM map[uint64]bool
}

var darkModeGlobal = darkModeState{
	windowAllowed:      make(map[uint64]bool),
	windowThemes:       make(map[uint64]windowThemeSelection),
	windowImmersiveDWM: make(map[uint64]bool),
}

func shouldAppsUseDarkMode() bool {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	switch darkModeGlobal.preferredMode {
	case preferredAppModeForceDark:
		return true
	case preferredAppModeForceLight:
		return false
	default:
		return darkModeGlobal.appsUseDark
	}
}

func darkModeAllowedForApp() bool {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	if darkModeGlobal.legacyAppAllowed {
		return true
	}
	return darkModeGlobal.preferredMode == preferredAppModeAllowDark ||
		darkModeGlobal.preferredMode == preferredAppModeForceDark
}

func shouldSystemUseDarkMode() bool {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	return darkModeGlobal.systemUsesDark
}

func darkModeAllowedForWindow(hwnd uint64) bool {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	return darkModeGlobal.windowAllowed[hwnd]
}

func windowThemeSelectionFor(hwnd uint64) (windowThemeSelection, bool) {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	selection, ok := darkModeGlobal.windowThemes[hwnd]
	return selection, ok
}

func immersiveDarkModeForWindow(hwnd uint64) (bool, bool) {
	darkModeGlobal.mu.RLock()
	defer darkModeGlobal.mu.RUnlock()
	dark, ok := darkModeGlobal.windowImmersiveDWM[hwnd]
	return dark, ok
}

func darkModeRequestedForWindow(hwnd uint64) bool {
	if dark, ok := immersiveDarkModeForWindow(hwnd); ok && dark {
		return true
	}
	if selection, ok := windowThemeSelectionFor(hwnd); ok {
		names := strings.ToLower(selection.SubAppName + ";" + selection.SubIDList)
		if strings.Contains(names, "darkmode") || strings.Contains(names, "dark") {
			return true
		}
	}
	return darkModeAllowedForWindow(hwnd) && darkModeAllowedForApp() && shouldAppsUseDarkMode()
}

func effectiveDarkModeForWindow(hwnd uint64, children map[uint64]*controlState) bool {
	for hwnd != 0 {
		if darkModeRequestedForWindow(hwnd) {
			return true
		}
		state := children[hwnd]
		if state == nil || state.parentHWND == hwnd {
			break
		}
		hwnd = state.parentHWND
	}
	return false
}

func clearDarkModeWindowState(hwnd uint64) {
	darkModeGlobal.mu.Lock()
	delete(darkModeGlobal.windowAllowed, hwnd)
	delete(darkModeGlobal.windowThemes, hwnd)
	delete(darkModeGlobal.windowImmersiveDWM, hwnd)
	darkModeGlobal.mu.Unlock()
}

func darkRepaintWindowRoots(hctx *HandlerCtx) []uint64 {
	if hctx == nil {
		return nil
	}
	roots := make(map[uint64]bool)
	if hctx.MainHWND != 0 {
		roots[hctx.MainHWND] = true
	}
	for hwnd, state := range hctx.HwndChildren {
		if root, _, owned := topLevelDialogTarget(hctx, hwnd); owned {
			roots[root] = true
			continue
		}
		if state != nil && state.parentHWND == 0 {
			roots[hwnd] = true
		}
	}
	result := make([]uint64, 0, len(roots))
	for hwnd := range roots {
		result = append(result, hwnd)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

type bufferedPaintState struct {
	mu         sync.Mutex
	nextHandle uint32
	paints     map[uint32]uint64
}

var bufferedPaintGlobal = bufferedPaintState{nextHandle: 0x6000, paints: make(map[uint32]uint64)}

type dwmThumbnailState struct {
	mu         sync.Mutex
	nextHandle uint32
	thumbs     map[uint32]struct{}
}

var dwmThumbnailGlobal = dwmThumbnailState{nextHandle: 0x7000, thumbs: make(map[uint32]struct{})}

var themeColors = struct {
	ButtonFace      uint32
	ButtonHighlight uint32
	ButtonShadow    uint32
	ButtonText      uint32
	Window          uint32
	WindowText      uint32
	Highlight       uint32
	HighlightText   uint32
	GrayText        uint32
	Border          uint32
	ScrollbarTrack  uint32
	ScrollbarThumb  uint32
}{
	ButtonFace:      0x00F0F0F0,
	ButtonHighlight: 0x00FFFFFF,
	ButtonShadow:    0x00A0A0A0,
	ButtonText:      0x00000000,
	Window:          0x00FFFFFF,
	WindowText:      0x00000000,
	Highlight:       0x000078D7,
	HighlightText:   0x00FFFFFF,
	GrayText:        0x006D6D6D,
	Border:          0x00D5D5D5,
	ScrollbarTrack:  0x00F0F0F0,
	ScrollbarThumb:  0x00CDCDCD,
}

type darkRenderPalette struct {
	Background    uint32
	Control       uint32
	Input         uint32
	Border        uint32
	Text          uint32
	SecondaryText uint32
	DisabledText  uint32
	Highlight     uint32
	HighlightText uint32
}

var darkPalette = darkRenderPalette{
	Background:    0x00202020,
	Control:       0x002B2B2B,
	Input:         0x00252525,
	Border:        0x00656565,
	Text:          0x00E0E0E0,
	SecondaryText: 0x00C0C0C0,
	DisabledText:  0x00808080,
	Highlight:     0x00404040,
	HighlightText: 0x00FFFFFF,
}

func darkThemeColor(color uint32) uint32 {
	color &= 0x00FFFFFF
	switch color {
	case darkPalette.Background, darkPalette.Control, darkPalette.Input, darkPalette.Border,
		darkPalette.Text, darkPalette.SecondaryText, darkPalette.DisabledText,
		darkPalette.Highlight, darkPalette.HighlightText:
		return color
	}
	r := int32(color >> 16)
	g := int32(color >> 8 & 0xFF)
	b := int32(color & 0xFF)
	high := max(r, max(g, b))
	low := min(r, min(g, b))
	if high-low > 48 {
		return color
	}
	switch {
	case high >= 245:
		return darkPalette.Background
	case high >= 220:
		return darkPalette.Control
	case high >= 145:
		return darkPalette.Border
	case high <= 32:
		return darkPalette.Text
	case high <= 96:
		return darkPalette.SecondaryText
	default:
		return darkPalette.DisabledText
	}
}

func remapDCRectForDarkMode(dc *gdi.DC, left, top, right, bottom int32) {
	if dc == nil || left >= right || top >= bottom {
		return
	}
	for y := top; y < bottom; y++ {
		for x := left; x < right; x++ {
			color := dc.GetPixel(x, y)
			if color != 0xFFFFFFFF {
				dc.SetPixel(x, y, darkThemeColor(color))
			}
		}
	}
}

const (
	sOK                     uint64 = 0
	eInvalidArg             uint64 = 0x80070057
	dwmECompositionDisabled uint64 = 0x80263001
)

const (
	tmtBorderColor = 3801
	tmtFillColor   = 3802
	tmtTextColor   = 3803
)

func normalizeThemeClass(className string) string {
	className = strings.TrimSpace(className)
	if className == "" {
		return "WINDOW"
	}
	parts := strings.FieldsFunc(className, func(r rune) bool {
		return r == ';' || r == ','
	})
	if len(parts) > 0 {
		className = parts[0]
	}
	if idx := strings.LastIndex(className, "::"); idx >= 0 {
		className = className[idx+2:]
	}
	return strings.ToUpper(strings.TrimSpace(className))
}

func getThemeInfo(handle uint64) *themeData {
	themeGlobal.mu.Lock()
	defer themeGlobal.mu.Unlock()
	td := themeGlobal.themes[uint32(handle)]
	if td == nil {
		return nil
	}
	copy := *td
	return &copy
}

func themedStateFlags(className string, partID, stateID int32) (hot, pressed, disabled, checked, selected bool) {
	switch className {
	case "BUTTON":
		switch partID {
		case 1:
			hot = stateID == 2 || stateID == 6
			pressed = stateID == 3 || stateID == 6
			disabled = stateID == 4
			selected = stateID == 5 || stateID == 6
		case 2, 3:
			if stateID >= 1 {
				mode := (stateID - 1) % 4
				hot = mode == 1
				pressed = mode == 2
				disabled = mode == 3
				checked = stateID > 4
			}
		}
	case "HEADER", "TOOLBAR":
		hot = stateID == 2
		pressed = stateID == 3
		disabled = stateID == 4
	case "TAB":
		selected = stateID == 2 || stateID == 4
		hot = stateID == 3
		disabled = stateID == 5
	case "MENU":
		selected = stateID == 2 || stateID == 3
		hot = selected
		disabled = stateID == 4
	case "EDIT":
		selected = stateID == 5 || stateID == 6
		disabled = stateID == 4
	case "LISTVIEW", "TREEVIEW":
		selected = stateID == 2 || stateID == 3
		hot = stateID == 2
		disabled = stateID == 4
	case "SCROLLBAR":
		if partID == 1 && stateID >= 1 {
			mode := (stateID - 1) % 4
			hot = mode == 1
			pressed = mode == 2
			disabled = mode == 3
		} else {
			hot = stateID == 2
			pressed = stateID == 3
			disabled = stateID == 4
		}
	case "WINDOW":
		selected = stateID == 1
		disabled = stateID != 1
	}
	return
}

func themePartColors(className string, partID, stateID int32) (fillColor, borderColor, textColor uint32) {
	fillColor = themeColors.ButtonFace
	borderColor = themeColors.Border
	textColor = themeColors.WindowText

	hot, pressed, disabled, checked, selected := themedStateFlags(className, partID, stateID)
	if disabled {
		textColor = themeColors.GrayText
		fillColor = 0x00F6F6F6
	}

	switch className {
	case "BUTTON":
		switch partID {
		case 1:
			if pressed {
				fillColor = 0x00E5F1FB
				borderColor = 0x00006CBE
			} else if hot || selected {
				fillColor = 0x00F5F9FF
				borderColor = 0x000078D7
			}
			if disabled {
				borderColor = themeColors.Border
			}
		case 2, 3:
			fillColor = themeColors.Window
			if hot {
				borderColor = themeColors.Highlight
			}
			if pressed {
				fillColor = 0x00E5F1FB
				borderColor = 0x00006CBE
			}
			if checked {
				fillColor = themeColors.Window
			}
		case 4:
			fillColor = 0
			borderColor = themeColors.Border
		}
	case "EDIT":
		fillColor = themeColors.Window
		if selected {
			borderColor = themeColors.Highlight
		}
		if disabled {
			fillColor = themeColors.ButtonFace
		}
	case "LISTVIEW":
		fillColor = themeColors.Window
		if selected {
			fillColor = themeColors.Highlight
			textColor = themeColors.HighlightText
			borderColor = themeColors.Highlight
		}
	case "HEADER":
		if pressed {
			fillColor = 0x00E8E8E8
		} else if hot {
			fillColor = 0x00F8F8F8
		}
	case "TOOLBAR":
		if partID == 1 {
			if pressed {
				fillColor = 0x00E5F1FB
				borderColor = 0x00006CBE
			} else if hot || selected {
				fillColor = 0x00F5F9FF
				borderColor = themeColors.Highlight
			}
		} else {
			fillColor = 0
			borderColor = themeColors.Border
		}
	case "TAB":
		if partID == 1 {
			if selected {
				fillColor = themeColors.Window
				borderColor = themeColors.Border
			} else if hot {
				fillColor = 0x00FAFAFA
			} else {
				fillColor = 0x00EDEDED
			}
		} else {
			fillColor = themeColors.Window
		}
	case "SCROLLBAR":
		if partID == 1 {
			fillColor = themeColors.ScrollbarTrack
			if hot {
				fillColor = 0x00E8E8E8
			}
			if pressed {
				fillColor = 0x00DADADA
			}
		} else if partID == 2 || partID == 3 {
			fillColor = themeColors.ScrollbarThumb
		} else {
			fillColor = themeColors.ScrollbarTrack
		}
	case "REBAR":
		fillColor = themeColors.ButtonFace
	case "STATUS":
		fillColor = themeColors.ButtonFace
	case "MENU":
		switch partID {
		case 7:
			fillColor = themeColors.ButtonFace
			borderColor = 0
		case 8:
			if selected {
				fillColor = 0x00E5F3FF
				borderColor = themeColors.Highlight
			}
		case 9:
			fillColor = themeColors.Window
		case 14:
			fillColor = themeColors.Window
			if selected {
				fillColor = themeColors.Highlight
				textColor = themeColors.HighlightText
				borderColor = themeColors.Highlight
			}
		}
	case "TREEVIEW":
		if partID == 1 && selected {
			fillColor = themeColors.Highlight
			borderColor = themeColors.Highlight
			textColor = themeColors.HighlightText
		} else if partID == 2 {
			fillColor = themeColors.Window
		}
	case "WINDOW":
		switch partID {
		case 1, 2, 3:
			if selected {
				fillColor = themeColors.Highlight
				textColor = themeColors.HighlightText
			} else {
				fillColor = themeColors.ButtonFace
			}
		default:
			fillColor = 0
			borderColor = themeColors.Border
		}
	}
	return
}

func themePartSize(className string, partID int32) (int32, int32) {
	switch className {
	case "BUTTON":
		switch partID {
		case 1:
			return 75, 23
		case 2, 3:
			return 13, 13
		case 4:
			return 80, 18
		}
	case "EDIT":
		return 100, 23
	case "LISTVIEW":
		if partID == 2 {
			return 120, 24
		}
		return 80, 18
	case "HEADER":
		return 80, 20
	case "TOOLBAR":
		if partID == 5 {
			return 6, 24
		}
		return 24, 24
	case "TAB":
		if partID == 9 {
			return 120, 24
		}
		return 80, 24
	case "SCROLLBAR":
		switch partID {
		case 1:
			return 17, 17
		case 2:
			return 17, 10
		case 3:
			return 10, 17
		case 8, 9:
			return 8, 8
		}
	case "REBAR":
		return 120, 24
	case "STATUS":
		switch partID {
		case 1:
			return 80, 20
		case 2, 3:
			return 16, 16
		}
	case "MENU":
		switch partID {
		case 7:
			return 120, 24
		case 8, 14:
			return 100, 22
		case 9:
			return 160, 24
		}
	case "TREEVIEW":
		if partID == 2 {
			return 9, 9
		}
		return 120, 18
	case "WINDOW":
		switch partID {
		case 1:
			return 120, 23
		case 2, 3:
			return 120, 18
		default:
			return 4, 4
		}
	}
	return 20, 20
}

func themeMin32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func drawThemedRect(dc *gdi.DC, left, top, right, bottom int32, fillColor, borderColor uint32) {
	if dc == nil || left >= right || top >= bottom {
		return
	}
	if fillColor != 0 {
		dc.FillRect(left, top, right, bottom, fillColor)
	}
	if borderColor != 0 {
		dc.DrawBorder(left, top, right, bottom, borderColor)
	}
}

func drawThemeArrow(dc *gdi.DC, left, top, right, bottom int32, direction int, color uint32) {
	if dc == nil || color == 0 {
		return
	}
	cx := (left + right) / 2
	cy := (top + bottom) / 2
	size := themeMin32((right-left)/2, (bottom-top)/2)
	if size < 2 {
		size = 2
	}
	for i := int32(0); i < size; i++ {
		switch direction {
		case 0:
			y := cy - size/2 + i
			dc.FillRect(cx-i, y, cx+i+1, y+1, color)
		case 1:
			y := cy + size/2 - i
			dc.FillRect(cx-i, y, cx+i+1, y+1, color)
		case 2:
			x := cx - size/2 + i
			dc.FillRect(x, cy-i, x+1, cy+i+1, color)
		default:
			x := cx + size/2 - i
			dc.FillRect(x, cy-i, x+1, cy+i+1, color)
		}
	}
}

func drawThemeCheckMark(dc *gdi.DC, left, top, right, bottom int32, color uint32) {
	if dc == nil || color == 0 {
		return
	}
	size := themeMin32(right-left, bottom-top)
	startX := left + size/5
	startY := top + size/2
	for i := int32(0); i < size/4; i++ {
		dc.FillRect(startX+i, startY+i, startX+i+2, startY+i+2, color)
	}
	midX := startX + size/4
	midY := startY + size/4
	for i := int32(0); i < size/2; i++ {
		dc.FillRect(midX+i, midY-i, midX+i+2, midY-i+2, color)
	}
}

func drawThemeGripper(dc *gdi.DC, left, top, right, bottom int32, vertical bool, color uint32) {
	if dc == nil || color == 0 {
		return
	}
	if vertical {
		x := (left + right) / 2
		for y := top + 3; y < bottom-2; y += 4 {
			dc.FillRect(x, y, x+2, y+2, color)
		}
		return
	}
	y := (top + bottom) / 2
	for x := left + 3; x < right-2; x += 4 {
		dc.FillRect(x, y, x+2, y+2, color)
	}
}

func drawThemeGlyph(dc *gdi.DC, left, top, right, bottom int32, expanded bool) {
	drawThemedRect(dc, left, top, right, bottom, themeColors.Window, themeColors.Border)
	midX := (left + right) / 2
	midY := (top + bottom) / 2
	dc.FillRect(left+2, midY, right-2, midY+1, themeColors.WindowText)
	if !expanded {
		dc.FillRect(midX, top+2, midX+1, bottom-2, themeColors.WindowText)
	}
}

func drawThemeClassBackground(dc *gdi.DC, className string, partID, stateID int32, left, top, right, bottom int32) {
	fillColor, borderColor, textColor := themePartColors(className, partID, stateID)
	width := right - left
	height := bottom - top

	switch className {
	case "BUTTON":
		switch partID {
		case 2, 3:
			size := themeMin32(width, height)
			boxLeft := left + (width-size)/2
			boxTop := top + (height-size)/2
			boxRight := boxLeft + size
			boxBottom := boxTop + size
			drawThemedRect(dc, boxLeft, boxTop, boxRight, boxBottom, fillColor, borderColor)
			_, _, _, checked, _ := themedStateFlags(className, partID, stateID)
			if checked {
				if partID == 2 {
					dc.FillRect(boxLeft+4, boxTop+4, boxRight-4, boxBottom-4, textColor)
				} else {
					drawThemeCheckMark(dc, boxLeft+2, boxTop+2, boxRight-2, boxBottom-2, textColor)
				}
			}
			return
		case 4:
			if top < bottom {
				midY := top + 7
				if midY < bottom {
					dc.FillRect(left, midY, right, midY+1, borderColor)
				}
				dc.FillRect(left, midY, left+1, bottom, borderColor)
				dc.FillRect(right-1, midY, right, bottom, borderColor)
				dc.FillRect(left, bottom-1, right, bottom, borderColor)
			}
			return
		}
	case "EDIT", "HEADER", "REBAR", "STATUS", "LISTVIEW", "TAB":
		drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
		if className == "TAB" && partID == 1 {
			_, _, _, _, selected := themedStateFlags(className, partID, stateID)
			if selected {
				dc.FillRect(left+1, bottom-1, right-1, bottom, themeColors.Window)
			}
		}
		return
	case "TOOLBAR":
		if partID == 5 {
			x := (left + right) / 2
			dc.FillRect(x, top+2, x+1, bottom-2, themeColors.Border)
			return
		}
		drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
		return
	case "SCROLLBAR":
		switch partID {
		case 1:
			drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
			dir := 0
			if stateID >= 1 {
				dir = int((stateID - 1) / 4)
			}
			drawThemeArrow(dc, left+3, top+3, right-3, bottom-3, dir, textColor)
			return
		case 2, 3:
			drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
			drawThemeGripper(dc, left+2, top+2, right-2, bottom-2, partID == 3, themeColors.ButtonShadow)
			return
		case 8:
			drawThemeGripper(dc, left, top, right, bottom, false, themeColors.ButtonShadow)
			return
		case 9:
			drawThemeGripper(dc, left, top, right, bottom, true, themeColors.ButtonShadow)
			return
		}
	case "MENU":
		drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
		return
	case "TREEVIEW":
		if partID == 2 {
			drawThemeGlyph(dc, left, top, right, bottom, stateID == 2)
			return
		}
		if fillColor != 0 && (fillColor != themeColors.Window || borderColor != themeColors.Border) {
			drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
		}
		return
	case "WINDOW":
		drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
		return
	}

	drawThemedRect(dc, left, top, right, bottom, fillColor, borderColor)
}

func themeTextDefaultAlign(className string, partID int32) (centerX, centerY bool, margin int32) {
	margin = 4
	switch className {
	case "BUTTON":
		if partID == 1 {
			return true, true, 0
		}
		if partID == 4 {
			return false, false, 8
		}
	case "HEADER", "TAB":
		return true, true, 0
	case "MENU":
		if partID == 8 {
			return true, true, 0
		}
		return false, true, 6
	case "STATUS":
		return false, true, 4
	case "EDIT":
		return false, true, 4
	}
	return false, true, margin
}

func drawThemeTextToDC(dc *gdi.DC, className string, partID, stateID int32, text string, left, top, right, bottom int32) {
	if dc == nil || text == "" {
		return
	}
	_, _, textColor := themePartColors(className, partID, stateID)
	prevColor := dc.TextColor
	prevBkMode := dc.BkMode
	prevAlign := dc.TextAlign
	dc.TextColor = textColor
	dc.BkMode = 1
	dc.TextAlign = 0

	centerX, centerY, margin := themeTextDefaultAlign(className, partID)
	w, h := dc.TextExtentStr(text)
	x := left + margin
	y := top
	if centerX {
		x = left + ((right-left)-w)/2
	}
	if centerY {
		y = top + ((bottom-top)-h)/2
	}
	if x < left {
		x = left
	}
	if y < top {
		y = top
	}

	dc.TextOut(x, y, text, false)
	dc.TextColor = prevColor
	dc.BkMode = prevBkMode
	dc.TextAlign = prevAlign
}

func writeRect(mem *mmu.MMU, addr uint64, left, top, right, bottom int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(left))
	mem.Write32(addr+4, uint32(top))
	mem.Write32(addr+8, uint32(right))
	mem.Write32(addr+12, uint32(bottom))
}

func readRect(mem *mmu.MMU, addr uint64) (int32, int32, int32, int32, bool) {
	if addr == 0 {
		return 0, 0, 0, 0, false
	}
	left, _ := mem.Read32(addr + 0)
	top, _ := mem.Read32(addr + 4)
	right, _ := mem.Read32(addr + 8)
	bottom, _ := mem.Read32(addr + 12)
	return int32(left), int32(top), int32(right), int32(bottom), true
}

func copyRect(mem *mmu.MMU, dst, src uint64) bool {
	left, top, right, bottom, ok := readRect(mem, src)
	if !ok || dst == 0 {
		return false
	}
	writeRect(mem, dst, left, top, right, bottom)
	return true
}

func writeSize(mem *mmu.MMU, addr uint64, cx, cy int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(cx))
	mem.Write32(addr+4, uint32(cy))
}

func writePoint(mem *mmu.MMU, addr uint64, x, y int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(x))
	mem.Write32(addr+4, uint32(y))
}

func writeMargins(mem *mmu.MMU, addr uint64, leftWidth, rightWidth, topHeight, bottomHeight int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(leftWidth))
	mem.Write32(addr+4, uint32(rightWidth))
	mem.Write32(addr+8, uint32(topHeight))
	mem.Write32(addr+12, uint32(bottomHeight))
}

func writeBool32(mem *mmu.MMU, addr uint64, value bool) {
	if addr == 0 {
		return
	}
	if value {
		mem.Write32(addr, 1)
	} else {
		mem.Write32(addr, 0)
	}
}

func readOptionalThemeString(mem *mmu.MMU, addr uint64) (string, bool) {
	if addr == 0 {
		return "", true
	}
	chars := make([]uint16, 0, 64)
	for i := 0; i < 1024; i++ {
		value, err := mem.Read16(addr + uint64(i)*2)
		if err != nil {
			return "", false
		}
		if value == 0 {
			return string(utf16Decode(chars)), true
		}
		chars = append(chars, value)
	}
	return "", false
}

func setPreferredDarkAppMode(mode preferredAppMode) preferredAppMode {
	darkModeGlobal.mu.Lock()
	defer darkModeGlobal.mu.Unlock()
	previous := darkModeGlobal.preferredMode
	if mode < preferredAppModeMax {
		darkModeGlobal.preferredMode = mode
		darkModeGlobal.legacyAppAllowed = false
	}
	return previous
}

func allowDarkModeForApp(allow bool) {
	darkModeGlobal.mu.Lock()
	darkModeGlobal.legacyAppAllowed = allow
	if allow {
		darkModeGlobal.preferredMode = preferredAppModeAllowDark
	} else {
		darkModeGlobal.preferredMode = preferredAppModeDefault
	}
	darkModeGlobal.mu.Unlock()
}

func allowDarkModeForWindow(hwnd uint64, allow bool) bool {
	if hwnd == 0 {
		return false
	}
	darkModeGlobal.mu.Lock()
	darkModeGlobal.windowAllowed[hwnd] = allow
	darkModeGlobal.mu.Unlock()
	return true
}

func setWindowThemeSelection(hwnd uint64, selection windowThemeSelection) bool {
	if hwnd == 0 {
		return false
	}
	darkModeGlobal.mu.Lock()
	darkModeGlobal.windowThemes[hwnd] = selection
	darkModeGlobal.mu.Unlock()
	return true
}

func setImmersiveDarkModeForWindow(hwnd uint64, dark bool) bool {
	if hwnd == 0 {
		return false
	}
	darkModeGlobal.mu.Lock()
	darkModeGlobal.windowImmersiveDWM[hwnd] = dark
	darkModeGlobal.mu.Unlock()
	return true
}

func writeThemeString(mem *mmu.MMU, addr uint64, cch uint32, value string) uint32 {
	if addr == 0 || cch == 0 {
		return 0
	}
	ws := utf16Encode(value)
	limit := int(cch) - 1
	if limit < 0 {
		limit = 0
	}
	if len(ws) > limit {
		ws = ws[:limit]
	}
	for i, wc := range ws {
		mem.Write16(addr+uint64(i)*2, wc)
	}
	mem.Write16(addr+uint64(len(ws))*2, 0)
	return uint32(len(ws))
}

func writeLogFontW(mem *mmu.MMU, addr uint64, face string, height int32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr+0, uint32(height))
	mem.Write32(addr+4, 0)
	mem.Write32(addr+8, 0)
	mem.Write32(addr+12, 0)
	mem.Write32(addr+16, 400)
	mem.Write8(addr+20, 0)
	mem.Write8(addr+21, 0)
	mem.Write8(addr+22, 0)
	mem.Write8(addr+23, 1)
	mem.Write8(addr+24, 0)
	mem.Write8(addr+25, 0)
	mem.Write8(addr+26, 5)
	mem.Write8(addr+27, 0x22)
	ws := utf16Encode(face)
	if len(ws) > 31 {
		ws = ws[:31]
	}
	for i, wc := range ws {
		mem.Write16(addr+28+uint64(i)*2, wc)
	}
	mem.Write16(addr+28+uint64(len(ws))*2, 0)
}

func registerUxthemeHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16
	gdiMgr := hctx.GdiMgr
	getSysColor := hctx.GetSysColor

	uxtheme, ok := hctx.SynthByName["uxtheme.dll"]
	if !ok {
		return
	}

	defaultThemeColor := func() uint32 {
		if getSysColor != nil {
			return getSysColor(15)
		}
		return themeColors.ButtonFace
	}
	defaultThemeInt := func() uint32 { return 0 }
	defaultThemeSize := func(className string, partID int32) (int32, int32) { return themePartSize(className, partID) }
	defaultTextRect := func(text string) (int32, int32, int32, int32) {
		width := int32(len([]rune(text)) * 8)
		if width <= 0 {
			width = 20
		}
		return 0, 0, width, 20
	}
	allocThemeHandle := func(hwnd uint64, className string) uint64 {
		themeGlobal.mu.Lock()
		defer themeGlobal.mu.Unlock()
		h := themeGlobal.nextHandle
		themeGlobal.nextHandle++
		themeGlobal.themes[h] = &themeData{className: className, hwnd: hwnd}
		return uint64(h)
	}
	closeThemeHandle := func(handle uint64) {
		themeGlobal.mu.Lock()
		delete(themeGlobal.themes, uint32(handle))
		themeGlobal.mu.Unlock()
	}
	allocBufferedHandle := func(hdcTarget uint64) uint64 {
		bufferedPaintGlobal.mu.Lock()
		defer bufferedPaintGlobal.mu.Unlock()
		h := bufferedPaintGlobal.nextHandle
		bufferedPaintGlobal.nextHandle++
		bufferedPaintGlobal.paints[h] = hdcTarget
		return uint64(h)
	}
	closeBufferedHandle := func(handle uint64) {
		bufferedPaintGlobal.mu.Lock()
		delete(bufferedPaintGlobal.paints, uint32(handle))
		bufferedPaintGlobal.mu.Unlock()
	}
	registerDarkHandler := func(name string, handler ntapi.TrapHandler) {
		registerAutoOrDynamicHandler(hctx, uxtheme, name, handler)
	}
	requestDarkRepaint := func(hwnd uint64) {
		if hctx.RequestWindowRepaint != nil && hwnd != 0 {
			hctx.RequestWindowRepaint(hwnd)
		}
	}
	requestAllDarkRepaint := func() {
		for _, hwnd := range darkRepaintWindowRoots(hctx) {
			requestDarkRepaint(hwnd)
		}
	}

	registerDarkHandler("OpenNcThemeData", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		className := normalizeThemeClass(readGuestUTF16(ctx.Arg(1)))
		ctx.SetReturn(allocThemeHandle(hwnd, className))
		return 0
	})
	registerDarkHandler("RefreshImmersiveColorPolicyState", func(ctx *ntapi.TrapContext) uint32 {
		requestAllDarkRepaint()
		ctx.SetReturn(0)
		return 0
	})
	registerDarkHandler("GetIsImmersiveColorUsingHighContrast", func(ctx *ntapi.TrapContext) uint32 {
		_ = ctx.Arg(0)
		ctx.SetReturn(0)
		return 0
	})
	registerDarkHandler("ShouldAppsUseDarkMode", func(ctx *ntapi.TrapContext) uint32 {
		if shouldAppsUseDarkMode() {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	registerDarkHandler("AllowDarkModeForWindow", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		allow := ctx.Arg(1) != 0
		previous := darkModeAllowedForWindow(hwnd)
		if allowDarkModeForWindow(hwnd, allow) {
			if previous != allow {
				requestDarkRepaint(hwnd)
			}
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	registerDarkHandler("AllowDarkModeForApp", func(ctx *ntapi.TrapContext) uint32 {
		allowDarkModeForApp(ctx.Arg(0) != 0)
		requestAllDarkRepaint()
		ctx.SetReturn(1)
		return 0
	})
	registerDarkHandler("SetPreferredAppMode", func(ctx *ntapi.TrapContext) uint32 {
		mode := preferredAppMode(uint32(ctx.Arg(0)))
		previous := setPreferredDarkAppMode(mode)
		if mode < preferredAppModeMax && previous != mode {
			requestAllDarkRepaint()
		}
		ctx.SetReturn(uint64(previous))
		return 0
	})
	registerDarkHandler("FlushMenuThemes", func(ctx *ntapi.TrapContext) uint32 {
		requestDarkRepaint(hctx.MainHWND)
		ctx.SetReturn(0)
		return 0
	})
	registerDarkHandler("IsDarkModeAllowedForWindow", func(ctx *ntapi.TrapContext) uint32 {
		if darkModeAllowedForWindow(ctx.Arg(0)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	registerDarkHandler("ShouldSystemUseDarkMode", func(ctx *ntapi.TrapContext) uint32 {
		if shouldSystemUseDarkMode() {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "OpenThemeData", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		className := normalizeThemeClass(readGuestUTF16(ctx.Arg(1)))
		ctx.SetReturn(allocThemeHandle(hwnd, className))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "OpenThemeDataEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		className := normalizeThemeClass(readGuestUTF16(ctx.Arg(1)))
		_ = ctx.Arg(2)
		ctx.SetReturn(allocThemeHandle(hwnd, className))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "CloseThemeData", func(ctx *ntapi.TrapContext) uint32 {
		closeThemeHandle(ctx.Arg(0))
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeActive", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsAppThemed", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "SetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		subAppName, appOK := readOptionalThemeString(mem, ctx.Arg(1))
		subIDList, idOK := readOptionalThemeString(mem, ctx.Arg(2))
		selection := windowThemeSelection{
			SubAppName: subAppName,
			SubIDList:  subIDList,
		}
		previous, existed := windowThemeSelectionFor(hwnd)
		if !appOK || !idOK || !setWindowThemeSelection(hwnd, selection) {
			ctx.SetReturn(eInvalidArg)
		} else {
			if !existed || previous != selection {
				requestDarkRepaint(hwnd)
			}
			ctx.SetReturn(sOK)
		}
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetCurrentThemeName", func(ctx *ntapi.TrapContext) uint32 {
		writeThemeString(mem, ctx.Arg(0), uint32(ctx.Arg(1)), "Raven")
		writeThemeString(mem, ctx.Arg(2), uint32(ctx.Arg(3)), "NormalColor")
		writeThemeString(mem, ctx.Arg(4), uint32(ctx.Arg(5)), "NormalSize")
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		td := getThemeInfo(ctx.Arg(0))
		className := "WINDOW"
		if td != nil && td.className != "" {
			className = td.className
		}
		dc := gdiMgr.GetDC(ctx.Arg(1))
		if dc == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		left, top, right, bottom, ok := readRect(mem, ctx.Arg(4))
		if !ok {
			ctx.SetReturn(sOK)
			return 0
		}
		if clipAddr := ctx.Arg(5); clipAddr != 0 {
			if cLeft, cTop, cRight, cBottom, clipOK := readRect(mem, clipAddr); clipOK {
				prev := [4]int32{dc.ClipX0, dc.ClipY0, dc.ClipX1, dc.ClipY1}
				dc.SetClipRect(cLeft+dc.OriginX, cTop+dc.OriginY, cRight+dc.OriginX, cBottom+dc.OriginY)
				drawThemeClassBackground(dc, className, int32(ctx.Arg(2)), int32(ctx.Arg(3)), left, top, right, bottom)
				if td != nil && darkModeRequestedForWindow(td.hwnd) {
					remapDCRectForDarkMode(dc, left, top, right, bottom)
				}
				dc.SetClipRect(prev[0], prev[1], prev[2], prev[3])
				ctx.SetReturn(sOK)
				return 0
			}
		}
		drawThemeClassBackground(dc, className, int32(ctx.Arg(2)), int32(ctx.Arg(3)), left, top, right, bottom)
		if td != nil && darkModeRequestedForWindow(td.hwnd) {
			remapDCRectForDarkMode(dc, left, top, right, bottom)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackgroundEx", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		td := getThemeInfo(ctx.Arg(0))
		className := "WINDOW"
		if td != nil && td.className != "" {
			className = td.className
		}
		dc := gdiMgr.GetDC(ctx.Arg(1))
		if dc != nil {
			left, top, right, bottom, ok := readRect(mem, ctx.Arg(4))
			if ok {
				drawThemeClassBackground(dc, className, int32(ctx.Arg(2)), int32(ctx.Arg(3)), left, top, right, bottom)
				if td != nil && darkModeRequestedForWindow(td.hwnd) {
					remapDCRectForDarkMode(dc, left, top, right, bottom)
				}
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeText", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		td := getThemeInfo(ctx.Arg(0))
		className := "WINDOW"
		if td != nil && td.className != "" {
			className = td.className
		}
		dc := gdiMgr.GetDC(ctx.Arg(1))
		if dc == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		pText := ctx.Arg(4)
		cchText := int(int32(ctx.Arg(5)))
		text := ""
		if cchText < 0 {
			text = readGuestUTF16(pText)
		} else {
			text = hctx.ReadGuestUTF16N(pText, cchText)
		}
		left, top, right, bottom, ok := readRect(mem, ctx.Arg(7))
		if !ok {
			left, top, right, bottom = 0, 0, 0, 0
		}
		drawThemeTextToDC(dc, className, int32(ctx.Arg(2)), int32(ctx.Arg(3)), text, left, top, right, bottom)
		if td != nil && darkModeRequestedForWindow(td.hwnd) {
			remapDCRectForDarkMode(dc, left, top, right, bottom)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeTextEx", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		td := getThemeInfo(ctx.Arg(0))
		className := "WINDOW"
		if td != nil && td.className != "" {
			className = td.className
		}
		dc := gdiMgr.GetDC(ctx.Arg(1))
		if dc == nil {
			ctx.SetReturn(sOK)
			return 0
		}
		pText := ctx.Arg(4)
		cchText := int(int32(ctx.Arg(5)))
		text := ""
		if cchText < 0 {
			text = readGuestUTF16(pText)
		} else {
			text = hctx.ReadGuestUTF16N(pText, cchText)
		}
		if left, top, right, bottom, ok := readRect(mem, ctx.Arg(7)); ok {
			drawThemeTextToDC(dc, className, int32(ctx.Arg(2)), int32(ctx.Arg(3)), text, left, top, right, bottom)
			if td != nil && darkModeRequestedForWindow(td.hwnd) {
				remapDCRectForDarkMode(dc, left, top, right, bottom)
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeIcon", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeEdge", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackground", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackgroundEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "GetThemePartSize", func(ctx *ntapi.TrapContext) uint32 {
		className := "WINDOW"
		if td := getThemeInfo(ctx.Arg(0)); td != nil && td.className != "" {
			className = td.className
		}
		w, h := defaultThemeSize(className, int32(ctx.Arg(2)))
		writeSize(mem, ctx.Arg(6), w, h)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeColor", func(ctx *ntapi.TrapContext) uint32 {
		className := "WINDOW"
		td := getThemeInfo(ctx.Arg(0))
		if td != nil && td.className != "" {
			className = td.className
		}
		fillColor, borderColor, textColor := themePartColors(className, int32(ctx.Arg(1)), int32(ctx.Arg(2)))
		if td != nil && darkModeRequestedForWindow(td.hwnd) {
			fillColor = darkThemeColor(fillColor)
			borderColor = darkThemeColor(borderColor)
			textColor = darkThemeColor(textColor)
		}
		if pColor := ctx.Arg(4); pColor != 0 {
			color := defaultThemeColor()
			switch uint32(ctx.Arg(3)) {
			case tmtBorderColor:
				color = borderColor
			case tmtTextColor:
				color = textColor
			case tmtFillColor:
				color = fillColor
			default:
				if textColor != 0 {
					color = textColor
				} else if fillColor != 0 {
					color = fillColor
				}
			}
			mem.Write32(pColor, color)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeFont", func(ctx *ntapi.TrapContext) uint32 {
		writeLogFontW(mem, ctx.Arg(5), "Segoe UI", -12)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeInt", func(ctx *ntapi.TrapContext) uint32 {
		if pValue := ctx.Arg(4); pValue != 0 {
			mem.Write32(pValue, defaultThemeInt())
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBool", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(4), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeMetric", func(ctx *ntapi.TrapContext) uint32 {
		iPropId := uint32(ctx.Arg(4))
		if pValue := ctx.Arg(5); pValue != 0 {
			switch iPropId {
			case 2403: // TMT_BORDERSIZE
				mem.Write32(pValue, 1)
			case 3801: // TMT_BORDERCOLOR
				mem.Write32(pValue, 0x00A0A0A0)
			case 2411: // TMT_ROUNDCORNERWIDTH
				mem.Write32(pValue, 2)
			case 2412: // TMT_ROUNDCORNERHEIGHT
				mem.Write32(pValue, 2)
			default:
				mem.Write32(pValue, 0)
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeMargins", func(ctx *ntapi.TrapContext) uint32 {
		writeMargins(mem, ctx.Arg(6), 0, 0, 0, 0)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeRect", func(ctx *ntapi.TrapContext) uint32 {
		writeRect(mem, ctx.Arg(4), 0, 0, 20, 20)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemePosition", func(ctx *ntapi.TrapContext) uint32 {
		writePoint(mem, ctx.Arg(4), 0, 0)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundContentRect", func(ctx *ntapi.TrapContext) uint32 {
		if !copyRect(mem, ctx.Arg(5), ctx.Arg(4)) {
			writeRect(mem, ctx.Arg(5), 0, 0, 20, 20)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundExtent", func(ctx *ntapi.TrapContext) uint32 {
		if !copyRect(mem, ctx.Arg(5), ctx.Arg(4)) {
			writeRect(mem, ctx.Arg(5), 0, 0, 20, 20)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTextExtent", func(ctx *ntapi.TrapContext) uint32 {
		pBoundingRect := ctx.Arg(6)
		pExtentRect := ctx.Arg(7)
		if pBoundingRect != 0 && pExtentRect != 0 {
			copyRect(mem, pExtentRect, pBoundingRect)
		} else {
			text := readGuestUTF16(ctx.Arg(4))
			left, top, right, bottom := defaultTextRect(text)
			writeRect(mem, pExtentRect, left, top, right, bottom)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysColor", func(ctx *ntapi.TrapContext) uint32 {
		if getSysColor != nil {
			ctx.SetReturn(uint64(getSysColor(uint32(ctx.Arg(1)))))
		} else {
			ctx.SetReturn(uint64(defaultThemeColor()))
		}
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysColorBrush", func(ctx *ntapi.TrapContext) uint32 {
		if gdiMgr == nil {
			ctx.SetReturn(0)
		} else {
			color := defaultThemeColor()
			if getSysColor != nil {
				color = getSysColor(uint32(ctx.Arg(1)))
			}
			ctx.SetReturn(gdiMgr.CreateSolidBrush(color))
		}
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysFont", func(ctx *ntapi.TrapContext) uint32 {
		writeLogFontW(mem, ctx.Arg(2), "Segoe UI", -12)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeSysSize", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(16)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemePartDefined", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeBackgroundPartiallyTransparent", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeDialogTextureEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "HitTestThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
		if pHitTest := ctx.Arg(8); pHitTest != 0 {
			mem.Write16(pHitTest, 0)
		}
		ctx.SetReturn(sOK)
		return 0
	})

	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintInit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintUnInit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BeginBufferedPaint", func(ctx *ntapi.TrapContext) uint32 {
		hdcTarget := ctx.Arg(0)
		if phdc := ctx.Arg(4); phdc != 0 {
			mem.Write64(phdc, hdcTarget)
		}
		ctx.SetReturn(allocBufferedHandle(hdcTarget))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EndBufferedPaint", func(ctx *ntapi.TrapContext) uint32 {
		closeBufferedHandle(ctx.Arg(0))
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintSetAlpha", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BeginBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		hdcTarget := ctx.Arg(1)
		if phdcFrom := ctx.Arg(6); phdcFrom != 0 {
			mem.Write64(phdcFrom, hdcTarget)
		}
		if phdcTo := ctx.Arg(7); phdcTo != 0 {
			mem.Write64(phdcTo, hdcTarget)
		}
		ctx.SetReturn(allocBufferedHandle(hdcTarget))
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EndBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		closeBufferedHandle(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintRenderAnimation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTransitionDuration", func(ctx *ntapi.TrapContext) uint32 {
		if pDuration := ctx.Arg(4); pDuration != 0 {
			mem.Write32(pDuration, 0)
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EnableThemeDialogTexture", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintStopAllAnimations", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
}

func registerDwmapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	dwmapi, ok := hctx.SynthByName["dwmapi.dll"]
	if !ok {
		return
	}

	defaultWindowRect := func() (int32, int32, int32, int32) {
		if hctx.WlWindow != nil {
			return 0, 0, hctx.WlWindow.Width, hctx.WlWindow.Height
		}
		return 0, 0, 800, 600
	}
	allocThumbnail := func() uint64 {
		dwmThumbnailGlobal.mu.Lock()
		defer dwmThumbnailGlobal.mu.Unlock()
		h := dwmThumbnailGlobal.nextHandle
		dwmThumbnailGlobal.nextHandle++
		dwmThumbnailGlobal.thumbs[h] = struct{}{}
		return uint64(h)
	}
	freeThumbnail := func(handle uint64) bool {
		dwmThumbnailGlobal.mu.Lock()
		defer dwmThumbnailGlobal.mu.Unlock()
		h := uint32(handle)
		if _, ok := dwmThumbnailGlobal.thumbs[h]; !ok {
			return false
		}
		delete(dwmThumbnailGlobal.thumbs, h)
		return true
	}
	hasThumbnail := func(handle uint64) bool {
		dwmThumbnailGlobal.mu.Lock()
		_, ok := dwmThumbnailGlobal.thumbs[uint32(handle)]
		dwmThumbnailGlobal.mu.Unlock()
		return ok
	}

	d.RegisterAutoStubHandler(dwmapi, "DwmIsCompositionEnabled", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(0), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmEnableComposition", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmExtendFrameIntoClientArea", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		attr := uint32(ctx.Arg(1))
		pvAttr := ctx.Arg(2)
		cbAttr := uint32(ctx.Arg(3))
		if attr == dwmwaUseImmersiveDarkModeBefore20H1 || attr == dwmwaUseImmersiveDarkMode {
			if pvAttr == 0 || cbAttr != 4 {
				ctx.SetReturn(eInvalidArg)
				return 0
			}
			value, err := mem.Read32(pvAttr)
			dark := value != 0
			previous, existed := immersiveDarkModeForWindow(hwnd)
			if err != nil || !setImmersiveDarkModeForWindow(hwnd, dark) {
				ctx.SetReturn(eInvalidArg)
				return 0
			}
			if (!existed || previous != dark) && hctx.RequestWindowRepaint != nil {
				hctx.RequestWindowRepaint(hwnd)
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
		attr := uint32(ctx.Arg(1))
		pvAttr := ctx.Arg(2)
		cbAttr := uint32(ctx.Arg(3))
		if attr == dwmwaUseImmersiveDarkModeBefore20H1 || attr == dwmwaUseImmersiveDarkMode {
			if pvAttr == 0 || cbAttr != 4 {
				ctx.SetReturn(eInvalidArg)
				return 0
			}
			dark, _ := immersiveDarkModeForWindow(ctx.Arg(0))
			if dark {
				if err := mem.Write32(pvAttr, 1); err != nil {
					ctx.SetReturn(eInvalidArg)
					return 0
				}
			} else if err := mem.Write32(pvAttr, 0); err != nil {
				ctx.SetReturn(eInvalidArg)
				return 0
			}
			ctx.SetReturn(sOK)
			return 0
		}
		if pvAttr != 0 {
			switch attr {
			case 1:
				if cbAttr >= 4 {
					mem.Write32(pvAttr, 1)
				}
			case 5, 9:
				left, top, right, bottom := defaultWindowRect()
				if cbAttr >= 16 {
					writeRect(mem, pvAttr, left, top, right, bottom)
				}
			case 14:
				if cbAttr >= 4 {
					mem.Write32(pvAttr, 0)
				}
			default:
				switch {
				case cbAttr >= 16:
					left, top, right, bottom := defaultWindowRect()
					writeRect(mem, pvAttr, left, top, right, bottom)
				case cbAttr >= 8:
					mem.Write64(pvAttr, 0)
				case cbAttr >= 4:
					mem.Write32(pvAttr, 0)
				case cbAttr >= 1:
					mem.Write8(pvAttr, 0)
				}
			}
		}
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmEnableBlurBehindWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmDefWindowProc", func(ctx *ntapi.TrapContext) uint32 {
		if plResult := ctx.Arg(4); plResult != 0 {
			mem.Write64(plResult, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetColorizationColor", func(ctx *ntapi.TrapContext) uint32 {
		if pcrColor := ctx.Arg(0); pcrColor != 0 {
			mem.Write32(pcrColor, 0xFF1E90FF)
		}
		writeBool32(mem, ctx.Arg(1), true)
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmFlush", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmInvalidateIconicBitmaps", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetIconicThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmSetIconicLivePreviewBitmap", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmRegisterThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 || ctx.Arg(1) == 0 || ctx.Arg(2) == 0 {
			ctx.SetReturn(eInvalidArg)
			return 0
		}
		mem.Write64(ctx.Arg(2), allocThumbnail())
		ctx.SetReturn(sOK)
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmUnregisterThumbnail", func(ctx *ntapi.TrapContext) uint32 {
		if freeThumbnail(ctx.Arg(0)) {
			ctx.SetReturn(sOK)
		} else {
			ctx.SetReturn(eInvalidArg)
		}
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmUpdateThumbnailProperties", func(ctx *ntapi.TrapContext) uint32 {
		if !hasThumbnail(ctx.Arg(0)) {
			ctx.SetReturn(eInvalidArg)
		} else {
			ctx.SetReturn(sOK)
		}
		return 0
	})
	d.RegisterAutoStubHandler(dwmapi, "DwmGetTransportAttributes", func(ctx *ntapi.TrapContext) uint32 {
		writeBool32(mem, ctx.Arg(0), false)
		writeBool32(mem, ctx.Arg(1), false)
		if pGeneration := ctx.Arg(2); pGeneration != 0 {
			mem.Write32(pGeneration, 0)
		}
		ctx.SetReturn(dwmECompositionDisabled)
		return 0
	})
}
