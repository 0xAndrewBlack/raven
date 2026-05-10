//go:build guest_windows

package main

import "strings"

const (
	tvmInsertItemA  = 0x1100
	tvmDeleteItem   = 0x1101
	tvmExpand       = 0x1102
	tvmGetItemRect  = 0x1104
	tvmGetCount     = 0x1105
	tvmGetImageList = 0x1108
	tvmSetImageList = 0x1109
	tvmGetNextItem  = 0x110A
	tvmSelectItem   = 0x110B
	tvmGetItemA     = 0x110C
	tvmSetItemA     = 0x110D
	tvmEditLabelA   = 0x110E
	tvmSortChildren = 0x1113
	tvmInsertItemW  = 0x1132
	tvmGetItemW     = 0x113E
	tvmSetItemW     = 0x113F
	tvmEditLabelW   = 0x1141
)

type listViewState struct {
	items        []lvItem
	columns      []lvColumn
	style        uint32
	extStyle     uint32
	selectedIdx  int
	virtualCount int
}

type lvItem struct {
	text     string
	image    int
	param    uint64
	state    uint32
	subItems []string
}

type lvColumn struct {
	text       string
	width, fmt int
}

type treeViewState struct {
	root     *tvItem
	selected *tvItem
	nextH    uint64
	style    uint32
}

type tvItem struct {
	text     string
	children []*tvItem
	parent   *tvItem
	handle   uint64
	param    uint64
	expanded bool
	state    uint32
}

type statusBarState struct {
	parts []int
	texts []string
}

type tabState struct {
	items  []tabItem
	curSel int
}

func tabRowCount(tab *tabState) uint64 {
	if tab == nil || len(tab.items) == 0 {
		return 0
	}
	return 1
}

func tabItemOffsets(is32 bool) (text, param uint64) {
	if is32 {
		return 12, 24
	}
	return 16, 32
}

type treeViewItemLayout struct {
	item       uint64
	state      uint64
	text       uint64
	textMax    uint64
	param      uint64
	insertItem uint64
}

type treeViewNotifyLayout struct {
	action  uint64
	itemOld uint64
	itemNew uint64
	point   uint64
	size    uint64
}

func treeViewNotifyOffsets(is32 bool) treeViewNotifyLayout {
	if is32 {
		return treeViewNotifyLayout{action: 12, itemOld: 16, itemNew: 56, point: 96, size: 104}
	}
	return treeViewNotifyLayout{action: 24, itemOld: 32, itemNew: 88, point: 144, size: 152}
}

func treeViewItemOffsets(is32 bool) treeViewItemLayout {
	if is32 {
		return treeViewItemLayout{item: 4, state: 8, text: 16, textMax: 20, param: 36, insertItem: 8}
	}
	return treeViewItemLayout{item: 8, state: 16, text: 24, textMax: 32, param: 48, insertItem: 16}
}

type listViewItemLayout struct {
	text    uint64
	textMax uint64
	image   uint64
	param   uint64
}

type listViewNotifyLayout struct {
	header uint64
	size   uint64
}

func listViewNotifyOffsets(is32 bool) listViewNotifyLayout {
	if is32 {
		return listViewNotifyLayout{header: 12, size: 72}
	}
	return listViewNotifyLayout{header: 24, size: 112}
}

func setListViewExtendedStyle(lv *listViewState, mask, style uint32) uint32 {
	old := lv.extStyle
	if mask == 0 {
		lv.extStyle = style
	} else {
		lv.extStyle = (old &^ mask) | (style & mask)
	}
	return old
}

func listViewItemOffsets(is32 bool) listViewItemLayout {
	if is32 {
		return listViewItemLayout{text: 20, textMax: 24, image: 28, param: 32}
	}
	return listViewItemLayout{text: 24, textMax: 32, image: 36, param: 40}
}

func listViewColumnTextOffset(is32 bool) uint64 {
	if is32 {
		return 12
	}
	return 16
}

func isTextCallbackPointer(ptr uint64, is32 bool) bool {
	if is32 {
		return ptr == uint64(^uint32(0))
	}
	return ptr == ^uint64(0)
}

func tabInputNeedsSubclassFirst(hasGuestWndProc, callingBuiltin bool, msg uint32) bool {
	if !hasGuestWndProc || callingBuiltin {
		return false
	}
	switch msg {
	case 0x0201, 0x0203: // WM_LBUTTONDOWN, WM_LBUTTONDBLCLK
		return true
	default:
		return false
	}
}

const (
	tcmAdjustRect  = uint32(0x1328)
	tcnSelChange   = uint32(0xFFFFFDD9) // -551
	tcnSelChanging = uint32(0xFFFFFDD8) // -552
)

func selectTabFromInput(tab *tabState, hit int, notify func(uint32) uint64) bool {
	if tab == nil || hit < 0 || hit >= len(tab.items) || hit == tab.curSel {
		return false
	}
	if notify != nil && notify(tcnSelChanging) != 0 {
		return false
	}
	tab.curSel = hit
	if notify != nil {
		notify(tcnSelChange)
	}
	return true
}

func adjustTabRect(rect [4]int32, style uint32, larger bool, tabHeight, rows int32) [4]int32 {
	if tabHeight <= 0 {
		tabHeight = 22
	}
	if rows <= 0 {
		rows = 1
	}
	const padding = int32(4)
	const (
		tcsBottom   = uint32(0x0002)
		tcsVertical = uint32(0x0080)
	)
	tabsExtent := tabHeight * rows
	if larger {
		if style&tcsVertical != 0 {
			if style&tcsBottom != 0 {
				rect[2] += tabsExtent
			} else {
				rect[0] -= tabsExtent
			}
		} else if style&tcsBottom != 0 {
			rect[3] += tabsExtent
		} else {
			rect[1] -= tabsExtent
		}
		rect[0] -= padding
		rect[1] -= padding
		rect[2] += padding
		rect[3] += padding
		return rect
	}

	rect[0] += padding
	rect[1] += padding
	rect[2] -= padding
	rect[3] -= padding
	if style&tcsVertical != 0 {
		if style&tcsBottom != 0 {
			rect[2] -= tabsExtent
		} else {
			rect[0] += tabsExtent
		}
	} else if style&tcsBottom != 0 {
		rect[3] -= tabsExtent
	} else {
		rect[1] += tabsExtent
	}
	return rect
}

type tabItem struct {
	text  string
	param uint64
}

type progressState struct {
	pos, min, max, step int
	barColor, bkColor   uint32
	state               int32
	marquee             bool
}

type toolbarState struct {
	buttons  []tbButton
	extStyle uint32
}

type toolbarButtonLayout struct {
	size   uint64
	data   uint64
	string uint64
}

type toolbarButtonInfoLayout struct {
	param   uint64
	text    uint64
	textMax uint64
}

func toolbarButtonOffsets(is32 bool) toolbarButtonLayout {
	if is32 {
		return toolbarButtonLayout{size: 20, data: 12, string: 16}
	}
	return toolbarButtonLayout{size: 32, data: 16, string: 24}
}

func toolbarButtonInfoOffsets(is32 bool) toolbarButtonInfoLayout {
	if is32 {
		return toolbarButtonInfoLayout{param: 20, text: 24, textMax: 28}
	}
	return toolbarButtonInfoLayout{param: 24, text: 32, textMax: 40}
}

func toolbarAddBitmapResourceOffset(is32 bool) uint64 {
	if is32 {
		return 4
	}
	return 8
}

func setToolbarButtonFlag(toolbar *toolbarState, id int, flag int, enabled bool) bool {
	if toolbar == nil {
		return false
	}
	for i := range toolbar.buttons {
		if toolbar.buttons[i].id != id {
			continue
		}
		if enabled {
			toolbar.buttons[i].state |= flag
		} else {
			toolbar.buttons[i].state &^= flag
		}
		return true
	}
	return false
}

func makeToolbarPlaceholderIcon(width, height int, seed uint64) []uint32 {
	if width <= 0 || height <= 0 {
		return nil
	}
	pixels := make([]uint32, width*height)
	color := uint32(0xFF000000 | ((seed * 0x45D9F3B) & 0x00FFFFFF))
	for y := 2; y < height-2; y++ {
		for x := 2; x < width-2; x++ {
			if x == y || x+y == width-1 || x == width/2 || y == height/2 {
				pixels[y*width+x] = color
			}
		}
	}
	return pixels
}

func toolbarIconHasVisiblePixel(pixels []uint32) bool {
	for _, pixel := range pixels {
		if pixel>>24 != 0 {
			return true
		}
	}
	return false
}

type toolbarFallbackCache struct {
	width  int
	height int
	icons  [][]uint32
}

type toolbarFallbackKey struct {
	parent uint64
	layout uint64
}

func toolbarLayoutSignature(toolbar *toolbarState) uint64 {
	if toolbar == nil || len(toolbar.buttons) == 0 {
		return 0
	}
	hash := uint64(14695981039346656037)
	for _, button := range toolbar.buttons {
		for _, value := range [...]uint64{uint64(uint32(button.id)), uint64(uint32(button.iBitmap)), uint64(uint32(button.style))} {
			hash ^= value
			hash *= 1099511628211
		}
	}
	return hash
}

func cacheToolbarFallbackIcon(hctx *HandlerCtx, key toolbarFallbackKey, index, width, height int, pixels []uint32) {
	if hctx == nil || key.parent == 0 || key.layout == 0 || index < 0 || width <= 0 || height <= 0 ||
		len(pixels) < width*height || !toolbarIconHasVisiblePixel(pixels) {
		return
	}
	hctx.ToolbarFallbackMu.Lock()
	defer hctx.ToolbarFallbackMu.Unlock()
	if hctx.ToolbarFallbackIcons == nil {
		hctx.ToolbarFallbackIcons = make(map[toolbarFallbackKey]*toolbarFallbackCache)
	}
	cache := hctx.ToolbarFallbackIcons[key]
	if cache == nil || cache.width != width || cache.height != height {
		cache = &toolbarFallbackCache{width: width, height: height}
		hctx.ToolbarFallbackIcons[key] = cache
	}
	for len(cache.icons) <= index {
		cache.icons = append(cache.icons, nil)
	}
	cache.icons[index] = append([]uint32(nil), pixels[:width*height]...)
}

func toolbarFallbackIcon(hctx *HandlerCtx, key toolbarFallbackKey, index, width, height int) []uint32 {
	if hctx == nil || key.parent == 0 || key.layout == 0 || index < 0 {
		return nil
	}
	hctx.ToolbarFallbackMu.RLock()
	defer hctx.ToolbarFallbackMu.RUnlock()
	cache := hctx.ToolbarFallbackIcons[key]
	if cache == nil || cache.width != width || cache.height != height || index >= len(cache.icons) {
		return nil
	}
	pixels := cache.icons[index]
	if !toolbarIconHasVisiblePixel(pixels) {
		return nil
	}
	return pixels
}

func toolbarMaskPixelTransparent(mask []byte, width, height, x, y int) bool {
	if width <= 0 || height <= 0 || x < 0 || y < 0 || x >= width || y >= height {
		return false
	}
	pixel := y*width + x
	stride := ((width + 31) / 32) * 4
	if len(mask) == stride*height {
		off := y*stride + x/8
		return mask[off]&(0x80>>uint(x&7)) != 0
	}
	if len(mask) >= width*height*4 {
		off := pixel * 4
		return mask[off] != 0 || mask[off+1] != 0 || mask[off+2] != 0
	}
	if len(mask) >= width*height {
		return mask[pixel] != 0
	}
	off := y*stride + x/8
	return off < len(mask) && mask[off]&(0x80>>uint(x&7)) != 0
}

func toolbarImagePixels(pixels, mask []byte, hasAlpha bool, width, height int) []uint32 {
	if width <= 0 || height <= 0 || len(pixels) < width*height*4 {
		return nil
	}
	out := make([]uint32, width*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := y*width + x
			off := i * 4
			if toolbarMaskPixelTransparent(mask, width, height, x, y) {
				continue
			}
			alpha := pixels[off+3]
			if !hasAlpha {
				alpha = 0xFF
			}
			out[i] = uint32(pixels[off]) |
				uint32(pixels[off+1])<<8 |
				uint32(pixels[off+2])<<16 |
				uint32(alpha)<<24
		}
	}
	return out
}

type tbButton struct {
	id          int
	iBitmap     int // bitmap index in tbBitmapStore or ImageList
	text        string
	state       int
	style       int
	param       uint64
	stringValue uint64
}

type tooltipState struct {
	tools     []tooltipTool
	active    bool
	maxWidth  int32
	bgColor   uint32
	textColor uint32
}

type tooltipTool struct {
	id    uint64
	text  string
	hwnd  uint64
	rect  [4]int32
	flags uint32
}

type headerState struct {
	items      []headerItem
	imageList  uint64
	focusedIdx int32
}

type headerItem struct {
	text   string
	width  int32
	fmt    int32
	param  uint64
	image  int32
	order  int32
	state  uint32
	bitmap uint64
}

func initBuiltinControlState(cs *controlState) {
	if cs == nil {
		return
	}
	cs.className = strings.ToLower(cs.className)
	switch cs.className {
	case "listbox":
		if cs.listItems == nil && cs.listCurSel == 0 {
			cs.listCurSel = -1
		}
	case "combobox", "comboboxex32":
		if cs.comboItems == nil && cs.comboCurSel == 0 {
			cs.comboCurSel = -1
		}
	case "msctls_trackbar32":
		if cs.trackMax == 0 {
			cs.trackMax = 100
		}
	case "msctls_statusbar32":
		if cs.statusBar == nil {
			cs.statusBar = &statusBarState{}
		}
	case "syslistview32":
		if cs.listView == nil {
			cs.listView = &listViewState{style: cs.style, selectedIdx: -1}
		}
	case "systreeview32":
		if cs.treeView == nil {
			cs.treeView = &treeViewState{
				root:  &tvItem{expanded: true},
				nextH: 0x10001,
				style: cs.style,
			}
		}
		if cs.treeViewIndex == nil {
			cs.treeViewIndex = map[uint64]*tvItem{}
		}
	case "systabcontrol32":
		if cs.tab == nil {
			cs.tab = &tabState{curSel: -1}
		}
	case "msctls_progress32":
		if cs.progress == nil {
			cs.progress = &progressState{min: 0, max: 100, step: 10, barColor: 0x0078D7, bkColor: 0xE6E6E6, state: 1}
		}
	case "toolbarwindow32":
		if cs.toolbar == nil {
			cs.toolbar = &toolbarState{}
		}
	case "tooltips_class32":
		if cs.tooltip == nil {
			cs.tooltip = &tooltipState{active: true, maxWidth: -1, bgColor: 0xFFFFE1, textColor: 0x000000}
		}
	case "sysheader32":
		if cs.header == nil {
			cs.header = &headerState{focusedIdx: -1}
		}
	}
}

func treeViewVisibleItems(tv *treeViewState) []*tvItem {
	if tv == nil || tv.root == nil {
		return nil
	}
	var out []*tvItem
	var walk func(items []*tvItem)
	walk = func(items []*tvItem) {
		for _, item := range items {
			if item == nil {
				continue
			}
			out = append(out, item)
			if item.expanded {
				walk(item.children)
			}
		}
	}
	walk(tv.root.children)
	return out
}

func treeViewNextSibling(item *tvItem) *tvItem {
	if item == nil || item.parent == nil {
		return nil
	}
	siblings := item.parent.children
	for i, sibling := range siblings {
		if sibling == item && i+1 < len(siblings) {
			return siblings[i+1]
		}
	}
	return nil
}

func treeViewRemoveItem(cs *controlState, item *tvItem) {
	if cs == nil || item == nil || cs.treeView == nil || cs.treeView.root == nil {
		return
	}
	for _, child := range item.children {
		treeViewRemoveItem(cs, child)
	}
	delete(cs.treeViewIndex, item.handle)
	if item.parent != nil {
		children := item.parent.children
		for i, child := range children {
			if child == item {
				item.parent.children = append(children[:i], children[i+1:]...)
				break
			}
		}
	}
	if cs.treeView.selected == item {
		cs.treeView.selected = nil
	}
}

func syncStatusBarCompat(cs *controlState) {
	if cs == nil || cs.statusBar == nil {
		return
	}
	cs.sbParts = make([]int32, len(cs.statusBar.parts))
	copyTexts := make([]string, len(cs.statusBar.texts))
	copy(copyTexts, cs.statusBar.texts)
	cs.sbTexts = copyTexts
	for i, part := range cs.statusBar.parts {
		cs.sbParts[i] = int32(part)
	}
}

func syncTabCompat(cs *controlState) {
	if cs == nil || cs.tab == nil {
		return
	}
	cs.tabCount = len(cs.tab.items)
	cs.tabCurSel = cs.tab.curSel
	cs.tabTitles = make([]string, len(cs.tab.items))
	for i, item := range cs.tab.items {
		cs.tabTitles[i] = item.text
	}
}

func syncListViewCompat(cs *controlState) {
	if cs == nil || cs.listView == nil {
		return
	}
	cs.lvColumns = make([]listColumn, len(cs.listView.columns))
	for i, col := range cs.listView.columns {
		cs.lvColumns[i] = listColumn{text: col.text, width: int32(col.width)}
	}
}

func syncTreeViewCompat(cs *controlState) {
	if cs == nil || cs.treeView == nil || cs.treeView.root == nil {
		return
	}
	cs.tvItems = map[uint64]*treeItem{}
	cs.tvRoots = nil
	cs.tvNextHandle = cs.treeView.nextH
	var walk func(item *tvItem)
	walk = func(item *tvItem) {
		if item == nil {
			return
		}
		ti := &treeItem{
			handle:   item.handle,
			text:     item.text,
			expanded: item.expanded,
			lParam:   item.param,
		}
		if item.parent != nil {
			ti.parent = item.parent.handle
		}
		cs.tvItems[item.handle] = ti
		if item.parent == cs.treeView.root {
			cs.tvRoots = append(cs.tvRoots, item.handle)
		}
		for _, child := range item.children {
			ti.children = append(ti.children, child.handle)
			walk(child)
		}
	}
	for _, child := range cs.treeView.root.children {
		walk(child)
	}
}

func syncToolbarCompat(cs *controlState) {
	if cs == nil || cs.toolbar == nil {
		return
	}
	cs.tbButtons = make([]tbButtonData, len(cs.toolbar.buttons))
	for i, btn := range cs.toolbar.buttons {
		cs.tbButtons[i] = tbButtonData{
			iBitmap:   int32(btn.iBitmap),
			idCommand: int32(btn.id),
			fsState:   uint8(btn.state),
			fsStyle:   uint8(btn.style),
		}
	}
}

func syncProgressBarCompat(cs *controlState) {
	if cs == nil || cs.progress == nil {
		return
	}
	cs.progressBarCompat = &progressBarCompat{
		hwnd:      cs.ctrlID,
		className: cs.className,
		min:       int32(cs.progress.min),
		max:       int32(cs.progress.max),
		pos:       int32(cs.progress.pos),
		step:      int32(cs.progress.step),
		marquee:   cs.progress.marquee,
	}
}
