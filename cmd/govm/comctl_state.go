package main

import "strings"

type listViewState struct {
	items       []lvItem
	columns     []lvColumn
	style       uint32
	extStyle    uint32
	selectedIdx int
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

type tabItem struct {
	text  string
	param uint64
}

type progressState struct {
	pos, min, max, step int
}

type toolbarState struct {
	buttons []tbButton
}

type tbButton struct {
	id    int
	text  string
	state int
	style int
	param uint64
}

type tooltipState struct {
	tools []tooltipTool
}

type tooltipTool struct {
	id   uint64
	text string
	hwnd uint64
}

func initBuiltinControlState(cs *controlState) {
	if cs == nil {
		return
	}
	cs.className = strings.ToLower(cs.className)
	switch cs.className {
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
			cs.progress = &progressState{min: 0, max: 100, step: 10}
		}
	case "toolbarwindow32":
		if cs.toolbar == nil {
			cs.toolbar = &toolbarState{}
		}
	case "tooltips_class32":
		if cs.tooltip == nil {
			cs.tooltip = &tooltipState{}
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
			idCommand: int32(btn.id),
			fsState:   uint8(btn.state),
			fsStyle:   uint8(btn.style),
		}
	}
}
