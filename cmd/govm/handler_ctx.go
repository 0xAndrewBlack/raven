package main

import (
	"bufio"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/mirkobrombin/Raven/pkg/arch"
	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/loader"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

// ─── Package-level crash recovery state ─────────────────────────────────────

// MsgLoopSP/PC are set in GetMessageW; used by __fastfail recovery in runPE.
var msgLoopSP, msgLoopPC uint64

// ─── Types formerly local to registerAutoSynthHandlers ──────────────────────

type menuItem struct {
	flags   uint32
	id      uint64
	text    string
	submenu []menuItem
}

type menuData struct {
	items []menuItem
}

type popupMenuState struct {
	Menu       uint64
	OwnerHWND  uint64
	X, Y       int32
	Width      int32
	Height     int32
	ItemHeight int32
	Items      []menuItem
}

type viewMapping struct {
	GuestAddr uint64
	HostBuf   []byte
	Size      uint64
	FileFD    int
	Offset    uint64
	Writable  bool
	FM        *ntapi.FileMappingHandle
}

type bitmapHandleData struct {
	w, h  int
	slots [][]uint32
	pix   []uint32
}

// tbLazyRef tracks a not-yet-loaded toolbar bitmap slot.
// When TB_ADDBITMAP is called before LoadImage creates the HBITMAP, we store
// the expected handle and the slot offset within that bitmap strip.
type tbLazyRef struct {
	handle    uint64
	slotIndex int
}

type treeItem struct {
	handle   uint64
	parent   uint64
	text     string
	children []uint64
	expanded bool
	lParam   uint64
}

type listColumn struct {
	text  string
	width int32
}

type tbButtonData struct {
	iBitmap   int32
	idCommand int32
	fsState   uint8
	fsStyle   uint8
}

type progressBarCompat struct {
	hwnd          uint64
	className     string
	min, max, pos int32
	step          int32
	marquee       bool
}

type controlState struct {
	className         string
	parentHWND        uint64
	ctrlID            uint64
	x, y, w, h        int32
	style             uint32
	exStyle           uint32
	text              string
	visible           bool
	listView          *listViewState
	treeView          *treeViewState
	treeViewIndex     map[uint64]*tvItem
	statusBar         *statusBarState
	statusSimple      bool
	statusMinH        int32
	tab               *tabState
	progress          *progressState
	progressMq        bool
	toolbar           *toolbarState
	tooltip           *tooltipState
	header            *headerState
	progressBarCompat *progressBarCompat
	sbParts           []int32
	sbTexts           []string
	editModified      bool
	tvItems           map[uint64]*treeItem
	tvNextHandle      uint64
	tvRoots           []uint64
	lvColumns         []listColumn
	checkState        uint32
	tabCount          int
	tabCurSel         int
	tabTitles         []string
	tbButtons         []tbButtonData
	tbBtnW            int32
	tbBtnH            int32
	tbBitmapIconW     int32
	tbBitmapIconH     int32
	tbBitmapStore     [][]uint32
	tbHandleMap       map[int]tbLazyRef // slot index → pending HBITMAP handle + slot offset (lazy resolution)
	tbImageList       uint64         // HIMAGELIST from TB_SETIMAGELIST
}

type queuedMsg struct {
	hwnd    uint64
	message uint32
	wParam  uint64
	lParam  uint64
}

type win32Timer struct {
	id         uint64
	hwnd       uint64
	intervalMs uint64
	proc       uint64
	deadline   time.Time
}

type syncDispatch struct {
	wndProc uint64
	hwnd    uint64
	msg     uint64
	wParam  uint64
	lParam  uint64
}

type syncDispatchFrame struct {
	queue               []syncDispatch
	retAddr             uint64
	hwnd                uint64
	returnWndProcResult bool
	// IsModalDialog: when true the trampoline redirects to the message loop
	// after the WM_INITDIALOG dispatch completes (instead of returning to the
	// DialogBoxParamW call site immediately).  The actual return is triggered
	// later by EndDialog via a stack-unwind (longjmp-style).
	IsModalDialog bool
	ModalDlgHwnd  uint64
}

type freeBlock struct {
	addr      uint64
	blockSize uint64
}

type registeredClassInfo struct {
	Style     uint32
	WndProc   uint64
	ClsExtra  int32
	WndExtra  int32
	HInstance uint64
	HIcon     uint64
	HCursor   uint64
	HbrBG     uint64
	MenuName  uint64
	ClassName string
	HIconSm   uint64
	Atom      uint16
}

// FindDialogState holds state for the built-in modeless Find/Replace dialog overlay.
// Created by FindTextW/ReplaceTextW, rendered by DrawDialogOverlay.
type FindDialogState struct {
	DlgHWND          uint64
	OwnerHWND        uint64
	PFR              uint64 // guest pointer to FINDREPLACEW
	LpstrFindWhat    uint64 // guest pointer to find-string buffer
	FindWhatLen      uint16
	LpstrReplaceWith uint64 // guest pointer to replace-string buffer (Replace only)
	ReplaceWithLen   uint16
	MsgID            uint32 // registered FINDMSGSTRING message ID
	IsReplace        bool
	// UI input state
	FindText       string
	ReplaceText    string
	FocusOnReplace bool // cursor in replace field vs find field
	CaseSensitive  bool
	WholeWord      bool
	SearchDown     bool
	// Rendering hit-test bounds (set each frame by DrawFindDialog)
	X, Y, W, H                     int32
	FindEditX, FindEditY, FindEditW, FindEditH         int32
	ReplEditX, ReplEditY, ReplEditW, ReplEditH         int32
	FindNextBtnX, FindNextBtnY, FindNextBtnW, FindNextBtnH int32
	ReplaceBtnX, ReplaceBtnY, ReplaceBtnW, ReplaceBtnH int32
	ReplAllBtnX, ReplAllBtnY, ReplAllBtnW, ReplAllBtnH int32
	CancelBtnX, CancelBtnY, CancelBtnW, CancelBtnH    int32
}

// ─── HandlerCtx bridges closure-captured state to extracted DLL files ───────

type HandlerCtx struct {
	// Core references
	Mem         *mmu.MMU
	Disp        *ntapi.Dispatcher
	Handles     *ntapi.HandleTable
	ProcState   *ntapi.ProcessState
	ExTable     *ntapi.ExceptionTable
	MainModule  *loader.PEModule
	TMPtr       **thread.Manager
	RegHive     *ntapi.RegistryHive
	SynthByName map[string]*ntapi.SynthPE
	Com         *comState
	CurrentCPU  arch.CPU

	// Config
	Argv        []string
	CmdLine     string
	ImagePath   string
	StartTime   time.Time
	BootTime    time.Time
	StdinReader *bufio.Reader
	Dlls        []*ntapi.SynthPE

	// Wayland / GUI (pointers, safe to copy)
	WlDisplay     *wl.Display
	WlWindow      *wl.Window
	OnWlWindowSet func(*wl.Window) // callback to sync local wlWindow in main.go closures
	GdiMgr        *gdi.Manager

	// Maps (reference types, safe to copy)
	EnvVars              map[string]string
	LocalAtomTable       map[string]uint16
	LocalAtomNames       map[uint16]string
	GlobalAtomTable      map[string]uint16
	GlobalAtomNames      map[uint16]string
	NamedMappings        map[string]*ntapi.FileMappingHandle
	IniCache             map[string]map[string]map[string]string
	Menus                map[uint64]*menuData
	HwndMenuBar          map[uint64]uint64
	BitmapHandles        map[uint64]*bitmapHandleData
	HwndChildren         map[uint64]*controlState
	HwndTitle            map[uint64]string
	HwndExplicitlyHidden map[uint64]bool
	HwndWndProc          map[uint64]uint64
	AtomWndProc          map[uint16]uint64
	ClassNameAtom        map[string]uint16
	ClassMenuHandle      map[uint16]uint64
	ClassBrush           map[uint16]uint32
	ClassInfo            map[uint16]*registeredClassInfo
	HwndClassAtom        map[uint64]uint16
	TimerMap             map[uint64]*win32Timer
	WindowLongPtr        map[uint64]map[int32]uint64
	WindowProps          map[uint64]map[string]uint64
	WinErasePending      map[uint64]bool
	RebarBandCounts      map[uint64]int

	// Mutable scalars (accessed directly as hctx.Field)
	MainHWND          uint64
	MainTitle         string
	MainActive        bool
	FrameCount        int
	NextLocalAtom     uint16
	NextGlobalAtom    uint16
	DelayLoadFallback uint64
	NextDelayID       uint32
	FocusHwnd         uint64
	MouseCapture      uint64
	ActiveHwnd        uint64
	OpenMenuIdx       int
	OpenMenuHwnd      uint64
	ActivePopupMenu   *popupMenuState

	// Modal dialog overlay state
	DialogActive        bool
	DialogTitle         string
	DialogText          string
	DialogText2         string // secondary line (e.g. version info)
	DialogHwnd          uint64 // owner window
	DialogBtnX          int32  // OK button bounds (set by DrawDialogOverlay)
	DialogBtnY          int32
	DialogBtnW          int32
	DialogBtnH          int32

	// Modeless Find/Replace dialog state (FindTextW/ReplaceTextW)
	FindDialog         *FindDialogState
	RegisteredMsgNames map[string]uint32 // RegisterWindowMessage name → ID

	NextHWND            uint64
	NextMsgID           uint32
	NextAtom            uint16
	NextGDIHandle       uint64
	NextBitmapHandle    uint64
	NextTimerID         uint64
	FrameReady          bool
	HasBaseFrame        bool
	RepaintBuiltin      bool
	ScratchOff          uint64
	ScratchPage         uint64
	SyncTrampoline      uint64
	GuestCallTrampoline *ntapi.DllMainTrampoline
	LastPostedMainW     int32
	LastPostedMainH     int32

	// Caret state
	CaretHwnd    uint64
	CaretWidth   int32
	CaretHeight  int32
	CaretX       int32
	CaretY       int32
	CaretVisible bool

	// Mouse tracking
	TrackMouseHwnds map[uint64]uint32

	// Mutable slices/arrays
	ViewMappings           []viewMapping
	MsgQueue               []queuedMsg
	WinInvalid             map[uint64]bool
	SyncStack              []syncDispatchFrame
	DelayHandlerRegistrars []func()
	SysColors              [31]uint32

	// Func fields - shared dialog handlers set by registerComdlg32Handlers
	HandleFileDialogW func(*ntapi.TrapContext, bool)
	HandleFileDialogA func(*ntapi.TrapContext, bool)

	// Func fields - closures from setup section
	ReadGuestUTF16      func(uint64) string
	ReadGuestUTF16N     func(uint64, int) string
	ReadGuestString     func(uint64) string
	HeapAlloc           func(uint64, bool) uint64
	HeapFree            func(uint64)
	Wideprintf          func(string, []uint64) string
	CrtStreamWriter     func(uint64, uint64, uint64) *os.File
	AddAtomLocal        func(string) uint16
	AddAtomGlobal       func(string) uint16
	IniRead             func(string) map[string]map[string]string
	IniWrite            func(string, string, string, string)
	DoCreateFileMapping func(*ntapi.TrapContext, ntapi.Handle, uint32, uint32, uint32, string) uint64
	DoMapView           func(*ntapi.TrapContext, ntapi.Handle, uint32, uint32, uint32, uint64) uint64
	DoUnmapView         func(*ntapi.TrapContext, uint64) bool
	PickBestLangEntry   func(uint64, uint64) (uint64, bool)
	PeLoadStringW       func(uint32) (string, uint64, int)
	PeLoadMenuResource  func(uint32) *menuData
	PeLoadRawResource   func(uint64, uint32, uint32, uint32) (uint64, uint32, bool)
	DecodeDIBSlots      func(uint64, uint32, int, int) [][]uint32
	GetSysColor         func(uint32) uint32
	SyncScreenSurface   func()
	AllocScreenDC       func(int32, int32) (uint64, *gdi.DC)
	GetDCFn             func(uint64) *gdi.DC
	ReadDIBInfo         func(uint64) (int32, int32, int32, uint32, []uint32, uint64)
	ReadDIBPixels       func(uint64, int32, int32, int32) []byte
	RegKeyPath          func(uint64, string) string
	RegQueryValue       func(*ntapi.TrapContext, uint64, string) uint32
	RegIsProbeKey       func(string) bool
	GdiAlloc            func() uint64
	HwndAlloc           func() uint64
	MenuStripAmpersand  func(string) string
	ClientAreaOrigin    func(uint64) (int32, int32)
	QueuePaint          func(uint64)
	PaintTree           func(uint64)
	BuiltinWndProc      func(uint64, uint32, uint64, uint64) (uint64, bool)
	ScratchAlloc        func(uint64) uint64
	NcTextFont          func(int32) *gdi.Font
	NcDrawText          func(int32, int32, string, uint32, uint32, bool, int32)
	NcDrawTextClipped   func(x, y, cx0, cy0, cx1, cy1 int32, text string, fg, bg uint32, opaque bool, size int32)
	MeasureNcText       func(string, int32) int32 // measure text width in NC font
	DrawMenuOverlay     func()
	DrawDialogOverlay   func()
	CommitIfDone        func()

	CrtFiles  map[uint64]*os.File // guest FILE* → Go *os.File
	CrtNextFP uint64              // next guest FILE* address to allocate
}

func (h *HandlerCtx) SetCurrentCPU(cpu arch.CPU) {
	h.CurrentCPU = cpu
}

const menuBarHeight int32 = 20

const popupMenuItemHeight int32 = 22

func menuHasRenderableText(s string) bool {
	for _, r := range s {
		if r > 32 && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func menuTextParts(s string) (label, accel string) {
	label = s
	if idx := strings.IndexByte(s, '\t'); idx >= 0 {
		label = s[:idx]
		accel = s[idx+1:]
	}
	return label, accel
}

// menuTextMeasure is set at runtime to use real TrueType glyph metrics.
// Falls back to len(rune)*7 if not set.
var menuTextMeasure func(string, int32) int32

func menuTextWidth(s string) int32 {
	if menuTextMeasure != nil {
		return menuTextMeasure(s, 12) // 12px = NC menu font
	}
	return int32(len([]rune(s)) * 7)
}

func menuPopupLayout(items []menuItem, x, y, boundW, boundH int32, stripAmp func(string) string) popupMenuState {
	layout := popupMenuState{
		X:          x,
		Y:          y,
		ItemHeight: popupMenuItemHeight,
		Items:      items,
	}
	width := int32(96)
	for _, item := range items {
		if item.flags&0x0800 != 0 {
			continue
		}
		label, accel := menuTextParts(item.text)
		if stripAmp != nil {
			label = stripAmp(label)
			accel = stripAmp(accel)
		}
		if !menuHasRenderableText(label) && !menuHasRenderableText(accel) {
			continue
		}
		itemW := int32(28) + menuTextWidth(label)
		if accel != "" {
			itemW += int32(24) + menuTextWidth(accel)
		} else {
			itemW += 20
		}
		if len(item.submenu) > 0 || item.flags&0x0010 != 0 {
			itemW += 12
		}
		if itemW > width {
			width = itemW
		}
	}
	if len(items) == 0 {
		layout.Width = width
		layout.Height = 0
		return layout
	}
	layout.Width = width
	layout.Height = int32(len(items)) * layout.ItemHeight
	if boundW > 0 && layout.X+layout.Width > boundW {
		layout.X = boundW - layout.Width
	}
	if boundH > 0 && layout.Y+layout.Height > boundH {
		layout.Y = boundH - layout.Height
	}
	if layout.X < 0 {
		layout.X = 0
	}
	if layout.Y < 0 {
		layout.Y = 0
	}
	return layout
}
