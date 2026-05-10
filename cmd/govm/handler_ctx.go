//go:build guest_windows

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/audio"
	"github.com/mirkobrombin/Raven/pkg/d3d11"
	"github.com/mirkobrombin/Raven/pkg/d3d9"
	dsound "github.com/mirkobrombin/Raven/pkg/dsound"
	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/loader"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

// ─── Package-level crash recovery state ─────────────────────────────────────

// MsgLoopSP/PC are set in GetMessageW; used by __fastfail recovery in runPE.
var msgLoopSP, msgLoopPC uint64

// modalPumpTrampolineID is the vmcall ID for the modal dialog message pump.
// Used when an app calls DialogBoxParam before GetMessageA/W (e.g. installers).
const modalPumpTrampolineID uint32 = 0x3FFD

// ─── Types formerly local to registerAutoSynthHandlers ──────────────────────

type menuItem struct {
	flags           uint32
	id              uint64
	text            string
	submenu         []menuItem
	submenuHandle   uint64
	submenuData     *menuData
	checkedBitmap   uint64
	uncheckedBitmap uint64
	itemData        uint64
	bitmap          uint64
}

func (item *menuItem) submenuItems() []menuItem {
	if item != nil && item.submenuData != nil {
		return item.submenuData.items
	}
	if item == nil {
		return nil
	}
	return item.submenu
}

func (item *menuItem) bindSubmenu(handle uint64, submenu *menuData) {
	item.submenuHandle = handle
	item.submenuData = submenu
	item.submenu = nil
	if handle != 0 {
		item.flags |= 0x0010
	} else {
		item.flags &^= 0x0010
	}
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
	Selected   int
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
	w, h       int
	slots      [][]uint32
	pix        []uint32
	monochrome bool
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
	showCalled        bool
	listItems         []string
	listItemData      []uint64
	listCurSel        int
	listItemHeight    int32
	listItemHeights   []int32
	listColumnWidth   int32
	comboItems        []string
	comboItemData     []uint64
	comboCurSel       int
	comboDropped      bool
	comboTopIndex     int
	comboPressedIndex int
	comboPopupAbove   bool
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
	trackMin          int32
	trackMax          int32
	trackPos          int32
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
	tbImageList       uint64            // HIMAGELIST from TB_SETIMAGELIST
}

type queuedMsg struct {
	cpu       arch.CPU
	hwnd      uint64
	message   uint32
	wParam    uint64
	lParam    uint64
	time      uint32
	x, y      int32
	extraInfo uint64
}

func newQueuedMsg(hctx *HandlerCtx, hwnd uint64, message uint32, wParam, lParam uint64) queuedMsg {
	messageTime := uint32(0)
	if hctx != nil && !hctx.BootTime.IsZero() {
		messageTime = uint32(time.Since(hctx.BootTime).Milliseconds())
	}
	msg := queuedMsg{hwnd: hwnd, message: message, wParam: wParam, lParam: lParam, time: messageTime}
	if hctx != nil {
		msg.x = hctx.CursorPosX
		msg.y = hctx.CursorPosY
	}
	if traceEnqueue {
		if _, file, line, ok := runtime.Caller(1); ok {
			ravelog.Logf("[msg-trace] enqueue hwnd=0x%x msg=0x%x wp=0x%x lp=0x%x from %s:%d\n",
				hwnd, message, wParam, lParam, filepath.Base(file), line)
		}
	}
	return msg
}

var traceEnqueue = os.Getenv("RAVEN_TRACE_MSG") != ""

type win32Timer struct {
	id         uint64
	hwnd       uint64
	intervalMs uint64
	proc       uint64
	deadline   time.Time
	cpu        arch.CPU
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
	// IsModalDialog redirects the callback return to the modal message loop.
	// Once EndDialog marks the dialog complete, the callback return finishes
	// the original DialogBox call.
	IsModalDialog bool
	ModalDlgHwnd  uint64
	ModalLoopSP   uint64
	ModalLoopPC   uint64
	// savedCalleeRegs holds the caller's callee-saved registers (EBX, EBP,
	// ESI, EDI) captured when this frame was pushed, so a synchronously
	// INJECTED WndProc dispatch (e.g. WM_NCCREATE/WM_CREATE/activation from
	// CreateWindowEx) is transparent to the caller's register state even if
	// the guest WndProc does not perfectly preserve them. Restored when the
	// frame pops. hasSavedCalleeRegs gates the restore.
	savedCalleeRegs    [4]uint64
	hasSavedCalleeRegs bool
}

type modalDlgEntry struct {
	hwnd           uint64
	retAddr        uint64
	retRSP         uint64
	pumpSP         uint64
	callee         guestNonvolatileRegisters
	syncDepth      int
	parent         uint64
	previousFocus  uint64
	previousActive uint64
	ended          bool
	result         uint64
}

type modalOwnerState struct {
	count       int
	wasDisabled bool
}

type modalOwnerRegistry struct {
	mu     sync.Mutex
	owners map[uint64]modalOwnerState
}

func (r *modalOwnerRegistry) acquire(hwnd uint64, isDisabled func() bool, disable func()) {
	if hwnd == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners == nil {
		r.owners = make(map[uint64]modalOwnerState)
	}
	state := r.owners[hwnd]
	if state.count == 0 {
		state.wasDisabled = isDisabled()
		if !state.wasDisabled {
			disable()
		}
	}
	state.count++
	r.owners[hwnd] = state
}

func (r *modalOwnerRegistry) release(hwnd uint64, enable func()) {
	if hwnd == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	state, ok := r.owners[hwnd]
	if !ok {
		return
	}
	state.count--
	if state.count > 0 {
		r.owners[hwnd] = state
		return
	}
	delete(r.owners, hwnd)
	if !state.wasDisabled {
		enable()
	}
}

type modalDialogRegistry struct {
	mu     sync.Mutex
	stacks map[arch.CPU][]modalDlgEntry
}

func (r *modalDialogRegistry) push(cpu arch.CPU, entry modalDlgEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stacks == nil {
		r.stacks = make(map[arch.CPU][]modalDlgEntry)
	}
	r.stacks[cpu] = append(r.stacks[cpu], entry)
}

func (r *modalDialogRegistry) top(cpu arch.CPU) (modalDlgEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stack := r.stacks[cpu]
	if len(stack) == 0 {
		return modalDlgEntry{}, false
	}
	return stack[len(stack)-1], true
}

func (r *modalDialogRegistry) markEnded(cpu arch.CPU, hwnd, result uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	stack := r.stacks[cpu]
	if !markModalDialogEnded(stack, hwnd, result) {
		return false
	}
	r.stacks[cpu] = stack
	return true
}

func (r *modalDialogRegistry) takeEnded(cpu arch.CPU, hwnd uint64) (modalDlgEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stack := r.stacks[cpu]
	for i := len(stack) - 1; i >= 0; i-- {
		entry := stack[i]
		if entry.hwnd != hwnd || !entry.ended {
			continue
		}
		stack = stack[:i]
		if len(stack) == 0 {
			delete(r.stacks, cpu)
		} else {
			r.stacks[cpu] = stack
		}
		return entry, true
	}
	return modalDlgEntry{}, false
}

func markModalDialogEnded(entries []modalDlgEntry, hwnd, result uint64) bool {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].hwnd == hwnd {
			entries[i].ended = true
			entries[i].result = result
			return true
		}
	}
	return false
}

func modalDialogLoopTarget(dialogRSP, pumpPC, fallbackSP, fallbackPC uint64) (uint64, uint64) {
	if dialogRSP != 0 && pumpPC != 0 {
		return dialogRSP, pumpPC
	}
	return fallbackSP, fallbackPC
}

func modalPumpEntrySP(callSP uint64, is32 bool) uint64 {
	if is32 {
		return callSP
	}
	const trampolineStackAdjustment = uint64(0x28)
	if callSP < trampolineStackAdjustment {
		return 0
	}
	return callSP - trampolineStackAdjustment
}

func modalMessageWndProc(dialogHWND, dialogProc, messageHWND uint64, wndProcs map[uint64]uint64) uint64 {
	if messageHWND == dialogHWND {
		return dialogProc
	}
	return wndProcs[messageHWND]
}

func isModalInputMessage(message uint32) bool {
	return message >= 0x0100 && message <= 0x0109 ||
		message >= 0x0200 && message <= 0x020E ||
		message >= 0x00A0 && message <= 0x00AD
}

func disabledWindowInHierarchy(
	hwnd, root uint64,
	isDisabled func(uint64) bool,
	parent func(uint64) (uint64, bool),
) bool {
	for depth := 0; hwnd != 0 && depth < 64; depth++ {
		if isDisabled(hwnd) {
			return true
		}
		if hwnd == root {
			break
		}
		next, ok := parent(hwnd)
		if !ok {
			break
		}
		hwnd = next
	}
	return false
}

type guestNonvolatileRegisters struct {
	values [8]uint64
	count  int
}

func captureGuestNonvolatileRegisters(reader ntapi.RegisterReader, is32 bool) guestNonvolatileRegisters {
	registers := [...]int{3, 5, 6, 7, 12, 13, 14, 15}
	count := len(registers)
	if is32 {
		count = 4
	}
	state := guestNonvolatileRegisters{count: count}
	for index := 0; index < count; index++ {
		state.values[index] = reader.ReadReg(registers[index])
	}
	return state
}

func restoreGuestNonvolatileRegisters(writer ntapi.RegisterWriter, state guestNonvolatileRegisters) {
	registers := [...]int{3, 5, 6, 7, 12, 13, 14, 15}
	for index := 0; index < state.count; index++ {
		writer.WriteReg(registers[index], state.values[index])
	}
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

// FindDialogState holds state for the built-in modeless Find/Replace dialog.
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
	X, Y, W, H                                             int32
	FindEditX, FindEditY, FindEditW, FindEditH             int32
	ReplEditX, ReplEditY, ReplEditW, ReplEditH             int32
	FindNextBtnX, FindNextBtnY, FindNextBtnW, FindNextBtnH int32
	ReplaceBtnX, ReplaceBtnY, ReplaceBtnW, ReplaceBtnH     int32
	ReplAllBtnX, ReplAllBtnY, ReplAllBtnW, ReplAllBtnH     int32
	CancelBtnX, CancelBtnY, CancelBtnW, CancelBtnH         int32
}

type PrintDialogState struct {
	DlgHWND, OwnerHWND uint64
	OutputPath         string
	AllPages           bool
	FromPage, ToPage   uint16
	MinPage, MaxPage   uint16
	AllowPageRange     bool
	Copies             uint16
	Result             int
	PrintBtnX          int32
	PrintBtnY          int32
	PrintBtnW          int32
	PrintBtnH          int32
	CancelBtnX         int32
	CancelBtnY         int32
	CancelBtnW         int32
	CancelBtnH         int32
	AllPagesX          int32
	AllPagesY          int32
	PagesX             int32
	PagesY             int32
	FromMinusX         int32
	FromPlusX          int32
	ToMinusX           int32
	ToPlusX            int32
	RangeButtonsY      int32
	CopiesMinusX       int32
	CopiesPlusX        int32
	CopiesY            int32
}

// ─── HandlerCtx bridges closure-captured state to extracted DLL files ───────

type HandlerCtx struct {
	// Core references
	Mem                   *mmu.MMU
	Disp                  *ntapi.Dispatcher
	Handles               *ntapi.HandleTable
	ProcState             *ntapi.ProcessState
	ExTable               *ntapi.ExceptionTable
	MainModule            *loader.PEModule
	TMPtr                 **thread.Manager
	RegHive               *ntapi.RegistryHive
	SynthByName           map[string]*ntapi.SynthPE
	Com                   *comState
	CurrentCPU            arch.CPU
	CurrentCPUMu          sync.RWMutex
	WindowCPUMu           sync.RWMutex
	WindowCPU             map[uint64]arch.CPU
	DialogRendering       atomic.Bool
	D3D9Device            *d3d9.Device
	D3D9Renderer          *d3d9.Renderer
	D3D11Device           *d3d11.Device
	D3D11ImmediateContext *d3d11.DeviceContext
	DirectSound           *dsound.DirectSound
	AudioOutput           audio.Output

	// Config
	Argv              []string
	CmdLine           string
	ImagePath         string
	HostImagePath     string
	StartTime         time.Time
	BootTime          time.Time
	StdinReader       *bufio.Reader
	Dlls              []*ntapi.SynthPE
	KeepHeadlessAlive bool
	StartChildProcess func(string, string) (*os.Process, error)

	// Wayland / GUI (pointers, safe to copy)
	WlDisplay             *wl.Display
	WlWindow              *wl.Window
	WlWindows             map[uint64]*wl.Window
	WlWindowHWND          map[*wl.Window]uint64
	OnWlWindowSet         func(*wl.Window) // callback to sync local wlWindow in main.go closures
	RenderSnapshot        func()
	RenderDialogCustom    func(root uint64, target *wl.Window)
	ReleaseDialogPaintDC  func(hwnd uint64)
	RenderingDialogCustom bool
	CallBuiltinControl    bool
	GdiMgr                *gdi.Manager

	// Maps (reference types, safe to copy)
	EnvVars              map[string]string
	LocalAtomTable       map[string]uint16
	LocalAtomNames       map[uint16]string
	GlobalAtomTable      map[string]uint16
	GlobalAtomNames      map[uint16]string
	NamedMappings        map[string]*ntapi.FileMappingHandle
	LocalAllocSizes      map[uint64]uint64
	LocalAllocMu         sync.Mutex
	GlobalAllocSizes     map[uint64]uint64
	GlobalAllocMu        sync.Mutex
	IniCache             map[string]map[string]map[string]string
	Menus                map[uint64]*menuData
	HwndMenuBar          map[uint64]uint64
	BitmapHandles        map[uint64]*bitmapHandleData
	HwndChildren         map[uint64]*controlState
	HwndOrder            []uint64
	HwndZOrder           []uint64
	HwndTitle            map[uint64]string
	HwndExplicitlyHidden map[uint64]bool
	HwndWndProc          map[uint64]uint64
	AtomWndProc          map[uint16]uint64
	ClassNameAtom        map[string]uint16
	ClassMenuHandle      map[uint16]uint64
	ClassBrush           map[uint16]uint32
	ClassInfo            map[uint16]*registeredClassInfo
	HwndClassAtom        map[uint64]uint16
	WindowLongPtr        map[uint64]map[int32]uint64
	WindowProps          map[uint64]map[string]uint64
	WinErasePending      map[uint64]bool
	RebarBandCounts      map[uint64]int
	HostSavePaths        map[string]string
	HostSaveMu           sync.Mutex
	SynthMu              sync.RWMutex
	NextDelayMu          sync.Mutex
	ToolbarFallbackMu    sync.RWMutex
	ToolbarFallbackIcons map[toolbarFallbackKey]*toolbarFallbackCache

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
	CursorPosX        int32
	CursorPosY        int32
	MessageMetadata   messageMetadataStore
	ActiveHwnd        uint64
	OpenMenuIdx       int
	OpenMenuHwnd      uint64
	ActivePopupMenu   *popupMenuState
	// MenuBehind is a save-behind snapshot of the window content captured when a
	// popup menu first opens, so DrawMenuOverlay can restore it before each redraw
	// (preventing overlap while navigating menu-bar items) and closePopupMenus can
	// restore it on dismissal (preventing leftover menu fragments).
	MenuBehind []byte
	// NotifyBuf holds separate stable NMHDR slots for tab selection notifications.
	// ScratchAlloc cannot be used because a queued notification may outlive its
	// current ring allocation.
	NotifyBuf uint64

	// Modal dialog overlay state
	DialogActive bool
	DialogTitle  string
	DialogText   string
	DialogText2  string // secondary line (e.g. version info)
	DialogHwnd   uint64 // owner window
	DialogBtnX   int32  // OK button bounds (set by DrawDialogOverlay)
	DialogBtnY   int32
	DialogBtnW   int32
	DialogBtnH   int32

	// Modeless Find/Replace dialog state (FindTextW/ReplaceTextW)
	FindDialog         *FindDialogState
	PrintDialog        *PrintDialogState
	PrintDialogMu      sync.Mutex
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
	ModalPumpTrampoline uint64 // address of the modal message pump trampoline stub
	SyncCallWndProc     func(ctx *ntapi.TrapContext, wndProc, hwnd uint64, msg uint32, wParam, lParam, retAddr uint64)
	FinishModalDialog   func(ctx *ntapi.TrapContext, hwnd uint64) bool
	SyncStacks          sync.Map
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
	MsgQueue               messageQueue
	Timers                 timerStore
	WinInvalid             map[uint64]bool
	SyncStack              []syncDispatchFrame
	DelayHandlerRegistrars []func()
	SysColors              [31]uint32

	// Func fields - shared dialog handlers set by registerComdlg32Handlers
	HandleFileDialogW func(*ntapi.TrapContext, bool)
	HandleFileDialogA func(*ntapi.TrapContext, bool)

	// Func fields - closures from setup section
	ReadGuestUTF16       func(uint64) string
	ReadGuestUTF16N      func(uint64, int) string
	ReadGuestString      func(uint64) string
	HeapAlloc            func(uint64, bool) uint64
	HeapFree             func(uint64)
	Wideprintf           func(string, []uint64) string
	Ansiprintf           func(string, []uint64) string
	CrtStreamWriter      func(uint64, uint64, uint64) *os.File
	AddAtomLocal         func(string) uint16
	AddAtomGlobal        func(string) uint16
	IniRead              func(string) map[string]map[string]string
	IniWrite             func(string, string, string, string)
	DoCreateFileMapping  func(*ntapi.TrapContext, ntapi.Handle, uint32, uint32, uint32, string) uint64
	DoMapView            func(*ntapi.TrapContext, ntapi.Handle, uint32, uint32, uint32, uint64) uint64
	DoUnmapView          func(*ntapi.TrapContext, uint64) bool
	PickBestLangEntry    func(uint64, uint64) (uint64, bool)
	PeLoadStringW        func(uint32) (string, uint64, int)
	PeLoadMenuResource   func(uint32) *menuData
	PeLoadRawResource    func(uint64, uint32, uint32, uint32) (uint64, uint32, bool)
	DecodeDIBSlots       func(uint64, uint32, int, int) [][]uint32
	GetSysColor          func(uint32) uint32
	SyncScreenSurface    func()
	AllocScreenDC        func(int32, int32) (uint64, *gdi.DC)
	GetDCFn              func(uint64) *gdi.DC
	ReadDIBInfo          func(uint64) (int32, int32, int32, uint32, []uint32, uint64)
	ReadDIBPixels        func(uint64, int32, int32, int32) []byte
	RegKeyPath           func(uint64, string) string
	RegQueryValue        func(*ntapi.TrapContext, uint64, string) uint32
	RegIsProbeKey        func(string) bool
	GdiAlloc             func() uint64
	HwndAlloc            func() uint64
	MenuStripAmpersand   func(string) string
	ClientAreaOrigin     func(uint64) (int32, int32)
	QueuePaint           func(uint64)
	PaintTree            func(uint64)
	BuiltinWndProc       func(uint64, uint32, uint64, uint64) (uint64, bool)
	ScratchAlloc         func(uint64) uint64
	NcTextFont           func(int32) *gdi.Font
	NcDrawText           func(int32, int32, string, uint32, uint32, bool, int32)
	NcDrawTextClipped    func(x, y, cx0, cy0, cx1, cy1 int32, text string, fg, bg uint32, opaque bool, size int32)
	MeasureNcText        func(string, int32) int32 // measure text width in NC font
	DrawMenuOverlay      func()
	DrawDialogOverlay    func()
	CommitIfDone         func()
	RequestWindowRepaint func(uint64)
	DestroyOwnedDialog   func(uint64)
	PumpWaylandOnce      func() bool

	CrtFiles  map[uint64]*os.File // guest FILE* → Go *os.File
	CrtNextFP uint64              // next guest FILE* address to allocate

	// VfsModuleResRVA maps each loaded PE base address to its resource directory RVA.
	// LoadLibrary extends it for modules extracted at runtime.
	// Used by loadDlgTemplate to locate dialog resources in the correct module.
	VfsModuleResRVA map[uint64]uint32
	VfsModuleResMu  sync.RWMutex
	PrintJobs       map[uint64]*printJobState
	PrintJobsMu     sync.Mutex
}

func (h *HandlerCtx) syncStack(ctx *ntapi.TrapContext) *[]syncDispatchFrame {
	if ctx == nil || ctx.CPU == nil {
		return &h.SyncStack
	}
	stack := new([]syncDispatchFrame)
	actual, _ := h.SyncStacks.LoadOrStore(ctx.CPU, stack)
	return actual.(*[]syncDispatchFrame)
}

func (h *HandlerCtx) setWindowCPU(hwnd uint64, cpu arch.CPU) {
	if hwnd == 0 || cpu == nil {
		return
	}
	h.WindowCPUMu.Lock()
	if h.WindowCPU == nil {
		h.WindowCPU = make(map[uint64]arch.CPU)
	}
	h.WindowCPU[hwnd] = cpu
	h.WindowCPUMu.Unlock()
}

func (h *HandlerCtx) windowCPU(hwnd uint64) arch.CPU {
	h.WindowCPUMu.RLock()
	cpu := h.WindowCPU[hwnd]
	h.WindowCPUMu.RUnlock()
	return cpu
}

func (h *HandlerCtx) clearWindowCPU(hwnd uint64) {
	h.WindowCPUMu.Lock()
	delete(h.WindowCPU, hwnd)
	h.WindowCPUMu.Unlock()
}

func (h *HandlerCtx) clearWindowsForCPU(cpu arch.CPU) {
	h.WindowCPUMu.Lock()
	for hwnd, owner := range h.WindowCPU {
		if owner == cpu {
			delete(h.WindowCPU, hwnd)
		}
	}
	h.WindowCPUMu.Unlock()
}

func (hctx *HandlerCtx) allocGlobal(size uint64) uint64 {
	if size == 0 {
		size = 1
	}
	addr := hctx.Mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	hctx.GlobalAllocMu.Lock()
	if hctx.GlobalAllocSizes == nil {
		hctx.GlobalAllocSizes = make(map[uint64]uint64)
	}
	hctx.GlobalAllocSizes[addr] = size
	hctx.GlobalAllocMu.Unlock()
	return addr
}

func (hctx *HandlerCtx) globalAllocSize(addr uint64) (uint64, bool) {
	hctx.GlobalAllocMu.Lock()
	defer hctx.GlobalAllocMu.Unlock()
	size, ok := hctx.GlobalAllocSizes[addr]
	return size, ok
}

func (hctx *HandlerCtx) releaseGlobal(addr uint64) (uint64, bool) {
	hctx.GlobalAllocMu.Lock()
	defer hctx.GlobalAllocMu.Unlock()
	size, ok := hctx.GlobalAllocSizes[addr]
	if ok {
		delete(hctx.GlobalAllocSizes, addr)
	}
	return size, ok
}

func (h *HandlerCtx) setModuleResourceRVA(base uint64, resourceRVA uint32) {
	if base == 0 || resourceRVA == 0 {
		return
	}
	h.VfsModuleResMu.Lock()
	if h.VfsModuleResRVA == nil {
		h.VfsModuleResRVA = make(map[uint64]uint32)
	}
	h.VfsModuleResRVA[base] = resourceRVA
	h.VfsModuleResMu.Unlock()
}

func (h *HandlerCtx) moduleResourceRVA(base uint64) uint32 {
	h.VfsModuleResMu.RLock()
	resourceRVA := h.VfsModuleResRVA[base]
	h.VfsModuleResMu.RUnlock()
	return resourceRVA
}

func (h *HandlerCtx) trackLocalAlloc(addr, size uint64) {
	if addr == 0 {
		return
	}
	h.LocalAllocMu.Lock()
	if h.LocalAllocSizes == nil {
		h.LocalAllocSizes = make(map[uint64]uint64)
	}
	h.LocalAllocSizes[addr] = size
	h.LocalAllocMu.Unlock()
}

func (h *HandlerCtx) localAllocSize(addr uint64) (uint64, bool) {
	h.LocalAllocMu.Lock()
	defer h.LocalAllocMu.Unlock()
	size, ok := h.LocalAllocSizes[addr]
	return size, ok
}

func (h *HandlerCtx) takeLocalAlloc(addr uint64) (uint64, bool) {
	h.LocalAllocMu.Lock()
	defer h.LocalAllocMu.Unlock()
	size, ok := h.LocalAllocSizes[addr]
	if ok {
		delete(h.LocalAllocSizes, addr)
	}
	return size, ok
}

func (h *HandlerCtx) SetCurrentCPU(cpu arch.CPU) {
	h.CurrentCPUMu.Lock()
	h.CurrentCPU = cpu
	h.CurrentCPUMu.Unlock()
}

func (h *HandlerCtx) GetCurrentCPU() arch.CPU {
	h.CurrentCPUMu.RLock()
	cpu := h.CurrentCPU
	h.CurrentCPUMu.RUnlock()
	return cpu
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
		Selected:   -1,
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
		if len(item.submenuItems()) > 0 || item.flags&0x0010 != 0 {
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

func popupMenuNextSelectable(items []menuItem, start, step int) int {
	if len(items) == 0 || step == 0 {
		return -1
	}
	idx := start
	for range items {
		idx = (idx + step + len(items)) % len(items)
		if items[idx].flags&0x0803 == 0 {
			return idx
		}
	}
	return -1
}

func registerAutoOrDynamicHandler(hctx *HandlerCtx, dll *ntapi.SynthPE, name string, handler ntapi.TrapHandler) {
	if hctx == nil || hctx.Disp == nil || dll == nil || handler == nil {
		return
	}
	hctx.NextDelayMu.Lock()
	defer hctx.NextDelayMu.Unlock()
	hctx.Disp.RegisterAutoStubHandler(dll, name, handler)
	if hctx.Disp.LookupSynthExport(dll, name, 0) != 0 {
		return
	}
	_, nextID, added := hctx.Disp.EnsureDynamicExport(hctx.Mem, dll, name, hctx.NextDelayID)
	hctx.NextDelayID = nextID
	if added {
		hctx.Disp.PostRegisterSynthDLL(dll)
	}
}
