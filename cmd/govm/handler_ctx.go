package main

import (
	"bufio"
	"os"
	"time"

	gdi "github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/loader"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/wl"
)

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

type controlState struct {
	className     string
	parentHWND    uint64
	ctrlID        uint64
	x, y, w, h    int32
	style         uint32
	exStyle       uint32
	text          string
	visible       bool
	sbParts       []int32
	sbTexts       []string
	editModified  bool
	tvItems       map[uint64]*treeItem
	tvNextHandle  uint64
	tvRoots       []uint64
	lvColumns     []listColumn
	checkState    uint32
	tabCount      int
	tabCurSel     int
	tabTitles     []string
	tbButtons     []tbButtonData
	tbBtnW        int32
	tbBtnH        int32
	tbBitmapIconW int32
	tbBitmapIconH int32
	tbBitmapStore [][]uint32
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
}

type freeBlock struct {
	addr      uint64
	blockSize uint64
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

	// Config
	Argv        []string
	CmdLine     string
	ImagePath   string
	StartTime   time.Time
	BootTime    time.Time
	StdinReader *bufio.Reader
	Dlls        []*ntapi.SynthPE

	// Wayland / GUI (pointers, safe to copy)
	WlDisplay *wl.Display
	WlWindow  *wl.Window
	GdiMgr    *gdi.Manager

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
	HwndClassAtom        map[uint64]uint16
	TimerMap             map[uint64]*win32Timer
	WindowLongPtr        map[uint64]map[int32]uint64
	WindowProps          map[uint64]map[string]uint64
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
	NextHWND          uint64
	NextMsgID         uint32
	NextAtom          uint16
	NextGDIHandle     uint64
	NextBitmapHandle  uint64
	NextTimerID       uint64
	FrameReady        bool
	HasBaseFrame      bool
	RepaintBuiltin    bool
	ScratchOff        uint64
	ScratchPage       uint64
	SyncTrampoline    uint64
	LastPostedMainW   int32
	LastPostedMainH   int32

	// Mutable slices/arrays
	ViewMappings           []viewMapping
	MsgQueue               []queuedMsg
	WinInvalid             map[uint64]bool
	SyncStack              []syncDispatchFrame
	DelayHandlerRegistrars []func()
	SysColors              [31]uint32

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
	DrawMenuOverlay     func()
	CommitIfDone        func()
}

const menuBarHeight int32 = 20
