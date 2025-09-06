package win32k

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
	"github.com/mirkobrombin/go-vm/pkg/ntapi"
)

// Window represents a guest window mapped to a Wayland surface.
type Window struct {
	Handle   uint64
	ClassName string
	Title    string
	X, Y     int32
	Width    int32
	Height   int32
	Visible  bool
	Style    uint32
	ExStyle  uint32
	WndProc  uint64 // guest address of the window procedure
	HInst    uint64
	Parent   uint64
	Menu     uint64
	DC       *DeviceContext
	MsgQueue chan WinMessage
}

// DeviceContext represents a Win32 GDI device context.
type DeviceContext struct {
	Handle    uint64
	Window    *Window
	BitmapAddr uint64 // guest memory address of the pixel buffer
	Width     int32
	Height    int32
	BkColor   uint32
	TextColor uint32
	BkMode    int32 // OPAQUE=2, TRANSPARENT=1
}

// WinMessage represents a Windows message (WM_*).
type WinMessage struct {
	Hwnd    uint64
	Message uint32
	WParam  uint64
	LParam  uint64
	Time    uint32
	PtX     int32
	PtY     int32
}

// WindowClass stores a registered window class.
type WindowClass struct {
	ClassName string
	WndProc   uint64
	Style     uint32
	HInst     uint64
}

// Win32kSubsystem manages the Win32k graphics and window subsystem.
type Win32kSubsystem struct {
	mu         sync.RWMutex
	mem        *mmu.MMU
	handles    *ntapi.HandleTable
	windows    map[uint64]*Window
	classes    map[string]*WindowClass
	dcs        map[uint64]*DeviceContext
	nextHwnd   uint64
	nextHdc    uint64
	globalMsgQ chan WinMessage
	timerID    uint32
}

// New creates a Win32k subsystem.
func New(mem *mmu.MMU, handles *ntapi.HandleTable) *Win32kSubsystem {
	return &Win32kSubsystem{
		mem:        mem,
		handles:    handles,
		windows:    make(map[uint64]*Window),
		classes:    make(map[string]*WindowClass),
		dcs:        make(map[uint64]*DeviceContext),
		nextHwnd:   0x00010000,
		nextHdc:    0x01010000,
		globalMsgQ: make(chan WinMessage, 256),
	}
}

// RegisterHandlers registers all Win32k trap handlers with the dispatcher.
func (w *Win32kSubsystem) RegisterHandlers(d *ntapi.Dispatcher) {
	d.RegisterWin32kHandler("NtUserCreateWindowEx", w.handleCreateWindowEx)
	d.RegisterWin32kHandler("NtUserDestroyWindow", w.handleDestroyWindow)
	d.RegisterWin32kHandler("NtUserShowWindow", w.handleShowWindow)
	d.RegisterWin32kHandler("NtUserMoveWindow", w.handleMoveWindow)
	d.RegisterWin32kHandler("NtUserGetClientRect", w.handleGetClientRect)
	d.RegisterWin32kHandler("NtUserGetWindowRect", w.handleGetWindowRect)
	d.RegisterWin32kHandler("NtUserGetMessage", w.handleGetMessage)
	d.RegisterWin32kHandler("NtUserPeekMessage", w.handlePeekMessage)
	d.RegisterWin32kHandler("NtUserDispatchMessage", w.handleDispatchMessage)
	d.RegisterWin32kHandler("NtUserDefWindowProc", w.handleDefWindowProc)
	d.RegisterWin32kHandler("NtUserRegisterClassEx", w.handleRegisterClassEx)
	d.RegisterWin32kHandler("NtUserGetDC", w.handleGetDC)
	d.RegisterWin32kHandler("NtUserReleaseDC", w.handleReleaseDC)
	d.RegisterWin32kHandler("NtUserBeginPaint", w.handleBeginPaint)
	d.RegisterWin32kHandler("NtUserEndPaint", w.handleEndPaint)
	d.RegisterWin32kHandler("NtUserInvalidateRect", w.handleInvalidateRect)
	d.RegisterWin32kHandler("NtUserSetTimer", w.handleSetTimer)
	d.RegisterWin32kHandler("NtUserKillTimer", w.handleKillTimer)
	d.RegisterWin32kHandler("NtUserSetFocus", w.handleSetFocus)
	d.RegisterWin32kHandler("NtUserGetForegroundWindow", w.handleGetForegroundWindow)
	d.RegisterWin32kHandler("NtGdiCreateCompatibleDC", w.handleCreateCompatibleDC)
	d.RegisterWin32kHandler("NtGdiDeleteObjectApp", w.handleDeleteObject)
	d.RegisterWin32kHandler("NtGdiSelectObject", w.handleSelectObject)
	d.RegisterWin32kHandler("NtGdiSetTextColor", w.handleSetTextColor)
	d.RegisterWin32kHandler("NtGdiSetBkColor", w.handleSetBkColor)
	d.RegisterWin32kHandler("NtGdiSetBkMode", w.handleSetBkMode)
	d.RegisterWin32kHandler("NtGdiFillRect", w.handleFillRect)
	d.RegisterWin32kHandler("NtGdiRectangle", w.handleRectangle)
}

// PostMessage posts a message to a window's queue.
func (w *Win32kSubsystem) PostMessage(hwnd uint64, msg uint32, wParam, lParam uint64) {
	wm := WinMessage{
		Hwnd:    hwnd,
		Message: msg,
		WParam:  wParam,
		LParam:  lParam,
		Time:    uint32(time.Now().UnixMilli()),
	}
	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()
	if ok && win.MsgQueue != nil {
		select {
		case win.MsgQueue <- wm:
		default: // queue full
		}
	}
}

// allocHwnd returns the next unique window handle.
func (w *Win32kSubsystem) allocHwnd() uint64 {
	return atomic.AddUint64(&w.nextHwnd, 1)
}

// allocHdc returns the next unique device context handle.
func (w *Win32kSubsystem) allocHdc() uint64 {
	return atomic.AddUint64(&w.nextHdc, 1)
}

// ======================== WINDOW MANAGEMENT ========================

func (w *Win32kSubsystem) handleCreateWindowEx(ctx *ntapi.TrapContext) uint32 {
	hwnd := w.allocHwnd()

	win := &Window{
		Handle:   hwnd,
		Width:    800,
		Height:   600,
		Style:    0x00CF0000, // WS_OVERLAPPEDWINDOW
		MsgQueue: make(chan WinMessage, 64),
	}

	w.mu.Lock()
	w.windows[hwnd] = win
	w.mu.Unlock()

	if ctx.Trace {
		fmt.Printf("  NtUserCreateWindowEx → hwnd=0x%x\n", hwnd)
	}

	ctx.CPU.SetSyscallReturn(hwnd)
	return uint32(hwnd)
}

func (w *Win32kSubsystem) handleDestroyWindow(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	w.mu.Lock()
	delete(w.windows, hwnd)
	w.mu.Unlock()
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleShowWindow(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	cmdShow := ctx.Arg(1)
	w.mu.Lock()
	if win, ok := w.windows[hwnd]; ok {
		win.Visible = cmdShow != 0
	}
	w.mu.Unlock()
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleMoveWindow(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	x := int32(ctx.Arg(1))
	y := int32(ctx.Arg(2))
	width := int32(ctx.Arg(3))

	w.mu.Lock()
	if win, ok := w.windows[hwnd]; ok {
		win.X = x
		win.Y = y
		if width > 0 {
			win.Width = width
		}
	}
	w.mu.Unlock()
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleGetClientRect(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	rectAddr := ctx.Arg(1)

	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	if !ok || rectAddr == 0 {
		return ntapi.StatusInvalidHandle
	}

	// RECT: left, top, right, bottom (each int32)
	ctx.Mem.Write32(rectAddr+0, 0)
	ctx.Mem.Write32(rectAddr+4, 0)
	ctx.Mem.Write32(rectAddr+8, uint32(win.Width))
	ctx.Mem.Write32(rectAddr+12, uint32(win.Height))
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleGetWindowRect(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	rectAddr := ctx.Arg(1)

	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	if !ok || rectAddr == 0 {
		return ntapi.StatusInvalidHandle
	}

	ctx.Mem.Write32(rectAddr+0, uint32(win.X))
	ctx.Mem.Write32(rectAddr+4, uint32(win.Y))
	ctx.Mem.Write32(rectAddr+8, uint32(win.X+win.Width))
	ctx.Mem.Write32(rectAddr+12, uint32(win.Y+win.Height))
	return ntapi.StatusSuccess
}

// ======================== MESSAGE QUEUE ========================

func (w *Win32kSubsystem) handleGetMessage(ctx *ntapi.TrapContext) uint32 {
	msgAddr := ctx.Arg(0)
	hwnd := ctx.Arg(1)

	if msgAddr == 0 {
		return ntapi.StatusInvalidParameter
	}

	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	if !ok {
		// Get from any window
		select {
		case msg := <-w.globalMsgQ:
			writeMsg(ctx.Mem, msgAddr, &msg)
			return ntapi.StatusSuccess
		case <-time.After(100 * time.Millisecond):
			// Synthesize WM_PAINT
			wm := WinMessage{Hwnd: hwnd, Message: 0x000F, Time: uint32(time.Now().UnixMilli())}
			writeMsg(ctx.Mem, msgAddr, &wm)
			return ntapi.StatusSuccess
		}
	}

	select {
	case msg := <-win.MsgQueue:
		writeMsg(ctx.Mem, msgAddr, &msg)
	case <-time.After(100 * time.Millisecond):
		// WM_PAINT
		wm := WinMessage{Hwnd: hwnd, Message: 0x000F, Time: uint32(time.Now().UnixMilli())}
		writeMsg(ctx.Mem, msgAddr, &wm)
	}

	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handlePeekMessage(ctx *ntapi.TrapContext) uint32 {
	msgAddr := ctx.Arg(0)
	hwnd := ctx.Arg(1)

	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	if ok {
		select {
		case msg := <-win.MsgQueue:
			if msgAddr != 0 {
				writeMsg(ctx.Mem, msgAddr, &msg)
			}
			ctx.CPU.SetSyscallReturn(1) // TRUE
			return 1
		default:
		}
	}

	ctx.CPU.SetSyscallReturn(0) // FALSE, no message
	return 0
}

func (w *Win32kSubsystem) handleDispatchMessage(ctx *ntapi.TrapContext) uint32 {
	// In a real implementation, this would call the window procedure.
	// For now, return 0 (message processed).
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleDefWindowProc(ctx *ntapi.TrapContext) uint32 {
	msg := uint32(ctx.Arg(1))

	// Handle WM_DESTROY
	if msg == 0x0002 { // WM_DESTROY
		// Post WM_QUIT
		ctx.CPU.SetSyscallReturn(0)
		return 0
	}

	ctx.CPU.SetSyscallReturn(0)
	return 0
}

func (w *Win32kSubsystem) handleRegisterClassEx(ctx *ntapi.TrapContext) uint32 {
	// Return a unique class atom
	atom := uint32(0xC000 + uint32(len(w.classes)))
	ctx.CPU.SetSyscallReturn(uint64(atom))
	return atom
}

func (w *Win32kSubsystem) handleSetFocus(ctx *ntapi.TrapContext) uint32 {
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleGetForegroundWindow(ctx *ntapi.TrapContext) uint32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for hwnd := range w.windows {
		ctx.CPU.SetSyscallReturn(hwnd)
		return uint32(hwnd)
	}
	ctx.CPU.SetSyscallReturn(0)
	return 0
}

// ======================== PAINTING / DC ========================

func (w *Win32kSubsystem) handleGetDC(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)

	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	dc := &DeviceContext{
		Handle:    w.allocHdc(),
		TextColor: 0x000000, // black
		BkColor:   0xFFFFFF, // white
		BkMode:    2,        // OPAQUE
	}

	if ok {
		dc.Window = win
		dc.Width = win.Width
		dc.Height = win.Height
	}

	w.mu.Lock()
	w.dcs[dc.Handle] = dc
	w.mu.Unlock()

	ctx.CPU.SetSyscallReturn(dc.Handle)
	return uint32(dc.Handle)
}

func (w *Win32kSubsystem) handleReleaseDC(ctx *ntapi.TrapContext) uint32 {
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleBeginPaint(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	paintStructAddr := ctx.Arg(1)

	// Get or create DC
	w.mu.RLock()
	win, ok := w.windows[hwnd]
	w.mu.RUnlock()

	dc := &DeviceContext{
		Handle:    w.allocHdc(),
		TextColor: 0x000000,
		BkColor:   0xFFFFFF,
		BkMode:    2,
	}
	if ok {
		dc.Window = win
		dc.Width = win.Width
		dc.Height = win.Height
	}

	w.mu.Lock()
	w.dcs[dc.Handle] = dc
	w.mu.Unlock()

	// Write PAINTSTRUCT
	if paintStructAddr != 0 {
		ctx.Mem.Write64(paintStructAddr+0, dc.Handle) // hdc
		ctx.Mem.Write32(paintStructAddr+8, 1)          // fErase
		// rcPaint
		ctx.Mem.Write32(paintStructAddr+12, 0) // left
		ctx.Mem.Write32(paintStructAddr+16, 0) // top
		if ok {
			ctx.Mem.Write32(paintStructAddr+20, uint32(win.Width))  // right
			ctx.Mem.Write32(paintStructAddr+24, uint32(win.Height)) // bottom
		}
	}

	ctx.CPU.SetSyscallReturn(dc.Handle)
	return uint32(dc.Handle)
}

func (w *Win32kSubsystem) handleEndPaint(ctx *ntapi.TrapContext) uint32 {
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleInvalidateRect(ctx *ntapi.TrapContext) uint32 {
	hwnd := ctx.Arg(0)
	w.PostMessage(hwnd, 0x000F, 0, 0) // WM_PAINT
	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleSetTimer(ctx *ntapi.TrapContext) uint32 {
	id := atomic.AddUint32(&w.timerID, 1)
	ctx.CPU.SetSyscallReturn(uint64(id))
	return id
}

func (w *Win32kSubsystem) handleKillTimer(ctx *ntapi.TrapContext) uint32 {
	return ntapi.StatusSuccess
}

// ======================== GDI ========================

func (w *Win32kSubsystem) handleCreateCompatibleDC(ctx *ntapi.TrapContext) uint32 {
	dc := &DeviceContext{
		Handle:    w.allocHdc(),
		Width:     1,
		Height:    1,
		TextColor: 0x000000,
		BkColor:   0xFFFFFF,
		BkMode:    2,
	}

	w.mu.Lock()
	w.dcs[dc.Handle] = dc
	w.mu.Unlock()

	ctx.CPU.SetSyscallReturn(dc.Handle)
	return uint32(dc.Handle)
}

func (w *Win32kSubsystem) handleDeleteObject(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1) // TRUE
	return 1
}

func (w *Win32kSubsystem) handleSelectObject(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1) // previous object (dummy)
	return 1
}

func (w *Win32kSubsystem) handleSetTextColor(ctx *ntapi.TrapContext) uint32 {
	hdcVal := ctx.Arg(0)
	color := uint32(ctx.Arg(1))

	w.mu.Lock()
	if dc, ok := w.dcs[hdcVal]; ok {
		old := dc.TextColor
		dc.TextColor = color
		ctx.CPU.SetSyscallReturn(uint64(old))
	}
	w.mu.Unlock()

	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleSetBkColor(ctx *ntapi.TrapContext) uint32 {
	hdcVal := ctx.Arg(0)
	color := uint32(ctx.Arg(1))

	w.mu.Lock()
	if dc, ok := w.dcs[hdcVal]; ok {
		old := dc.BkColor
		dc.BkColor = color
		ctx.CPU.SetSyscallReturn(uint64(old))
	}
	w.mu.Unlock()

	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleSetBkMode(ctx *ntapi.TrapContext) uint32 {
	hdcVal := ctx.Arg(0)
	mode := int32(ctx.Arg(1))

	w.mu.Lock()
	if dc, ok := w.dcs[hdcVal]; ok {
		old := dc.BkMode
		dc.BkMode = mode
		ctx.CPU.SetSyscallReturn(uint64(old))
	}
	w.mu.Unlock()

	return ntapi.StatusSuccess
}

func (w *Win32kSubsystem) handleFillRect(ctx *ntapi.TrapContext) uint32 {
	// In a real implementation, this would fill pixels in the wl_shm buffer.
	ctx.CPU.SetSyscallReturn(1) // nonzero = success
	return 1
}

func (w *Win32kSubsystem) handleRectangle(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

// ======================== HELPERS ========================

func writeMsg(mem *mmu.MMU, addr uint64, msg *WinMessage) {
	// MSG structure: hwnd(8) + message(4) + wParam(8) + lParam(8) + time(4) + pt.x(4) + pt.y(4)
	mem.Write64(addr+0, msg.Hwnd)
	mem.Write32(addr+8, msg.Message)
	mem.Write64(addr+16, msg.WParam)
	mem.Write64(addr+24, msg.LParam)
	mem.Write32(addr+32, msg.Time)
	mem.Write32(addr+36, uint32(msg.PtX))
	mem.Write32(addr+40, uint32(msg.PtY))
}
