package win32k

import (
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// MessageQueue translates host input events into Windows messages.
// In the future, Wayland events (wl_pointer, wl_keyboard) will feed this queue
// and be translated into WM_* messages for the guest application.
type MessageQueue struct {
	mu       sync.Mutex
	mem      *mmu.MMU
	win32k   *Win32kSubsystem
	pending  []WinMessage
	shutdown bool
}

// NewMessageQueue creates a message queue bridge.
func NewMessageQueue(mem *mmu.MMU, w *Win32kSubsystem) *MessageQueue {
	return &MessageQueue{
		mem:    mem,
		win32k: w,
	}
}

// Windows message constants.
const (
	WM_NULL          = 0x0000
	WM_CREATE        = 0x0001
	WM_DESTROY       = 0x0002
	WM_MOVE          = 0x0003
	WM_SIZE          = 0x0005
	WM_ACTIVATE      = 0x0006
	WM_SETFOCUS      = 0x0007
	WM_KILLFOCUS     = 0x0008
	WM_CLOSE         = 0x0010
	WM_QUIT          = 0x0012
	WM_PAINT         = 0x000F
	WM_ERASEBKGND    = 0x0014
	WM_SHOWWINDOW    = 0x0018
	WM_KEYDOWN       = 0x0100
	WM_KEYUP         = 0x0101
	WM_CHAR          = 0x0102
	WM_SYSKEYDOWN    = 0x0104
	WM_SYSKEYUP      = 0x0105
	WM_MOUSEMOVE     = 0x0200
	WM_LBUTTONDOWN   = 0x0201
	WM_LBUTTONUP     = 0x0202
	WM_RBUTTONDOWN   = 0x0204
	WM_RBUTTONUP     = 0x0205
	WM_MBUTTONDOWN   = 0x0207
	WM_MBUTTONUP     = 0x0208
	WM_MOUSEWHEEL    = 0x020A
	WM_TIMER         = 0x0113
	WM_NCCREATE      = 0x0081
	WM_NCDESTROY     = 0x0082
	WM_NCHITTEST     = 0x0084
	WM_NCPAINT       = 0x0085
	WM_GETMINMAXINFO = 0x0024
	WM_WINDOWPOSCHANGING = 0x0046
	WM_WINDOWPOSCHANGED  = 0x0047
)

// InjectKeyDown injects a key-down event from Wayland into the guest.
func (mq *MessageQueue) InjectKeyDown(hwnd uint64, vkCode uint32, scanCode uint32) {
	mq.win32k.PostMessage(hwnd, WM_KEYDOWN, uint64(vkCode), uint64(scanCode)<<16|1)
}

// InjectKeyUp injects a key-up event.
func (mq *MessageQueue) InjectKeyUp(hwnd uint64, vkCode uint32, scanCode uint32) {
	mq.win32k.PostMessage(hwnd, WM_KEYUP, uint64(vkCode), uint64(scanCode)<<16|0xC0000001)
}

// InjectChar injects a WM_CHAR event (translated character).
func (mq *MessageQueue) InjectChar(hwnd uint64, char rune) {
	mq.win32k.PostMessage(hwnd, WM_CHAR, uint64(char), 1)
}

// InjectMouseMove injects a mouse movement event.
func (mq *MessageQueue) InjectMouseMove(hwnd uint64, x, y int32) {
	lParam := uint64(uint32(y))<<16 | uint64(uint32(x)&0xFFFF)
	mq.win32k.PostMessage(hwnd, WM_MOUSEMOVE, 0, lParam)
}

// InjectMouseButton injects a mouse button press/release.
func (mq *MessageQueue) InjectMouseButton(hwnd uint64, button int, down bool, x, y int32) {
	lParam := uint64(uint32(y))<<16 | uint64(uint32(x)&0xFFFF)
	var msg uint32
	switch button {
	case 0: // left
		if down {
			msg = WM_LBUTTONDOWN
		} else {
			msg = WM_LBUTTONUP
		}
	case 1: // right
		if down {
			msg = WM_RBUTTONDOWN
		} else {
			msg = WM_RBUTTONUP
		}
	case 2: // middle
		if down {
			msg = WM_MBUTTONDOWN
		} else {
			msg = WM_MBUTTONUP
		}
	}
	mq.win32k.PostMessage(hwnd, msg, 0, lParam)
}

// Run starts the message queue pump. In the future, this reads from a Wayland
// connection and translates events. For now it generates periodic WM_TIMER.
func (mq *MessageQueue) Run() {
	ticker := time.NewTicker(16 * time.Millisecond) // ~60fps
	defer ticker.Stop()

	for range ticker.C {
		mq.mu.Lock()
		if mq.shutdown {
			mq.mu.Unlock()
			return
		}
		mq.mu.Unlock()
	}
}

// Stop shuts down the message queue.
func (mq *MessageQueue) Stop() {
	mq.mu.Lock()
	mq.shutdown = true
	mq.mu.Unlock()
}
