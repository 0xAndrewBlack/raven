// Package wl implements a minimal Wayland client for displaying windows.
// It speaks the Wayland wire protocol directly over a UNIX socket,
// using xdg-shell for window management and wl_shm for software rendering.
package wl

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

// Object types for event dispatch
type objKind int

const (
	kindDisplay objKind = iota
	kindRegistry
	kindCallback
	kindCompositor
	kindShm
	kindShmPool
	kindBuffer
	kindSurface
	kindXdgWmBase
	kindXdgSurface
	kindXdgToplevel
	kindSeat
	kindKeyboard
	kindPointer
	kindDecorationManager
	kindDecoration
	kindCursorShapeManager
	kindCursorShapeDevice
	kindLinuxDmabuf
	kindLinuxBufferParams
)

// CursorShape values for wp_cursor_shape_device_v1.set_shape.
// Matches the wp-cursor-shape-v1 protocol enum.
const (
	CursorDefault    = uint32(1)
	CursorText       = uint32(9) // I-beam
	CursorWait       = uint32(6)
	CursorCrosshair  = uint32(8)
	CursorPointer    = uint32(4) // hand
	CursorMove       = uint32(13)
	CursorNotAllowed = uint32(15)
	CursorResizeNS   = uint32(27) // NS_RESIZE
	CursorResizeEW   = uint32(26) // EW_RESIZE
	CursorResizeNWSE = uint32(29)
	CursorResizeNESW = uint32(28)
	CursorResizeAll  = uint32(32) // ALL_SCROLL
	CursorHelp       = uint32(3)
	CursorProgress   = uint32(5)
)

// EventType returned by Dispatch.
type EventType int

const (
	EventNone      EventType = iota
	EventConfigure           // window was resized by compositor
	EventClose               // close requested
	EventKey                 // keyboard input
	EventMouse               // mouse button/motion
)

// KeyEvent holds a keyboard event from Wayland.
type KeyEvent struct {
	Window   *Window
	Keycode  uint32 // Linux evdev keycode
	Pressed  bool   // true=press, false=release
	Char     rune   // mapped character (0 if non-printable)
	VK       uint32 // Win32 virtual key code
	ScanCode uint32 // best-effort hardware scan code
	Extended bool   // true when Win32 lParam extended-key bit should be set
}

// MouseEvent holds a mouse event from Wayland.
type MouseEvent struct {
	Window  *Window
	X, Y    int32  // surface-local coordinates
	Button  uint32 // Linux button code (BTN_LEFT=272, BTN_RIGHT=273, BTN_MIDDLE=274)
	Pressed bool   // true=press, false=release
	Kind    int    // 0=motion, 1=button, 2=axis(scroll)
	AxisVal int32  // scroll delta (for Kind==2)
	When    time.Time
}

const shmFmtXRGB8888 = 1

// Display is a connection to a Wayland compositor.
type Display struct {
	conn    *net.UnixConn
	fd      int // raw socket fd for unix.Select/epoll use
	nextID  uint32
	objects map[uint32]objKind

	registryID   uint32
	compositorID uint32
	shmID        uint32
	wmBaseID     uint32

	// globals advertised by the compositor
	compositorGlobal, compositorVer uint32
	shmGlobal, shmVer               uint32
	wmBaseGlobal, wmBaseVer         uint32
	seatGlobal, seatVer             uint32
	decorMgrGlobal, decorMgrVer     uint32
	cursorShapeMgrGlobal            uint32
	dmabufGlobal, dmabufVer         uint32

	decorMgrID       uint32
	cursorShapeMgrID uint32
	cursorShapeDevID uint32
	dmabufID         uint32
	pendingCursor    uint32 // shape to set on next enter, or 0

	seatID     uint32
	keyboardID uint32
	pointerID  uint32

	// keyboard state
	inputMu     sync.Mutex
	inputHoldMu sync.Mutex
	eventMu     sync.Mutex
	shiftDown   bool
	ctrlDown    bool
	altDown     bool
	keyEvents   []KeyEvent

	// mouse state
	mouseX, mouseY int32 // current surface-local position (fixed-point → int)
	mouseEvents    []MouseEvent
	lastSerial     uint32 // last input event serial (for interactive move/resize)
	dmabufFormats  map[uint32]map[uint64]struct{}
	dmabufParams   map[uint32]*Window

	readBuf []byte // buffered data from oversized reads

	windowsMu           sync.RWMutex
	win                 *Window
	windowsBySurface    map[uint32]*Window
	windowsByXdgSurface map[uint32]*Window
	windowsByToplevel   map[uint32]*Window
	pointerWindow       *Window
	keyboardWindow      *Window
	lastEventWindow     *Window
	pendingEvents       []displayEvent
}

type displayEvent struct {
	kind   EventType
	window *Window
}

// Window is a toplevel Wayland surface backed by a shared-memory pixel buffer.
type Window struct {
	disp       *Display
	surfaceID  uint32
	xdgSurfID  uint32
	toplevelID uint32
	decorID    uint32
	poolID     uint32
	bufferID   uint32
	frameMu    sync.RWMutex
	titleMu    sync.RWMutex

	Width     int32
	Height    int32
	TitleBarH int32  // extra pixels above client area for the title bar (0 = no title bar)
	Title     string // window title shown in the title bar
	Stride    int32
	Pix       []byte // mmap'd XRGB8888 pixels (B, G, R, X per pixel)
	fd        int    // memfd backing Pix
	dmabufID  uint32

	configured  bool
	needsResize bool
	appResized  bool // set when app called Resize(); suppresses compositor shrink
	Closed      bool

	dmabufWidth     uint32
	dmabufHeight    uint32
	dmabufStride    uint32
	dmabufFormat    uint32
	dmabufModifier  uint64
	dmabufParamsID  uint32
	dmabufCreateErr error
}

// NewHeadlessWindow creates a software-only window with the same pixel format
// used by Wayland SHM buffers. It is used by headless render tests.
func NewHeadlessWindow(title string, w, h, titleBarH int32) *Window {
	if w <= 0 {
		w = 800
	}
	if h <= 0 {
		h = 600
	}
	if titleBarH < 0 {
		titleBarH = 0
	}
	win := &Window{Width: w, Height: h, TitleBarH: titleBarH, Title: title}
	win.Stride = win.Width * 4
	win.Pix = make([]byte, int(win.Stride*(win.Height+win.TitleBarH)))
	for i := 0; i < len(win.Pix); i += 4 {
		win.Pix[i+0] = 0xC0
		win.Pix[i+1] = 0xC0
		win.Pix[i+2] = 0xC0
		win.Pix[i+3] = 0xFF
	}
	return win
}

// UpdateFrame applies a complete framebuffer update without exposing partial
// pixels to concurrent screenshots.
func (w *Window) UpdateFrame(update func()) {
	w.frameMu.Lock()
	defer w.frameMu.Unlock()
	update()
}

func (w *Window) TitleText() string {
	w.titleMu.RLock()
	defer w.titleMu.RUnlock()
	return w.Title
}

func (w *Window) SetTitleText(title string) {
	w.titleMu.Lock()
	w.Title = title
	w.titleMu.Unlock()
}

// --- wire helpers ---

func pu32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func pi32(v int32) []byte { return pu32(uint32(v)) }

func pstr(s string) []byte {
	data := append([]byte(s), 0) // NUL-terminated
	length := uint32(len(data))
	padded := (len(data) + 3) &^ 3
	buf := make([]byte, 4+padded)
	binary.LittleEndian.PutUint32(buf, length)
	copy(buf[4:], data)
	return buf
}

func gu32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func (d *Display) windowForSurface(surfaceID uint32) *Window {
	d.windowsMu.RLock()
	defer d.windowsMu.RUnlock()
	return d.windowsBySurface[surfaceID]
}

func gstr(b []byte) (string, int) {
	length := gu32(b)
	if length == 0 {
		return "", 4
	}
	s := string(b[4 : 4+length-1]) // exclude NUL
	consumed := 4 + int((length+3)&^3)
	return s, consumed
}

// --- sending ---

func (d *Display) send(obj uint32, op uint16, args ...[]byte) error {
	plen := 0
	for _, a := range args {
		plen += len(a)
	}
	sz := uint32(8 + plen)
	msg := make([]byte, 0, sz)
	msg = append(msg, pu32(obj)...)
	msg = append(msg, pu32(sz<<16|uint32(op))...)
	for _, a := range args {
		msg = append(msg, a...)
	}
	_, err := d.conn.Write(msg)
	return err
}

func (d *Display) sendFD(obj uint32, op uint16, fd int, args ...[]byte) error {
	plen := 0
	for _, a := range args {
		plen += len(a)
	}
	sz := uint32(8 + plen)
	msg := make([]byte, 0, sz)
	msg = append(msg, pu32(obj)...)
	msg = append(msg, pu32(sz<<16|uint32(op))...)
	for _, a := range args {
		msg = append(msg, a...)
	}
	oob := unix.UnixRights(fd)
	_, _, err := d.conn.WriteMsgUnix(msg, oob, nil)
	return err
}

// --- receiving ---

func (d *Display) readEvent() (uint32, uint16, []byte, []int, error) {
	// If we have buffered data from a previous oversized read, use it
	if len(d.readBuf) >= 8 {
		objID := gu32(d.readBuf[0:])
		sizeOp := gu32(d.readBuf[4:])
		sz := int(sizeOp >> 16)
		op := uint16(sizeOp & 0xFFFF)
		if sz < 8 {
			d.readBuf = nil
			return 0, 0, nil, nil, fmt.Errorf("wayland: bad msg size %d", sz)
		}
		if len(d.readBuf) >= sz {
			payload := make([]byte, sz-8)
			copy(payload, d.readBuf[8:sz])
			d.readBuf = append([]byte{}, d.readBuf[sz:]...)
			return objID, op, payload, nil, nil
		}
		// Not enough buffered data - need more from network (fall through)
	}

	// Read from network with ancillary data support
	hdrBuf := make([]byte, 4096)
	oobBuf := make([]byte, 64)
	// Prepend any leftover buffered data
	prefixLen := copy(hdrBuf, d.readBuf)
	d.readBuf = nil

	n, oobn, _, _, err := d.conn.ReadMsgUnix(hdrBuf[prefixLen:], oobBuf)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("wayland recv: %w", err)
	}
	n += prefixLen
	if n < 8 {
		return 0, 0, nil, nil, fmt.Errorf("wayland: short read %d", n)
	}

	var fds []int
	if oobn > 0 {
		scms, err := unix.ParseSocketControlMessage(oobBuf[:oobn])
		if err == nil {
			for _, scm := range scms {
				if gotFDs, err := unix.ParseUnixRights(&scm); err == nil {
					fds = append(fds, gotFDs...)
				}
			}
		}
	}

	objID := gu32(hdrBuf[0:])
	sizeOp := gu32(hdrBuf[4:])
	sz := int(sizeOp >> 16)
	op := uint16(sizeOp & 0xFFFF)
	if sz < 8 {
		return 0, 0, nil, fds, fmt.Errorf("wayland: bad msg size %d", sz)
	}

	if n >= sz {
		payload := make([]byte, sz-8)
		copy(payload, hdrBuf[8:sz])
		if n > sz {
			d.readBuf = append(d.readBuf, hdrBuf[sz:n]...)
		}
		return objID, op, payload, fds, nil
	}

	// Partial message - read the rest
	payload := make([]byte, sz-8)
	copied := copy(payload, hdrBuf[8:n])
	if copied < len(payload) {
		if _, err := io.ReadFull(d.conn, payload[copied:]); err != nil {
			return 0, 0, nil, fds, fmt.Errorf("wayland recv payload: %w", err)
		}
	}
	return objID, op, payload, fds, nil
}

// dispatchOne reads and handles one event.
func (d *Display) dispatchOne() (EventType, error) {
	objID, op, payload, fds, err := d.readEvent()
	if err != nil {
		return EventNone, err
	}
	// Close any FDs we don't use (except for keymap which is handled below)
	kind, ok := d.objects[objID]
	if !ok {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return EventNone, nil
	}

	switch kind {
	case kindDisplay:
		if op == 0 { // error
			if len(payload) >= 12 {
				errObj := gu32(payload[0:])
				errCode := gu32(payload[4:])
				msg, _ := gstr(payload[8:])
				return EventNone, fmt.Errorf("wayland protocol error: obj=%d code=%d msg=%q", errObj, errCode, msg)
			}
			return EventNone, fmt.Errorf("wayland protocol error: short payload (%d bytes): %x", len(payload), payload)
		} else if op == 1 && len(payload) >= 4 { // delete_id
			delete(d.objects, gu32(payload))
		}

	case kindRegistry:
		if op == 0 { // global
			name := gu32(payload[0:])
			iface, n := gstr(payload[4:])
			ver := gu32(payload[4+n:])
			d.handleGlobal(name, iface, ver)
		}

	case kindCallback:
		if op == 0 { // done
			delete(d.objects, objID)
		}

	case kindShm:
		// format - ignore

	case kindLinuxDmabuf:
		if op == 0 && len(payload) >= 4 {
			d.recordDmabufFormat(gu32(payload[0:]), 0)
		} else if op == 1 && len(payload) >= 12 {
			format := gu32(payload[0:])
			modifier := uint64(gu32(payload[4:]))<<32 | uint64(gu32(payload[8:]))
			d.recordDmabufFormat(format, modifier)
		}

	case kindBuffer:
		// release - TODO: double buffering

	case kindLinuxBufferParams:
		win := d.dmabufParams[objID]
		switch op {
		case 0:
			if win != nil && len(payload) >= 4 {
				win.dmabufID = gu32(payload[0:])
				d.objects[win.dmabufID] = kindBuffer
				win.dmabufParamsID = 0
				win.dmabufCreateErr = nil
				delete(d.dmabufParams, objID)
				delete(d.objects, objID)
			}
		case 1:
			if win != nil {
				win.dmabufParamsID = 0
				win.dmabufCreateErr = fmt.Errorf("wayland: zwp_linux_buffer_params_v1.create failed")
				delete(d.dmabufParams, objID)
				delete(d.objects, objID)
			}
		}

	case kindXdgWmBase:
		if op == 0 { // ping
			serial := gu32(payload)
			d.send(d.wmBaseID, 3, pu32(serial)) // pong
		}

	case kindXdgSurface:
		if op == 0 { // configure
			serial := gu32(payload)
			d.send(objID, 4, pu32(serial)) // ack_configure
			if win := d.windowsByXdgSurface[objID]; win != nil {
				win.configured = true
				d.setLastEventWindow(win)
			}
			return EventConfigure, nil
		}

	case kindXdgToplevel:
		win := d.windowsByToplevel[objID]
		if op == 0 { // configure(width, height, states)
			if len(payload) >= 8 && win != nil {
				w := int32(gu32(payload[0:]))
				h := int32(gu32(payload[4:]))
				// The compositor reports the total surface size including
				// the NC area (TitleBarH). Subtract it to get client height.
				if win.TitleBarH > 0 && h > win.TitleBarH {
					h -= win.TitleBarH
				}
				if w > 0 && h > 0 && (w != win.Width || h != win.Height) {
					// If the app explicitly resized and the compositor is trying to
					// shrink us back, ignore it (the app's size takes priority).
					if win.appResized && (w < win.Width || h < win.Height) {
						win.appResized = false
					} else {
						win.Width = w
						win.Height = h
						win.needsResize = true
						win.appResized = false
					}
				}
				d.setLastEventWindow(win)
			}
		} else if op == 1 { // close
			if win != nil {
				win.Closed = true
				d.setLastEventWindow(win)
			}
			return EventClose, nil
		}

	case kindDecoration:
		// configure (opcode 0): compositor reports which decoration mode it chose.
		// Accept silently - we requested server_side, compositor confirms.

	case kindSeat:
		if op == 0 { // capabilities
			caps := gu32(payload)
			const seatCapPointer = 1
			const seatCapKeyboard = 2
			if caps&seatCapPointer != 0 && d.pointerID == 0 {
				d.pointerID = d.alloc(kindPointer)
				d.send(d.seatID, 0, pu32(d.pointerID)) // wl_seat.get_pointer
				// create cursor shape device if the manager is available
				if d.cursorShapeMgrID != 0 {
					d.cursorShapeDevID = d.alloc(kindCursorShapeDevice)
					// wp_cursor_shape_manager_v1.get_pointer(id, pointer)
					d.send(d.cursorShapeMgrID, 1, pu32(d.cursorShapeDevID), pu32(d.pointerID))
				}
			}
			if caps&seatCapKeyboard != 0 && d.keyboardID == 0 {
				d.keyboardID = d.alloc(kindKeyboard)
				d.send(d.seatID, 1, pu32(d.keyboardID))
			}
		}

	case kindPointer:
		if op == 0 && len(payload) >= 8 {
			win := d.windowForSurface(gu32(payload[4:]))
			d.inputMu.Lock()
			d.pointerWindow = win
			d.inputMu.Unlock()
		}
		switch op {
		case 0: // enter (serial, surface, sx, sy) - fixed-point 24.8
			if len(payload) >= 16 {
				d.lastSerial = gu32(payload[0:])
				d.inputMu.Lock()
				d.mouseX = int32(gu32(payload[8:])) >> 8
				d.mouseY = int32(gu32(payload[12:])) >> 8
				d.inputMu.Unlock()
				// Apply pending cursor shape (set via SetCursorShape before enter)
				// or reset to default arrow when entering our surface.
				shape := d.pendingCursor
				if shape == 0 {
					shape = CursorDefault
				}
				d.setCursorShapeNow(shape)
			}
		case 1:
			if len(payload) >= 8 {
				win := d.windowForSurface(gu32(payload[4:]))
				d.inputMu.Lock()
				if d.pointerWindow == win {
					d.pointerWindow = nil
				}
				d.inputMu.Unlock()
			}
		case 2: // motion (time, sx, sy)
			if len(payload) >= 12 {
				d.inputHoldMu.Lock()
				d.inputMu.Lock()
				d.mouseX = int32(gu32(payload[4:])) >> 8
				d.mouseY = int32(gu32(payload[8:])) >> 8
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					Window: d.pointerWindow, X: d.mouseX, Y: d.mouseY, Kind: 0,
				})
				d.inputMu.Unlock()
				d.inputHoldMu.Unlock()
				return EventMouse, nil
			}
		case 3: // button (serial, time, button, state)
			if len(payload) >= 16 {
				d.lastSerial = gu32(payload[0:])
				button := gu32(payload[8:])
				state := gu32(payload[12:])
				d.inputHoldMu.Lock()
				d.inputMu.Lock()
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					Window: d.pointerWindow, X: d.mouseX, Y: d.mouseY,
					Button: button, Pressed: state == 1, Kind: 1, When: time.Now(),
				})
				d.inputMu.Unlock()
				d.inputHoldMu.Unlock()
				return EventMouse, nil
			}
		case 4: // axis (time, axis, value)
			if len(payload) >= 12 {
				val := int32(gu32(payload[8:])) >> 8
				d.inputHoldMu.Lock()
				d.inputMu.Lock()
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					Window: d.pointerWindow, X: d.mouseX, Y: d.mouseY,
					Kind: 2, AxisVal: val,
				})
				d.inputMu.Unlock()
				d.inputHoldMu.Unlock()
				return EventMouse, nil
			}
		case 5: // frame - end of a group of events
		}

	case kindKeyboard:
		if op == 1 && len(payload) >= 8 {
			win := d.windowForSurface(gu32(payload[4:]))
			d.inputMu.Lock()
			d.keyboardWindow = win
			d.inputMu.Unlock()
		}
		switch op {
		case 0: // keymap (format, size) - fd comes via ancillary data
			for _, fd := range fds {
				unix.Close(fd)
			}
			fds = nil // mark as consumed
		case 1: // enter - keyboard focus gained
		case 2: // leave - keyboard focus lost
		case 3: // key (serial, time, key, state)
			if len(payload) >= 16 {
				keycode := gu32(payload[8:])
				state := gu32(payload[12:])
				d.inputHoldMu.Lock()
				d.inputMu.Lock()
				vk, ch, extended := evdevToWin32(keycode, d.shiftDown)
				d.keyEvents = append(d.keyEvents, KeyEvent{
					Window:   d.keyboardWindow,
					Keycode:  keycode,
					Pressed:  state == 1,
					Char:     ch,
					VK:       vk,
					ScanCode: keycode & 0xFF,
					Extended: extended,
				})
				d.inputMu.Unlock()
				d.inputHoldMu.Unlock()
				return EventKey, nil
			}
		case 4: // modifiers (serial, mods_depressed, mods_latched, mods_locked, group)
			if len(payload) >= 16 {
				depressed := gu32(payload[4:])
				d.inputMu.Lock()
				d.shiftDown = depressed&1 != 0 // MOD_SHIFT
				d.ctrlDown = depressed&4 != 0  // MOD_CONTROL
				d.altDown = depressed&8 != 0   // MOD_ALT
				d.inputMu.Unlock()
			}
		}
	}
	// Close any unconsumed FDs
	for _, fd := range fds {
		unix.Close(fd)
	}
	return EventNone, nil
}

func (d *Display) handleGlobal(name uint32, iface string, ver uint32) {
	switch iface {
	case "wl_compositor":
		d.compositorGlobal, d.compositorVer = name, ver
	case "wl_shm":
		d.shmGlobal, d.shmVer = name, ver
	case "xdg_wm_base":
		d.wmBaseGlobal, d.wmBaseVer = name, ver
	case "wl_seat":
		d.seatGlobal, d.seatVer = name, ver
	case "zxdg_decoration_manager_v1":
		d.decorMgrGlobal, d.decorMgrVer = name, ver
	case "wp_cursor_shape_manager_v1":
		d.cursorShapeMgrGlobal = name
	case "zwp_linux_dmabuf_v1":
		d.dmabufGlobal, d.dmabufVer = name, ver
	}
}

// roundtrip reads events until the given callback fires.
func (d *Display) roundtrip(callbackID uint32) error {
	for {
		objID, op, payload, fds, err := d.readEvent()
		if err != nil {
			return err
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
		kind, ok := d.objects[objID]
		if !ok {
			continue
		}
		switch kind {
		case kindRegistry:
			if op == 0 {
				name := gu32(payload[0:])
				iface, n := gstr(payload[4:])
				ver := gu32(payload[4+n:])
				d.handleGlobal(name, iface, ver)
			}
		case kindCallback:
			if objID == callbackID && op == 0 {
				delete(d.objects, callbackID)
				return nil
			}
		case kindXdgWmBase:
			if op == 0 {
				serial := gu32(payload)
				d.send(d.wmBaseID, 3, pu32(serial))
			}
		case kindXdgSurface:
			if op == 0 { // configure - must ack even during roundtrip
				serial := gu32(payload)
				d.send(objID, 4, pu32(serial))
				if win := d.windowsByXdgSurface[objID]; win != nil {
					win.configured = true
					d.setLastEventWindow(win)
					d.retainEvent(EventConfigure)
				}
			}
		case kindXdgToplevel:
			win := d.windowsByToplevel[objID]
			if op == 0 { // configure(width, height, states) - update pending size
				if len(payload) >= 8 && win != nil {
					w := int32(gu32(payload[0:]))
					h := int32(gu32(payload[4:]))
					if win.TitleBarH > 0 && h > win.TitleBarH {
						h -= win.TitleBarH
					}
					if w > 0 && h > 0 && (w != win.Width || h != win.Height) {
						if !(win.appResized && (w < win.Width || h < win.Height)) {
							win.Width = w
							win.Height = h
							win.needsResize = true
							win.appResized = false
						}
					}
				}
			} else if op == 1 {
				if win != nil {
					win.Closed = true
					d.setLastEventWindow(win)
					d.retainEvent(EventClose)
				}
			}
		case kindSeat:
			if op == 0 { // capabilities during roundtrip
				caps := gu32(payload)
				const seatCapPointer = 1
				const seatCapKeyboard = 2
				if caps&seatCapPointer != 0 && d.pointerID == 0 {
					d.pointerID = d.alloc(kindPointer)
					d.send(d.seatID, 0, pu32(d.pointerID))
					if d.cursorShapeMgrID != 0 {
						d.cursorShapeDevID = d.alloc(kindCursorShapeDevice)
						d.send(d.cursorShapeMgrID, 1, pu32(d.cursorShapeDevID), pu32(d.pointerID))
					}
				}
				if caps&seatCapKeyboard != 0 && d.keyboardID == 0 {
					d.keyboardID = d.alloc(kindKeyboard)
					d.send(d.seatID, 1, pu32(d.keyboardID))
				}
			}
		case kindDisplay:
			if op == 0 {
				if len(payload) >= 12 {
					errObj := gu32(payload[0:])
					errCode := gu32(payload[4:])
					msg, _ := gstr(payload[8:])
					return fmt.Errorf("wayland protocol error: obj=%d code=%d msg=%q", errObj, errCode, msg)
				}
				return fmt.Errorf("wayland protocol error: short payload (%d): %x", len(payload), payload)
			}
		case kindLinuxDmabuf:
			if op == 0 && len(payload) >= 4 {
				d.recordDmabufFormat(gu32(payload[0:]), 0)
			} else if op == 1 && len(payload) >= 12 {
				format := gu32(payload[0:])
				modifier := uint64(gu32(payload[4:]))<<32 | uint64(gu32(payload[8:]))
				d.recordDmabufFormat(format, modifier)
			}
		}
	}
}

func (d *Display) alloc(k objKind) uint32 {
	id := d.nextID
	d.nextID++
	d.objects[id] = k
	return id
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// --- public API ---

// Connect establishes a connection to the Wayland compositor.
func Connect() (*Display, error) {
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		return nil, fmt.Errorf("XDG_RUNTIME_DIR not set")
	}
	name := os.Getenv("WAYLAND_DISPLAY")
	if name == "" {
		name = "wayland-0"
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: filepath.Join(xdg, name), Net: "unix",
	})
	if err != nil {
		return nil, err
	}

	d := &Display{
		conn:                conn,
		nextID:              2,
		objects:             map[uint32]objKind{1: kindDisplay},
		dmabufFormats:       map[uint32]map[uint64]struct{}{},
		dmabufParams:        map[uint32]*Window{},
		windowsBySurface:    map[uint32]*Window{},
		windowsByXdgSurface: map[uint32]*Window{},
		windowsByToplevel:   map[uint32]*Window{},
	}

	// extract raw fd for non-blocking Poll / unix.Select
	if sc, err2 := conn.SyscallConn(); err2 == nil {
		_ = sc.Control(func(f uintptr) { d.fd = int(f) })
	}

	// wl_display.get_registry
	d.registryID = d.alloc(kindRegistry)
	d.send(1, 1, pu32(d.registryID))

	// sync to collect all globals
	cb := d.alloc(kindCallback)
	d.send(1, 0, pu32(cb))
	if err := d.roundtrip(cb); err != nil {
		conn.Close()
		return nil, err
	}

	if d.compositorGlobal == 0 || d.shmGlobal == 0 || d.wmBaseGlobal == 0 {
		conn.Close()
		return nil, fmt.Errorf("wayland: missing globals (compositor=%v shm=%v xdg_wm_base=%v)",
			d.compositorGlobal != 0, d.shmGlobal != 0, d.wmBaseGlobal != 0)
	}

	// bind globals
	d.compositorID = d.alloc(kindCompositor)
	d.send(d.registryID, 0, pu32(d.compositorGlobal), pstr("wl_compositor"),
		pu32(min32(d.compositorVer, 6)), pu32(d.compositorID))

	d.shmID = d.alloc(kindShm)
	d.send(d.registryID, 0, pu32(d.shmGlobal), pstr("wl_shm"),
		pu32(min32(d.shmVer, 1)), pu32(d.shmID))

	d.wmBaseID = d.alloc(kindXdgWmBase)
	d.send(d.registryID, 0, pu32(d.wmBaseGlobal), pstr("xdg_wm_base"),
		pu32(min32(d.wmBaseVer, 2)), pu32(d.wmBaseID))

	// bind wl_seat for keyboard input
	if d.seatGlobal != 0 {
		d.seatID = d.alloc(kindSeat)
		d.send(d.registryID, 0, pu32(d.seatGlobal), pstr("wl_seat"),
			pu32(min32(d.seatVer, 5)), pu32(d.seatID))
	}

	// bind zxdg_decoration_manager_v1 if compositor advertises it
	if d.decorMgrGlobal != 0 {
		d.decorMgrID = d.alloc(kindDecorationManager)
		d.send(d.registryID, 0, pu32(d.decorMgrGlobal), pstr("zxdg_decoration_manager_v1"),
			pu32(min32(d.decorMgrVer, 1)), pu32(d.decorMgrID))
	}

	// bind wp_cursor_shape_manager_v1 if compositor advertises it
	if d.cursorShapeMgrGlobal != 0 {
		d.cursorShapeMgrID = d.alloc(kindCursorShapeManager)
		d.send(d.registryID, 0, pu32(d.cursorShapeMgrGlobal), pstr("wp_cursor_shape_manager_v1"),
			pu32(1), pu32(d.cursorShapeMgrID))
	}
	if d.dmabufGlobal != 0 {
		d.dmabufID = d.alloc(kindLinuxDmabuf)
		d.send(d.registryID, 0, pu32(d.dmabufGlobal), pstr("zwp_linux_dmabuf_v1"),
			pu32(min32(d.dmabufVer, 3)), pu32(d.dmabufID))
	}

	// second roundtrip for shm formats etc
	cb = d.alloc(kindCallback)
	d.send(1, 0, pu32(cb))
	if err := d.roundtrip(cb); err != nil {
		conn.Close()
		return nil, err
	}

	return d, nil
}

// CreateWindow creates a toplevel window with a shared-memory pixel buffer.
// titleBarH is the height in pixels to reserve at the top for a client-side
// title bar (0 = no CSD title bar, rely on compositor server-side decorations).
func (d *Display) CreateWindow(title string, w, h, titleBarH int32) (*Window, error) {
	return d.createWindow(title, w, h, titleBarH, nil)
}

// CreateOwnedWindow creates a toplevel whose window-manager parent is parent.
func (d *Display) CreateOwnedWindow(title string, w, h, titleBarH int32, parent *Window) (*Window, error) {
	return d.createWindow(title, w, h, titleBarH, parent)
}

func (d *Display) createWindow(title string, w, h, titleBarH int32, parent *Window) (*Window, error) {
	win := &Window{disp: d, Width: w, Height: h, TitleBarH: titleBarH, Title: title}
	created := false
	defer func() {
		if !created {
			win.Destroy()
		}
	}()

	// wl_compositor.create_surface (opcode 0)
	win.surfaceID = d.alloc(kindSurface)
	d.send(d.compositorID, 0, pu32(win.surfaceID))

	// xdg_wm_base.get_xdg_surface (opcode 2)
	win.xdgSurfID = d.alloc(kindXdgSurface)
	d.send(d.wmBaseID, 2, pu32(win.xdgSurfID), pu32(win.surfaceID))

	// xdg_surface.get_toplevel (opcode 1)
	win.toplevelID = d.alloc(kindXdgToplevel)
	d.send(win.xdgSurfID, 1, pu32(win.toplevelID))
	d.windowsMu.Lock()
	d.windowsBySurface[win.surfaceID] = win
	d.windowsByXdgSurface[win.xdgSurfID] = win
	d.windowsByToplevel[win.toplevelID] = win
	if d.win == nil {
		d.win = win
	}
	d.windowsMu.Unlock()
	if parent != nil {
		d.send(win.toplevelID, 1, pu32(parent.toplevelID))
	}

	// xdg_toplevel.set_title (opcode 2)
	d.send(win.toplevelID, 2, pstr(title))
	// xdg_toplevel.set_app_id (opcode 3)
	d.send(win.toplevelID, 3, pstr("govm"))

	// Request server-side decorations (title bar + chrome) if supported.
	// zxdg_decoration_manager_v1: get_toplevel_decoration (opcode 1) → new object id, toplevel id
	// zxdg_toplevel_decoration_v1: set_mode (opcode 1) → mode=2 (server_side)
	if d.decorMgrID != 0 {
		win.decorID = d.alloc(kindDecoration)
		d.send(d.decorMgrID, 1, pu32(win.decorID), pu32(win.toplevelID))
		d.send(win.decorID, 1, pu32(2)) // set_mode(server_side=2)
	}

	// initial commit triggers configure
	d.send(win.surfaceID, 6) // wl_surface.commit
	// wait for configure
	for !win.configured {
		evt, err := d.dispatchOne()
		if err != nil {
			return nil, err
		}
		d.retainEvent(evt)
	}

	// create SHM buffer
	if err := win.createBuffer(); err != nil {
		return nil, err
	}

	// fill with light gray
	for i := 0; i < len(win.Pix); i += 4 {
		win.Pix[i+0] = 0xC0 // B
		win.Pix[i+1] = 0xC0 // G
		win.Pix[i+2] = 0xC0 // R
		win.Pix[i+3] = 0xFF // X
	}

	// attach + damage + commit
	d.send(win.surfaceID, 1, pu32(win.bufferID), pi32(0), pi32(0))                              // attach
	d.send(win.surfaceID, 9, pi32(0), pi32(0), pi32(win.Width), pi32(win.Height+win.TitleBarH)) // damage_buffer
	d.send(win.surfaceID, 6)                                                                    // commit

	// Wait for the compositor to process the initial buffer commit. labwc
	// sends xdg_toplevel.configure(activated) + xdg_surface.configure after
	// seeing the first buffer. We must ack that configure before any further
	// commit or the compositor closes the connection (protocol error).
	cb2 := d.alloc(kindCallback)
	d.send(1, 0, pu32(cb2))
	if err := d.roundtrip(cb2); err != nil {
		return nil, err
	}

	created = true
	return win, nil
}

func (w *Window) createBuffer() error {
	w.Stride = w.Width * 4
	totalH := w.Height + w.TitleBarH
	size := int(w.Stride * totalH)

	fd, err := unix.MemfdCreate("govm-shm", 0)
	if err != nil {
		return fmt.Errorf("memfd_create: %w", err)
	}
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		unix.Close(fd)
		return fmt.Errorf("ftruncate: %w", err)
	}
	data, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("mmap: %w", err)
	}
	w.fd = fd
	w.Pix = data

	d := w.disp

	// wl_shm.create_pool(pool_id, fd, size) - opcode 0, fd via SCM_RIGHTS
	w.poolID = d.alloc(kindShmPool)
	d.sendFD(d.shmID, 0, fd, pu32(w.poolID), pi32(int32(size)))

	// wl_shm_pool.create_buffer(buf_id, offset, w, h, stride, format) - opcode 0
	w.bufferID = d.alloc(kindBuffer)
	d.send(w.poolID, 0,
		pu32(w.bufferID),
		pi32(0), // offset
		pi32(w.Width),
		pi32(totalH),
		pi32(w.Stride),
		pu32(shmFmtXRGB8888),
	)

	// pool can be destroyed; buffer keeps the shm reference
	d.send(w.poolID, 1) // wl_shm_pool.destroy (opcode 1)

	return nil
}

// drainIncoming reads and dispatches all pending events from the Wayland
// socket without blocking. This ensures pending xdg_surface.configure
// events are acked before the next commit (required by the protocol).
func (d *Display) drainIncoming() {
	for {
		if len(d.readBuf) < 8 {
			var rfds unix.FdSet
			rfds.Set(d.fd)
			n, _ := unix.Select(d.fd+1, &rfds, nil, nil, &unix.Timeval{Sec: 0, Usec: 0})
			if n <= 0 {
				return
			}
		}
		evt, err := d.dispatchOne()
		if err != nil {
			return
		}
		d.retainEvent(evt)
	}
}

func (d *Display) retainEvent(evt EventType) {
	if evt != EventClose && evt != EventConfigure {
		return
	}
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	d.pendingEvents = append(d.pendingEvents, displayEvent{kind: evt, window: d.lastEventWindow})
}

func (d *Display) pollRetainedEvent() (EventType, bool) {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	if len(d.pendingEvents) == 0 {
		return EventNone, false
	}
	evt := d.pendingEvents[0]
	d.pendingEvents = d.pendingEvents[1:]
	d.lastEventWindow = evt.window
	return evt.kind, true
}

// InjectCloseWindow queues a close request through the normal display event path.
func (d *Display) InjectCloseWindow(win *Window) {
	if win == nil {
		return
	}
	d.eventMu.Lock()
	d.pendingEvents = append(d.pendingEvents, displayEvent{kind: EventClose, window: win})
	d.eventMu.Unlock()
}

// Commit submits the current pixel buffer to the compositor and waits for
// the compositor to signal it is ready for the next frame. This ensures:
//   - Any xdg_surface.configure events sent after this commit are received and
//     acked before the caller can issue the next commit (protocol requirement).
//   - Natural vsync throttling: Present() blocks until the compositor renders.
//
// SnapshotPixels returns a copy of the window's current pixel buffer, for
// save-behind of transient overlays (popup menus) so the content underneath can
// be restored when the overlay is dismissed.
func (w *Window) SnapshotPixels() []byte {
	if len(w.Pix) == 0 {
		return nil
	}
	snap := make([]byte, len(w.Pix))
	copy(snap, w.Pix)
	return snap
}

// RestorePixels blits a previously captured snapshot back into the window
// buffer. The snapshot must have been taken at the same buffer size.
func (w *Window) RestorePixels(snap []byte) bool {
	if len(snap) == 0 || len(snap) != len(w.Pix) {
		return false
	}
	copy(w.Pix, snap)
	return true
}

func (w *Window) Commit() {
	if w.disp == nil {
		return
	}
	totalH := w.Height + w.TitleBarH
	d := w.disp

	// Drain any events that arrived since the last call (non-blocking).
	d.drainIncoming()

	// Request a frame callback so we know when the compositor is done with
	// this frame. We MUST wait for this before committing the next frame.
	frameCbID := d.alloc(kindCallback)
	d.send(w.surfaceID, 3, pu32(frameCbID)) // wl_surface.frame

	if err := d.send(w.surfaceID, 1, pu32(w.bufferID), pi32(0), pi32(0)); err != nil {
		delete(d.objects, frameCbID)
		return
	}
	if err := d.send(w.surfaceID, 9, pi32(0), pi32(0), pi32(w.Width), pi32(totalH)); err != nil {
		delete(d.objects, frameCbID)
		return
	}
	d.send(w.surfaceID, 6) //nolint:errcheck

	// Block until the frame callback fires. While waiting, all incoming
	// events (including configure events) are dispatched and acked. This
	// prevents the "commit without ack_configure" protocol violation.
	// A 50ms timeout prevents deadlock if the compositor never fires the callback
	// (e.g. when the window is minimized or the compositor is throttling).
	for {
		if _, fired := d.objects[frameCbID]; !fired {
			return // callback was deleted by dispatchOne when it fired
		}
		// Wait up to 50ms for data; don't block indefinitely.
		if len(d.readBuf) < 8 {
			var rfds unix.FdSet
			rfds.Set(d.fd)
			n, _ := unix.Select(d.fd+1, &rfds, nil, nil, &unix.Timeval{Sec: 0, Usec: 50_000})
			if n <= 0 {
				delete(d.objects, frameCbID)
				return
			}
		}
		evt, err := d.dispatchOne()
		if err != nil {
			delete(d.objects, frameCbID)
			return
		}
		d.retainEvent(evt)
	}
}

// Destroy releases a toplevel and its local framebuffer resources.
func (w *Window) Destroy() {
	if w == nil || w.disp == nil {
		return
	}
	d := w.disp
	d.clearWindowInput(w)
	w.destroyDmabufBuffer()
	if w.decorID != 0 {
		d.send(w.decorID, 0)
		delete(d.objects, w.decorID)
		w.decorID = 0
	}
	d.windowsMu.Lock()
	if w.toplevelID != 0 {
		d.send(w.toplevelID, 0)
		delete(d.objects, w.toplevelID)
		delete(d.windowsByToplevel, w.toplevelID)
	}
	if w.xdgSurfID != 0 {
		d.send(w.xdgSurfID, 0)
		delete(d.objects, w.xdgSurfID)
		delete(d.windowsByXdgSurface, w.xdgSurfID)
	}
	if w.surfaceID != 0 {
		d.send(w.surfaceID, 0)
		delete(d.objects, w.surfaceID)
		delete(d.windowsBySurface, w.surfaceID)
	}
	if d.win == w {
		d.win = nil
	}
	d.windowsMu.Unlock()
	if w.bufferID != 0 {
		d.send(w.bufferID, 0)
		delete(d.objects, w.bufferID)
		w.bufferID = 0
	}
	if w.Pix != nil {
		unix.Munmap(w.Pix)
		w.Pix = nil
	}
	if w.fd > 0 {
		unix.Close(w.fd)
		w.fd = -1
	}
	w.Closed = true
	w.disp = nil
}

func (d *Display) clearWindowInput(w *Window) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	if d.pointerWindow == w {
		d.pointerWindow = nil
	}
	if d.keyboardWindow == w {
		d.keyboardWindow = nil
		d.shiftDown = false
		d.ctrlDown = false
		d.altDown = false
	}
	keys := d.keyEvents[:0]
	for _, event := range d.keyEvents {
		if event.Window != w {
			keys = append(keys, event)
		}
	}
	d.keyEvents = keys
	mouse := d.mouseEvents[:0]
	for _, event := range d.mouseEvents {
		if event.Window != w {
			mouse = append(mouse, event)
		}
	}
	d.mouseEvents = mouse
	d.eventMu.Lock()
	if d.lastEventWindow == w {
		d.lastEventWindow = nil
	}
	events := d.pendingEvents[:0]
	for _, event := range d.pendingEvents {
		if event.window != w {
			events = append(events, event)
		}
	}
	d.pendingEvents = events
	d.eventMu.Unlock()
}

// SetTitleBar sets the title bar height and title, and marks the buffer for recreation.
// Call this after CreateWindow to enable the client-side title bar decoration.
func (w *Window) SetTitleBar(h int32, title string) {
	w.TitleBarH = h
	w.SetTitleText(title)
	w.needsResize = true
}

// Resize requests a window resize to the given dimensions.
// The buffer is recreated immediately if the size changed.
func (w *Window) Resize(width, height int32) bool {
	if width == w.Width && height == w.Height {
		return false
	}
	w.Width = width
	w.Height = height
	w.needsResize = true
	w.appResized = true
	return w.ResizeIfNeeded()
}

// NeedsResize returns true if the compositor requested a resize that hasn't been applied.
func (w *Window) NeedsResize() bool { return w.needsResize }

// ResizeIfNeeded recreates the shm buffer if the compositor changed the window size.
// Returns true if the buffer was resized (all pixels are zeroed).
func (w *Window) ResizeIfNeeded() bool {
	if !w.needsResize {
		return false
	}
	w.needsResize = false
	if w.disp == nil {
		w.Stride = w.Width * 4
		w.Pix = make([]byte, int(w.Stride*(w.Height+w.TitleBarH)))
		return true
	}
	if w.Pix != nil {
		unix.Munmap(w.Pix)
		w.Pix = nil
	}
	if w.fd > 0 {
		unix.Close(w.fd)
		w.fd = 0
	}
	w.destroyDmabufBuffer()
	w.disp.send(w.bufferID, 0) // wl_buffer.destroy
	w.createBuffer()
	return true
}

// Minimize sends xdg_toplevel.set_minimized (opcode 9).
func (w *Window) Minimize() {
	w.disp.send(w.toplevelID, 9)
}

// Maximize sends xdg_toplevel.set_maximized (opcode 6).
func (w *Window) Maximize() {
	w.disp.send(w.toplevelID, 6)
}

// Restore sends xdg_toplevel.unset_maximized (opcode 7).
func (w *Window) Restore() {
	w.disp.send(w.toplevelID, 7)
}

// StartMove initiates an interactive move via xdg_toplevel.move (opcode 5).
func (w *Window) StartMove() {
	w.disp.send(w.toplevelID, 5, pu32(w.disp.seatID), pu32(w.disp.lastSerial))
}

// Dispatch blocks until a user-facing event occurs (configure, close, or key).
func (d *Display) Dispatch() (EventType, error) {
	if evt, ok := d.pollRetainedEvent(); ok {
		return evt, nil
	}
	for {
		evt, err := d.dispatchOne()
		if err != nil {
			return EventNone, err
		}
		if evt != EventNone {
			return evt, nil
		}
		// Got EventNone (e.g. wl_pointer.frame) - only loop if more data is
		// already buffered or immediately available on the socket. Otherwise
		// return EventNone to avoid blocking indefinitely.
		if len(d.readBuf) < 8 {
			var rfds unix.FdSet
			rfds.Set(d.fd)
			n, _ := unix.Select(d.fd+1, &rfds, nil, nil, &unix.Timeval{Sec: 0, Usec: 0})
			if n <= 0 {
				return EventNone, nil
			}
		}
	}
}

// Fd returns the underlying socket file descriptor for use with select/epoll.
func (d *Display) Fd() int { return d.fd }

func (d *Display) setLastEventWindow(win *Window) {
	d.eventMu.Lock()
	d.lastEventWindow = win
	d.eventMu.Unlock()
}

// LastEventWindow returns the window associated with the latest dispatched event.
func (d *Display) LastEventWindow() *Window {
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	return d.lastEventWindow
}

// Windows returns the currently live toplevel windows.
func (d *Display) Windows() []*Window {
	d.windowsMu.RLock()
	defer d.windowsMu.RUnlock()
	windows := make([]*Window, 0, len(d.windowsBySurface))
	for _, win := range d.windowsBySurface {
		windows = append(windows, win)
	}
	return windows
}

// Poll checks whether there is data to read on the Wayland socket without
// blocking. Processes buffered data first, then checks the socket.
// Returns EventNone immediately when no data is ready.
func (d *Display) Poll() (EventType, error) {
	if evt, ok := d.pollRetainedEvent(); ok {
		return evt, nil
	}
	if d.fd < 0 {
		return EventNone, nil
	}
	// Process any previously buffered data before checking the socket.
	if len(d.readBuf) >= 8 {
		return d.dispatchOne()
	}
	var rfds unix.FdSet
	rfds.Set(d.fd)
	n, err := unix.Select(d.fd+1, &rfds, nil, nil, &unix.Timeval{Sec: 0, Usec: 0})
	if err != nil || n == 0 {
		return EventNone, nil
	}
	return d.dispatchOne()
}

// PollKey returns the next queued key event, if any.
func (d *Display) PollKey() (KeyEvent, bool) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	if len(d.keyEvents) == 0 {
		return KeyEvent{}, false
	}
	ev := d.keyEvents[0]
	d.keyEvents = d.keyEvents[1:]
	switch ev.VK {
	case 0x10:
		d.shiftDown = ev.Pressed
	case 0x11:
		d.ctrlDown = ev.Pressed
	case 0x12:
		d.altDown = ev.Pressed
	}
	return ev, true
}

// PollKeyForWindows returns the first queued key event targeting one of the
// supplied windows without consuming input queued for other windows.
func (d *Display) PollKeyForWindows(windows ...*Window) (KeyEvent, bool) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	for index, event := range d.keyEvents {
		if !windowInSet(event.Window, windows) {
			continue
		}
		d.keyEvents = append(d.keyEvents[:index], d.keyEvents[index+1:]...)
		d.updateModifierState(event)
		return event, true
	}
	return KeyEvent{}, false
}

func windowInSet(window *Window, windows []*Window) bool {
	for _, candidate := range windows {
		if candidate != nil && window == candidate {
			return true
		}
	}
	return false
}

func (d *Display) updateModifierState(event KeyEvent) {
	switch event.VK {
	case 0x10:
		d.shiftDown = event.Pressed
	case 0x11:
		d.ctrlDown = event.Pressed
	case 0x12:
		d.altDown = event.Pressed
	}
}

// ShiftDown returns the current shift key state.
func (d *Display) ShiftDown() bool {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return d.shiftDown
}

// SetWindowTitle sends xdg_toplevel.set_title to update the compositor's title bar.
func (d *Display) SetWindowTitle(win *Window, title string) {
	win.SetTitleText(title)
	d.send(win.toplevelID, 2, pstr(title))
}

// HasNoSSD reports whether the compositor did NOT advertise zxdg_decoration_manager_v1,
// meaning we must draw client-side decorations ourselves.
func (d *Display) HasNoSSD() bool {
	return d.decorMgrGlobal == 0
}

// CtrlDown returns the current control key state.
func (d *Display) CtrlDown() bool {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return d.ctrlDown
}

// AltDown returns the current alt key state.
func (d *Display) AltDown() bool {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return d.altDown
}

// SetCursorShape sets the Wayland pointer cursor shape.
// Uses wp_cursor_shape_device_v1 if available; silently ignores otherwise.
// Safe to call at any time; the shape is remembered and applied on next pointer enter.
func (d *Display) SetCursorShape(shape uint32) {
	d.pendingCursor = shape
	d.setCursorShapeNow(shape)
}

// setCursorShapeNow sends set_shape immediately using the current serial.
func (d *Display) setCursorShapeNow(shape uint32) {
	if d.cursorShapeDevID == 0 || shape == 0 {
		return
	}
	// wp_cursor_shape_device_v1.set_shape(serial, shape)
	d.send(d.cursorShapeDevID, 1, pu32(d.lastSerial), pu32(shape))
}

// PollMouse returns the next queued mouse event, if any.
func (d *Display) PollMouse() (MouseEvent, bool) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	if len(d.mouseEvents) == 0 {
		return MouseEvent{}, false
	}
	ev := d.mouseEvents[0]
	d.mouseEvents = d.mouseEvents[1:]
	return ev, true
}

// PollMouseForWindows returns the first queued mouse event targeting one of the
// supplied windows without consuming input queued for other windows.
func (d *Display) PollMouseForWindows(windows ...*Window) (MouseEvent, bool) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	for index, event := range d.mouseEvents {
		if !windowInSet(event.Window, windows) {
			continue
		}
		d.mouseEvents = append(d.mouseEvents[:index], d.mouseEvents[index+1:]...)
		return event, true
	}
	return MouseEvent{}, false
}

// MousePos returns the current mouse position on the surface.
func (d *Display) MousePos() (int32, int32) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return d.mouseX, d.mouseY
}

// HasPendingInput returns true if there are queued mouse or key events
// (e.g. from InjectClick/InjectKey) that haven't been polled yet.
func (d *Display) HasPendingInput() bool {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return len(d.mouseEvents) > 0 || len(d.keyEvents) > 0
}

// HasPendingInputForWindows reports whether input is queued for one of the
// supplied windows.
func (d *Display) HasPendingInputForWindows(windows ...*Window) bool {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	for _, event := range d.mouseEvents {
		if windowInSet(event.Window, windows) {
			return true
		}
	}
	for _, event := range d.keyEvents {
		if windowInSet(event.Window, windows) {
			return true
		}
	}
	return false
}

// TakeInputForWindows removes and returns input targeting the supplied windows.
// The returned events can be restored with PrependInput after other input has
// been dispatched.
func (d *Display) TakeInputForWindows(windows ...*Window) ([]KeyEvent, []MouseEvent) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	return d.takeInputForWindowsLocked(windows)
}

func (d *Display) takeInputForWindowsLocked(windows []*Window) ([]KeyEvent, []MouseEvent) {
	var keys []KeyEvent
	keptKeys := d.keyEvents[:0]
	for _, event := range d.keyEvents {
		if windowInSet(event.Window, windows) {
			keys = append(keys, event)
		} else {
			keptKeys = append(keptKeys, event)
		}
	}
	d.keyEvents = keptKeys
	var mouse []MouseEvent
	keptMouse := d.mouseEvents[:0]
	for _, event := range d.mouseEvents {
		if windowInSet(event.Window, windows) {
			mouse = append(mouse, event)
		} else {
			keptMouse = append(keptMouse, event)
		}
	}
	d.mouseEvents = keptMouse
	return keys, mouse
}

// PrependInput restores input ahead of events queued since it was removed.
func (d *Display) PrependInput(keys []KeyEvent, mouse []MouseEvent) {
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	d.prependInputLocked(keys, mouse)
}

func (d *Display) prependInputLocked(keys []KeyEvent, mouse []MouseEvent) {
	if len(keys) != 0 {
		d.keyEvents = append(append(make([]KeyEvent, 0, len(keys)+len(d.keyEvents)), keys...), d.keyEvents...)
	}
	if len(mouse) != 0 {
		d.mouseEvents = append(append(make([]MouseEvent, 0, len(mouse)+len(d.mouseEvents)), mouse...), d.mouseEvents...)
	}
}

// WithInputForWindowsSuspended runs dispatch while input for the supplied
// windows is temporarily hidden. Input producers are held until restoration.
func (d *Display) WithInputForWindowsSuspended(windows []*Window, dispatch func()) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	keys, mouse := d.takeInputForWindowsLocked(windows)
	d.inputMu.Unlock()
	if dispatch != nil {
		dispatch()
	}
	d.inputMu.Lock()
	d.prependInputLocked(keys, mouse)
	d.inputMu.Unlock()
}

// InjectClick queues a synthetic left-click at surface-absolute (x, y).
// Generates motion → press → release events.
func (d *Display) InjectClick(x, y int32) {
	d.InjectClickWindow(d.win, x, y)
}

func (d *Display) InjectDoubleClick(x, y int32) {
	d.InjectDoubleClickWindow(d.win, x, y)
}

// InjectClickWindow queues a synthetic left-click for a specific window.
func (d *Display) InjectClickWindow(win *Window, x, y int32) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	d.mouseX = x
	d.mouseY = y
	when := time.Now()
	d.mouseEvents = append(d.mouseEvents,
		MouseEvent{Window: win, X: x, Y: y, Kind: 0},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: true, Kind: 1, When: when},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: false, Kind: 1, When: when},
	)
}

func (d *Display) InjectDoubleClickWindow(win *Window, x, y int32) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	d.mouseX = x
	d.mouseY = y
	first := time.Now()
	second := first.Add(100 * time.Millisecond)
	d.mouseEvents = append(d.mouseEvents,
		MouseEvent{Window: win, X: x, Y: y, Kind: 0},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: true, Kind: 1, When: first},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: false, Kind: 1, When: first},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: true, Kind: 1, When: second},
		MouseEvent{Window: win, X: x, Y: y, Button: 272, Pressed: false, Kind: 1, When: second},
	)
}

// InjectMouseMove queues a synthetic mouse move at surface-absolute (x, y).
func (d *Display) InjectMouseMove(x, y int32) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	d.mouseX = x
	d.mouseY = y
	d.mouseEvents = append(d.mouseEvents, MouseEvent{Window: d.win, X: x, Y: y, Kind: 0})
}

// InjectKey queues a synthetic key press+release for a given Linux keycode.
func (d *Display) InjectKey(keycode uint32) {
	d.InjectKeyWindow(d.win, keycode)
}

// InjectKeyWindow queues a synthetic key press and release for a window.
func (d *Display) InjectKeyWindow(win *Window, keycode uint32) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	vk, ch, extended := evdevToWin32(keycode, d.shiftDown)
	d.keyEvents = append(d.keyEvents,
		KeyEvent{Window: win, Keycode: keycode, Pressed: true, VK: vk, Char: ch, ScanCode: keycode & 0xFF, Extended: extended},
		KeyEvent{Window: win, Keycode: keycode, Pressed: false, VK: vk, Char: ch, ScanCode: keycode & 0xFF, Extended: extended},
	)
}

// InjectTextWindow queues character input for a specific window.
func (d *Display) InjectTextWindow(win *Window, value string) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	for _, ch := range value {
		vk := uint32(unicode.ToUpper(ch))
		d.keyEvents = append(d.keyEvents,
			KeyEvent{Window: win, Pressed: true, VK: vk, Char: ch},
			KeyEvent{Window: win, Pressed: false, VK: vk, Char: ch},
		)
	}
}

// InjectKeyChord queues modifier-down, key press/release, modifier-up.
func (d *Display) InjectKeyChord(modifier, keycode uint32) {
	d.inputHoldMu.Lock()
	defer d.inputHoldMu.Unlock()
	d.inputMu.Lock()
	defer d.inputMu.Unlock()
	modVK, _, modExtended := evdevToWin32(modifier, false)
	vk, _, extended := evdevToWin32(keycode, false)
	d.keyEvents = append(d.keyEvents,
		KeyEvent{Window: d.win, Keycode: modifier, Pressed: true, VK: modVK, ScanCode: modifier & 0xFF, Extended: modExtended},
		KeyEvent{Window: d.win, Keycode: keycode, Pressed: true, VK: vk, ScanCode: keycode & 0xFF, Extended: extended},
		KeyEvent{Window: d.win, Keycode: keycode, Pressed: false, VK: vk, ScanCode: keycode & 0xFF, Extended: extended},
		KeyEvent{Window: d.win, Keycode: modifier, Pressed: false, VK: modVK, ScanCode: modifier & 0xFF, Extended: modExtended},
	)
}

// Close tears down the Wayland connection.
func (d *Display) Close() {
	for _, win := range d.Windows() {
		win.destroyDmabufBuffer()
		if win.Pix != nil {
			unix.Munmap(win.Pix)
		}
		if win.fd > 0 {
			unix.Close(win.fd)
		}
	}
	d.conn.Close()
}

// evdevToWin32 maps a Linux evdev keycode to a Win32 VK code and character.
func evdevToWin32(keycode uint32, shift bool) (vk uint32, ch rune, extended bool) {
	type keyMap struct {
		vk       uint32
		lower    rune
		upper    rune
		extended bool
	}

	// Common evdev keycodes (KEY_* from input-event-codes.h)
	table := map[uint32]keyMap{
		1:  {0x1B, 0x1B, 0x1B, false}, // ESC
		2:  {0x31, '1', '!', false},   // 1
		3:  {0x32, '2', '@', false},   // 2
		4:  {0x33, '3', '#', false},   // 3
		5:  {0x34, '4', '$', false},   // 4
		6:  {0x35, '5', '%', false},   // 5
		7:  {0x36, '6', '^', false},   // 6
		8:  {0x37, '7', '&', false},   // 7
		9:  {0x38, '8', '*', false},   // 8
		10: {0x39, '9', '(', false},   // 9
		11: {0x30, '0', ')', false},   // 0
		12: {0xBD, '-', '_', false},   // minus
		13: {0xBB, '=', '+', false},   // equal
		14: {0x08, '\b', '\b', false}, // backspace
		15: {0x09, '\t', '\t', false}, // tab
		16: {0x51, 'q', 'Q', false},
		17: {0x57, 'w', 'W', false},
		18: {0x45, 'e', 'E', false},
		19: {0x52, 'r', 'R', false},
		20: {0x54, 't', 'T', false},
		21: {0x59, 'y', 'Y', false},
		22: {0x55, 'u', 'U', false},
		23: {0x49, 'i', 'I', false},
		24: {0x4F, 'o', 'O', false},
		25: {0x50, 'p', 'P', false},
		26: {0xDB, '[', '{', false},
		27: {0xDD, ']', '}', false},
		28: {0x0D, '\r', '\r', false}, // enter
		29: {0x11, 0, 0, false},       // left ctrl
		30: {0x41, 'a', 'A', false},
		31: {0x53, 's', 'S', false},
		32: {0x44, 'd', 'D', false},
		33: {0x46, 'f', 'F', false},
		34: {0x47, 'g', 'G', false},
		35: {0x48, 'h', 'H', false},
		36: {0x4A, 'j', 'J', false},
		37: {0x4B, 'k', 'K', false},
		38: {0x4C, 'l', 'L', false},
		39: {0xBA, ';', ':', false},
		40: {0xDE, '\'', '"', false},
		41: {0xC0, '`', '~', false},
		42: {0x10, 0, 0, false}, // left shift
		43: {0xDC, '\\', '|', false},
		44: {0x5A, 'z', 'Z', false},
		45: {0x58, 'x', 'X', false},
		46: {0x43, 'c', 'C', false},
		47: {0x56, 'v', 'V', false},
		48: {0x42, 'b', 'B', false},
		49: {0x4E, 'n', 'N', false},
		50: {0x4D, 'm', 'M', false},
		51: {0xBC, ',', '<', false},
		52: {0xBE, '.', '>', false},
		53: {0xBF, '/', '?', false},
		54: {0x10, 0, 0, false},     // right shift
		56: {0x12, 0, 0, false},     // left alt
		57: {0x20, ' ', ' ', false}, // space
		// Function keys
		59: {0x70, 0, 0, false}, // F1
		60: {0x71, 0, 0, false}, // F2
		61: {0x72, 0, 0, false}, // F3
		62: {0x73, 0, 0, false}, // F4
		63: {0x74, 0, 0, false}, // F5
		64: {0x75, 0, 0, false}, // F6
		65: {0x76, 0, 0, false}, // F7
		66: {0x77, 0, 0, false}, // F8
		67: {0x78, 0, 0, false}, // F9
		68: {0x79, 0, 0, false}, // F10
		87: {0x7A, 0, 0, false}, // F11
		88: {0x7B, 0, 0, false}, // F12
		// Navigation
		97:  {0x11, 0, 0, true}, // right ctrl
		100: {0x12, 0, 0, true}, // right alt
		102: {0x24, 0, 0, true}, // Home
		103: {0x26, 0, 0, true}, // Up
		104: {0x21, 0, 0, true}, // PageUp
		105: {0x25, 0, 0, true}, // Left
		106: {0x27, 0, 0, true}, // Right
		107: {0x23, 0, 0, true}, // End
		108: {0x28, 0, 0, true}, // Down
		109: {0x22, 0, 0, true}, // PageDown
		110: {0x2D, 0, 0, true}, // Insert
		111: {0x2E, 0, 0, true}, // Delete
	}

	if km, ok := table[keycode]; ok {
		ch := km.lower
		if shift && km.upper != 0 {
			ch = km.upper
		}
		return km.vk, ch, km.extended
	}
	return 0, 0, false
}
