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
	Keycode  uint32 // Linux evdev keycode
	Pressed  bool   // true=press, false=release
	Char     rune   // mapped character (0 if non-printable)
	VK       uint32 // Win32 virtual key code
}

// MouseEvent holds a mouse event from Wayland.
type MouseEvent struct {
	X, Y    int32  // surface-local coordinates
	Button  uint32 // Linux button code (BTN_LEFT=272, BTN_RIGHT=273, BTN_MIDDLE=274)
	Pressed bool   // true=press, false=release
	Kind    int    // 0=motion, 1=button, 2=axis(scroll)
	AxisVal int32  // scroll delta (for Kind==2)
}

const shmFmtXRGB8888 = 1

// Display is a connection to a Wayland compositor.
type Display struct {
	conn    *net.UnixConn
	fd      int    // raw socket fd for unix.Select/epoll use
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

	decorMgrID uint32

	seatID     uint32
	keyboardID uint32
	pointerID  uint32

	// keyboard state
	shiftDown bool
	ctrlDown  bool
	altDown   bool
	keyEvents []KeyEvent

	// mouse state
	mouseX, mouseY int32 // current surface-local position (fixed-point → int)
	mouseEvents    []MouseEvent

	readBuf []byte // buffered data from oversized reads

	win *Window
}

// Window is a toplevel Wayland surface backed by a shared-memory pixel buffer.
type Window struct {
	disp       *Display
	surfaceID  uint32
	xdgSurfID  uint32
	toplevelID uint32
	poolID     uint32
	bufferID   uint32

	Width     int32
	Height    int32
	TitleBarH int32  // extra pixels above client area for the title bar (0 = no title bar)
	Title     string // window title shown in the title bar
	Stride    int32
	Pix       []byte // mmap'd XRGB8888 pixels (B, G, R, X per pixel)
	fd        int    // memfd backing Pix

	configured  bool
	needsResize bool
	Closed      bool
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
		if op == 0 && len(payload) >= 12 { // error
			msg, _ := gstr(payload[8:])
			return EventNone, fmt.Errorf("wayland error: %s", msg)
		}

	case kindRegistry:
		if op == 0 { // global
			name := gu32(payload[0:])
			iface, n := gstr(payload[4:])
			ver := gu32(payload[4+n:])
			d.handleGlobal(name, iface, ver)
		}

	case kindCallback:
		// done - handled by roundtrip

	case kindShm:
		// format - ignore

	case kindBuffer:
		// release - TODO: double buffering

	case kindXdgWmBase:
		if op == 0 { // ping
			serial := gu32(payload)
			d.send(d.wmBaseID, 3, pu32(serial)) // pong
		}

	case kindXdgSurface:
		if op == 0 { // configure
			serial := gu32(payload)
			d.send(objID, 4, pu32(serial)) // ack_configure
			if d.win != nil {
				d.win.configured = true
			}
			return EventConfigure, nil
		}

	case kindXdgToplevel:
		if op == 0 { // configure(width, height, states)
			if len(payload) >= 8 && d.win != nil {
				w := int32(gu32(payload[0:]))
				h := int32(gu32(payload[4:]))
				// The compositor reports the total surface size including
				// the NC area (TitleBarH). Subtract it to get client height.
				if d.win.TitleBarH > 0 && h > d.win.TitleBarH {
					h -= d.win.TitleBarH
				}
				if w > 0 && h > 0 && (w != d.win.Width || h != d.win.Height) {
					d.win.Width = w
					d.win.Height = h
					d.win.needsResize = true
				}
			}
		} else if op == 1 { // close
			if d.win != nil {
				d.win.Closed = true
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
			}
			if caps&seatCapKeyboard != 0 && d.keyboardID == 0 {
				d.keyboardID = d.alloc(kindKeyboard)
				d.send(d.seatID, 1, pu32(d.keyboardID))
			}
		}

	case kindPointer:
		switch op {
		case 0: // enter (serial, surface, sx, sy) - fixed-point 24.8
			if len(payload) >= 16 {
				d.mouseX = int32(gu32(payload[8:])) >> 8
				d.mouseY = int32(gu32(payload[12:])) >> 8
			}
		case 1: // leave
		case 2: // motion (time, sx, sy)
			if len(payload) >= 12 {
				d.mouseX = int32(gu32(payload[4:])) >> 8
				d.mouseY = int32(gu32(payload[8:])) >> 8
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					X: d.mouseX, Y: d.mouseY, Kind: 0,
				})
				return EventMouse, nil
			}
		case 3: // button (serial, time, button, state)
			if len(payload) >= 16 {
				button := gu32(payload[8:])
				state := gu32(payload[12:])
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					X: d.mouseX, Y: d.mouseY,
					Button: button, Pressed: state == 1, Kind: 1,
				})
				return EventMouse, nil
			}
		case 4: // axis (time, axis, value)
			if len(payload) >= 12 {
				val := int32(gu32(payload[8:])) >> 8
				d.mouseEvents = append(d.mouseEvents, MouseEvent{
					X: d.mouseX, Y: d.mouseY,
					Kind: 2, AxisVal: val,
				})
				return EventMouse, nil
			}
		case 5: // frame - end of a group of events
		}

	case kindKeyboard:
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
				vk, ch := evdevToWin32(keycode, d.shiftDown)
				d.keyEvents = append(d.keyEvents, KeyEvent{
					Keycode: keycode,
					Pressed: state == 1,
					Char:    ch,
					VK:      vk,
				})
				return EventKey, nil
			}
		case 4: // modifiers (serial, mods_depressed, mods_latched, mods_locked, group)
			if len(payload) >= 16 {
				depressed := gu32(payload[4:])
				d.shiftDown = depressed&1 != 0 // MOD_SHIFT
				d.ctrlDown = depressed&4 != 0   // MOD_CONTROL
				d.altDown = depressed&8 != 0     // MOD_ALT
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
		case kindSeat:
			if op == 0 { // capabilities during roundtrip
				caps := gu32(payload)
				const seatCapKeyboard = 2
				if caps&seatCapKeyboard != 0 && d.keyboardID == 0 {
					d.keyboardID = d.alloc(kindKeyboard)
					d.send(d.seatID, 1, pu32(d.keyboardID))
				}
			}
		case kindDisplay:
			if op == 0 && len(payload) >= 12 {
				msg, _ := gstr(payload[8:])
				return fmt.Errorf("wayland error: %s", msg)
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
		conn:    conn,
		nextID:  2,
		objects: map[uint32]objKind{1: kindDisplay},
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
	win := &Window{disp: d, Width: w, Height: h, TitleBarH: titleBarH, Title: title}

	// wl_compositor.create_surface (opcode 0)
	win.surfaceID = d.alloc(kindSurface)
	d.send(d.compositorID, 0, pu32(win.surfaceID))

	// xdg_wm_base.get_xdg_surface (opcode 2)
	win.xdgSurfID = d.alloc(kindXdgSurface)
	d.send(d.wmBaseID, 2, pu32(win.xdgSurfID), pu32(win.surfaceID))

	// xdg_surface.get_toplevel (opcode 1)
	win.toplevelID = d.alloc(kindXdgToplevel)
	d.send(win.xdgSurfID, 1, pu32(win.toplevelID))

	// xdg_toplevel.set_title (opcode 2)
	d.send(win.toplevelID, 2, pstr(title))
	// xdg_toplevel.set_app_id (opcode 3)
	d.send(win.toplevelID, 3, pstr("govm"))

	// Request server-side decorations (title bar + chrome) if supported.
	// zxdg_decoration_manager_v1: get_toplevel_decoration (opcode 1) → new object id, toplevel id
	// zxdg_toplevel_decoration_v1: set_mode (opcode 1) → mode=2 (server_side)
	if d.decorMgrID != 0 {
		decorID := d.alloc(kindDecoration)
		d.send(d.decorMgrID, 1, pu32(decorID), pu32(win.toplevelID))
		d.send(decorID, 1, pu32(2)) // set_mode(server_side=2)
	}

	// initial commit triggers configure
	d.send(win.surfaceID, 6) // wl_surface.commit
	d.win = win

	// wait for configure
	for !win.configured {
		if _, err := d.dispatchOne(); err != nil {
			return nil, err
		}
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
	d.send(win.surfaceID, 1, pu32(win.bufferID), pi32(0), pi32(0))                                         // attach
	d.send(win.surfaceID, 9, pi32(0), pi32(0), pi32(win.Width), pi32(win.Height+win.TitleBarH)) // damage_buffer
	d.send(win.surfaceID, 6)                                                                                 // commit

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

// Commit submits the current pixel buffer to the compositor.
// NC area painting is handled by WM_NCPAINT in DefWindowProcW, not here.
func (w *Window) Commit() {
	totalH := w.Height + w.TitleBarH
	d := w.disp
	d.send(w.surfaceID, 1, pu32(w.bufferID), pi32(0), pi32(0))                        // attach
	d.send(w.surfaceID, 9, pi32(0), pi32(0), pi32(w.Width), pi32(totalH)) // damage_buffer
	d.send(w.surfaceID, 6)                                                              // commit
}

// SetTitleBar sets the title bar height and title, and marks the buffer for recreation.
// Call this after CreateWindow to enable the client-side title bar decoration.
func (w *Window) SetTitleBar(h int32, title string) {
	w.TitleBarH = h
	w.Title = title
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
	return w.ResizeIfNeeded()
}

// ResizeIfNeeded recreates the shm buffer if the compositor changed the window size.
// Returns true if the buffer was resized (all pixels are zeroed).
func (w *Window) ResizeIfNeeded() bool {
	if !w.needsResize {
		return false
	}
	w.needsResize = false
	if w.Pix != nil {
		unix.Munmap(w.Pix)
		w.Pix = nil
	}
	if w.fd > 0 {
		unix.Close(w.fd)
		w.fd = 0
	}
	w.disp.send(w.bufferID, 0) // wl_buffer.destroy
	w.createBuffer()
	return true
}

// Dispatch blocks until a user-facing event occurs (configure, close, or key).
func (d *Display) Dispatch() (EventType, error) {
	for {
		evt, err := d.dispatchOne()
		if err != nil {
			return EventNone, err
		}
		if evt != EventNone {
			return evt, nil
		}
	}
}

// Fd returns the underlying socket file descriptor for use with select/epoll.
func (d *Display) Fd() int { return d.fd }

// Poll checks whether there is data to read on the Wayland socket without
// blocking. If data is available it calls dispatchOne() and returns the event.
// Returns EventNone immediately when no data is ready.
func (d *Display) Poll() (EventType, error) {
	if d.fd < 0 {
		return EventNone, nil
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
	if len(d.keyEvents) == 0 {
		return KeyEvent{}, false
	}
	ev := d.keyEvents[0]
	d.keyEvents = d.keyEvents[1:]
	return ev, true
}

// ShiftDown returns the current shift key state.
func (d *Display) ShiftDown() bool { return d.shiftDown }

// SetWindowTitle sends xdg_toplevel.set_title to update the compositor's title bar.
func (d *Display) SetWindowTitle(win *Window, title string) {
	d.send(win.toplevelID, 2, pstr(title))
}

// HasNoSSD reports whether the compositor did NOT advertise zxdg_decoration_manager_v1,
// meaning we must draw client-side decorations ourselves.
func (d *Display) HasNoSSD() bool {
	return d.decorMgrGlobal == 0
}

// CtrlDown returns the current control key state.
func (d *Display) CtrlDown() bool { return d.ctrlDown }

// PollMouse returns the next queued mouse event, if any.
func (d *Display) PollMouse() (MouseEvent, bool) {
	if len(d.mouseEvents) == 0 {
		return MouseEvent{}, false
	}
	ev := d.mouseEvents[0]
	d.mouseEvents = d.mouseEvents[1:]
	return ev, true
}

// MousePos returns the current mouse position on the surface.
func (d *Display) MousePos() (int32, int32) { return d.mouseX, d.mouseY }

// Close tears down the Wayland connection.
func (d *Display) Close() {
	if d.win != nil {
		if d.win.Pix != nil {
			unix.Munmap(d.win.Pix)
		}
		if d.win.fd > 0 {
			unix.Close(d.win.fd)
		}
	}
	d.conn.Close()
}

// evdevToWin32 maps a Linux evdev keycode to a Win32 VK code and character.
func evdevToWin32(keycode uint32, shift bool) (vk uint32, ch rune) {
type keyMap struct {
vk      uint32
lower   rune
upper   rune
}

// Common evdev keycodes (KEY_* from input-event-codes.h)
table := map[uint32]keyMap{
1:  {0x1B, 0x1B, 0x1B},     // ESC
2:  {0x31, '1', '!'},        // 1
3:  {0x32, '2', '@'},        // 2
4:  {0x33, '3', '#'},        // 3
5:  {0x34, '4', '$'},        // 4
6:  {0x35, '5', '%'},        // 5
7:  {0x36, '6', '^'},        // 6
8:  {0x37, '7', '&'},        // 7
9:  {0x38, '8', '*'},        // 8
10: {0x39, '9', '('},        // 9
11: {0x30, '0', ')'},        // 0
12: {0xBD, '-', '_'},        // minus
13: {0xBB, '=', '+'},        // equal
14: {0x08, '\b', '\b'},      // backspace
15: {0x09, '\t', '\t'},      // tab
16: {0x51, 'q', 'Q'},
17: {0x57, 'w', 'W'},
18: {0x45, 'e', 'E'},
19: {0x52, 'r', 'R'},
20: {0x54, 't', 'T'},
21: {0x59, 'y', 'Y'},
22: {0x55, 'u', 'U'},
23: {0x49, 'i', 'I'},
24: {0x4F, 'o', 'O'},
25: {0x50, 'p', 'P'},
26: {0xDB, '[', '{'},
27: {0xDD, ']', '}'},
28: {0x0D, '\r', '\r'},      // enter
30: {0x41, 'a', 'A'},
31: {0x53, 's', 'S'},
32: {0x44, 'd', 'D'},
33: {0x46, 'f', 'F'},
34: {0x47, 'g', 'G'},
35: {0x48, 'h', 'H'},
36: {0x4A, 'j', 'J'},
37: {0x4B, 'k', 'K'},
38: {0x4C, 'l', 'L'},
39: {0xBA, ';', ':'},
40: {0xDE, '\'', '"'},
41: {0xC0, '`', '~'},
43: {0xDC, '\\', '|'},
44: {0x5A, 'z', 'Z'},
45: {0x58, 'x', 'X'},
46: {0x43, 'c', 'C'},
47: {0x56, 'v', 'V'},
48: {0x42, 'b', 'B'},
49: {0x4E, 'n', 'N'},
50: {0x4D, 'm', 'M'},
51: {0xBC, ',', '<'},
52: {0xBE, '.', '>'},
53: {0xBF, '/', '?'},
57: {0x20, ' ', ' '},        // space
// Function keys
59: {0x70, 0, 0}, // F1
60: {0x71, 0, 0}, // F2
61: {0x72, 0, 0}, // F3
62: {0x73, 0, 0}, // F4
63: {0x74, 0, 0}, // F5
64: {0x75, 0, 0}, // F6
65: {0x76, 0, 0}, // F7
66: {0x77, 0, 0}, // F8
67: {0x78, 0, 0}, // F9
68: {0x79, 0, 0}, // F10
87: {0x7A, 0, 0}, // F11
88: {0x7B, 0, 0}, // F12
// Navigation
102: {0x24, 0, 0}, // Home
103: {0x26, 0, 0}, // Up
104: {0x21, 0, 0}, // PageUp
105: {0x25, 0, 0}, // Left
106: {0x27, 0, 0}, // Right
107: {0x23, 0, 0}, // End
108: {0x28, 0, 0}, // Down
109: {0x22, 0, 0}, // PageDown
110: {0x2D, 0, 0}, // Insert
111: {0x2E, 0, 0}, // Delete
}

if km, ok := table[keycode]; ok {
ch := km.lower
if shift {
ch = km.upper
}
return km.vk, ch
}
return 0, 0
}
