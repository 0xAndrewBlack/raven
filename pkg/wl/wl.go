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
)

// EventType returned by Dispatch.
type EventType int

const (
	EventNone      EventType = iota
	EventConfigure           // window was resized by compositor
	EventClose               // close requested
)

const shmFmtXRGB8888 = 1

// Display is a connection to a Wayland compositor.
type Display struct {
	conn    *net.UnixConn
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

	Width  int32
	Height int32
	Stride int32
	Pix    []byte // mmap'd XRGB8888 pixels (B, G, R, X per pixel)
	fd     int    // memfd backing Pix

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

func (d *Display) readEvent() (uint32, uint16, []byte, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(d.conn, hdr[:]); err != nil {
		return 0, 0, nil, fmt.Errorf("wayland recv: %w", err)
	}
	objID := gu32(hdr[0:])
	sizeOp := gu32(hdr[4:])
	sz := int(sizeOp >> 16)
	op := uint16(sizeOp & 0xFFFF)
	if sz < 8 {
		return 0, 0, nil, fmt.Errorf("wayland: bad msg size %d", sz)
	}
	payload := make([]byte, sz-8)
	if len(payload) > 0 {
		if _, err := io.ReadFull(d.conn, payload); err != nil {
			return 0, 0, nil, fmt.Errorf("wayland recv payload: %w", err)
		}
	}
	return objID, op, payload, nil
}

// dispatchOne reads and handles one event.
func (d *Display) dispatchOne() (EventType, error) {
	objID, op, payload, err := d.readEvent()
	if err != nil {
		return EventNone, err
	}
	kind, ok := d.objects[objID]
	if !ok {
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
	}
}

// roundtrip reads events until the given callback fires.
func (d *Display) roundtrip(callbackID uint32) error {
	for {
		objID, op, payload, err := d.readEvent()
		if err != nil {
			return err
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
func (d *Display) CreateWindow(title string, w, h int32) (*Window, error) {
	win := &Window{disp: d, Width: w, Height: h}

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
	d.send(win.surfaceID, 1, pu32(win.bufferID), pi32(0), pi32(0))            // attach
	d.send(win.surfaceID, 9, pi32(0), pi32(0), pi32(win.Width), pi32(win.Height)) // damage_buffer
	d.send(win.surfaceID, 6)                                                       // commit

	return win, nil
}

func (w *Window) createBuffer() error {
	w.Stride = w.Width * 4
	size := int(w.Stride * w.Height)

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
		pi32(w.Height),
		pi32(w.Stride),
		pu32(shmFmtXRGB8888),
	)

	// pool can be destroyed; buffer keeps the shm reference
	d.send(w.poolID, 1) // wl_shm_pool.destroy (opcode 1)

	return nil
}

// Commit submits the current pixel buffer to the compositor.
func (w *Window) Commit() {
	d := w.disp
	d.send(w.surfaceID, 1, pu32(w.bufferID), pi32(0), pi32(0))                    // attach
	d.send(w.surfaceID, 9, pi32(0), pi32(0), pi32(w.Width), pi32(w.Height)) // damage_buffer
	d.send(w.surfaceID, 6)                                                          // commit
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

// Dispatch blocks until a user-facing event occurs (configure or close).
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
