//go:build guest_windows

package main

// win32k_bridge wires the pure-Go GUI engines (pkg/winmgr window manager, pkg/gfx
// GDI) to the guest via NUMBER-INDEXED win32k syscalls - the path real
// gdi32/user32/win32u DLLs use (they issue `syscall` with a service index, not a
// vmcall import thunk). This lets DLLs run on top
// of the engines built in Phases 3-4.
//
// The service indices here are PLACEHOLDERS structured like the ReactOS shadow
// SSDT; they must be regenerated from the pinned ReactOS win32k table before
// running real DLLs . The dispatch machinery
// and the marshalling pattern are final.

import (
	"fmt"
	"image"
	"image/png"
	"os"

	"github.com/mirkobrombin/Raven/pkg/gfx"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/winmgr"
)

// win32k service indices (placeholder numbering, pin to ReactOS).
const (
	sysNtUserCreateWindow  = 0x1000
	sysNtUserShowWindow    = 0x1001
	sysNtUserDestroyWindow = 0x1002
	sysNtUserGetWindowRect = 0x1003
	sysNtUserWindowFromPt  = 0x1004
	sysNtGdiFillRect       = 0x2000
)

// win32kBridge owns the engine instances and the syscall table.
type win32kBridge struct {
	mem     *mmu.MMU
	wm      *winmgr.Manager
	menus   *winmgr.MenuTable
	gdiObjs *gfx.ObjectTable
	screen  *gfx.Surface // the desktop/compositor surface NtGdi draws into
	table   *winmgr.SyscallTable
	fonts   *gfx.FontCache
	fontID  int
	classOK bool

	// DLL message-loop and paint state.
	paintQueue   []winmgr.HWND      // windows awaiting their first WM_PAINT
	paintDCs     map[uint32]paintDC // HDC -> client-area origin on screen
	nextPaintHDC uint32             // HDC allocator for BeginPaint
}

// paintDC binds a BeginPaint HDC to where its window's client area lives on the
// screen surface, so real gdi32 NtGdi* draws land in the right place.
type paintDC struct {
	originX, originY int
	w, h             int
}

func newWin32kBridge(mem *mmu.MMU, screenW, screenH int) *win32kBridge {
	b := &win32kBridge{
		mem:          mem,
		wm:           winmgr.New(),
		menus:        winmgr.NewMenuTable(),
		gdiObjs:      gfx.NewObjectTable(),
		screen:       gfx.NewSurface(screenW, screenH),
		table:        winmgr.NewSyscallTable(),
		fonts:        gfx.NewFontCache(),
		fontID:       -1,
		paintDCs:     make(map[uint32]paintDC),
		nextPaintHDC: 0xDC000001,
	}
	for _, p := range []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
	} {
		if id, err := b.fonts.LoadFile(p); err == nil {
			b.fontID = id
			break
		}
	}
	b.register()
	return b
}

// ensureClass registers the default class the bridge uses when the guest hasn't
// gone through NtUserRegisterClassExWOW yet (real user32 will register its own).
func (b *win32kBridge) ensureClass() {
	if !b.classOK {
		b.wm.RegisterClass(&winmgr.Class{Name: "RavenWindow"})
		b.classOK = true
	}
}

// beginPaintDC allocates an HDC bound to the window's client area on the screen
// surface (client = window rect minus the caption bar drawn by RenderPNG).
func (b *win32kBridge) beginPaintDC(hwnd winmgr.HWND) uint32 {
	const titleH = 22
	hdc := b.nextPaintHDC
	b.nextPaintHDC++
	pdc := paintDC{originX: 0, originY: 0, w: b.screen.W, h: b.screen.H}
	if r, ok := b.wm.WindowRect(hwnd); ok {
		pdc = paintDC{
			originX: int(r.Left), originY: int(r.Top) + titleH,
			w: int(r.Right - r.Left), h: int(r.Bottom-r.Top) - titleH,
		}
	}
	b.paintDCs[hdc] = pdc
	return hdc
}

func (b *win32kBridge) register() {
	// NtUserCreateWindow(style, x, y, (w<<16)|h) -> HWND
	b.table.Register(sysNtUserCreateWindow, "NtUserCreateWindow", func(a []uint64) uint64 {
		b.ensureClass()
		wh := a[3]
		win := b.wm.CreateWindow(winmgr.CreateWindowParams{
			ClassName: "RavenWindow",
			Style:     uint32(a[0]),
			X:         int32(int32(uint32(a[1]))),
			Y:         int32(int32(uint32(a[2]))),
			W:         int32(wh >> 16),
			H:         int32(wh & 0xFFFF),
		})
		if win == nil {
			return 0
		}
		return uint64(win.Handle)
	})

	// NtUserShowWindow(hwnd, show) -> previous visible (0/1)
	b.table.Register(sysNtUserShowWindow, "NtUserShowWindow", func(a []uint64) uint64 {
		if b.wm.ShowWindow(winmgr.HWND(uint32(a[0])), a[1] != 0) {
			return 1
		}
		return 0
	})

	// NtUserDestroyWindow(hwnd) -> BOOL
	b.table.Register(sysNtUserDestroyWindow, "NtUserDestroyWindow", func(a []uint64) uint64 {
		if b.wm.DestroyWindow(winmgr.HWND(uint32(a[0]))) {
			return 1
		}
		return 0
	})

	// NtUserGetWindowRect(hwnd, pRect) -> BOOL; writes RECT{l,t,r,b} to guest mem.
	b.table.Register(sysNtUserGetWindowRect, "NtUserGetWindowRect", func(a []uint64) uint64 {
		r, ok := b.wm.WindowRect(winmgr.HWND(uint32(a[0])))
		if !ok {
			return 0
		}
		p := a[1]
		b.mem.Write32(p+0, uint32(r.Left))
		b.mem.Write32(p+4, uint32(r.Top))
		b.mem.Write32(p+8, uint32(r.Right))
		b.mem.Write32(p+12, uint32(r.Bottom))
		return 1
	})

	// NtUserWindowFromPoint(x, y) -> HWND
	b.table.Register(sysNtUserWindowFromPt, "NtUserWindowFromPoint", func(a []uint64) uint64 {
		return uint64(b.wm.WindowFromPoint(int32(int32(uint32(a[0]))), int32(int32(uint32(a[1])))))
	})

	// NtGdiFillSolidRect(l, t, (r<<16)|b? no -> pack: l,t,r,b in two args) ...
	// NtGdiFillRect(packedLT, packedRB, colorref) -> BOOL. Fills the screen surface.
	b.table.Register(sysNtGdiFillRect, "NtGdiFillRect", func(a []uint64) uint64 {
		lt, rb := a[0], a[1]
		rect := gfx.Rect{
			Left:   int(int32(uint32(lt >> 32))),
			Top:    int(int32(uint32(lt))),
			Right:  int(int32(uint32(rb >> 32))),
			Bottom: int(int32(uint32(rb))),
		}
		b.screen.FillRect(rect, gfx.FromCOLORREF(uint32(a[2])))
		return 1
	})
}

// dispatch routes a numbered win32k syscall. ok=false if the index is unbound
// (the caller then returns STATUS_NOT_IMPLEMENTED).
func (b *win32kBridge) dispatch(index uint32, args []uint64) (ret uint64, name string, ok bool) {
	ret, ok = b.table.Dispatch(index, args)
	if ok {
		name, _ = b.table.NameOf(index)
	}
	return ret, name, ok
}

// RenderPNG composites every visible top-level window (back-to-front in z-order)
// onto the desktop surface - title bar, client area, frame and title text drawn
// by the engine (pkg/gfx, real TrueType) - and writes the result as a PNG. This
// is the visual end-to-end proof of the window manager, GDI
// raster, text, compositor and syscall bridge, driven entirely
// by guest code, with no ReactOS DLL involved.
func (b *win32kBridge) RenderPNG(path string) error {
	b.screen.ResetClip()
	b.screen.FillRect(b.screen.Bounds(), 0xFF1E1E2E) // desktop background

	z := b.wm.TopLevelZOrder(true)     // front..back
	for i := len(z) - 1; i >= 0; i-- { // paint back-to-front
		r, ok := b.wm.WindowRect(z[i])
		if !ok {
			continue
		}
		rect := gfx.Rect{Left: int(r.Left), Top: int(r.Top), Right: int(r.Right), Bottom: int(r.Bottom)}
		const titleH = 22
		b.screen.FillRect(gfx.Rect{rect.Left, rect.Top, rect.Right, rect.Top + titleH}, 0xFF3B6EA5)    // caption
		b.screen.FillRect(gfx.Rect{rect.Left, rect.Top + titleH, rect.Right, rect.Bottom}, 0xFFF2F2F2) // client
		b.screen.FrameRect(rect, 0xFF101010)                                                           // frame
		if b.fontID >= 0 {
			b.fonts.DrawText(b.screen, fmt.Sprintf("Raven Window %#x", uint32(z[i])),
				rect.Left+8, rect.Top+16, b.fontID, 14, 0xFFFFFFFF)
			b.fonts.DrawText(b.screen, "rendered by pkg/winmgr + pkg/gfx (no Wine, no ReactOS DLL yet)",
				rect.Left+10, rect.Top+titleH+24, b.fontID, 13, 0xFF202020)
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, b.screen.W, b.screen.H))
	for i, p := range b.screen.Pix {
		// ARGB (0xAARRGGBB) -> RGBA bytes
		img.Pix[i*4+0] = byte(p >> 16)
		img.Pix[i*4+1] = byte(p >> 8)
		img.Pix[i*4+2] = byte(p)
		img.Pix[i*4+3] = byte(p >> 24)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}
