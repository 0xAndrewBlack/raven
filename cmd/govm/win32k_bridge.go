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
	"sort"

	"github.com/mirkobrombin/Raven/pkg/gfx"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/win32"
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

	// USER shared handle table (what real user32 ValidateHwnd reads).
	aheList     uint32            // guest addr of the HANDLEENTRY array
	aheCount    uint32            // number of entries
	gpsi        uint32            // guest addr of SERVERINFO
	wndProcOf   map[uint32]uint32 // class atom -> guest WndProc
	wndOf       map[uint32]uint32 // HWND -> guest WND object address
	lastWndProc uint32            // most-recently registered class WndProc
	heapNext    uint32            // bump allocator for USER kernel objects
}

// USER object layout constants (ReactOS, 32-bit). HANDLEENTRY = 12 bytes.
const (
	heSize         = 12    // sizeof(HANDLEENTRY)
	typeWindow     = 1     // TYPE_WINDOW
	wndStyle       = 0x20  // WND.style
	wndExStyle     = 0x1C  // WND.ExStyle
	wndRcWindow    = 0x40  // WND.rcWindow (RECT)
	wndRcClient    = 0x50  // WND.rcClient (RECT)
	wndLpfnWndProc = 0x60  // WND.lpfnWndProc
	wndPcls        = 0x64  // WND.pcls
	wndState       = 0x14  // WND.state
	wndSizeAlloc   = 0x100 // generous WND allocation
)

// userAlloc bumps a small guest region for USER kernel objects (WND/CLS/handle
// table). Allocated once from the MMU in setupSharedInfo.
func (b *win32kBridge) userAlloc(n uint32) uint32 {
	a := b.heapNext
	b.heapNext += (n + 15) &^ 15
	return a
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
		wndProcOf:    make(map[uint32]uint32),
		wndOf:        make(map[uint32]uint32),
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

// setupSharedInfo lazily allocates the USER shared region (HANDLEENTRY table +
// SERVERINFO + room for WND/CLS objects) and writes a USERCONNECT for the
// caller. Mirrors what win32k returns from NtUserProcessConnect; ulSharedDelta=0
// so kernel pointers == user pointers (single address space).
func (b *win32kBridge) setupSharedInfo(pUserConnect uint32) {
	if b.aheList == 0 {
		const region = 8 << 20 // 8 MiB for handle table + USER objects
		base := uint32(b.mem.Mmap(0, region, mmu.PermRead|mmu.PermWrite))
		b.aheCount = 0x4000
		b.aheList = base
		psi := base + b.aheCount*heSize          // SERVERINFO after the handle table
		b.mem.Write32(uint64(psi+4), b.aheCount) // cHandleEntries
		b.heapNext = psi + 0x600                 // objects after SERVERINFO
		b.gpsi = psi
	}
	if pUserConnect == 0 {
		return
	}
	// USERCONNECT: ulVersion@0, ulCurrentVersion@4, dwDispatchCount@8, siClient@12
	b.mem.Write32(uint64(pUserConnect+0), 0x00050000) // USER_VERSION
	b.mem.Write32(uint64(pUserConnect+4), 0x00050000)
	b.mem.Write32(uint64(pUserConnect+8), 0)
	// SHAREDINFO: psi@0, aheList@4, pDispInfo@8, ulSharedDelta@12
	si := pUserConnect + 12
	b.mem.Write32(uint64(si+0), b.gpsi)
	b.mem.Write32(uint64(si+4), b.aheList)
	b.mem.Write32(uint64(si+8), 0)
	b.mem.Write32(uint64(si+12), 0) // ulSharedDelta = 0
}

// createWND allocates a WND object, fills the fields real user32 reads, and
// registers its HANDLEENTRY so ValidateHwnd(hwnd) resolves. wndproc is the
// guest WndProc (from the class). Returns the WND guest address.
func (b *win32kBridge) createWND(hwnd, style, exStyle, wndproc, pcls uint32, x, y, w, h int32) uint32 {
	wnd := b.userAlloc(wndSizeAlloc)
	for i := uint32(0); i < wndSizeAlloc; i += 4 {
		b.mem.Write32(uint64(wnd+i), 0)
	}
	b.mem.Write32(uint64(wnd+0), hwnd) // head.h
	b.mem.Write32(uint64(wnd+16), wnd) // head.pSelf (delta 0)
	b.mem.Write32(uint64(wnd+wndState), 0)
	b.mem.Write32(uint64(wnd+wndExStyle), exStyle)
	b.mem.Write32(uint64(wnd+wndStyle), style)
	b.mem.Write32(uint64(wnd+wndRcWindow+0), uint32(x))
	b.mem.Write32(uint64(wnd+wndRcWindow+4), uint32(y))
	b.mem.Write32(uint64(wnd+wndRcWindow+8), uint32(x+w))
	b.mem.Write32(uint64(wnd+wndRcWindow+12), uint32(y+h))
	b.mem.Write32(uint64(wnd+wndRcClient+0), uint32(x))
	b.mem.Write32(uint64(wnd+wndRcClient+4), uint32(y))
	b.mem.Write32(uint64(wnd+wndRcClient+8), uint32(x+w))
	b.mem.Write32(uint64(wnd+wndRcClient+12), uint32(y+h))
	b.mem.Write32(uint64(wnd+wndLpfnWndProc), wndproc)
	b.mem.Write32(uint64(wnd+wndPcls), pcls)
	// register HANDLEENTRY[index]
	idx := hwnd & 0xFFFF
	if idx < b.aheCount {
		e := b.aheList + idx*heSize
		b.mem.Write32(uint64(e+0), wnd) // phead
		b.mem.Write32(uint64(e+4), 0)   // pOwner
		b.mem.Write8(uint64(e+8), typeWindow)
		b.mem.Write8(uint64(e+9), 0)
		b.mem.Write16(uint64(e+10), uint16(hwnd>>16)) // wUniq
	}
	b.wndOf[hwnd] = wnd
	return wnd
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

	z := b.wm.TopLevelZOrder(true) // front..back
	if len(z) > 0 {
		for i := len(z) - 1; i >= 0; i-- { // paint back-to-front
			r, ok := b.wm.WindowRect(z[i])
			if !ok {
				continue
			}
			rect := gfx.Rect{Left: int(r.Left), Top: int(r.Top), Right: int(r.Right), Bottom: int(r.Bottom)}
			b.renderWindowFrame(rect, fmt.Sprintf("Raven Window %#x", uint32(z[i])))
		}
	} else {
		b.renderHLEWindows()
	}

	img := image.NewRGBA(image.Rect(0, 0, b.screen.W, b.screen.H))
	for i, p := range b.screen.Pix {
		// ARGB (0xAARRGGBB) -> RGBA bytes
		img.Pix[i*4+0] = byte(p >> 16)
		img.Pix[i*4+1] = byte(p >> 8)
		img.Pix[i*4+2] = byte(p)
		img.Pix[i*4+3] = byte(p >> 24)
	}
	tmpPath := path + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func (b *win32kBridge) renderWindowFrame(rect gfx.Rect, title string) {
	const titleH = 22
	b.screen.FillRect(gfx.Rect{rect.Left, rect.Top, rect.Right, rect.Top + titleH}, 0xFF3B6EA5)
	b.screen.FillRect(gfx.Rect{rect.Left, rect.Top + titleH, rect.Right, rect.Bottom}, 0xFFF2F2F2)
	b.screen.FrameRect(rect, 0xFF101010)
	if b.fontID >= 0 {
		b.fonts.DrawText(b.screen, title, rect.Left+8, rect.Top+16, b.fontID, 14, 0xFFFFFFFF)
	}
}

func (b *win32kBridge) renderHLEWindows() {
	handles := win32.Global.AllWindows()
	sort.Slice(handles, func(i, j int) bool { return handles[i] < handles[j] })
	topLevels := make([]uint64, 0, len(handles))
	for _, h := range handles {
		wnd := win32.Global.Get(h)
		if wnd == nil || wnd.Parent != 0 || wnd.RcWindow.Empty() || isRenderableControlClass(wnd.ClassName) {
			continue
		}
		topLevels = append(topLevels, h)
	}
	for _, h := range topLevels {
		wnd := win32.Global.Get(h)
		if wnd == nil {
			continue
		}
		rect := gfx.Rect{Left: int(wnd.RcWindow.Left), Top: int(wnd.RcWindow.Top), Right: int(wnd.RcWindow.Right), Bottom: int(wnd.RcWindow.Bottom)}
		title := wnd.ClassName
		if title == "" {
			title = fmt.Sprintf("HWND %#x", h)
		}
		b.renderWindowFrame(rect, title)
		for _, ch := range handles {
			child := win32.Global.Get(ch)
			if child == nil || child.Parent != h || child.RcWindow.Empty() || child.ClassName == "tooltips_class32" {
				continue
			}
			r := gfx.Rect{Left: int(child.RcWindow.Left), Top: int(child.RcWindow.Top), Right: int(child.RcWindow.Right), Bottom: int(child.RcWindow.Bottom)}
			fill := uint32(0xFFECE9D8)
			switch child.ClassName {
			case "scintilla":
				fill = 0xFFFFFFFF
			case "tooltips_class32":
				fill = 0xFFFFFFE1
			case "msctls_statusbar32":
				fill = 0xFFF0F0F0
			}
			b.screen.FillRect(r, fill)
			b.screen.FrameRect(r, 0xFF9A9A9A)
			if b.fontID >= 0 && child.ClassName != "" && r.Right-r.Left > 80 && r.Bottom-r.Top > 18 {
				b.fonts.DrawText(b.screen, child.ClassName, r.Left+4, r.Top+14, b.fontID, 11, 0xFF202020)
			}
		}
	}
}

func isRenderableControlClass(className string) bool {
	switch className {
	case "tooltips_class32", "rebarwindow32", "toolbarwindow32", "msctls_statusbar32", "systabcontrol32", "scintilla":
		return true
	default:
		return false
	}
}
