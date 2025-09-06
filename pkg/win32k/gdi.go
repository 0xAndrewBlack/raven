package win32k

import (
	"github.com/mirkobrombin/go-vm/pkg/mmu"
	"github.com/mirkobrombin/go-vm/pkg/ntapi"
)

// GDISubsystem handles GDI rendering operations using MMU-backed pixel buffers.
// In the future, these buffers will be shared with the Wayland compositor
// via wl_shm for zero-copy rendering.
type GDISubsystem struct {
	mem   *mmu.MMU
	w     *Win32kSubsystem
}

// NewGDI creates the GDI rendering subsystem.
func NewGDI(mem *mmu.MMU, w *Win32kSubsystem) *GDISubsystem {
	return &GDISubsystem{mem: mem, w: w}
}

// RegisterHandlers registers GDI-specific trap handlers.
func (g *GDISubsystem) RegisterHandlers(d *ntapi.Dispatcher) {
	d.RegisterWin32kHandler("NtGdiCreateDIBSection", g.handleCreateDIBSection)
	d.RegisterWin32kHandler("NtGdiBitBlt", g.handleBitBlt)
	d.RegisterWin32kHandler("NtGdiExtTextOutW", g.handleExtTextOut)
	d.RegisterWin32kHandler("NtGdiTextOutW", g.handleTextOut)
	d.RegisterWin32kHandler("NtGdiGetTextExtentPoint32W", g.handleGetTextExtent)
	d.RegisterWin32kHandler("NtGdiCreateSolidBrush", g.handleCreateSolidBrush)
	d.RegisterWin32kHandler("NtGdiCreatePen", g.handleCreatePen)
	d.RegisterWin32kHandler("NtGdiPolyline", g.handlePolyline)
	d.RegisterWin32kHandler("NtGdiEllipse", g.handleEllipse)
	d.RegisterWin32kHandler("NtGdiCreateFontIndirectW", g.handleCreateFont)
	d.RegisterWin32kHandler("NtGdiStretchBlt", g.handleStretchBlt)
}

// handleCreateDIBSection allocates a pixel buffer in guest memory.
// This buffer can later be shared with the Wayland compositor via wl_shm.
func (g *GDISubsystem) handleCreateDIBSection(ctx *ntapi.TrapContext) uint32 {
	// Simplified: allocate a 1920x1080x32bpp buffer
	width := int32(1920)
	height := int32(1080)
	stride := width * 4
	bufSize := uint64(stride) * uint64(abs32(height))

	// Allocate pixel buffer in guest MMU
	bufAddr := ctx.Mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)

	// Return bitmap handle (using bufAddr as handle for now)
	ctx.CPU.SetSyscallReturn(bufAddr)
	return uint32(bufAddr & 0xFFFFFFFF)
}

func (g *GDISubsystem) handleBitBlt(ctx *ntapi.TrapContext) uint32 {
	// BitBlt: copy rectangle between DCs
	// In a real implementation, this copies pixels between MMU buffers.
	ctx.CPU.SetSyscallReturn(1) // TRUE
	return 1
}

func (g *GDISubsystem) handleStretchBlt(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleExtTextOut(ctx *ntapi.TrapContext) uint32 {
	// ExtTextOutW: render text to a DC
	// In a real implementation, this would rasterize with golang.org/x/image/font
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleTextOut(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleGetTextExtent(ctx *ntapi.TrapContext) uint32 {
	// Return dummy text extent: 8px per char width, 16px height
	sizeAddr := ctx.Arg(3)
	if sizeAddr != 0 {
		strLen := ctx.Arg(2)
		ctx.Mem.Write32(sizeAddr+0, uint32(strLen*8)) // cx
		ctx.Mem.Write32(sizeAddr+4, 16)               // cy
	}
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleCreateSolidBrush(ctx *ntapi.TrapContext) uint32 {
	color := ctx.Arg(0)
	// Return a unique handle embedding the color
	handle := 0x80000000 | (color & 0x00FFFFFF)
	ctx.CPU.SetSyscallReturn(handle)
	return uint32(handle)
}

func (g *GDISubsystem) handleCreatePen(ctx *ntapi.TrapContext) uint32 {
	handle := uint64(0x90000001)
	ctx.CPU.SetSyscallReturn(handle)
	return uint32(handle)
}

func (g *GDISubsystem) handlePolyline(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleEllipse(ctx *ntapi.TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

func (g *GDISubsystem) handleCreateFont(ctx *ntapi.TrapContext) uint32 {
	handle := uint64(0xA0000001)
	ctx.CPU.SetSyscallReturn(handle)
	return uint32(handle)
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}
