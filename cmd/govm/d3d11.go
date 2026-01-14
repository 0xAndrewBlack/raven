package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerD3d11Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["d3d11.dll"]
	if !ok {
		return
	}

	// D3D11CreateDevice - most apps call this to probe GPU support.
	// Return DXGI_ERROR_UNSUPPORTED (0x887A0004) to signal no D3D11 device.
	// Well-behaved apps fall back to software rendering or GDI.
	d.RegisterAutoStubHandler(dll, "D3D11CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[d3d11] D3D11CreateDevice → DXGI_ERROR_UNSUPPORTED\n")
		ctx.SetReturn(0x887A0004) // DXGI_ERROR_UNSUPPORTED
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11CreateDeviceAndSwapChain", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[d3d11] D3D11CreateDeviceAndSwapChain → DXGI_ERROR_UNSUPPORTED\n")
		ctx.SetReturn(0x887A0004)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "D3D11On12CreateDevice", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x887A0004)
		return 0
	})

	// DXGI stubs - often imported alongside D3D11
	dxgi, dxgiOK := hctx.SynthByName["dxgi.dll"]
	if dxgiOK {
		d.RegisterAutoStubHandler(dxgi, "CreateDXGIFactory", func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[dxgi] CreateDXGIFactory → DXGI_ERROR_UNSUPPORTED\n")
			ctx.SetReturn(0x887A0004)
			return 0
		})
		d.RegisterAutoStubHandler(dxgi, "CreateDXGIFactory1", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x887A0004)
			return 0
		})
		d.RegisterAutoStubHandler(dxgi, "CreateDXGIFactory2", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x887A0004)
			return 0
		})
		d.RegisterAutoStubHandler(dxgi, "DXGIGetDebugInterface1", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0x887A0004)
			return 0
		})
	}
}

func registerOpengl32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["opengl32.dll"]
	if !ok {
		return
	}

	// wglCreateContext - apps call this to create an OpenGL context.
	// Return NULL to indicate no OpenGL support; apps fall back to GDI.
	d.RegisterAutoStubHandler(dll, "wglCreateContext", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[opengl32] wglCreateContext → NULL (no GL support)\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglMakeCurrent", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglDeleteContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglGetProcAddress", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - no GL extensions
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglGetCurrentContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglGetCurrentDC", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglShareLists", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglDescribePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // 0 pixel formats available
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglChoosePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // no matching format
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglSetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "wglSwapBuffers", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	// ChoosePixelFormat / DescribePixelFormat / SetPixelFormat are in gdi32
	// but some apps import them from opengl32
	d.RegisterAutoStubHandler(dll, "ChoosePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DescribePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SwapBuffers", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
}
