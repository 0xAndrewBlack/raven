package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerMsimg32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["msimg32.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "vSetDdrawflag", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[msimg32] vSetDdrawflag()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "AlphaBlend", func(ctx *ntapi.TrapContext) uint32 {
		hdcDest := ctx.Arg(0)
		xoriginDest := ctx.Arg(1)
		yoriginDest := ctx.Arg(2)
		wDest := ctx.Arg(3)
		hDest := ctx.Arg(4)
		hdcSrc := ctx.Arg(5)
		ravelog.Logf("[msimg32] AlphaBlend dest=0x%x src=0x%x (%d,%d %dx%d)\n", hdcDest, hdcSrc, xoriginDest, yoriginDest, wDest, hDest)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-private", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[msimg32] -private(0x%x, 0x%x, 0x%x)\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GradientFill", func(ctx *ntapi.TrapContext) uint32 {
		hdc := ctx.Arg(0)
		pVertex := ctx.Arg(1)
		nVertex := ctx.Arg(2)
		pMesh := ctx.Arg(3)
		nMesh := ctx.Arg(4)
		ulMode := ctx.Arg(5)
		ravelog.Logf("[msimg32] GradientFill hdc=0x%x vertices=%d mesh=%d mode=%d\n", hdc, nVertex, nMesh, ulMode)
		_ = pVertex
		_ = pMesh
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "TransparentBlt", func(ctx *ntapi.TrapContext) uint32 {
		hdcDest := ctx.Arg(0)
		xoriginDest := ctx.Arg(1)
		yoriginDest := ctx.Arg(2)
		wDest := ctx.Arg(3)
		hDest := ctx.Arg(4)
		hdcSrc := ctx.Arg(5)
		ravelog.Logf("[msimg32] TransparentBlt dest=0x%x src=0x%x (%d,%d %dx%d)\n", hdcDest, hdcSrc, xoriginDest, yoriginDest, wDest, hDest)
		ctx.SetReturn(1) // TRUE
		return 0
	})
}
