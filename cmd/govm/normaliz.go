package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerNormalizHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["normaliz.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "IdnToAscii", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		lpUnicodeCharStr := ctx.Arg(1)
		cchUnicodeChar := ctx.Arg(2)
		lpASCIICharStr := ctx.Arg(3)
		cchASCIIChar := ctx.Arg(4)
		ravelog.Logf("[normaliz] IdnToAscii flags=0x%x src=0x%x len=%d\n", dwFlags, lpUnicodeCharStr, cchUnicodeChar)
		// Copy input to output (passthrough for ASCII-compatible input)
		if lpASCIICharStr != 0 && cchASCIIChar > 0 {
			for i := uint64(0); i < cchUnicodeChar && i < cchASCIIChar; i++ {
				ch, _ := ctx.Mem.Read16(lpUnicodeCharStr + i*2)
				ctx.Mem.Write16(lpASCIICharStr+i*2, ch)
			}
		}
		ctx.SetReturn(cchUnicodeChar) // return chars written
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IdnToNameprepUnicode", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		lpUnicodeCharStr := ctx.Arg(1)
		cchUnicodeChar := ctx.Arg(2)
		lpNameprepCharStr := ctx.Arg(3)
		cchNameprepChar := ctx.Arg(4)
		ravelog.Logf("[normaliz] IdnToNameprepUnicode flags=0x%x len=%d\n", dwFlags, cchUnicodeChar)
		if lpNameprepCharStr != 0 && cchNameprepChar > 0 {
			for i := uint64(0); i < cchUnicodeChar && i < cchNameprepChar; i++ {
				ch, _ := ctx.Mem.Read16(lpUnicodeCharStr + i*2)
				ctx.Mem.Write16(lpNameprepCharStr+i*2, ch)
			}
		}
		ctx.SetReturn(cchUnicodeChar)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IdnToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		lpASCIICharStr := ctx.Arg(1)
		cchASCIIChar := ctx.Arg(2)
		lpUnicodeCharStr := ctx.Arg(3)
		cchUnicodeChar := ctx.Arg(4)
		ravelog.Logf("[normaliz] IdnToUnicode flags=0x%x len=%d\n", dwFlags, cchASCIIChar)
		if lpUnicodeCharStr != 0 && cchUnicodeChar > 0 {
			for i := uint64(0); i < cchASCIIChar && i < cchUnicodeChar; i++ {
				ch, _ := ctx.Mem.Read16(lpASCIICharStr + i*2)
				ctx.Mem.Write16(lpUnicodeCharStr+i*2, ch)
			}
		}
		ctx.SetReturn(cchASCIIChar)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "IsNormalizedString", func(ctx *ntapi.TrapContext) uint32 {
		NormForm := ctx.Arg(0)
		lpString := ctx.Arg(1)
		cwLength := ctx.Arg(2)
		ravelog.Logf("[normaliz] IsNormalizedString form=%d str=0x%x len=%d\n", NormForm, lpString, cwLength)
		ctx.SetReturn(1) // TRUE - assume already normalized
		return 0
	})
	d.RegisterAutoStubHandler(dll, "NormalizeString", func(ctx *ntapi.TrapContext) uint32 {
		NormForm := ctx.Arg(0)
		lpSrcString := ctx.Arg(1)
		cwSrcLength := ctx.Arg(2)
		lpDstString := ctx.Arg(3)
		cwDstLength := ctx.Arg(4)
		ravelog.Logf("[normaliz] NormalizeString form=%d src=0x%x slen=%d\n", NormForm, lpSrcString, cwSrcLength)
		// Passthrough copy (already normalized)
		if lpDstString != 0 && cwDstLength > 0 {
			for i := uint64(0); i < cwSrcLength && i < cwDstLength; i++ {
				ch, _ := ctx.Mem.Read16(lpSrcString + i*2)
				ctx.Mem.Write16(lpDstString+i*2, ch)
			}
		}
		ctx.SetReturn(cwSrcLength) // return required length
		return 0
	})
}
