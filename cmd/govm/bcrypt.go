package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerBcryptHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["bcrypt.dll"]
	if !ok {
		return
	}
	_ = dll
	readGuestUTF16 := hctx.ReadGuestUTF16

	d.RegisterAutoStubHandler(dll, "BCryptCloseAlgorithmProvider", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		dwFlags := ctx.Arg(1)
		ravelog.Logf("[bcrypt] BCryptCloseAlgorithmProvider handle=0x%x flags=0x%x\n", hAlgorithm, dwFlags)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptCreateHash", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		phHash := ctx.Arg(1)
		pbHashObject := ctx.Arg(2)
		cbHashObject := ctx.Arg(3)
		pbSecret := ctx.Arg(4)
		cbSecret := ctx.Arg(5)
		ravelog.Logf("[bcrypt] BCryptCreateHash alg=0x%x\n", hAlgorithm)
		_ = pbHashObject; _ = cbHashObject; _ = pbSecret; _ = cbSecret
		if phHash != 0 { ctx.Mem.Write64(phHash, 0xBC000010) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptDestroyHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		ravelog.Logf("[bcrypt] BCryptDestroyHash hash=0x%x\n", hHash)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[bcrypt] -stub(0x%x)\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptEnumAlgorithms", func(ctx *ntapi.TrapContext) uint32 {
		dwAlgOps := ctx.Arg(0)
		pAlgCount := ctx.Arg(1)
		ppAlgList := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		ravelog.Logf("[bcrypt] BCryptEnumAlgorithms ops=0x%x count=0x%x list=0x%x flags=0x%x\n", dwAlgOps, pAlgCount, ppAlgList, dwFlags)
		if pAlgCount != 0 { ctx.Mem.Write32(pAlgCount, 0) }
		if ppAlgList != 0 { ctx.Mem.Write64(ppAlgList, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptFinishHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbOutput := ctx.Arg(1)
		cbOutput := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		ravelog.Logf("[bcrypt] BCryptFinishHash hash=0x%x out=0x%x size=%d\n", hHash, pbOutput, cbOutput)
		_ = dwFlags
		// Write zero hash output
		for i := uint64(0); i < cbOutput; i++ { ctx.Mem.Write8(pbOutput+i, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptGenRandom", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		pbBuffer := ctx.Arg(1)
		cbBuffer := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		ravelog.Logf("[bcrypt] BCryptGenRandom handle=0x%x buf=0x%x size=%d flags=0x%x\n", hAlgorithm, pbBuffer, cbBuffer, dwFlags)
		// Fill buffer with pseudo-random data
		for i := uint64(0); i < cbBuffer; i++ {
			ctx.Mem.Write8(pbBuffer+i, byte(i*0x5DEECE66D+0xB))
		}
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptGetFipsAlgorithmMode", func(ctx *ntapi.TrapContext) uint32 {
		pfEnabled := ctx.Arg(0)
		ravelog.Logf("[bcrypt] BCryptGetFipsAlgorithmMode out=0x%x\n", pfEnabled)
		if pfEnabled != 0 { ctx.Mem.Write8(pfEnabled, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptGetProperty", func(ctx *ntapi.TrapContext) uint32 {
		hObject := ctx.Arg(0)
		pszProperty := ctx.Arg(1)
		pbOutput := ctx.Arg(2)
		cbOutput := ctx.Arg(3)
		pcbResult := ctx.Arg(4)
		dwFlags := ctx.Arg(5)
		var propName string
		if pszProperty != 0 { propName = readGuestUTF16(pszProperty) }
		ravelog.Logf("[bcrypt] BCryptGetProperty obj=0x%x prop=%q\n", hObject, propName)
		_ = pbOutput; _ = cbOutput; _ = dwFlags
		if pcbResult != 0 { ctx.Mem.Write32(pcbResult, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptHash", func(ctx *ntapi.TrapContext) uint32 {
		hAlg := ctx.Arg(0)
		pbSecret := ctx.Arg(1)
		cbSecret := ctx.Arg(2)
		pbInput := ctx.Arg(3)
		cbInput := ctx.Arg(4)
		pbOutput := ctx.Arg(5)
		cbOutput := ctx.Arg(6)
		ravelog.Logf("[bcrypt] BCryptHash alg=0x%x in=%d out=%d\n", hAlg, cbInput, cbOutput)
		_, _ = pbSecret, cbSecret
		_ = pbInput
		for i := uint64(0); i < cbOutput && i < 256; i++ { ctx.Mem.Write8(pbOutput+i, 0) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptHashData", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbInput := ctx.Arg(1)
		cbInput := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		ravelog.Logf("[bcrypt] BCryptHashData hash=0x%x input=0x%x size=%d\n", hHash, pbInput, cbInput)
		_ = dwFlags
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[bcrypt] -stub(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "BCryptOpenAlgorithmProvider", func(ctx *ntapi.TrapContext) uint32 {
		phAlgorithm := ctx.Arg(0)
		pszAlgId := ctx.Arg(1)
		pszImplementation := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		_ = pszImplementation; _ = dwFlags
		var algName string
		if pszAlgId != 0 { algName = readGuestUTF16(pszAlgId) }
		ravelog.Logf("[bcrypt] BCryptOpenAlgorithmProvider alg=%q flags=0x%x\n", algName, dwFlags)
		if phAlgorithm != 0 { ctx.Mem.Write64(phAlgorithm, 0xBC000001) }
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[bcrypt] -stub(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
}
