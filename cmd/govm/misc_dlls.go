package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerUxthemeHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	uxtheme, ok := hctx.SynthByName["uxtheme.dll"]
	if !ok {
		return
	}
	_ = uxtheme

	d.RegisterAutoStubHandler(uxtheme, "SetWindowTheme", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK - we don't support visual themes
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "OpenThemeData", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - no theme data
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "CloseThemeData", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		ravelog.Logf("[uxtheme] CloseThemeData hTheme=0x%x\n", hTheme)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeBackground", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] DrawThemeBackground hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeText", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] DrawThemeText hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeColor", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		iPartId := int32(ctx.Arg(1))
		iStateId := int32(ctx.Arg(2))
		iPropId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeColor hTheme=0x%x part=%d state=%d prop=%d\n", hTheme, iPartId, iStateId, iPropId)
		ctx.SetReturn(0x80070006) // E_HANDLE - no theme handle
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeInt", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		iPartId := int32(ctx.Arg(1))
		iStateId := int32(ctx.Arg(2))
		iPropId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeInt hTheme=0x%x part=%d state=%d prop=%d\n", hTheme, iPartId, iStateId, iPropId)
		ctx.SetReturn(0x80070006) // E_HANDLE
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeMetric", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeMetric hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80070006) // E_HANDLE
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeFont", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeFont hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeRect", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		iPartId := int32(ctx.Arg(1))
		iStateId := int32(ctx.Arg(2))
		iPropId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeRect hTheme=0x%x part=%d state=%d prop=%d\n", hTheme, iPartId, iStateId, iPropId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemePartSize", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemePartSize hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTextExtent", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		hdc := ctx.Arg(1)
		iPartId := int32(ctx.Arg(2))
		iStateId := int32(ctx.Arg(3))
		ravelog.Logf("[uxtheme] GetThemeTextExtent hTheme=0x%x hdc=0x%x part=%d state=%d\n", hTheme, hdc, iPartId, iStateId)
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeActive", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[uxtheme] IsThemeActive -> FALSE (themes disabled)\n")
		ctx.SetReturn(0) // FALSE - themes disabled
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsAppThemed", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[uxtheme] IsAppThemed -> FALSE\n")
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "IsThemeBackgroundPartiallyTransparent", func(ctx *ntapi.TrapContext) uint32 {
		hTheme := ctx.Arg(0)
		iPartId := int32(ctx.Arg(1))
		iStateId := int32(ctx.Arg(2))
		ravelog.Logf("[uxtheme] IsThemeBackgroundPartiallyTransparent hTheme=0x%x part=%d state=%d\n", hTheme, iPartId, iStateId)
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeParentBackground", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		hdc := ctx.Arg(1)
		pRect := ctx.Arg(2)
		ravelog.Logf("[uxtheme] DrawThemeParentBackground hwnd=0x%x hdc=0x%x rect=0x%x\n", hwnd, hdc, pRect)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintInit", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintUnInit", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[uxtheme] BufferedPaintUnInit called\n")
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EndBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeTransitionDuration", func(ctx *ntapi.TrapContext) uint32 {
		pdwDuration := ctx.Arg(4)
		if pdwDuration != 0 {
			ctx.Mem.Write32(pdwDuration, 0)
		}
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "GetThemeBackgroundContentRect", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "EnableThemeDialogTexture", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "DrawThemeTextEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004001) // E_NOTIMPL
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintStopAllAnimations", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BeginBufferedAnimation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - no animation handle
		return 0
	})
	d.RegisterAutoStubHandler(uxtheme, "BufferedPaintRenderAnimation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - no animation to render
		return 0
	})
}

func registerMprHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	mpr, ok := hctx.SynthByName["mpr.dll"]
	if !ok {
		return
	}
	_ = mpr

	d.RegisterAutoStubHandler(mpr, "WNetGetProviderNameA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1203) // ERROR_NO_NET_OR_BAD_PATH
		return 0
	})
	d.RegisterAutoStubHandler(mpr, "WNetGetProviderNameW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1203) // ERROR_NO_NET_OR_BAD_PATH
		return 0
	})
}

func registerIphlpapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	iphlpapi, ok := hctx.SynthByName["iphlpapi.dll"]
	if !ok {
		return
	}
	_ = iphlpapi

	// GetAdaptersAddresses: return ERROR_NO_DATA (no adapters to enumerate)
	d.RegisterAutoStubHandler(iphlpapi, "GetAdaptersAddresses", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(232) // ERROR_NO_DATA
		return 0
	})
}

func registerVersionHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16

	version, ok := hctx.SynthByName["version.dll"]
	if !ok {
		return
	}
	_ = version

	versionBuf := mem.Mmap(0, 128, mmu.PermRead|mmu.PermWrite)
	mem.Write32(versionBuf+0, 0xFEEF04BD)  // dwSignature
	mem.Write32(versionBuf+4, 0x00010000)  // dwStrucVersion
	mem.Write32(versionBuf+8, 0x00080007)  // dwFileVersionMS (8.7)
	mem.Write32(versionBuf+12, 0x00060000) // dwFileVersionLS
	mem.Write32(versionBuf+16, 0x00080007) // dwProductVersionMS
	mem.Write32(versionBuf+20, 0x00060000) // dwProductVersionLS
	mem.Write32(versionBuf+24, 0x0000003F) // dwFileFlagsMask
	mem.Write32(versionBuf+28, 0)          // dwFileFlags
	mem.Write32(versionBuf+32, 0x00040004) // dwFileOS (VOS_NT_WINDOWS32)
	mem.Write32(versionBuf+36, 1)          // dwFileType (VFT_APP)

	setLastError := func(ctx *ntapi.TrapContext, code uint32) {
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			ctx.Mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, code)
		}
	}

	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeW", func(ctx *ntapi.TrapContext) uint32 {
		pHandle := ctx.Arg(1)
		if pHandle != 0 {
			ctx.Mem.Write32(pHandle, 0)
		}
		setLastError(ctx, 0) // ERROR_SUCCESS
		ctx.SetReturn(128)   // fake non-zero size
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
		lpData := ctx.Arg(3)
		if lpData != 0 {
			for i := uint64(0); i < 52; i += 4 {
				v, _ := ctx.Mem.Read32(versionBuf + i)
				ctx.Mem.Write32(lpData+i, v)
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerQueryValueW", func(ctx *ntapi.TrapContext) uint32 {
		pBlock := ctx.Arg(0)
		lpSubBlock := ctx.Arg(1)
		lplpBuffer := ctx.Arg(2)
		puLen := ctx.Arg(3)
		sub := readGuestUTF16(lpSubBlock)
		if sub == "\\" {
			if lplpBuffer != 0 {
				ctx.Mem.Write64(lplpBuffer, pBlock)
			}
			if puLen != 0 {
				ctx.Mem.Write32(puLen, 52)
			}
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0) // not found
		}
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing version handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(version, "GetFileVersionInfoA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[version] GetFileVersionInfoA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[version] GetFileVersionInfoExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[version] GetFileVersionInfoExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[version] GetFileVersionInfoSizeA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(64)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[version] GetFileVersionInfoSizeExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(64)
		return 0
	})
	d.RegisterAutoStubHandler(version, "GetFileVersionInfoSizeExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[version] GetFileVersionInfoSizeExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(64)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerFindFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[version] VerFindFileA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerFindFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[version] VerFindFileW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerInstallFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[version] VerInstallFileA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerInstallFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[version] VerInstallFileW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerLanguageNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[version] VerLanguageNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerLanguageNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[version] VerLanguageNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(version, "VerQueryValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[version] VerQueryValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
}

func registerImm32CompatHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	imm32dll, ok := hctx.SynthByName["imm32.dll"]
	if !ok {
		return
	}
	_ = imm32dll

	d.RegisterAutoStubHandler(imm32dll, "ImmGetContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL HIMC - no IME
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionStringW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // 0 = no composition string / GCS_RESULTSTR not available
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetDefaultIMEWnd", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - no IME window
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - no previous context
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContextEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDisableIME", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIsIME", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - no IME
		return 0
	})
	for _, fname := range []string{
		"ImmSetCandidateWindow", "ImmSetCompositionWindow",
		"ImmSetCompositionFontW", "ImmSetCompositionStringW",
		"ImmNotifyIME", "ImmEscapeW",
	} {
		n := fname
		d.RegisterAutoStubHandler(imm32dll, n, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(0) // FALSE / no-op
			return 0
		})
	}

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing imm32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(imm32dll, "CtfAImmActivate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfAImmActivate p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfAImmDeactivate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfAImmDeactivate p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfAImmIsIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfAImmIsIME p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmCoUninitialize", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmCoUninitialize()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmDispatchDefImeMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] CtfImmDispatchDefImeMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmEnterCoInitCountSkipMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmEnterCoInitCountSkipMode()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmGenerateMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] CtfImmGenerateMessage p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmGetGuidAtom", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] CtfImmGetGuidAtom p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmHideToolbarWnd", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmHideToolbarWnd()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmIsCiceroEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmIsCiceroEnabled()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmIsCiceroStartedInThread", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmIsCiceroStartedInThread()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmIsGuidMapEnable", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfImmIsGuidMapEnable p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmIsTextFrameServiceDisabled", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmIsTextFrameServiceDisabled()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmLastEnabledWndDestroy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfImmLastEnabledWndDestroy p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmLeaveCoInitCountSkipMode", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] CtfImmLeaveCoInitCountSkipMode()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmRestoreToolbarWnd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] CtfImmRestoreToolbarWnd p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmSetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfImmSetAppCompatFlags p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmSetCiceroStartInThread", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfImmSetCiceroStartInThread p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "CtfImmTIMActivate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] CtfImmTIMActivate p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "GetKeyboardLayoutCP", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] GetKeyboardLayoutCP p0=0x%x\n", p0)
		ctx.SetReturn(1252)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmActivateLayout", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmActivateLayout p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmCallImeConsoleIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[imm32] ImmCallImeConsoleIME p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmConfigureIMEA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmConfigureIMEA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmConfigureIMEW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmConfigureIMEW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmCreateContext", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[imm32] ImmCreateContext()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmCreateIMCC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmCreateIMCC p0=0x%x\n", p0)
		ctx.SetReturn(0xDEAD2000)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmCreateSoftKeyboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmCreateSoftKeyboard p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDestroyContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmDestroyContext p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDestroyIMCC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmDestroyIMCC p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDestroySoftKeyboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmDestroySoftKeyboard p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDisableIme", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmDisableIme p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDisableTextFrameService", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmDisableTextFrameService p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEnumInputContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmEnumInputContext p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEnumRegisterWordA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmEnumRegisterWordA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEnumRegisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmEnumRegisterWordW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEscapeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmEscapeA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEscapeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmEscapeW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmFreeLayout", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmFreeLayout p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGenerateMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGenerateMessage p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetAppCompatFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetAppCompatFlags p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetCandidateListA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListCountA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetCandidateListCountA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListCountW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetCandidateListCountW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetCandidateListW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetCandidateWindow p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionFontA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetCompositionFontA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionFontW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetCompositionFontW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetCompositionString p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetCompositionStringA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetCompositionWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetConversionListA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmGetConversionListA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetConversionListW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmGetConversionListW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetConversionStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetConversionStatus p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetDescriptionA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetDescriptionA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetDescriptionW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetDescriptionW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetGuideLineA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetGuideLineA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetGuideLineW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetGuideLineW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetHotKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmGetHotKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMCCLockCount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetIMCCLockCount p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMCCSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetIMCCSize p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMCLockCount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetIMCLockCount p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMEFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetIMEFileNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMEFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetIMEFileNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetImeInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetImeInfoEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetImeMenuItemsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmGetImeMenuItemsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetImeMenuItemsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmGetImeMenuItemsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetOpenStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetOpenStatus p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetProperty", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetProperty p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetRegisterWordStyleA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetRegisterWordStyleA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetRegisterWordStyleW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmGetRegisterWordStyleW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetStatusWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmGetStatusWindowPos p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetVirtualKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmGetVirtualKey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPGetIMEA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmIMPGetIMEA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPGetIMEW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmIMPGetIMEW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPQueryIMEA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmIMPQueryIMEA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPQueryIMEW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmIMPQueryIMEW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPSetIMEA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmIMPSetIMEA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIMPSetIMEW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmIMPSetIMEW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmInstallIMEA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmInstallIMEA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmInstallIMEW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmInstallIMEW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIsUIMessageA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmIsUIMessageA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIsUIMessageW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmIsUIMessageW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLoadIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmLoadIME p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLoadLayout", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmLoadLayout p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLockClientImc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmLockClientImc p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLockIMC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmLockIMC p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLockIMCC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmLockIMCC p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmLockImeDpi", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmLockImeDpi p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmNotifyIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmNotifyIME p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmProcessKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[imm32] ImmProcessKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmPutImeMenuItemsIntoMappedFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmPutImeMenuItemsIntoMappedFile p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmReSizeIMCC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmReSizeIMCC p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0xDEAD2000)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRegisterClient", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmRegisterClient p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRegisterWordA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmRegisterWordA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRegisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmRegisterWordW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRequestMessageA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmRequestMessageA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRequestMessageW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmRequestMessageW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSendIMEMessageExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSendIMEMessageExA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSendIMEMessageExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSendIMEMessageExW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetActiveContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmSetActiveContext p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetActiveContextConsoleIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetActiveContextConsoleIME p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCandidateWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetCandidateWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionFontA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetCompositionFontA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionFontW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetCompositionFontW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionStringA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmSetCompositionStringA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionStringW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[imm32] ImmSetCompositionStringW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetCompositionWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetConversionStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmSetConversionStatus p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetHotKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmSetHotKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetOpenStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetOpenStatus p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetStatusWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSetStatusWindowPos p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmShowSoftKeyboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmShowSoftKeyboard p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSimulateHotKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmSimulateHotKey p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSystemHandler", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[imm32] ImmSystemHandler p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmTranslateMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmTranslateMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnlockClientImc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmUnlockClientImc p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnlockIMC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmUnlockIMC p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnlockIMCC", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmUnlockIMCC p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnlockImeDpi", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmUnlockImeDpi p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnregisterWordA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmUnregisterWordA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnregisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[imm32] ImmUnregisterWordW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmWINNLSEnableIME", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[imm32] ImmWINNLSEnableIME p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmWINNLSGetEnableStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmWINNLSGetEnableStatus p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmWINNLSGetIMEHotkey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[imm32] ImmWINNLSGetIMEHotkey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
}

func registerSensapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	sensapi, ok := hctx.SynthByName["sensapi.dll"]
	if !ok {
		return
	}
	_ = sensapi

	d.RegisterAutoStubHandler(sensapi, "IsNetworkAlive", func(ctx *ntapi.TrapContext) uint32 {
		lpdwFlags := ctx.Arg(0)
		if lpdwFlags != 0 {
			ctx.Mem.Write32(lpdwFlags, 1) // NETWORK_ALIVE_LAN
		}
		ctx.SetReturn(1) // TRUE - pretend connected
		return 0
	})
	d.RegisterAutoStubHandler(sensapi, "IsDestinationReachableW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
}

func registerDwmapiHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	dwmapi, ok := hctx.SynthByName["dwmapi.dll"]
	if !ok {
		return
	}
	_ = dwmapi

	d.RegisterAutoStubHandler(dwmapi, "DwmSetWindowAttribute", func(ctx *ntapi.TrapContext) uint32 {
		// hwnd := ctx.Arg(0), dwAttribute := ctx.Arg(1)
		// pvAttribute := ctx.Arg(2), cbAttribute := ctx.Arg(3)
		// Accept all attributes silently - we don't render DWM effects
		ctx.SetReturn(0) // S_OK
		return 0
	})
}

func registerDbghelpHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	dbghelp, ok := hctx.SynthByName["dbghelp.dll"]
	if !ok {
		return
	}
	_ = dbghelp

	d.RegisterAutoStubHandler(dbghelp, "ImageNtHeader", func(ctx *ntapi.TrapContext) uint32 {
		base := ctx.Arg(0)
		if base == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// NT headers start at base + e_lfanew (DOS header offset 0x3C)
		lfanew, _ := ctx.Mem.Read32(base + 0x3C)
		ctx.SetReturn(base + uint64(lfanew))
		return 0
	})
}

func registerWintrustHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	wintrust, ok := hctx.SynthByName["wintrust.dll"]
	if !ok {
		return
	}
	_ = wintrust

	d.RegisterAutoStubHandler(wintrust, "WinVerifyTrust", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK - trusted (skip signature check)
		return 0
	})
}

func registerWininetHandlers(hctx *HandlerCtx) {
	d := hctx.Disp

	wininet, ok := hctx.SynthByName["wininet.dll"]
	if !ok {
		return
	}
	_ = wininet

	d.RegisterAutoStubHandler(wininet, "InternetCrackUrlW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - no URL parsing in emulator
		return 0
	})
	d.RegisterAutoStubHandler(wininet, "InternetGetConnectedState", func(ctx *ntapi.TrapContext) uint32 {
		lpdwFlags := ctx.Arg(0)
		if lpdwFlags != 0 {
			ctx.Mem.Write32(lpdwFlags, 0x40)
		} // INTERNET_CONNECTION_LAN
		ctx.SetReturn(1) // TRUE
		return 0
	})
}
