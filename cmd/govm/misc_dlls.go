package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

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

// registerWininetHandlers is in wininet.go with real HTTP implementation.
