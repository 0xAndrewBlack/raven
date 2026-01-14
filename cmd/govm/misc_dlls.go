package main

import (
	"fmt"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"golang.org/x/sys/unix"
)

func registerRpcrt4Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	rpcrt4, ok := hctx.SynthByName["rpcrt4.dll"]
	if !ok {
		return
	}
	_ = rpcrt4

	genGUIDrpc := func(ptr uint64) {
		if ptr == 0 {
			return
		}
		var b [16]byte
		unix.Getrandom(b[:], 0)
		b[6] = (b[6] & 0x0F) | 0x40
		b[8] = (b[8] & 0x3F) | 0x80
		mem.Write32(ptr, uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24)
		mem.Write16(ptr+4, uint16(b[4])|uint16(b[5])<<8)
		mem.Write16(ptr+6, uint16(b[6])|uint16(b[7])<<8)
		for i := 0; i < 8; i++ {
			mem.Write8(ptr+8+uint64(i), b[8+i])
		}
	}
	d.RegisterAutoStubHandler(rpcrt4, "UuidCreate", func(ctx *ntapi.TrapContext) uint32 {
		genGUIDrpc(ctx.Arg(0))
		ctx.SetReturn(0) // RPC_S_OK
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidCreateSequential", func(ctx *ntapi.TrapContext) uint32 {
		genGUIDrpc(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidToStringW", func(ctx *ntapi.TrapContext) uint32 {
		// UuidToStringW(UUID* uuid, RPC_WSTR* StringUuid)
		uuidPtr := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if uuidPtr == 0 || ppStr == 0 {
			ctx.SetReturn(10) /* RPC_S_INVALID_ARG */
			return 0
		}
		a0, _ := mem.Read32(uuidPtr)
		a1, _ := mem.Read16(uuidPtr + 4)
		a2, _ := mem.Read16(uuidPtr + 6)
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i], _ = mem.Read8(uuidPtr + 8 + uint64(i))
		}
		s := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			a0, a1, a2, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
		ws := utf16Encode(s)
		addr := mem.Mmap(0, uint64(len(ws)+1)*2, mmu.PermRead|mmu.PermWrite)
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		mem.Write64(ppStr, addr)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidToStringA", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if uuidPtr == 0 || ppStr == 0 {
			ctx.SetReturn(10)
			return 0
		}
		a0, _ := mem.Read32(uuidPtr)
		a1, _ := mem.Read16(uuidPtr + 4)
		a2, _ := mem.Read16(uuidPtr + 6)
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i], _ = mem.Read8(uuidPtr + 8 + uint64(i))
		}
		s := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			a0, a1, a2, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7])
		addr := mem.Mmap(0, uint64(len(s)+1), mmu.PermRead|mmu.PermWrite)
		mem.WriteBytes(addr, append([]byte(s), 0))
		mem.Write64(ppStr, addr)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringFreeW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // RPC_S_OK
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringFreeA", func(ctx *ntapi.TrapContext) uint32 {
		// RPC_STATUS RpcStringFreeA(RPC_CSTR *String)
		ppStr := ctx.Arg(0)
		if ppStr != 0 {
			mem.Write64(ppStr, 0) // set *String = NULL
		}
		ctx.SetReturn(0) // RPC_S_OK
		return 0
	})
	for _, fn := range []string{"RpcBindingFree", "RpcBindingFromStringBindingW",
		"RpcBindingFromStringBindingA", "RpcStringBindingComposeW", "RpcStringBindingComposeA",
		"RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerListen",
		"NdrClientCall2", "NdrClientCall3"} {
		fn := fn
		d.RegisterAutoStubHandler(rpcrt4, fn, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[rpcrt4] %s arg0=0x%x - RPC stub\n", fn, ctx.Arg(0))
			ctx.SetReturn(0)
			return 0
		})
	}
}

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
}

func registerImm32Handlers(hctx *HandlerCtx) {
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
