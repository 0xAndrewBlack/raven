//go:build guest_windows

package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerWtsapi32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["wtsapi32.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "WTSCloseServer", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSCloseServer handle=0x%x\n", hServer)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSConnectSessionA", func(ctx *ntapi.TrapContext) uint32 {
		LogonId := ctx.Arg(0)
		TargetLogonId := ctx.Arg(1)
		pPassword := ctx.Arg(2)
		bWait := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSConnectSessionA src=%d dst=%d\n", LogonId, TargetLogonId)
		_ = pPassword
		_ = bWait
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSConnectSessionW", func(ctx *ntapi.TrapContext) uint32 {
		LogonId := ctx.Arg(0)
		TargetLogonId := ctx.Arg(1)
		pPassword := ctx.Arg(2)
		bWait := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSConnectSessionW src=%d dst=%d\n", LogonId, TargetLogonId)
		_ = pPassword
		_ = bWait
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSDisconnectSession", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		bWait := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSDisconnectSession session=%d wait=%d\n", SessionId, bWait)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnableChildSessions", func(ctx *ntapi.TrapContext) uint32 {
		bEnable := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSEnableChildSessions enable=%d\n", bEnable)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateProcessesA", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppProcessInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateProcessesA server=0x%x\n", hServer)
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppProcessInfo != 0 {
			ctx.Mem.Write64(ppProcessInfo, 0)
		}
		ctx.SetReturn(1) // TRUE (0 processes)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateProcessesExA", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		pLevel := ctx.Arg(1)
		SessionId := ctx.Arg(2)
		ppProcessInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateProcessesExA level=%d session=%d\n", pLevel, SessionId)
		_ = hServer
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppProcessInfo != 0 {
			ctx.Mem.Write64(ppProcessInfo, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateProcessesExW", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		pLevel := ctx.Arg(1)
		SessionId := ctx.Arg(2)
		ppProcessInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateProcessesExW level=%d session=%d\n", pLevel, SessionId)
		_ = hServer
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppProcessInfo != 0 {
			ctx.Mem.Write64(ppProcessInfo, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateProcessesW", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppProcessInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateProcessesW server=0x%x\n", hServer)
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppProcessInfo != 0 {
			ctx.Mem.Write64(ppProcessInfo, 0)
		}
		ctx.SetReturn(1) // TRUE (0 processes)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateServersA", func(ctx *ntapi.TrapContext) uint32 {
		pDomainName := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppServerInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateServersA\n")
		_ = pDomainName
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppServerInfo != 0 {
			ctx.Mem.Write64(ppServerInfo, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateServersW", func(ctx *ntapi.TrapContext) uint32 {
		pDomainName := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppServerInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateServersW\n")
		_ = pDomainName
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppServerInfo != 0 {
			ctx.Mem.Write64(ppServerInfo, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateSessionsA", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppSessionInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateSessionsA server=0x%x\n", hServer)
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppSessionInfo != 0 {
			ctx.Mem.Write64(ppSessionInfo, 0)
		}
		ctx.SetReturn(1) // TRUE (0 sessions)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateSessionsExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateSessionsExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateSessionsExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateSessionsExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSEnumerateSessionsW", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		Reserved := ctx.Arg(1)
		Version := ctx.Arg(2)
		ppSessionInfo := ctx.Arg(3)
		pCount := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSEnumerateSessionsW server=0x%x\n", hServer)
		_ = Reserved
		_ = Version
		if pCount != 0 {
			ctx.Mem.Write32(pCount, 0)
		}
		if ppSessionInfo != 0 {
			ctx.Mem.Write64(ppSessionInfo, 0)
		}
		ctx.SetReturn(1) // TRUE (0 sessions)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSFreeMemory", func(ctx *ntapi.TrapContext) uint32 {
		pMemory := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSFreeMemory mem=0x%x\n", pMemory)
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSFreeMemoryExA", func(ctx *ntapi.TrapContext) uint32 {
		WTSTypeClass := ctx.Arg(0)
		pMemory := ctx.Arg(1)
		NumberOfEntries := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSFreeMemoryExA class=%d entries=%d\n", WTSTypeClass, NumberOfEntries)
		_ = pMemory
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSFreeMemoryExW", func(ctx *ntapi.TrapContext) uint32 {
		WTSTypeClass := ctx.Arg(0)
		pMemory := ctx.Arg(1)
		NumberOfEntries := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSFreeMemoryExW class=%d entries=%d\n", WTSTypeClass, NumberOfEntries)
		_ = pMemory
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSLogoffSession", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		bWait := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSLogoffSession session=%d wait=%d\n", SessionId, bWait)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSOpenServerA", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSOpenServerA server=0x%x\n", pServerName)
		ctx.SetReturn(0xDEAD0500) // fake server handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSOpenServerExA", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSOpenServerExA server=0x%x\n", pServerName)
		ctx.SetReturn(0xDEAD0501) // fake server handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSOpenServerExW", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSOpenServerExW server=0x%x\n", pServerName)
		ctx.SetReturn(0xDEAD0501) // fake server handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSOpenServerW", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSOpenServerW server=0x%x\n", pServerName)
		ctx.SetReturn(0xDEAD0500) // fake server handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSQuerySessionInformationA", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		WTSInfoClass := ctx.Arg(2)
		ppBuffer := ctx.Arg(3)
		pBytesReturned := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSQuerySessionInformationA session=%d class=%d\n", SessionId, WTSInfoClass)
		_ = hServer
		if ppBuffer != 0 {
			ctx.Mem.Write64(ppBuffer, 0)
		}
		if pBytesReturned != 0 {
			ctx.Mem.Write32(pBytesReturned, 0)
		}
		ctx.SetReturn(0) // FALSE (not available)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSQuerySessionInformationW", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		WTSInfoClass := ctx.Arg(2)
		ppBuffer := ctx.Arg(3)
		pBytesReturned := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSQuerySessionInformationW session=%d class=%d\n", SessionId, WTSInfoClass)
		_ = hServer
		if ppBuffer != 0 {
			ctx.Mem.Write64(ppBuffer, 0)
		}
		if pBytesReturned != 0 {
			ctx.Mem.Write32(pBytesReturned, 0)
		}
		ctx.SetReturn(0) // FALSE (not available)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSQueryUserConfigA", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		pUserName := ctx.Arg(1)
		WTSConfigClass := ctx.Arg(2)
		ppBuffer := ctx.Arg(3)
		pBytesReturned := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSQueryUserConfigA class=%d\n", WTSConfigClass)
		_ = pServerName
		_ = pUserName
		if ppBuffer != 0 {
			ctx.Mem.Write64(ppBuffer, 0)
		}
		if pBytesReturned != 0 {
			ctx.Mem.Write32(pBytesReturned, 0)
		}
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSQueryUserConfigW", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		pUserName := ctx.Arg(1)
		WTSConfigClass := ctx.Arg(2)
		ppBuffer := ctx.Arg(3)
		pBytesReturned := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSQueryUserConfigW class=%d\n", WTSConfigClass)
		_ = pServerName
		_ = pUserName
		if ppBuffer != 0 {
			ctx.Mem.Write64(ppBuffer, 0)
		}
		if pBytesReturned != 0 {
			ctx.Mem.Write32(pBytesReturned, 0)
		}
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSQueryUserToken", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[wtsapi32] WTSQueryUserToken p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSRegisterSessionNotification", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		dwFlags := ctx.Arg(1)
		ravelog.Logf("[wtsapi32] WTSRegisterSessionNotification hwnd=0x%x flags=0x%x\n", hWnd, dwFlags)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSRegisterSessionNotificationEx", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		hWnd := ctx.Arg(1)
		dwFlags := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSRegisterSessionNotificationEx hwnd=0x%x flags=0x%x\n", hWnd, dwFlags)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSSendMessageA", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		pTitle := ctx.Arg(2)
		TitleLength := ctx.Arg(3)
		pMessage := ctx.Arg(4)
		MessageLength := ctx.Arg(5)
		ravelog.Logf("[wtsapi32] WTSSendMessageA session=%d\n", SessionId)
		_ = hServer
		_ = pTitle
		_ = TitleLength
		_ = pMessage
		_ = MessageLength
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSSendMessageW", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		pTitle := ctx.Arg(2)
		TitleLength := ctx.Arg(3)
		pMessage := ctx.Arg(4)
		MessageLength := ctx.Arg(5)
		ravelog.Logf("[wtsapi32] WTSSendMessageW session=%d\n", SessionId)
		_ = hServer
		_ = pTitle
		_ = TitleLength
		_ = pMessage
		_ = MessageLength
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSSetUserConfigA", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		pUserName := ctx.Arg(1)
		WTSConfigClass := ctx.Arg(2)
		pBuffer := ctx.Arg(3)
		DataLength := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSSetUserConfigA class=%d len=%d\n", WTSConfigClass, DataLength)
		_ = pServerName
		_ = pUserName
		_ = pBuffer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSSetUserConfigW", func(ctx *ntapi.TrapContext) uint32 {
		pServerName := ctx.Arg(0)
		pUserName := ctx.Arg(1)
		WTSConfigClass := ctx.Arg(2)
		pBuffer := ctx.Arg(3)
		DataLength := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSSetUserConfigW class=%d len=%d\n", WTSConfigClass, DataLength)
		_ = pServerName
		_ = pUserName
		_ = pBuffer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSShutdownSystem", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		ShutdownFlag := ctx.Arg(1)
		ravelog.Logf("[wtsapi32] WTSShutdownSystem flag=%d\n", ShutdownFlag)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSStartRemoteControlSessionA", func(ctx *ntapi.TrapContext) uint32 {
		pTargetServerName := ctx.Arg(0)
		TargetLogonId := ctx.Arg(1)
		HotkeyVk := ctx.Arg(2)
		HotkeyModifiers := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSStartRemoteControlSessionA session=%d\n", TargetLogonId)
		_ = pTargetServerName
		_ = HotkeyVk
		_ = HotkeyModifiers
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSStartRemoteControlSessionW", func(ctx *ntapi.TrapContext) uint32 {
		pTargetServerName := ctx.Arg(0)
		TargetLogonId := ctx.Arg(1)
		HotkeyVk := ctx.Arg(2)
		HotkeyModifiers := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSStartRemoteControlSessionW session=%d\n", TargetLogonId)
		_ = pTargetServerName
		_ = HotkeyVk
		_ = HotkeyModifiers
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSStopRemoteControlSession", func(ctx *ntapi.TrapContext) uint32 {
		LogonId := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSStopRemoteControlSession session=%d\n", LogonId)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSTerminateProcess", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		ProcessId := ctx.Arg(1)
		ExitCode := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSTerminateProcess pid=%d exit=%d\n", ProcessId, ExitCode)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSUnRegisterSessionNotification", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSUnRegisterSessionNotification hwnd=0x%x\n", hWnd)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSUnRegisterSessionNotificationEx", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		hWnd := ctx.Arg(1)
		ravelog.Logf("[wtsapi32] WTSUnRegisterSessionNotificationEx hwnd=0x%x\n", hWnd)
		_ = hServer
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelClose", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelClose handle=0x%x\n", hChannelHandle)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelOpen", func(ctx *ntapi.TrapContext) uint32 {
		hServer := ctx.Arg(0)
		SessionId := ctx.Arg(1)
		pVirtualName := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelOpen session=%d\n", SessionId)
		_ = hServer
		_ = pVirtualName
		ctx.SetReturn(0xDEAD0600) // fake channel handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelOpenEx", func(ctx *ntapi.TrapContext) uint32 {
		SessionId := ctx.Arg(0)
		pVirtualName := ctx.Arg(1)
		flags := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelOpenEx session=%d flags=0x%x\n", SessionId, flags)
		_ = pVirtualName
		ctx.SetReturn(0xDEAD0601) // fake channel handle
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelPurgeInput", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelPurgeInput handle=0x%x\n", hChannelHandle)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelPurgeOutput", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelPurgeOutput handle=0x%x\n", hChannelHandle)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelQuery", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		class := ctx.Arg(1)
		ppBuffer := ctx.Arg(2)
		pBytesReturned := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelQuery handle=0x%x class=%d\n", hChannelHandle, class)
		if ppBuffer != 0 {
			ctx.Mem.Write64(ppBuffer, 0)
		}
		if pBytesReturned != 0 {
			ctx.Mem.Write32(pBytesReturned, 0)
		}
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelRead", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		TimeOut := ctx.Arg(1)
		Buffer := ctx.Arg(2)
		BufferSize := ctx.Arg(3)
		pBytesRead := ctx.Arg(4)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelRead handle=0x%x timeout=%d\n", hChannelHandle, TimeOut)
		_ = Buffer
		_ = BufferSize
		if pBytesRead != 0 {
			ctx.Mem.Write32(pBytesRead, 0)
		}
		ctx.SetReturn(1) // TRUE (0 bytes)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSVirtualChannelWrite", func(ctx *ntapi.TrapContext) uint32 {
		hChannelHandle := ctx.Arg(0)
		Buffer := ctx.Arg(1)
		Length := ctx.Arg(2)
		pBytesWritten := ctx.Arg(3)
		ravelog.Logf("[wtsapi32] WTSVirtualChannelWrite handle=0x%x len=%d\n", hChannelHandle, Length)
		_ = Buffer
		if pBytesWritten != 0 {
			ctx.Mem.Write32(pBytesWritten, uint32(Length))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(dll, "WTSWaitSystemEvent", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[wtsapi32] WTSWaitSystemEvent p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
}
