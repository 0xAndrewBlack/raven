package main

import (
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerWinmmHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["winmm.dll"]
	if !ok {
		return
	}
	_ = dll

	d.RegisterAutoStubHandler(dll, "CloseDriver", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] CloseDriver\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DefDriverProc", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DefDriverProc\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DriverCallback", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DriverCallback\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvDefDriverProc", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvDefDriverProc\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvGetModuleHandle", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvGetModuleHandle\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvOpenA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvOpenA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "DrvSendMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] DrvSendMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDriverFlags", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] GetDriverFlags\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "GetDriverModuleHandle", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] GetDriverModuleHandle\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "OpenDriver", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] OpenDriver\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "OpenDriverA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] OpenDriverA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PlaySound", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySound\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PlaySoundA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySoundA\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PlaySoundW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySoundW\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "SendDriverMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] SendDriverMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxGetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxGetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxOutMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxOutMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "auxSetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] auxSetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2, p3, p4, p5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[winmm] -stub(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", p0, p1, p2, p3, p4, p5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[winmm] -stub(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[winmm] -stub(0x%x)\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1, p2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[winmm] -stub(0x%x, 0x%x, 0x%x)\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "-stub", func(ctx *ntapi.TrapContext) uint32 {
		p0, p1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[winmm] -stub(0x%x, 0x%x)\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyConfigChanged", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyConfigChanged\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetDevCapsA\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetDevCapsW\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetPos", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetPos\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetPosEx", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetPosEx\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyGetThreshold", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyGetThreshold\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joyReleaseCapture", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joyReleaseCapture\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joySetCapture", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joySetCapture\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "joySetThreshold", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] joySetThreshold\n")
		ctx.SetReturn(6)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciDriverNotify", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciDriverNotify\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciDriverYield", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciDriverYield\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciExecute", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciExecute\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciFreeCommandResource", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciFreeCommandResource\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetCreatorTask", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetCreatorTask\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDA\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDFromElementIDA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDFromElementIDA\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDFromElementIDW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDFromElementIDW\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDW\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDriverData", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDriverData\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetErrorStringA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetErrorStringA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetErrorStringW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetErrorStringW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetYieldProc", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetYieldProc\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciLoadCommandResource", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciLoadCommandResource\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSendCommandA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendCommandA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSendCommandW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendCommandW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSendStringA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendStringA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSendStringW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendStringW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSetDriverData", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSetDriverData\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSetYieldProc", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSetYieldProc\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiConnect", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiConnect\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiDisconnect", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiDisconnect\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInAddBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInAddBuffer\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetErrorTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetErrorTextA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetErrorTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetErrorTextW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetID\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInPrepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInReset\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInStart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInStart\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInStop", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInStop\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiInUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiInUnprepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutCacheDrumPatches", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutCacheDrumPatches\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutCachePatches", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutCachePatches\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetErrorTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetErrorTextA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetErrorTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetErrorTextW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetID\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutGetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutGetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutLongMsg", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutLongMsg\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutPrepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutReset\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutSetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutSetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutShortMsg", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutShortMsg\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiOutUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiOutUnprepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamOut", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamOut\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamPause", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamPause\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamPosition", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamPosition\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamProperty", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamProperty\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamRestart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamRestart\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "midiStreamStop", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] midiStreamStop\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetControlDetailsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetControlDetailsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetControlDetailsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetControlDetailsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetID\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetLineControlsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetLineControlsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetLineControlsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetLineControlsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetLineInfoA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetLineInfoA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetLineInfoW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetLineInfoW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mixerSetControlDetails", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mixerSetControlDetails\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmGetCurrentTask", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmGetCurrentTask\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmTaskBlock", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmTaskBlock\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmTaskCreate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmTaskCreate\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmTaskSignal", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmTaskSignal\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmTaskYield", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmTaskYield\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioAdvance", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioAdvance\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioAscend", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioAscend\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioCreateChunk", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioCreateChunk\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioDescend", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioDescend\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioFlush", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioFlush\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioGetInfo", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioGetInfo\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioInstallIOProcA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioInstallIOProcA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioInstallIOProcW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioInstallIOProcW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioOpenA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioOpenA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioOpenW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioOpenW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioRead", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioRead\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioRenameA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioRenameA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioRenameW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioRenameW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioSeek", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioSeek\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioSendMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioSendMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioSetBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioSetBuffer\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioSetInfo", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioSetInfo\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioStringToFOURCCA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioStringToFOURCCA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioStringToFOURCCW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioStringToFOURCCW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioWrite", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioWrite\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmsystemGetVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmsystemGetVersion\n")
		ctx.SetReturn(0x0500)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "sndPlaySoundA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] sndPlaySoundA\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "sndPlaySoundW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] sndPlaySoundW\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeBeginPeriod", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeBeginPeriod\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeEndPeriod", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeEndPeriod\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetDevCaps", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeGetDevCaps\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeGetSystemTime\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetTime", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeGetTime\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeKillEvent", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeKillEvent\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeSetEvent", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeSetEvent\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInAddBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInAddBuffer\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetErrorTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetErrorTextA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetErrorTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetErrorTextW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetID\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetNumDevs\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetPosition", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetPosition\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInPrepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInReset\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInStart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInStart\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInStop", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInStop\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInUnprepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutBreakLoop", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutBreakLoop\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutClose\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetDevCapsA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetDevCapsA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetDevCapsW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetDevCapsW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetErrorTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetErrorTextA\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetErrorTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetErrorTextW\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetID\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetNumDevs\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPitch", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPitch\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPlaybackRate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPlaybackRate\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPosition", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPosition\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutMessage\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutOpen\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutPause", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutPause\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutPrepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutReset\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutRestart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutRestart\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetPitch", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetPitch\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetPlaybackRate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetPlaybackRate\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetVolume\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutUnprepareHeader\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutWrite", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutWrite\n")
		ctx.SetReturn(0)
		return 0
	})
}
