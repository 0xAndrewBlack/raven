//go:build guest_windows

package main

import (
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	MF_VERSION              = 0x00020070
	MF_E_PLATFORM_NOT_INIT  = 0xC00D36B0
	MF_E_UNSUPPORTED_SCHEME = 0xC00D36C3
	MFSTARTUP_NOSOCKET      = 0x1
	MFSTARTUP_LITE          = 0x1
)

type mfState struct {
	mu         sync.Mutex
	started    bool
	nextHandle uint32
	attrStores map[uint32]map[string]interface{}
}

var mfGlobal = mfState{
	nextHandle: 0x4000,
	attrStores: make(map[uint32]map[string]interface{}),
}

func registerMediaFoundationHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	startTime := hctx.StartTime

	allocHandle := func(storeAttrs bool) uint32 {
		mfGlobal.mu.Lock()
		defer mfGlobal.mu.Unlock()
		handle := mfGlobal.nextHandle
		mfGlobal.nextHandle++
		if storeAttrs {
			mfGlobal.attrStores[handle] = make(map[string]interface{})
		}
		return handle
	}

	isStarted := func() bool {
		mfGlobal.mu.Lock()
		defer mfGlobal.mu.Unlock()
		return mfGlobal.started
	}

	writeHandle := func(ctx *ntapi.TrapContext, outPtr uint64, handle uint32) uint32 {
		if outPtr == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(outPtr, uint64(handle))
		ctx.SetReturn(S_OK)
		return 0
	}

	requireStarted := func(ctx *ntapi.TrapContext) bool {
		if isStarted() {
			return true
		}
		ctx.SetReturn(MF_E_PLATFORM_NOT_INIT)
		return false
	}

	if dll, ok := hctx.SynthByName["mfplat.dll"]; ok {
		d.RegisterAutoStubHandler(dll, "MFStartup", func(ctx *ntapi.TrapContext) uint32 {
			mfGlobal.mu.Lock()
			mfGlobal.started = true
			mfGlobal.mu.Unlock()
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFShutdown", func(ctx *ntapi.TrapContext) uint32 {
			mfGlobal.mu.Lock()
			mfGlobal.started = false
			mfGlobal.mu.Unlock()
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateMediaType", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(true))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateAttributes", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(true))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateMemoryBuffer", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(1), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSample", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSourceResolver", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFGetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(time.Since(startTime).Nanoseconds() / 100))
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateEventQueue", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFTRegister", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFTUnregister", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFTEnum", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			pppMFTActivate := ctx.Arg(5)
			pcMFTActivate := ctx.Arg(6)
			if pppMFTActivate != 0 {
				ctx.Mem.Write64(pppMFTActivate, 0)
			}
			if pcMFTActivate != 0 {
				ctx.Mem.Write32(pcMFTActivate, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFTEnumEx", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			pppMFTActivate := ctx.Arg(5)
			pcMFTActivate := ctx.Arg(6)
			if pppMFTActivate != 0 {
				ctx.Mem.Write64(pppMFTActivate, 0)
			}
			if pcMFTActivate != 0 {
				ctx.Mem.Write32(pcMFTActivate, 0)
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCopyImage", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			pDest := ctx.Arg(0)
			lDestStride := int64(int32(ctx.Arg(1)))
			pSrc := ctx.Arg(2)
			lSrcStride := int64(int32(ctx.Arg(3)))
			dwWidthInBytes := int(ctx.Arg(4))
			dwLines := int(ctx.Arg(5))
			if pDest == 0 || pSrc == 0 {
				ctx.SetReturn(E_POINTER)
				return 0
			}
			dest := int64(pDest)
			src := int64(pSrc)
			for i := 0; i < dwLines; i++ {
				if dest < 0 || src < 0 {
					ctx.SetReturn(E_INVALIDARG)
					return 0
				}
				row, err := ctx.Mem.ReadBytes(uint64(src), dwWidthInBytes)
				if err != nil {
					ctx.SetReturn(E_FAIL)
					return 0
				}
				if err := ctx.Mem.WriteBytes(uint64(dest), row); err != nil {
					ctx.SetReturn(E_FAIL)
					return 0
				}
				dest += lDestStride
				src += lSrcStride
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateAsyncResult", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFInvokeCallback", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFLockPlatform", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFUnlockPlatform", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFAllocateWorkQueue", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			workQueueID := ctx.Arg(0)
			if workQueueID != 0 {
				ctx.Mem.Write32(workQueueID, 1)
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFLockWorkQueue", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFUnlockWorkQueue", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFPutWorkItem", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFPutWorkItemEx", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(S_OK)
			return 0
		})
	}

	if dll, ok := hctx.SynthByName["mf.dll"]; ok {
		d.RegisterAutoStubHandler(dll, "MFCreateMediaSession", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(1), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateTopology", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(0), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateTopologyNode", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(1), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFGetService", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(3) != 0 {
				ctx.Mem.Write64(ctx.Arg(3), 0)
			}
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreatePresentationDescriptor", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(3), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateStreamDescriptor", func(ctx *ntapi.TrapContext) uint32 {
			if !requireStarted(ctx) {
				return 0
			}
			return writeHandle(ctx, ctx.Arg(3), allocHandle(false))
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSequencerSource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateAggregateSource", func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
	}

	if dll, ok := hctx.SynthByName["mfreadwrite.dll"]; ok {
		d.RegisterAutoStubHandler(dll, "MFCreateSourceReaderFromURL", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(2) != 0 {
				ctx.Mem.Write64(ctx.Arg(2), 0)
			}
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(MF_E_UNSUPPORTED_SCHEME)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSourceReaderFromByteStream", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(2) != 0 {
				ctx.Mem.Write64(ctx.Arg(2), 0)
			}
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(MF_E_UNSUPPORTED_SCHEME)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSourceReaderFromMediaSource", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(2) != 0 {
				ctx.Mem.Write64(ctx.Arg(2), 0)
			}
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSinkWriterFromURL", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(3) != 0 {
				ctx.Mem.Write64(ctx.Arg(3), 0)
			}
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})

		d.RegisterAutoStubHandler(dll, "MFCreateSinkWriterFromMediaSink", func(ctx *ntapi.TrapContext) uint32 {
			if ctx.Arg(2) != 0 {
				ctx.Mem.Write64(ctx.Arg(2), 0)
			}
			if !requireStarted(ctx) {
				return 0
			}
			ctx.SetReturn(E_NOTIMPL)
			return 0
		})
	}
}
