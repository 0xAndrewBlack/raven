//go:build guest_windows

package main

import (
	"sync"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	GCS_COMPSTR      = 0x0008
	GCS_COMPATTR     = 0x0010
	GCS_COMPCLAUSE   = 0x0020
	GCS_CURSORPOS    = 0x0080
	GCS_RESULTSTR    = 0x0800
	GCS_RESULTCLAUSE = 0x1000

	IME_CMODE_ALPHANUMERIC = 0x0000
	IME_CMODE_NATIVE       = 0x0001
	IME_SMODE_NONE         = 0x0000

	CFS_DEFAULT = 0x0000
	CFS_RECT    = 0x0001
	CFS_POINT   = 0x0002

	IMN_CLOSESTATUSWINDOW = 0x0001
	IMN_OPENSTATUSWINDOW  = 0x0002
	IMN_SETCONVERSIONMODE = 0x0006
	IMN_SETSENTENCEMODE   = 0x0008

	IGP_PROPERTY   = 0x0004
	IGP_CONVERSION = 0x0008
	IGP_SENTENCE   = 0x000C
	IGP_UI         = 0x000F
	IGP_SETCOMPSTR = 0x0014

	vkProcessKey = 0xE5
)

type immState struct {
	mu         sync.Mutex
	nextHandle uint32
	contexts   map[uint32]*imeContext
	hwndAssoc  map[uint64]uint32
}

type imeContext struct {
	hwnd           uint64
	open           bool
	conversionMode uint32
	sentenceMode   uint32
	compStr        string
	resultStr      string
	candidateList  []string

	compStyle  uint32
	compX      int32
	compY      int32
	compLeft   int32
	compTop    int32
	compRight  int32
	compBottom int32
}

var immGlobal = immState{
	nextHandle: 0x1000,
	contexts:   make(map[uint32]*imeContext),
	hwndAssoc:  make(map[uint64]uint32),
}

func registerImm32Handlers(hctx *HandlerCtx) {
	registerImm32CompatHandlers(hctx)

	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16N := hctx.ReadGuestUTF16N

	imm32dll, ok := hctx.SynthByName["imm32.dll"]
	if !ok {
		return
	}

	newContext := func(hwnd uint64) uint32 {
		himc := immGlobal.nextHandle
		immGlobal.nextHandle++
		immGlobal.contexts[himc] = &imeContext{
			hwnd:           hwnd,
			open:           false,
			conversionMode: IME_CMODE_ALPHANUMERIC,
			sentenceMode:   IME_SMODE_NONE,
			candidateList:  nil,
			compStyle:      CFS_DEFAULT,
		}
		if hwnd != 0 {
			immGlobal.hwndAssoc[hwnd] = himc
		}
		return himc
	}
	lookupContext := func(himc uint32) *imeContext {
		return immGlobal.contexts[himc]
	}
	getOrCreateContext := func(hwnd uint64) (uint32, *imeContext) {
		if himc := immGlobal.hwndAssoc[hwnd]; himc != 0 {
			if ime := immGlobal.contexts[himc]; ime != nil {
				return himc, ime
			}
		}
		himc := newContext(hwnd)
		return himc, immGlobal.contexts[himc]
	}
	writeUTF16Bytes := func(dst uint64, dstLen uint32, s string) uint64 {
		ws := utf16Encode(s)
		required := uint64(len(ws) * 2)
		if dst == 0 || dstLen == 0 {
			return required
		}
		maxChars := int(dstLen / 2)
		if maxChars > len(ws) {
			maxChars = len(ws)
		}
		for i := 0; i < maxChars; i++ {
			mem.Write16(dst+uint64(i)*2, ws[i])
		}
		return required
	}
	writeZeroBytes := func(dst uint64, dstLen uint32, count int) uint64 {
		required := uint64(count)
		if dst == 0 || dstLen == 0 || count <= 0 {
			return required
		}
		n := int(dstLen)
		if n > count {
			n = count
		}
		for i := 0; i < n; i++ {
			mem.Write8(dst+uint64(i), 0)
		}
		return required
	}
	writeCompositionForm := func(ptr uint64, ime *imeContext) {
		if ptr == 0 || ime == nil {
			return
		}
		mem.Write32(ptr+0, ime.compStyle)
		mem.Write32(ptr+4, uint32(ime.compX))
		mem.Write32(ptr+8, uint32(ime.compY))
		mem.Write32(ptr+12, uint32(ime.compLeft))
		mem.Write32(ptr+16, uint32(ime.compTop))
		mem.Write32(ptr+20, uint32(ime.compRight))
		mem.Write32(ptr+24, uint32(ime.compBottom))
	}
	readCompositionForm := func(ptr uint64, ime *imeContext) {
		if ptr == 0 || ime == nil {
			return
		}
		style, _ := mem.Read32(ptr + 0)
		x, _ := mem.Read32(ptr + 4)
		y, _ := mem.Read32(ptr + 8)
		left, _ := mem.Read32(ptr + 12)
		top, _ := mem.Read32(ptr + 16)
		right, _ := mem.Read32(ptr + 20)
		bottom, _ := mem.Read32(ptr + 24)
		ime.compStyle = style
		ime.compX = int32(x)
		ime.compY = int32(y)
		ime.compLeft = int32(left)
		ime.compTop = int32(top)
		ime.compRight = int32(right)
		ime.compBottom = int32(bottom)
	}

	d.RegisterAutoStubHandler(imm32dll, "ImmGetContext", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		immGlobal.mu.Lock()
		himc, _ := getOrCreateContext(hwnd)
		immGlobal.mu.Unlock()
		ctx.SetReturn(uint64(himc))
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmCreateContext", func(ctx *ntapi.TrapContext) uint32 {
		immGlobal.mu.Lock()
		himc := newContext(0)
		immGlobal.mu.Unlock()
		ctx.SetReturn(uint64(himc))
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDestroyContext", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		if ime != nil {
			delete(immGlobal.contexts, himc)
			for hwnd, assoc := range immGlobal.hwndAssoc {
				if assoc == himc {
					delete(immGlobal.hwndAssoc, hwnd)
				}
			}
		}
		immGlobal.mu.Unlock()
		if ime != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContext", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		himc := uint32(ctx.Arg(1))
		immGlobal.mu.Lock()
		prev := immGlobal.hwndAssoc[hwnd]
		if himc == 0 {
			delete(immGlobal.hwndAssoc, hwnd)
		} else if ime := lookupContext(himc); ime != nil {
			ime.hwnd = hwnd
			immGlobal.hwndAssoc[hwnd] = himc
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmAssociateContextEx", func(ctx *ntapi.TrapContext) uint32 {
		hwnd := ctx.Arg(0)
		himc := uint32(ctx.Arg(1))
		_ = ctx.Arg(2)
		immGlobal.mu.Lock()
		if himc == 0 {
			delete(immGlobal.hwndAssoc, hwnd)
		} else if ime := lookupContext(himc); ime != nil {
			ime.hwnd = hwnd
			immGlobal.hwndAssoc[hwnd] = himc
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmGetOpenStatus", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		open := ime != nil && ime.open
		immGlobal.mu.Unlock()
		if open {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetOpenStatus", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		open := ctx.Arg(1) != 0
		immGlobal.mu.Lock()
		if ime := lookupContext(himc); ime != nil {
			ime.open = open
			immGlobal.mu.Unlock()
			ctx.SetReturn(1)
			return 0
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetConversionStatus", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		lpConv := ctx.Arg(1)
		lpSent := ctx.Arg(2)
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		if ime != nil {
			if lpConv != 0 {
				mem.Write32(lpConv, ime.conversionMode)
			}
			if lpSent != 0 {
				mem.Write32(lpSent, ime.sentenceMode)
			}
		}
		immGlobal.mu.Unlock()
		if ime != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetConversionStatus", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		conv := uint32(ctx.Arg(1))
		sent := uint32(ctx.Arg(2))
		immGlobal.mu.Lock()
		if ime := lookupContext(himc); ime != nil {
			ime.conversionMode = conv
			ime.sentenceMode = sent
			immGlobal.mu.Unlock()
			ctx.SetReturn(1)
			return 0
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetProperty", func(ctx *ntapi.TrapContext) uint32 {
		_ = ctx.Arg(0)
		switch uint32(ctx.Arg(1)) {
		case IGP_CONVERSION:
			ctx.SetReturn(IME_CMODE_ALPHANUMERIC)
		case IGP_SENTENCE:
			ctx.SetReturn(IME_SMODE_NONE)
		case IGP_PROPERTY, IGP_SETCOMPSTR, IGP_UI:
			ctx.SetReturn(0)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmIsIME", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionStringW", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		index := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		bufLen := uint32(ctx.Arg(3))
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		if ime == nil {
			immGlobal.mu.Unlock()
			ctx.SetReturn(0)
			return 0
		}

		switch index {
		case GCS_COMPSTR:
			if ime.compStr == "" {
				immGlobal.mu.Unlock()
				ctx.SetReturn(0)
				return 0
			}
			required := writeUTF16Bytes(buf, bufLen, ime.compStr)
			immGlobal.mu.Unlock()
			ctx.SetReturn(required)
		case GCS_RESULTSTR:
			if ime.resultStr == "" {
				immGlobal.mu.Unlock()
				ctx.SetReturn(0)
				return 0
			}
			required := writeUTF16Bytes(buf, bufLen, ime.resultStr)
			immGlobal.mu.Unlock()
			ctx.SetReturn(required)
		case GCS_COMPATTR:
			if ime.compStr == "" {
				immGlobal.mu.Unlock()
				ctx.SetReturn(0)
				return 0
			}
			required := writeZeroBytes(buf, bufLen, len(utf16Encode(ime.compStr)))
			immGlobal.mu.Unlock()
			ctx.SetReturn(required)
		case GCS_CURSORPOS:
			cursor := len(utf16Encode(ime.compStr))
			immGlobal.mu.Unlock()
			ctx.SetReturn(uint64(cursor))
		default:
			immGlobal.mu.Unlock()
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionStringW", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		index := uint32(ctx.Arg(1))
		lpComp := ctx.Arg(2)
		compLen := uint32(ctx.Arg(3))
		lpRead := ctx.Arg(4)
		readLen := uint32(ctx.Arg(5))
		_ = lpRead
		_ = readLen

		immGlobal.mu.Lock()
		if ime := lookupContext(himc); ime != nil {
			text := ""
			if lpComp != 0 && compLen >= 2 {
				text = readGuestUTF16N(lpComp, int(compLen/2))
			}
			if index == GCS_RESULTSTR {
				ime.resultStr = text
				if text != "" {
					ime.compStr = ""
				}
			} else {
				ime.compStr = text
			}
			immGlobal.mu.Unlock()
			ctx.SetReturn(1)
			return 0
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCompositionWindow", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		ptr := ctx.Arg(1)
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		if ime != nil && ptr != 0 {
			writeCompositionForm(ptr, ime)
		}
		immGlobal.mu.Unlock()
		if ime != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionWindow", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		ptr := ctx.Arg(1)
		immGlobal.mu.Lock()
		if ime := lookupContext(himc); ime != nil {
			if ptr != 0 {
				readCompositionForm(ptr, ime)
			}
			immGlobal.mu.Unlock()
			ctx.SetReturn(1)
			return 0
		}
		immGlobal.mu.Unlock()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCompositionFontW", func(ctx *ntapi.TrapContext) uint32 {
		himc := uint32(ctx.Arg(0))
		_ = ctx.Arg(1)
		immGlobal.mu.Lock()
		ime := lookupContext(himc)
		immGlobal.mu.Unlock()
		if ime != nil {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateListCountW", func(ctx *ntapi.TrapContext) uint32 {
		if ptr := ctx.Arg(1); ptr != 0 {
			mem.Write32(ptr, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetCandidateWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetCandidateWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmGetStatusWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetStatusWindowPos", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmGetDefaultIMEWnd", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmNotifyIME", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSimulateHotKey", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmInstallIMEW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetDescriptionW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetIMEFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(imm32dll, "ImmDisableIME", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmDisableTextFrameService", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEnumInputContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetVirtualKey", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(vkProcessKey)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmRegisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmUnregisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEnumRegisterWordW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetRegisterWordStyleW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmConfigureIMEW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmEscapeW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmGetHotKey", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(imm32dll, "ImmSetHotKey", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
}
