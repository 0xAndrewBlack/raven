//go:build guest_windows

package main

import (
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	glFalse = 0
	glTrue  = 1

	glNoError                = 0
	glVendor                 = 0x1F00
	glRenderer               = 0x1F01
	glVersion                = 0x1F02
	glMaxTextureSize         = 0x0D33
	glShadingLanguageVersion = 0x8B8C
	glCompileStatus          = 0x8B81
	glLinkStatus             = 0x8B82
	glMaxDrawBuffers         = 0x8824
	glMaxVertexAttribs       = 0x8869
	glMajorVersion           = 0x821B
	glMinorVersion           = 0x821C
	glFramebufferComplete    = 0x8CD5

	pfdDoublebuffer  = 0x00000001
	pfdDrawToWindow  = 0x00000004
	pfdSupportOpenGL = 0x00000020
	pfdTypeRGBA      = 0
	pfdMainPlane     = 0
)

type glState struct {
	mu         sync.Mutex
	nextCtx    uint32
	contexts   map[uint32]*glContext
	currCtx    uint32
	swapIntv   int32
	nextTex    uint32
	nextBuf    uint32
	nextShd    uint32
	nextProg   uint32
	nextFbo    uint32
	nextRbo    uint32
	nextVao    uint32
	pixelFmts  map[uint64]int32
	textures   map[uint32]struct{}
	buffers    map[uint32]struct{}
	shaders    map[uint32]struct{}
	programs   map[uint32]struct{}
	fbos       map[uint32]struct{}
	rbos       map[uint32]struct{}
	vaos       map[uint32]struct{}
	currProg   uint32
	viewport   [4]int32
	stringPtrs map[string]uint64
}

type glContext struct {
	hdc      uint64
	pixelFmt int32
}

var glGlobal = glState{
	nextCtx:    0x8000,
	contexts:   make(map[uint32]*glContext),
	nextTex:    1,
	nextBuf:    1,
	nextShd:    1,
	nextProg:   1,
	nextFbo:    1,
	nextRbo:    1,
	nextVao:    1,
	pixelFmts:  make(map[uint64]int32),
	textures:   make(map[uint32]struct{}),
	buffers:    make(map[uint32]struct{}),
	shaders:    make(map[uint32]struct{}),
	programs:   make(map[uint32]struct{}),
	fbos:       make(map[uint32]struct{}),
	rbos:       make(map[uint32]struct{}),
	vaos:       make(map[uint32]struct{}),
	stringPtrs: make(map[string]uint64),
}

func glCreateContextHandle(hdc uint64) uint32 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()

	handle := glGlobal.nextCtx
	glGlobal.nextCtx++
	pixelFmt := glGlobal.pixelFmts[hdc]
	if pixelFmt == 0 {
		pixelFmt = 1
	}
	glGlobal.contexts[handle] = &glContext{hdc: hdc, pixelFmt: pixelFmt}
	return handle
}

func glDeleteContextHandle(hglrc uint32) bool {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()

	delete(glGlobal.contexts, hglrc)
	if glGlobal.currCtx == hglrc {
		glGlobal.currCtx = 0
	}
	return true
}

func glMakeCurrentContext(hdc uint64, hglrc uint32) bool {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()

	if hglrc == 0 {
		glGlobal.currCtx = 0
		return true
	}
	ctx, ok := glGlobal.contexts[hglrc]
	if !ok {
		return false
	}
	ctx.hdc = hdc
	if pixelFmt := glGlobal.pixelFmts[hdc]; pixelFmt != 0 {
		ctx.pixelFmt = pixelFmt
	}
	glGlobal.currCtx = hglrc
	return true
}

func glCurrentContextHandle() uint32 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	return glGlobal.currCtx
}

func glCurrentDCHandle() uint64 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()

	ctx := glGlobal.contexts[glGlobal.currCtx]
	if ctx == nil {
		return 0
	}
	return ctx.hdc
}

func glRememberPixelFormat(hdc uint64, format int32) {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	glGlobal.pixelFmts[hdc] = format
	if ctx := glGlobal.contexts[glGlobal.currCtx]; ctx != nil && ctx.hdc == hdc {
		ctx.pixelFmt = format
	}
}

func glLookupPixelFormat(hdc uint64) int32 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	if format := glGlobal.pixelFmts[hdc]; format != 0 {
		return format
	}
	return 1
}

func glAllocObjectID(next *uint32, store map[uint32]struct{}) uint32 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	id := *next
	*next++
	store[id] = struct{}{}
	return id
}

func glDeleteObjectID(store map[uint32]struct{}, id uint32) {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	delete(store, id)
}

func glStoreCurrentProgram(id uint32) {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	glGlobal.currProg = id
}

func glStoreViewport(x, y, w, h int32) {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	glGlobal.viewport = [4]int32{x, y, w, h}
}

func glSetSwapInterval(interval int32) {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	glGlobal.swapIntv = interval
}

func glGetSwapInterval() int32 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()
	return glGlobal.swapIntv
}

func glCachedCString(mem *mmu.MMU, alloc func(uint64, bool) uint64, key, value string) uint64 {
	glGlobal.mu.Lock()
	defer glGlobal.mu.Unlock()

	if ptr := glGlobal.stringPtrs[key]; ptr != 0 {
		return ptr
	}
	ptr := alloc(uint64(len(value)+1), true)
	if ptr == 0 {
		return 0
	}
	_ = mem.WriteBytes(ptr, append([]byte(value), 0))
	glGlobal.stringPtrs[key] = ptr
	return ptr
}

func glWriteDefaultPFD(mem *mmu.MMU, ppfd uint64) {
	if ppfd == 0 {
		return
	}
	_ = mem.Write16(ppfd+0, 40)
	_ = mem.Write16(ppfd+2, 1)
	_ = mem.Write32(ppfd+4, pfdDoublebuffer|pfdDrawToWindow|pfdSupportOpenGL)
	_ = mem.Write8(ppfd+8, pfdTypeRGBA)
	_ = mem.Write8(ppfd+9, 32)
	_ = mem.Write8(ppfd+10, 8)
	_ = mem.Write8(ppfd+11, 0)
	_ = mem.Write8(ppfd+12, 8)
	_ = mem.Write8(ppfd+13, 0)
	_ = mem.Write8(ppfd+14, 8)
	_ = mem.Write8(ppfd+15, 0)
	_ = mem.Write8(ppfd+16, 8)
	_ = mem.Write8(ppfd+17, 0)
	_ = mem.Write8(ppfd+18, 0)
	_ = mem.Write8(ppfd+19, 0)
	_ = mem.Write8(ppfd+20, 0)
	_ = mem.Write8(ppfd+21, 0)
	_ = mem.Write8(ppfd+22, 0)
	_ = mem.Write8(ppfd+23, 24)
	_ = mem.Write8(ppfd+24, 8)
	_ = mem.Write8(ppfd+25, 0)
	_ = mem.Write8(ppfd+26, pfdMainPlane)
	_ = mem.Write8(ppfd+27, 0)
	_ = mem.Write32(ppfd+28, 0)
	_ = mem.Write32(ppfd+32, 0)
	_ = mem.Write32(ppfd+36, 0)
}

func glWriteZeroes(mem *mmu.MMU, addr uint64, size uint64) {
	if addr == 0 || size == 0 {
		return
	}
	zero := make([]byte, 4096)
	for size > 0 {
		chunk := uint64(len(zero))
		if size < chunk {
			chunk = size
		}
		_ = mem.WriteBytes(addr, zero[:chunk])
		addr += chunk
		size -= chunk
	}
}

func registerOpengl32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	sharedHeapAlloc := hctx.HeapAlloc
	readGuestString := hctx.ReadGuestString
	dll, ok := hctx.SynthByName["opengl32.dll"]
	if !ok {
		return
	}

	const wglExtensions = "WGL_ARB_extensions_string WGL_ARB_pixel_format WGL_ARB_create_context WGL_EXT_swap_control"

	nextDynID := uint32(ntapi.DynExportIDBase + 0x300)
	reg := func(name string, h ntapi.TrapHandler) {
		d.RegisterDynamicHandler(mem, dll, name, nextDynID, h)
		nextDynID++
	}

	writeInfoLog := func(maxLength uint64, lengthPtr, infoLog uint64) {
		if lengthPtr != 0 {
			_ = mem.Write32(lengthPtr, 0)
		}
		if infoLog != 0 && maxLength > 0 {
			_ = mem.Write8(infoLog, 0)
		}
	}

	genIDs := func(n int, out uint64, next *uint32, store map[uint32]struct{}) {
		if n <= 0 || out == 0 {
			return
		}
		for i := 0; i < n; i++ {
			id := glAllocObjectID(next, store)
			_ = mem.Write32(out+uint64(i*4), id)
		}
	}

	deleteIDs := func(n int, in uint64, store map[uint32]struct{}) {
		if n <= 0 || in == 0 {
			return
		}
		for i := 0; i < n; i++ {
			id, _ := mem.Read32(in + uint64(i*4))
			glDeleteObjectID(store, id)
		}
	}

	reg("wglCreateContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glCreateContextHandle(ctx.Arg(0))))
		return 0
	})
	reg("wglDeleteContext", func(ctx *ntapi.TrapContext) uint32 {
		if glDeleteContextHandle(uint32(ctx.Arg(0))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("wglMakeCurrent", func(ctx *ntapi.TrapContext) uint32 {
		if glMakeCurrentContext(ctx.Arg(0), uint32(ctx.Arg(1))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	reg("wglGetCurrentContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glCurrentContextHandle()))
		return 0
	})
	reg("wglGetCurrentDC", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(glCurrentDCHandle())
		return 0
	})
	reg("wglGetProcAddress", func(ctx *ntapi.TrapContext) uint32 {
		procName := readGuestString(ctx.Arg(0))
		if procName == "" {
			ctx.SetReturn(0)
			return 0
		}
		if addr, ok := dll.Exports[procName]; ok {
			ctx.SetReturn(addr)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	reg("wglShareLists", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("wglCopyContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("wglCreateLayerContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glCreateContextHandle(ctx.Arg(0))))
		return 0
	})
	reg("wglDescribeLayerPlane", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("wglSwapLayerBuffers", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("wglUseFontBitmapsW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("wglUseFontOutlinesW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	reg("ChoosePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("SetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		glRememberPixelFormat(ctx.Arg(0), int32(ctx.Arg(1)))
		ctx.SetReturn(1)
		return 0
	})
	reg("GetPixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glLookupPixelFormat(ctx.Arg(0))))
		return 0
	})
	reg("DescribePixelFormat", func(ctx *ntapi.TrapContext) uint32 {
		glWriteDefaultPFD(mem, ctx.Arg(3))
		ctx.SetReturn(1)
		return 0
	})
	reg("SwapBuffers", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	reg("glGetString", func(ctx *ntapi.TrapContext) uint32 {
		var value string
		switch uint32(ctx.Arg(0)) {
		case glVendor:
			value = "Raven"
		case glRenderer:
			value = "Raven GL Bridge"
		case glVersion:
			value = "4.6.0"
		case glShadingLanguageVersion:
			value = "4.60"
		}
		if value == "" {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(glCachedCString(mem, sharedHeapAlloc, "gl:"+value, value))
		return 0
	})
	reg("glGetIntegerv", func(ctx *ntapi.TrapContext) uint32 {
		params := ctx.Arg(1)
		if params == 0 {
			return 0
		}
		var value uint32
		switch uint32(ctx.Arg(0)) {
		case glMaxTextureSize:
			value = 16384
		case glMajorVersion:
			value = 4
		case glMinorVersion:
			value = 6
		case glMaxVertexAttribs:
			value = 16
		case glMaxDrawBuffers:
			value = 8
		default:
			value = 0
		}
		_ = mem.Write32(params, value)
		return 0
	})
	reg("glGetError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(glNoError)
		return 0
	})
	reg("glEnable", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDisable", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glViewport", func(ctx *ntapi.TrapContext) uint32 {
		glStoreViewport(int32(ctx.Arg(0)), int32(ctx.Arg(1)), int32(ctx.Arg(2)), int32(ctx.Arg(3)))
		return 0
	})
	reg("glClear", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glClearColor", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glFlush", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glFinish", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glGenTextures", func(ctx *ntapi.TrapContext) uint32 {
		genIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), &glGlobal.nextTex, glGlobal.textures)
		return 0
	})
	reg("glDeleteTextures", func(ctx *ntapi.TrapContext) uint32 {
		deleteIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), glGlobal.textures)
		return 0
	})
	reg("glBindTexture", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glGenBuffers", func(ctx *ntapi.TrapContext) uint32 {
		genIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), &glGlobal.nextBuf, glGlobal.buffers)
		return 0
	})
	reg("glDeleteBuffers", func(ctx *ntapi.TrapContext) uint32 {
		deleteIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), glGlobal.buffers)
		return 0
	})
	reg("glBindBuffer", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glCreateShader", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glAllocObjectID(&glGlobal.nextShd, glGlobal.shaders)))
		return 0
	})
	reg("glDeleteShader", func(ctx *ntapi.TrapContext) uint32 {
		glDeleteObjectID(glGlobal.shaders, uint32(ctx.Arg(0)))
		return 0
	})
	reg("glCompileShader", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glCreateProgram", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glAllocObjectID(&glGlobal.nextProg, glGlobal.programs)))
		return 0
	})
	reg("glDeleteProgram", func(ctx *ntapi.TrapContext) uint32 {
		glDeleteObjectID(glGlobal.programs, uint32(ctx.Arg(0)))
		if uint32(ctx.Arg(0)) == glGlobal.currProg {
			glStoreCurrentProgram(0)
		}
		return 0
	})
	reg("glLinkProgram", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glUseProgram", func(ctx *ntapi.TrapContext) uint32 {
		glStoreCurrentProgram(uint32(ctx.Arg(0)))
		return 0
	})
	reg("glGetShaderiv", func(ctx *ntapi.TrapContext) uint32 {
		params := ctx.Arg(2)
		if params != 0 {
			value := uint32(0)
			if uint32(ctx.Arg(1)) == glCompileStatus {
				value = glTrue
			}
			_ = mem.Write32(params, value)
		}
		return 0
	})
	reg("glGetProgramiv", func(ctx *ntapi.TrapContext) uint32 {
		params := ctx.Arg(2)
		if params != 0 {
			value := uint32(0)
			if uint32(ctx.Arg(1)) == glLinkStatus {
				value = glTrue
			}
			_ = mem.Write32(params, value)
		}
		return 0
	})
	reg("glGetShaderInfoLog", func(ctx *ntapi.TrapContext) uint32 {
		writeInfoLog(ctx.Arg(1), ctx.Arg(2), ctx.Arg(3))
		return 0
	})
	reg("glGetProgramInfoLog", func(ctx *ntapi.TrapContext) uint32 {
		writeInfoLog(ctx.Arg(1), ctx.Arg(2), ctx.Arg(3))
		return 0
	})
	reg("glShaderSource", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glAttachShader", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDetachShader", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glGetUniformLocation", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("glUniform1i", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glUniform2f", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glUniform3f", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glUniform4f", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glUniformMatrix4fv", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glVertexAttribPointer", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glEnableVertexAttribArray", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDisableVertexAttribArray", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDrawArrays", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDrawElements", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glPixelStorei", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glTexImage2D", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glTexSubImage2D", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glTexParameteri", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glBlendFunc", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glBlendFuncSeparate", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDepthFunc", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDepthMask", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glStencilFunc", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glStencilOp", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glScissor", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glReadPixels", func(ctx *ntapi.TrapContext) uint32 {
		width := int64(int32(ctx.Arg(2)))
		height := int64(int32(ctx.Arg(3)))
		if width <= 0 || height <= 0 {
			return 0
		}
		size := uint64(width * height * 4)
		glWriteZeroes(mem, ctx.Arg(6), size)
		return 0
	})
	reg("glGenFramebuffers", func(ctx *ntapi.TrapContext) uint32 {
		genIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), &glGlobal.nextFbo, glGlobal.fbos)
		return 0
	})
	reg("glBindFramebuffer", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDeleteFramebuffers", func(ctx *ntapi.TrapContext) uint32 {
		deleteIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), glGlobal.fbos)
		return 0
	})
	reg("glGenRenderbuffers", func(ctx *ntapi.TrapContext) uint32 {
		genIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), &glGlobal.nextRbo, glGlobal.rbos)
		return 0
	})
	reg("glBindRenderbuffer", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDeleteRenderbuffers", func(ctx *ntapi.TrapContext) uint32 {
		deleteIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), glGlobal.rbos)
		return 0
	})
	reg("glFramebufferTexture2D", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glRenderbufferStorage", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glCheckFramebufferStatus", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(glFramebufferComplete)
		return 0
	})
	reg("glGenVertexArrays", func(ctx *ntapi.TrapContext) uint32 {
		genIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), &glGlobal.nextVao, glGlobal.vaos)
		return 0
	})
	reg("glBindVertexArray", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glDeleteVertexArrays", func(ctx *ntapi.TrapContext) uint32 {
		deleteIDs(int(int32(ctx.Arg(0))), ctx.Arg(1), glGlobal.vaos)
		return 0
	})
	reg("glBufferData", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glBufferSubData", func(ctx *ntapi.TrapContext) uint32 { return 0 })
	reg("glMapBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	reg("glUnmapBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	reg("glIsEnabled", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(glFalse)
		return 0
	})

	reg("wglGetExtensionsStringARB", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(glCachedCString(mem, sharedHeapAlloc, "wgl:extensions", wglExtensions))
		return 0
	})
	reg("wglChoosePixelFormatARB", func(ctx *ntapi.TrapContext) uint32 {
		nMaxFormats := uint32(ctx.Arg(3))
		formats := ctx.Arg(4)
		numFormats := ctx.Arg(5)
		if formats != 0 && nMaxFormats > 0 {
			_ = mem.Write32(formats, 1)
		}
		if numFormats != 0 {
			_ = mem.Write32(numFormats, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	reg("wglCreateContextAttribsARB", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(glCreateContextHandle(ctx.Arg(0))))
		return 0
	})
	reg("wglSwapIntervalEXT", func(ctx *ntapi.TrapContext) uint32 {
		glSetSwapInterval(int32(ctx.Arg(0)))
		ctx.SetReturn(1)
		return 0
	})
	reg("wglGetSwapIntervalEXT", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(uint32(glGetSwapInterval())))
		return 0
	})
}
