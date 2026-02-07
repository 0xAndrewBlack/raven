//go:build guest_windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	gotime "time"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

// registerMsvcp140Handlers registers handlers for msvcp140.dll - the MSVC
// C++ Standard Library runtime. Covers operator new/delete, basic_string,
// std::mutex, std::exception, stream init, and concurrency helpers.
func registerMsvcp140Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree

	msvcp, ok := hctx.SynthByName["msvcp140.dll"]
	if !ok {
		return
	}

	abortRuntime := func(kind, msg string) uint32 {
		if msg != "" {
			ravelog.Logf("[msvcp] %s: %s\n", kind, msg)
			fmt.Fprintf(os.Stderr, "govm: %s: %s\n", kind, msg)
		} else {
			ravelog.Logf("[msvcp] %s\n", kind)
			fmt.Fprintf(os.Stderr, "govm: %s\n", kind)
		}
		os.Exit(3)
		return 0
	}
	_ = abortRuntime

	// ════════════════════════════════════════════════════════════════════
	// operator new / operator delete
	//
	// MSVC's operator new calls malloc and throws std::bad_alloc on failure.
	// operator delete calls free.  The mangled names are:
	//   ??2@YAPEAX_K@Z   = operator new(size_t)
	//   ??3@YAXPEAX@Z    = operator delete(void*)
	//   ??_U@YAPEAX_K@Z  = operator new[](size_t)
	//   ??_V@YAXPEAX@Z   = operator delete[](void*)
	// ════════════════════════════════════════════════════════════════════

	operatorNew := func(ctx *ntapi.TrapContext) uint32 {
		size := ctx.Arg(0)
		if size == 0 {
			size = 1 // C++ requires new(0) to return non-null
		}
		ptr := sharedHeapAlloc(size, false)
		if ptr == 0 {
			ravelog.Logf("[msvcp] operator new(%d) failed - out of memory\n", size)
			// In a real implementation this would throw std::bad_alloc.
			// Return 0 to trigger NULL pointer dereference which is detectable.
		}
		ctx.SetReturn(ptr)
		return 0
	}

	operatorDelete := func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		if ptr != 0 {
			sharedHeapFree(ptr)
		}
		return 0
	}

	// operator new(size_t)
	d.RegisterAutoStubHandler(msvcp, "??2@YAPEAX_K@Z", operatorNew)
	d.RegisterAutoStubHandler(msvcp, "??2@YAPAXI@Z", operatorNew)
	// operator new[](size_t)
	d.RegisterAutoStubHandler(msvcp, "??_U@YAPEAX_K@Z", operatorNew)
	d.RegisterAutoStubHandler(msvcp, "??_U@YAPAXI@Z", operatorNew)
	// operator delete(void*)
	d.RegisterAutoStubHandler(msvcp, "??3@YAXPEAX@Z", operatorDelete)
	d.RegisterAutoStubHandler(msvcp, "??3@YAXPAX@Z", operatorDelete)
	// operator delete[](void*)
	d.RegisterAutoStubHandler(msvcp, "??_V@YAXPEAX@Z", operatorDelete)
	d.RegisterAutoStubHandler(msvcp, "??_V@YAXPAX@Z", operatorDelete)
	// operator delete(void*, size_t) - sized delete
	d.RegisterAutoStubHandler(msvcp, "??3@YAXPEAX_K@Z", operatorDelete)
	d.RegisterAutoStubHandler(msvcp, "??3@YAXPAXI@Z", operatorDelete)
	// operator delete[](void*, size_t) - sized delete[]
	d.RegisterAutoStubHandler(msvcp, "??_V@YAXPEAX_K@Z", operatorDelete)
	d.RegisterAutoStubHandler(msvcp, "??_V@YAXPAXI@Z", operatorDelete)
	// operator new(size_t, nothrow) - returns null on failure
	d.RegisterAutoStubHandler(msvcp, "??2@YAPEAX_KAEBUnothrow_t@std@@@Z", operatorNew)
	// operator new[](size_t, nothrow)
	d.RegisterAutoStubHandler(msvcp, "??_U@YAPEAX_KAEBUnothrow_t@std@@@Z", operatorNew)

	// ════════════════════════════════════════════════════════════════════
	// std::exception::what()
	// Mangled: ?what@exception@@UEBAPEBDXZ
	// Returns const char* to the stored what-string.
	//
	// MSVC std::exception layout (x64):
	//   [0]   vtable pointer
	//   [8]   char* _Mywhat    (the what() string)
	//   [16]  bool  _Mydofree
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(msvcp, "?what@exception@@UEBAPEBDXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			static := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
			msg := []byte("Unknown exception\x00")
			mem.WriteBytes(static, msg)
			ctx.SetReturn(static)
			return 0
		}
		whatPtr, _ := mem.Read64(thisPtr + 8) // _Mywhat
		if whatPtr == 0 {
			static := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
			msg := []byte("Unknown exception\x00")
			mem.WriteBytes(static, msg)
			ctx.SetReturn(static)
			return 0
		}
		ctx.SetReturn(whatPtr)
		return 0
	})

	// std::exception copy constructor
	// ??0exception@@QEAA@AEBV0@@Z
	d.RegisterAutoStubHandler(msvcp, "??0exception@@QEAA@AEBV0@@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		other := ctx.Arg(1)
		if thisPtr == 0 || other == 0 {
			ctx.SetReturn(thisPtr)
			return 0
		}
		vtable, _ := mem.Read64(other)
		srcWhat, _ := mem.Read64(other + 8)
		mem.Write64(thisPtr, vtable)
		if srcWhat != 0 {
			n := uint64(0)
			for {
				b, _ := mem.Read8(srcWhat + n)
				if b == 0 {
					break
				}
				n++
				if n > 0x10000 {
					break
				}
			}
			newBuf := sharedHeapAlloc(n+1, false)
			if newBuf != 0 {
				data, _ := mem.ReadBytes(srcWhat, int(n))
				mem.WriteBytes(newBuf, append(data, 0))
			}
			mem.Write64(thisPtr+8, newBuf)
			mem.Write8(thisPtr+16, 1) // _Mydofree = true
		} else {
			mem.Write64(thisPtr+8, 0)
			mem.Write8(thisPtr+16, 0)
		}
		ctx.SetReturn(thisPtr)
		return 0
	})

	// std::exception default constructor: ??0exception@@QEAA@XZ
	d.RegisterAutoStubHandler(msvcp, "??0exception@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr != 0 {
			mem.Write64(thisPtr, 0)   // vtable
			mem.Write64(thisPtr+8, 0) // _Mywhat = NULL
			mem.Write8(thisPtr+16, 0) // _Mydofree = false
		}
		ctx.SetReturn(thisPtr)
		return 0
	})

	// std::exception destructor: ??1exception@@UEAA@XZ
	d.RegisterAutoStubHandler(msvcp, "??1exception@@UEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr != 0 {
			whatPtr, _ := mem.Read64(thisPtr + 8)
			doFree, _ := mem.Read8(thisPtr + 16)
			if whatPtr != 0 && doFree != 0 {
				sharedHeapFree(whatPtr)
			}
			mem.Write64(thisPtr+8, 0)
			mem.Write8(thisPtr+16, 0)
		}
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// std::basic_string<char> (MSVC x64 layout)
	//
	// MSVC std::string has SSO (Small String Optimization):
	//   [0..15]  union { char Buf[16]; struct { char* Ptr; } }
	//   [16]     size_t _Mysize (character count)
	//   [24]     size_t _Myres  (allocated capacity, or 15 for SSO)
	//
	// If _Myres <= 15: string is stored inline in Buf[0..15]
	// If _Myres > 15:  Ptr at [0..7] points to heap allocation
	//
	// Total struct size: 32 bytes
	// ════════════════════════════════════════════════════════════════════

	const (
		msvcStringBufOff  = 0  // union: inline buffer or heap pointer
		msvcStringSizeOff = 16 // _Mysize
		msvcStringResOff  = 24 // _Myres (capacity)
		msvcStringSSOMax  = 15 // max chars for SSO
		msvcStringSize    = 32 // sizeof(std::string)
	)

	readMsvcString := func(addr uint64) string {
		if addr == 0 {
			return ""
		}
		size, _ := mem.Read64(addr + msvcStringSizeOff)
		res, _ := mem.Read64(addr + msvcStringResOff)
		if size == 0 {
			return ""
		}
		if size > 0x100000 {
			size = 0x100000
		}
		var dataAddr uint64
		if res <= msvcStringSSOMax {
			dataAddr = addr + msvcStringBufOff
		} else {
			dataAddr, _ = mem.Read64(addr + msvcStringBufOff)
		}
		if dataAddr == 0 {
			return ""
		}
		data, _ := mem.ReadBytes(dataAddr, int(size))
		return string(data)
	}

	writeMsvcString := func(addr uint64, s string) {
		if addr == 0 {
			return
		}
		n := uint64(len(s))
		mem.Write64(addr+msvcStringSizeOff, n)
		if n <= msvcStringSSOMax {
			mem.Write64(addr+msvcStringResOff, msvcStringSSOMax)
			if n > 0 {
				mem.WriteBytes(addr+msvcStringBufOff, []byte(s))
			}
			mem.Write8(addr+msvcStringBufOff+n, 0) // null terminator
		} else {
			buf := sharedHeapAlloc(n+1, false)
			mem.WriteBytes(buf, append([]byte(s), 0))
			mem.Write64(addr+msvcStringBufOff, buf)
			mem.Write64(addr+msvcStringResOff, n)
		}
	}

	destroyMsvcString := func(addr uint64) {
		if addr == 0 {
			return
		}
		res, _ := mem.Read64(addr + msvcStringResOff)
		if res > msvcStringSSOMax {
			heapPtr, _ := mem.Read64(addr + msvcStringBufOff)
			if heapPtr != 0 {
				sharedHeapFree(heapPtr)
			}
		}
		for i := uint64(0); i < msvcStringSize; i += 8 {
			mem.Write64(addr+i, 0)
		}
	}

	// Constructor from const char*:
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		srcPtr := ctx.Arg(1)
		s := hctx.ReadGuestString(srcPtr)
		writeMsvcString(thisPtr, s)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// Copy constructor:
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		other := ctx.Arg(1)
		s := readMsvcString(other)
		writeMsvcString(thisPtr, s)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// Default constructor:
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr != 0 {
			writeMsvcString(thisPtr, "")
		}
		ctx.SetReturn(thisPtr)
		return 0
	})

	// Destructor:
	d.RegisterAutoStubHandler(msvcp, "??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		destroyMsvcString(thisPtr)
		return 0
	})

	// assign(const char*, size_t):
	d.RegisterAutoStubHandler(msvcp, "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD_K@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		srcPtr := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x100000 {
			count = 0x100000
		}
		data, _ := mem.ReadBytes(srcPtr, int(count))
		destroyMsvcString(thisPtr)
		writeMsvcString(thisPtr, string(data))
		ctx.SetReturn(thisPtr)
		return 0
	})

	// assign(const basic_string&):
	d.RegisterAutoStubHandler(msvcp, "?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@AEBV12@@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		other := ctx.Arg(1)
		s := readMsvcString(other)
		destroyMsvcString(thisPtr)
		writeMsvcString(thisPtr, s)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// append(const char*, size_t):
	d.RegisterAutoStubHandler(msvcp, "?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD_K@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		srcPtr := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x100000 {
			count = 0x100000
		}
		existing := readMsvcString(thisPtr)
		appendData, _ := mem.ReadBytes(srcPtr, int(count))
		combined := existing + string(appendData)
		destroyMsvcString(thisPtr)
		writeMsvcString(thisPtr, combined)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// c_str():
	d.RegisterAutoStubHandler(msvcp, "?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		res, _ := mem.Read64(thisPtr + msvcStringResOff)
		if res <= msvcStringSSOMax {
			ctx.SetReturn(thisPtr + msvcStringBufOff)
		} else {
			ptr, _ := mem.Read64(thisPtr + msvcStringBufOff)
			ctx.SetReturn(ptr)
		}
		return 0
	})

	// size():
	d.RegisterAutoStubHandler(msvcp, "?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		sz, _ := mem.Read64(thisPtr + msvcStringSizeOff)
		ctx.SetReturn(sz)
		return 0
	})

	// empty():
	d.RegisterAutoStubHandler(msvcp, "?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(1)
			return 0
		}
		sz, _ := mem.Read64(thisPtr + msvcStringSizeOff)
		if sz == 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// std::basic_string<wchar_t> (wide string)
	// Same layout but with 2-byte characters; SSO threshold is 7 chars.
	// ════════════════════════════════════════════════════════════════════

	const wstrSSOMax = 7

	readMsvcWString := func(addr uint64) string {
		if addr == 0 {
			return ""
		}
		size, _ := mem.Read64(addr + msvcStringSizeOff)
		res, _ := mem.Read64(addr + msvcStringResOff)
		if size == 0 {
			return ""
		}
		if size > 0x80000 {
			size = 0x80000
		}
		var dataAddr uint64
		if res <= wstrSSOMax {
			dataAddr = addr + msvcStringBufOff
		} else {
			dataAddr, _ = mem.Read64(addr + msvcStringBufOff)
		}
		if dataAddr == 0 {
			return ""
		}
		runes := make([]rune, size)
		for i := uint64(0); i < size; i++ {
			ch, _ := mem.Read16(dataAddr + i*2)
			runes[i] = rune(ch)
		}
		return string(runes)
	}

	writeMsvcWString := func(addr uint64, s string) {
		if addr == 0 {
			return
		}
		runes := []rune(s)
		n := uint64(len(runes))
		mem.Write64(addr+msvcStringSizeOff, n)
		if n <= wstrSSOMax {
			mem.Write64(addr+msvcStringResOff, wstrSSOMax)
			for i := uint64(0); i < n; i++ {
				mem.Write16(addr+msvcStringBufOff+i*2, uint16(runes[i]))
			}
			mem.Write16(addr+msvcStringBufOff+n*2, 0)
		} else {
			buf := sharedHeapAlloc((n+1)*2, false)
			for i := uint64(0); i < n; i++ {
				mem.Write16(buf+i*2, uint16(runes[i]))
			}
			mem.Write16(buf+n*2, 0)
			mem.Write64(addr+msvcStringBufOff, buf)
			mem.Write64(addr+msvcStringResOff, n)
		}
	}

	destroyMsvcWString := func(addr uint64) {
		if addr == 0 {
			return
		}
		res, _ := mem.Read64(addr + msvcStringResOff)
		if res > wstrSSOMax {
			heapPtr, _ := mem.Read64(addr + msvcStringBufOff)
			if heapPtr != 0 {
				sharedHeapFree(heapPtr)
			}
		}
		for i := uint64(0); i < msvcStringSize; i += 8 {
			mem.Write64(addr+i, 0)
		}
	}

	// wstring default constructor
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		writeMsvcWString(thisPtr, "")
		ctx.SetReturn(thisPtr)
		return 0
	})

	// wstring copy constructor
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@AEBV01@@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		other := ctx.Arg(1)
		s := readMsvcWString(other)
		writeMsvcWString(thisPtr, s)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// wstring destructor
	d.RegisterAutoStubHandler(msvcp, "??1?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		destroyMsvcWString(thisPtr)
		return 0
	})

	// wstring constructor from const wchar_t*
	d.RegisterAutoStubHandler(msvcp, "??0?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAA@PEB_W@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		srcPtr := ctx.Arg(1)
		writeMsvcWString(thisPtr, hctx.ReadGuestUTF16(srcPtr))
		ctx.SetReturn(thisPtr)
		return 0
	})

	// wstring assign(const wchar_t*)
	d.RegisterAutoStubHandler(msvcp, "?assign@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEAAAEAV12@PEB_W@Z", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		destroyMsvcWString(thisPtr)
		writeMsvcWString(thisPtr, hctx.ReadGuestUTF16(ctx.Arg(1)))
		ctx.SetReturn(thisPtr)
		return 0
	})

	// wstring c_str()
	d.RegisterAutoStubHandler(msvcp, "?c_str@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBAPEB_WXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		res, _ := mem.Read64(thisPtr + msvcStringResOff)
		if res <= wstrSSOMax {
			ctx.SetReturn(thisPtr + msvcStringBufOff)
		} else {
			ptr, _ := mem.Read64(thisPtr + msvcStringBufOff)
			ctx.SetReturn(ptr)
		}
		return 0
	})

	// wstring size()/length()
	d.RegisterAutoStubHandler(msvcp, "?size@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		sz, _ := mem.Read64(thisPtr + msvcStringSizeOff)
		ctx.SetReturn(sz)
		return 0
	})
	d.RegisterAutoStubHandler(msvcp, "?length@?$basic_string@_WU?$char_traits@_W@std@@V?$allocator@_W@2@@std@@QEBA_KXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		sz, _ := mem.Read64(thisPtr + msvcStringSizeOff)
		ctx.SetReturn(sz)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// std::mutex - backed by Go sync.Mutex keyed on guest address
	// ════════════════════════════════════════════════════════════════════

	var mutexMapMu sync.Mutex
	mutexMap := make(map[uint64]*sync.Mutex)

	getMutex := func(addr uint64) *sync.Mutex {
		mutexMapMu.Lock()
		defer mutexMapMu.Unlock()
		m, ok := mutexMap[addr]
		if !ok {
			m = &sync.Mutex{}
			mutexMap[addr] = m
		}
		return m
	}

	// ?lock@mutex@std@@QEAAXXZ
	d.RegisterAutoStubHandler(msvcp, "?lock@mutex@std@@QEAAXXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		getMutex(thisPtr).Lock()
		return 0
	})

	// ?unlock@mutex@std@@QEAAXXZ
	d.RegisterAutoStubHandler(msvcp, "?unlock@mutex@std@@QEAAXXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		getMutex(thisPtr).Unlock()
		return 0
	})

	// ?try_lock@mutex@std@@QEAA_NXZ
	d.RegisterAutoStubHandler(msvcp, "?try_lock@mutex@std@@QEAA_NXZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if getMutex(thisPtr).TryLock() {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// mutex constructor: ??0mutex@std@@QEAA@XZ
	d.RegisterAutoStubHandler(msvcp, "??0mutex@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		_ = getMutex(thisPtr)
		ctx.SetReturn(thisPtr)
		return 0
	})

	// mutex destructor: ??1mutex@std@@QEAA@XZ
	d.RegisterAutoStubHandler(msvcp, "??1mutex@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		mutexMapMu.Lock()
		delete(mutexMap, thisPtr)
		mutexMapMu.Unlock()
		return 0
	})

	// recursive_mutex constructor: ??0recursive_mutex@std@@QEAA@XZ
	d.RegisterAutoStubHandler(msvcp, "??0recursive_mutex@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		thisPtr := ctx.Arg(0)
		if thisPtr != 0 {
			mem.Write64(thisPtr, 0)
			mem.Write32(thisPtr+8, 0)
			mem.Write32(thisPtr+12, 0)
			mem.Write64(thisPtr+16, 0)
			mem.Write64(thisPtr+24, 0)
			mem.Write64(thisPtr+32, 0)
		}
		ctx.SetReturn(thisPtr)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// std::thread::hardware_concurrency
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(msvcp, "?hardware_concurrency@thread@std@@SAIXZ", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(runtime.NumCPU()))
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// std::ios_base::Init
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(msvcp, "??0Init@ios_base@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[msvcp] std::ios_base::Init constructed\n")
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "??1Init@ios_base@std@@QEAA@XZ", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// Locale support (minimal)
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(msvcp, "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	var codecvtIdSlot uint64
	d.RegisterAutoStubHandler(msvcp, "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A", func(ctx *ntapi.TrapContext) uint32 {
		if codecvtIdSlot == 0 {
			codecvtIdSlot = mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
			mem.Write64(codecvtIdSlot, 1)
		}
		ctx.SetReturn(codecvtIdSlot)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// Concurrency / once_flag / condition variables / low-level mutex
	// ════════════════════════════════════════════════════════════════════

	var onceMu sync.Mutex
	onceFlags := make(map[uint64]bool)

	d.RegisterAutoStubHandler(msvcp, "?_Execute_once@std@@YAHAEAUonce_flag@1@P6AHPEAX1PEAPEAX@Z1@Z", func(ctx *ntapi.TrapContext) uint32 {
		flagAddr := ctx.Arg(0)
		callbackAddr := ctx.Arg(1)
		onceMu.Lock()
		already := onceFlags[flagAddr]
		if !already {
			onceFlags[flagAddr] = true
		}
		onceMu.Unlock()
		if !already && callbackAddr != 0 {
			trampoline := ntapi.AllocTrampoline(mem)
			_, _ = ntapi.CallGuestFunction(ctx.CPU, mem, trampoline, callbackAddr,
				[]uint64{0, ctx.Arg(2), 0}, ctx.Trace)
		}
		ctx.SetReturn(1)
		return 0
	})

	getCond := func(addr uint64) *ntapi.CondVarEntry {
		return ntapi.GlobalCondVars.Get(addr)
	}

	d.RegisterAutoStubHandler(msvcp, "_Cnd_init", func(ctx *ntapi.TrapContext) uint32 {
		_ = getCond(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Cnd_wait", func(ctx *ntapi.TrapContext) uint32 {
		getCond(ctx.Arg(0)).Sleep(10 * gotime.Millisecond)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Cnd_signal", func(ctx *ntapi.TrapContext) uint32 {
		getCond(ctx.Arg(0)).Signal()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Cnd_broadcast", func(ctx *ntapi.TrapContext) uint32 {
		getCond(ctx.Arg(0)).Broadcast()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Cnd_destroy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Mtx_init", func(ctx *ntapi.TrapContext) uint32 {
		_ = getMutex(ctx.Arg(0))
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Mtx_lock", func(ctx *ntapi.TrapContext) uint32 {
		getMutex(ctx.Arg(0)).Lock()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Mtx_unlock", func(ctx *ntapi.TrapContext) uint32 {
		getMutex(ctx.Arg(0)).Unlock()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Mtx_trylock", func(ctx *ntapi.TrapContext) uint32 {
		if getMutex(ctx.Arg(0)).TryLock() {
			ctx.SetReturn(0) // _Thrd_success
		} else {
			ctx.SetReturn(2) // _Thrd_busy
		}
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Mtx_destroy", func(ctx *ntapi.TrapContext) uint32 {
		mutexMapMu.Lock()
		delete(mutexMap, ctx.Arg(0))
		mutexMapMu.Unlock()
		ctx.SetReturn(0)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// Error-throwing helpers and time utilities
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(msvcp, "?_Throw_C_error@std@@YAXH@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Throw_C_error", fmt.Sprintf("code=%d", int32(ctx.Arg(0))))
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xlength_error@std@@YAXPEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xlength_error", hctx.ReadGuestString(ctx.Arg(0)))
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xout_of_range@std@@YAXPEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xout_of_range", hctx.ReadGuestString(ctx.Arg(0)))
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xbad_alloc@std@@YAXXZ", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xbad_alloc", "")
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xinvalid_argument@std@@YAXPEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xinvalid_argument", hctx.ReadGuestString(ctx.Arg(0)))
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xoverflow_error@std@@YAXPEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xoverflow_error", hctx.ReadGuestString(ctx.Arg(0)))
	})

	d.RegisterAutoStubHandler(msvcp, "?_Xruntime_error@std@@YAXPEBD@Z", func(ctx *ntapi.TrapContext) uint32 {
		return abortRuntime("std::_Xruntime_error", hctx.ReadGuestString(ctx.Arg(0)))
	})

	d.RegisterAutoStubHandler(msvcp, "_Xtime_get_ticks", func(ctx *ntapi.TrapContext) uint32 {
		elapsed := gotime.Since(hctx.StartTime).Nanoseconds()
		ticks := elapsed / 100
		ctx.SetReturn(uint64(ticks))
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Thrd_yield", func(ctx *ntapi.TrapContext) uint32 {
		runtime.Gosched()
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Thrd_sleep", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(msvcp, "_Thrd_id", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	_ = readMsvcString
	_ = readMsvcWString

	ravelog.Logf("[msvcp] registered msvcp140 handlers\n")
}
