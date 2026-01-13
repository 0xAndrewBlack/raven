package main

import (
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"golang.org/x/sys/unix"
)

func registerOle32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16

	ole32, ok := hctx.SynthByName["ole32.dll"]
	if !ok {
		return
	}
	_ = ole32

	comInitCount := 0

	d.RegisterAutoStubHandler(ole32, "CoInitialize", func(ctx *ntapi.TrapContext) uint32 {
		comInitCount++
		if comInitCount > 1 {
			ctx.SetReturn(1) // S_FALSE - already initialized
		} else {
			ctx.SetReturn(0) // S_OK
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
		comInitCount++
		if comInitCount > 1 {
			ctx.SetReturn(1) // S_FALSE
		} else {
			ctx.SetReturn(0) // S_OK
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoInitializeSecurity", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
		// rclsid *CLSID, pUnkOuter, dwClsContext, riid *IID, ppv **void
		ppv := ctx.Arg(4)
		if ppv == 0 {
			ctx.SetReturn(0x80004003) // E_POINTER
			return 0
		}
		// Build a minimal IUnknown vtable in guest memory.
		// vtable[0] = QueryInterface stub, [1] = AddRef stub, [2] = Release stub
		// Each stub is a trap that returns S_OK / 1.
		// We reuse a single shared IUnknown object for all CoCreateInstance calls.
		// The guest object layout: [8-byte vtable ptr] → vtable[3 pointers]
		const comObjSize = 8  // just the vtable pointer
		const vtableSize = 24 // 3 × 8-byte pointers
		// Allocate per-call so each object is independent.
		objAddr := mem.Mmap(0, comObjSize+vtableSize+3*64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		vtableAddr := objAddr + comObjSize
		// Write 3 stub functions right after vtable entries.
		stubBase := vtableAddr + vtableSize
		// Stub: mov eax, 0; ret (returns 0 / S_OK or 1 for AddRef/Release)
		for i := uint64(0); i < 3; i++ {
			sAddr := stubBase + i*64
			// xor eax, eax; ret
			ctx.Mem.Write8(sAddr+0, 0x31)
			ctx.Mem.Write8(sAddr+1, 0xC0)
			ctx.Mem.Write8(sAddr+2, 0xC3)
			ctx.Mem.Write64(vtableAddr+i*8, sAddr)
		}
		// AddRef/Release return 1 not 0 - patch the ret value
		// mov eax, 1; ret
		for _, i := range []uint64{1, 2} {
			sAddr := stubBase + i*64
			ctx.Mem.Write8(sAddr+0, 0xB8)
			ctx.Mem.Write32(sAddr+1, 1)
			ctx.Mem.Write8(sAddr+5, 0xC3)
		}
		// Object: vtable pointer at offset 0
		ctx.Mem.Write64(objAddr, vtableAddr)
		// *ppv = objAddr
		ctx.Mem.Write64(ppv, objAddr)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateInstanceEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StringFromGUID2", func(ctx *ntapi.TrapContext) uint32 {
		// rguid *GUID, lpsz *OLECHAR, cchMax int → returns chars written
		guidPtr := ctx.Arg(0)
		outPtr := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		if guidPtr == 0 || outPtr == 0 || cchMax < 39 {
			ctx.SetReturn(0)
			return 0
		}
		// Read 16 bytes of GUID
		b := make([]byte, 16)
		for i := range b {
			v, _ := ctx.Mem.Read8(guidPtr + uint64(i))
			b[i] = v
		}
		d1 := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
		d2 := uint16(b[4]) | uint16(b[5])<<8
		d3 := uint16(b[6]) | uint16(b[7])<<8
		s := fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
		// Write as UTF-16LE
		runes := []rune(s)
		for i, r := range runes {
			ctx.Mem.Write16(outPtr+uint64(i)*2, uint16(r))
		}
		ctx.Mem.Write16(outPtr+uint64(len(runes))*2, 0) // NUL
		ctx.SetReturn(uint64(len(runes) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLSIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		// Parse "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" → GUID struct
		strPtr := ctx.Arg(0)
		clsidPtr := ctx.Arg(1)
		if strPtr == 0 || clsidPtr == 0 {
			ctx.SetReturn(0x80004003) // E_POINTER
			return 0
		}
		s := readGuestUTF16(strPtr)
		var d1 uint32
		var d2, d3 uint16
		var rest [8]byte
		n, _ := fmt.Sscanf(s, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			&d1, &d2, &d3,
			&rest[0], &rest[1], &rest[2], &rest[3], &rest[4], &rest[5], &rest[6], &rest[7])
		if n < 11 {
			ctx.SetReturn(0x80070057) // E_INVALIDARG
			return 0
		}
		ctx.Mem.Write8(clsidPtr+0, byte(d1))
		ctx.Mem.Write8(clsidPtr+1, byte(d1>>8))
		ctx.Mem.Write8(clsidPtr+2, byte(d1>>16))
		ctx.Mem.Write8(clsidPtr+3, byte(d1>>24))
		ctx.Mem.Write8(clsidPtr+4, byte(d2))
		ctx.Mem.Write8(clsidPtr+5, byte(d2>>8))
		ctx.Mem.Write8(clsidPtr+6, byte(d3))
		ctx.Mem.Write8(clsidPtr+7, byte(d3>>8))
		for i := 0; i < 8; i++ {
			ctx.Mem.Write8(clsidPtr+8+uint64(i), rest[i])
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLSIDFromProgID", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x800401F3) // CO_E_CLASSSTRING
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StringFromCLSID", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT StringFromCLSID(REFCLSID rclsid, LPOLESTR *lplpsz)
		guidPtr := ctx.Arg(0)
		ppszOut := ctx.Arg(1)
		if guidPtr == 0 || ppszOut == 0 {
			ctx.SetReturn(0x80004003) // E_POINTER
			return 0
		}
		s := readGUIDString(ctx.Mem, guidPtr)
		ws := utf16Encode(s)
		bufSize := uint64(len(ws)+1) * 2
		addr := mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		ctx.Mem.Write64(ppszOut, addr)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT IIDFromString(LPCOLESTR lpsz, LPIID lpiid)
		strPtr := ctx.Arg(0)
		iidPtr := ctx.Arg(1)
		if strPtr == 0 || iidPtr == 0 {
			ctx.SetReturn(0x80004003) // E_POINTER
			return 0
		}
		s := readGuestUTF16(strPtr)
		var d1 uint32
		var d2, d3 uint16
		var rest [8]byte
		n, _ := fmt.Sscanf(s, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			&d1, &d2, &d3,
			&rest[0], &rest[1], &rest[2], &rest[3], &rest[4], &rest[5], &rest[6], &rest[7])
		if n < 11 {
			ctx.SetReturn(0x80070057) // E_INVALIDARG
			return 0
		}
		ctx.Mem.Write8(iidPtr+0, byte(d1))
		ctx.Mem.Write8(iidPtr+1, byte(d1>>8))
		ctx.Mem.Write8(iidPtr+2, byte(d1>>16))
		ctx.Mem.Write8(iidPtr+3, byte(d1>>24))
		ctx.Mem.Write8(iidPtr+4, byte(d2))
		ctx.Mem.Write8(iidPtr+5, byte(d2>>8))
		ctx.Mem.Write8(iidPtr+6, byte(d3))
		ctx.Mem.Write8(iidPtr+7, byte(d3>>8))
		for i := 0; i < 8; i++ {
			ctx.Mem.Write8(iidPtr+8+uint64(i), rest[i])
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IsEqualGUID", func(ctx *ntapi.TrapContext) uint32 {
		// rguid1 *GUID, rguid2 *GUID → BOOL
		g1 := ctx.Arg(0)
		g2 := ctx.Arg(1)
		for i := uint64(0); i < 16; i++ {
			b1, _ := ctx.Mem.Read8(g1 + i)
			b2, _ := ctx.Mem.Read8(g2 + i)
			if b1 != b2 {
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateStreamOnHGlobal", func(ctx *ntapi.TrapContext) uint32 {
		// hGlobal, fDeleteOnRelease, ppstm
		ppstm := ctx.Arg(2)
		if ppstm == 0 {
			ctx.SetReturn(0x80004003)
			return 0
		}
		// Minimal IStream stub (same IUnknown pattern)
		objAddr := mem.Mmap(0, 8+64+10*64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		vtAddr := objAddr + 8
		stubBase := vtAddr + 80 // 10 vtable entries × 8
		// Write xor eax,eax; ret for all 10 IStream methods
		for i := uint64(0); i < 10; i++ {
			s := stubBase + i*64
			ctx.Mem.Write8(s+0, 0x31)
			ctx.Mem.Write8(s+1, 0xC0)
			ctx.Mem.Write8(s+2, 0xC3)
			ctx.Mem.Write64(vtAddr+i*8, s)
		}
		// AddRef/Release (idx 1,2) → return 1
		for _, i := range []uint64{1, 2} {
			s := stubBase + i*64
			ctx.Mem.Write8(s+0, 0xB8)
			ctx.Mem.Write32(s+1, 1)
			ctx.Mem.Write8(s+5, 0xC3)
		}
		ctx.Mem.Write64(objAddr, vtAddr)
		ctx.Mem.Write64(ppstm, objAddr)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoUninitialize", func(ctx *ntapi.TrapContext) uint32 {
		if comInitCount > 0 {
			comInitCount--
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemAlloc", func(ctx *ntapi.TrapContext) uint32 {
		size := ctx.Arg(0)
		if size == 0 {
			size = 1
		}
		addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemFree", func(ctx *ntapi.TrapContext) uint32 {
		return 0 // No-op (guest GC handles cleanup)
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemRealloc", func(ctx *ntapi.TrapContext) uint32 {
		oldPtr := ctx.Arg(0)
		size := ctx.Arg(1)
		if size == 0 {
			ctx.SetReturn(0) // realloc(ptr, 0) = free
			return 0
		}
		addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
		if oldPtr != 0 {
			// Copy old data (we don't track alloc sizes, so copy up to new size)
			old, err := ctx.Mem.ReadBytes(oldPtr, int(size))
			if err == nil {
				ctx.Mem.WriteBytes(addr, old)
			}
		}
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleInitialize", func(ctx *ntapi.TrapContext) uint32 {
		comInitCount++
		if comInitCount > 1 {
			ctx.SetReturn(1) // S_FALSE
		} else {
			ctx.SetReturn(0) // S_OK
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleUninitialize", func(ctx *ntapi.TrapContext) uint32 {
		if comInitCount > 0 {
			comInitCount--
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "RegisterDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK (drag-drop not actually supported)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "RevokeDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DoDragDrop", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004004) // DRAGDROP_S_DROP cancel
		return 0
	})
	// UUID/GUID generation
	genGUID := func(ptr uint64) {
		if ptr == 0 {
			return
		}
		var b [16]byte
		unix.Getrandom(b[:], 0)
		// Set version 4 and variant bits (RFC 4122)
		b[6] = (b[6] & 0x0F) | 0x40
		b[8] = (b[8] & 0x3F) | 0x80
		ctx := ptr
		mem.Write32(ctx, uint32(b[0])|uint32(b[1])<<8|uint32(b[2])<<16|uint32(b[3])<<24)
		mem.Write16(ctx+4, uint16(b[4])|uint16(b[5])<<8)
		mem.Write16(ctx+6, uint16(b[6])|uint16(b[7])<<8)
		for i := 0; i < 8; i++ {
			mem.Write8(ctx+8+uint64(i), b[8+i])
		}
	}
	d.RegisterAutoStubHandler(ole32, "CoCreateGuid", func(ctx *ntapi.TrapContext) uint32 {
		genGUID(ctx.Arg(0))
		ctx.SetReturn(0) // S_OK
		return 0
	})
}

func registerOleaut32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem

	oleaut32, ok := hctx.SynthByName["oleaut32.dll"]
	if !ok {
		return
	}
	_ = oleaut32

	d.RegisterAutoStubHandler(oleaut32, "SysAllocString", func(ctx *ntapi.TrapContext) uint32 {
		// Allocate a copy of the BSTR in guest memory
		src := ctx.Arg(0)
		if src == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Count wchar_t length
		n := uint64(0)
		for {
			w, _ := ctx.Mem.Read16(src + n*2)
			if w == 0 {
				break
			}
			n++
		}
		// BSTR layout: 4-byte length prefix + wchar data + null terminator
		buf := mem.Mmap(0, 4+n*2+2, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(buf, uint32(n*2))
		for i := uint64(0); i < n; i++ {
			w, _ := ctx.Mem.Read16(src + i*2)
			ctx.Mem.Write16(buf+4+i*2, w)
		}
		ctx.SetReturn(buf + 4) // BSTR points past length prefix
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysFreeString", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysStringLen", func(ctx *ntapi.TrapContext) uint32 {
		// UINT SysStringLen(BSTR bstr) - returns character count
		bstr := ctx.Arg(0)
		if bstr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// BSTR length prefix is 4 bytes before the string pointer, in bytes
		byteLen, _ := ctx.Mem.Read32(bstr - 4)
		ctx.SetReturn(uint64(byteLen / 2))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysAllocStringLen", func(ctx *ntapi.TrapContext) uint32 {
		// BSTR SysAllocStringLen(const OLECHAR *strIn, UINT ui)
		src := ctx.Arg(0)
		cch := ctx.Arg(1) // character count
		byteLen := cch * 2
		// BSTR layout: 4-byte length prefix + wchar data + null terminator
		buf := mem.Mmap(0, 4+byteLen+2, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(buf, uint32(byteLen))
		if src != 0 && cch > 0 {
			for i := uint64(0); i < cch; i++ {
				w, _ := ctx.Mem.Read16(src + i*2)
				ctx.Mem.Write16(buf+4+i*2, w)
			}
		}
		ctx.Mem.Write16(buf+4+byteLen, 0) // null terminator
		ctx.SetReturn(buf + 4)             // BSTR points past length prefix
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysReAllocStringLen", func(ctx *ntapi.TrapContext) uint32 {
		// INT SysReAllocStringLen(BSTR *pbstr, const OLECHAR *psz, UINT len)
		pbstr := ctx.Arg(0)
		psz := ctx.Arg(1)
		cch := ctx.Arg(2)
		byteLen := cch * 2
		buf := mem.Mmap(0, 4+byteLen+2, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(buf, uint32(byteLen))
		if psz != 0 && cch > 0 {
			for i := uint64(0); i < cch; i++ {
				w, _ := ctx.Mem.Read16(psz + i*2)
				ctx.Mem.Write16(buf+4+i*2, w)
			}
		}
		ctx.Mem.Write16(buf+4+byteLen, 0)
		if pbstr != 0 {
			ctx.Mem.Write64(pbstr, buf+4)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	// VariantInit: zero the 16-byte VARIANT struct
	d.RegisterAutoStubHandler(oleaut32, "VariantInit", func(ctx *ntapi.TrapContext) uint32 {
		pVar := ctx.Arg(0)
		if pVar != 0 {
			zeros := make([]byte, 16)
			ctx.Mem.WriteBytes(pVar, zeros) // VT_EMPTY = 0
		}
		return 0
	})
	// VariantClear: reset VARIANT to VT_EMPTY
	d.RegisterAutoStubHandler(oleaut32, "VariantClear", func(ctx *ntapi.TrapContext) uint32 {
		pVar := ctx.Arg(0)
		if pVar != 0 {
			zeros := make([]byte, 16)
			ctx.Mem.WriteBytes(pVar, zeros)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	// VariantCopy
	d.RegisterAutoStubHandler(oleaut32, "VariantCopy", func(ctx *ntapi.TrapContext) uint32 {
		pDest := ctx.Arg(0)
		pSrc := ctx.Arg(1)
		if pDest != 0 && pSrc != 0 {
			data, err := ctx.Mem.ReadBytes(pSrc, 16)
			if err == nil {
				ctx.Mem.WriteBytes(pDest, data)
			}
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	// VariantChangeType
	d.RegisterAutoStubHandler(oleaut32, "VariantChangeType", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0x80004002) // E_NOINTERFACE - can't convert
		return 0
	})
}
