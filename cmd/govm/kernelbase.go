//go:build guest_windows

package main

import (
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

// registerKernelbaseHandlers registers handlers for kernelbase.dll functions.
// kernelbase.dll is usually serviced by the kernel32 synth, so we alias the
// module name to the kernel32 synth and, if a dedicated kernelbase synth exists,
// wire all kernel32 handlers into it as forwards. This function also adds the
// extra advapi32/ntdll-style exports that kernelbase exposes directly.
func registerKernelbaseHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestString := hctx.ReadGuestString
	regHive := hctx.RegHive
	regKeyPath := hctx.RegKeyPath
	regQueryValue := hctx.RegQueryValue
	regIsProbeKey := hctx.RegIsProbeKey

	kernel32, ok := hctx.SynthByName["kernel32.dll"]
	if !ok {
		return
	}
	kb := kernel32
	if dedicatedKB, ok := hctx.SynthByName["kernelbase.dll"]; ok && dedicatedKB != kernel32 {
		registerKernel32HandlersForSynth(hctx, dedicatedKB)
		kb = dedicatedKB
	} else {
		hctx.SynthByName["kernelbase.dll"] = kernel32
	}
	_ = readGuestString
	_ = regHive

	// ── Registry functions (same logic as advapi32) ──

	d.RegisterAutoStubHandler(kb, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			if regIsProbeKey(path) {
				ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
				return 0
			}
			key = ctx.Reg.CreateKey(path)
		}
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(4); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegOpenKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			if regIsProbeKey(path) {
				ctx.SetReturn(2)
				return 0
			}
			key = ctx.Reg.CreateKey(path)
		}
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(4); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
		handles.Close(ntapi.Handle(ctx.Arg(0)))
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestUTF16(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestString(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil {
			name := readGuestUTF16(ctx.Arg(1))
			valType := uint32(ctx.Arg(3))
			dataLen := int(ctx.Arg(5))
			data, _ := ctx.Mem.ReadBytes(ctx.Arg(4), dataLen)
			if rk.Key.Values == nil {
				rk.Key.Values = make(map[string]*ntapi.RegistryValue)
			}
			rk.Key.Values[name] = &ntapi.RegistryValue{Name: name, Type: valType, Data: data}
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			key = ctx.Reg.CreateKey(path)
		}
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(7); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		if pDisp := ctx.Arg(8); pDisp != 0 {
			ctx.Mem.Write32(pDisp, 1) // REG_CREATED_NEW_KEY
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk == nil || rk.Key == nil {
			ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
			return 0
		}
		index := int(ctx.Arg(1))
		subkeys := ctx.Reg.EnumerateKeys(rk.Key)
		if index >= len(subkeys) {
			ctx.SetReturn(259)
			return 0
		}
		name := subkeys[index]
		buf := ctx.Arg(2)
		if buf != 0 {
			for i, ch := range name {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(name)*2), 0)
		}
		if cch := ctx.Arg(3); cch != 0 {
			ctx.Mem.Write32(cch, uint32(len(name)))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk == nil || rk.Key == nil || rk.Key.Values == nil {
			ctx.SetReturn(259)
			return 0
		}
		index := int(ctx.Arg(1))
		names := make([]string, 0, len(rk.Key.Values))
		for k := range rk.Key.Values {
			names = append(names, k)
		}
		if index >= len(names) {
			ctx.SetReturn(259)
			return 0
		}
		valName := names[index]
		val := rk.Key.Values[valName]
		buf := ctx.Arg(2)
		if buf != 0 {
			for i, ch := range valName {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(valName)*2), 0)
		}
		if cch := ctx.Arg(3); cch != 0 {
			ctx.Mem.Write32(cch, uint32(len(valName)))
		}
		if lpType := ctx.Arg(4); lpType != 0 {
			ctx.Mem.Write32(lpType, val.Type)
		}
		lpData := ctx.Arg(5)
		lpcbData := ctx.Arg(6)
		if lpcbData != 0 {
			ctx.Mem.Write32(lpcbData, uint32(len(val.Data)))
		}
		if lpData != 0 && len(val.Data) > 0 {
			ctx.Mem.WriteBytes(lpData, val.Data)
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil && rk.Key.Values != nil {
			name := readGuestUTF16(ctx.Arg(1))
			delete(rk.Key.Values, name)
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "RegDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})

	// ── User/security functions (advapi32 forwards) ──

	d.RegisterAutoStubHandler(kb, "GetUserNameW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		size := ctx.Arg(1)
		name := "User"
		if size != 0 {
			ctx.Mem.Write32(size, uint32(len(name)+1))
		}
		if buf != 0 {
			for i, ch := range name {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(name)*2), 0)
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "GetUserNameA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		size := ctx.Arg(1)
		name := "User"
		if size != 0 {
			ctx.Mem.Write32(size, uint32(len(name)+1))
		}
		if buf != 0 {
			for i := 0; i < len(name); i++ {
				ctx.Mem.Write8(buf+uint64(i), name[i])
			}
			ctx.Mem.Write8(buf+uint64(len(name)), 0)
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "AccessCheck", func(ctx *ntapi.TrapContext) uint32 {
		// pSecurityDescriptor, ClientToken, DesiredAccess, GenericMapping,
		// PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus
		grantedAccessPtr := ctx.Arg(6)
		accessStatusPtr := ctx.Arg(7)
		if grantedAccessPtr != 0 {
			ctx.Mem.Write32(grantedAccessPtr, uint32(ctx.Arg(2))) // grant all requested
		}
		if accessStatusPtr != 0 {
			ctx.Mem.Write32(accessStatusPtr, 1) // TRUE = access granted
		}
		ctx.SetReturn(1) // success
		return 0
	})

	d.RegisterAutoStubHandler(kb, "OpenProcessToken", func(ctx *ntapi.TrapContext) uint32 {
		tokenPtr := ctx.Arg(2)
		if tokenPtr != 0 {
			fakeToken := handles.Alloc(&ntapi.GenericHandle{Kind: "Token"})
			ctx.Mem.Write64(tokenPtr, uint64(fakeToken))
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "GetTokenInformation", func(ctx *ntapi.TrapContext) uint32 {
		tokenInfoClass := ctx.Arg(1)
		tokenInfo := ctx.Arg(2)
		tokenInfoLen := ctx.Arg(3)
		returnLength := ctx.Arg(4)
		ravelog.Logf("[kernelbase] GetTokenInformation class=%d buf=0x%x len=%d\n", tokenInfoClass, tokenInfo, tokenInfoLen)
		// TokenUser (1): return a minimal TOKEN_USER with a well-known SID
		if tokenInfoClass == 1 && tokenInfo != 0 && tokenInfoLen >= 20 {
			// SID pointer at offset 0, then attributes at offset 8
			sidAddr := tokenInfo + 16
			ctx.Mem.Write64(tokenInfo, sidAddr) // SID*
			ctx.Mem.Write32(tokenInfo+8, 0)     // Attributes
			// Write a minimal SID: S-1-5-21-0-0-0-1000 (local user)
			ctx.Mem.Write8(sidAddr+0, 1) // Revision
			ctx.Mem.Write8(sidAddr+1, 5) // SubAuthorityCount
			ctx.Mem.Write8(sidAddr+2, 0) // IdentifierAuthority[0..5]
			ctx.Mem.Write8(sidAddr+3, 0)
			ctx.Mem.Write8(sidAddr+4, 0)
			ctx.Mem.Write8(sidAddr+5, 0)
			ctx.Mem.Write8(sidAddr+6, 0)
			ctx.Mem.Write8(sidAddr+7, 5)   // NT Authority
			ctx.Mem.Write32(sidAddr+8, 21) // SECURITY_NT_NON_UNIQUE
			ctx.Mem.Write32(sidAddr+12, 0)
			ctx.Mem.Write32(sidAddr+16, 0)
			ctx.Mem.Write32(sidAddr+20, 0)
			ctx.Mem.Write32(sidAddr+24, 1000) // RID
			if returnLength != 0 {
				ctx.Mem.Write32(returnLength, 44)
			}
			ctx.SetReturn(1)
			return 0
		}
		if returnLength != 0 {
			ctx.Mem.Write32(returnLength, 0)
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(kb, "LookupPrivilegeValueW", func(ctx *ntapi.TrapContext) uint32 {
		luidPtr := ctx.Arg(2)
		if luidPtr != 0 {
			ctx.Mem.Write32(luidPtr, 20)  // LUID.LowPart (SE_DEBUG_PRIVILEGE)
			ctx.Mem.Write32(luidPtr+4, 0) // LUID.HighPart
		}
		ctx.SetReturn(1)
		return 0
	})

	// ── NTDLL forwarded functions ──

	// RtlInitUnicodeString: initializes a UNICODE_STRING from a PCWSTR.
	// struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; }
	d.RegisterAutoStubHandler(kb, "RtlInitUnicodeString", func(ctx *ntapi.TrapContext) uint32 {
		destAddr := ctx.Arg(0)
		sourceStr := ctx.Arg(1)
		if destAddr == 0 {
			return 0
		}
		if sourceStr == 0 {
			ctx.Mem.Write16(destAddr+0, 0) // Length
			ctx.Mem.Write16(destAddr+2, 0) // MaximumLength
			ctx.Mem.Write64(destAddr+8, 0) // Buffer (offset 8 on x64 due to padding)
			return 0
		}
		// Count characters until null terminator
		charCount := 0
		for addr := sourceStr; ; addr += 2 {
			ch, _ := ctx.Mem.Read16(addr)
			if ch == 0 {
				break
			}
			charCount++
			if charCount > 32767 {
				break
			}
		}
		byteLen := uint16(charCount * 2)
		ctx.Mem.Write16(destAddr+0, byteLen)   // Length (bytes, not including null)
		ctx.Mem.Write16(destAddr+2, byteLen+2) // MaximumLength
		ctx.Mem.Write64(destAddr+8, sourceStr) // Buffer
		return 0
	})

	// RtlFreeUnicodeString: frees a UNICODE_STRING buffer if it was allocated.
	// In our emulator, strings are typically guest-static, so just zero out the struct.
	d.RegisterAutoStubHandler(kb, "RtlFreeUnicodeString", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		if addr == 0 {
			return 0
		}
		bufPtr, _ := ctx.Mem.Read64(addr + 8)
		if bufPtr != 0 {
			hctx.HeapFree(bufPtr)
		}
		ctx.Mem.Write16(addr+0, 0)
		ctx.Mem.Write16(addr+2, 0)
		ctx.Mem.Write64(addr+8, 0)
		return 0
	})

	// RtlInitAnsiString: same layout but byte-length strings.
	d.RegisterAutoStubHandler(kb, "RtlInitAnsiString", func(ctx *ntapi.TrapContext) uint32 {
		destAddr := ctx.Arg(0)
		sourceStr := ctx.Arg(1)
		if destAddr == 0 {
			return 0
		}
		if sourceStr == 0 {
			ctx.Mem.Write16(destAddr+0, 0)
			ctx.Mem.Write16(destAddr+2, 0)
			ctx.Mem.Write64(destAddr+8, 0)
			return 0
		}
		charCount := 0
		for addr := sourceStr; ; addr++ {
			ch, _ := ctx.Mem.Read8(addr)
			if ch == 0 {
				break
			}
			charCount++
			if charCount > 65535 {
				break
			}
		}
		ctx.Mem.Write16(destAddr+0, uint16(charCount))
		ctx.Mem.Write16(destAddr+2, uint16(charCount+1))
		ctx.Mem.Write64(destAddr+8, sourceStr)
		return 0
	})

	// RtlFreeAnsiString: free an ANSI_STRING buffer.
	d.RegisterAutoStubHandler(kb, "RtlFreeAnsiString", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		if addr == 0 {
			return 0
		}
		bufPtr, _ := ctx.Mem.Read64(addr + 8)
		if bufPtr != 0 {
			hctx.HeapFree(bufPtr)
		}
		ctx.Mem.Write16(addr+0, 0)
		ctx.Mem.Write16(addr+2, 0)
		ctx.Mem.Write64(addr+8, 0)
		return 0
	})

	// RtlUnicodeStringToAnsiString: convert UNICODE_STRING to ANSI_STRING.
	d.RegisterAutoStubHandler(kb, "RtlUnicodeStringToAnsiString", func(ctx *ntapi.TrapContext) uint32 {
		dstAddr := ctx.Arg(0)
		srcAddr := ctx.Arg(1)
		allocDest := ctx.Arg(2) != 0
		if dstAddr == 0 || srcAddr == 0 {
			ctx.SetReturn(0xC0000000) // STATUS_INVALID_PARAMETER
			return 0
		}
		srcLen, _ := ctx.Mem.Read16(srcAddr + 0)
		srcBuf, _ := ctx.Mem.Read64(srcAddr + 8)
		charCount := int(srcLen / 2)
		// Read UTF-16 characters, convert to ASCII (truncate to low byte)
		ansi := make([]byte, charCount+1)
		for i := 0; i < charCount; i++ {
			ch, _ := ctx.Mem.Read16(srcBuf + uint64(i*2))
			if ch > 255 {
				ansi[i] = '?'
			} else {
				ansi[i] = byte(ch)
			}
		}
		ansi[charCount] = 0
		if allocDest {
			buf := mem.Mmap(0, uint64(charCount+2), 0x3)
			mem.WriteBytes(buf, ansi)
			ctx.Mem.Write16(dstAddr+0, uint16(charCount))
			ctx.Mem.Write16(dstAddr+2, uint16(charCount+1))
			ctx.Mem.Write64(dstAddr+8, buf)
		} else {
			existBuf, _ := ctx.Mem.Read64(dstAddr + 8)
			if existBuf != 0 {
				ctx.Mem.WriteBytes(existBuf, ansi)
			}
			ctx.Mem.Write16(dstAddr+0, uint16(charCount))
		}
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})

	// RtlNtStatusToDosError: map NTSTATUS to Win32 error code.
	d.RegisterAutoStubHandler(kb, "RtlNtStatusToDosError", func(ctx *ntapi.TrapContext) uint32 {
		status := uint32(ctx.Arg(0))
		var dosErr uint32
		switch status {
		case 0x00000000: // STATUS_SUCCESS
			dosErr = 0
		case 0xC0000022: // STATUS_ACCESS_DENIED
			dosErr = 5
		case 0xC0000034: // STATUS_OBJECT_NAME_NOT_FOUND
			dosErr = 2
		case 0xC000000D: // STATUS_INVALID_PARAMETER
			dosErr = 87
		case 0xC0000008: // STATUS_INVALID_HANDLE
			dosErr = 6
		case 0xC0000005: // STATUS_ACCESS_VIOLATION
			dosErr = 998
		case 0xC00000BB: // STATUS_NOT_SUPPORTED
			dosErr = 50
		default:
			dosErr = uint32(status & 0xFFFF)
		}
		ctx.SetReturn(uint64(dosErr))
		return 0
	})

	// RtlCompareUnicodeString: compare two UNICODE_STRINGs.
	d.RegisterAutoStubHandler(kb, "RtlCompareUnicodeString", func(ctx *ntapi.TrapContext) uint32 {
		s1Addr := ctx.Arg(0)
		s2Addr := ctx.Arg(1)
		caseInsensitive := ctx.Arg(2) != 0
		s1Len, _ := ctx.Mem.Read16(s1Addr + 0)
		s1Buf, _ := ctx.Mem.Read64(s1Addr + 8)
		s2Len, _ := ctx.Mem.Read16(s2Addr + 0)
		s2Buf, _ := ctx.Mem.Read64(s2Addr + 8)
		c1 := int(s1Len / 2)
		c2 := int(s2Len / 2)
		n := c1
		if c2 < n {
			n = c2
		}
		for i := 0; i < n; i++ {
			ch1, _ := ctx.Mem.Read16(s1Buf + uint64(i*2))
			ch2, _ := ctx.Mem.Read16(s2Buf + uint64(i*2))
			if caseInsensitive {
				if ch1 >= 'A' && ch1 <= 'Z' {
					ch1 += 32
				}
				if ch2 >= 'A' && ch2 <= 'Z' {
					ch2 += 32
				}
			}
			if ch1 != ch2 {
				if ch1 < ch2 {
					ctx.SetReturn(^uint64(0)) // -1
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
		}
		if c1 < c2 {
			ctx.SetReturn(^uint64(0))
		} else if c1 > c2 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// RtlEqualUnicodeString: returns BOOLEAN.
	d.RegisterAutoStubHandler(kb, "RtlEqualUnicodeString", func(ctx *ntapi.TrapContext) uint32 {
		s1Addr := ctx.Arg(0)
		s2Addr := ctx.Arg(1)
		caseInsensitive := ctx.Arg(2) != 0
		s1Len, _ := ctx.Mem.Read16(s1Addr + 0)
		s1Buf, _ := ctx.Mem.Read64(s1Addr + 8)
		s2Len, _ := ctx.Mem.Read16(s2Addr + 0)
		s2Buf, _ := ctx.Mem.Read64(s2Addr + 8)
		if s1Len != s2Len {
			ctx.SetReturn(0)
			return 0
		}
		for i := 0; i < int(s1Len/2); i++ {
			ch1, _ := ctx.Mem.Read16(s1Buf + uint64(i*2))
			ch2, _ := ctx.Mem.Read16(s2Buf + uint64(i*2))
			if caseInsensitive {
				if ch1 >= 'A' && ch1 <= 'Z' {
					ch1 += 32
				}
				if ch2 >= 'A' && ch2 <= 'Z' {
					ch2 += 32
				}
			}
			if ch1 != ch2 {
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// PathCchCombineEx: safe path combine (kernelbase export).
	d.RegisterAutoStubHandler(kb, "PathCchCombineEx", func(ctx *ntapi.TrapContext) uint32 {
		outBuf := ctx.Arg(0)
		outCch := ctx.Arg(1)
		path1 := readGuestUTF16(ctx.Arg(2))
		path2 := readGuestUTF16(ctx.Arg(3))
		var combined string
		if path2 != "" && (len(path2) >= 2 && path2[1] == ':' || strings.HasPrefix(path2, `\\`)) {
			combined = path2 // path2 is absolute
		} else if path1 != "" && path2 != "" {
			combined = strings.TrimRight(path1, `\/`) + `\` + path2
		} else if path1 != "" {
			combined = path1
		} else {
			combined = path2
		}
		if outBuf != 0 && outCch > 0 {
			n := len(combined)
			if uint64(n) >= outCch {
				n = int(outCch) - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(outBuf+uint64(i*2), uint16(combined[i]))
			}
			ctx.Mem.Write16(outBuf+uint64(n*2), 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})

	ravelog.Logf("[kernelbase] registered extra kernelbase handlers\n")
}
