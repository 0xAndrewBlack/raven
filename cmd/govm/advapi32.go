package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"
	"sync"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"golang.org/x/sys/unix"
)

func registerAdvapi32Handlers1(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	regHive := hctx.RegHive
	regKeyPath := hctx.RegKeyPath
	regQueryValue := hctx.RegQueryValue

	advapi32, ok := hctx.SynthByName["advapi32.dll"]
	if !ok {
		return
	}
	_ = advapi32

	d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(advapi32, "RegOpenKeyW", func(ctx *ntapi.TrapContext) uint32 {
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
		if phk := ctx.Arg(2); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
		handles.Close(ntapi.Handle(ctx.Arg(0)))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestUTF16(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(advapi32, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		existed := ctx.Reg.OpenKey(path) != nil
		key := ctx.Reg.CreateKey(path)
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(6); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		if disp := ctx.Arg(7); disp != 0 {
			if existed {
				ctx.Mem.Write32(disp, 2)
			} else {
				ctx.Mem.Write32(disp, 1)
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk == nil || rk.Key == nil {
			ctx.SetReturn(259)
			return 0
		}
		names := ctx.Reg.EnumerateKeys(rk.Key)
		idx := uint32(ctx.Arg(1))
		if int(idx) >= len(names) {
			ctx.SetReturn(259)
			return 0
		}
		ws := utf16Encode(names[idx])
		if buf := ctx.Arg(2); buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		}
		if lp := ctx.Arg(3); lp != 0 {
			ctx.Mem.Write32(lp, uint32(len(ws)))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk == nil || rk.Key == nil {
			ctx.SetReturn(259)
			return 0
		}
		vnames := ctx.Reg.EnumerateValues(rk.Key)
		idx := uint32(ctx.Arg(1))
		if int(idx) >= len(vnames) {
			ctx.SetReturn(259)
			return 0
		}
		name := vnames[idx]
		val := rk.Key.Values[name]
		ws := utf16Encode(name)
		if buf := ctx.Arg(2); buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		}
		if lp := ctx.Arg(3); lp != 0 {
			ctx.Mem.Write32(lp, uint32(len(ws)))
		}
		if lpType := ctx.Arg(5); lpType != 0 {
			ctx.Mem.Write32(lpType, val.Type)
		}
		needed := uint32(len(val.Data))
		if lpcb := ctx.Arg(7); lpcb != 0 {
			avail, _ := ctx.Mem.Read32(lpcb)
			ctx.Mem.Write32(lpcb, needed)
			if ctx.Arg(6) != 0 && avail < needed {
				ctx.SetReturn(234)
				return 0
			}
		}
		if lpData := ctx.Arg(6); lpData != 0 {
			ctx.Mem.WriteBytes(lpData, val.Data)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		var nSubKeys, nValues, maxSubKeyLen, maxValueNameLen, maxValueLen uint32
		if rk != nil && rk.Key != nil {
			nSubKeys = uint32(len(rk.Key.Children))
			nValues = uint32(len(rk.Key.Values))
			for name := range rk.Key.Children {
				if uint32(len(name)) > maxSubKeyLen {
					maxSubKeyLen = uint32(len(name))
				}
			}
			for name, val := range rk.Key.Values {
				if uint32(len(name)) > maxValueNameLen {
					maxValueNameLen = uint32(len(name))
				}
				if uint32(len(val.Data)) > maxValueLen {
					maxValueLen = uint32(len(val.Data))
				}
			}
		}
		if p := ctx.Arg(2); p != 0 {
			ctx.Mem.Write32(p, 0)
		}
		if p := ctx.Arg(4); p != 0 {
			ctx.Mem.Write32(p, nSubKeys)
		}
		if p := ctx.Arg(5); p != 0 {
			ctx.Mem.Write32(p, maxSubKeyLen)
		}
		if p := ctx.Arg(6); p != 0 {
			ctx.Mem.Write32(p, 0)
		}
		if p := ctx.Arg(7); p != 0 {
			ctx.Mem.Write32(p, nValues)
		}
		if p := ctx.Arg(8); p != 0 {
			ctx.Mem.Write32(p, maxValueNameLen)
		}
		if p := ctx.Arg(9); p != 0 {
			ctx.Mem.Write32(p, maxValueLen)
		}
		if p := ctx.Arg(10); p != 0 {
			ctx.Mem.Write32(p, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil {
			name := readGuestUTF16(ctx.Arg(1))
			for k := range rk.Key.Values {
				if strings.EqualFold(k, name) {
					delete(rk.Key.Values, k)
					break
				}
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetUserNameW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		size := ctx.Arg(1)
		name := "user"
		if size != 0 {
			ctx.Mem.Write32(size, uint32(len(name)+1))
		}
		for i, ch := range name {
			ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(name)*2), 0)
		ctx.SetReturn(1)
		return 0
	})

	// GetUserNameA: write ANSI username "User"
	d.RegisterAutoStubHandler(advapi32, "GetUserNameA", func(ctx *ntapi.TrapContext) uint32 {
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

	// RegOpenKeyExA: convert ANSI subkey name then use same logic as RegOpenKeyExW
	d.RegisterAutoStubHandler(advapi32, "RegOpenKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
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
	d.RegisterAutoStubHandler(advapi32, "RegQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestString(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		// RegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
		hKey := ctx.Arg(0)
		subKey := readGuestUTF16(ctx.Arg(1))
		valueName := readGuestUTF16(ctx.Arg(2))
		if subKey != "" {
			path := regKeyPath(hKey, subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				ctx.SetReturn(2)
				return 0
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			ctx.SetReturn(uint64(regQueryValue(ctx, uint64(h), valueName)))
		} else {
			ctx.SetReturn(uint64(regQueryValue(ctx, hKey, valueName)))
		}
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteValueA", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil {
			name := readGuestString(ctx.Arg(1))
			delete(rk.Key.Values, name)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegCreateKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		existed := ctx.Reg.OpenKey(path) != nil
		key := ctx.Reg.CreateKey(path)
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(6); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		if disp := ctx.Arg(7); disp != 0 {
			if existed {
				ctx.Mem.Write32(disp, 2) // REG_OPENED_EXISTING_KEY
			} else {
				ctx.Mem.Write32(disp, 1) // REG_CREATED_NEW_KEY
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegCreateKeyA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.CreateKey(path)
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(2); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOpenKeyA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
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
		if phk := ctx.Arg(2); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSetValueExA", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil {
			name := readGuestString(ctx.Arg(1))
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
	d.RegisterAutoStubHandler(advapi32, "RegSetValueA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		hKey := ctx.Arg(0)
		valType := uint32(ctx.Arg(2))
		dataLen := int(ctx.Arg(4))
		data, _ := ctx.Mem.ReadBytes(ctx.Arg(3), dataLen)
		targetHKey := hKey
		if subKey != "" {
			path := regKeyPath(hKey, subKey)
			key := ctx.Reg.CreateKey(path)
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			targetHKey = uint64(h)
		}
		rk := handles.GetRegKey(ntapi.Handle(targetHKey))
		if rk != nil && rk.Key != nil {
			if rk.Key.Values == nil {
				rk.Key.Values = make(map[string]*ntapi.RegistryValue)
			}
			rk.Key.Values[""] = &ntapi.RegistryValue{Name: "", Type: valType, Data: data}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryValueA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		hKey := ctx.Arg(0)
		if subKey != "" {
			path := regKeyPath(hKey, subKey)
			key := ctx.Reg.OpenKey(path)
			if key == nil {
				ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
				return 0
			}
			h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
			ctx.SetReturn(uint64(regQueryValue(ctx, uint64(h), "")))
		} else {
			ctx.SetReturn(uint64(regQueryValue(ctx, hKey, "")))
		}
		return 0
	})
	// CryptAcquireContextW: acquire a CSP handle
	d.RegisterAutoStubHandler(advapi32, "CryptAcquireContextW", func(ctx *ntapi.TrapContext) uint32 {
		phProv := ctx.Arg(0)
		if phProv != 0 {
			ctx.Mem.Write64(phProv, 0xC0DE1234)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptAcquireContextA", func(ctx *ntapi.TrapContext) uint32 {
		phProv := ctx.Arg(0)
		if phProv != 0 {
			ctx.Mem.Write64(phProv, 0xC0DE1234)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// CryptCreateHash, CryptHashData, CryptGetHashParam, CryptDestroyHash, CryptReleaseContext
	// Real hash implementations using Go standard library
	type cryptHashState struct {
		h     hash.Hash
		algID uint32
	}
	cryptHashes := map[uint64]*cryptHashState{}
	cryptHashMu := sync.Mutex{}
	nextCryptH := uint64(0xA0010001)
	d.RegisterAutoStubHandler(advapi32, "CryptCreateHash", func(ctx *ntapi.TrapContext) uint32 {
		algID := uint32(ctx.Arg(1))
		phHash := ctx.Arg(3)
		var h hash.Hash
		switch algID {
		case 0x8003:
			h = md5.New() // CALG_MD5
		case 0x8004:
			h = sha1.New() // CALG_SHA1
		case 0x800c:
			h = sha256.New() // CALG_SHA_256
		case 0x800d:
			h = sha256.New() // CALG_SHA_384 (use sha256 as fallback)
		case 0x800e:
			h = sha256.New() // CALG_SHA_512 (use sha256 as fallback)
		case 0x8002:
			h = md5.New() // CALG_MD2 (use md5)
		default:
			h = sha1.New() // fallback
		}
		cryptHashMu.Lock()
		handle := nextCryptH
		nextCryptH++
		cryptHashes[handle] = &cryptHashState{h: h, algID: algID}
		cryptHashMu.Unlock()
		if phHash != 0 {
			ctx.Mem.Write64(phHash, handle)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptHashData", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbData := ctx.Arg(1)
		dwLen := ctx.Arg(2)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		if hs != nil && pbData != 0 && dwLen > 0 {
			data, _ := ctx.Mem.ReadBytes(pbData, int(dwLen))
			hs.h.Write(data)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetHashParam", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		dwParam := ctx.Arg(1)
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		if hs == nil {
			ctx.SetReturn(0)
			return 0
		}
		const HP_HASHVAL = 2
		const HP_HASHSIZE = 4
		const HP_ALGID = 1
		switch dwParam {
		case HP_ALGID:
			if pdwDataLen != 0 {
				ctx.Mem.Write32(pdwDataLen, 4)
			}
			if pbData != 0 {
				ctx.Mem.Write32(pbData, hs.algID)
			}
		case HP_HASHSIZE:
			sz := uint32(hs.h.Size())
			if pdwDataLen != 0 {
				ctx.Mem.Write32(pdwDataLen, 4)
			}
			if pbData != 0 {
				ctx.Mem.Write32(pbData, sz)
			}
		case HP_HASHVAL:
			sum := hs.h.Sum(nil)
			sz := uint32(len(sum))
			if pdwDataLen != 0 {
				avail, _ := ctx.Mem.Read32(pdwDataLen)
				ctx.Mem.Write32(pdwDataLen, sz)
				if pbData != 0 && avail >= sz {
					ctx.Mem.WriteBytes(pbData, sum)
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDestroyHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		cryptHashMu.Lock()
		delete(cryptHashes, hHash)
		cryptHashMu.Unlock()
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptHashSessionKey", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		hKey := ctx.Arg(1)
		dwFlags := uint32(ctx.Arg(2))
		ravelog.Logf("[advapi32] CryptHashSessionKey hash=0x%x key=0x%x flags=0x%x\n", hHash, hKey, dwFlags)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGenRandom", func(ctx *ntapi.TrapContext) uint32 {
		dwLen := ctx.Arg(1)
		pbBuffer := ctx.Arg(2)
		if pbBuffer != 0 && dwLen > 0 {
			buf := make([]byte, dwLen)
			_, _ = unix.Getrandom(buf, 0)
			for i, b := range buf {
				ctx.Mem.Write8(pbBuffer+uint64(i), b)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// CryptDeriveKey, CryptImportKey, CryptExportKey, CryptEncrypt, CryptDecrypt
	// Store simple key handles
	type cryptKeyState struct {
		data  []byte
		algID uint32
	}
	cryptKeys := map[uint64]*cryptKeyState{}
	cryptKeyMu := sync.Mutex{}
	nextCryptKey := uint64(0xB0010001)
	d.RegisterAutoStubHandler(advapi32, "CryptDeriveKey", func(ctx *ntapi.TrapContext) uint32 {
		algID := uint32(ctx.Arg(1))
		phKey := ctx.Arg(4)
		cryptKeyMu.Lock()
		kh := nextCryptKey
		nextCryptKey++
		cryptKeys[kh] = &cryptKeyState{algID: algID}
		cryptKeyMu.Unlock()
		if phKey != 0 {
			ctx.Mem.Write64(phKey, kh)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptImportKey", func(ctx *ntapi.TrapContext) uint32 {
		pbData := ctx.Arg(1)
		dwLen := ctx.Arg(2)
		phKey := ctx.Arg(4)
		var data []byte
		if pbData != 0 && dwLen > 0 {
			data, _ = ctx.Mem.ReadBytes(pbData, int(dwLen))
		}
		cryptKeyMu.Lock()
		kh := nextCryptKey
		nextCryptKey++
		cryptKeys[kh] = &cryptKeyState{data: data}
		cryptKeyMu.Unlock()
		if phKey != 0 {
			ctx.Mem.Write64(phKey, kh)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptExportKey", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pbData := ctx.Arg(4)
		pdwLen := ctx.Arg(5)
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if ks != nil && pdwLen != 0 {
			if pbData != 0 {
				ctx.Mem.WriteBytes(pbData, ks.data)
			}
			ctx.Mem.Write32(pdwLen, uint32(len(ks.data)))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDestroyKey", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		cryptKeyMu.Lock()
		delete(cryptKeys, hKey)
		cryptKeyMu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetKeyParam", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		dwParam := uint32(ctx.Arg(1))
		pbData := ctx.Arg(2)
		dwFlags := uint32(ctx.Arg(3))
		ravelog.Logf("[advapi32] CryptSetKeyParam key=0x%x param=%d data=0x%x flags=0x%x\n", hKey, dwParam, pbData, dwFlags)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetKeyParam", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		dwParam := uint32(ctx.Arg(1))
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptGetKeyParam key=0x%x param=%d\n", hKey, dwParam)
		if pdwDataLen != 0 && pbData == 0 {
			ctx.Mem.Write32(pdwDataLen, 4)
		} else if pdwDataLen != 0 && pbData != 0 {
			ctx.Mem.Write32(pbData, 0)
			ctx.Mem.Write32(pdwDataLen, 4)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSignHashW", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		dwKeySpec := uint32(ctx.Arg(1))
		pbSignature := ctx.Arg(3)
		pdwSigLen := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptSignHashW hash=0x%x keySpec=%d\n", hHash, dwKeySpec)
		if pdwSigLen != 0 && pbSignature == 0 {
			ctx.Mem.Write32(pdwSigLen, 128)
		} else if pdwSigLen != 0 && pbSignature != 0 {
			ctx.Mem.Write32(pdwSigLen, 128)
			for i := uint64(0); i < 128; i++ {
				ctx.Mem.Write8(pbSignature+i, 0xAA)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSignHashA", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		dwKeySpec := uint32(ctx.Arg(1))
		pbSignature := ctx.Arg(3)
		pdwSigLen := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptSignHashA hash=0x%x keySpec=%d\n", hHash, dwKeySpec)
		if pdwSigLen != 0 && pbSignature == 0 {
			ctx.Mem.Write32(pdwSigLen, 128)
		} else if pdwSigLen != 0 && pbSignature != 0 {
			ctx.Mem.Write32(pdwSigLen, 128)
			for i := uint64(0); i < 128; i++ {
				ctx.Mem.Write8(pbSignature+i, 0xAA)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptVerifySignatureW", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbSignature := ctx.Arg(1)
		dwSigLen := uint32(ctx.Arg(2))
		hPubKey := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptVerifySignatureW hash=0x%x sig=0x%x len=%d key=0x%x\n", hHash, pbSignature, dwSigLen, hPubKey)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptVerifySignatureA", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbSignature := ctx.Arg(1)
		dwSigLen := uint32(ctx.Arg(2))
		hPubKey := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptVerifySignatureA hash=0x%x sig=0x%x len=%d key=0x%x\n", hHash, pbSignature, dwSigLen, hPubKey)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEncrypt", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
		//   DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen)
		// Pass-through: data already in pbData, leave as-is (no-op encryption)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDecrypt", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
		//   DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen)
		// Pass-through: data already in pbData, leave as-is (no-op decryption)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGenKey", func(ctx *ntapi.TrapContext) uint32 {
		algID := uint32(ctx.Arg(1))
		phKey := ctx.Arg(3)
		cryptKeyMu.Lock()
		kh := nextCryptKey
		nextCryptKey++
		cryptKeys[kh] = &cryptKeyState{algID: algID}
		cryptKeyMu.Unlock()
		if phKey != 0 {
			ctx.Mem.Write64(phKey, kh)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetHashParam", func(ctx *ntapi.TrapContext) uint32 {
		// HP_HMAC_INFO (0x0005) - set HMAC key
		hHash := ctx.Arg(0)
		dwParam := ctx.Arg(1)
		pbData := ctx.Arg(2)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		const HP_HMAC_INFO = 5
		if hs != nil && dwParam == HP_HMAC_INFO && pbData != 0 {
			// HMAC_INFO: HashAlgid(4)+pad(4)+pbInnerString(8)+cbInnerString(4)+pad(4)+pbOuterString(8)+cbOuterString(4)
			// Reinitialize as HMAC-SHA256 (simplified)
			hs.h = hmac.New(sha256.New, nil)
		}
		ctx.SetReturn(1)
		return 0
	})
	_ = hmac.New // ensure import used
	// SystemFunction036 = RtlGenRandom (used by msvcrt, ucrt, etc.)
	d.RegisterAutoStubHandler(advapi32, "SystemFunction036", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		sz := ctx.Arg(1)
		if buf != 0 && sz > 0 {
			b := make([]byte, sz)
			unix.Getrandom(b, 0)
			for i, v := range b {
				ctx.Mem.Write8(buf+uint64(i), v)
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
}

func registerCrypt32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp

	crypt32, ok := hctx.SynthByName["crypt32.dll"]
	if !ok {
		return
	}
	_ = crypt32

	d.RegisterAutoStubHandler(crypt32, "CryptQueryObject", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - no crypto
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CryptMsgClose", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CryptMsgGetParam", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CertCloseStore", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CertFindCertificateInStore", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - not found
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CertGetCertificateContextProperty", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CertGetNameStringW", func(ctx *ntapi.TrapContext) uint32 {
		pszNameString := ctx.Arg(4)
		cchNameString := ctx.Arg(3)
		if pszNameString != 0 && cchNameString > 0 {
			ctx.Mem.Write16(pszNameString, 0)
		}
		ctx.SetReturn(1) // 1 char (empty string with NUL)
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CertNameToStrW", func(ctx *ntapi.TrapContext) uint32 {
		psz := ctx.Arg(3)
		csz := ctx.Arg(4)
		if psz != 0 && csz > 0 {
			ctx.Mem.Write16(psz, 0)
		}
		ctx.SetReturn(1)
		return 0
	})

	// CryptProtectData / CryptUnprotectData - pass-through (no real encryption).
	// CRYPT_DATA_BLOB: { cbData DWORD(4), padding(4), pbData BYTE*(8) } = 16 bytes on x64
	d.RegisterAutoStubHandler(crypt32, "CryptProtectData", func(ctx *ntapi.TrapContext) uint32 {
		pDataIn := ctx.Arg(0)  // DATA_BLOB *pDataIn
		pDataOut := ctx.Arg(4) // DATA_BLOB *pDataOut
		if pDataIn == 0 || pDataOut == 0 {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		cbData, _ := ctx.Mem.Read32(pDataIn)
		pbData, _ := ctx.Mem.Read64(pDataIn + 8)
		if cbData == 0 || pbData == 0 {
			ctx.Mem.Write32(pDataOut, 0)
			ctx.Mem.Write64(pDataOut+8, 0)
			ctx.SetReturn(1) // TRUE
			return 0
		}
		src, _ := ctx.Mem.ReadBytes(pbData, int(cbData))
		dst := ctx.Mem.Mmap(0, uint64(cbData), mmu.PermRead|mmu.PermWrite)
		ctx.Mem.WriteBytes(dst, src)
		ctx.Mem.Write32(pDataOut, cbData)
		ctx.Mem.Write64(pDataOut+8, dst)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(crypt32, "CryptUnprotectData", func(ctx *ntapi.TrapContext) uint32 {
		pDataIn := ctx.Arg(0)
		pDataOut := ctx.Arg(4)
		if pDataIn == 0 || pDataOut == 0 {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		cbData, _ := ctx.Mem.Read32(pDataIn)
		pbData, _ := ctx.Mem.Read64(pDataIn + 8)
		if cbData == 0 || pbData == 0 {
			ctx.Mem.Write32(pDataOut, 0)
			ctx.Mem.Write64(pDataOut+8, 0)
			ctx.SetReturn(1)
			return 0
		}
		src, _ := ctx.Mem.ReadBytes(pbData, int(cbData))
		dst := ctx.Mem.Mmap(0, uint64(cbData), mmu.PermRead|mmu.PermWrite)
		ctx.Mem.WriteBytes(dst, src)
		ctx.Mem.Write32(pDataOut, cbData)
		ctx.Mem.Write64(pDataOut+8, dst)
		ctx.SetReturn(1) // TRUE
		return 0
	})
}

func registerAdvapi32Handlers2(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	advapi32, ok := hctx.SynthByName["advapi32.dll"]
	if !ok {
		return
	}
	_ = advapi32

	d.RegisterAutoStubHandler(advapi32, "AllocateAndInitializeSid", func(ctx *ntapi.TrapContext) uint32 {
		// Allocate a minimal SID in guest memory
		pSid := ctx.Arg(8) // 9th arg (stack arg on Win64)
		if pSid != 0 {
			sidBuf := mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
			ctx.Mem.Write64(pSid, sidBuf)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CheckTokenMembership", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember)
		pIsMember := ctx.Arg(2)
		if pIsMember != 0 {
			ctx.Mem.Write32(pIsMember, 1) // TRUE - claim membership
		}
		ctx.SetReturn(1) // TRUE (success)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FreeSid", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL on success
		return 0
	})
	// IsTextUnicode: heuristic check for Unicode text - return TRUE (assume Unicode)
	d.RegisterAutoStubHandler(advapi32, "IsTextUnicode", func(ctx *ntapi.TrapContext) uint32 {
		pResult := ctx.Arg(2)
		if pResult != 0 {
			ctx.Mem.Write32(pResult, 0x0001) // IS_TEXT_UNICODE_ASCII16
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// Token / privilege helpers - single-user emulator: always succeed, return safe values
	for _, fn := range []string{"LookupPrivilegeValueA", "LookupPrivilegeValueW",
		"LookupPrivilegeNameA", "LookupPrivilegeNameW",
		"LookupPrivilegeDisplayNameA", "LookupPrivilegeDisplayNameW"} {
		fn := fn
		_ = fn
		d.RegisterAutoStubHandler(advapi32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(1)
			return 0 // TRUE
		})
	}
	// Real LookupPrivilegeValueW/A: write a LUID for the given privilege name
	d.RegisterAutoStubHandler(advapi32, "LookupPrivilegeValueW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		luidPtr := ctx.Arg(2)
		name := readGuestUTF16(namePtr)
		// Map known privilege names to LUIDs (from ntddk.h / winnt.h)
		luidMap := map[string]uint64{
			"SeCreateTokenPrivilege":          2,
			"SeAssignPrimaryTokenPrivilege":   3,
			"SeLockMemoryPrivilege":           4,
			"SeIncreaseQuotaPrivilege":        5,
			"SeMachineAccountPrivilege":       6,
			"SeTcbPrivilege":                  7,
			"SeSecurityPrivilege":             8,
			"SeTakeOwnershipPrivilege":        9,
			"SeLoadDriverPrivilege":           10,
			"SeSystemProfilePrivilege":        11,
			"SeSystemtimePrivilege":           12,
			"SeProfileSingleProcessPrivilege": 13,
			"SeIncreaseBasePriorityPrivilege": 14,
			"SeCreatePagefilePrivilege":       15,
			"SeCreatePermanentPrivilege":      16,
			"SeBackupPrivilege":               17,
			"SeRestorePrivilege":              18,
			"SeShutdownPrivilege":             19,
			"SeDebugPrivilege":                20,
			"SeAuditPrivilege":                21,
			"SeSystemEnvironmentPrivilege":    22,
			"SeChangeNotifyPrivilege":         23,
			"SeRemoteShutdownPrivilege":       24,
			"SeUndockPrivilege":               25,
			"SeSyncAgentPrivilege":            26,
			"SeEnableDelegationPrivilege":     27,
			"SeManageVolumePrivilege":         28,
			"SeImpersonatePrivilege":          29,
			"SeCreateGlobalPrivilege":         30,
			"SeTrustedCredManAccessPrivilege": 31,
			"SeRelabelPrivilege":              32,
			"SeIncreaseWorkingSetPrivilege":   33,
			"SeTimeZonePrivilege":             34,
			"SeCreateSymbolicLinkPrivilege":   35,
		}
		luid := uint64(0)
		if v, ok := luidMap[name]; ok {
			luid = v
		} else {
			luid = 0xFFFF // unknown but nonzero
		}
		if luidPtr != 0 {
			mem.Write32(luidPtr, uint32(luid)) // LowPart
			mem.Write32(luidPtr+4, 0)          // HighPart
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupPrivilegeValueA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		luidPtr := ctx.Arg(2)
		name := readGuestString(namePtr)
		luidMap := map[string]uint32{
			"SeDebugPrivilege": 20, "SeShutdownPrivilege": 19,
			"SeBackupPrivilege": 17, "SeRestorePrivilege": 18,
			"SeImpersonatePrivilege": 29, "SeCreateGlobalPrivilege": 30,
			"SeChangeNotifyPrivilege": 23, "SeIncreaseQuotaPrivilege": 5,
			"SeIncreaseBasePriorityPrivilege": 14, "SeLoadDriverPrivilege": 10,
			"SeManageVolumePrivilege": 28, "SeSecurityPrivilege": 8,
			"SeSystemEnvironmentPrivilege": 22, "SeSystemProfilePrivilege": 11,
			"SeSystemtimePrivilege": 12, "SeTakeOwnershipPrivilege": 9,
			"SeTcbPrivilege": 7, "SeUndockPrivilege": 25,
		}
		luid := uint32(0xFFFF)
		if v, ok := luidMap[name]; ok {
			luid = v
		}
		if luidPtr != 0 {
			mem.Write32(luidPtr, luid)
			mem.Write32(luidPtr+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AdjustTokenPrivileges", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL AdjustTokenPrivileges(HANDLE, BOOL DisableAll, PTOKEN_PRIVILEGES NewState,
		//   DWORD BufLen, PTOKEN_PRIVILEGES PrevState, PDWORD ReturnLen)
		disableAll := ctx.Arg(1)
		newState := ctx.Arg(2)
		if disableAll == 0 && newState != 0 {
			// Not all privileges assigned - set ERROR_NOT_ALL_ASSIGNED
			if ctx.State != nil && ctx.State.TEBAddr != 0 {
				mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, 1300)
			}
		} else {
			if ctx.State != nil && ctx.State.TEBAddr != 0 {
				mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, 0)
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenProcessToken", func(ctx *ntapi.TrapContext) uint32 {
		phToken := ctx.Arg(2)
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "token"})
		if phToken != 0 {
			mem.Write64(phToken, uint64(h))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenThreadToken", func(ctx *ntapi.TrapContext) uint32 {
		phToken := ctx.Arg(2)
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "token"})
		if phToken != 0 {
			mem.Write64(phToken, uint64(h))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DuplicateTokenEx", func(ctx *ntapi.TrapContext) uint32 {
		phNewToken := ctx.Arg(5)
		h := handles.Alloc(&ntapi.TokenHandle{})
		if phNewToken != 0 {
			mem.Write64(phNewToken, uint64(h))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DuplicateToken", func(ctx *ntapi.TrapContext) uint32 {
		phNewToken := ctx.Arg(2)
		h := handles.Alloc(&ntapi.TokenHandle{})
		if phNewToken != 0 {
			mem.Write64(phNewToken, uint64(h))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "IsTokenRestricted", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0 // FALSE = not restricted
	})
	for _, fn := range []string{"ImpersonateSelf", "RevertToSelf", "ImpersonateLoggedOnUser",
		"SetThreadToken", "PrivilegeCheck"} {
		fn := fn
		d.RegisterAutoStubHandler(advapi32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[advapi32] %s arg0=0x%x arg1=0x%x\n", fn, ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(1)
			return 0
		})
	}
	// SCM stubs - service manager not supported but apps probe for it
	for _, fn := range []string{"OpenSCManagerA", "OpenSCManagerW",
		"OpenServiceA", "OpenServiceW",
		"CreateServiceA", "CreateServiceW",
		"StartServiceA", "StartServiceW",
		"ControlService", "DeleteService",
		"CloseServiceHandle", "QueryServiceStatus",
		"QueryServiceConfigA", "QueryServiceConfigW",
		"ChangeServiceConfigA", "ChangeServiceConfigW"} {
		fn := fn
		d.RegisterAutoStubHandler(advapi32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[advapi32] %s arg0=0x%x arg1=0x%x - SCM not supported\n", fn, ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(0)
			return 0
		})
	}
	// Event log stubs
	for _, fn := range []string{"RegisterEventSourceA", "RegisterEventSourceW",
		"DeregisterEventSource", "ReportEventA", "ReportEventW",
		"OpenEventLogA", "OpenEventLogW", "CloseEventLog",
		"ReadEventLogA", "ReadEventLogW"} {
		fn := fn
		d.RegisterAutoStubHandler(advapi32, fn, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[advapi32] %s arg0=0x%x arg1=0x%x - event log stub\n", fn, ctx.Arg(0), ctx.Arg(1))
			ctx.SetReturn(1)
			return 0
		})
	}
	// SID helpers - real implementations
	d.RegisterAutoStubHandler(advapi32, "IsValidSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rev, _ := ctx.Mem.Read8(pSid)
		nSub, _ := ctx.Mem.Read8(pSid + 1)
		if rev == 1 && nSub <= 8 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EqualSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid1 := ctx.Arg(0)
		pSid2 := ctx.Arg(1)
		if pSid1 == 0 || pSid2 == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub1, _ := ctx.Mem.Read8(pSid1 + 1)
		nSub2, _ := ctx.Mem.Read8(pSid2 + 1)
		if nSub1 != nSub2 {
			ctx.SetReturn(0)
			return 0
		}
		size := uint64(8 + uint64(nSub1)*4)
		b1, _ := ctx.Mem.ReadBytes(pSid1, int(size))
		b2, _ := ctx.Mem.ReadBytes(pSid2, int(size))
		for i := range b1 {
			if b1[i] != b2[i] {
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetLengthSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub, _ := ctx.Mem.Read8(pSid + 1)
		ctx.SetReturn(8 + uint64(nSub)*4)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CopySid", func(ctx *ntapi.TrapContext) uint32 {
		nDestLen := uint32(ctx.Arg(0))
		pDest := ctx.Arg(1)
		pSrc := ctx.Arg(2)
		if pSrc == 0 || pDest == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub, _ := ctx.Mem.Read8(pSrc + 1)
		sidLen := uint32(8 + uint32(nSub)*4)
		if nDestLen < sidLen {
			ctx.SetReturn(0)
			return 0
		}
		data, _ := ctx.Mem.ReadBytes(pSrc, int(sidLen))
		ctx.Mem.WriteBytes(pDest, data)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSidToStringSidW", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if pSid == 0 || ppStr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub, _ := ctx.Mem.Read8(pSid + 1)
		var auth uint64
		for i := uint64(0); i < 6; i++ {
			b, _ := ctx.Mem.Read8(pSid + 2 + i)
			auth = (auth << 8) | uint64(b)
		}
		s := fmt.Sprintf("S-1-%d", auth)
		for i := uint8(0); i < nSub; i++ {
			sub, _ := ctx.Mem.Read32(pSid + 8 + uint64(i)*4)
			s += fmt.Sprintf("-%d", sub)
		}
		ws := utf16Encode(s)
		strBuf := mem.Mmap(0, uint64(len(ws)+1)*2, mmu.PermRead|mmu.PermWrite)
		for i, w := range ws {
			mem.Write16(strBuf+uint64(i)*2, w)
		}
		mem.Write16(strBuf+uint64(len(ws))*2, 0)
		mem.Write64(ppStr, strBuf)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSidToStringSidA", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if pSid == 0 || ppStr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub, _ := ctx.Mem.Read8(pSid + 1)
		var auth uint64
		for i := uint64(0); i < 6; i++ {
			b, _ := ctx.Mem.Read8(pSid + 2 + i)
			auth = (auth << 8) | uint64(b)
		}
		s := fmt.Sprintf("S-1-%d", auth)
		for i := uint8(0); i < nSub; i++ {
			sub, _ := ctx.Mem.Read32(pSid + 8 + uint64(i)*4)
			s += fmt.Sprintf("-%d", sub)
		}
		strBuf := mem.Mmap(0, uint64(len(s)+1), mmu.PermRead|mmu.PermWrite)
		for i := 0; i < len(s); i++ {
			mem.Write8(strBuf+uint64(i), s[i])
		}
		mem.Write8(strBuf+uint64(len(s)), 0)
		mem.Write64(ppStr, strBuf)
		ctx.SetReturn(1)
		return 0
	})
	// SID helpers - real implementations per ReactOS
	// buildSID constructs a binary SID from authority and sub-authorities
	buildSID := func(authority uint64, subAuths ...uint32) []byte {
		nSub := len(subAuths)
		sid := make([]byte, 8+nSub*4)
		sid[0] = 1 // Revision
		sid[1] = byte(nSub)
		sid[2] = byte(authority >> 40)
		sid[3] = byte(authority >> 32)
		sid[4] = byte(authority >> 24)
		sid[5] = byte(authority >> 16)
		sid[6] = byte(authority >> 8)
		sid[7] = byte(authority)
		for i, v := range subAuths {
			sid[8+i*4+0] = byte(v)
			sid[8+i*4+1] = byte(v >> 8)
			sid[8+i*4+2] = byte(v >> 16)
			sid[8+i*4+3] = byte(v >> 24)
		}
		return sid
	}

	// GetSidSubAuthorityCount returns pointer to SubAuthorityCount byte in SID
	d.RegisterAutoStubHandler(advapi32, "GetSidSubAuthorityCount", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(pSid + 1) // SubAuthorityCount at offset 1
		return 0
	})
	// GetSidSubAuthority returns pointer to SubAuthority[nSubAuthority]
	d.RegisterAutoStubHandler(advapi32, "GetSidSubAuthority", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		nSubAuth := ctx.Arg(1)
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(pSid + 8 + nSubAuth*4) // SubAuthority array at offset 8
		return 0
	})
	// GetSidIdentifierAuthority returns pointer to IdentifierAuthority (6 bytes at offset 2)
	d.RegisterAutoStubHandler(advapi32, "GetSidIdentifierAuthority", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(pSid + 2)
		return 0
	})
	// InitializeSid writes revision, authority, and zeroed sub-authorities
	d.RegisterAutoStubHandler(advapi32, "InitializeSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		pAuth := ctx.Arg(1)
		nSub := uint8(ctx.Arg(2))
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		mem.Write8(pSid, 1)      // Revision = SID_REVISION
		mem.Write8(pSid+1, nSub) // SubAuthorityCount
		if pAuth != 0 {
			for i := uint64(0); i < 6; i++ {
				b, _ := mem.Read8(pAuth + i)
				mem.Write8(pSid+2+i, b)
			}
		}
		for i := uint8(0); i < nSub; i++ {
			mem.Write32(pSid+8+uint64(i)*4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	// CreateWellKnownSid builds a well-known SID by type
	d.RegisterAutoStubHandler(advapi32, "CreateWellKnownSid", func(ctx *ntapi.TrapContext) uint32 {
		sidType := uint32(ctx.Arg(0))
		pSid := ctx.Arg(2)
		pcbSid := ctx.Arg(3)
		var sid []byte
		switch sidType {
		case 0: // WinNullSid: S-1-0-0
			sid = buildSID(0, 0)
		case 1: // WinWorldSid: S-1-1-0
			sid = buildSID(1, 0)
		case 2: // WinLocalSid: S-1-2-0
			sid = buildSID(2, 0)
		case 3: // WinCreatorOwnerSid: S-1-3-0
			sid = buildSID(3, 0)
		case 4: // WinCreatorGroupSid: S-1-3-1
			sid = buildSID(3, 1)
		case 7: // WinNtAuthoritySid: S-1-5
			sid = buildSID(5)
		case 8: // WinDialupSid: S-1-5-1
			sid = buildSID(5, 1)
		case 9: // WinNetworkSid: S-1-5-2
			sid = buildSID(5, 2)
		case 10: // WinBatchSid: S-1-5-3
			sid = buildSID(5, 3)
		case 11: // WinInteractiveSid: S-1-5-4
			sid = buildSID(5, 4)
		case 12: // WinServiceSid: S-1-5-6
			sid = buildSID(5, 6)
		case 13: // WinAnonymousSid: S-1-5-7
			sid = buildSID(5, 7)
		case 22: // WinLocalSystemSid: S-1-5-18
			sid = buildSID(5, 18)
		case 23: // WinLocalServiceSid: S-1-5-19
			sid = buildSID(5, 19)
		case 24: // WinNetworkServiceSid: S-1-5-20
			sid = buildSID(5, 20)
		case 25: // WinBuiltinDomainSid: S-1-5-32
			sid = buildSID(5, 32)
		case 26: // WinBuiltinAdministratorsSid: S-1-5-32-544
			sid = buildSID(5, 32, 544)
		case 27: // WinBuiltinUsersSid: S-1-5-32-545
			sid = buildSID(5, 32, 545)
		case 28: // WinBuiltinGuestsSid: S-1-5-32-546
			sid = buildSID(5, 32, 546)
		case 29: // WinBuiltinPowerUsersSid: S-1-5-32-547
			sid = buildSID(5, 32, 547)
		case 36: // WinAuthenticatedUserSid: S-1-5-11
			sid = buildSID(5, 11)
		case 66: // WinLowLabelSid: S-1-16-4096
			sid = buildSID(16, 4096)
		case 67: // WinMediumLabelSid: S-1-16-8192
			sid = buildSID(16, 8192)
		case 68: // WinHighLabelSid: S-1-16-12288
			sid = buildSID(16, 12288)
		case 69: // WinSystemLabelSid: S-1-16-16384
			sid = buildSID(16, 16384)
		default:
			sid = buildSID(0, 0) // fallback: null SID
		}
		needed := uint32(len(sid))
		if pcbSid != 0 {
			avail, _ := mem.Read32(pcbSid)
			mem.Write32(pcbSid, needed)
			if avail < needed {
				ctx.SetReturn(0) // ERROR_INSUFFICIENT_BUFFER
				return 0
			}
		}
		if pSid != 0 {
			mem.WriteBytes(pSid, sid)
		}
		ctx.SetReturn(1)
		return 0
	})
	// IsWellKnownSid checks if a SID matches a well-known SID type
	d.RegisterAutoStubHandler(advapi32, "IsWellKnownSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(0)
		sidType := uint32(ctx.Arg(1))
		if pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var expected []byte
		switch sidType {
		case 0:
			expected = buildSID(0, 0)
		case 1:
			expected = buildSID(1, 0)
		case 2:
			expected = buildSID(2, 0)
		case 3:
			expected = buildSID(3, 0)
		case 4:
			expected = buildSID(3, 1)
		case 22:
			expected = buildSID(5, 18)
		case 23:
			expected = buildSID(5, 19)
		case 24:
			expected = buildSID(5, 20)
		case 25:
			expected = buildSID(5, 32)
		case 26:
			expected = buildSID(5, 32, 544)
		case 27:
			expected = buildSID(5, 32, 545)
		case 36:
			expected = buildSID(5, 11)
		case 66:
			expected = buildSID(16, 4096)
		case 67:
			expected = buildSID(16, 8192)
		case 68:
			expected = buildSID(16, 12288)
		case 69:
			expected = buildSID(16, 16384)
		default:
			ctx.SetReturn(0)
			return 0
		}
		actual, _ := mem.ReadBytes(pSid, len(expected))
		for i := range expected {
			if i >= len(actual) || actual[i] != expected[i] {
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	// EqualPrefixSid compares SID prefix (all sub-authorities except the last)
	d.RegisterAutoStubHandler(advapi32, "EqualPrefixSid", func(ctx *ntapi.TrapContext) uint32 {
		pSid1 := ctx.Arg(0)
		pSid2 := ctx.Arg(1)
		if pSid1 == 0 || pSid2 == 0 {
			ctx.SetReturn(0)
			return 0
		}
		nSub1, _ := mem.Read8(pSid1 + 1)
		nSub2, _ := mem.Read8(pSid2 + 1)
		if nSub1 != nSub2 {
			ctx.SetReturn(0)
			return 0
		}
		// Compare authority (6 bytes at offset 2)
		for i := uint64(0); i < 6; i++ {
			b1, _ := mem.Read8(pSid1 + 2 + i)
			b2, _ := mem.Read8(pSid2 + 2 + i)
			if b1 != b2 {
				ctx.SetReturn(0)
				return 0
			}
		}
		// Compare sub-authorities except the last (the RID)
		if nSub1 > 1 {
			for i := uint8(0); i < nSub1-1; i++ {
				off := 8 + uint64(i)*4
				s1, _ := mem.Read32(pSid1 + off)
				s2, _ := mem.Read32(pSid2 + off)
				if s1 != s2 {
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})

	// ConvertStringSidToSidA/W - parse "S-1-5-21-xxx-yyy-zzz-500" into a binary SID
	parseSidString := func(s string) []byte {
		// Expected format: S-Revision-Authority-Sub1-Sub2-...
		if len(s) < 4 || s[0] != 'S' || s[1] != '-' {
			return nil
		}
		parts := []string{}
		cur := ""
		for _, c := range s[2:] {
			if c == '-' {
				parts = append(parts, cur)
				cur = ""
			} else {
				cur += string(c)
			}
		}
		parts = append(parts, cur)
		if len(parts) < 2 {
			return nil
		}
		var rev uint8 = 1
		if len(parts[0]) > 0 {
			fmt.Sscanf(parts[0], "%d", &rev)
		}
		var auth uint64
		fmt.Sscanf(parts[1], "%d", &auth)
		nSub := len(parts) - 2
		if nSub < 0 {
			nSub = 0
		}
		sid := make([]byte, 8+nSub*4)
		sid[0] = rev
		sid[1] = byte(nSub)
		// Authority (6 bytes, big-endian)
		sid[2] = byte(auth >> 40)
		sid[3] = byte(auth >> 32)
		sid[4] = byte(auth >> 24)
		sid[5] = byte(auth >> 16)
		sid[6] = byte(auth >> 8)
		sid[7] = byte(auth)
		for i := 0; i < nSub; i++ {
			var v uint32
			fmt.Sscanf(parts[2+i], "%d", &v)
			sid[8+i*4+0] = byte(v)
			sid[8+i*4+1] = byte(v >> 8)
			sid[8+i*4+2] = byte(v >> 16)
			sid[8+i*4+3] = byte(v >> 24)
		}
		return sid
	}
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSidToSidA", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		ppSid := ctx.Arg(1)
		if strPtr == 0 || ppSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestString(strPtr)
		sid := parseSidString(s)
		if sid == nil {
			ctx.SetReturn(0)
			return 0
		}
		buf := mem.Mmap(0, uint64(len(sid)), mmu.PermRead|mmu.PermWrite)
		mem.WriteBytes(buf, sid)
		mem.Write64(ppSid, buf)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSidToSidW", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		ppSid := ctx.Arg(1)
		if strPtr == 0 || ppSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestUTF16(strPtr)
		sid := parseSidString(s)
		if sid == nil {
			ctx.SetReturn(0)
			return 0
		}
		buf := mem.Mmap(0, uint64(len(sid)), mmu.PermRead|mmu.PermWrite)
		mem.WriteBytes(buf, sid)
		mem.Write64(ppSid, buf)
		ctx.SetReturn(1)
		return 0
	})

	// LookupAccountSidW: return "User" / "RAVEN" for any SID
	d.RegisterAutoStubHandler(advapi32, "LookupAccountSidW", func(ctx *ntapi.TrapContext) uint32 {
		// (lpSystemName, Sid, Name, cchName, ReferencedDomainName, cchReferencedDomainName, peUse)
		lpName := ctx.Arg(2)
		lpcchName := ctx.Arg(3)
		lpDomain := ctx.Arg(4)
		lpcchDomain := ctx.Arg(5)
		peUse := ctx.Arg(6)

		nameWs := utf16Encode("User")
		domainWs := utf16Encode("RAVEN")
		nameNeeded := uint32(len(nameWs) + 1)
		domainNeeded := uint32(len(domainWs) + 1)

		nameAvail := uint32(0)
		domainAvail := uint32(0)
		if lpcchName != 0 {
			nameAvail, _ = mem.Read32(lpcchName)
			mem.Write32(lpcchName, nameNeeded)
		}
		if lpcchDomain != 0 {
			domainAvail, _ = mem.Read32(lpcchDomain)
			mem.Write32(lpcchDomain, domainNeeded)
		}
		if (lpName != 0 && nameAvail < nameNeeded) || (lpDomain != 0 && domainAvail < domainNeeded) {
			ctx.SetReturn(0) // ERROR_INSUFFICIENT_BUFFER
			return 0
		}
		if lpName != 0 {
			for i, w := range nameWs {
				mem.Write16(lpName+uint64(i)*2, w)
			}
			mem.Write16(lpName+uint64(len(nameWs))*2, 0)
		}
		if lpDomain != 0 {
			for i, w := range domainWs {
				mem.Write16(lpDomain+uint64(i)*2, w)
			}
			mem.Write16(lpDomain+uint64(len(domainWs))*2, 0)
		}
		if peUse != 0 {
			mem.Write32(peUse, 1) // SidTypeUser
		}
		ctx.SetReturn(1)
		return 0
	})
	// LookupAccountSidA: ANSI variant
	d.RegisterAutoStubHandler(advapi32, "LookupAccountSidA", func(ctx *ntapi.TrapContext) uint32 {
		lpName := ctx.Arg(2)
		lpcchName := ctx.Arg(3)
		lpDomain := ctx.Arg(4)
		lpcchDomain := ctx.Arg(5)
		peUse := ctx.Arg(6)

		name := "User"
		domain := "RAVEN"
		nameNeeded := uint32(len(name) + 1)
		domainNeeded := uint32(len(domain) + 1)

		nameAvail := uint32(0)
		domainAvail := uint32(0)
		if lpcchName != 0 {
			nameAvail, _ = mem.Read32(lpcchName)
			mem.Write32(lpcchName, nameNeeded)
		}
		if lpcchDomain != 0 {
			domainAvail, _ = mem.Read32(lpcchDomain)
			mem.Write32(lpcchDomain, domainNeeded)
		}
		if (lpName != 0 && nameAvail < nameNeeded) || (lpDomain != 0 && domainAvail < domainNeeded) {
			ctx.SetReturn(0)
			return 0
		}
		if lpName != 0 {
			for i := 0; i < len(name); i++ {
				mem.Write8(lpName+uint64(i), name[i])
			}
			mem.Write8(lpName+uint64(len(name)), 0)
		}
		if lpDomain != 0 {
			for i := 0; i < len(domain); i++ {
				mem.Write8(lpDomain+uint64(i), domain[i])
			}
			mem.Write8(lpDomain+uint64(len(domain)), 0)
		}
		if peUse != 0 {
			mem.Write32(peUse, 1) // SidTypeUser
		}
		ctx.SetReturn(1)
		return 0
	})
	// Security descriptor helpers
	d.RegisterAutoStubHandler(advapi32, "InitializeSecurityDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		pSd := ctx.Arg(0)
		// rev := ctx.Arg(1) // SECURITY_DESCRIPTOR_REVISION = 1
		if pSd == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// SECURITY_DESCRIPTOR (absolute): revision(1)+sbz(1)+control(2)+owner(8)+group(8)+sacl(8)+dacl(8)
		for i := uint64(0); i < 40; i++ {
			mem.Write8(pSd+i, 0)
		}
		mem.Write8(pSd, 1)         // Revision = 1
		mem.Write16(pSd+2, 0x8000) // SE_SELF_RELATIVE flag off, no DACL by default
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorDacl", func(ctx *ntapi.TrapContext) uint32 {
		pSd := ctx.Arg(0)
		bDaclPresent := ctx.Arg(1) != 0
		pDacl := ctx.Arg(2)
		bDaclDefaulted := ctx.Arg(3) != 0
		if pSd == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Modify Control flags at offset 2
		ctrl, _ := mem.Read16(pSd + 2)
		const seDaclPresent = 0x0004
		const seDaclDefaulted = 0x0008
		ctrl &^= seDaclPresent | seDaclDefaulted
		if bDaclPresent {
			ctrl |= seDaclPresent
		}
		if bDaclDefaulted {
			ctrl |= seDaclDefaulted
		}
		mem.Write16(pSd+2, ctrl)
		// DACL pointer at offset 28 in absolute SD
		mem.Write64(pSd+28, pDacl)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorSacl", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetSecurityDescriptorSacl(PSECURITY_DESCRIPTOR pSd, BOOL bSaclPresent,
		//   PACL pSacl, BOOL bSaclDefaulted)
		pSd := ctx.Arg(0)
		bSaclPresent := ctx.Arg(1) != 0
		pSacl := ctx.Arg(2)
		bSaclDefaulted := ctx.Arg(3) != 0
		if pSd != 0 {
			const seSaclPresent = 0x0010
			const seSaclDefaulted = 0x0020
			ctrl, _ := mem.Read16(pSd + 2)
			ctrl &^= seSaclPresent | seSaclDefaulted
			if bSaclPresent {
				ctrl |= seSaclPresent
			}
			if bSaclDefaulted {
				ctrl |= seSaclDefaulted
			}
			mem.Write16(pSd+2, ctrl)
			// SACL pointer at offset 20 in absolute SD
			mem.Write64(pSd+20, pSacl)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorOwner", func(ctx *ntapi.TrapContext) uint32 {
		pSd := ctx.Arg(0)
		pOwner := ctx.Arg(1)
		bOwnerDefaulted := ctx.Arg(2) != 0
		if pSd != 0 {
			const seOwnerDefaulted = 0x0001
			ctrl, _ := mem.Read16(pSd + 2)
			ctrl &^= seOwnerDefaulted
			if bOwnerDefaulted {
				ctrl |= seOwnerDefaulted
			}
			mem.Write16(pSd+2, ctrl)
			mem.Write64(pSd+8, pOwner) // Owner at offset 8 in absolute SD
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorGroup", func(ctx *ntapi.TrapContext) uint32 {
		pSd := ctx.Arg(0)
		pGroup := ctx.Arg(1)
		bGroupDefaulted := ctx.Arg(2) != 0
		if pSd != 0 {
			const seGroupDefaulted = 0x0002
			ctrl, _ := mem.Read16(pSd + 2)
			ctrl &^= seGroupDefaulted
			if bGroupDefaulted {
				ctrl |= seGroupDefaulted
			}
			mem.Write16(pSd+2, ctrl)
			mem.Write64(pSd+16, pGroup) // Group at offset 16 in absolute SD
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorDacl", func(ctx *ntapi.TrapContext) uint32 {
		pbPresent := ctx.Arg(1)
		ppDacl := ctx.Arg(2)
		pbDefaulted := ctx.Arg(3)
		if pbPresent != 0 {
			mem.Write32(pbPresent, 0)
		} // no DACL
		if ppDacl != 0 {
			mem.Write64(ppDacl, 0)
		}
		if pbDefaulted != 0 {
			mem.Write32(pbDefaulted, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorOwner", func(ctx *ntapi.TrapContext) uint32 {
		ppOwner := ctx.Arg(1)
		pbDefaulted := ctx.Arg(2)
		if ppOwner != 0 {
			mem.Write64(ppOwner, 0)
		}
		if pbDefaulted != 0 {
			mem.Write32(pbDefaulted, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorGroup", func(ctx *ntapi.TrapContext) uint32 {
		ppGroup := ctx.Arg(1)
		pbDefaulted := ctx.Arg(2)
		if ppGroup != 0 {
			mem.Write64(ppGroup, 0)
		}
		if pbDefaulted != 0 {
			mem.Write32(pbDefaulted, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "IsValidSecurityDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		pSd := ctx.Arg(0)
		if pSd == 0 {
			ctx.SetReturn(0) // NULL is not valid
			return 0
		}
		rev, _ := mem.Read8(pSd)
		if rev != 1 {
			ctx.SetReturn(0) // invalid revision
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MakeSelfRelativeSD", func(ctx *ntapi.TrapContext) uint32 {
		// Just copy as-is (pretend already self-relative)
		pAbsSD := ctx.Arg(0)
		pSelfSD := ctx.Arg(1)
		pLen := ctx.Arg(2)
		size := uint32(40)
		if pLen != 0 {
			needed, _ := mem.Read32(pLen)
			if needed < size {
				mem.Write32(pLen, size)
				ctx.SetReturn(0)
				return 0
			}
		}
		if pSelfSD != 0 && pAbsSD != 0 {
			data, _ := mem.ReadBytes(pAbsSD, 40)
			mem.WriteBytes(pSelfSD, data)
			// Set SE_SELF_RELATIVE bit in Control
			ctrl, _ := mem.Read16(pSelfSD + 2)
			mem.Write16(pSelfSD+2, ctrl|0x8000)
		}
		ctx.SetReturn(1)
		return 0
	})

	// ACL helpers
	d.RegisterAutoStubHandler(advapi32, "InitializeAcl", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		nAclLen := ctx.Arg(1)
		// aclRevision := ctx.Arg(2) // 2 = ACL_REVISION
		if pAcl == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// ACL header: AclRevision(1)+Sbz1(1)+AclSize(2)+AceCount(2)+Sbz2(2)
		mem.Write8(pAcl, 2) // AclRevision
		mem.Write8(pAcl+1, 0)
		mem.Write16(pAcl+2, uint16(nAclLen)) // AclSize
		mem.Write16(pAcl+4, 0)               // AceCount = 0
		mem.Write16(pAcl+6, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessAllowedAce", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		// dwAceRevision := ctx.Arg(1)
		accessMask := uint32(ctx.Arg(2))
		pSid := ctx.Arg(3)
		if pAcl == 0 || pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Read current AceCount
		aceCount, _ := mem.Read16(pAcl + 4)
		aclSize, _ := mem.Read16(pAcl + 2)
		nSub, _ := mem.Read8(pSid + 1)
		sidLen := uint32(8 + uint32(nSub)*4)
		aceSize := uint16(4 + 4 + sidLen) // ACE_HEADER(4) + Mask(4) + SID
		// Write ACE after ACL header + existing ACEs
		// Find end: we track AclSize used in bytes (simple append)
		aceOff := uint64(aclSize) // placed at end of current ACL
		_ = aceOff
		aceOff = pAcl + 8 + uint64(aceCount)*uint64(aceSize) // naive
		mem.Write8(aceOff, 0)                                // ACCESS_ALLOWED_ACE_TYPE
		mem.Write8(aceOff+1, 0)                              // Flags
		mem.Write16(aceOff+2, aceSize)                       // AceSize
		mem.Write32(aceOff+4, accessMask)
		sidData, _ := mem.ReadBytes(pSid, int(sidLen))
		mem.WriteBytes(aceOff+8, sidData)
		mem.Write16(pAcl+4, aceCount+1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessAllowedAceEx", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		aceFlags := uint8(ctx.Arg(2))
		accessMask := uint32(ctx.Arg(3))
		pSid := ctx.Arg(4)
		if pAcl == 0 || pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		aceCount, _ := mem.Read16(pAcl + 4)
		nSub, _ := mem.Read8(pSid + 1)
		sidLen := uint32(8 + uint32(nSub)*4)
		aceSize := uint16(4 + 4 + sidLen)
		aceOff := pAcl + 8 + uint64(aceCount)*uint64(aceSize)
		mem.Write8(aceOff, 0)           // ACCESS_ALLOWED_ACE_TYPE
		mem.Write8(aceOff+1, aceFlags)
		mem.Write16(aceOff+2, aceSize)
		mem.Write32(aceOff+4, accessMask)
		sidData, _ := mem.ReadBytes(pSid, int(sidLen))
		mem.WriteBytes(aceOff+8, sidData)
		mem.Write16(pAcl+4, aceCount+1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessDeniedAce", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		accessMask := uint32(ctx.Arg(2))
		pSid := ctx.Arg(3)
		if pAcl == 0 || pSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		aceCount, _ := mem.Read16(pAcl + 4)
		nSub, _ := mem.Read8(pSid + 1)
		sidLen := uint32(8 + uint32(nSub)*4)
		aceSize := uint16(4 + 4 + sidLen)
		aceOff := pAcl + 8 + uint64(aceCount)*uint64(aceSize)
		mem.Write8(aceOff, 1)           // ACCESS_DENIED_ACE_TYPE
		mem.Write8(aceOff+1, 0)
		mem.Write16(aceOff+2, aceSize)
		mem.Write32(aceOff+4, accessMask)
		sidData, _ := mem.ReadBytes(pSid, int(sidLen))
		mem.WriteBytes(aceOff+8, sidData)
		mem.Write16(pAcl+4, aceCount+1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAce", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		dwStartingAceIndex := uint32(ctx.Arg(2))
		pAceList := ctx.Arg(3)
		nAceListLength := uint32(ctx.Arg(4))
		ravelog.Logf("[advapi32] AddAce acl=0x%x start=%d aceList=0x%x len=%d\n", pAcl, dwStartingAceIndex, pAceList, nAceListLength)
		if pAcl == 0 || pAceList == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAce", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		aceIndex := ctx.Arg(1)
		ppAce := ctx.Arg(2)
		aceCount, _ := mem.Read16(pAcl + 4)
		if uint64(aceCount) <= aceIndex {
			ctx.SetReturn(0)
			return 0
		}
		if ppAce != 0 {
			// Find ace at index (fixed-size: 12 bytes each for simple ACEs)
			aceOff := pAcl + 8 + aceIndex*12
			mem.Write64(ppAce, aceOff)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAclInformation", func(ctx *ntapi.TrapContext) uint32 {
		pAcl := ctx.Arg(0)
		pInfo := ctx.Arg(1)
		// nInfoLen := ctx.Arg(2)
		infoClass := ctx.Arg(3)
		if pAcl == 0 || pInfo == 0 {
			ctx.SetReturn(0)
			return 0
		}
		switch infoClass {
		case 1: // AclRevisionInformation: Revision(4)
			rev, _ := mem.Read8(pAcl)
			mem.Write32(pInfo, uint32(rev))
		case 2: // AclSizeInformation: AceCount(4), AclBytesFree(4), AclBytesInUse(4)
			aceCount, _ := mem.Read16(pAcl + 4)
			aclSize, _ := mem.Read16(pAcl + 2)
			mem.Write32(pInfo, uint32(aceCount))
			mem.Write32(pInfo+4, 0)
			mem.Write32(pInfo+8, uint32(aclSize))
		}
		ctx.SetReturn(1)
		return 0
	})

	// GetNamedSecurityInfo / SetNamedSecurityInfo
	d.RegisterAutoStubHandler(advapi32, "GetNamedSecurityInfoA", func(ctx *ntapi.TrapContext) uint32 {
		ppSecDesc := ctx.Arg(7)
		if ppSecDesc != 0 {
			mem.Write64(ppSecDesc, 0)
		}
		ctx.SetReturn(0)
		return 0 // ERROR_SUCCESS, no security info
	})
	d.RegisterAutoStubHandler(advapi32, "GetNamedSecurityInfoW", func(ctx *ntapi.TrapContext) uint32 {
		ppSecDesc := ctx.Arg(7)
		if ppSecDesc != 0 {
			mem.Write64(ppSecDesc, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetNamedSecurityInfoA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0 // ERROR_SUCCESS
	})
	d.RegisterAutoStubHandler(advapi32, "SetNamedSecurityInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pObjectName := ctx.Arg(0)
		objectType := uint32(ctx.Arg(1))
		secInfo := uint32(ctx.Arg(2))
		name := readGuestUTF16(pObjectName)
		ravelog.Logf("[advapi32] SetNamedSecurityInfoW obj=%q type=%d secInfo=0x%x\n", name, objectType, secInfo)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityInfo", func(ctx *ntapi.TrapContext) uint32 {
		ppSecDesc := ctx.Arg(7)
		if ppSecDesc != 0 {
			mem.Write64(ppSecDesc, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityInfo", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		objectType := uint32(ctx.Arg(1))
		secInfo := uint32(ctx.Arg(2))
		ravelog.Logf("[advapi32] SetSecurityInfo handle=0x%x type=%d secInfo=0x%x\n", handle, objectType, secInfo)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})

	// AllocateAndInitializeSid - builds a SID from authority + sub-auths
	d.RegisterAutoStubHandler(advapi32, "AllocateAndInitializeSid", func(ctx *ntapi.TrapContext) uint32 {
		pAuth := ctx.Arg(0)
		nSub := uint8(ctx.Arg(1))
		ppSid := ctx.Arg(8)
		if pAuth == 0 || ppSid == 0 {
			ctx.SetReturn(0)
			return 0
		}
		sidLen := 8 + uint64(nSub)*4
		buf := mem.Mmap(0, sidLen, mmu.PermRead|mmu.PermWrite)
		mem.Write8(buf, 1) // Revision
		mem.Write8(buf+1, nSub)
		// Copy 6-byte authority from SID_IDENTIFIER_AUTHORITY
		for i := uint64(0); i < 6; i++ {
			b, _ := mem.Read8(pAuth + i)
			mem.Write8(buf+2+i, b)
		}
		// Sub-authorities: arg2..arg7 (RDX=1, R8=2, R9=3, then stack)
		for i := uint8(0); i < nSub && i < 6; i++ {
			v := uint32(ctx.Arg(int(2 + i)))
			mem.Write32(buf+8+uint64(i)*4, v)
		}
		mem.Write64(ppSid, buf)
		ctx.SetReturn(1)
		return 0
	})

	// GetTokenInformation - expanded classes
	d.RegisterAutoStubHandler(advapi32, "GetTokenInformation", func(ctx *ntapi.TrapContext) uint32 {
		tokenClass := ctx.Arg(1)
		buf := ctx.Arg(2)
		bufLen := ctx.Arg(3)
		retLen := ctx.Arg(4)
		switch tokenClass {
		case 1: // TokenUser: TOKEN_USER = {SID_AND_ATTRIBUTES{pSid, Attributes}}
			// We return a TOKEN_USER with a minimal local admin SID S-1-5-21-0-0-0-500
			// SID S-1-5-21: 28 bytes (Revision+nSub+6auth+5*4sub)
			sidBytes := []byte{
				1, 5, // Revision=1, nSub=5
				0, 0, 0, 0, 0, 5, // Authority=5 (NT)
				21, 0, 0, 0, // Sub 1 = 21
				0, 0, 0, 0, // Sub 2
				0, 0, 0, 0, // Sub 3
				0, 0, 0, 0, // Sub 4
				0xF4, 1, 0, 0, // Sub 5 = 500 (Administrator RID)
			}
			needed := 16 + uint32(len(sidBytes)) // SID_AND_ATTRIBUTES(16) + SID
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				sidAddr := buf + 16
				mem.WriteBytes(sidAddr, sidBytes)
				mem.Write64(buf, sidAddr) // pSid
				mem.Write32(buf+8, 0)     // Attributes
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 2: // TokenGroups
			needed := uint32(4) // TOKEN_GROUPS.GroupCount=0 only
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 0) // GroupCount = 0
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 3: // TokenPrivileges
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 0)
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 5: // TokenPrimaryGroup
			needed := uint32(8)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write64(buf, 0)
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 6: // TokenDefaultDacl
			needed := uint32(8)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write64(buf, 0)
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 7: // TokenSource
			needed := uint32(16)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				// TOKEN_SOURCE: SourceName[8] + SourceIdentifier (LUID 8 bytes)
				for i := uint64(0); i < 16; i++ {
					mem.Write8(buf+i, 0)
				}
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 8: // TokenType
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 1) // TokenPrimary = 1
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 9: // TokenImpersonationLevel
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 2) // SecurityImpersonation
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 10: // TokenStatistics: 48 bytes
			needed := uint32(48)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				for i := uint64(0); i < 48; i++ {
					mem.Write8(buf+i, 0)
				}
				mem.Write32(buf+16, 1) // TokenType = Primary
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 17: // TokenElevationType
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 1) // TokenElevationTypeDefault
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 18: // TokenLinkedToken
			needed := uint32(8)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write64(buf, 0)
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 19: // TokenElevation
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 0) // TokenIsElevated = FALSE
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 20: // TokenHasRestrictions
			needed := uint32(4)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write32(buf, 0) // FALSE
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		case 25: // TokenIntegrityLevel
			needed := uint32(20) // SID_AND_ATTRIBUTES + minimal SID
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				// S-1-16-8192 (Medium integrity)
				sidAddr := buf + 12
				mem.Write8(sidAddr, 1)   // Revision
				mem.Write8(sidAddr+1, 1) // nSub = 1
				mem.Write8(sidAddr+2, 0)
				mem.Write8(sidAddr+3, 0)
				mem.Write8(sidAddr+4, 0)
				mem.Write8(sidAddr+5, 0)
				mem.Write8(sidAddr+6, 0)
				mem.Write8(sidAddr+7, 16)    // Authority = 16 (mandatory)
				mem.Write32(sidAddr+8, 8192) // Sub = 0x2000 = medium
				mem.Write64(buf, sidAddr)    // pSid
				mem.Write32(buf+8, 0)        // Attributes
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		default:
			needed := uint32(8)
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= uint64(needed) {
				mem.Write64(buf, 0)
				ctx.SetReturn(1)
				return 0
			}
			ctx.SetReturn(0)
			return 0
		}
	})
	// GetSecurityDescriptorControl: return default control flags
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorControl", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR pSD,
		//   PSECURITY_DESCRIPTOR_CONTROL pControl, LPDWORD lpdwRevision)
		pSd := ctx.Arg(0)
		pControl := ctx.Arg(1)
		pRevision := ctx.Arg(2)
		if pSd != 0 && pControl != 0 {
			ctrl, _ := mem.Read16(pSd + 2)
			mem.Write16(pControl, ctrl)
		} else if pControl != 0 {
			mem.Write16(pControl, 0)
		}
		if pRevision != 0 {
			mem.Write32(pRevision, 1) // SECURITY_DESCRIPTOR_REVISION
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// SetTokenInformation: no-op, always succeed
	d.RegisterAutoStubHandler(advapi32, "SetTokenInformation", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS,
		//   LPVOID TokenInformation, DWORD TokenInformationLength)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// RegNotifyChangeKeyValue: registry change notification - no-op
	d.RegisterAutoStubHandler(advapi32, "RegNotifyChangeKeyValue", func(ctx *ntapi.TrapContext) uint32 {
		// LSTATUS RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree,
		//   DWORD dwNotifyFilter, HANDLE hEvent, BOOL fAsynchronous)
		// ReactOS: NtNotifyChangeKey in ntoskrnl/config/cmapi.c
		// We don't have a filesystem-backed registry, so we accept the request
		// and return success. The event will never be signaled.
		hEvent := ctx.Arg(3)
		if hEvent != 0 {
			ravelog.Logf("[advapi32] RegNotifyChangeKeyValue: event=0x%X (will never signal)\n", hEvent)
		}
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing advapi32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(advapi32, "AbortSystemShutdownA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AbortSystemShutdownA(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AbortSystemShutdownW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AbortSystemShutdownW(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheck", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheck(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckAndAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckAndAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByType", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByType(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeAndAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeAndAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultList", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultList(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmByHandleA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmByHandleA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmByHandleW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmByHandleW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessAllowedObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAccessAllowedObjectAce(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessDeniedAceEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] AddAccessDeniedAceEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessDeniedObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAccessDeniedObjectAce(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessAce(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessAceEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessAceEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessObjectAce(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddUsersToEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] AddUsersToEncryptedFile(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AdjustTokenGroups", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] AdjustTokenGroups(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AllocateLocallyUniqueId", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AllocateLocallyUniqueId(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AreAllAccessesGranted", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] AreAllAccessesGranted(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AreAnyAccessesGranted", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] AreAnyAccessesGranted(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BackupEventLogA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BackupEventLogW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildExplicitAccessWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildExplicitAccessWithNameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildExplicitAccessWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildExplicitAccessWithNameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateExplicitAccessWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildImpersonateExplicitAccessWithNameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateExplicitAccessWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildImpersonateExplicitAccessWithNameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateTrusteeA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildImpersonateTrusteeA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateTrusteeW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildImpersonateTrusteeW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildSecurityDescriptorA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildSecurityDescriptorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithNameA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithNameW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndNameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndNameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndSidA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndSidA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndSidW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndSidW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithSidA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithSidA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithSidW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithSidW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfig2A", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ChangeServiceConfig2A(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfig2W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ChangeServiceConfig2W(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ClearEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ClearEventLogA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ClearEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ClearEventLogW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CloseEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CloseEncryptedFileRaw(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CommandLineFromMsiDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CommandLineFromMsiDescriptor(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] ConvertSecurityDescriptorToStringSecurityDescriptorA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] ConvertSecurityDescriptorToStringSecurityDescriptorW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] ConvertStringSecurityDescriptorToSecurityDescriptorA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] ConvertStringSecurityDescriptorToSecurityDescriptorW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertToAutoInheritPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ConvertToAutoInheritPrivateObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurityEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurityEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurityWithMultipleInheritance", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurityWithMultipleInheritance(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessAsUserA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessAsUserA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessAsUserW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessWithLogonW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessWithLogonW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessWithTokenW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessWithTokenW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateRestrictedToken", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateRestrictedToken(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateTraceInstanceId", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CreateTraceInstanceId(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredDeleteA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredDeleteA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredDeleteW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredDeleteW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredEnumerateA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredEnumerateA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredEnumerateW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredEnumerateW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredFree", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredFree(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredGetSessionTypes", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CredGetSessionTypes(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredIsMarshaledCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredIsMarshaledCredentialA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredIsMarshaledCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredIsMarshaledCredentialW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredMarshalCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredMarshalCredentialA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredMarshalCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredMarshalCredentialW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadDomainCredentialsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadDomainCredentialsA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadDomainCredentialsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadDomainCredentialsW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredUnmarshalCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredUnmarshalCredentialA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredUnmarshalCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CredUnmarshalCredentialW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredWriteA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CredWriteA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredWriteW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CredWriteW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptContextAddRef", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CryptContextAddRef(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDuplicateHash", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptDuplicateHash(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDuplicateKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptDuplicateKey(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProviderTypesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProviderTypesA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProviderTypesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProviderTypesW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProvidersA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProvidersA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProvidersW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProvidersW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetDefaultProviderA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetDefaultProviderA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetDefaultProviderW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetDefaultProviderW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetProvParam", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		dwParam := ctx.Arg(1)
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		dwFlags := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetProvParam prov=0x%x param=%d\n", hProv, dwParam)
		_ = pbData; _ = dwFlags
		if pdwDataLen != 0 { ctx.Mem.Write32(pdwDataLen, 0) }
		ctx.SetReturn(0) // FALSE - param not supported
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetUserKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] CryptGetUserKey(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProvParam", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		dwParam := ctx.Arg(1)
		pbData := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptSetProvParam prov=0x%x param=%d data=0x%x flags=0x%x\n", hProv, dwParam, pbData, dwFlags)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CryptSetProviderA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptSetProviderExA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptSetProviderExW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] CryptSetProviderW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DecryptFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] DecryptFileA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DecryptFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] DecryptFileW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DeleteAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] DeleteAce(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DestroyPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] DestroyPrivateObjectSecurity(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfBackupEventLogFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfBackupEventLogFileA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfBackupEventLogFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfBackupEventLogFileW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfChangeNotify", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfChangeNotify(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfClearEventLogFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfClearEventLogFileA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfClearEventLogFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfClearEventLogFileW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfCloseEventLog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfCloseEventLog(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfDeregisterEventSource", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfDeregisterEventSource(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfFlushEventLog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfFlushEventLog(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfNumberOfRecords", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfNumberOfRecords(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOldestRecord", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfOldestRecord(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenBackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenBackupEventLogA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenBackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenBackupEventLogW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenEventLogA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenEventLogW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReadEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReadEventLogA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReadEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReadEventLogW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfRegisterEventSourceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfRegisterEventSourceA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfRegisterEventSourceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfRegisterEventSourceW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventAndSourceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventAndSourceW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptFileA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] EncryptFileA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptFileW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] EncryptFileW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptionDisable", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] EncryptionDisable(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumDependentServicesA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumDependentServicesA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumDependentServicesW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumDependentServicesW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServiceGroupW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServiceGroupW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EqualDomainSid", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] EqualDomainSid(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FileEncryptionStatusA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] FileEncryptionStatusA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FileEncryptionStatusW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] FileEncryptionStatusW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FindFirstFreeAce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] FindFirstFreeAce(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FreeEncryptionCertificateHashList", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] FreeEncryptionCertificateHashList(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FreeInheritedFromArray", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] FreeInheritedFromArray(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAuditedPermissionsFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetAuditedPermissionsFromAclA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAuditedPermissionsFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetAuditedPermissionsFromAclW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetCurrentHwProfileA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetCurrentHwProfileA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetCurrentHwProfileW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetCurrentHwProfileW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEffectiveRightsFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] GetEffectiveRightsFromAclA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEffectiveRightsFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] GetEffectiveRightsFromAclW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEventLogInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] GetEventLogInformation(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetExplicitEntriesFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] GetExplicitEntriesFromAclA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetExplicitEntriesFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] GetExplicitEntriesFromAclW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetFileSecurityA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] GetFileSecurityA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetFileSecurityW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] GetFileSecurityW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetInheritanceSourceA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] GetInheritanceSourceA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetInheritanceSourceW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] GetInheritanceSourceW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetKernelObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] GetKernelObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeOperationA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeOperationA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeOperationW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeOperationW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetNumberOfEventLogRecords", func(ctx *ntapi.TrapContext) uint32 {
		hEventLog := ctx.Arg(0)
		pnRecords := ctx.Arg(1)
		ravelog.Logf("[advapi32] GetNumberOfEventLogRecords log=0x%x\n", hEventLog)
		if pnRecords != 0 { ctx.Mem.Write32(pnRecords, 0) }
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetOldestEventLogRecord", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] GetOldestEventLogRecord(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] GetPrivateObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorLength", func(ctx *ntapi.TrapContext) uint32 {
		pSD := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetSecurityDescriptorLength pSD=0x%x\n", pSD)
		ctx.SetReturn(40) // minimal absolute SD size
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorRMControl", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] GetSecurityDescriptorRMControl(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorSacl", func(ctx *ntapi.TrapContext) uint32 {
		pSD := ctx.Arg(0)
		lpbSaclPresent := ctx.Arg(1)
		pSacl := ctx.Arg(2)
		lpbSaclDefaulted := ctx.Arg(3)
		ravelog.Logf("[advapi32] GetSecurityDescriptorSacl pSD=0x%x\n", pSD)
		if pSD != 0 {
			ctrl, _ := ctx.Mem.Read16(pSD + 2)
			if lpbSaclPresent != 0 {
				if ctrl&0x0010 != 0 { ctx.Mem.Write32(lpbSaclPresent, 1) } else { ctx.Mem.Write32(lpbSaclPresent, 0) }
			}
			if pSacl != 0 { ctx.Mem.Write64(pSacl, 0) }
			if lpbSaclDefaulted != 0 {
				if ctrl&0x0020 != 0 { ctx.Mem.Write32(lpbSaclDefaulted, 1) } else { ctx.Mem.Write32(lpbSaclDefaulted, 0) }
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] GetSecurityInfoExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] GetSecurityInfoExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceDisplayNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetServiceDisplayNameA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceDisplayNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetServiceDisplayNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceKeyNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetServiceKeyNameA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceKeyNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] GetServiceKeyNameW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSidLengthRequired", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetSidLengthRequired(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceEnableFlags", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceEnableFlags(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceEnableLevel", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceEnableLevel(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceLoggerHandle", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceLoggerHandle(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeFormA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeFormA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeFormW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeFormW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeNameA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeNameW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeTypeA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeTypeA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeTypeW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeTypeW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetWindowsAccountDomainSid", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] GetWindowsAccountDomainSid(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_QueryTagInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] I_QueryTagInformation(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScGetCurrentGroupStateW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScGetCurrentGroupStateW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScIsSecurityProcess", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[advapi32] I_ScIsSecurityProcess()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScPnPGetServiceName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScPnPGetServiceName(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSendPnPMessage", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] I_ScSendPnPMessage(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSetServiceBitsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] I_ScSetServiceBitsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSetServiceBitsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] I_ScSetServiceBitsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScValidatePnpService", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScValidatePnpService(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ImpersonateAnonymousToken", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ImpersonateAnonymousToken 0x%x\n", a0)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ImpersonateNamedPipeClient", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ImpersonateNamedPipeClient 0x%x\n", a0)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] InitiateSystemShutdownA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] InitiateSystemShutdownExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] InitiateSystemShutdownExW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] InitiateSystemShutdownW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "IsValidAcl", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] IsValidAcl(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LockServiceDatabase", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LockServiceDatabase(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LogonUserA", func(ctx *ntapi.TrapContext) uint32 {
		lpUsername := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		var user string
		if lpUsername != 0 { user = readGuestUTF16(lpUsername) }
		ravelog.Logf("[advapi32] LogonUserA user=%q domain=0x%x\n", user, lpDomain)
		_ = lpPassword
		ctx.SetReturn(1) // TRUE - logon always succeeds in emulator
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LogonUserExA", func(ctx *ntapi.TrapContext) uint32 {
		lpUsername := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		var user string
		if lpUsername != 0 { user = readGuestUTF16(lpUsername) }
		ravelog.Logf("[advapi32] LogonUserExA user=%q domain=0x%x\n", user, lpDomain)
		_ = lpPassword
		ctx.SetReturn(1) // TRUE - logon always succeeds in emulator
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LogonUserExW", func(ctx *ntapi.TrapContext) uint32 {
		lpUsername := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		var user string
		if lpUsername != 0 { user = readGuestUTF16(lpUsername) }
		ravelog.Logf("[advapi32] LogonUserExW user=%q domain=0x%x\n", user, lpDomain)
		_ = lpPassword
		ctx.SetReturn(1) // TRUE - logon always succeeds in emulator
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LogonUserW", func(ctx *ntapi.TrapContext) uint32 {
		lpUsername := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		var user string
		if lpUsername != 0 { user = readGuestUTF16(lpUsername) }
		ravelog.Logf("[advapi32] LogonUserW user=%q domain=0x%x\n", user, lpDomain)
		_ = lpPassword
		ctx.SetReturn(1) // TRUE - logon always succeeds in emulator
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupAccountNameA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] LookupAccountNameA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupAccountNameW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] LookupAccountNameW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaAddAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaAddAccountRights(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaAddPrivilegesToAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaAddPrivilegesToAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaClearAuditLog", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaClearAuditLog(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaClose", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaClose(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateAccount(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateSecret", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateSecret(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateTrustedDomain(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateTrustedDomainEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaCreateTrustedDomainEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaDelete", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaDelete(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaDeleteTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaDeleteTrustedDomain(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaEnumerateAccountRights(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccounts", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateAccounts(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccountsWithUserRight", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaEnumerateAccountsWithUserRight(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumeratePrivileges", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumeratePrivileges(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumeratePrivilegesOfAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaEnumeratePrivilegesOfAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateTrustedDomains", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateTrustedDomains(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateTrustedDomainsEx", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateTrustedDomainsEx(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaFreeMemory", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaFreeMemory(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetQuotasForAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetQuotasForAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetRemoteUserName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaGetRemoteUserName(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetSystemAccessAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetSystemAccessAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetUserName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetUserName(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupNames", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaLookupNames(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupNames2", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] LsaLookupNames2(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeDisplayName(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeName(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeValue", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeValue(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupSids", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaLookupSids(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaNtStatusToWinError", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaNtStatusToWinError(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenAccount(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenPolicy(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenPolicySce", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenPolicySce(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenSecret", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenSecret(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenTrustedDomain(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenTrustedDomainByName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenTrustedDomainByName(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryDomainInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryDomainInformationPolicy(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryForestTrustInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryForestTrustInformation(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryInfoTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryInfoTrustedDomain(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryInformationPolicy(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQuerySecret", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaQuerySecret(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQuerySecurityObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQuerySecurityObject(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryTrustedDomainInfo", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaQueryTrustedDomainInfo(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryTrustedDomainInfoByName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaQueryTrustedDomainInfoByName(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRemoveAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaRemoveAccountRights(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRemovePrivilegesFromAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaRemovePrivilegesFromAccount(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRetrievePrivateData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaRetrievePrivateData(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetDomainInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetDomainInformationPolicy(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetForestTrustInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaSetForestTrustInformation(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetInformationPolicy(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetInformationTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetInformationTrustedDomain(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetQuotasForAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaSetQuotasForAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSecret", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetSecret(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSecurityObject", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetSecurityObject(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSystemAccessAccount", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaSetSystemAccessAccount(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetTrustedDomainInfoByName", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaSetTrustedDomainInfoByName(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetTrustedDomainInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaSetTrustedDomainInformation(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaStorePrivateData", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaStorePrivateData(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MakeAbsoluteSD", func(ctx *ntapi.TrapContext) uint32 {
		pSelfRelSD := ctx.Arg(0)
		pAbsSD := ctx.Arg(1)
		// args 2-10: size pointers
		ravelog.Logf("[advapi32] MakeAbsoluteSD self=0x%x abs=0x%x\n", pSelfRelSD, pAbsSD)
		if pAbsSD != 0 {
			ctx.Mem.Write8(pAbsSD, 1) // revision
			ctx.Mem.Write16(pAbsSD+2, 0) // not self-relative
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MakeAbsoluteSD2", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] MakeAbsoluteSD2(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MapGenericMask", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] MapGenericMask(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "NotifyBootConfigStatus", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] NotifyBootConfigStatus(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "NotifyChangeEventLog", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] NotifyChangeEventLog(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectCloseAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectCloseAuditAlarmA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectCloseAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectCloseAuditAlarmW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectDeleteAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectDeleteAuditAlarmA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectDeleteAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectDeleteAuditAlarmW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectOpenAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectOpenAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectOpenAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectOpenAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectPrivilegeAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectPrivilegeAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectPrivilegeAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectPrivilegeAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenBackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] OpenBackupEventLogA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenBackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] OpenBackupEventLogW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenEncryptedFileRawA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] OpenEncryptedFileRawA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenEncryptedFileRawW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] OpenEncryptedFileRawW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenTraceA", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] OpenTraceA(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenTraceW", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] OpenTraceW(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "PrivilegedServiceAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] PrivilegedServiceAuditAlarmA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "PrivilegedServiceAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] PrivilegedServiceAuditAlarmW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ProcessTrace", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] ProcessTrace(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryRecoveryAgentsOnEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] QueryRecoveryAgentsOnEncryptedFile(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfig2A", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] QueryServiceConfig2A(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfig2W", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] QueryServiceConfig2W(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceLockStatusA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] QueryServiceLockStatusA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceLockStatusW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] QueryServiceLockStatusW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] QueryServiceObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceStatusEx", func(ctx *ntapi.TrapContext) uint32 {
		hService := ctx.Arg(0)
		infoLevel := ctx.Arg(1)
		lpBuffer := ctx.Arg(2)
		cbBufSize := ctx.Arg(3)
		pcbBytesNeeded := ctx.Arg(4)
		ravelog.Logf("[advapi32] QueryServiceStatusEx svc=0x%x level=%d buf=0x%x size=%d\n", hService, infoLevel, lpBuffer, cbBufSize)
		needed := uint32(36) // SERVICE_STATUS_PROCESS size
		if pcbBytesNeeded != 0 { ctx.Mem.Write32(pcbBytesNeeded, needed) }
		if cbBufSize < uint64(needed) {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		if lpBuffer != 0 {
			ctx.Mem.Write32(lpBuffer, 0x10) // SERVICE_WIN32_OWN_PROCESS
			ctx.Mem.Write32(lpBuffer+4, 1)  // SERVICE_STOPPED
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryUsersOnEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] QueryUsersOnEncryptedFile(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ReadEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] ReadEncryptedFileRaw(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegConnectRegistryA", func(ctx *ntapi.TrapContext) uint32 {
		lpMachineName := ctx.Arg(0)
		hKey := ctx.Arg(1)
		phkResult := ctx.Arg(2)
		var machine string
		if lpMachineName != 0 { machine = readGuestUTF16(lpMachineName) }
		ravelog.Logf("[advapi32] RegConnectRegistryA machine=%q hkey=0x%x\n", machine, hKey)
		if phkResult != 0 { ctx.Mem.Write64(phkResult, hKey) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegConnectRegistryW", func(ctx *ntapi.TrapContext) uint32 {
		lpMachineName := ctx.Arg(0)
		hKey := ctx.Arg(1)
		phkResult := ctx.Arg(2)
		var machine string
		if lpMachineName != 0 { machine = readGuestUTF16(lpMachineName) }
		ravelog.Logf("[advapi32] RegConnectRegistryW machine=%q hkey=0x%x\n", machine, hKey)
		if phkResult != 0 { ctx.Mem.Write64(phkResult, hKey) }
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegCreateKeyW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] RegCreateKeyW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		samDesired := ctx.Arg(2)
		var sub string
		if lpSubKey != 0 { sub = readGuestUTF16(lpSubKey) }
		ravelog.Logf("[advapi32] RegDeleteKeyExA hkey=0x%x sub=%q sam=0x%x\n", hKey, sub, samDesired)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		samDesired := ctx.Arg(2)
		var sub string
		if lpSubKey != 0 { sub = readGuestUTF16(lpSubKey) }
		ravelog.Logf("[advapi32] RegDeleteKeyExW hkey=0x%x sub=%q sam=0x%x\n", hKey, sub, samDesired)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDisablePredefinedCache", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[advapi32] RegDisablePredefinedCache()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDisableReflectionKey", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegDisableReflectionKey(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnableReflectionKey", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegEnableReflectionKey(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] RegEnumKeyA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] RegEnumKeyExA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		dwIndex := ctx.Arg(1)
		lpName := ctx.Arg(2)
		cchName := ctx.Arg(3)
		ravelog.Logf("[advapi32] RegEnumKeyW hkey=0x%x idx=%d\n", hKey, dwIndex)
		_ = lpName; _ = cchName
		ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] RegEnumValueA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegFlushKey", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegFlushKey(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegGetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		secInfo := ctx.Arg(1)
		pSD := ctx.Arg(2)
		lpcbSD := ctx.Arg(3)
		ravelog.Logf("[advapi32] RegGetKeySecurity hkey=0x%x secInfo=0x%x\n", hKey, secInfo)
		_ = pSD
		if lpcbSD != 0 { ctx.Mem.Write32(lpcbSD, 20) } // SECURITY_DESCRIPTOR_MIN_LENGTH
		ctx.SetReturn(122) // ERROR_INSUFFICIENT_BUFFER
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		lpValue := ctx.Arg(2)
		dwFlags := ctx.Arg(3)
		pdwType := ctx.Arg(4)
		pvData := ctx.Arg(5)
		var sub, val string
		if lpSubKey != 0 { sub = readGuestUTF16(lpSubKey) }
		if lpValue != 0 { val = readGuestUTF16(lpValue) }
		ravelog.Logf("[advapi32] RegGetValueA hkey=0x%x sub=%q val=%q flags=0x%x data=0x%x\n", hKey, sub, val, dwFlags, pvData)
		_ = pdwType
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegLoadKeyA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegLoadKeyW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOpenCurrentUser", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RegOpenCurrentUser(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOpenUserClassesRoot", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] RegOpenUserClassesRoot(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOverridePredefKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RegOverridePredefKey(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		// lpClass(1), lpcchClass(2), reserved(3), lpcSubKeys(4), lpcbMaxSubKeyLen(5)
		// ... lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime
		for _, off := range []int{4, 5} {
			ptr := ctx.Arg(off)
			if ptr != 0 { ctx.Mem.Write32(ptr, 0) }
		}
		// lpcValues
		if p := ctx.Arg(6); p != 0 { ctx.Mem.Write32(p, 0) }
		ravelog.Logf("[advapi32] RegQueryInfoKeyA hkey=0x%x → 0 subkeys/values\n", hKey)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryMultipleValuesA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		val_list := ctx.Arg(1)
		num_vals := ctx.Arg(2)
		lpValueBuf := ctx.Arg(3)
		ldwTotsize := ctx.Arg(4)
		ravelog.Logf("[advapi32] RegQueryMultipleValuesA hkey=0x%x nvals=%d\n", hKey, num_vals)
		_ = val_list; _ = lpValueBuf; _ = ldwTotsize
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryMultipleValuesW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		val_list := ctx.Arg(1)
		num_vals := ctx.Arg(2)
		lpValueBuf := ctx.Arg(3)
		ldwTotsize := ctx.Arg(4)
		ravelog.Logf("[advapi32] RegQueryMultipleValuesW hkey=0x%x nvals=%d\n", hKey, num_vals)
		_ = val_list; _ = lpValueBuf; _ = ldwTotsize
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryReflectionKey", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RegQueryReflectionKey(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryValueW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		lpData := ctx.Arg(2)
		lpcbData := ctx.Arg(3)
		subKey := readGuestUTF16(lpSubKey)
		ravelog.Logf("[advapi32] RegQueryValueW hkey=0x%x sub=%q\n", hKey, subKey)
		if lpcbData != 0 {
			cb, _ := ctx.Mem.Read32(lpcbData)
			if lpData != 0 && cb >= 2 {
				ctx.Mem.Write16(lpData, 0) // empty string
			}
			ctx.Mem.Write32(lpcbData, 2)
		}
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegReplaceKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegReplaceKeyA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegReplaceKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegReplaceKeyW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegRestoreKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegRestoreKeyA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegRestoreKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegRestoreKeyW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSaveKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegSaveKeyA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSaveKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegSaveKeyExA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSaveKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegSaveKeyExW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSaveKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegSaveKeyW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		secInfo := ctx.Arg(1)
		pSD := ctx.Arg(2)
		ravelog.Logf("[advapi32] RegSetKeySecurity hkey=0x%x secInfo=0x%x pSD=0x%x\n", hKey, secInfo, pSD)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] RegSetValueW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegUnLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegUnLoadKeyA hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegUnLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		a1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegUnLoadKeyW hkey=0x%x a1=0x%x\n", hKey, a1)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerA(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerExA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerExA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerExW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerExW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerW(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterTraceGuidsA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] RegisterTraceGuidsA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterTraceGuidsW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] RegisterTraceGuidsW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RemoveUsersFromEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] RemoveUsersFromEncryptedFile(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferCloseLevel", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SaferCloseLevel(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferComputeTokenFromLevel", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] SaferComputeTokenFromLevel(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferCreateLevel", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] SaferCreateLevel(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferGetPolicyInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] SaferGetPolicyInformation(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferIdentifyLevel", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] SaferIdentifyLevel(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferRecordEventLogEntry", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] SaferRecordEventLogEntry(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetAclInformation", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] SetAclInformation(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetEntriesInAclA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] SetEntriesInAclA(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetEntriesInAclW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] SetEntriesInAclW(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetFileSecurityA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] SetFileSecurityA(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetFileSecurityW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] SetFileSecurityW(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetKernelObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] SetKernelObjectSecurity(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)
		ravelog.Logf("[advapi32] SetPrivateObjectSecurity(0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorControl", func(ctx *ntapi.TrapContext) uint32 {
		pSD := ctx.Arg(0)
		ctrlBitsOfInterest := ctx.Arg(1)
		ctrlBitsToSet := ctx.Arg(2)
		ravelog.Logf("[advapi32] SetSecurityDescriptorControl pSD=0x%x mask=0x%x bits=0x%x\n", pSD, ctrlBitsOfInterest, ctrlBitsToSet)
		if pSD != 0 {
			ctrl := func() uint64 { v, _ := ctx.Mem.Read16(pSD + 2); return uint64(v) }()
			ctrl = (ctrl &^ ctrlBitsOfInterest) | (ctrlBitsToSet & ctrlBitsOfInterest)
			ctx.Mem.Write16(pSD+2, uint16(ctrl))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetSecurityDescriptorRMControl", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1 := ctx.Arg(0), ctx.Arg(1)
		ravelog.Logf("[advapi32] SetSecurityDescriptorRMControl(0x%x, 0x%x)\n", a0, a1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetServiceBits", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] SetServiceBits(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetServiceObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] SetServiceObjectSecurity(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetServiceStatus", func(ctx *ntapi.TrapContext) uint32 {
		hServiceStatus := ctx.Arg(0)
		lpServiceStatus := ctx.Arg(1)
		ravelog.Logf("[advapi32] SetServiceStatus handle=0x%x status=0x%x\n", hServiceStatus, lpServiceStatus)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "StartServiceCtrlDispatcherA", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceTable := ctx.Arg(0)
		ravelog.Logf("[advapi32] StartServiceCtrlDispatcherA table=0x%x\n", lpServiceTable)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "StartServiceCtrlDispatcherW", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceTable := ctx.Arg(0)
		ravelog.Logf("[advapi32] StartServiceCtrlDispatcherW table=0x%x\n", lpServiceTable)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction001", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction001(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction002", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction002(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction003", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction003(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction004", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction004(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction005", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction005(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction006", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction006(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction007", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction007(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction008", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction008(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction009", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction009(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction010", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction010(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction011", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction011(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction012", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction012(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction013", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction013(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction014", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction014(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction015", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction015(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction016", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction016(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction017", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction017(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction018", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction018(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction019", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction019(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction020", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction020(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction021", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction021(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction022", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction022(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction023", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction023(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction024", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction024(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction025", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction025(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction026", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction026(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction027", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction027(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction028", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction028(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction029", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction029(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction030", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction030(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction031", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction031(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction032", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction032(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction033", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction033(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction034", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction034(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction035", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction035(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction040", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction040(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction041", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction041(0x%x)\n", a0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TraceEventInstance", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3)
		ravelog.Logf("[advapi32] TraceEventInstance(0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TraceMessage", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[advapi32] TraceMessage()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TraceMessageVa", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[advapi32] TraceMessageVa()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TreeResetNamedSecurityInfoA", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] TreeResetNamedSecurityInfoA(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TreeResetNamedSecurityInfoW", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2, a3, a4, a5 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4), ctx.Arg(5)
		ravelog.Logf("[advapi32] TreeResetNamedSecurityInfoW(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)\n", a0, a1, a2, a3, a4, a5)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "UnlockServiceDatabase", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] UnlockServiceDatabase(0x%x)\n", a0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "UnregisterTraceGuids", func(ctx *ntapi.TrapContext) uint32 {
		a0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] UnregisterTraceGuids(0x%x)\n", a0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "WriteEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		a0, a1, a2 := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
		ravelog.Logf("[advapi32] WriteEncryptedFileRaw(0x%x, 0x%x, 0x%x)\n", a0, a1, a2)
		ctx.SetReturn(0)
		return 0
	})
}
