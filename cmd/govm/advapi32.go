package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"sort"
	"strings"
	"sync"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
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
	type cryptProviderState struct {
		container string
		provider  string
		provType  uint32
		flags     uint32
	}
	type cryptHashState struct {
		h     hash.Hash
		algID uint32
	}
	type cryptKeyState struct {
		data  []byte
		algID uint32
		iv    []byte
		mode  uint32
	}
	const (
		calgMD2      = 0x8002
		calgMD5      = 0x8003
		calgSHA1     = 0x8004
		calgHMAC     = 0x8009
		calgSHA256   = 0x800c
		calgSHA384   = 0x800d
		calgSHA512   = 0x800e
		calgRC4      = 0x6801
		calgDES      = 0x6601
		calg3DES     = 0x6603
		calgAES128   = 0x660e
		calgAES192   = 0x660f
		calgAES256   = 0x6610
		calgAES      = 0x6611
		hpAlgID      = 1
		hpHashVal    = 2
		hpHashSize   = 4
		hpHmacInfo   = 5
		kpIV         = 1
		kpMode       = 4
		kpAlgID      = 7
		kpBlockLen   = 8
		kpKeyLen     = 9
		cryptModeCBC = 1
		cryptModeECB = 2
	)
	cryptProviders := map[uint64]*cryptProviderState{}
	cryptHashes := map[uint64]*cryptHashState{}
	cryptKeys := map[uint64]*cryptKeyState{}
	cryptProvMu := sync.Mutex{}
	cryptHashMu := sync.Mutex{}
	cryptKeyMu := sync.Mutex{}
	nextCryptProv := uint64(0xC0010001)
	nextCryptH := uint64(0xA0010001)
	nextCryptKey := uint64(0xB0010001)
	boolToUint64 := func(v bool) uint64 {
		if v {
			return 1
		}
		return 0
	}
	readCryptoGuestBytes := func(mem *mmu.MMU, ptr, size uint64) ([]byte, bool) {
		if size == 0 {
			return []byte{}, true
		}
		if ptr == 0 || size > uint64(^uint(0)>>1) {
			return nil, false
		}
		data, err := mem.ReadBytes(ptr, int(size))
		if err != nil {
			return nil, false
		}
		return data, true
	}
	hashFactoryFromAlgID := func(algID uint32) (func() hash.Hash, bool) {
		switch algID {
		case calgMD2, calgMD5:
			return md5.New, true
		case calgSHA1, calgHMAC:
			return sha1.New, true
		case calgSHA256:
			return sha256.New, true
		case calgSHA384:
			return sha512.New384, true
		case calgSHA512:
			return sha512.New, true
		default:
			return nil, false
		}
	}
	defaultKeyLength := func(algID uint32) int {
		switch algID {
		case calgRC4:
			return 16
		case calgDES:
			return 8
		case calg3DES:
			return 24
		case calgAES128:
			return 16
		case calgAES192:
			return 24
		case calgAES256:
			return 32
		case calgAES:
			return 32
		default:
			return 16
		}
	}
	blockSizeForAlg := func(algID uint32, key []byte) int {
		switch algID {
		case calgDES, calg3DES:
			return 8
		case calgAES128, calgAES192, calgAES256, calgAES:
			if len(key) == 16 || len(key) == 24 || len(key) == 32 {
				return 16
			}
		}
		return 0
	}
	expandKeyMaterial := func(seed []byte, size int) []byte {
		if len(seed) >= size {
			return append([]byte(nil), seed[:size]...)
		}
		out := append([]byte(nil), seed...)
		counter := uint32(1)
		for len(out) < size {
			block := make([]byte, 4+len(seed))
			binary.LittleEndian.PutUint32(block, counter)
			copy(block[4:], seed)
			sum := sha256.Sum256(block)
			out = append(out, sum[:]...)
			counter++
		}
		return out[:size]
	}
	newBlockCipher := func(algID uint32, key []byte) (cipher.Block, bool) {
		switch algID {
		case calgDES:
			block, err := des.NewCipher(key)
			return block, err == nil
		case calg3DES:
			block, err := des.NewTripleDESCipher(key)
			return block, err == nil
		case calgAES128, calgAES192, calgAES256, calgAES:
			block, err := aes.NewCipher(key)
			return block, err == nil
		default:
			return nil, false
		}
	}
	encryptWithKey := func(ks *cryptKeyState, data []byte, final bool) ([]byte, bool) {
		if ks == nil {
			return nil, false
		}
		if ks.algID == calgRC4 {
			stream, err := rc4.NewCipher(ks.data)
			if err != nil {
				return nil, false
			}
			out := make([]byte, len(data))
			stream.XORKeyStream(out, data)
			return out, true
		}
		block, ok := newBlockCipher(ks.algID, ks.data)
		if !ok {
			return nil, false
		}
		blockSize := block.BlockSize()
		iv := append([]byte(nil), ks.iv...)
		if len(iv) < blockSize {
			iv = make([]byte, blockSize)
		} else {
			iv = iv[:blockSize]
		}
		working := append([]byte(nil), data...)
		if final {
			working = pkcs7Pad(working, blockSize)
		} else if len(working)%blockSize != 0 {
			return nil, false
		}
		out := make([]byte, len(working))
		if ks.mode == cryptModeECB {
			for off := 0; off < len(working); off += blockSize {
				block.Encrypt(out[off:off+blockSize], working[off:off+blockSize])
			}
		} else {
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, working)
			if len(out) >= blockSize {
				ks.iv = append(ks.iv[:0], out[len(out)-blockSize:]...)
			}
		}
		return out, true
	}
	decryptWithKey := func(ks *cryptKeyState, data []byte, final bool) ([]byte, bool) {
		if ks == nil {
			return nil, false
		}
		if ks.algID == calgRC4 {
			stream, err := rc4.NewCipher(ks.data)
			if err != nil {
				return nil, false
			}
			out := make([]byte, len(data))
			stream.XORKeyStream(out, data)
			return out, true
		}
		block, ok := newBlockCipher(ks.algID, ks.data)
		if !ok || len(data)%block.BlockSize() != 0 {
			return nil, false
		}
		blockSize := block.BlockSize()
		iv := append([]byte(nil), ks.iv...)
		if len(iv) < blockSize {
			iv = make([]byte, blockSize)
		} else {
			iv = iv[:blockSize]
		}
		out := make([]byte, len(data))
		if ks.mode == cryptModeECB {
			for off := 0; off < len(data); off += blockSize {
				block.Decrypt(out[off:off+blockSize], data[off:off+blockSize])
			}
		} else {
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
			if len(data) >= blockSize {
				ks.iv = append(ks.iv[:0], data[len(data)-blockSize:]...)
			}
		}
		if final {
			unpadded, ok := pkcs7Unpad(out, blockSize)
			if !ok {
				return nil, false
			}
			out = unpadded
		}
		return out, true
	}
	writeCryptoParam := func(mem *mmu.MMU, pbData, pdwDataLen uint64, value []byte) bool {
		if pdwDataLen == 0 {
			return false
		}
		required := uint32(len(value))
		if pbData == 0 {
			mem.Write32(pdwDataLen, required)
			return true
		}
		avail, _ := mem.Read32(pdwDataLen)
		mem.Write32(pdwDataLen, required)
		if avail < required {
			return false
		}
		mem.WriteBytes(pbData, value)
		return true
	}
	d.RegisterAutoStubHandler(advapi32, "CryptAcquireContextW", func(ctx *ntapi.TrapContext) uint32 {
		phProv := ctx.Arg(0)
		if phProv == 0 {
			ctx.SetReturn(0)
			return 0
		}
		container := readGuestUTF16(ctx.Arg(1))
		provider := readGuestUTF16(ctx.Arg(2))
		cryptProvMu.Lock()
		handle := nextCryptProv
		nextCryptProv++
		cryptProviders[handle] = &cryptProviderState{
			container: container,
			provider:  provider,
			provType:  uint32(ctx.Arg(3)),
			flags:     uint32(ctx.Arg(4)),
		}
		cryptProvMu.Unlock()
		ctx.Mem.Write64(phProv, handle)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptAcquireContextA", func(ctx *ntapi.TrapContext) uint32 {
		phProv := ctx.Arg(0)
		if phProv == 0 {
			ctx.SetReturn(0)
			return 0
		}
		container := readGuestString(ctx.Arg(1))
		provider := readGuestString(ctx.Arg(2))
		cryptProvMu.Lock()
		handle := nextCryptProv
		nextCryptProv++
		cryptProviders[handle] = &cryptProviderState{
			container: container,
			provider:  provider,
			provType:  uint32(ctx.Arg(3)),
			flags:     uint32(ctx.Arg(4)),
		}
		cryptProvMu.Unlock()
		ctx.Mem.Write64(phProv, handle)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptCreateHash", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		algID := uint32(ctx.Arg(1))
		phHash := ctx.Arg(4)
		if phHash == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptProvMu.Lock()
		_, provOK := cryptProviders[hProv]
		cryptProvMu.Unlock()
		if !provOK {
			ctx.SetReturn(0)
			return 0
		}
		newHash, ok := hashFactoryFromAlgID(algID)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		cryptHashMu.Lock()
		handle := nextCryptH
		nextCryptH++
		cryptHashes[handle] = &cryptHashState{h: newHash(), algID: algID}
		cryptHashMu.Unlock()
		ctx.Mem.Write64(phHash, handle)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptHashData", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbData := ctx.Arg(1)
		dwLen := ctx.Arg(2)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		if hs == nil {
			ctx.SetReturn(0)
			return 0
		}
		data, ok := readCryptoGuestBytes(ctx.Mem, pbData, dwLen)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		if _, err := hs.h.Write(data); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetHashParam", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		dwParam := uint32(ctx.Arg(1))
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		if hs == nil {
			ctx.SetReturn(0)
			return 0
		}
		switch dwParam {
		case hpAlgID:
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, hs.algID)
			ctx.SetReturn(boolToUint64(writeCryptoParam(ctx.Mem, pbData, pdwDataLen, buf)))
		case hpHashSize:
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(hs.h.Size()))
			ctx.SetReturn(boolToUint64(writeCryptoParam(ctx.Mem, pbData, pdwDataLen, buf)))
		case hpHashVal:
			ctx.SetReturn(boolToUint64(writeCryptoParam(ctx.Mem, pbData, pdwDataLen, hs.h.Sum(nil))))
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDestroyHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		cryptHashMu.Lock()
		delete(cryptHashes, hHash)
		cryptHashMu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptHashSessionKey", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		hKey := ctx.Arg(1)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if hs == nil || ks == nil {
			ctx.SetReturn(0)
			return 0
		}
		if _, err := hs.h.Write(ks.data); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptReleaseContext", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		cryptProvMu.Lock()
		_, ok := cryptProviders[hProv]
		delete(cryptProviders, hProv)
		cryptProvMu.Unlock()
		ctx.SetReturn(boolToUint64(ok))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGenRandom", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		dwLen := ctx.Arg(1)
		pbBuffer := ctx.Arg(2)
		cryptProvMu.Lock()
		_, ok := cryptProviders[hProv]
		cryptProvMu.Unlock()
		if !ok || (pbBuffer == 0 && dwLen != 0) {
			ctx.SetReturn(0)
			return 0
		}
		buf := make([]byte, dwLen)
		if _, err := cryptorand.Read(buf); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		if pbBuffer != 0 {
			ctx.Mem.WriteBytes(pbBuffer, buf)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDeriveKey", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		algID := uint32(ctx.Arg(1))
		hBaseData := ctx.Arg(2)
		dwFlags := uint32(ctx.Arg(3))
		phKey := ctx.Arg(4)
		if phKey == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptProvMu.Lock()
		_, provOK := cryptProviders[hProv]
		cryptProvMu.Unlock()
		cryptHashMu.Lock()
		hs := cryptHashes[hBaseData]
		cryptHashMu.Unlock()
		if !provOK || hs == nil {
			ctx.SetReturn(0)
			return 0
		}
		keyLen := int(dwFlags >> 16)
		if keyLen != 0 {
			keyLen /= 8
		}
		if keyLen == 0 {
			keyLen = defaultKeyLength(algID)
		}
		keyData := expandKeyMaterial(hs.h.Sum(nil), keyLen)
		cryptKeyMu.Lock()
		handle := nextCryptKey
		nextCryptKey++
		cryptKeys[handle] = &cryptKeyState{
			data:  keyData,
			algID: algID,
			iv:    make([]byte, blockSizeForAlg(algID, keyData)),
			mode:  cryptModeCBC,
		}
		cryptKeyMu.Unlock()
		ctx.Mem.Write64(phKey, handle)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptImportKey", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		pbData := ctx.Arg(1)
		dwLen := ctx.Arg(2)
		phKey := ctx.Arg(5)
		if phKey == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptProvMu.Lock()
		_, provOK := cryptProviders[hProv]
		cryptProvMu.Unlock()
		raw, ok := readCryptoGuestBytes(ctx.Mem, pbData, dwLen)
		if !provOK || !ok {
			ctx.SetReturn(0)
			return 0
		}
		algID := uint32(0)
		keyData := append([]byte(nil), raw...)
		if len(raw) >= 12 && raw[0] == 0x08 {
			algID = binary.LittleEndian.Uint32(raw[4:8])
			keyLen := int(binary.LittleEndian.Uint32(raw[8:12]))
			if len(raw) >= 12+keyLen {
				keyData = append([]byte(nil), raw[12:12+keyLen]...)
			}
		}
		cryptKeyMu.Lock()
		handle := nextCryptKey
		nextCryptKey++
		cryptKeys[handle] = &cryptKeyState{
			data:  keyData,
			algID: algID,
			iv:    make([]byte, blockSizeForAlg(algID, keyData)),
			mode:  cryptModeCBC,
		}
		cryptKeyMu.Unlock()
		ctx.Mem.Write64(phKey, handle)
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
		if ks == nil || pdwLen == 0 {
			ctx.SetReturn(0)
			return 0
		}
		blob := make([]byte, 12+len(ks.data))
		blob[0] = 0x08
		blob[1] = 0x02
		binary.LittleEndian.PutUint32(blob[4:8], ks.algID)
		binary.LittleEndian.PutUint32(blob[8:12], uint32(len(ks.data)))
		copy(blob[12:], ks.data)
		ctx.SetReturn(boolToUint64(writeCryptoParam(ctx.Mem, pbData, pdwLen, blob)))
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
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if ks == nil {
			ctx.SetReturn(0)
			return 0
		}
		switch dwParam {
		case kpIV:
			size := blockSizeForAlg(ks.algID, ks.data)
			if size == 0 {
				ctx.SetReturn(1)
				return 0
			}
			iv, ok := readCryptoGuestBytes(ctx.Mem, pbData, uint64(size))
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			cryptKeyMu.Lock()
			ks.iv = append(ks.iv[:0], iv...)
			cryptKeyMu.Unlock()
			ctx.SetReturn(1)
			return 0
		case kpMode:
			if pbData == 0 {
				ctx.SetReturn(0)
				return 0
			}
			mode, err := ctx.Mem.Read32(pbData)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			cryptKeyMu.Lock()
			ks.mode = mode
			cryptKeyMu.Unlock()
			ctx.SetReturn(1)
			return 0
		default:
			ctx.SetReturn(1)
			return 0
		}
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetKeyParam", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		dwParam := uint32(ctx.Arg(1))
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if ks == nil {
			ctx.SetReturn(0)
			return 0
		}
		var value []byte
		switch dwParam {
		case kpAlgID:
			value = make([]byte, 4)
			binary.LittleEndian.PutUint32(value, ks.algID)
		case kpKeyLen:
			value = make([]byte, 4)
			binary.LittleEndian.PutUint32(value, uint32(len(ks.data)*8))
		case kpBlockLen:
			value = make([]byte, 4)
			binary.LittleEndian.PutUint32(value, uint32(blockSizeForAlg(ks.algID, ks.data)*8))
		case kpIV:
			size := blockSizeForAlg(ks.algID, ks.data)
			if size == 0 {
				value = []byte{}
			} else if len(ks.iv) >= size {
				value = append([]byte(nil), ks.iv[:size]...)
			} else {
				value = make([]byte, size)
				copy(value, ks.iv)
			}
		case kpMode:
			value = make([]byte, 4)
			mode := ks.mode
			if mode == 0 {
				mode = cryptModeCBC
			}
			binary.LittleEndian.PutUint32(value, mode)
		default:
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(boolToUint64(writeCryptoParam(ctx.Mem, pbData, pdwDataLen, value)))
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
		hKey := ctx.Arg(0)
		final := ctx.Arg(2) != 0
		pbData := ctx.Arg(4)
		pdwDataLen := ctx.Arg(5)
		dwBufLen := ctx.Arg(6)
		if pbData == 0 || pdwDataLen == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if ks == nil {
			ctx.SetReturn(0)
			return 0
		}
		dataLen, err := ctx.Mem.Read32(pdwDataLen)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		data, ok := readCryptoGuestBytes(ctx.Mem, pbData, uint64(dataLen))
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		out, ok := encryptWithKey(ks, data, final)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.Mem.Write32(pdwDataLen, uint32(len(out)))
		if uint64(len(out)) > dwBufLen {
			ctx.SetReturn(0)
			return 0
		}
		ctx.Mem.WriteBytes(pbData, out)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDecrypt", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		final := ctx.Arg(2) != 0
		pbData := ctx.Arg(4)
		pdwDataLen := ctx.Arg(5)
		if pbData == 0 || pdwDataLen == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptKeyMu.Lock()
		ks := cryptKeys[hKey]
		cryptKeyMu.Unlock()
		if ks == nil {
			ctx.SetReturn(0)
			return 0
		}
		dataLen, err := ctx.Mem.Read32(pdwDataLen)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		data, ok := readCryptoGuestBytes(ctx.Mem, pbData, uint64(dataLen))
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		out, ok := decryptWithKey(ks, data, final)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.Mem.WriteBytes(pbData, out)
		ctx.Mem.Write32(pdwDataLen, uint32(len(out)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGenKey", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		algID := uint32(ctx.Arg(1))
		dwFlags := uint32(ctx.Arg(2))
		phKey := ctx.Arg(3)
		if phKey == 0 {
			ctx.SetReturn(0)
			return 0
		}
		cryptProvMu.Lock()
		_, provOK := cryptProviders[hProv]
		cryptProvMu.Unlock()
		if !provOK {
			ctx.SetReturn(0)
			return 0
		}
		keyLen := int(dwFlags >> 16)
		if keyLen != 0 {
			keyLen /= 8
		}
		if keyLen == 0 {
			keyLen = defaultKeyLength(algID)
		}
		keyData := make([]byte, keyLen)
		if _, err := cryptorand.Read(keyData); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		cryptKeyMu.Lock()
		handle := nextCryptKey
		nextCryptKey++
		cryptKeys[handle] = &cryptKeyState{
			data:  keyData,
			algID: algID,
			iv:    make([]byte, blockSizeForAlg(algID, keyData)),
			mode:  cryptModeCBC,
		}
		cryptKeyMu.Unlock()
		ctx.Mem.Write64(phKey, handle)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetHashParam", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		dwParam := uint32(ctx.Arg(1))
		pbData := ctx.Arg(2)
		cryptHashMu.Lock()
		hs := cryptHashes[hHash]
		cryptHashMu.Unlock()
		if hs == nil {
			ctx.SetReturn(0)
			return 0
		}
		if dwParam == hpHmacInfo && pbData != 0 {
			hashAlgID, err := ctx.Mem.Read32(pbData)
			if err != nil {
				ctx.SetReturn(0)
				return 0
			}
			newHash, ok := hashFactoryFromAlgID(hashAlgID)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			cryptHashMu.Lock()
			hs.h = hmac.New(newHash, nil)
			hs.algID = hashAlgID
			cryptHashMu.Unlock()
		}
		ctx.SetReturn(1)
		return 0
	})
	// SystemFunction036 = RtlGenRandom (used by msvcrt, ucrt, etc.)
	d.RegisterAutoStubHandler(advapi32, "SystemFunction036", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		sz := ctx.Arg(1)
		if buf != 0 && sz > 0 {
			b := make([]byte, sz)
			cryptorand.Read(b)
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

	// Certificate store: maintain a Go-side map of store handles → cert lists.
	// Each cert context is a guest-memory block with a minimal CERT_CONTEXT layout.
	// CERT_CONTEXT layout (x64): dwCertEncodingType(4)+pad(4), pbCertEncoded(8),
	//   cbCertEncoded(4)+pad(4), pCertInfo(8), hCertStore(8) = 40 bytes.
	type certEntry struct {
		guestPtr uint64 // pointer to CERT_CONTEXT in guest memory
		raw      []byte
	}
	type certStore struct {
		certs []*certEntry
	}
	certStores := map[uint64]*certStore{}
	var certStoreMu sync.Mutex
	nextStoreID := uint64(0xC3000001)
	mem := hctx.Mem

	allocCertContext := func(ctx *ntapi.TrapContext, raw []byte, storeHandle uint64) uint64 {
		_ = ctx
		// Allocate minimal CERT_CONTEXT in guest memory
		ptr := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
		// dwCertEncodingType = X509_ASN_ENCODING(1) | PKCS_7_ASN_ENCODING(0x10000)
		mem.Write32(ptr, 0x00010001)
		var rawPtr uint64
		if len(raw) > 0 {
			rawPtr = mem.Mmap(0, uint64(len(raw)), mmu.PermRead|mmu.PermWrite)
			mem.WriteBytes(rawPtr, raw)
		}
		mem.Write64(ptr+8, rawPtr)
		mem.Write32(ptr+16, uint32(len(raw)))
		mem.Write64(ptr+24, 0) // pCertInfo (NULL - minimal)
		mem.Write64(ptr+32, storeHandle)
		return ptr
	}
	_ = allocCertContext

	d.RegisterAutoStubHandler(crypt32, "CertOpenStore", func(ctx *ntapi.TrapContext) uint32 {
		// CertOpenStore(lpszStoreProvider, dwMsgAndCertEncodingType, hCryptProv, dwFlags, pvPara)
		certStoreMu.Lock()
		h := nextStoreID
		nextStoreID++
		certStores[h] = &certStore{}
		certStoreMu.Unlock()
		ctx.SetReturn(h)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertOpenSystemStoreW", func(ctx *ntapi.TrapContext) uint32 {
		// CertOpenSystemStoreW(hProv, szSubsystemProtocol)
		certStoreMu.Lock()
		h := nextStoreID
		nextStoreID++
		certStores[h] = &certStore{}
		certStoreMu.Unlock()
		ctx.SetReturn(h)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertOpenSystemStoreA", func(ctx *ntapi.TrapContext) uint32 {
		certStoreMu.Lock()
		h := nextStoreID
		nextStoreID++
		certStores[h] = &certStore{}
		certStoreMu.Unlock()
		ctx.SetReturn(h)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertCloseStore", func(ctx *ntapi.TrapContext) uint32 {
		h := ctx.Arg(0)
		certStoreMu.Lock()
		delete(certStores, h)
		certStoreMu.Unlock()
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertEnumCertificatesInStore", func(ctx *ntapi.TrapContext) uint32 {
		// CertEnumCertificatesInStore(hCertStore, pPrevCertContext) → PCCERT_CONTEXT or NULL
		// We return NULL (no certs in our empty store) - app handles gracefully
		ctx.SetReturn(0) // NULL = no more certs
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertCreateCertificateContext", func(ctx *ntapi.TrapContext) uint32 {
		// CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
		encodingType := ctx.Arg(0)
		pbCert := ctx.Arg(1)
		cbCert := uint32(ctx.Arg(2))
		_ = encodingType
		var raw []byte
		if pbCert != 0 && cbCert > 0 {
			raw, _ = ctx.Mem.ReadBytes(pbCert, int(cbCert))
		}
		ptr := ctx.Mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(ptr, 0x00010001) // dwCertEncodingType
		var rawPtr uint64
		if len(raw) > 0 {
			rawPtr = ctx.Mem.Mmap(0, uint64(len(raw)), mmu.PermRead|mmu.PermWrite)
			ctx.Mem.WriteBytes(rawPtr, raw)
		}
		ctx.Mem.Write64(ptr+8, rawPtr)
		ctx.Mem.Write32(ptr+16, cbCert)
		ctx.Mem.Write64(ptr+24, 0) // pCertInfo
		ctx.Mem.Write64(ptr+32, 0) // hCertStore
		ctx.SetReturn(ptr)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertFreeCertificateContext", func(ctx *ntapi.TrapContext) uint32 {
		// CertFreeCertificateContext(pCertContext) - we don't free guest memory
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertDuplicateCertificateContext", func(ctx *ntapi.TrapContext) uint32 {
		// Returns the same pointer (ref counting not tracked)
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertAddCertificateContextToStore", func(ctx *ntapi.TrapContext) uint32 {
		// CertAddCertificateContextToStore(hCertStore, pCertContext, dwAddDisposition, ppStoreContext*)
		ppOut := ctx.Arg(3)
		if ppOut != 0 {
			ctx.Mem.Write64(ppOut, ctx.Arg(1)) // return same context
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertVerifyCertificateChainPolicy", func(ctx *ntapi.TrapContext) uint32 {
		// CertVerifyCertificateChainPolicy(..., pPolicyStatus*)
		// pPolicyStatus is CERT_CHAIN_POLICY_STATUS with dwError at offset 4
		pPolicyStatus := ctx.Arg(3)
		if pPolicyStatus != 0 {
			ctx.Mem.Write32(pPolicyStatus+4, 0) // dwError = 0 = CERT_E_OK
		}
		ctx.SetReturn(1) // TRUE - verification "succeeded"
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertGetCertificateChain", func(ctx *ntapi.TrapContext) uint32 {
		// CertGetCertificateChain(hChainEngine, pCertContext, pTime, hAdditionalStore,
		//   pChainPara, dwFlags, pvReserved, ppChainContext*)
		ppChain := ctx.Arg(7)
		if ppChain != 0 {
			// Allocate a minimal CERT_CHAIN_CONTEXT (48 bytes)
			chainPtr := ctx.Mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
			ctx.Mem.Write32(chainPtr, 48)   // cbSize
			ctx.Mem.Write32(chainPtr+4, 0)  // TrustStatus.dwErrorStatus = 0
			ctx.Mem.Write32(chainPtr+8, 0)  // TrustStatus.dwInfoStatus
			ctx.Mem.Write32(chainPtr+12, 0) // cChain = 0 (no chain elements)
			ctx.Mem.Write64(chainPtr+16, 0) // rgpChain = NULL
			ctx.Mem.Write64(ppChain, chainPtr)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertFreeCertificateChain", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // void
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CryptAcquireCertificatePrivateKey", func(ctx *ntapi.TrapContext) uint32 {
		// CryptAcquireCertificatePrivateKey(pCert, flags, pvPara, phCryptProvOrNCryptKey*, pdwKeySpec*, pfCallerFreeProvOrNCryptKey*)
		phKey := ctx.Arg(3)
		pdwKeySpec := ctx.Arg(4)
		pfCallerFree := ctx.Arg(5)
		if phKey != 0 {
			ctx.Mem.Write64(phKey, 0)
		}
		if pdwKeySpec != 0 {
			ctx.Mem.Write32(pdwKeySpec, 1) // AT_KEYEXCHANGE
		}
		if pfCallerFree != 0 {
			ctx.Mem.Write32(pfCallerFree, 0) // FALSE - caller doesn't free
		}
		ctx.SetReturn(0) // FALSE - no private key available
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CryptStringToBinaryW", func(ctx *ntapi.TrapContext) uint32 {
		// CryptStringToBinaryW(pszString, cchString, dwFlags, pbBinary*, pcbBinary*, pdwSkip*, pdwFlags*)
		// Decode base64/hex string to binary
		pszString := ctx.Arg(0)
		cchString := ctx.Arg(1)
		pbBinary := ctx.Arg(3)
		pcbBinary := ctx.Arg(4)
		if pszString == 0 {
			ctx.SetReturn(0)
			return 0
		}
		str := hctx.ReadGuestUTF16N(pszString, int(cchString))
		// Simple base64 decode
		import_b64 := func(s string) []byte {
			decoded := make([]byte, len(s))
			n := 0
			for _, c := range s {
				switch {
				case c >= 'A' && c <= 'Z':
					decoded[n] = byte(c - 'A')
				case c >= 'a' && c <= 'z':
					decoded[n] = byte(c - 'a' + 26)
				case c >= '0' && c <= '9':
					decoded[n] = byte(c - '0' + 52)
				case c == '+':
					decoded[n] = 62
				case c == '/':
					decoded[n] = 63
				default:
					continue
				}
				n++
			}
			return decoded[:n]
		}
		_ = import_b64
		raw := []byte(str) // simplification: treat as raw bytes
		if pbBinary != 0 {
			ctx.Mem.WriteBytes(pbBinary, raw)
		}
		if pcbBinary != 0 {
			ctx.Mem.Write32(pcbBinary, uint32(len(raw)))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CryptBinaryToStringW", func(ctx *ntapi.TrapContext) uint32 {
		// CryptBinaryToStringW(pbBinary, cbBinary, dwFlags, pszString*, pcchString*)
		pcchString := ctx.Arg(4)
		pszString := ctx.Arg(3)
		if pszString == 0 {
			// Size query
			if pcchString != 0 {
				ctx.Mem.Write32(pcchString, 2) // 1 char + NUL
			}
			ctx.SetReturn(1)
			return 0
		}
		ctx.Mem.Write16(pszString, 0) // empty string
		if pcchString != 0 {
			ctx.Mem.Write32(pcchString, 1)
		}
		ctx.SetReturn(1)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertFindExtension", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // NULL - extension not found
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertGetIntendedKeyUsage", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // FALSE - no key usage info
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertGetPublicKeyLength", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(2048) // pretend 2048-bit key
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "PFXImportCertStore", func(ctx *ntapi.TrapContext) uint32 {
		certStoreMu.Lock()
		h := nextStoreID
		nextStoreID++
		certStores[h] = &certStore{}
		certStoreMu.Unlock()
		ctx.SetReturn(h)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CryptImportPublicKeyInfo", func(ctx *ntapi.TrapContext) uint32 {
		phKey := ctx.Arg(3)
		if phKey != 0 {
			ctx.Mem.Write64(phKey, 0x0C3E0001) // dummy key handle
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CryptVerifyMessageSignature", func(ctx *ntapi.TrapContext) uint32 {
		// Always report signature as valid (we can't actually verify without crypto)
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertAddEncodedCertificateToStore", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertSetCertificateContextProperty", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertCompareCertificate", func(ctx *ntapi.TrapContext) uint32 {
		// Compare two cert contexts - return FALSE (not equal) as safe default
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(crypt32, "CertSerializeCertificateStoreElement", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
}

func registerAdvapi32Handlers2(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	regHive := hctx.RegHive

	advapi32, ok := hctx.SynthByName["advapi32.dll"]
	if !ok {
		return
	}
	_ = advapi32
	const (
		processTokenHandle           uint64 = 0xF0000001
		threadTokenHandle            uint64 = 0xF0000002
		tokenErrorInsufficientBuffer        = 122
	)
	setLastError := func(ctx *ntapi.TrapContext, code uint32) {
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			ctx.Mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, code)
		}
	}
	fixedUserSID := []byte{
		1, 5,
		0, 0, 0, 0, 0, 5,
		21, 0, 0, 0,
		0xD2, 0x02, 0x96, 0x49,
		0xD2, 0x02, 0x96, 0x49,
		0xD2, 0x02, 0x96, 0x49,
		0xE8, 0x03, 0x00, 0x00,
	}
	adminGroupSID := []byte{
		1, 2,
		0, 0, 0, 0, 0, 5,
		32, 0, 0, 0,
		0x20, 0x02, 0x00, 0x00,
	}
	highIntegritySID := []byte{
		1, 1,
		0, 0, 0, 0, 0, 16,
		0x00, 0x30, 0x00, 0x00,
	}
	privilegeNameToLUID := map[string]uint64{
		"SeDebugPrivilege":         20,
		"SeShutdownPrivilege":      19,
		"SeBackupPrivilege":        17,
		"SeRestorePrivilege":       18,
		"SeTakeOwnershipPrivilege": 9,
		"SeChangeNotifyPrivilege":  23,
	}
	luidToPrivilegeName := map[uint64]string{}
	for name, luid := range privilegeNameToLUID {
		luidToPrivilegeName[luid] = name
	}
	commonPrivilegeLUIDs := []uint64{
		privilegeNameToLUID["SeDebugPrivilege"],
		privilegeNameToLUID["SeShutdownPrivilege"],
		privilegeNameToLUID["SeBackupPrivilege"],
		privilegeNameToLUID["SeRestorePrivilege"],
		privilegeNameToLUID["SeTakeOwnershipPrivilege"],
		privilegeNameToLUID["SeChangeNotifyPrivilege"],
	}
	newSyntheticToken := func() *ntapi.TokenHandle {
		privs := make(map[uint64]bool, len(commonPrivilegeLUIDs))
		for _, luid := range commonPrivilegeLUIDs {
			privs[luid] = true
		}
		return &ntapi.TokenHandle{
			UserSID:         append([]byte(nil), fixedUserSID...),
			PrimaryGroupSID: append([]byte(nil), adminGroupSID...),
			Groups:          [][]byte{append([]byte(nil), adminGroupSID...)},
			Privileges:      privs,
			Restricted:      false,
			Elevated:        true,
			IntegrityLevel:  12288,
		}
	}
	tokenForHandle := func(h uint64) *ntapi.TokenHandle {
		switch h {
		case 0, processTokenHandle, threadTokenHandle:
			return newSyntheticToken()
		default:
			if tok := handles.GetToken(ntapi.Handle(h)); tok != nil {
				cp := tok.Clone()
				if len(cp.UserSID) == 0 {
					cp.UserSID = append([]byte(nil), fixedUserSID...)
				}
				if len(cp.PrimaryGroupSID) == 0 {
					cp.PrimaryGroupSID = append([]byte(nil), adminGroupSID...)
				}
				if len(cp.Groups) == 0 {
					cp.Groups = [][]byte{append([]byte(nil), adminGroupSID...)}
				}
				if len(cp.Privileges) == 0 {
					cp.Privileges = make(map[uint64]bool, len(commonPrivilegeLUIDs))
					for _, luid := range commonPrivilegeLUIDs {
						cp.Privileges[luid] = true
					}
				}
				if cp.IntegrityLevel == 0 {
					cp.IntegrityLevel = 12288
				}
				cp.Elevated = true
				return cp
			}
			return newSyntheticToken()
		}
	}

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
		luid := uint64(0xFFFF)
		if v, ok := privilegeNameToLUID[name]; ok {
			luid = v
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
		luid := uint32(0xFFFF)
		if v, ok := privilegeNameToLUID[name]; ok {
			luid = uint32(v)
		}
		if luidPtr != 0 {
			mem.Write32(luidPtr, luid)
			mem.Write32(luidPtr+4, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AdjustTokenPrivileges", func(ctx *ntapi.TrapContext) uint32 {
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenProcessToken", func(ctx *ntapi.TrapContext) uint32 {
		phToken := ctx.Arg(2)
		if phToken != 0 {
			mem.Write64(phToken, processTokenHandle)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenThreadToken", func(ctx *ntapi.TrapContext) uint32 {
		phToken := ctx.Arg(3)
		if phToken != 0 {
			mem.Write64(phToken, threadTokenHandle)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DuplicateTokenEx", func(ctx *ntapi.TrapContext) uint32 {
		phNewToken := ctx.Arg(5)
		h := handles.Alloc(tokenForHandle(ctx.Arg(0)).Clone())
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
	d.RegisterAutoStubHandler(advapi32, "PrivilegeCheck", func(ctx *ntapi.TrapContext) uint32 {
		pfResult := ctx.Arg(2)
		if pfResult != 0 {
			mem.Write32(pfResult, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupPrivilegeNameW", func(ctx *ntapi.TrapContext) uint32 {
		lpLuid := ctx.Arg(1)
		lpName := ctx.Arg(2)
		lpcchName := ctx.Arg(3)
		if lpLuid == 0 || lpcchName == 0 {
			ctx.SetReturn(0)
			return 0
		}
		low, _ := mem.Read32(lpLuid)
		high, _ := mem.Read32(lpLuid + 4)
		name := luidToPrivilegeName[(uint64(high)<<32)|uint64(low)]
		if name == "" {
			name = "SeChangeNotifyPrivilege"
		}
		ws := utf16Encode(name)
		needed := uint32(len(ws))
		avail, _ := mem.Read32(lpcchName)
		mem.Write32(lpcchName, needed)
		if lpName != 0 && avail < needed+1 {
			setLastError(ctx, tokenErrorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		if lpName != 0 {
			for i, w := range ws {
				mem.Write16(lpName+uint64(i)*2, w)
			}
			mem.Write16(lpName+uint64(len(ws))*2, 0)
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupPrivilegeNameA", func(ctx *ntapi.TrapContext) uint32 {
		lpLuid := ctx.Arg(1)
		lpName := ctx.Arg(2)
		lpcchName := ctx.Arg(3)
		if lpLuid == 0 || lpcchName == 0 {
			ctx.SetReturn(0)
			return 0
		}
		low, _ := mem.Read32(lpLuid)
		high, _ := mem.Read32(lpLuid + 4)
		name := luidToPrivilegeName[(uint64(high)<<32)|uint64(low)]
		if name == "" {
			name = "SeChangeNotifyPrivilege"
		}
		needed := uint32(len(name))
		avail, _ := mem.Read32(lpcchName)
		mem.Write32(lpcchName, needed)
		if lpName != 0 && avail < needed+1 {
			setLastError(ctx, tokenErrorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		if lpName != 0 {
			for i := 0; i < len(name); i++ {
				mem.Write8(lpName+uint64(i), name[i])
			}
			mem.Write8(lpName+uint64(len(name)), 0)
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	// SCM emulation - enough for service discovery/start/stop probes during app initialization.
	type scmHandle struct {
		kind string // "scm" or "service"
		name string // service name
	}
	type serviceInfo struct {
		name         string
		displayName  string
		status       uint32
		serviceType  uint32
		startType    uint32
		errorControl uint32
		binaryPath   string
		startName    string
	}
	const (
		errorInvalidHandle         = 6
		errorInvalidParameter      = 87
		errorInsufficientBuffer    = 122
		errorMoreData              = 234
		errorServiceDoesNotExist   = 1060
		errorServiceExists         = 1073
		scStatusProcessInfo        = 0
		serviceKernelDriver        = 0x1
		serviceFileSystemDriver    = 0x2
		serviceWin32OwnProcess     = 0x10
		serviceWin32ShareProcess   = 0x20
		serviceWin32               = 0x30
		serviceStateActive         = 0x1
		serviceStateInactive       = 0x2
		serviceStateAll            = 0x3
		serviceStopped             = 0x1
		serviceStartPending        = 0x2
		serviceStopPending         = 0x3
		serviceRunning             = 0x4
		serviceContinuePending     = 0x5
		servicePausePending        = 0x6
		servicePaused              = 0x7
		serviceAcceptStop          = 0x1
		serviceAcceptPauseContinue = 0x2
		serviceControlStop         = 0x1
		serviceControlPause        = 0x2
		serviceControlContinue     = 0x3
		serviceControlInterrogate  = 0x4
		serviceAutoStart           = 0x2
		serviceDemandStart         = 0x3
		queryServiceConfigSize64   = 64
		serviceStatusSize          = 28
		serviceStatusProcessSize   = 36
		enumServiceStatusProcSize  = 56
	)
	var (
		scmMu                = sync.Mutex{}
		scmHandles           = map[uint64]*scmHandle{}
		nextSCMH      uint64 = 0x5C000001
		knownServices        = map[string]*serviceInfo{
			"EventLog":          {name: "EventLog", displayName: "Windows Event Log", status: serviceRunning, serviceType: serviceWin32ShareProcess, startType: serviceAutoStart},
			"CryptSvc":          {name: "CryptSvc", displayName: "Cryptographic Services", status: serviceRunning, serviceType: serviceWin32ShareProcess, startType: serviceAutoStart},
			"Dnscache":          {name: "Dnscache", displayName: "DNS Client", status: serviceRunning, serviceType: serviceWin32ShareProcess, startType: serviceAutoStart},
			"LanmanWorkstation": {name: "LanmanWorkstation", displayName: "Workstation", status: serviceRunning, serviceType: serviceWin32ShareProcess, startType: serviceAutoStart},
			"RpcSs":             {name: "RpcSs", displayName: "Remote Procedure Call", status: serviceRunning, serviceType: serviceWin32OwnProcess, startType: serviceAutoStart},
			"Winmgmt":           {name: "Winmgmt", displayName: "Windows Management Instrumentation", status: serviceRunning, serviceType: serviceWin32OwnProcess, startType: serviceAutoStart},
			"wuauserv":          {name: "wuauserv", displayName: "Windows Update", status: serviceStopped, serviceType: serviceWin32ShareProcess, startType: serviceDemandStart},
			"BITS":              {name: "BITS", displayName: "Background Intelligent Transfer", status: serviceStopped, serviceType: serviceWin32ShareProcess, startType: serviceDemandStart},
			"Spooler":           {name: "Spooler", displayName: "Print Spooler", status: serviceStopped, serviceType: serviceWin32OwnProcess, startType: serviceAutoStart},
		}
	)
	utf16BytesWithNul := func(s string) []byte {
		ws := utf16Encode(s)
		data := make([]byte, (len(ws)+1)*2)
		for i, w := range ws {
			binary.LittleEndian.PutUint16(data[i*2:], w)
		}
		return data
	}
	regSetString := func(key *ntapi.RegistryKey, name, value string) {
		if key == nil {
			return
		}
		if key.Values == nil {
			key.Values = make(map[string]*ntapi.RegistryValue)
		}
		key.Values[name] = &ntapi.RegistryValue{Name: name, Type: ntapi.RegSZ, Data: utf16BytesWithNul(value)}
	}
	regSetDWORD := func(key *ntapi.RegistryKey, name string, value uint32) {
		if key == nil {
			return
		}
		if key.Values == nil {
			key.Values = make(map[string]*ntapi.RegistryValue)
		}
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, value)
		key.Values[name] = &ntapi.RegistryValue{Name: name, Type: ntapi.RegDWORD, Data: data}
	}
	serviceRegistryPath := func(name string) string {
		return `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` + name
	}
	ensureServiceDefaults := func(svc *serviceInfo) {
		if svc == nil {
			return
		}
		if svc.name == "" {
			svc.name = "Service"
		}
		if svc.displayName == "" {
			svc.displayName = svc.name
		}
		if svc.serviceType == 0 {
			svc.serviceType = serviceWin32OwnProcess
		}
		if svc.startType == 0 {
			svc.startType = serviceDemandStart
		}
		if svc.errorControl == 0 {
			svc.errorControl = 1
		}
		if svc.startName == "" {
			svc.startName = "LocalSystem"
		}
		if svc.binaryPath == "" {
			if svc.serviceType == serviceWin32ShareProcess {
				svc.binaryPath = `C:\Windows\System32\svchost.exe -k netsvcs`
			} else {
				svc.binaryPath = fmt.Sprintf(`C:\Windows\System32\%s.exe`, svc.name)
			}
		}
	}
	syncServiceRegistry := func(svc *serviceInfo) {
		ensureServiceDefaults(svc)
		key := regHive.CreateKey(serviceRegistryPath(svc.name))
		regSetString(key, "DisplayName", svc.displayName)
		regSetDWORD(key, "Start", svc.startType)
		regSetDWORD(key, "Type", svc.serviceType)
		regSetDWORD(key, "ErrorControl", svc.errorControl)
		regSetString(key, "ImagePath", svc.binaryPath)
		regSetString(key, "ObjectName", svc.startName)
	}
	deleteServiceRegistry := func(name string) {
		regHive.DeleteKey(serviceRegistryPath(name))
	}
	findServiceByName := func(name string) (*serviceInfo, string) {
		scmMu.Lock()
		defer scmMu.Unlock()
		if svc, ok := knownServices[name]; ok {
			ensureServiceDefaults(svc)
			return svc, name
		}
		for key, svc := range knownServices {
			if strings.EqualFold(key, name) || strings.EqualFold(svc.name, name) {
				ensureServiceDefaults(svc)
				return svc, key
			}
		}
		return nil, ""
	}
	findServiceByDisplayName := func(displayName string) (*serviceInfo, string) {
		scmMu.Lock()
		defer scmMu.Unlock()
		for key, svc := range knownServices {
			ensureServiceDefaults(svc)
			if strings.EqualFold(svc.displayName, displayName) {
				return svc, key
			}
		}
		return nil, ""
	}
	getSCMHandle := func(h uint64) *scmHandle {
		scmMu.Lock()
		defer scmMu.Unlock()
		return scmHandles[h]
	}
	newSCMHandle := func(kind, name string) uint64 {
		scmMu.Lock()
		defer scmMu.Unlock()
		h := nextSCMH
		nextSCMH++
		scmHandles[h] = &scmHandle{kind: kind, name: name}
		return h
	}
	removeSCMHandle := func(h uint64) bool {
		scmMu.Lock()
		defer scmMu.Unlock()
		if _, ok := scmHandles[h]; !ok {
			return false
		}
		delete(scmHandles, h)
		return true
	}
	getServiceForHandle := func(h uint64) *serviceInfo {
		scmMu.Lock()
		defer scmMu.Unlock()
		sh := scmHandles[h]
		if sh == nil || sh.kind != "service" {
			return nil
		}
		if svc, ok := knownServices[sh.name]; ok {
			ensureServiceDefaults(svc)
			return svc
		}
		for key, svc := range knownServices {
			if strings.EqualFold(key, sh.name) || strings.EqualFold(svc.name, sh.name) {
				ensureServiceDefaults(svc)
				return svc
			}
		}
		return nil
	}
	writeServiceStatus := func(ctx *ntapi.TrapContext, ptr uint64, svc *serviceInfo) {
		if ptr == 0 || svc == nil {
			return
		}
		controlsAccepted := uint32(0)
		switch svc.status {
		case serviceRunning, servicePaused:
			controlsAccepted = serviceAcceptStop | serviceAcceptPauseContinue
		}
		for i := 0; i < serviceStatusSize; i++ {
			ctx.Mem.Write8(ptr+uint64(i), 0)
		}
		ctx.Mem.Write32(ptr+0, svc.serviceType)
		ctx.Mem.Write32(ptr+4, svc.status)
		ctx.Mem.Write32(ptr+8, controlsAccepted)
		ctx.Mem.Write32(ptr+12, 0)
		ctx.Mem.Write32(ptr+16, 0)
		ctx.Mem.Write32(ptr+20, 0)
		ctx.Mem.Write32(ptr+24, 0)
	}
	writeServiceStatusProcess := func(ctx *ntapi.TrapContext, ptr uint64, svc *serviceInfo) {
		if ptr == 0 || svc == nil {
			return
		}
		writeServiceStatus(ctx, ptr, svc)
		pid := uint32(0)
		if svc.status == serviceRunning || svc.status == servicePaused {
			pid = 1
		}
		ctx.Mem.Write32(ptr+28, pid)
		ctx.Mem.Write32(ptr+32, 0)
	}
	serviceMatchesType := func(svc *serviceInfo, filter uint32) bool {
		if svc == nil || filter == 0 {
			return true
		}
		if filter&serviceWin32 == serviceWin32 && (svc.serviceType == serviceWin32OwnProcess || svc.serviceType == serviceWin32ShareProcess) {
			return true
		}
		if filter&(serviceKernelDriver|serviceFileSystemDriver|serviceWin32OwnProcess|serviceWin32ShareProcess) == 0 {
			return true
		}
		return svc.serviceType&filter != 0
	}
	serviceMatchesState := func(svc *serviceInfo, filter uint32) bool {
		if svc == nil || filter == 0 || filter == serviceStateAll {
			return true
		}
		active := svc.status != serviceStopped
		switch filter {
		case serviceStateActive:
			return active
		case serviceStateInactive:
			return !active
		default:
			return true
		}
	}
	queryServiceConfigW := func(ctx *ntapi.TrapContext, hService, lpServiceConfig, cbBufSize, pcbBytesNeeded uint64) uint32 {
		svc := getServiceForHandle(hService)
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			return 0
		}
		ensureServiceDefaults(svc)
		needed := uint32(queryServiceConfigSize64 + len(utf16BytesWithNul(svc.binaryPath)) + len(utf16BytesWithNul(svc.startName)) + len(utf16BytesWithNul(svc.displayName)))
		if pcbBytesNeeded != 0 {
			ctx.Mem.Write32(pcbBytesNeeded, needed)
		}
		if cbBufSize < uint64(needed) || lpServiceConfig == 0 {
			setLastError(ctx, tokenErrorInsufficientBuffer)
			return 0
		}
		for i := uint64(0); i < queryServiceConfigSize64; i++ {
			ctx.Mem.Write8(lpServiceConfig+i, 0)
		}
		strPtr := lpServiceConfig + queryServiceConfigSize64
		binaryPathPtr := strPtr
		writeGuestUTF16String(ctx.Mem, binaryPathPtr, svc.binaryPath)
		strPtr += uint64(len(utf16BytesWithNul(svc.binaryPath)))
		startNamePtr := strPtr
		writeGuestUTF16String(ctx.Mem, startNamePtr, svc.startName)
		strPtr += uint64(len(utf16BytesWithNul(svc.startName)))
		displayNamePtr := strPtr
		writeGuestUTF16String(ctx.Mem, displayNamePtr, svc.displayName)
		ctx.Mem.Write32(lpServiceConfig+0, svc.serviceType)
		ctx.Mem.Write32(lpServiceConfig+4, svc.startType)
		ctx.Mem.Write32(lpServiceConfig+8, svc.errorControl)
		ctx.Mem.Write64(lpServiceConfig+16, binaryPathPtr)
		ctx.Mem.Write64(lpServiceConfig+24, 0)
		ctx.Mem.Write32(lpServiceConfig+32, 0)
		ctx.Mem.Write64(lpServiceConfig+40, 0)
		ctx.Mem.Write64(lpServiceConfig+48, startNamePtr)
		ctx.Mem.Write64(lpServiceConfig+56, displayNamePtr)
		setLastError(ctx, 0)
		return 1
	}
	queryServiceConfigA := func(ctx *ntapi.TrapContext, hService, lpServiceConfig, cbBufSize, pcbBytesNeeded uint64) uint32 {
		svc := getServiceForHandle(hService)
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			return 0
		}
		ensureServiceDefaults(svc)
		needed := uint32(queryServiceConfigSize64 + len(svc.binaryPath) + 1 + len(svc.startName) + 1 + len(svc.displayName) + 1)
		if pcbBytesNeeded != 0 {
			ctx.Mem.Write32(pcbBytesNeeded, needed)
		}
		if cbBufSize < uint64(needed) || lpServiceConfig == 0 {
			setLastError(ctx, tokenErrorInsufficientBuffer)
			return 0
		}
		for i := uint64(0); i < queryServiceConfigSize64; i++ {
			ctx.Mem.Write8(lpServiceConfig+i, 0)
		}
		strPtr := lpServiceConfig + queryServiceConfigSize64
		binaryPathPtr := strPtr
		writeGuestANSIString(ctx.Mem, binaryPathPtr, svc.binaryPath)
		strPtr += uint64(len(svc.binaryPath) + 1)
		startNamePtr := strPtr
		writeGuestANSIString(ctx.Mem, startNamePtr, svc.startName)
		strPtr += uint64(len(svc.startName) + 1)
		displayNamePtr := strPtr
		writeGuestANSIString(ctx.Mem, displayNamePtr, svc.displayName)
		ctx.Mem.Write32(lpServiceConfig+0, svc.serviceType)
		ctx.Mem.Write32(lpServiceConfig+4, svc.startType)
		ctx.Mem.Write32(lpServiceConfig+8, svc.errorControl)
		ctx.Mem.Write64(lpServiceConfig+16, binaryPathPtr)
		ctx.Mem.Write64(lpServiceConfig+24, 0)
		ctx.Mem.Write32(lpServiceConfig+32, 0)
		ctx.Mem.Write64(lpServiceConfig+40, 0)
		ctx.Mem.Write64(lpServiceConfig+48, startNamePtr)
		ctx.Mem.Write64(lpServiceConfig+56, displayNamePtr)
		setLastError(ctx, 0)
		return 1
	}
	changeServiceConfigCommon := func(ctx *ntapi.TrapContext, hService uint64, displayName string, serviceType, startType, errorControl uint32, binaryPath, startName string) uint32 {
		svc := getServiceForHandle(hService)
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			return 0
		}
		scmMu.Lock()
		if displayName != "" {
			svc.displayName = displayName
		}
		if serviceType != 0xFFFFFFFF && serviceType != 0 {
			svc.serviceType = serviceType
		}
		if startType != 0xFFFFFFFF && startType != 0 {
			svc.startType = startType
		}
		if errorControl != 0xFFFFFFFF && errorControl != 0 {
			svc.errorControl = errorControl
		}
		if binaryPath != "" {
			svc.binaryPath = binaryPath
		}
		if startName != "" {
			svc.startName = startName
		}
		ensureServiceDefaults(svc)
		scmMu.Unlock()
		syncServiceRegistry(svc)
		setLastError(ctx, 0)
		return 1
	}
	enumServicesStatusEx := func(ctx *ntapi.TrapContext, hSCManager, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle uint64, wide bool) uint32 {
		h := getSCMHandle(hSCManager)
		if h == nil || h.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			return 0
		}
		if infoLevel != scStatusProcessInfo {
			setLastError(ctx, errorInvalidParameter)
			return 0
		}
		scmMu.Lock()
		names := make([]string, 0, len(knownServices))
		for name := range knownServices {
			names = append(names, name)
		}
		sort.Strings(names)
		services := make([]*serviceInfo, 0, len(names))
		for _, name := range names {
			svc := knownServices[name]
			ensureServiceDefaults(svc)
			if serviceMatchesType(svc, uint32(dwServiceType)) && serviceMatchesState(svc, uint32(dwServiceState)) {
				services = append(services, svc)
			}
		}
		scmMu.Unlock()
		needed := uint32(len(services) * enumServiceStatusProcSize)
		for _, svc := range services {
			if wide {
				needed += uint32(len(utf16BytesWithNul(svc.name)) + len(utf16BytesWithNul(svc.displayName)))
			} else {
				needed += uint32(len(svc.name) + 1 + len(svc.displayName) + 1)
			}
		}
		if pcbBytesNeeded != 0 {
			ctx.Mem.Write32(pcbBytesNeeded, needed)
		}
		if lpServicesReturned != 0 {
			ctx.Mem.Write32(lpServicesReturned, 0)
		}
		if lpResumeHandle != 0 {
			ctx.Mem.Write32(lpResumeHandle, 0)
		}
		if cbBufSize < uint64(needed) || lpServices == 0 {
			setLastError(ctx, errorMoreData)
			return 0
		}
		strPtr := lpServices + uint64(len(services)*enumServiceStatusProcSize)
		for i, svc := range services {
			entry := lpServices + uint64(i*enumServiceStatusProcSize)
			namePtr := strPtr
			if wide {
				writeGuestUTF16String(ctx.Mem, namePtr, svc.name)
				strPtr += uint64(len(utf16BytesWithNul(svc.name)))
			} else {
				writeGuestANSIString(ctx.Mem, namePtr, svc.name)
				strPtr += uint64(len(svc.name) + 1)
			}
			displayNamePtr := strPtr
			if wide {
				writeGuestUTF16String(ctx.Mem, displayNamePtr, svc.displayName)
				strPtr += uint64(len(utf16BytesWithNul(svc.displayName)))
			} else {
				writeGuestANSIString(ctx.Mem, displayNamePtr, svc.displayName)
				strPtr += uint64(len(svc.displayName) + 1)
			}
			ctx.Mem.Write64(entry+0, namePtr)
			ctx.Mem.Write64(entry+8, displayNamePtr)
			writeServiceStatusProcess(ctx, entry+16, svc)
		}
		if lpServicesReturned != 0 {
			ctx.Mem.Write32(lpServicesReturned, uint32(len(services)))
		}
		setLastError(ctx, 0)
		return 1
	}
	for _, svc := range knownServices {
		ensureServiceDefaults(svc)
		syncServiceRegistry(svc)
	}
	d.RegisterAutoStubHandler(advapi32, "OpenSCManagerW", func(ctx *ntapi.TrapContext) uint32 {
		h := newSCMHandle("scm", "")
		setLastError(ctx, 0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenSCManagerA", func(ctx *ntapi.TrapContext) uint32 {
		h := newSCMHandle("scm", "")
		setLastError(ctx, 0)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CloseServiceHandle", func(ctx *ntapi.TrapContext) uint32 {
		if !removeSCMHandle(ctx.Arg(0)) {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenServiceW", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(ctx.Arg(1))
		svc, key := findServiceByName(name)
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(newSCMHandle("service", key))
		setLastError(ctx, 0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenServiceA", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(ctx.Arg(1))
		svc, key := findServiceByName(name)
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(newSCMHandle("service", key))
		setLastError(ctx, 0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateServiceW", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(ctx.Arg(1))
		if name == "" {
			setLastError(ctx, errorInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		if svc, _ := findServiceByName(name); svc != nil {
			setLastError(ctx, errorServiceExists)
			ctx.SetReturn(0)
			return 0
		}
		svc := &serviceInfo{
			name:         name,
			displayName:  readGuestUTF16(ctx.Arg(2)),
			status:       serviceStopped,
			serviceType:  uint32(ctx.Arg(4)),
			startType:    uint32(ctx.Arg(5)),
			errorControl: uint32(ctx.Arg(6)),
			binaryPath:   readGuestUTF16(ctx.Arg(7)),
			startName:    readGuestUTF16(ctx.Arg(11)),
		}
		ensureServiceDefaults(svc)
		scmMu.Lock()
		knownServices[name] = svc
		scmMu.Unlock()
		syncServiceRegistry(svc)
		ctx.SetReturn(newSCMHandle("service", name))
		setLastError(ctx, 0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateServiceA", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(ctx.Arg(1))
		if name == "" {
			setLastError(ctx, errorInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		if svc, _ := findServiceByName(name); svc != nil {
			setLastError(ctx, errorServiceExists)
			ctx.SetReturn(0)
			return 0
		}
		svc := &serviceInfo{
			name:         name,
			displayName:  readGuestString(ctx.Arg(2)),
			status:       serviceStopped,
			serviceType:  uint32(ctx.Arg(4)),
			startType:    uint32(ctx.Arg(5)),
			errorControl: uint32(ctx.Arg(6)),
			binaryPath:   readGuestString(ctx.Arg(7)),
			startName:    readGuestString(ctx.Arg(11)),
		}
		ensureServiceDefaults(svc)
		scmMu.Lock()
		knownServices[name] = svc
		scmMu.Unlock()
		syncServiceRegistry(svc)
		ctx.SetReturn(newSCMHandle("service", name))
		setLastError(ctx, 0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DeleteService", func(ctx *ntapi.TrapContext) uint32 {
		hService := ctx.Arg(0)
		sh := getSCMHandle(hService)
		if sh == nil || sh.kind != "service" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		scmMu.Lock()
		delete(knownServices, sh.name)
		scmMu.Unlock()
		deleteServiceRegistry(sh.name)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "StartServiceW", func(ctx *ntapi.TrapContext) uint32 {
		svc := getServiceForHandle(ctx.Arg(0))
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		scmMu.Lock()
		svc.status = serviceRunning
		scmMu.Unlock()
		syncServiceRegistry(svc)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "StartServiceA", func(ctx *ntapi.TrapContext) uint32 {
		svc := getServiceForHandle(ctx.Arg(0))
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		scmMu.Lock()
		svc.status = serviceRunning
		scmMu.Unlock()
		syncServiceRegistry(svc)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ControlService", func(ctx *ntapi.TrapContext) uint32 {
		svc := getServiceForHandle(ctx.Arg(0))
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		control := uint32(ctx.Arg(1))
		switch control {
		case serviceControlStop:
			scmMu.Lock()
			svc.status = serviceStopped
			scmMu.Unlock()
		case serviceControlPause:
			scmMu.Lock()
			svc.status = servicePaused
			scmMu.Unlock()
		case serviceControlContinue:
			scmMu.Lock()
			svc.status = serviceRunning
			scmMu.Unlock()
		case serviceControlInterrogate:
			// keep current status
		default:
			setLastError(ctx, errorInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		if pStatus := ctx.Arg(2); pStatus != 0 {
			writeServiceStatus(ctx, pStatus, svc)
		}
		syncServiceRegistry(svc)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceStatus", func(ctx *ntapi.TrapContext) uint32 {
		svc := getServiceForHandle(ctx.Arg(0))
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if pStatus := ctx.Arg(1); pStatus != 0 {
			writeServiceStatus(ctx, pStatus, svc)
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfigW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(queryServiceConfigW(ctx, ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3))))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfigA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(queryServiceConfigA(ctx, ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3))))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfigW", func(ctx *ntapi.TrapContext) uint32 {
		ret := changeServiceConfigCommon(
			ctx,
			ctx.Arg(0),
			readGuestUTF16(ctx.Arg(10)),
			uint32(ctx.Arg(1)),
			uint32(ctx.Arg(2)),
			uint32(ctx.Arg(3)),
			readGuestUTF16(ctx.Arg(4)),
			readGuestUTF16(ctx.Arg(8)),
		)
		ctx.SetReturn(uint64(ret))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfigA", func(ctx *ntapi.TrapContext) uint32 {
		ret := changeServiceConfigCommon(
			ctx,
			ctx.Arg(0),
			readGuestString(ctx.Arg(10)),
			uint32(ctx.Arg(1)),
			uint32(ctx.Arg(2)),
			uint32(ctx.Arg(3)),
			readGuestString(ctx.Arg(4)),
			readGuestString(ctx.Arg(8)),
		)
		ctx.SetReturn(uint64(ret))
		return 0
	})
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
		domainWs := utf16Encode("DESKTOP")
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
		domain := "DESKTOP"
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
		if pSd == 0 {
			ctx.SetReturn(0)
			return 0
		}
		for i := uint64(0); i < 40; i++ {
			mem.Write8(pSd+i, 0)
		}
		mem.Write8(pSd, 1)
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
		pSd := ctx.Arg(0)
		pbPresent := ctx.Arg(1)
		ppDacl := ctx.Arg(2)
		pbDefaulted := ctx.Arg(3)
		ctrl := uint16(0)
		if pSd != 0 {
			ctrl, _ = mem.Read16(pSd + 2)
		}
		if pbPresent != 0 {
			if ctrl&0x0004 != 0 {
				mem.Write32(pbPresent, 1)
			} else {
				mem.Write32(pbPresent, 0)
			}
		}
		if ppDacl != 0 {
			if pSd != 0 {
				dacl, _ := mem.Read64(pSd + 28)
				mem.Write64(ppDacl, dacl)
			} else {
				mem.Write64(ppDacl, 0)
			}
		}
		if pbDefaulted != 0 {
			if ctrl&0x0008 != 0 {
				mem.Write32(pbDefaulted, 1)
			} else {
				mem.Write32(pbDefaulted, 0)
			}
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
		_ = ctx.Arg(1)
		aclRevision := ctx.Arg(2)
		if pAcl == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if aclRevision == 0 {
			aclRevision = 2
		}
		mem.Write8(pAcl, uint8(aclRevision))
		mem.Write8(pAcl+1, 0)
		mem.Write16(pAcl+2, 8)
		mem.Write16(pAcl+4, 0)
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
		aceCount, _ := mem.Read16(pAcl + 4)
		aclSize, _ := mem.Read16(pAcl + 2)
		if aclSize < 8 {
			aclSize = 8
		}
		nSub, _ := mem.Read8(pSid + 1)
		sidLen := uint32(8 + uint32(nSub)*4)
		aceSize := uint16(8 + sidLen)
		aceOff := pAcl + uint64(aclSize)
		mem.Write8(aceOff, 0)
		mem.Write8(aceOff+1, 0)
		mem.Write16(aceOff+2, aceSize)
		mem.Write32(aceOff+4, accessMask)
		sidData, _ := mem.ReadBytes(pSid, int(sidLen))
		mem.WriteBytes(aceOff+8, sidData)
		mem.Write16(pAcl+4, aceCount+1)
		mem.Write16(pAcl+2, aclSize+aceSize)
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
		mem.Write8(aceOff, 0) // ACCESS_ALLOWED_ACE_TYPE
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
		mem.Write8(aceOff, 1) // ACCESS_DENIED_ACE_TYPE
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
		if pAcl == 0 || ppAce == 0 {
			ctx.SetReturn(0)
			return 0
		}
		aceCount, _ := mem.Read16(pAcl + 4)
		if uint64(aceCount) <= aceIndex {
			ctx.SetReturn(0)
			return 0
		}
		aceOff := pAcl + 8
		for i := uint64(0); i < aceIndex; i++ {
			aceSize, _ := mem.Read16(aceOff + 2)
			if aceSize == 0 {
				ctx.SetReturn(0)
				return 0
			}
			aceOff += uint64(aceSize)
		}
		mem.Write64(ppAce, aceOff)
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
		token := tokenForHandle(ctx.Arg(0))
		tokenClass := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		bufLen := uint32(ctx.Arg(3))
		retLen := ctx.Arg(4)
		failBuffer := func(needed uint32) uint32 {
			if retLen != 0 {
				mem.Write32(retLen, needed)
			}
			setLastError(ctx, tokenErrorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		switch tokenClass {
		case 1: // TokenUser: TOKEN_USER = {SID_AND_ATTRIBUTES{pSid, Attributes}}
			sidBytes := token.UserSID
			needed := uint32(16 + len(sidBytes))
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			sidAddr := buf + 16
			mem.WriteBytes(sidAddr, sidBytes)
			mem.Write64(buf, sidAddr)
			mem.Write32(buf+8, 0)
			mem.Write32(buf+12, 0)
		case 2: // TokenGroups
			groups := token.Groups
			if len(groups) == 0 {
				groups = [][]byte{adminGroupSID}
			}
			needed := uint32(8 + len(groups)*16)
			for _, sid := range groups {
				needed += uint32(len(sid))
			}
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, uint32(len(groups)))
			mem.Write32(buf+4, 0)
			sidAddr := buf + 8 + uint64(len(groups))*16
			for i, sid := range groups {
				entry := buf + 8 + uint64(i)*16
				mem.Write64(entry, sidAddr)
				mem.Write32(entry+8, 0x00000007)
				mem.Write32(entry+12, 0)
				mem.WriteBytes(sidAddr, sid)
				sidAddr += uint64(len(sid))
			}
		case 3: // TokenPrivileges
			var privs []uint64
			if len(token.Privileges) == 0 {
				privs = append(privs, commonPrivilegeLUIDs...)
			} else {
				for _, luid := range commonPrivilegeLUIDs {
					if token.Privileges[luid] {
						privs = append(privs, luid)
					}
				}
				if len(privs) == 0 {
					for luid, enabled := range token.Privileges {
						if enabled {
							privs = append(privs, luid)
						}
					}
					sort.Slice(privs, func(i, j int) bool { return privs[i] < privs[j] })
				}
			}
			needed := uint32(4 + len(privs)*12)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, uint32(len(privs)))
			for i, luid := range privs {
				entry := buf + 4 + uint64(i)*12
				mem.Write32(entry, uint32(luid))
				mem.Write32(entry+4, uint32(luid>>32))
				mem.Write32(entry+8, 0x00000003)
			}
		case 4: // TokenOwner
			sidBytes := token.UserSID
			needed := uint32(8 + len(sidBytes))
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			sidAddr := buf + 8
			mem.Write64(buf, sidAddr)
			mem.WriteBytes(sidAddr, sidBytes)
		case 5: // TokenPrimaryGroup
			sidBytes := token.PrimaryGroupSID
			if len(sidBytes) == 0 {
				sidBytes = adminGroupSID
			}
			needed := uint32(8 + len(sidBytes))
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			sidAddr := buf + 8
			mem.Write64(buf, sidAddr)
			mem.WriteBytes(sidAddr, sidBytes)
		case 6: // TokenDefaultDacl
			needed := uint32(8)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write64(buf, 0)
		case 7: // TokenSource
			needed := uint32(16)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			for i := uint64(0); i < 16; i++ {
				mem.Write8(buf+i, 0)
			}
		case 8: // TokenType
			needed := uint32(4)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, 1)
		case 9: // TokenImpersonationLevel
			needed := uint32(4)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, 2)
		case 10: // TokenStatistics: 48 bytes
			needed := uint32(48)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			for i := uint64(0); i < 48; i++ {
				mem.Write8(buf+i, 0)
			}
			mem.Write32(buf+16, 1)
		case 18: // TokenElevationType
			needed := uint32(4)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, 2)
		case 19: // TokenLinkedToken
			needed := uint32(8)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write64(buf, 0)
		case 20: // TokenElevation
			needed := uint32(4)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, 1)
		case 21: // TokenHasRestrictions
			needed := uint32(4)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			mem.Write32(buf, 0)
		case 25: // TokenIntegrityLevel
			needed := uint32(16 + len(highIntegritySID))
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			sidAddr := buf + 16
			mem.Write64(buf, sidAddr)
			mem.Write32(buf+8, 0x00000020)
			mem.Write32(buf+12, 0)
			mem.WriteBytes(sidAddr, highIntegritySID)
		default:
			needed := uint32(8)
			if buf == 0 || bufLen < needed {
				return failBuffer(needed)
			}
			for i := uint32(0); i < needed; i++ {
				mem.Write8(buf+uint64(i), 0)
			}
		}
		if retLen != 0 {
			switch tokenClass {
			case 1:
				mem.Write32(retLen, uint32(16+len(token.UserSID)))
			case 2:
				groups := token.Groups
				if len(groups) == 0 {
					groups = [][]byte{adminGroupSID}
				}
				needed := uint32(8 + len(groups)*16)
				for _, sid := range groups {
					needed += uint32(len(sid))
				}
				mem.Write32(retLen, needed)
			case 3:
				count := len(commonPrivilegeLUIDs)
				if len(token.Privileges) > 0 {
					count = 0
					for _, luid := range commonPrivilegeLUIDs {
						if token.Privileges[luid] {
							count++
						}
					}
					if count == 0 {
						for _, enabled := range token.Privileges {
							if enabled {
								count++
							}
						}
					}
				}
				mem.Write32(retLen, uint32(4+count*12))
			case 4:
				mem.Write32(retLen, uint32(8+len(token.UserSID)))
			case 5:
				groupSID := token.PrimaryGroupSID
				if len(groupSID) == 0 {
					groupSID = adminGroupSID
				}
				mem.Write32(retLen, uint32(8+len(groupSID)))
			case 6, 19:
				mem.Write32(retLen, 8)
			case 7:
				mem.Write32(retLen, 16)
			case 8, 9, 18, 20, 21:
				mem.Write32(retLen, 4)
			case 10:
				mem.Write32(retLen, 48)
			case 25:
				mem.Write32(retLen, uint32(16+len(highIntegritySID)))
			default:
				mem.Write32(retLen, 8)
			}
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
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
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AbortSystemShutdownA p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AbortSystemShutdownW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AbortSystemShutdownW p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheck", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheck p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckAndAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckAndAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByType p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeAndAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeAndAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultList p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmByHandleA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmByHandleA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmByHandleW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmByHandleW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AccessCheckByTypeResultListAndAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AccessCheckByTypeResultListAndAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessAllowedObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAccessAllowedObjectAce p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessDeniedAceEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] AddAccessDeniedAceEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAccessDeniedObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAccessDeniedObjectAce p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessAce p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessAceEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessAceEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddAuditAccessObjectAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AddAuditAccessObjectAce p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AddUsersToEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] AddUsersToEncryptedFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AdjustTokenGroups", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] AdjustTokenGroups p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AllocateLocallyUniqueId", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] AllocateLocallyUniqueId p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AreAllAccessesGranted", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] AreAllAccessesGranted p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "AreAnyAccessesGranted", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] AreAnyAccessesGranted p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BackupEventLogA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BackupEventLogW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildExplicitAccessWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildExplicitAccessWithNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildExplicitAccessWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildExplicitAccessWithNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateExplicitAccessWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildImpersonateExplicitAccessWithNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateExplicitAccessWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildImpersonateExplicitAccessWithNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateTrusteeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildImpersonateTrusteeA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildImpersonateTrusteeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildImpersonateTrusteeW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildSecurityDescriptorA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildSecurityDescriptorW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithNameA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithNameW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndNameW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndSidA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndSidA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithObjectsAndSidW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] BuildTrusteeWithObjectsAndSidW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithSidA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithSidA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "BuildTrusteeWithSidW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] BuildTrusteeWithSidW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfig2A", func(ctx *ntapi.TrapContext) uint32 {
		if getServiceForHandle(ctx.Arg(0)) == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ChangeServiceConfig2W", func(ctx *ntapi.TrapContext) uint32 {
		if getServiceForHandle(ctx.Arg(0)) == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ClearEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ClearEventLogA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ClearEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ClearEventLogW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CloseEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CloseEncryptedFileRaw p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CommandLineFromMsiDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CommandLineFromMsiDescriptor p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] ConvertSecurityDescriptorToStringSecurityDescriptorA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] ConvertSecurityDescriptorToStringSecurityDescriptorW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] ConvertStringSecurityDescriptorToSecurityDescriptorA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] ConvertStringSecurityDescriptorToSecurityDescriptorW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ConvertToAutoInheritPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ConvertToAutoInheritPrivateObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurityEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurityEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreatePrivateObjectSecurityWithMultipleInheritance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreatePrivateObjectSecurityWithMultipleInheritance p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessAsUserA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessAsUserA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessAsUserW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessWithLogonW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessWithLogonW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateProcessWithTokenW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateProcessWithTokenW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateRestrictedToken", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CreateRestrictedToken p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CreateTraceInstanceId", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CreateTraceInstanceId p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredDeleteA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredDeleteA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredDeleteW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredDeleteW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredEnumerateA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredEnumerateA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredEnumerateW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredEnumerateW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredFree p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredGetSessionTypes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CredGetSessionTypes p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredIsMarshaledCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredIsMarshaledCredentialA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredIsMarshaledCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] CredIsMarshaledCredentialW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredMarshalCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredMarshalCredentialA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredMarshalCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredMarshalCredentialW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadDomainCredentialsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadDomainCredentialsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadDomainCredentialsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadDomainCredentialsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredReadW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CredReadW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredUnmarshalCredentialA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredUnmarshalCredentialA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredUnmarshalCredentialW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CredUnmarshalCredentialW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredWriteA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CredWriteA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CredWriteW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CredWriteW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptContextAddRef", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CryptContextAddRef p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDuplicateHash", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptDuplicateHash p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptDuplicateKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptDuplicateKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProviderTypesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProviderTypesA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProviderTypesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProviderTypesW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProvidersA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProvidersA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptEnumProvidersW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] CryptEnumProvidersW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetDefaultProviderA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetDefaultProviderA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetDefaultProviderW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetDefaultProviderW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetProvParam", func(ctx *ntapi.TrapContext) uint32 {
		hProv := ctx.Arg(0)
		dwParam := ctx.Arg(1)
		pbData := ctx.Arg(2)
		pdwDataLen := ctx.Arg(3)
		dwFlags := ctx.Arg(4)
		ravelog.Logf("[advapi32] CryptGetProvParam prov=0x%x param=%d\n", hProv, dwParam)
		_ = pbData
		_ = dwFlags
		if pdwDataLen != 0 {
			ctx.Mem.Write32(pdwDataLen, 0)
		}
		ctx.SetReturn(0) // FALSE - param not supported
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptGetUserKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] CryptGetUserKey p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CryptSetProviderA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptSetProviderExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] CryptSetProviderExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "CryptSetProviderW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] CryptSetProviderW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DecryptFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] DecryptFileA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DecryptFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] DecryptFileW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DeleteAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] DeleteAce p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "DestroyPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] DestroyPrivateObjectSecurity p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfBackupEventLogFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfBackupEventLogFileA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfBackupEventLogFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfBackupEventLogFileW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfChangeNotify", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfChangeNotify p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfClearEventLogFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfClearEventLogFileA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfClearEventLogFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfClearEventLogFileW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfCloseEventLog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfCloseEventLog p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfDeregisterEventSource", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfDeregisterEventSource p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfFlushEventLog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ElfFlushEventLog p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfNumberOfRecords", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfNumberOfRecords p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOldestRecord", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] ElfOldestRecord p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenBackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenBackupEventLogA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenBackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenBackupEventLogW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenEventLogA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfOpenEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfOpenEventLogW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReadEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReadEventLogA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReadEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReadEventLogW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfRegisterEventSourceA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfRegisterEventSourceA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfRegisterEventSourceW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ElfRegisterEventSourceW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventAndSourceW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventAndSourceW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ElfReportEventW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ElfReportEventW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptFileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] EncryptFileA p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptFileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] EncryptFileW p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EncryptionDisable", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] EncryptionDisable p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumDependentServicesA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumDependentServicesA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumDependentServicesW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumDependentServicesW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServiceGroupW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServiceGroupW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusExA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(enumServicesStatusEx(
			ctx,
			ctx.Arg(0),
			ctx.Arg(1),
			ctx.Arg(2),
			ctx.Arg(3),
			ctx.Arg(4),
			ctx.Arg(5),
			ctx.Arg(6),
			ctx.Arg(7),
			ctx.Arg(8),
			false,
		)))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusExW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(enumServicesStatusEx(
			ctx,
			ctx.Arg(0),
			ctx.Arg(1),
			ctx.Arg(2),
			ctx.Arg(3),
			ctx.Arg(4),
			ctx.Arg(5),
			ctx.Arg(6),
			ctx.Arg(7),
			ctx.Arg(8),
			true,
		)))
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EnumServicesStatusW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] EnumServicesStatusW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "EqualDomainSid", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] EqualDomainSid p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FileEncryptionStatusA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] FileEncryptionStatusA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FileEncryptionStatusW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] FileEncryptionStatusW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FindFirstFreeAce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] FindFirstFreeAce p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FreeEncryptionCertificateHashList", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] FreeEncryptionCertificateHashList p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "FreeInheritedFromArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] FreeInheritedFromArray p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAuditedPermissionsFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] GetAuditedPermissionsFromAclA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetAuditedPermissionsFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] GetAuditedPermissionsFromAclW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetCurrentHwProfileA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetCurrentHwProfileA p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetCurrentHwProfileW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetCurrentHwProfileW p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEffectiveRightsFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] GetEffectiveRightsFromAclA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEffectiveRightsFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] GetEffectiveRightsFromAclW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetEventLogInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] GetEventLogInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetExplicitEntriesFromAclA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] GetExplicitEntriesFromAclA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetExplicitEntriesFromAclW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] GetExplicitEntriesFromAclW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetFileSecurityA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] GetFileSecurityA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetFileSecurityW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] GetFileSecurityW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetInheritanceSourceA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] GetInheritanceSourceA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetInheritanceSourceW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] GetInheritanceSourceW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetKernelObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] GetKernelObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeOperationA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeOperationA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeOperationW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeOperationW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetMultipleTrusteeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetMultipleTrusteeW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetNumberOfEventLogRecords", func(ctx *ntapi.TrapContext) uint32 {
		hEventLog := ctx.Arg(0)
		pnRecords := ctx.Arg(1)
		ravelog.Logf("[advapi32] GetNumberOfEventLogRecords log=0x%x\n", hEventLog)
		if pnRecords != 0 {
			ctx.Mem.Write32(pnRecords, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetOldestEventLogRecord", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] GetOldestEventLogRecord p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] GetPrivateObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorLength", func(ctx *ntapi.TrapContext) uint32 {
		pSD := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetSecurityDescriptorLength pSD=0x%x\n", pSD)
		ctx.SetReturn(40) // minimal absolute SD size
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityDescriptorRMControl", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] GetSecurityDescriptorRMControl p0=0x%x, p1=0x%x\n", p0, p1)
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
				if ctrl&0x0010 != 0 {
					ctx.Mem.Write32(lpbSaclPresent, 1)
				} else {
					ctx.Mem.Write32(lpbSaclPresent, 0)
				}
			}
			if pSacl != 0 {
				ctx.Mem.Write64(pSacl, 0)
			}
			if lpbSaclDefaulted != 0 {
				if ctrl&0x0020 != 0 {
					ctx.Mem.Write32(lpbSaclDefaulted, 1)
				} else {
					ctx.Mem.Write32(lpbSaclDefaulted, 0)
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] GetSecurityInfoExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSecurityInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] GetSecurityInfoExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceDisplayNameA", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		svc, _ := findServiceByName(readGuestString(ctx.Arg(1)))
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		needed := uint32(len(svc.displayName) + 1)
		if ctx.Arg(3) != 0 {
			avail, _ := ctx.Mem.Read32(ctx.Arg(3))
			ctx.Mem.Write32(ctx.Arg(3), needed)
			if ctx.Arg(2) == 0 || avail < needed {
				setLastError(ctx, errorInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
		}
		writeGuestANSIString(ctx.Mem, ctx.Arg(2), svc.displayName)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceDisplayNameW", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		svc, _ := findServiceByName(readGuestUTF16(ctx.Arg(1)))
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		needed := uint32(len(utf16Encode(svc.displayName)) + 1)
		if ctx.Arg(3) != 0 {
			avail, _ := ctx.Mem.Read32(ctx.Arg(3))
			ctx.Mem.Write32(ctx.Arg(3), needed)
			if ctx.Arg(2) == 0 || avail < needed {
				setLastError(ctx, errorInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
		}
		writeGuestUTF16String(ctx.Mem, ctx.Arg(2), svc.displayName)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceKeyNameA", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		svc, _ := findServiceByDisplayName(readGuestString(ctx.Arg(1)))
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		needed := uint32(len(svc.name) + 1)
		if ctx.Arg(3) != 0 {
			avail, _ := ctx.Mem.Read32(ctx.Arg(3))
			ctx.Mem.Write32(ctx.Arg(3), needed)
			if ctx.Arg(2) == 0 || avail < needed {
				setLastError(ctx, errorInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
		}
		writeGuestANSIString(ctx.Mem, ctx.Arg(2), svc.name)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetServiceKeyNameW", func(ctx *ntapi.TrapContext) uint32 {
		hMgr := getSCMHandle(ctx.Arg(0))
		if hMgr == nil || hMgr.kind != "scm" {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		svc, _ := findServiceByDisplayName(readGuestUTF16(ctx.Arg(1)))
		if svc == nil {
			setLastError(ctx, errorServiceDoesNotExist)
			ctx.SetReturn(0)
			return 0
		}
		needed := uint32(len(utf16Encode(svc.name)) + 1)
		if ctx.Arg(3) != 0 {
			avail, _ := ctx.Mem.Read32(ctx.Arg(3))
			ctx.Mem.Write32(ctx.Arg(3), needed)
			if ctx.Arg(2) == 0 || avail < needed {
				setLastError(ctx, errorInsufficientBuffer)
				ctx.SetReturn(0)
				return 0
			}
		}
		writeGuestUTF16String(ctx.Mem, ctx.Arg(2), svc.name)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetSidLengthRequired", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetSidLengthRequired p0=0x%x\n", p0)
		ctx.SetReturn(8)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceEnableFlags", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceEnableFlags p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceEnableLevel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceEnableLevel p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTraceLoggerHandle", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTraceLoggerHandle p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeFormA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeFormA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeFormW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeFormW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeNameA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeNameW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeNameW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeTypeA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeTypeA p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetTrusteeTypeW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] GetTrusteeTypeW p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "GetWindowsAccountDomainSid", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] GetWindowsAccountDomainSid p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_QueryTagInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] I_QueryTagInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScGetCurrentGroupStateW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScGetCurrentGroupStateW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScIsSecurityProcess", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[advapi32] I_ScIsSecurityProcess()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScPnPGetServiceName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScPnPGetServiceName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSendPnPMessage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] I_ScSendPnPMessage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSetServiceBitsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] I_ScSetServiceBitsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScSetServiceBitsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] I_ScSetServiceBitsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "I_ScValidatePnpService", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] I_ScValidatePnpService p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ImpersonateAnonymousToken", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ImpersonateAnonymousToken p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ImpersonateNamedPipeClient", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] ImpersonateNamedPipeClient p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] InitiateSystemShutdownA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] InitiateSystemShutdownExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] InitiateSystemShutdownExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "InitiateSystemShutdownW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] InitiateSystemShutdownW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "IsValidAcl", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] IsValidAcl p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LockServiceDatabase", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LockServiceDatabase p0=0x%x\n", p0)
		ctx.SetReturn(0xBEEF0002)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LogonUserA", func(ctx *ntapi.TrapContext) uint32 {
		lpUsername := ctx.Arg(0)
		lpDomain := ctx.Arg(1)
		lpPassword := ctx.Arg(2)
		var user string
		if lpUsername != 0 {
			user = readGuestUTF16(lpUsername)
		}
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
		if lpUsername != 0 {
			user = readGuestUTF16(lpUsername)
		}
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
		if lpUsername != 0 {
			user = readGuestUTF16(lpUsername)
		}
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
		if lpUsername != 0 {
			user = readGuestUTF16(lpUsername)
		}
		ravelog.Logf("[advapi32] LogonUserW user=%q domain=0x%x\n", user, lpDomain)
		_ = lpPassword
		ctx.SetReturn(1) // TRUE - logon always succeeds in emulator
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupAccountNameA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] LookupAccountNameA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupAccountNameW", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(2)
		pcbSid := ctx.Arg(3)
		pDomain := ctx.Arg(4)
		pcchDomain := ctx.Arg(5)
		peUse := ctx.Arg(6)
		sidNeeded := uint32(len(fixedUserSID))
		domainWs := utf16Encode("DESKTOP")
		domainNeeded := uint32(len(domainWs) + 1)
		sidAvail := uint32(0)
		domainAvail := uint32(0)
		if pcbSid != 0 {
			sidAvail, _ = mem.Read32(pcbSid)
			mem.Write32(pcbSid, sidNeeded)
		}
		if pcchDomain != 0 {
			domainAvail, _ = mem.Read32(pcchDomain)
			mem.Write32(pcchDomain, domainNeeded)
		}
		if (pSid != 0 && sidAvail < sidNeeded) || (pDomain != 0 && domainAvail < domainNeeded) {
			setLastError(ctx, errorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		if pSid != 0 {
			mem.WriteBytes(pSid, fixedUserSID)
		}
		if pDomain != 0 {
			for i, w := range domainWs {
				mem.Write16(pDomain+uint64(i)*2, w)
			}
			mem.Write16(pDomain+uint64(len(domainWs))*2, 0)
		}
		if peUse != 0 {
			mem.Write32(peUse, 1)
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LookupAccountNameA", func(ctx *ntapi.TrapContext) uint32 {
		pSid := ctx.Arg(2)
		pcbSid := ctx.Arg(3)
		pDomain := ctx.Arg(4)
		pcchDomain := ctx.Arg(5)
		peUse := ctx.Arg(6)
		sidNeeded := uint32(len(fixedUserSID))
		domain := "DESKTOP"
		domainNeeded := uint32(len(domain) + 1)
		sidAvail := uint32(0)
		domainAvail := uint32(0)
		if pcbSid != 0 {
			sidAvail, _ = mem.Read32(pcbSid)
			mem.Write32(pcbSid, sidNeeded)
		}
		if pcchDomain != 0 {
			domainAvail, _ = mem.Read32(pcchDomain)
			mem.Write32(pcchDomain, domainNeeded)
		}
		if (pSid != 0 && sidAvail < sidNeeded) || (pDomain != 0 && domainAvail < domainNeeded) {
			setLastError(ctx, errorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		if pSid != 0 {
			mem.WriteBytes(pSid, fixedUserSID)
		}
		if pDomain != 0 {
			for i := 0; i < len(domain); i++ {
				mem.Write8(pDomain+uint64(i), domain[i])
			}
			mem.Write8(pDomain+uint64(len(domain)), 0)
		}
		if peUse != 0 {
			mem.Write32(peUse, 1)
		}
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaAddAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaAddAccountRights p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaAddPrivilegesToAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaAddPrivilegesToAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaClearAuditLog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaClearAuditLog p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaClose", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaClose p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateAccount p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateSecret", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateSecret p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaCreateTrustedDomain p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaCreateTrustedDomainEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaCreateTrustedDomainEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaDelete", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaDelete p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaDeleteTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaDeleteTrustedDomain p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaEnumerateAccountRights p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccounts", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateAccounts p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateAccountsWithUserRight", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaEnumerateAccountsWithUserRight p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumeratePrivileges", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumeratePrivileges p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumeratePrivilegesOfAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaEnumeratePrivilegesOfAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateTrustedDomains", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateTrustedDomains p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaEnumerateTrustedDomainsEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaEnumerateTrustedDomainsEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaFreeMemory", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaFreeMemory p0=0x%x\n", p0)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetQuotasForAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetQuotasForAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetRemoteUserName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaGetRemoteUserName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetSystemAccessAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetSystemAccessAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaGetUserName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaGetUserName p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupNames", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaLookupNames p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupNames2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] LsaLookupNames2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeDisplayName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupPrivilegeValue", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaLookupPrivilegeValue p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaLookupSids", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaLookupSids p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaNtStatusToWinError", func(ctx *ntapi.TrapContext) uint32 {
		status := ctx.Arg(0)
		ravelog.Logf("[advapi32] LsaNtStatusToWinError status=0x%x\n", status)
		var win32 uint64
		switch status {
		case 0:
			win32 = 0
		case 0xC0000022:
			win32 = 5
		case 0xC000000D:
			win32 = 87
		case 0xC0000034:
			win32 = 2
		default:
			win32 = 317
		}
		ctx.SetReturn(win32)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenAccount p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenPolicy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenPolicy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenPolicySce", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenPolicySce p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenSecret", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenSecret p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenTrustedDomain p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaOpenTrustedDomainByName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaOpenTrustedDomainByName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryDomainInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryDomainInformationPolicy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryForestTrustInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryForestTrustInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryInfoTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryInfoTrustedDomain p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQueryInformationPolicy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQuerySecret", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaQuerySecret p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQuerySecurityObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaQuerySecurityObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryTrustedDomainInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaQueryTrustedDomainInfo p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaQueryTrustedDomainInfoByName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaQueryTrustedDomainInfoByName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRemoveAccountRights", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaRemoveAccountRights p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRemovePrivilegesFromAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaRemovePrivilegesFromAccount p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaRetrievePrivateData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaRetrievePrivateData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetDomainInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetDomainInformationPolicy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetForestTrustInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] LsaSetForestTrustInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetInformationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetInformationPolicy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetInformationTrustedDomain", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetInformationTrustedDomain p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetQuotasForAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaSetQuotasForAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSecret", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetSecret p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSecurityObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaSetSecurityObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetSystemAccessAccount", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] LsaSetSystemAccessAccount p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetTrustedDomainInfoByName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaSetTrustedDomainInfoByName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaSetTrustedDomainInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] LsaSetTrustedDomainInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "LsaStorePrivateData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] LsaStorePrivateData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MakeAbsoluteSD", func(ctx *ntapi.TrapContext) uint32 {
		pSelfRelSD := ctx.Arg(0)
		pAbsSD := ctx.Arg(1)
		// args 2-10: size pointers
		ravelog.Logf("[advapi32] MakeAbsoluteSD self=0x%x abs=0x%x\n", pSelfRelSD, pAbsSD)
		if pAbsSD != 0 {
			ctx.Mem.Write8(pAbsSD, 1)    // revision
			ctx.Mem.Write16(pAbsSD+2, 0) // not self-relative
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MakeAbsoluteSD2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] MakeAbsoluteSD2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "MapGenericMask", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] MapGenericMask p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "NotifyBootConfigStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] NotifyBootConfigStatus p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "NotifyChangeEventLog", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] NotifyChangeEventLog p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectCloseAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectCloseAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectCloseAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectCloseAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectDeleteAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectDeleteAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectDeleteAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ObjectDeleteAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectOpenAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectOpenAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectOpenAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectOpenAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectPrivilegeAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectPrivilegeAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ObjectPrivilegeAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] ObjectPrivilegeAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenBackupEventLogA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] OpenBackupEventLogA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0xBEEF0003)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenBackupEventLogW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] OpenBackupEventLogW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0xBEEF0003)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenEncryptedFileRawA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] OpenEncryptedFileRawA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenEncryptedFileRawW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] OpenEncryptedFileRawW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenTraceA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] OpenTraceA p0=0x%x\n", p0)
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "OpenTraceW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] OpenTraceW p0=0x%x\n", p0)
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "PrivilegedServiceAuditAlarmA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] PrivilegedServiceAuditAlarmA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "PrivilegedServiceAuditAlarmW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] PrivilegedServiceAuditAlarmW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ProcessTrace", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] ProcessTrace p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryRecoveryAgentsOnEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] QueryRecoveryAgentsOnEncryptedFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfig2A", func(ctx *ntapi.TrapContext) uint32 {
		if getServiceForHandle(ctx.Arg(0)) == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if ctx.Arg(4) != 0 {
			ctx.Mem.Write32(ctx.Arg(4), 0)
		}
		setLastError(ctx, errorInvalidParameter)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceConfig2W", func(ctx *ntapi.TrapContext) uint32 {
		if getServiceForHandle(ctx.Arg(0)) == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if ctx.Arg(4) != 0 {
			ctx.Mem.Write32(ctx.Arg(4), 0)
		}
		setLastError(ctx, errorInvalidParameter)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceLockStatusA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] QueryServiceLockStatusA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceLockStatusW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] QueryServiceLockStatusW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] QueryServiceObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryServiceStatusEx", func(ctx *ntapi.TrapContext) uint32 {
		svc := getServiceForHandle(ctx.Arg(0))
		if svc == nil {
			setLastError(ctx, errorInvalidHandle)
			ctx.SetReturn(0)
			return 0
		}
		if ctx.Arg(1) != scStatusProcessInfo {
			setLastError(ctx, errorInvalidParameter)
			ctx.SetReturn(0)
			return 0
		}
		if ctx.Arg(4) != 0 {
			ctx.Mem.Write32(ctx.Arg(4), serviceStatusProcessSize)
		}
		if ctx.Arg(3) < serviceStatusProcessSize || ctx.Arg(2) == 0 {
			setLastError(ctx, errorInsufficientBuffer)
			ctx.SetReturn(0)
			return 0
		}
		writeServiceStatusProcess(ctx, ctx.Arg(2), svc)
		setLastError(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "QueryUsersOnEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] QueryUsersOnEncryptedFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "ReadEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] ReadEncryptedFileRaw p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegConnectRegistryA", func(ctx *ntapi.TrapContext) uint32 {
		lpMachineName := ctx.Arg(0)
		hKey := ctx.Arg(1)
		phkResult := ctx.Arg(2)
		var machine string
		if lpMachineName != 0 {
			machine = readGuestUTF16(lpMachineName)
		}
		ravelog.Logf("[advapi32] RegConnectRegistryA machine=%q hkey=0x%x\n", machine, hKey)
		if phkResult != 0 {
			ctx.Mem.Write64(phkResult, hKey)
		}
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegConnectRegistryW", func(ctx *ntapi.TrapContext) uint32 {
		lpMachineName := ctx.Arg(0)
		hKey := ctx.Arg(1)
		phkResult := ctx.Arg(2)
		var machine string
		if lpMachineName != 0 {
			machine = readGuestUTF16(lpMachineName)
		}
		ravelog.Logf("[advapi32] RegConnectRegistryW machine=%q hkey=0x%x\n", machine, hKey)
		if phkResult != 0 {
			ctx.Mem.Write64(phkResult, hKey)
		}
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegCreateKeyW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] RegCreateKeyW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		samDesired := ctx.Arg(2)
		var sub string
		if lpSubKey != 0 {
			sub = readGuestUTF16(lpSubKey)
		}
		ravelog.Logf("[advapi32] RegDeleteKeyExA hkey=0x%x sub=%q sam=0x%x\n", hKey, sub, samDesired)
		ctx.SetReturn(0) // ERROR_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegDeleteKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		lpSubKey := ctx.Arg(1)
		samDesired := ctx.Arg(2)
		var sub string
		if lpSubKey != 0 {
			sub = readGuestUTF16(lpSubKey)
		}
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
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegDisableReflectionKey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnableReflectionKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegEnableReflectionKey p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] RegEnumKeyA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(259)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] RegEnumKeyExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(259)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumKeyW", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		dwIndex := ctx.Arg(1)
		lpName := ctx.Arg(2)
		cchName := ctx.Arg(3)
		ravelog.Logf("[advapi32] RegEnumKeyW hkey=0x%x idx=%d\n", hKey, dwIndex)
		_ = lpName
		_ = cchName
		ctx.SetReturn(259) // ERROR_NO_MORE_ITEMS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] RegEnumValueA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(259)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegFlushKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] RegFlushKey p0=0x%x\n", p0)
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
		if lpcbSD != 0 {
			ctx.Mem.Write32(lpcbSD, 20)
		} // SECURITY_DESCRIPTOR_MIN_LENGTH
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
		if lpSubKey != 0 {
			sub = readGuestUTF16(lpSubKey)
		}
		if lpValue != 0 {
			val = readGuestUTF16(lpValue)
		}
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegOpenCurrentUser p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOpenUserClassesRoot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] RegOpenUserClassesRoot p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegOverridePredefKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegOverridePredefKey p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		// lpClass(1), lpcchClass(2), reserved(3), lpcSubKeys(4), lpcbMaxSubKeyLen(5)
		// ... lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime
		for _, off := range []int{4, 5} {
			ptr := ctx.Arg(off)
			if ptr != 0 {
				ctx.Mem.Write32(ptr, 0)
			}
		}
		// lpcValues
		if p := ctx.Arg(6); p != 0 {
			ctx.Mem.Write32(p, 0)
		}
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
		_ = val_list
		_ = lpValueBuf
		_ = ldwTotsize
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
		_ = val_list
		_ = lpValueBuf
		_ = ldwTotsize
		ctx.SetReturn(2) // ERROR_FILE_NOT_FOUND
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegQueryReflectionKey", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegQueryReflectionKey p0=0x%x, p1=0x%x\n", p0, p1)
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] RegSetValueW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerA p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0xBEEF0001)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerExA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerExA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0xBEEF0001)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerExW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerExW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0xBEEF0001)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterServiceCtrlHandlerW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RegisterServiceCtrlHandlerW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0xBEEF0001)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterTraceGuidsA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] RegisterTraceGuidsA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RegisterTraceGuidsW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] RegisterTraceGuidsW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "RemoveUsersFromEncryptedFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] RemoveUsersFromEncryptedFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferCloseLevel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] SaferCloseLevel p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferComputeTokenFromLevel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] SaferComputeTokenFromLevel p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferCreateLevel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] SaferCreateLevel p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferGetPolicyInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] SaferGetPolicyInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferIdentifyLevel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] SaferIdentifyLevel p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SaferRecordEventLogEntry", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] SaferRecordEventLogEntry p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetAclInformation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] SetAclInformation p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetEntriesInAclA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] SetEntriesInAclA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetEntriesInAclW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] SetEntriesInAclW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetFileSecurityA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] SetFileSecurityA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetFileSecurityW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] SetFileSecurityW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetKernelObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] SetKernelObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetPrivateObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[advapi32] SetPrivateObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[advapi32] SetSecurityDescriptorRMControl p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetServiceBits", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] SetServiceBits p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SetServiceObjectSecurity", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] SetServiceObjectSecurity p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
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
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction001 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction002", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction002 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction003", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction003 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction004", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction004 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction005", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction005 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction006", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction006 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction007", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction007 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction008", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction008 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction009", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction009 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction010", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction010 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction011", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction011 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction012", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction012 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction013", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction013 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction014", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction014 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction015", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction015 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction016", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction016 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction017", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction017 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction018", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction018 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction019", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction019 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction020", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction020 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction021", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction021 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction022", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction022 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction023", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction023 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction024", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction024 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction025", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction025 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction026", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction026 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction027", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction027 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction028", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction028 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction029", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction029 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction030", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction030 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction031", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction031 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction032", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction032 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction033", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction033 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction034", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction034 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction035", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction035 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction040", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction040 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "SystemFunction041", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		ravelog.Logf("[advapi32] SystemFunction041 arg=0x%x\n", arg)
		_ = arg
		ctx.SetReturn(0) // STATUS_SUCCESS
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TraceEventInstance", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[advapi32] TraceEventInstance p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
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
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] TreeResetNamedSecurityInfoA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "TreeResetNamedSecurityInfoW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[advapi32] TreeResetNamedSecurityInfoW p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "UnlockServiceDatabase", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] UnlockServiceDatabase p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "UnregisterTraceGuids", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[advapi32] UnregisterTraceGuids p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(advapi32, "WriteEncryptedFileRaw", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[advapi32] WriteEncryptedFileRaw p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
}
