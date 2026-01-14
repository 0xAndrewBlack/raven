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
	"hash"
	"strings"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	statusSuccess           = uint32(0)
	statusInvalidHandle     = uint32(0xC0000008)
	statusInvalidParameter  = uint32(0xC000000D)
	statusNotSupported      = uint32(0xC00000BB)
	statusBufferTooSmall    = uint32(0xC0000023)
	statusNotFound          = uint32(0xC0000225)
	bcryptAlgHandleHMACFlag = uint32(0x00000008)
	bcryptBlockPaddingFlag  = uint32(0x00000001)
)

type bcryptAlgHandle struct {
	alg   string
	hmac  bool
	chain string
}

type bcryptHashHandle struct {
	alg  string
	hash hash.Hash
	hmac bool
}

type bcryptKeyHandle struct {
	alg   string
	key   []byte
	chain string
}

var (
	bcryptMu          sync.Mutex
	bcryptAlgHandles         = map[uint64]*bcryptAlgHandle{}
	bcryptHashHandles        = map[uint64]*bcryptHashHandle{}
	bcryptKeyHandles         = map[uint64]*bcryptKeyHandle{}
	nextBcryptAlgH    uint64 = 0xBA000001
	nextBcryptHashH   uint64 = 0xBB000001
	nextBcryptKeyH    uint64 = 0xBC000001
)

func normalizeBcryptAlg(name string) string {
	normalized := strings.ToUpper(strings.TrimSpace(name))
	switch normalized {
	case "SHA1", "SHA-1":
		return "SHA1"
	case "SHA256", "SHA-256":
		return "SHA256"
	case "SHA384", "SHA-384":
		return "SHA384"
	case "SHA512", "SHA-512":
		return "SHA512"
	case "MD5":
		return "MD5"
	case "AES":
		return "AES"
	case "3DES", "TRIPLEDES", "TRIPLE_DES":
		return "3DES"
	case "RC4":
		return "RC4"
	case "RSA":
		return "RSA"
	case "RNG":
		return "RNG"
	default:
		return normalized
	}
}

func normalizeBcryptProperty(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

func normalizeBcryptChain(name string) string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "CHAININGMODECBC", "CBC":
		return "CHAININGMODECBC"
	case "CHAININGMODEGCM", "GCM":
		return "CHAININGMODEGCM"
	default:
		return ""
	}
}

func bcryptHashFactory(alg string) (func() hash.Hash, uint32, uint32, bool) {
	switch alg {
	case "SHA1":
		return sha1.New, 64, 20, true
	case "SHA256":
		return sha256.New, 64, 32, true
	case "SHA384":
		return sha512.New384, 128, 48, true
	case "SHA512":
		return sha512.New, 128, 64, true
	case "MD5":
		return md5.New, 64, 16, true
	default:
		return nil, 0, 0, false
	}
}

func bcryptReadBytes(ctx *ntapi.TrapContext, ptr, size uint64) ([]byte, bool) {
	if size == 0 {
		return []byte{}, true
	}
	if ptr == 0 || size > uint64(^uint(0)>>1) {
		return nil, false
	}
	data, err := ctx.Mem.ReadBytes(ptr, int(size))
	if err != nil {
		return nil, false
	}
	return data, true
}

func bcryptWriteUint32Result(ctx *ntapi.TrapContext, pbOutput, cbOutput, pcbResult uint64, value uint32) uint32 {
	if pcbResult != 0 {
		ctx.Mem.Write32(pcbResult, 4)
	}
	if pbOutput == 0 {
		return statusSuccess
	}
	if cbOutput < 4 {
		return statusBufferTooSmall
	}
	ctx.Mem.Write32(pbOutput, value)
	return statusSuccess
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, bool) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, false
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, false
	}
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, false
		}
	}
	return data[:len(data)-padding], true
}

func bcryptEncryptBlockCipher(block cipher.Block, plaintext, iv []byte, padding bool) ([]byte, []byte, uint32) {
	blockSize := block.BlockSize()
	if len(iv) == 0 {
		iv = make([]byte, blockSize)
	}
	if len(iv) < blockSize {
		return nil, nil, statusInvalidParameter
	}
	working := append([]byte(nil), plaintext...)
	if padding {
		working = pkcs7Pad(working, blockSize)
	} else if len(working)%blockSize != 0 {
		return nil, nil, statusInvalidParameter
	}
	out := make([]byte, len(working))
	ivBuf := append([]byte(nil), iv[:blockSize]...)
	cipher.NewCBCEncrypter(block, ivBuf).CryptBlocks(out, working)
	nextIV := append([]byte(nil), ivBuf...)
	if len(out) >= blockSize {
		nextIV = append(nextIV[:0], out[len(out)-blockSize:]...)
	}
	return out, nextIV, statusSuccess
}

func bcryptDecryptBlockCipher(block cipher.Block, ciphertext, iv []byte, padding bool) ([]byte, []byte, uint32) {
	blockSize := block.BlockSize()
	if len(iv) == 0 {
		iv = make([]byte, blockSize)
	}
	if len(iv) < blockSize || len(ciphertext)%blockSize != 0 {
		return nil, nil, statusInvalidParameter
	}
	out := make([]byte, len(ciphertext))
	ivBuf := append([]byte(nil), iv[:blockSize]...)
	cipher.NewCBCDecrypter(block, ivBuf).CryptBlocks(out, ciphertext)
	nextIV := append([]byte(nil), ivBuf...)
	if len(ciphertext) >= blockSize {
		nextIV = append(nextIV[:0], ciphertext[len(ciphertext)-blockSize:]...)
	}
	if padding {
		unpadded, ok := pkcs7Unpad(out, blockSize)
		if !ok {
			return nil, nil, statusInvalidParameter
		}
		out = unpadded
	}
	return out, nextIV, statusSuccess
}

func bcryptPBKDF2(newHash func() hash.Hash, password, salt []byte, iterations, keyLen int) []byte {
	hLen := newHash().Size()
	blockCount := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blockCount*hLen)
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	msg := make([]byte, len(salt)+4)
	copy(msg, salt)

	for block := 1; block <= blockCount; block++ {
		binary.BigEndian.PutUint32(msg[len(salt):], uint32(block))
		mac := hmac.New(newHash, password)
		mac.Write(msg)
		sum := mac.Sum(nil)
		copy(u, sum)
		copy(t, sum)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(newHash, password)
			mac.Write(u)
			sum = mac.Sum(nil)
			copy(u, sum)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}

	return out[:keyLen]
}

func registerBcryptHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["bcrypt.dll"]
	if !ok {
		return
	}

	readGuestUTF16 := hctx.ReadGuestUTF16

	d.RegisterAutoStubHandler(dll, "BCryptOpenAlgorithmProvider", func(ctx *ntapi.TrapContext) uint32 {
		phAlgorithm := ctx.Arg(0)
		pszAlgId := ctx.Arg(1)
		dwFlags := uint32(ctx.Arg(3))
		if phAlgorithm == 0 || pszAlgId == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		algName := normalizeBcryptAlg(readGuestUTF16(pszAlgId))
		switch algName {
		case "SHA256", "SHA1", "SHA384", "SHA512", "MD5", "AES", "3DES", "RC4", "RSA", "RNG":
		default:
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}

		handle := uint64(0)
		bcryptMu.Lock()
		handle = nextBcryptAlgH
		nextBcryptAlgH++
		bcryptAlgHandles[handle] = &bcryptAlgHandle{
			alg:   algName,
			hmac:  (dwFlags & bcryptAlgHandleHMACFlag) != 0,
			chain: "CHAININGMODECBC",
		}
		bcryptMu.Unlock()

		ctx.Mem.Write64(phAlgorithm, handle)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptCloseAlgorithmProvider", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		bcryptMu.Lock()
		delete(bcryptAlgHandles, hAlgorithm)
		bcryptMu.Unlock()
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptSetProperty", func(ctx *ntapi.TrapContext) uint32 {
		hObject := ctx.Arg(0)
		pszProperty := ctx.Arg(1)
		pbInput := ctx.Arg(2)
		if pszProperty == 0 || pbInput == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		property := normalizeBcryptProperty(readGuestUTF16(pszProperty))
		switch property {
		case "CHAININGMODE":
			chain := normalizeBcryptChain(readGuestUTF16(pbInput))
			if chain == "" {
				ctx.SetReturn(uint64(statusNotSupported))
				return 0
			}

			bcryptMu.Lock()
			defer bcryptMu.Unlock()
			if alg := bcryptAlgHandles[hObject]; alg != nil {
				alg.chain = chain
				ctx.SetReturn(uint64(statusSuccess))
				return 0
			}
			if key := bcryptKeyHandles[hObject]; key != nil {
				key.chain = chain
				ctx.SetReturn(uint64(statusSuccess))
				return 0
			}
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		default:
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}
	})

	d.RegisterAutoStubHandler(dll, "BCryptGetProperty", func(ctx *ntapi.TrapContext) uint32 {
		hObject := ctx.Arg(0)
		pszProperty := ctx.Arg(1)
		pbOutput := ctx.Arg(2)
		cbOutput := ctx.Arg(3)
		pcbResult := ctx.Arg(4)
		if pszProperty == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		property := normalizeBcryptProperty(readGuestUTF16(pszProperty))

		bcryptMu.Lock()
		alg := ""
		if ah := bcryptAlgHandles[hObject]; ah != nil {
			alg = ah.alg
		} else if hh := bcryptHashHandles[hObject]; hh != nil {
			alg = hh.alg
		}
		bcryptMu.Unlock()

		if alg == "" {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		switch property {
		case "OBJECTLENGTH":
			_, objectLen, _, ok := bcryptHashFactory(alg)
			if !ok {
				ctx.SetReturn(uint64(statusNotSupported))
				return 0
			}
			ctx.SetReturn(uint64(bcryptWriteUint32Result(ctx, pbOutput, cbOutput, pcbResult, objectLen)))
			return 0
		case "HASHDIGESTLENGTH":
			_, _, digestLen, ok := bcryptHashFactory(alg)
			if !ok {
				ctx.SetReturn(uint64(statusNotSupported))
				return 0
			}
			ctx.SetReturn(uint64(bcryptWriteUint32Result(ctx, pbOutput, cbOutput, pcbResult, digestLen)))
			return 0
		default:
			ctx.SetReturn(uint64(statusNotFound))
			return 0
		}
	})

	d.RegisterAutoStubHandler(dll, "BCryptCreateHash", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		phHash := ctx.Arg(1)
		pbSecret := ctx.Arg(4)
		cbSecret := ctx.Arg(5)
		if phHash == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		bcryptMu.Lock()
		algHandle := bcryptAlgHandles[hAlgorithm]
		bcryptMu.Unlock()
		if algHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		newHash, _, _, ok := bcryptHashFactory(algHandle.alg)
		if !ok {
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}

		var h hash.Hash
		if algHandle.hmac {
			secret, ok := bcryptReadBytes(ctx, pbSecret, cbSecret)
			if !ok {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			h = hmac.New(newHash, secret)
		} else {
			h = newHash()
		}

		bcryptMu.Lock()
		handle := nextBcryptHashH
		nextBcryptHashH++
		bcryptHashHandles[handle] = &bcryptHashHandle{alg: algHandle.alg, hash: h, hmac: algHandle.hmac}
		bcryptMu.Unlock()

		ctx.Mem.Write64(phHash, handle)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptHashData", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbInput := ctx.Arg(1)
		cbInput := ctx.Arg(2)

		bcryptMu.Lock()
		hashHandle := bcryptHashHandles[hHash]
		bcryptMu.Unlock()
		if hashHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		data, ok := bcryptReadBytes(ctx, pbInput, cbInput)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		if _, err := hashHandle.hash.Write(data); err != nil {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptFinishHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		pbOutput := ctx.Arg(1)
		cbOutput := ctx.Arg(2)

		bcryptMu.Lock()
		hashHandle := bcryptHashHandles[hHash]
		bcryptMu.Unlock()
		if hashHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		sum := hashHandle.hash.Sum(nil)
		if pbOutput == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		if cbOutput < uint64(len(sum)) {
			ctx.SetReturn(uint64(statusBufferTooSmall))
			return 0
		}

		ctx.Mem.WriteBytes(pbOutput, sum)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptDestroyHash", func(ctx *ntapi.TrapContext) uint32 {
		hHash := ctx.Arg(0)
		bcryptMu.Lock()
		delete(bcryptHashHandles, hHash)
		bcryptMu.Unlock()
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptHash", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		pbSecret := ctx.Arg(1)
		cbSecret := ctx.Arg(2)
		pbInput := ctx.Arg(3)
		cbInput := ctx.Arg(4)
		pbOutput := ctx.Arg(5)
		cbOutput := ctx.Arg(6)

		bcryptMu.Lock()
		algHandle := bcryptAlgHandles[hAlgorithm]
		bcryptMu.Unlock()
		if algHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		newHash, _, _, ok := bcryptHashFactory(algHandle.alg)
		if !ok {
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}

		input, ok := bcryptReadBytes(ctx, pbInput, cbInput)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		var h hash.Hash
		if algHandle.hmac || cbSecret != 0 {
			secret, ok := bcryptReadBytes(ctx, pbSecret, cbSecret)
			if !ok {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			h = hmac.New(newHash, secret)
		} else {
			h = newHash()
		}
		if _, err := h.Write(input); err != nil {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		sum := h.Sum(nil)
		if pbOutput == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		if cbOutput < uint64(len(sum)) {
			ctx.SetReturn(uint64(statusBufferTooSmall))
			return 0
		}
		ctx.Mem.WriteBytes(pbOutput, sum)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptGenRandom", func(ctx *ntapi.TrapContext) uint32 {
		pbBuffer := ctx.Arg(1)
		cbBuffer := ctx.Arg(2)
		if pbBuffer == 0 && cbBuffer != 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		buf := make([]byte, cbBuffer)
		if _, err := cryptorand.Read(buf); err != nil {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		if pbBuffer != 0 {
			ctx.Mem.WriteBytes(pbBuffer, buf)
		}
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptGenerateSymmetricKey", func(ctx *ntapi.TrapContext) uint32 {
		hAlgorithm := ctx.Arg(0)
		phKey := ctx.Arg(1)
		pbSecret := ctx.Arg(4)
		cbSecret := ctx.Arg(5)
		if phKey == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		bcryptMu.Lock()
		algHandle := bcryptAlgHandles[hAlgorithm]
		bcryptMu.Unlock()
		if algHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		secret, ok := bcryptReadBytes(ctx, pbSecret, cbSecret)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		switch algHandle.alg {
		case "AES":
			if _, err := aes.NewCipher(secret); err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
		case "3DES":
			if _, err := des.NewTripleDESCipher(secret); err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
		case "RC4":
			if len(secret) == 0 {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
		default:
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}

		bcryptMu.Lock()
		handle := nextBcryptKeyH
		nextBcryptKeyH++
		bcryptKeyHandles[handle] = &bcryptKeyHandle{
			alg:   algHandle.alg,
			key:   append([]byte(nil), secret...),
			chain: algHandle.chain,
		}
		bcryptMu.Unlock()

		ctx.Mem.Write64(phKey, handle)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptDestroyKey", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		bcryptMu.Lock()
		delete(bcryptKeyHandles, hKey)
		bcryptMu.Unlock()
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptEncrypt", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pbInput := ctx.Arg(1)
		cbInput := ctx.Arg(2)
		pbIV := ctx.Arg(4)
		cbIV := ctx.Arg(5)
		pbOutput := ctx.Arg(6)
		cbOutput := ctx.Arg(7)
		pcbResult := ctx.Arg(8)
		dwFlags := uint32(ctx.Arg(9))

		bcryptMu.Lock()
		keyHandle := bcryptKeyHandles[hKey]
		bcryptMu.Unlock()
		if keyHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		input, ok := bcryptReadBytes(ctx, pbInput, cbInput)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		iv, ok := bcryptReadBytes(ctx, pbIV, cbIV)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		var (
			out    []byte
			nextIV []byte
			status uint32
		)
		switch keyHandle.alg {
		case "AES":
			block, err := aes.NewCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			if keyHandle.chain == "CHAININGMODEGCM" {
				gcm, err := cipher.NewGCM(block)
				if err != nil {
					ctx.SetReturn(uint64(statusInvalidParameter))
					return 0
				}
				if len(iv) == 0 {
					iv = make([]byte, gcm.NonceSize())
				}
				if len(iv) != gcm.NonceSize() {
					ctx.SetReturn(uint64(statusInvalidParameter))
					return 0
				}
				out = gcm.Seal(nil, iv, input, nil)
				nextIV = append([]byte(nil), iv...)
				status = statusSuccess
			} else {
				out, nextIV, status = bcryptEncryptBlockCipher(block, input, iv, (dwFlags&bcryptBlockPaddingFlag) != 0)
			}
		case "3DES":
			block, err := des.NewTripleDESCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			out, nextIV, status = bcryptEncryptBlockCipher(block, input, iv, (dwFlags&bcryptBlockPaddingFlag) != 0)
		case "RC4":
			stream, err := rc4.NewCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			out = make([]byte, len(input))
			stream.XORKeyStream(out, input)
			status = statusSuccess
		default:
			status = statusNotSupported
		}
		if status != statusSuccess {
			ctx.SetReturn(uint64(status))
			return 0
		}

		if pcbResult != 0 {
			ctx.Mem.Write32(pcbResult, uint32(len(out)))
		}
		if pbOutput == 0 {
			ctx.SetReturn(uint64(statusSuccess))
			return 0
		}
		if cbOutput < uint64(len(out)) {
			ctx.SetReturn(uint64(statusBufferTooSmall))
			return 0
		}

		ctx.Mem.WriteBytes(pbOutput, out)
		if pbIV != 0 && len(nextIV) != 0 {
			ctx.Mem.WriteBytes(pbIV, nextIV)
		}
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptDecrypt", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		pbInput := ctx.Arg(1)
		cbInput := ctx.Arg(2)
		pbIV := ctx.Arg(4)
		cbIV := ctx.Arg(5)
		pbOutput := ctx.Arg(6)
		cbOutput := ctx.Arg(7)
		pcbResult := ctx.Arg(8)
		dwFlags := uint32(ctx.Arg(9))

		bcryptMu.Lock()
		keyHandle := bcryptKeyHandles[hKey]
		bcryptMu.Unlock()
		if keyHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		input, ok := bcryptReadBytes(ctx, pbInput, cbInput)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		iv, ok := bcryptReadBytes(ctx, pbIV, cbIV)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		var (
			out    []byte
			nextIV []byte
			status uint32
		)
		switch keyHandle.alg {
		case "AES":
			block, err := aes.NewCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			if keyHandle.chain == "CHAININGMODEGCM" {
				gcm, err := cipher.NewGCM(block)
				if err != nil {
					ctx.SetReturn(uint64(statusInvalidParameter))
					return 0
				}
				if len(iv) == 0 {
					iv = make([]byte, gcm.NonceSize())
				}
				if len(iv) != gcm.NonceSize() {
					ctx.SetReturn(uint64(statusInvalidParameter))
					return 0
				}
				out, err = gcm.Open(nil, iv, input, nil)
				if err != nil {
					ctx.SetReturn(uint64(statusInvalidParameter))
					return 0
				}
				nextIV = append([]byte(nil), iv...)
				status = statusSuccess
			} else {
				out, nextIV, status = bcryptDecryptBlockCipher(block, input, iv, (dwFlags&bcryptBlockPaddingFlag) != 0)
			}
		case "3DES":
			block, err := des.NewTripleDESCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			out, nextIV, status = bcryptDecryptBlockCipher(block, input, iv, (dwFlags&bcryptBlockPaddingFlag) != 0)
		case "RC4":
			stream, err := rc4.NewCipher(keyHandle.key)
			if err != nil {
				ctx.SetReturn(uint64(statusInvalidParameter))
				return 0
			}
			out = make([]byte, len(input))
			stream.XORKeyStream(out, input)
			status = statusSuccess
		default:
			status = statusNotSupported
		}
		if status != statusSuccess {
			ctx.SetReturn(uint64(status))
			return 0
		}

		if pcbResult != 0 {
			ctx.Mem.Write32(pcbResult, uint32(len(out)))
		}
		if pbOutput == 0 {
			ctx.SetReturn(uint64(statusSuccess))
			return 0
		}
		if cbOutput < uint64(len(out)) {
			ctx.SetReturn(uint64(statusBufferTooSmall))
			return 0
		}

		ctx.Mem.WriteBytes(pbOutput, out)
		if pbIV != 0 && len(nextIV) != 0 {
			ctx.Mem.WriteBytes(pbIV, nextIV)
		}
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "BCryptDeriveKeyPBKDF2", func(ctx *ntapi.TrapContext) uint32 {
		hPrf := ctx.Arg(0)
		pbPassword := ctx.Arg(1)
		cbPassword := ctx.Arg(2)
		pbSalt := ctx.Arg(3)
		cbSalt := ctx.Arg(4)
		cIterations := ctx.Arg(5)
		pbDerivedKey := ctx.Arg(6)
		cbDerivedKey := ctx.Arg(7)

		if pbDerivedKey == 0 || cbDerivedKey == 0 || cIterations == 0 {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		bcryptMu.Lock()
		algHandle := bcryptAlgHandles[hPrf]
		bcryptMu.Unlock()
		if algHandle == nil {
			ctx.SetReturn(uint64(statusInvalidHandle))
			return 0
		}

		newHash, _, _, ok := bcryptHashFactory(algHandle.alg)
		if !ok {
			ctx.SetReturn(uint64(statusNotSupported))
			return 0
		}

		password, ok := bcryptReadBytes(ctx, pbPassword, cbPassword)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}
		salt, ok := bcryptReadBytes(ctx, pbSalt, cbSalt)
		if !ok {
			ctx.SetReturn(uint64(statusInvalidParameter))
			return 0
		}

		derived := bcryptPBKDF2(newHash, password, salt, int(cIterations), int(cbDerivedKey))
		ctx.Mem.WriteBytes(pbDerivedKey, derived)
		ctx.SetReturn(uint64(statusSuccess))
		return 0
	})
}
