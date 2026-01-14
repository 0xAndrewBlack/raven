package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	RPC_S_OK                      = 0
	RPC_S_NOT_LISTENING           = 0x000006D1
	RPC_S_NO_BINDINGS             = 0x000006B6
	RPC_S_INVALID_BINDING         = 0x000006A6
	RPC_S_WRONG_KIND_OF_BINDING   = 0x000006AB
	RPC_S_OUT_OF_MEMORY           = 0x0000000E
	RPC_S_INVALID_STRING_UUID     = 0x000006A9
	RPC_C_AUTHN_NONE              = 0
	RPC_C_AUTHN_GSS_NEGOTIATE     = 9
	RPC_C_AUTHN_WINNT             = 10
	RPC_C_AUTHN_LEVEL_DEFAULT     = 0
	RPC_C_AUTHN_LEVEL_NONE        = 1
	RPC_C_AUTHN_LEVEL_CONNECT     = 2
	RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6
)

type rpcState struct {
	mu             sync.Mutex
	nextBinding    uint32
	bindings       map[uint32]*rpcBinding
	interfaces     map[string]*rpcInterface
	threadHandle   uint64
	clientAlloc    uint64
	clientFree     uint64
	cancelTimeout  uint32
	serverStack    uint32
	sequentialSeed uint64
}

type rpcBinding struct {
	protSeq        string
	networkAddr    string
	endpoint       string
	options        string
	objUUID        string
	serverPrinc    string
	authLevel      uint32
	authSvc        uint32
	authzSvc       uint32
	authIdentity   uint64
	bindingOptions map[uint32]uint64
}

type rpcInterface struct {
	uuid     string
	verMajor uint16
	verMinor uint16
}

var rpcGlobal = rpcState{
	nextBinding: 0x6000,
	bindings:    make(map[uint32]*rpcBinding),
	interfaces:  make(map[string]*rpcInterface),
}

func registerRpcrt4Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree

	rpcrt4, ok := hctx.SynthByName["rpcrt4.dll"]
	if !ok {
		return
	}

	allocAnsiString := func(s string) uint64 {
		addr := sharedHeapAlloc(uint64(len(s)+1), true)
		if addr == 0 {
			return 0
		}
		_ = mem.WriteBytes(addr, append([]byte(s), 0))
		return addr
	}
	allocWideString := func(s string) uint64 {
		ws := utf16Encode(s)
		addr := sharedHeapAlloc(uint64((len(ws)+1)*2), true)
		if addr == 0 {
			return 0
		}
		for i, w := range ws {
			_ = mem.Write16(addr+uint64(i)*2, w)
		}
		_ = mem.Write16(addr+uint64(len(ws))*2, 0)
		return addr
	}
	freeIndirectPointer := func(pp uint64) {
		if pp == 0 {
			return
		}
		ptr, _ := mem.Read64(pp)
		if ptr != 0 {
			sharedHeapFree(ptr)
		}
		_ = mem.Write64(pp, 0)
	}
	writeStatus := func(statusPtr uint64, status uint32) {
		if statusPtr != 0 {
			_ = mem.Write32(statusPtr, status)
		}
	}
	setWideStringOut := func(pp uint64, s string) uint32 {
		if pp == 0 {
			return RPC_S_OK
		}
		if s == "" {
			_ = mem.Write64(pp, 0)
			return RPC_S_OK
		}
		addr := allocWideString(s)
		if addr == 0 {
			_ = mem.Write64(pp, 0)
			return RPC_S_OUT_OF_MEMORY
		}
		_ = mem.Write64(pp, addr)
		return RPC_S_OK
	}
	setAnsiStringOut := func(pp uint64, s string) uint32 {
		if pp == 0 {
			return RPC_S_OK
		}
		if s == "" {
			_ = mem.Write64(pp, 0)
			return RPC_S_OK
		}
		addr := allocAnsiString(s)
		if addr == 0 {
			_ = mem.Write64(pp, 0)
			return RPC_S_OUT_OF_MEMORY
		}
		_ = mem.Write64(pp, addr)
		return RPC_S_OK
	}
	guidKey := func(g GUID) string {
		return strings.ToLower(strings.Trim(guidString(g), "{}"))
	}
	guidBytes := func(g GUID) [16]byte {
		var out [16]byte
		binary.LittleEndian.PutUint32(out[0:4], g.Data1)
		binary.LittleEndian.PutUint16(out[4:6], g.Data2)
		binary.LittleEndian.PutUint16(out[6:8], g.Data3)
		copy(out[8:16], g.Data4[:])
		return out
	}
	createUUID := func(sequential bool) (GUID, bool) {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return GUID{}, false
		}
		if sequential {
			rpcGlobal.mu.Lock()
			rpcGlobal.sequentialSeed++
			seq := rpcGlobal.sequentialSeed
			rpcGlobal.mu.Unlock()
			binary.LittleEndian.PutUint64(raw[0:8], uint64(time.Now().UnixNano())^seq)
			raw[6] = (raw[6] & 0x0F) | 0x10
		} else {
			raw[6] = (raw[6] & 0x0F) | 0x40
		}
		raw[8] = (raw[8] & 0x3F) | 0x80
		return GUID{
			Data1: binary.LittleEndian.Uint32(raw[0:4]),
			Data2: binary.LittleEndian.Uint16(raw[4:6]),
			Data3: binary.LittleEndian.Uint16(raw[6:8]),
			Data4: [8]byte(raw[8:16]),
		}, true
	}
	composeBindingString := func(objUUID, protSeq, networkAddr, endpoint, options string) string {
		var b strings.Builder
		if objUUID != "" {
			b.WriteString(strings.Trim(objUUID, "{}"))
			b.WriteByte('@')
		}
		b.WriteString(protSeq)
		b.WriteByte(':')
		b.WriteString(networkAddr)
		if endpoint != "" || options != "" {
			b.WriteByte('[')
			if endpoint != "" {
				b.WriteString(endpoint)
			}
			if options != "" {
				if endpoint != "" {
					b.WriteByte(',')
				}
				b.WriteString(options)
			}
			b.WriteByte(']')
		}
		return b.String()
	}
	parseBindingString := func(s string) (objUUID, protSeq, networkAddr, endpoint, options string) {
		s = strings.TrimSpace(s)
		if at := strings.IndexByte(s, '@'); at >= 0 {
			colon := strings.IndexByte(s, ':')
			if colon == -1 || at < colon {
				objUUID = strings.TrimSpace(s[:at])
				s = s[at+1:]
			}
		}
		head := s
		if lb := strings.IndexByte(s, '['); lb >= 0 {
			head = s[:lb]
			if rb := strings.LastIndexByte(s, ']'); rb > lb {
				inside := s[lb+1 : rb]
				if comma := strings.IndexByte(inside, ','); comma >= 0 {
					endpoint = strings.TrimSpace(inside[:comma])
					options = strings.TrimSpace(inside[comma+1:])
				} else {
					endpoint = strings.TrimSpace(inside)
				}
			}
		}
		if colon := strings.IndexByte(head, ':'); colon >= 0 {
			protSeq = strings.TrimSpace(head[:colon])
			networkAddr = strings.TrimSpace(head[colon+1:])
		} else {
			protSeq = strings.TrimSpace(head)
		}
		return
	}
	allocBinding := func(info *rpcBinding) uint64 {
		rpcGlobal.mu.Lock()
		defer rpcGlobal.mu.Unlock()
		handle := rpcGlobal.nextBinding
		rpcGlobal.nextBinding += 0x10
		clone := *info
		if info.bindingOptions != nil {
			clone.bindingOptions = make(map[uint32]uint64, len(info.bindingOptions))
			for k, v := range info.bindingOptions {
				clone.bindingOptions[k] = v
			}
		} else {
			clone.bindingOptions = make(map[uint32]uint64)
		}
		rpcGlobal.bindings[handle] = &clone
		return uint64(handle)
	}
	getBinding := func(handle uint64) (*rpcBinding, uint32) {
		if handle == 0 {
			return nil, RPC_S_INVALID_BINDING
		}
		rpcGlobal.mu.Lock()
		defer rpcGlobal.mu.Unlock()
		b := rpcGlobal.bindings[uint32(handle)]
		if b == nil {
			return nil, RPC_S_INVALID_BINDING
		}
		return b, RPC_S_OK
	}
	copyBinding := func(src *rpcBinding) *rpcBinding {
		if src == nil {
			return nil
		}
		dst := *src
		dst.bindingOptions = make(map[uint32]uint64, len(src.bindingOptions))
		for k, v := range src.bindingOptions {
			dst.bindingOptions[k] = v
		}
		return &dst
	}
	readInterfaceSpec := func(ifSpec uint64) *rpcInterface {
		if ifSpec == 0 {
			return nil
		}
		g := readGUID(mem, ifSpec+4)
		verMajor, _ := mem.Read16(ifSpec + 20)
		verMinor, _ := mem.Read16(ifSpec + 22)
		return &rpcInterface{
			uuid:     guidKey(g),
			verMajor: verMajor,
			verMinor: verMinor,
		}
	}
	writeEmptyVector := func(pp uint64) uint32 {
		if pp == 0 {
			return RPC_S_OK
		}
		vec := sharedHeapAlloc(16, true)
		if vec == 0 {
			_ = mem.Write64(pp, 0)
			return RPC_S_OUT_OF_MEMORY
		}
		_ = mem.Write32(vec, 0)
		_ = mem.Write64(vec+8, 0)
		_ = mem.Write64(pp, vec)
		return RPC_S_OK
	}
	writeZeroStats := func(pp uint64) uint32 {
		if pp == 0 {
			return RPC_S_OK
		}
		stats := sharedHeapAlloc(32, true)
		if stats == 0 {
			_ = mem.Write64(pp, 0)
			return RPC_S_OUT_OF_MEMORY
		}
		_ = mem.Write64(pp, stats)
		return RPC_S_OK
	}
	setReturnStatus := func(ctx *ntapi.TrapContext, status uint32) uint32 {
		ctx.SetReturn(uint64(status))
		return 0
	}
	setBindingAuth := func(bindingHandle uint64, serverPrinc string, authLevel, authSvc uint32, authIdentity uint64, authzSvc uint32) uint32 {
		b, status := getBinding(bindingHandle)
		if status != RPC_S_OK {
			return status
		}
		rpcGlobal.mu.Lock()
		b.serverPrinc = serverPrinc
		b.authLevel = authLevel
		b.authSvc = authSvc
		b.authIdentity = authIdentity
		b.authzSvc = authzSvc
		rpcGlobal.mu.Unlock()
		return RPC_S_OK
	}

	d.RegisterAutoStubHandler(rpcrt4, "UuidCreate", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		if uuidPtr == 0 {
			return setReturnStatus(ctx, RPC_S_OK)
		}
		g, ok := createUUID(false)
		if !ok {
			return setReturnStatus(ctx, RPC_S_OUT_OF_MEMORY)
		}
		writeGUID(mem, uuidPtr, g)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidCreateSequential", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		if uuidPtr == 0 {
			return setReturnStatus(ctx, RPC_S_OK)
		}
		g, ok := createUUID(true)
		if !ok {
			return setReturnStatus(ctx, RPC_S_OUT_OF_MEMORY)
		}
		writeGUID(mem, uuidPtr, g)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidToStringW", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if uuidPtr == 0 || ppStr == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		g := readGUID(mem, uuidPtr)
		status := setWideStringOut(ppStr, strings.ToLower(strings.Trim(guidString(g), "{}")))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidToStringA", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		ppStr := ctx.Arg(1)
		if uuidPtr == 0 || ppStr == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		g := readGUID(mem, uuidPtr)
		status := setAnsiStringOut(ppStr, strings.ToLower(strings.Trim(guidString(g), "{}")))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidFromStringW", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		uuidPtr := ctx.Arg(1)
		if uuidPtr == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		if strPtr == 0 {
			writeGUID(mem, uuidPtr, GUID{})
			return setReturnStatus(ctx, RPC_S_OK)
		}
		g, ok := parseGUIDString(readGuestUTF16(strPtr))
		if !ok {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		writeGUID(mem, uuidPtr, g)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidFromStringA", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		uuidPtr := ctx.Arg(1)
		if uuidPtr == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		if strPtr == 0 {
			writeGUID(mem, uuidPtr, GUID{})
			return setReturnStatus(ctx, RPC_S_OK)
		}
		g, ok := parseGUIDString(readGuestString(strPtr))
		if !ok {
			return setReturnStatus(ctx, RPC_S_INVALID_STRING_UUID)
		}
		writeGUID(mem, uuidPtr, g)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidCompare", func(ctx *ntapi.TrapContext) uint32 {
		u1 := ctx.Arg(0)
		u2 := ctx.Arg(1)
		statusPtr := ctx.Arg(2)
		writeStatus(statusPtr, RPC_S_OK)
		var cmp int
		if u1 == 0 && u2 == 0 {
			cmp = 0
		} else if u1 == 0 {
			cmp = -1
		} else if u2 == 0 {
			cmp = 1
		} else {
			g1 := guidBytes(readGUID(mem, u1))
			g2 := guidBytes(readGUID(mem, u2))
			cmp = bytes.Compare(g1[:], g2[:])
		}
		switch {
		case cmp < 0:
			ctx.SetReturn(^uint64(0))
		case cmp > 0:
			ctx.SetReturn(1)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidIsNil", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		statusPtr := ctx.Arg(1)
		writeStatus(statusPtr, RPC_S_OK)
		if uuidPtr == 0 || guidEqual(readGUID(mem, uuidPtr), GUID{}) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidEqual", func(ctx *ntapi.TrapContext) uint32 {
		u1 := ctx.Arg(0)
		u2 := ctx.Arg(1)
		statusPtr := ctx.Arg(2)
		writeStatus(statusPtr, RPC_S_OK)
		if u1 == 0 && u2 == 0 {
			ctx.SetReturn(1)
		} else if u1 == 0 || u2 == 0 {
			ctx.SetReturn(0)
		} else if guidEqual(readGUID(mem, u1), readGUID(mem, u2)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "UuidHash", func(ctx *ntapi.TrapContext) uint32 {
		uuidPtr := ctx.Arg(0)
		statusPtr := ctx.Arg(1)
		writeStatus(statusPtr, RPC_S_OK)
		if uuidPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		b := guidBytes(readGUID(mem, uuidPtr))
		h := fnv.New32a()
		_, _ = h.Write(b[:])
		ctx.SetReturn(uint64(h.Sum32() & 0xFFFF))
		return 0
	})

	d.RegisterAutoStubHandler(rpcrt4, "RpcStringFreeW", func(ctx *ntapi.TrapContext) uint32 {
		freeIndirectPointer(ctx.Arg(0))
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringFreeA", func(ctx *ntapi.TrapContext) uint32 {
		freeIndirectPointer(ctx.Arg(0))
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringBindingComposeW", func(ctx *ntapi.TrapContext) uint32 {
		objUUID := readGuestUTF16(ctx.Arg(0))
		protSeq := readGuestUTF16(ctx.Arg(1))
		networkAddr := readGuestUTF16(ctx.Arg(2))
		endpoint := readGuestUTF16(ctx.Arg(3))
		options := readGuestUTF16(ctx.Arg(4))
		ppString := ctx.Arg(5)
		status := setWideStringOut(ppString, composeBindingString(objUUID, protSeq, networkAddr, endpoint, options))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringBindingComposeA", func(ctx *ntapi.TrapContext) uint32 {
		objUUID := readGuestString(ctx.Arg(0))
		protSeq := readGuestString(ctx.Arg(1))
		networkAddr := readGuestString(ctx.Arg(2))
		endpoint := readGuestString(ctx.Arg(3))
		options := readGuestString(ctx.Arg(4))
		ppString := ctx.Arg(5)
		status := setAnsiStringOut(ppString, composeBindingString(objUUID, protSeq, networkAddr, endpoint, options))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringBindingParseW", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestUTF16(ctx.Arg(0))
		objUUID, protSeq, networkAddr, endpoint, options := parseBindingString(s)
		for _, item := range []struct {
			pp uint64
			s  string
		}{
			{ctx.Arg(1), objUUID},
			{ctx.Arg(2), protSeq},
			{ctx.Arg(3), networkAddr},
			{ctx.Arg(4), endpoint},
			{ctx.Arg(5), options},
		} {
			if status := setWideStringOut(item.pp, item.s); status != RPC_S_OK {
				return setReturnStatus(ctx, status)
			}
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcStringBindingParseA", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		objUUID, protSeq, networkAddr, endpoint, options := parseBindingString(s)
		for _, item := range []struct {
			pp uint64
			s  string
		}{
			{ctx.Arg(1), objUUID},
			{ctx.Arg(2), protSeq},
			{ctx.Arg(3), networkAddr},
			{ctx.Arg(4), endpoint},
			{ctx.Arg(5), options},
		} {
			if status := setAnsiStringOut(item.pp, item.s); status != RPC_S_OK {
				return setReturnStatus(ctx, status)
			}
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})

	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingFromStringBindingW", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestUTF16(ctx.Arg(0))
		pBinding := ctx.Arg(1)
		if pBinding == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_BINDING)
		}
		objUUID, protSeq, networkAddr, endpoint, options := parseBindingString(s)
		handle := allocBinding(&rpcBinding{
			objUUID:        objUUID,
			protSeq:        protSeq,
			networkAddr:    networkAddr,
			endpoint:       endpoint,
			options:        options,
			authSvc:        RPC_C_AUTHN_NONE,
			bindingOptions: make(map[uint32]uint64),
		})
		_ = mem.Write64(pBinding, handle)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingFromStringBindingA", func(ctx *ntapi.TrapContext) uint32 {
		s := readGuestString(ctx.Arg(0))
		pBinding := ctx.Arg(1)
		if pBinding == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_BINDING)
		}
		objUUID, protSeq, networkAddr, endpoint, options := parseBindingString(s)
		handle := allocBinding(&rpcBinding{
			objUUID:        objUUID,
			protSeq:        protSeq,
			networkAddr:    networkAddr,
			endpoint:       endpoint,
			options:        options,
			authSvc:        RPC_C_AUTHN_NONE,
			bindingOptions: make(map[uint32]uint64),
		})
		_ = mem.Write64(pBinding, handle)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingFree", func(ctx *ntapi.TrapContext) uint32 {
		pBinding := ctx.Arg(0)
		if pBinding == 0 {
			return setReturnStatus(ctx, RPC_S_OK)
		}
		handle, _ := mem.Read64(pBinding)
		if handle != 0 {
			rpcGlobal.mu.Lock()
			delete(rpcGlobal.bindings, uint32(handle))
			rpcGlobal.mu.Unlock()
		}
		_ = mem.Write64(pBinding, 0)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingSetAuthInfoW", func(ctx *ntapi.TrapContext) uint32 {
		status := setBindingAuth(
			ctx.Arg(0),
			readGuestUTF16(ctx.Arg(1)),
			uint32(ctx.Arg(2)),
			uint32(ctx.Arg(3)),
			ctx.Arg(4),
			uint32(ctx.Arg(5)),
		)
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingSetAuthInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		status := setBindingAuth(
			ctx.Arg(0),
			readGuestUTF16(ctx.Arg(1)),
			uint32(ctx.Arg(2)),
			uint32(ctx.Arg(3)),
			ctx.Arg(4),
			uint32(ctx.Arg(5)),
		)
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingInqAuthInfoW", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		if status := setWideStringOut(ctx.Arg(1), b.serverPrinc); status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		if ctx.Arg(2) != 0 {
			_ = mem.Write32(ctx.Arg(2), b.authLevel)
		}
		if ctx.Arg(3) != 0 {
			_ = mem.Write32(ctx.Arg(3), b.authSvc)
		}
		if ctx.Arg(4) != 0 {
			_ = mem.Write64(ctx.Arg(4), b.authIdentity)
		}
		if ctx.Arg(5) != 0 {
			_ = mem.Write32(ctx.Arg(5), b.authzSvc)
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingSetOption", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		option := uint32(ctx.Arg(1))
		value := ctx.Arg(2)
		rpcGlobal.mu.Lock()
		if b.bindingOptions == nil {
			b.bindingOptions = make(map[uint32]uint64)
		}
		b.bindingOptions[option] = value
		rpcGlobal.mu.Unlock()
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingInqOption", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		option := uint32(ctx.Arg(1))
		pValue := ctx.Arg(2)
		if pValue == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_BINDING)
		}
		var value uint64
		rpcGlobal.mu.Lock()
		value = b.bindingOptions[option]
		rpcGlobal.mu.Unlock()
		_ = mem.Write64(pValue, value)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingCopy", func(ctx *ntapi.TrapContext) uint32 {
		src, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		pDst := ctx.Arg(1)
		if pDst == 0 {
			return setReturnStatus(ctx, RPC_S_INVALID_BINDING)
		}
		handle := allocBinding(copyBinding(src))
		_ = mem.Write64(pDst, handle)
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingToStringBindingW", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		status = setWideStringOut(ctx.Arg(1), composeBindingString(b.objUUID, b.protSeq, b.networkAddr, b.endpoint, b.options))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingToStringBindingA", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		status = setAnsiStringOut(ctx.Arg(1), composeBindingString(b.objUUID, b.protSeq, b.networkAddr, b.endpoint, b.options))
		return setReturnStatus(ctx, status)
	})

	d.RegisterAutoStubHandler(rpcrt4, "RpcServerRegisterIf", func(ctx *ntapi.TrapContext) uint32 {
		iface := readInterfaceSpec(ctx.Arg(0))
		if iface != nil {
			rpcGlobal.mu.Lock()
			rpcGlobal.interfaces[iface.uuid] = iface
			rpcGlobal.mu.Unlock()
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerRegisterIf2", func(ctx *ntapi.TrapContext) uint32 {
		iface := readInterfaceSpec(ctx.Arg(0))
		if iface != nil {
			rpcGlobal.mu.Lock()
			rpcGlobal.interfaces[iface.uuid] = iface
			rpcGlobal.mu.Unlock()
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerRegisterIf3", func(ctx *ntapi.TrapContext) uint32 {
		iface := readInterfaceSpec(ctx.Arg(0))
		if iface != nil {
			rpcGlobal.mu.Lock()
			rpcGlobal.interfaces[iface.uuid] = iface
			rpcGlobal.mu.Unlock()
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerRegisterIfEx", func(ctx *ntapi.TrapContext) uint32 {
		iface := readInterfaceSpec(ctx.Arg(0))
		if iface != nil {
			rpcGlobal.mu.Lock()
			rpcGlobal.interfaces[iface.uuid] = iface
			rpcGlobal.mu.Unlock()
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerUnregisterIf", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 {
			rpcGlobal.mu.Lock()
			rpcGlobal.interfaces = make(map[string]*rpcInterface)
			rpcGlobal.mu.Unlock()
			return setReturnStatus(ctx, RPC_S_OK)
		}
		iface := readInterfaceSpec(ctx.Arg(0))
		if iface != nil {
			rpcGlobal.mu.Lock()
			delete(rpcGlobal.interfaces, iface.uuid)
			rpcGlobal.mu.Unlock()
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerUseProtseqW", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerUseProtseqEpW", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerListen", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtStopServerListening", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtWaitServerListen", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcServerInqBindings", func(ctx *ntapi.TrapContext) uint32 {
		status := writeEmptyVector(ctx.Arg(0))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcEpRegisterW", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcEpUnregister", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})

	for _, name := range []string{"RpcSmAllocate", "NdrOleAllocate", "I_RpcAllocate", "MIDL_user_allocate"} {
		name := name
		d.RegisterAutoStubHandler(rpcrt4, name, func(ctx *ntapi.TrapContext) uint32 {
			size := ctx.Arg(0)
			statusPtr := uint64(0)
			if name == "RpcSmAllocate" || name == "NdrOleAllocate" {
				statusPtr = ctx.Arg(1)
			}
			ptr := sharedHeapAlloc(size, true)
			if statusPtr != 0 {
				if ptr == 0 {
					_ = mem.Write32(statusPtr, RPC_S_OUT_OF_MEMORY)
				} else {
					_ = mem.Write32(statusPtr, RPC_S_OK)
				}
			}
			ctx.SetReturn(ptr)
			return 0
		})
	}
	for _, name := range []string{"RpcSmFree", "NdrOleFree", "I_RpcFree", "MIDL_user_free"} {
		name := name
		d.RegisterAutoStubHandler(rpcrt4, name, func(ctx *ntapi.TrapContext) uint32 {
			sharedHeapFree(ctx.Arg(0))
			if name == "RpcSmFree" || name == "NdrOleFree" {
				ctx.SetReturn(0)
			}
			return 0
		})
	}

	d.RegisterAutoStubHandler(rpcrt4, "RpcImpersonateClient", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcRevertToSelf", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcRevertToSelfEx", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcBindingInqAuthClientW", func(ctx *ntapi.TrapContext) uint32 {
		b, status := getBinding(ctx.Arg(0))
		if status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		if ctx.Arg(1) != 0 {
			_ = mem.Write64(ctx.Arg(1), b.authIdentity)
		}
		if status := setWideStringOut(ctx.Arg(2), b.serverPrinc); status != RPC_S_OK {
			return setReturnStatus(ctx, status)
		}
		if ctx.Arg(3) != 0 {
			level := b.authLevel
			if level == 0 {
				level = RPC_C_AUTHN_LEVEL_CONNECT
			}
			_ = mem.Write32(ctx.Arg(3), level)
		}
		if ctx.Arg(4) != 0 {
			_ = mem.Write32(ctx.Arg(4), b.authSvc)
		}
		if ctx.Arg(5) != 0 {
			_ = mem.Write32(ctx.Arg(5), b.authzSvc)
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})

	d.RegisterAutoStubHandler(rpcrt4, "NdrClientCall2", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrClientCall3", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrServerCall2", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrServerCallAll", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrStubCall2", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrDllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(CLASS_E_CLASSNOTAVAILABLE)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrDllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_FALSE)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrDllRegisterProxy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "NdrDllUnregisterProxy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_OK)
		return 0
	})

	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtSetCancelTimeout", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		rpcGlobal.cancelTimeout = uint32(ctx.Arg(0))
		rpcGlobal.mu.Unlock()
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtIsServerListening", func(ctx *ntapi.TrapContext) uint32 {
		return setReturnStatus(ctx, RPC_S_NOT_LISTENING)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtInqServerPrincNameW", func(ctx *ntapi.TrapContext) uint32 {
		status := setWideStringOut(ctx.Arg(2), "")
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtInqIfIds", func(ctx *ntapi.TrapContext) uint32 {
		status := writeEmptyVector(ctx.Arg(1))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "I_RpcMapWin32Status", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtSetServerStackSize", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		rpcGlobal.serverStack = uint32(ctx.Arg(0))
		rpcGlobal.mu.Unlock()
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcMgmtInqStats", func(ctx *ntapi.TrapContext) uint32 {
		status := writeZeroStats(ctx.Arg(0))
		return setReturnStatus(ctx, status)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcSsGetThreadHandle", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		handle := rpcGlobal.threadHandle
		rpcGlobal.mu.Unlock()
		ctx.SetReturn(handle)
		return 0
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcSsSetThreadHandle", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		rpcGlobal.threadHandle = ctx.Arg(0)
		rpcGlobal.mu.Unlock()
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcSsSetClientAllocFree", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		rpcGlobal.clientAlloc = ctx.Arg(0)
		rpcGlobal.clientFree = ctx.Arg(1)
		rpcGlobal.mu.Unlock()
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcSsGetClientAllocFree", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		allocFn := rpcGlobal.clientAlloc
		freeFn := rpcGlobal.clientFree
		rpcGlobal.mu.Unlock()
		if ctx.Arg(0) != 0 {
			_ = mem.Write64(ctx.Arg(0), allocFn)
		}
		if ctx.Arg(1) != 0 {
			_ = mem.Write64(ctx.Arg(1), freeFn)
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})
	d.RegisterAutoStubHandler(rpcrt4, "RpcSsSwapClientAllocFree", func(ctx *ntapi.TrapContext) uint32 {
		rpcGlobal.mu.Lock()
		oldAlloc := rpcGlobal.clientAlloc
		oldFree := rpcGlobal.clientFree
		rpcGlobal.clientAlloc = ctx.Arg(0)
		rpcGlobal.clientFree = ctx.Arg(1)
		rpcGlobal.mu.Unlock()
		if ctx.Arg(2) != 0 {
			_ = mem.Write64(ctx.Arg(2), oldAlloc)
		}
		if ctx.Arg(3) != 0 {
			_ = mem.Write64(ctx.Arg(3), oldFree)
		}
		return setReturnStatus(ctx, RPC_S_OK)
	})

	_ = fmt.Sprintf
}
