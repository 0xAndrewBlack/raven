package main

import (
	"encoding/binary"
	"fmt"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"golang.org/x/sys/unix"
)

const (
	S_OK                      = 0x00000000
	S_FALSE                   = 0x00000001
	E_NOTIMPL                 = 0x80004001
	E_NOINTERFACE             = 0x80004002
	E_POINTER                 = 0x80004003
	E_FAIL                    = 0x80004005
	E_OUTOFMEMORY             = 0x8007000E
	E_INVALIDARG              = 0x80070057
	CLASS_E_NOAGGREGATION     = 0x80040110
	CLASS_E_CLASSNOTAVAILABLE = 0x80040111
	REGDB_E_CLASSNOTREG       = 0x80040154
	CO_E_CLASSSTRING          = 0x800401F3
	RPC_E_CHANGED_MODE        = 0x80010106

	COINIT_MULTITHREADED     = 0x0
	COINIT_APARTMENTTHREADED = 0x2

	comTrapIDBase = 0x10000000
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	IID_IUnknown      = GUID{0x00000000, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IClassFactory = GUID{0x00000001, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IDispatch     = GUID{0x00020400, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IMalloc       = GUID{0x00000002, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IStream       = GUID{0x0000000C, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}

	CLSID_StdComponentCategoriesMgr = GUID{0x0002E005, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

type hresultError uint32

func (e hresultError) Error() string {
	return fmt.Sprintf("HRESULT 0x%08X", uint32(e))
}

type comObject struct {
	clsid         GUID
	primaryIID    GUID
	refCount      int32
	vtableAddr    uint64
	objectAddr    uint64
	kind          string
	supportedIIDs map[GUID]bool
	data          interface{}
}

type classFactory struct {
	clsid  GUID
	create func(iid GUID) (*comObject, error)
}

type registeredClassObject struct {
	clsid        GUID
	unkPtr       uint64
	dwClsContext uint32
	flags        uint32
}

type comState struct {
	initialized   bool
	initCount     int32
	apartmentType uint32

	classFactories      map[GUID]*classFactory
	registeredFactories map[uint32]*registeredClassObject
	objects             map[uint64]*comObject
	nextHandle          uint64
	nextTrapID          uint32
	taskAllocs          map[uint64]uint64
	bstrAllocs          map[uint64]uint64
	mem                 *mmu.MMU
	disp                *ntapi.Dispatcher
	heapAlloc           func(uint64, bool) uint64
	heapFree            func(uint64)
	regHive             *ntapi.RegistryHive
	progIDs             map[string]GUID
}

func newCOMState(hctx *HandlerCtx) *comState {
	cs := &comState{
		apartmentType:       COINIT_APARTMENTTHREADED,
		classFactories:      make(map[GUID]*classFactory),
		registeredFactories: make(map[uint32]*registeredClassObject),
		objects:             make(map[uint64]*comObject),
		nextHandle:          1,
		nextTrapID:          comTrapIDBase,
		taskAllocs:          make(map[uint64]uint64),
		bstrAllocs:          make(map[uint64]uint64),
		mem:                 hctx.Mem,
		disp:                hctx.Disp,
		heapAlloc:           hctx.HeapAlloc,
		heapFree:            hctx.HeapFree,
		regHive:             hctx.RegHive,
		progIDs:             make(map[string]GUID),
	}
	cs.classFactories[CLSID_StdComponentCategoriesMgr] = &classFactory{
		clsid: CLSID_StdComponentCategoriesMgr,
		create: func(iid GUID) (*comObject, error) {
			var methods int
			switch {
			case guidEqual(iid, IID_IUnknown):
				methods = 3
			case guidEqual(iid, IID_IDispatch):
				methods = 7
			default:
				return nil, hresultError(E_NOINTERFACE)
			}
			obj, err := cs.createGuestObject(cs.mem, iid, methods)
			if err != nil {
				return nil, err
			}
			obj.clsid = CLSID_StdComponentCategoriesMgr
			if guidEqual(iid, IID_IDispatch) {
				obj.kind = "idispatch"
				obj.supportedIIDs[IID_IDispatch] = true
			}
			return obj, nil
		},
	}
	return cs
}

func readGUID(mem *mmu.MMU, addr uint64) GUID {
	data, err := mem.ReadBytes(addr, 16)
	if err != nil || len(data) < 16 {
		var tmp [16]byte
		copy(tmp[:], data)
		data = tmp[:]
	}
	return GUID{
		Data1: binary.LittleEndian.Uint32(data[0:4]),
		Data2: binary.LittleEndian.Uint16(data[4:6]),
		Data3: binary.LittleEndian.Uint16(data[6:8]),
		Data4: [8]byte(data[8:16]),
	}
}

func writeGUID(mem *mmu.MMU, addr uint64, g GUID) {
	var data [16]byte
	binary.LittleEndian.PutUint32(data[0:4], g.Data1)
	binary.LittleEndian.PutUint16(data[4:6], g.Data2)
	binary.LittleEndian.PutUint16(data[6:8], g.Data3)
	copy(data[8:16], g.Data4[:])
	mem.WriteBytes(addr, data[:])
}

func guidEqual(a, b GUID) bool {
	return a == b
}

func guidString(g GUID) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

func parseGUIDString(s string) (GUID, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return GUID{}, false
	}
	if !strings.HasPrefix(s, "{") {
		s = "{" + s
	}
	if !strings.HasSuffix(s, "}") {
		s = s + "}"
	}
	var g GUID
	n, _ := fmt.Sscanf(s, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		&g.Data1, &g.Data2, &g.Data3,
		&g.Data4[0], &g.Data4[1], &g.Data4[2], &g.Data4[3],
		&g.Data4[4], &g.Data4[5], &g.Data4[6], &g.Data4[7])
	return g, n == 11
}

func decodeUTF16LEString(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var sb strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		w := binary.LittleEndian.Uint16(data[i : i+2])
		if w == 0 {
			break
		}
		sb.WriteRune(rune(w))
	}
	return sb.String()
}

func hresultFromError(err error) uint32 {
	if err == nil {
		return S_OK
	}
	if hr, ok := err.(hresultError); ok {
		return uint32(hr)
	}
	return E_FAIL
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (cs *comState) initialize(apartmentType uint32) uint32 {
	if cs.initialized {
		if cs.apartmentType != apartmentType {
			return RPC_E_CHANGED_MODE
		}
		cs.initCount++
		return S_FALSE
	}
	cs.initialized = true
	cs.initCount = 1
	cs.apartmentType = apartmentType
	return S_OK
}

func (cs *comState) uninitialize() {
	if cs.initCount > 0 {
		cs.initCount--
	}
	if cs.initCount == 0 {
		cs.initialized = false
		cs.apartmentType = COINIT_APARTMENTTHREADED
	}
}

func (cs *comState) allocTaskMem(size uint64, zeroInit bool) uint64 {
	if size == 0 {
		size = 1
	}
	ptr := cs.heapAlloc(size, zeroInit)
	if ptr != 0 {
		cs.taskAllocs[ptr] = size
	}
	return ptr
}

func (cs *comState) freeTaskMem(ptr uint64) {
	if ptr == 0 {
		return
	}
	delete(cs.taskAllocs, ptr)
	cs.heapFree(ptr)
}

func (cs *comState) reallocTaskMem(ptr, size uint64) uint64 {
	if ptr == 0 {
		return cs.allocTaskMem(size, false)
	}
	if size == 0 {
		cs.freeTaskMem(ptr)
		return 0
	}
	newPtr := cs.allocTaskMem(size, false)
	if newPtr == 0 {
		return 0
	}
	oldSize := cs.taskAllocs[ptr]
	if oldSize == 0 {
		oldSize = size
	}
	if oldSize > 0 {
		if data, err := cs.mem.ReadBytes(ptr, int(minU64(size, oldSize))); err == nil {
			cs.mem.WriteBytes(newPtr, data)
		}
	}
	cs.freeTaskMem(ptr)
	return newPtr
}

func (cs *comState) allocBSTRChars(src uint64, chars uint64) uint64 {
	base := cs.heapAlloc(4+chars*2+2, true)
	if base == 0 {
		return 0
	}
	cs.mem.Write32(base, uint32(chars*2))
	for i := uint64(0); i < chars; i++ {
		w, _ := cs.mem.Read16(src + i*2)
		cs.mem.Write16(base+4+i*2, w)
	}
	cs.mem.Write16(base+4+chars*2, 0)
	bstr := base + 4
	cs.bstrAllocs[bstr] = base
	return bstr
}

func (cs *comState) allocBSTRByteLen(src uint64, byteLen uint64) uint64 {
	base := cs.heapAlloc(4+byteLen+2, true)
	if base == 0 {
		return 0
	}
	cs.mem.Write32(base, uint32(byteLen))
	for i := uint64(0); i < byteLen; i++ {
		b, _ := cs.mem.Read8(src + i)
		cs.mem.Write8(base+4+i, b)
	}
	bstr := base + 4
	cs.bstrAllocs[bstr] = base
	return bstr
}

func (cs *comState) freeBSTR(bstr uint64) {
	if bstr == 0 {
		return
	}
	if base, ok := cs.bstrAllocs[bstr]; ok {
		delete(cs.bstrAllocs, bstr)
		cs.heapFree(base)
	}
}

func (cs *comState) createGuestObject(mem *mmu.MMU, iid GUID, methods int) (*comObject, error) {
	if methods < 3 {
		methods = 3
	}
	totalSize := uint64(8 + methods*8 + methods*16)
	objAddr := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if objAddr == 0 {
		return nil, hresultError(E_OUTOFMEMORY)
	}
	vtableAddr := objAddr + 8
	stubBase := vtableAddr + uint64(methods*8)
	obj := &comObject{
		primaryIID:    iid,
		refCount:      1,
		vtableAddr:    vtableAddr,
		objectAddr:    objAddr,
		kind:          "iunknown",
		supportedIIDs: map[GUID]bool{IID_IUnknown: true, iid: true},
	}
	cs.objects[objAddr] = obj
	for i := 0; i < methods; i++ {
		trapID := cs.nextTrapID
		cs.nextTrapID++
		methodIndex := i
		cs.disp.RegisterHandler(trapID, fmt.Sprintf("com!%s[%d]", guidString(iid), methodIndex), func(ctx *ntapi.TrapContext) uint32 {
			return cs.dispatchObjectMethod(ctx, methodIndex)
		})
		stubAddr := stubBase + uint64(i*16)
		code := make([]byte, 16)
		code[0] = 0xB8
		binary.LittleEndian.PutUint32(code[1:5], trapID)
		code[5] = 0x0F
		code[6] = 0x01
		code[7] = 0xC1
		code[8] = 0xC3
		for j := 9; j < len(code); j++ {
			code[j] = 0xCC
		}
		mem.WriteBytes(stubAddr, code)
		mem.Write64(vtableAddr+uint64(i*8), stubAddr)
	}
	mem.Write64(objAddr, vtableAddr)
	return obj, nil
}

func (cs *comState) createClassFactoryObject(cf *classFactory) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IClassFactory, 5)
	if err != nil {
		return nil, err
	}
	obj.clsid = cf.clsid
	obj.kind = "class-factory"
	obj.data = cf
	obj.supportedIIDs[IID_IClassFactory] = true
	return obj, nil
}

func (cs *comState) createIMallocObject() (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IMalloc, 9)
	if err != nil {
		return nil, err
	}
	obj.kind = "imalloc"
	obj.supportedIIDs[IID_IMalloc] = true
	return obj, nil
}

func (cs *comState) addRef(obj *comObject) uint32 {
	obj.refCount++
	return uint32(obj.refCount)
}

func (cs *comState) release(obj *comObject) uint32 {
	if obj.refCount > 0 {
		obj.refCount--
	}
	if obj.refCount == 0 {
		delete(cs.objects, obj.objectAddr)
	}
	return uint32(obj.refCount)
}

func (cs *comState) queryInterface(ctx *ntapi.TrapContext, obj *comObject) uint32 {
	riidPtr := ctx.Arg(1)
	ppv := ctx.Arg(2)
	if ppv == 0 {
		return E_POINTER
	}
	ctx.Mem.Write64(ppv, 0)
	if riidPtr == 0 {
		return E_POINTER
	}
	iid := readGUID(ctx.Mem, riidPtr)
	if obj.supportedIIDs[iid] || guidEqual(iid, IID_IUnknown) {
		ctx.Mem.Write64(ppv, obj.objectAddr)
		cs.addRef(obj)
		return S_OK
	}
	return E_NOINTERFACE
}

func (cs *comState) dispatchIDispatch(ctx *ntapi.TrapContext, method int) uint32 {
	switch method {
	case 3:
		pctinfo := ctx.Arg(1)
		if pctinfo != 0 {
			ctx.Mem.Write32(pctinfo, 0)
		}
		return S_OK
	case 4, 5, 6:
		return E_NOTIMPL
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchClassFactory(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch method {
	case 3:
		pUnkOuter := ctx.Arg(1)
		riidPtr := ctx.Arg(2)
		ppv := ctx.Arg(3)
		if ppv == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppv, 0)
		if riidPtr == 0 {
			return E_POINTER
		}
		if pUnkOuter != 0 {
			return CLASS_E_NOAGGREGATION
		}
		cf, _ := obj.data.(*classFactory)
		if cf == nil {
			return E_FAIL
		}
		newObj, err := cf.create(readGUID(ctx.Mem, riidPtr))
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppv, newObj.objectAddr)
		return S_OK
	case 4:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchIMalloc(ctx *ntapi.TrapContext, method int) uint32 {
	switch method {
	case 3:
		ctx.SetReturn(cs.allocTaskMem(ctx.Arg(1), false))
		return 0
	case 4:
		ctx.SetReturn(cs.reallocTaskMem(ctx.Arg(1), ctx.Arg(2)))
		return 0
	case 5:
		cs.freeTaskMem(ctx.Arg(1))
		return 0
	case 6:
		ctx.SetReturn(cs.taskAllocs[ctx.Arg(1)])
		return 0
	case 7:
		if _, ok := cs.taskAllocs[ctx.Arg(1)]; ok {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	case 8:
		return 0
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchObjectMethod(ctx *ntapi.TrapContext, method int) uint32 {
	obj := cs.objects[ctx.Arg(0)]
	if obj == nil {
		return E_POINTER
	}
	switch method {
	case 0:
		return cs.queryInterface(ctx, obj)
	case 1:
		ctx.SetReturn(uint64(cs.addRef(obj)))
		return 0
	case 2:
		ctx.SetReturn(uint64(cs.release(obj)))
		return 0
	}
	switch obj.kind {
	case "class-factory":
		return cs.dispatchClassFactory(ctx, obj, method)
	case "imalloc":
		return cs.dispatchIMalloc(ctx, method)
	case "idispatch":
		return cs.dispatchIDispatch(ctx, method)
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) instantiate(clsid, iid GUID) (*comObject, uint32) {
	cf, ok := cs.classFactories[clsid]
	if !ok {
		return nil, CLASS_E_CLASSNOTAVAILABLE
	}
	obj, err := cf.create(iid)
	if err != nil {
		return nil, hresultFromError(err)
	}
	return obj, S_OK
}

func (cs *comState) findRegisteredFactory(clsid GUID) *registeredClassObject {
	for _, reg := range cs.registeredFactories {
		if guidEqual(reg.clsid, clsid) {
			return reg
		}
	}
	return nil
}

func (cs *comState) lookupProgID(progID string) (GUID, bool) {
	if g, ok := cs.progIDs[strings.ToLower(strings.TrimSpace(progID))]; ok {
		return g, true
	}
	if cs.regHive == nil {
		return GUID{}, false
	}
	key := cs.regHive.OpenKey(`HKEY_CLASSES_ROOT\` + progID + `\CLSID`)
	if key == nil || key.Values == nil {
		return GUID{}, false
	}
	if val, ok := key.Values[""]; ok {
		return parseGUIDString(decodeUTF16LEString(val.Data))
	}
	return GUID{}, false
}

func registerOle32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestUTF16 := hctx.ReadGuestUTF16
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	ole32, ok := hctx.SynthByName["ole32.dll"]
	if !ok {
		return
	}
	sharedHeapAlloc := hctx.HeapAlloc
	var nextLuid uint32 = 2000
	_ = sharedHeapAlloc
	_ = nextLuid
	_ = ole32

	d.RegisterAutoStubHandler(ole32, "CoInitialize", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.initialize(COINIT_APARTMENTTHREADED)))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoInitializeEx", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.initialize(uint32(ctx.Arg(1)))))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoInitializeSecurity", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateInstance", func(ctx *ntapi.TrapContext) uint32 {
		rclsid := ctx.Arg(0)
		pUnkOuter := ctx.Arg(1)
		_ = ctx.Arg(2) // dwClsContext
		riid := ctx.Arg(3)
		ppv := ctx.Arg(4)
		if ppv == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppv, 0)
		if rclsid == 0 || riid == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		obj, hr := cs.instantiate(readGUID(ctx.Mem, rclsid), readGUID(ctx.Mem, riid))
		if hr != S_OK {
			ctx.SetReturn(uint64(hr))
			return 0
		}
		ctx.Mem.Write64(ppv, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateInstanceEx", func(ctx *ntapi.TrapContext) uint32 {
		rclsid := ctx.Arg(0)
		pUnkOuter := ctx.Arg(1)
		_ = ctx.Arg(2) // dwClsContext
		_ = ctx.Arg(3) // pServerInfo
		cmq := ctx.Arg(4)
		pResults := ctx.Arg(5)
		if pResults == 0 || cmq == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		var overall uint32 = S_OK
		for i := uint64(0); i < cmq; i++ {
			entry := pResults + i*24
			pIID, _ := ctx.Mem.Read64(entry)
			ctx.Mem.Write64(entry+8, 0)
			ctx.Mem.Write32(entry+16, E_NOINTERFACE)
			if pIID == 0 {
				overall = E_POINTER
				continue
			}
			var hr uint32
			if pUnkOuter != 0 {
				hr = CLASS_E_NOAGGREGATION
			} else {
				obj, createHR := cs.instantiate(readGUID(ctx.Mem, rclsid), readGUID(ctx.Mem, pIID))
				hr = createHR
				if createHR == S_OK {
					ctx.Mem.Write64(entry+8, obj.objectAddr)
				}
			}
			ctx.Mem.Write32(entry+16, hr)
			if hr != S_OK && overall == S_OK {
				overall = hr
			}
		}
		ctx.SetReturn(uint64(overall))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StringFromGUID2", func(ctx *ntapi.TrapContext) uint32 {
		guidPtr := ctx.Arg(0)
		outPtr := ctx.Arg(1)
		cchMax := int(ctx.Arg(2))
		if guidPtr == 0 || outPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		guidText := guidString(readGUID(ctx.Mem, guidPtr))
		ws := utf16Encode(guidText)
		if cchMax < len(ws)+1 {
			ctx.SetReturn(0)
			return 0
		}
		for i, w := range ws {
			ctx.Mem.Write16(outPtr+uint64(i)*2, w)
		}
		ctx.Mem.Write16(outPtr+uint64(len(ws))*2, 0)
		ctx.SetReturn(uint64(len(ws) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLSIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		clsidPtr := ctx.Arg(1)
		if clsidPtr == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if strPtr == 0 {
			writeGUID(ctx.Mem, clsidPtr, GUID{})
			ctx.SetReturn(S_OK)
			return 0
		}
		g, ok := parseGUIDString(readGuestUTF16(strPtr))
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		writeGUID(ctx.Mem, clsidPtr, g)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLSIDFromProgID", func(ctx *ntapi.TrapContext) uint32 {
		progIDPtr := ctx.Arg(0)
		clsidPtr := ctx.Arg(1)
		if clsidPtr == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if progIDPtr == 0 {
			writeGUID(ctx.Mem, clsidPtr, GUID{})
			ctx.SetReturn(uint64(CO_E_CLASSSTRING))
			return 0
		}
		g, ok := cs.lookupProgID(readGuestUTF16(progIDPtr))
		if !ok {
			writeGUID(ctx.Mem, clsidPtr, GUID{})
			ctx.SetReturn(uint64(CO_E_CLASSSTRING))
			return 0
		}
		writeGUID(ctx.Mem, clsidPtr, g)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StringFromCLSID", func(ctx *ntapi.TrapContext) uint32 {
		guidPtr := ctx.Arg(0)
		ppszOut := ctx.Arg(1)
		if guidPtr == 0 || ppszOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ws := utf16Encode(guidString(readGUID(ctx.Mem, guidPtr)))
		addr := cs.allocTaskMem(uint64(len(ws)+1)*2, true)
		if addr == 0 {
			ctx.SetReturn(uint64(E_OUTOFMEMORY))
			return 0
		}
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		ctx.Mem.Write64(ppszOut, addr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IIDFromString", func(ctx *ntapi.TrapContext) uint32 {
		strPtr := ctx.Arg(0)
		iidPtr := ctx.Arg(1)
		if iidPtr == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if strPtr == 0 {
			writeGUID(ctx.Mem, iidPtr, GUID{})
			ctx.SetReturn(S_OK)
			return 0
		}
		g, ok := parseGUIDString(readGuestUTF16(strPtr))
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		writeGUID(ctx.Mem, iidPtr, g)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IsEqualGUID", func(ctx *ntapi.TrapContext) uint32 {
		g1 := ctx.Arg(0)
		g2 := ctx.Arg(1)
		if g1 == 0 || g2 == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if guidEqual(readGUID(ctx.Mem, g1), readGUID(ctx.Mem, g2)) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
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
		cs.uninitialize()
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemAlloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(cs.allocTaskMem(ctx.Arg(0), true))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemFree", func(ctx *ntapi.TrapContext) uint32 {
		cs.freeTaskMem(ctx.Arg(0))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTaskMemRealloc", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(cs.reallocTaskMem(ctx.Arg(0), ctx.Arg(1)))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleInitialize", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.initialize(COINIT_APARTMENTTHREADED)))
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleUninitialize", func(ctx *ntapi.TrapContext) uint32 {
		cs.uninitialize()
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
	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing ole32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(ole32, "BindMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] BindMoniker p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLIPFORMAT_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CLIPFORMAT_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLIPFORMAT_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CLIPFORMAT_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLIPFORMAT_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CLIPFORMAT_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLIPFORMAT_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CLIPFORMAT_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CLSIDFromProgIDEx", func(ctx *ntapi.TrapContext) uint32 {
		progIDPtr := ctx.Arg(0)
		clsidPtr := ctx.Arg(1)
		ravelog.Logf("[ole32] CLSIDFromProgIDEx p0=0x%x, p1=0x%x\n", progIDPtr, clsidPtr)
		if clsidPtr == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if progIDPtr == 0 {
			writeGUID(ctx.Mem, clsidPtr, GUID{})
			ctx.SetReturn(uint64(CO_E_CLASSSTRING))
			return 0
		}
		g, ok := cs.lookupProgID(readGuestUTF16(progIDPtr))
		if !ok {
			writeGUID(ctx.Mem, clsidPtr, GUID{})
			ctx.SetReturn(uint64(CO_E_CLASSSTRING))
			return 0
		}
		writeGUID(ctx.Mem, clsidPtr, g)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoAddRefServerProcess", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoAddRefServerProcess()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoAllowSetForegroundWindow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoAllowSetForegroundWindow p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoBuildVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoBuildVersion()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCancelCall", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoCancelCall p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCopyProxy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoCopyProxy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateFreeThreadedMarshaler", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoCreateFreeThreadedMarshaler p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoCreateInstanceFromApp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoCreateInstanceFromApp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoDecrementMTAUsage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoDecrementMTAUsage p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoDisableCallCancellation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoDisableCallCancellation p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoDisconnectObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoDisconnectObject p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoDosDateTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoDosDateTimeToFileTime p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoEnableCallCancellation", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoEnableCallCancellation p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFileTimeNow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoFileTimeNow p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFileTimeToDosDateTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoFileTimeToDosDateTime p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFreeAllLibraries", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoFreeAllLibraries()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoFreeLibrary\n")
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFreeUnusedLibraries", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoFreeUnusedLibraries()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoFreeUnusedLibrariesEx", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoFreeUnusedLibrariesEx\n")
		ctx.SetReturn(0) // void
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetActivationState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoGetActivationState p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetApartmentType", func(ctx *ntapi.TrapContext) uint32 {
		pAptType := ctx.Arg(0)
		pAptQualifier := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetApartmentType\n")
		if pAptType != 0 {
			ctx.Mem.Write32(pAptType, 0)
		} // APTTYPE_STA
		if pAptQualifier != 0 {
			ctx.Mem.Write32(pAptQualifier, 0)
		} // APTTYPEQUALIFIER_NONE
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCallContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetCallContext p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCallState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetCallState p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCallerTID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoGetCallerTID p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCancelObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoGetCancelObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		rclsid := ctx.Arg(0)
		dwClsContext := ctx.Arg(1)
		pvReserved := ctx.Arg(2)
		riid := ctx.Arg(3)
		ppv := ctx.Arg(4)
		_ = pvReserved
		ravelog.Logf("[ole32] CoGetClassObject clsid=%s ctx=0x%x iid=%s\n",
			readGUIDString(ctx.Mem, rclsid), dwClsContext, readGUIDString(ctx.Mem, riid))
		if ppv == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppv, 0)
		if riid == 0 || rclsid == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		iid := readGUID(ctx.Mem, riid)
		if !guidEqual(iid, IID_IClassFactory) && !guidEqual(iid, IID_IUnknown) {
			ctx.SetReturn(uint64(E_NOINTERFACE))
			return 0
		}
		clsid := readGUID(ctx.Mem, rclsid)
		if reg := cs.findRegisteredFactory(clsid); reg != nil {
			ctx.Mem.Write64(ppv, reg.unkPtr)
			ctx.SetReturn(S_OK)
			return 0
		}
		cf, ok := cs.classFactories[clsid]
		if !ok {
			ctx.SetReturn(uint64(REGDB_E_CLASSNOTREG))
			return 0
		}
		obj, err := cs.createClassFactoryObject(cf)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppv, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetContextToken", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoGetContextToken p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCurrentLogicalThreadId", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoGetCurrentLogicalThreadId p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetCurrentProcess", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoGetCurrentProcess()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetDefaultContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoGetDefaultContext p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetInstanceFromFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoGetInstanceFromFile p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetInstanceFromIStorage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoGetInstanceFromIStorage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetInterfaceAndReleaseStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoGetInterfaceAndReleaseStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetMalloc", func(ctx *ntapi.TrapContext) uint32 {
		dwMemContext := ctx.Arg(0)
		ppMalloc := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetMalloc ctx=%d out=0x%x\n", dwMemContext, ppMalloc)
		if ppMalloc == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppMalloc, 0)
		obj, err := cs.createIMallocObject()
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppMalloc, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetMarshalSizeMax", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoGetMarshalSizeMax p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] CoGetObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetObjectContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetObjectContext p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetPSClsid", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetPSClsid p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetStandardMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoGetStandardMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoGetState p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoGetTreatAsClass", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoGetTreatAsClass p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoImpersonateClient", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoImpersonateClient()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoIncrementMTAUsage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoIncrementMTAUsage p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoInitializeWOW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoInitializeWOW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoIsHandlerConnected", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoIsHandlerConnected p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoIsOle1Class", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoIsOle1Class p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoLoadLibrary", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoLoadLibrary p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoLockObjectExternal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoLockObjectExternal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoMarshalHresult", func(ctx *ntapi.TrapContext) uint32 {
		pstm := ctx.Arg(0)
		hrresult := ctx.Arg(1)
		ravelog.Logf("[ole32] CoMarshalHresult stm=0x%x hr=0x%x\n", pstm, hrresult)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoMarshalInterThreadInterfaceInStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoMarshalInterThreadInterfaceInStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoMarshalInterface", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoMarshalInterface p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoQueryClientBlanket", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoQueryClientBlanket p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoQueryProxyBlanket", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoQueryProxyBlanket p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterChannelHook", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoRegisterChannelHook p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterClassObject", func(ctx *ntapi.TrapContext) uint32 {
		rclsid := ctx.Arg(0)
		pUnk := ctx.Arg(1)
		dwClsContext := uint32(ctx.Arg(2))
		flags := uint32(ctx.Arg(3))
		lpdwRegister := ctx.Arg(4)
		ravelog.Logf("[ole32] CoRegisterClassObject clsid=%s unk=0x%x ctx=0x%x flags=0x%x\n",
			readGUIDString(ctx.Mem, rclsid), pUnk, dwClsContext, flags)
		if rclsid == 0 || lpdwRegister == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		cookie := uint32(cs.nextHandle)
		cs.nextHandle++
		cs.registeredFactories[cookie] = &registeredClassObject{
			clsid:        readGUID(ctx.Mem, rclsid),
			unkPtr:       pUnk,
			dwClsContext: dwClsContext,
			flags:        flags,
		}
		ctx.Mem.Write32(lpdwRegister, cookie)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterInitializeSpy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoRegisterInitializeSpy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterMallocSpy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoRegisterMallocSpy p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterMessageFilter", func(ctx *ntapi.TrapContext) uint32 {
		lpMessageFilter := ctx.Arg(0)
		lplpMessageFilter := ctx.Arg(1)
		ravelog.Logf("[ole32] CoRegisterMessageFilter new=0x%x old=0x%x\n", lpMessageFilter, lplpMessageFilter)
		if lplpMessageFilter != 0 {
			ctx.Mem.Write64(lplpMessageFilter, 0)
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterPSClsid", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoRegisterPSClsid p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterSurrogate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoRegisterSurrogate p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRegisterSurrogateEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoRegisterSurrogateEx p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoReleaseMarshalData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoReleaseMarshalData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoReleaseServerProcess", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoReleaseServerProcess()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoResumeClassObjects", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoResumeClassObjects()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRevertToSelf", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoRevertToSelf()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRevokeClassObject", func(ctx *ntapi.TrapContext) uint32 {
		cookie := uint32(ctx.Arg(0))
		ravelog.Logf("[ole32] CoRevokeClassObject p0=0x%x\n", cookie)
		delete(cs.registeredFactories, cookie)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRevokeInitializeSpy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoRevokeInitializeSpy p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoRevokeMallocSpy", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoRevokeMallocSpy()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoSetProxyBlanket", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] CoSetProxyBlanket p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoSetState", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CoSetState p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoSuspendClassObjects", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] CoSuspendClassObjects()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoSwitchCallContext", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoSwitchCallContext p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoTreatAsClass", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CoTreatAsClass p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoUnmarshalHresult", func(ctx *ntapi.TrapContext) uint32 {
		pstm := ctx.Arg(0)
		phrresult := ctx.Arg(1)
		ravelog.Logf("[ole32] CoUnmarshalHresult stm=0x%x out=0x%x\n", pstm, phrresult)
		if phrresult != 0 {
			ctx.Mem.Write32(phrresult, 0)
		} // S_OK
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoUnmarshalInterface", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CoUnmarshalInterface p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CoWaitForMultipleHandles", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[ole32] CoWaitForMultipleHandles p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateAntiMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CreateAntiMoniker p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateBindCtx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CreateBindCtx p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateClassMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CreateClassMoniker p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateDataAdviseHolder", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CreateDataAdviseHolder p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateDataCache", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] CreateDataCache p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CreateErrorInfo p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateFileMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CreateFileMoniker p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateGenericComposite", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CreateGenericComposite p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateILockBytesOnHGlobal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CreateILockBytesOnHGlobal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateItemMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] CreateItemMoniker p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateObjrefMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CreateObjrefMoniker p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreateOleAdviseHolder", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] CreateOleAdviseHolder p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "CreatePointerMoniker", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] CreatePointerMoniker p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DestroyRunningObjectTable", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] DestroyRunningObjectTable()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DllDebugObjectRPCHook", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] DllDebugObjectRPCHook p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] DllGetClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DllRegisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] DllRegisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "DllUnregisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] DllUnregisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "FmtIdToPropStgName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] FmtIdToPropStgName p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "FreePropVariantArray", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] FreePropVariantArray p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetClassFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] GetClassFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetConvertStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] GetConvertStg p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] GetErrorInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetHGlobalFromILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] GetHGlobalFromILockBytes p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetHGlobalFromStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] GetHGlobalFromStream p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetRunningObjectTable", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] GetRunningObjectTable p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HACCEL_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HACCEL_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HACCEL_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HACCEL_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HACCEL_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HACCEL_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HACCEL_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HACCEL_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBITMAP_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HBITMAP_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBITMAP_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBITMAP_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBITMAP_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBITMAP_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBITMAP_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBITMAP_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBRUSH_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HBRUSH_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBRUSH_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBRUSH_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBRUSH_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBRUSH_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HBRUSH_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HBRUSH_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HDC_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HDC_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HDC_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HDC_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HDC_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HDC_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HDC_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HDC_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HENHMETAFILE_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HENHMETAFILE_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HENHMETAFILE_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HENHMETAFILE_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HENHMETAFILE_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HENHMETAFILE_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HENHMETAFILE_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HENHMETAFILE_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HGLOBAL_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HGLOBAL_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HGLOBAL_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HGLOBAL_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HGLOBAL_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HGLOBAL_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HGLOBAL_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HGLOBAL_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HICON_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HICON_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HICON_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HICON_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HICON_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HICON_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HICON_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HICON_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMENU_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HMENU_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMENU_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMENU_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMENU_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMENU_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMENU_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMENU_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILEPICT_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HMETAFILEPICT_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILEPICT_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILEPICT_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILEPICT_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILEPICT_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILEPICT_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILEPICT_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILE_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HMETAFILE_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILE_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILE_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILE_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILE_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HMETAFILE_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HMETAFILE_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HPALETTE_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HPALETTE_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HPALETTE_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HPALETTE_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HPALETTE_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HPALETTE_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HPALETTE_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HPALETTE_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HWND_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] HWND_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HWND_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HWND_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HWND_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HWND_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "HWND_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] HWND_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IsAccelerator", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] IsAccelerator p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "IsValidInterface", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] IsValidInterface p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "MkParseDisplayName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] MkParseDisplayName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "MonikerCommonPrefixWith", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] MonikerCommonPrefixWith p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "Ole32DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] Ole32DllGetClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleBuildVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] OleBuildVersion()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleConvertIStorageToOLESTREAM", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleConvertIStorageToOLESTREAM p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleConvertIStorageToOLESTREAMEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleConvertIStorageToOLESTREAMEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleConvertOLESTREAMToIStorage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleConvertOLESTREAMToIStorage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateDefaultHandler", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] OleCreateDefaultHandler p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateEmbeddingHelper", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateEmbeddingHelper p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateFromData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateFromData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateFromDataEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateFromDataEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateFromFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateFromFile p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateFromFileEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateFromFileEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateLink", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateLink p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateLinkFromData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateLinkFromData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateLinkToFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateLinkToFile p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateMenuDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleCreateMenuDescriptor p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleCreateStaticFromData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] OleCreateStaticFromData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleDestroyMenuDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleDestroyMenuDescriptor p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleDoAutoConvert", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleDoAutoConvert p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleDraw", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] OleDraw p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleDuplicateData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleDuplicateData p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleFlushClipboard", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ole32] OleFlushClipboard()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleGetAutoConvert", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleGetAutoConvert p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleGetClipboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleGetClipboard p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleGetIconOfClass", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleGetIconOfClass p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleGetIconOfFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleGetIconOfFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleInitializeWOW", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleInitializeWOW p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleIsCurrentClipboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleIsCurrentClipboard p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleIsRunning", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleIsRunning p0=0x%x\n", p0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleLoad", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] OleLoad p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleLoadFromStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleLoadFromStream p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleLockRunning", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleLockRunning p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleMetafilePictFromIconAndLabel", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] OleMetafilePictFromIconAndLabel p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleNoteObjectVisible", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleNoteObjectVisible p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleQueryCreateFromData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleQueryCreateFromData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleQueryLinkFromData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleQueryLinkFromData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleRegEnumFormatEtc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleRegEnumFormatEtc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleRegEnumVerbs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleRegEnumVerbs p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleRegGetMiscStatus", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleRegGetMiscStatus p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleRegGetUserType", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleRegGetUserType p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleRun", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleRun p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSave", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleSave p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSaveToStream", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleSaveToStream p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSetAutoConvert", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleSetAutoConvert p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSetClipboard", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] OleSetClipboard p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSetContainedObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] OleSetContainedObject p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleSetMenuDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[ole32] OleSetMenuDescriptor p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "OleTranslateAccelerator", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] OleTranslateAccelerator p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "ProgIDFromCLSID", func(ctx *ntapi.TrapContext) uint32 {
		clsid := ctx.Arg(0)
		lplpszProgID := ctx.Arg(1)
		ravelog.Logf("[ole32] ProgIDFromCLSID clsid=0x%x out=0x%x\n", clsid, lplpszProgID)
		if lplpszProgID != 0 {
			ctx.Mem.Write64(lplpszProgID, 0)
		}
		ctx.SetReturn(0x800401F3) // CO_E_CLASSSTRING
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropStgNameToFmtId", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] PropStgNameToFmtId p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropSysAllocString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] PropSysAllocString p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropSysFreeString", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] PropSysFreeString p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropVariantClear", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] PropVariantClear p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropVariantCopy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] PropVariantCopy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "ReadClassStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] ReadClassStg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "ReadClassStm", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] ReadClassStm p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "ReadFmtUserTypeStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] ReadFmtUserTypeStg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "ReleaseStgMedium", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] ReleaseStgMedium p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "RoGetAgileReference", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] RoGetAgileReference p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SNB_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] SNB_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SNB_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] SNB_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SNB_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] SNB_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SNB_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] SNB_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "STGMEDIUM_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] STGMEDIUM_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "STGMEDIUM_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] STGMEDIUM_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "STGMEDIUM_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] STGMEDIUM_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "STGMEDIUM_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] STGMEDIUM_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SetConvertStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] SetConvertStg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "SetErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] SetErrorInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgConvertPropertyToVariant", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] StgConvertPropertyToVariant p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgConvertVariantToProperty", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgConvertVariantToProperty p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreateDocfile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] StgCreateDocfile p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreateDocfileOnILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] StgCreateDocfileOnILockBytes p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreatePropSetStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] StgCreatePropSetStg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreatePropStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgCreatePropStg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreateStorageEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgCreateStorageEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgIsStorageFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] StgIsStorageFile p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgIsStorageILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] StgIsStorageILockBytes p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenPropStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[ole32] StgOpenPropStg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorage", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgOpenStorage p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorageEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgOpenStorageEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorageOnILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[ole32] StgOpenStorageOnILockBytes p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgSetTimes", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] StgSetTimes p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StringFromIID", func(ctx *ntapi.TrapContext) uint32 {
		riid := ctx.Arg(0)
		lplpsz := ctx.Arg(1)
		ravelog.Logf("[ole32] StringFromIID iid=0x%x out=0x%x\n", riid, lplpsz)
		if riid == 0 || lplpsz == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		guidStr := guidString(readGUID(ctx.Mem, riid))
		buf := cs.allocTaskMem(uint64(len(guidStr)+1)*2, true)
		if buf == 0 {
			ctx.SetReturn(uint64(E_OUTOFMEMORY))
			return 0
		}
		for i, ch := range guidStr {
			ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(guidStr)*2), 0)
		ctx.Mem.Write64(lplpsz, buf)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WdtpInterfacePointer_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[ole32] WdtpInterfacePointer_UserFree p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WdtpInterfacePointer_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[ole32] WdtpInterfacePointer_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WdtpInterfacePointer_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[ole32] WdtpInterfacePointer_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WdtpInterfacePointer_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[ole32] WdtpInterfacePointer_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WriteClassStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] WriteClassStg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WriteClassStm", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[ole32] WriteClassStm p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "WriteFmtUserTypeStg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] WriteFmtUserTypeStg p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
}

func registerOleaut32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	oleaut32, ok := hctx.SynthByName["oleaut32.dll"]
	if !ok {
		return
	}
	sharedHeapAlloc := hctx.HeapAlloc
	_ = oleaut32

	d.RegisterAutoStubHandler(oleaut32, "SysAllocString", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		if src == 0 {
			ctx.SetReturn(0)
			return 0
		}
		n := uint64(0)
		for {
			w, _ := ctx.Mem.Read16(src + n*2)
			if w == 0 {
				break
			}
			n++
		}
		ctx.SetReturn(cs.allocBSTRChars(src, n))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysFreeString", func(ctx *ntapi.TrapContext) uint32 {
		cs.freeBSTR(ctx.Arg(0))
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
		src := ctx.Arg(0)
		cch := ctx.Arg(1) // character count
		if src == 0 && cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(cs.allocBSTRChars(src, cch))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysReAllocStringLen", func(ctx *ntapi.TrapContext) uint32 {
		pbstr := ctx.Arg(0)
		psz := ctx.Arg(1)
		cch := ctx.Arg(2)
		if pbstr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		oldBstr, _ := ctx.Mem.Read64(pbstr)
		cs.freeBSTR(oldBstr)
		ctx.Mem.Write64(pbstr, cs.allocBSTRChars(psz, cch))
		ctx.SetReturn(1)
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
	// VariantChangeType: Convert a VARIANT to a different type.
	// ReactOS/Wine: dll/win32/oleaut32/variant.c
	d.RegisterAutoStubHandler(oleaut32, "VariantChangeType", func(ctx *ntapi.TrapContext) uint32 {
		// HRESULT VariantChangeType(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, USHORT wFlags, VARTYPE vt)
		pvargDest := ctx.Arg(0)
		pvarSrc := ctx.Arg(1)
		vtTarget := uint16(ctx.Arg(3))
		if pvargDest == 0 || pvarSrc == 0 {
			ctx.SetReturn(0x80070057) // E_INVALIDARG
			return 0
		}
		// VARIANT layout: vt(2), reserved(6), data(8..16)
		vtSrc, _ := mem.Read16(pvarSrc)
		const (
			VT_EMPTY = 0
			VT_I4    = 3
			VT_BSTR  = 8
		)
		// Trivial same-type copy
		if vtSrc == vtTarget {
			for i := uint64(0); i < 24; i++ {
				b, _ := mem.Read8(pvarSrc + i)
				mem.Write8(pvargDest+i, b)
			}
			ctx.SetReturn(0) // S_OK
			return 0
		}
		// Can't convert complex types - return DISP_E_TYPEMISMATCH
		ctx.SetReturn(0x80020005)
		return 0
	})
	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing oleaut32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(oleaut32, "BSTR_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] BSTR_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "BSTR_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] BSTR_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "BSTR_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] BSTR_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "BSTR_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] BSTR_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "BstrFromVector", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] BstrFromVector p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "ClearCustData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] ClearCustData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateDispTypeInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] CreateDispTypeInfo p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		pperrinfo := ctx.Arg(0)
		ravelog.Logf("[oleaut32] CreateErrorInfo out=0x%x\n", pperrinfo)
		if pperrinfo != 0 {
			ctx.Mem.Write64(pperrinfo, 0)
		}
		ctx.SetReturn(0x80004005) // E_FAIL
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateStdDispatch", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] CreateStdDispatch p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateTypeLib", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] CreateTypeLib p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateTypeLib2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] CreateTypeLib2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DispCallFunc", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] DispCallFunc p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DispGetIDsOfNames", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] DispGetIDsOfNames p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DispGetParam", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] DispGetParam p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DispInvoke", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] DispInvoke p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[oleaut32] DllCanUnloadNow()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[ole32] DllGetClassObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DllRegisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[oleaut32] DllRegisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DllUnregisterServer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[oleaut32] DllUnregisterServer()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "DosDateTimeToVariantTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] DosDateTimeToVariantTime p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "GetActiveObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] GetActiveObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "GetAltMonthNames", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] GetAltMonthNames p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "GetErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		dwReserved := ctx.Arg(0)
		pperrinfo := ctx.Arg(1)
		ravelog.Logf("[oleaut32] GetErrorInfo reserved=%d out=0x%x\n", dwReserved, pperrinfo)
		if pperrinfo != 0 {
			ctx.Mem.Write64(pperrinfo, 0)
		} // no error info
		ctx.SetReturn(1) // S_FALSE - no error info available
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "GetRecordInfoFromGuids", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] GetRecordInfoFromGuids p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "GetRecordInfoFromTypeInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] GetRecordInfoFromTypeInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LHashValOfNameSys", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] LHashValOfNameSys p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LHashValOfNameSysA", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] LHashValOfNameSysA p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LPSAFEARRAY_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] LPSAFEARRAY_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LPSAFEARRAY_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] LPSAFEARRAY_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LPSAFEARRAY_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] LPSAFEARRAY_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "LPSAFEARRAY_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] LPSAFEARRAY_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OaBuildVersion", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[oleaut32] OaBuildVersion()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleCreateFontIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] OleCreateFontIndirect p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleCreatePictureIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] OleCreatePictureIndirect p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleCreatePropertyFrame", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] OleCreatePropertyFrame p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleCreatePropertyFrameIndirect", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] OleCreatePropertyFrameIndirect p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleIconToCursor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] OleIconToCursor p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleLoadPicture", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] OleLoadPicture p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleLoadPictureEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] OleLoadPictureEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleLoadPictureFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] OleLoadPictureFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleLoadPicturePath", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] OleLoadPicturePath p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleSavePictureFile", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] OleSavePictureFile p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "OleTranslateColor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] OleTranslateColor p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "QueryPathOfRegTypeLib", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] QueryPathOfRegTypeLib p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "RegisterActiveObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] RegisterActiveObject p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "RegisterTypeLib", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] RegisterTypeLib p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "RegisterTypeLibForUser", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] RegisterTypeLibForUser p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "RevokeActiveObject", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] RevokeActiveObject p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAccessData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayAccessData p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayAllocData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayAllocDescriptor p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocDescriptorEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayAllocDescriptorEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCopy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayCopy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCopyData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayCopyData p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCreate", func(ctx *ntapi.TrapContext) uint32 {
		vt := ctx.Arg(0)
		cDims := ctx.Arg(1)
		rgsabound := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayCreate vt=%d dims=%d\n", vt, cDims)
		// Return minimal fake SAFEARRAY
		buf := sharedHeapAlloc(64, true)
		ctx.Mem.Write16(buf, uint16(cDims)) // cDims
		ctx.Mem.Write16(buf+2, 0)           // fFeatures
		ctx.Mem.Write32(buf+4, 0)           // cbElements
		_ = rgsabound
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCreateEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] SafeArrayCreateEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCreateVector", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayCreateVector p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCreateVectorEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] SafeArrayCreateVectorEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayDestroy", func(ctx *ntapi.TrapContext) uint32 {
		psa := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayDestroy psa=0x%x\n", psa)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayDestroyData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayDestroyData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayDestroyDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayDestroyDescriptor p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetDim", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayGetDim p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetElement", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayGetElement p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetElemsize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayGetElemsize p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetIID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayGetIID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetLBound", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayGetLBound p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetRecordInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayGetRecordInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetUBound", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayGetUBound p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetVartype", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayGetVartype p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayLock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayLock p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayPtrOfIndex", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayPtrOfIndex p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayPutElement", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] SafeArrayPutElement p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayRedim", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArrayRedim p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArraySetIID", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArraySetIID p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArraySetRecordInfo", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SafeArraySetRecordInfo p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayUnaccessData", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayUnaccessData p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayUnlock", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		ravelog.Logf("[oleaut32] SafeArrayUnlock p0=0x%x\n", p0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SetErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		dwReserved := ctx.Arg(0)
		perrinfo := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SetErrorInfo reserved=%d info=0x%x\n", dwReserved, perrinfo)
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SetOaNoCache", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[oleaut32] SetOaNoCache()\n")
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysAllocStringByteLen", func(ctx *ntapi.TrapContext) uint32 {
		psz := ctx.Arg(0)
		len_ := ctx.Arg(1)
		if psz == 0 && len_ == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(cs.allocBSTRByteLen(psz, len_))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysReAllocString", func(ctx *ntapi.TrapContext) uint32 {
		pbstr := ctx.Arg(0)
		psz := ctx.Arg(1)
		if pbstr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		len_ := uint64(0)
		if psz != 0 {
			for {
				ch, _ := ctx.Mem.Read16(psz + len_*2)
				if ch == 0 {
					break
				}
				len_++
			}
		}
		oldBstr, _ := ctx.Mem.Read64(pbstr)
		cs.freeBSTR(oldBstr)
		ctx.Mem.Write64(pbstr, cs.allocBSTRChars(psz, len_))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SysStringByteLen", func(ctx *ntapi.TrapContext) uint32 {
		bstr := ctx.Arg(0)
		if bstr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		byteLen, _ := ctx.Mem.Read32(bstr - 4)
		ctx.SetReturn(uint64(byteLen))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SystemTimeToVariantTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] SystemTimeToVariantTime p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "UnRegisterTypeLibForUser", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] UnRegisterTypeLibForUser p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VARIANT_UserFree", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VARIANT_UserFree p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VARIANT_UserMarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VARIANT_UserMarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VARIANT_UserSize", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VARIANT_UserSize p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VARIANT_UserUnmarshal", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VARIANT_UserUnmarshal p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarAbs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarAbs p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarAdd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarAdd p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarAnd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarAnd p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarBoolFromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBoolFromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBoolFromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarBoolFromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrCat", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarBstrCat p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrCmp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrCmp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromBool p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromCy p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromDate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromDec p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromI1 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromI2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromI4 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromI8 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromR4 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromR8 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromUI1 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromUI2 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromUI4 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarBstrFromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarBstrFromUI8 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCat", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCat p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCmp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarCmp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyAbs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyAbs p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyAdd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyAdd p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyCmp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyCmp p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyCmpR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyCmpR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFix", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFix p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyFromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarCyFromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyFromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyFromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyInt p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyMul", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyMul p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyMulI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyMulI4 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyMulI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyMulI8 p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyNeg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarCyNeg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCyRound", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCyRound p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarCySub", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarCySub p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDateFromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarDateFromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDateFromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUdate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDateFromUdate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDateFromUdateEx", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarDateFromUdateEx p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecAbs", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecAbs p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecAdd", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecAdd p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecCmp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecCmp p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecCmpR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecCmpR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecDiv", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecDiv p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFix", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFix p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecFromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarDecFromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecFromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecFromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecInt p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecMul", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecMul p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecNeg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarDecNeg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecRound", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecRound p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDecSub", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDecSub p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarDiv", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarDiv p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarEqv", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarEqv p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFix", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarFix p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFormat", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] VarFormat p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFormatCurrency", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] VarFormatCurrency p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFormatDateTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarFormatDateTime p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFormatNumber", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] VarFormatNumber p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarFormatPercent", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		p5 := ctx.Arg(5)
		ravelog.Logf("[oleaut32] VarFormatPercent p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		_ = p5
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarI1FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarI1FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI1FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI1FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarI2FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarI2FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI2FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI2FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarI4FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarI4FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI4FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI4FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarI8FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarI8FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarI8FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarI8FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarIdiv", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarIdiv p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarImp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarImp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarInt", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarInt p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarMod", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarMod p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarMonthName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarMonthName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarMul", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarMul p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarNeg", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarNeg p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarNot", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarNot p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarNumFromParseNum", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarNumFromParseNum p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarOr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarOr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarParseNumFromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] VarParseNumFromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarPow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarPow p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4CmpR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4CmpR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarR4FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarR4FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR4FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR4FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarR8FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarR8FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarR8FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8Pow", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarR8Pow p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarR8Round", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarR8Round p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarRound", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarRound p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarSub", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarSub p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarUI1FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarUI1FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI1FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI1FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarUI2FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarUI2FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI2FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI2FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarUI4FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarUI4FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI4FromUI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI4FromUI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromBool", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromBool p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromCy", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromCy p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromDate p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromDec", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromDec p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromDisp", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarUI8FromDisp p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromI8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromI8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromR4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromR4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromR8", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromR8 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromStr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		ravelog.Logf("[oleaut32] VarUI8FromStr p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromUI1", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromUI1 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromUI2", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromUI2 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUI8FromUI4", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VarUI8FromUI4 p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarUdateFromDate", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarUdateFromDate p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarWeekdayName", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		p3 := ctx.Arg(3)
		p4 := ctx.Arg(4)
		ravelog.Logf("[oleaut32] VarWeekdayName p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		_ = p3
		_ = p4
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VarXor", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VarXor p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantChangeTypeEx", func(ctx *ntapi.TrapContext) uint32 {
		pvargDest := ctx.Arg(0)
		pvarSrc := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VariantChangeTypeEx dest=0x%x src=0x%x\n", pvargDest, pvarSrc)
		// Just copy for now
		if pvargDest != 0 && pvarSrc != 0 {
			for i := uint64(0); i < 24; i++ {
				b, _ := ctx.Mem.Read8(pvarSrc + i)
				ctx.Mem.Write8(pvargDest+i, b)
			}
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantCopyInd", func(ctx *ntapi.TrapContext) uint32 {
		pvargDest := ctx.Arg(0)
		pvargSrc := ctx.Arg(1)
		if pvargDest != 0 && pvargSrc != 0 {
			for i := uint64(0); i < 24; i++ {
				b, _ := ctx.Mem.Read8(pvargSrc + i)
				ctx.Mem.Write8(pvargDest+i, b)
			}
		}
		ctx.SetReturn(0) // S_OK
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantTimeToDosDateTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		p2 := ctx.Arg(2)
		ravelog.Logf("[oleaut32] VariantTimeToDosDateTime p0=0x%x, p1=0x%x, p2=0x%x\n", p0, p1, p2)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantTimeToSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VariantTimeToSystemTime p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VectorFromBstr", func(ctx *ntapi.TrapContext) uint32 {
		p0 := ctx.Arg(0)
		p1 := ctx.Arg(1)
		ravelog.Logf("[oleaut32] VectorFromBstr p0=0x%x, p1=0x%x\n", p0, p1)
		ctx.SetReturn(0)
		return 0
	})
}
