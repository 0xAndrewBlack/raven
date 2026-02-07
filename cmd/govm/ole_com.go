//go:build guest_windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	STG_E_INVALIDFUNCTION     = 0x80030001
	STG_E_FILENOTFOUND        = 0x80030002
	STG_E_PATHNOTFOUND        = 0x80030003
	STG_E_ACCESSDENIED        = 0x80030005
	STG_E_INVALIDPOINTER      = 0x80030009
	STG_E_NOMOREFILES         = 0x80030012
	STG_E_FILEALREADYEXISTS   = 0x80030050
	STG_E_INVALIDNAME         = 0x800300FC
	STG_E_REVERTED            = 0x80030102

	COINIT_MULTITHREADED     = 0x0
	COINIT_APARTMENTTHREADED = 0x2

	STGM_READ            = 0x00000000
	STGM_WRITE           = 0x00000001
	STGM_READWRITE       = 0x00000002
	STGM_SHARE_EXCLUSIVE = 0x00000010
	STGM_SHARE_DENY_NONE = 0x00000040
	STGM_CREATE          = 0x00001000
	STGM_DELETEONRELEASE = 0x04000000

	STATFLAG_NONAME = 0x00000001

	STGTY_STORAGE   = 1
	STGTY_STREAM    = 2
	STGTY_LOCKBYTES = 3

	comTrapIDBase = 0x10000000
	variantSize   = 24

	FADF_HAVEVARTYPE = 0x0080

	VARIANT_FALSE = 0x0000
	VARIANT_TRUE  = 0xFFFF

	DISP_E_MEMBERNOTFOUND = 0x80020003
	DISP_E_PARAMNOTFOUND  = 0x80020004
	DISP_E_TYPEMISMATCH   = 0x80020005
	DISP_E_UNKNOWNNAME    = 0x80020006
	DISP_E_EXCEPTION      = 0x80020009
	DISP_E_BADPARAMCOUNT  = 0x8002000E

	VT_EMPTY    = 0
	VT_NULL     = 1
	VT_I2       = 2
	VT_I4       = 3
	VT_R4       = 4
	VT_R8       = 5
	VT_BSTR     = 8
	VT_DISPATCH = 9
	VT_ERROR    = 10
	VT_BOOL     = 11
	VT_VARIANT  = 12
	VT_UNKNOWN  = 13
	VT_I1       = 16
	VT_UI1      = 17
	VT_UI2      = 18
	VT_UI4      = 19
	VT_I8       = 20
	VT_UI8      = 21
	VT_INT      = 22
	VT_UINT     = 23
	VT_HRESULT  = 25
	VT_PTR      = 26
	VT_LPSTR    = 30
	VT_LPWSTR   = 31
	VT_ARRAY    = 0x2000
	VT_BYREF    = 0x4000
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	IID_IUnknown         = GUID{0x00000000, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IClassFactory    = GUID{0x00000001, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IMalloc          = GUID{0x00000002, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IDispatch        = GUID{0x00020400, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_ILockBytes       = GUID{0x0000000A, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IStorage         = GUID{0x0000000B, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IStream          = GUID{0x0000000C, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IEnumSTATSTG     = GUID{0x0000000D, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersist         = GUID{0x0000010C, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IPersistFile     = GUID{0x0000010B, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IEnumIDList      = GUID{0x000214F2, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellFolder     = GUID{0x000214E6, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkA      = GUID{0x000214EE, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IShellLinkW      = GUID{0x000214F9, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IErrorInfo       = GUID{0x1CF2B120, 0x547D, 0x101B, [8]byte{0x8E, 0x65, 0x08, 0x00, 0x2B, 0x2B, 0xD1, 0x19}}
	IID_ICreateErrorInfo = GUID{0x22F03340, 0x547D, 0x101B, [8]byte{0x8E, 0x65, 0x08, 0x00, 0x2B, 0x2B, 0xD1, 0x19}}
	IID_ITypeInfo        = GUID{0x00020401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_ITypeLib         = GUID{0x00020402, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	IID_IModalWindow     = GUID{0xB4DB1657, 0x70D7, 0x485E, [8]byte{0x8E, 0x3E, 0x6F, 0xCB, 0x5A, 0x5C, 0x18, 0x02}}
	IID_IFileDialog      = GUID{0x42F85136, 0xDB7E, 0x439C, [8]byte{0x85, 0xF1, 0xE4, 0x07, 0x5D, 0x13, 0x5F, 0xC8}}
	IID_IFileOpenDialog  = GUID{0xD57C7288, 0xD4AD, 0x4768, [8]byte{0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60}}

	CLSID_StdComponentCategoriesMgr = GUID{0x0002E005, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	CLSID_ShellLink                 = GUID{0x00021401, 0x0000, 0x0000, [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
	CLSID_FileOpenDialog            = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	CLSID_MemoryAllocator           = GUID{0x1E651CC0, 0xB199, 0x11D0, [8]byte{0x82, 0x12, 0x00, 0xC0, 0x4F, 0xC3, 0x2C, 0x45}}
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
	altInterfaces map[GUID]uint64
	data          interface{}
}

type classFactory struct {
	clsid  GUID
	create func(iid GUID) (*comObject, error)
}

type safeArrayBound struct {
	cElements uint32
	lLbound   int32
}

type safeArrayInfo struct {
	addr       uint64
	vt         uint16
	cDims      uint16
	fFeatures  uint16
	cbElements uint32
	cLocks     uint32
	pvData     uint64
	bounds     []safeArrayBound
	iid        GUID
	recordInfo uint64
}

type typeInfoData struct {
	lcid     uint32
	nextID   int32
	names    map[string]int32
	dispToID map[int32]string
}

type stdDispatchData struct {
	instance uint64
	typeInfo uint64
}

type errorInfoData struct {
	peer        uint64
	guid        GUID
	source      string
	description string
	helpFile    string
	helpContext uint32
}

type typeLibData struct {
	path string
}

type registeredClassObject struct {
	clsid        GUID
	unkPtr       uint64
	dwClsContext uint32
	flags        uint32
}

type shellLinkData struct {
	path         string
	description  string
	workingDir   string
	arguments    string
	iconLocation string
	iconIndex    int32
	showCmd      int32
	hotkey       uint16
	currentFile  string
	dirty        bool
}

type shellFolderData struct {
	path string
}

type enumIDListData struct {
	items []string
	index int
}

type memoryBuffer struct {
	data            []byte
	hglobal         uint64
	deleteOnRelease bool
	refs            int32
}

type memStream struct {
	buffer *memoryBuffer
	pos    int64
	name   string
}

type fileOpenDialogData struct {
	title           string
	fileName        string
	okButtonLabel   string
	fileNameLabel   string
	defaultExt      string
	options         uint32
	fileTypeIndex   uint32
	clientGUID      GUID
	nextAdviseToken uint32
}

type fileStream struct {
	path    string
	file    *os.File
	pos     int64
	name    string
	grfMode uint32
}

type lockBytes struct {
	buffer *memoryBuffer
}

type dirStorage struct {
	path            string
	name            string
	grfMode         uint32
	deleteOnRelease bool
	clsid           GUID
	stateBits       uint32
}

type statStgEntry struct {
	name    string
	stgType uint32
	size    uint64
	modTime time.Time
	clsid   GUID
}

type enumSTATSTG struct {
	entries []statStgEntry
	index   int
}

type comThreadState struct {
	initialized   bool
	initCount     int32
	apartmentType uint32
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
	safeArrays          map[uint64]*safeArrayInfo
	mem                 *mmu.MMU
	disp                *ntapi.Dispatcher
	heapAlloc           func(uint64, bool) uint64
	heapFree            func(uint64)
	regHive             *ntapi.RegistryHive
	hctx                *HandlerCtx
	progIDs             map[string]GUID
	errorInfo           uint64
	threadStates        map[uint64]*comThreadState
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
		safeArrays:          make(map[uint64]*safeArrayInfo),
		mem:                 hctx.Mem,
		disp:                hctx.Disp,
		heapAlloc:           hctx.HeapAlloc,
		heapFree:            hctx.HeapFree,
		regHive:             hctx.RegHive,
		hctx:                hctx,
		progIDs:             make(map[string]GUID),
		threadStates:        make(map[uint64]*comThreadState),
	}
	cs.registerClassFactory(CLSID_StdComponentCategoriesMgr, func(iid GUID) (*comObject, error) {
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
	})
	cs.registerClassFactory(CLSID_ShellLink, cs.createShellLinkObjects)
	cs.registerClassFactory(CLSID_FileOpenDialog, cs.createFileOpenDialogObject)
	cs.registerClassFactory(CLSID_MemoryAllocator, cs.createMemoryAllocatorObject)
	registerMSXMLClassFactories(cs)
	registerWICClassFactories(cs)
	registerD2D1ClassFactories(cs)
	return cs
}

func (cs *comState) registerClassFactory(clsid GUID, create func(iid GUID) (*comObject, error)) {
	cs.classFactories[clsid] = &classFactory{clsid: clsid, create: create}
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

func readBSTRString(mem *mmu.MMU, bstr uint64) string {
	if bstr == 0 {
		return ""
	}
	byteLen, err := mem.Read32(bstr - 4)
	if err != nil || byteLen == 0 {
		return ""
	}
	data, err := mem.ReadBytes(bstr, int(byteLen))
	if err != nil {
		return ""
	}
	return decodeUTF16LEString(data)
}

func writeUTF16Buffer(mem *mmu.MMU, addr uint64, s string) {
	ws := utf16Encode(s)
	for i, w := range ws {
		mem.Write16(addr+uint64(i)*2, w)
	}
	mem.Write16(addr+uint64(len(ws))*2, 0)
}

func (cs *comState) allocBSTRString(s string) uint64 {
	ws := utf16Encode(s)
	base := cs.heapAlloc(4+uint64(len(ws))*2+2, true)
	if base == 0 {
		return 0
	}
	cs.mem.Write32(base, uint32(len(ws)*2))
	for i, w := range ws {
		cs.mem.Write16(base+4+uint64(i)*2, w)
	}
	cs.mem.Write16(base+4+uint64(len(ws))*2, 0)
	bstr := base + 4
	cs.bstrAllocs[bstr] = base
	return bstr
}

func readVariantType(mem *mmu.MMU, addr uint64) uint16 {
	vt, _ := mem.Read16(addr)
	return vt
}

func readVariantValue(mem *mmu.MMU, addr uint64) uint64 {
	val, _ := mem.Read64(addr + 8)
	return val
}

func writeVariantEmpty(mem *mmu.MMU, addr uint64) {
	mem.WriteBytes(addr, make([]byte, variantSize))
}

func writeVariantScalar(mem *mmu.MMU, addr uint64, vt uint16, value uint64) {
	writeVariantEmpty(mem, addr)
	mem.Write16(addr, vt)
	mem.Write64(addr+8, value)
}

func variantBaseType(vt uint16) uint16 {
	return vt &^ (VT_ARRAY | VT_BYREF)
}

func variantElementType(vt uint16) uint16 {
	return vt &^ VT_BYREF
}

func vartypeElemSize(vt uint16) uint32 {
	switch vt &^ (VT_ARRAY | VT_BYREF) {
	case VT_I1, VT_UI1:
		return 1
	case VT_I2, VT_UI2, VT_BOOL:
		return 2
	case VT_I4, VT_UI4, VT_INT, VT_UINT, VT_R4, VT_ERROR, VT_HRESULT:
		return 4
	case VT_VARIANT:
		return variantSize
	default:
		return 8
	}
}

func signExtend32(v uint32) int64 {
	return int64(int32(v))
}

func boolToVariantBool(v bool) uint16 {
	if v {
		return VARIANT_TRUE
	}
	return VARIANT_FALSE
}

func normalizeBoolString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func oleVariantTimeToTime(v float64) time.Time {
	base := time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	days := int64(v)
	frac := v - float64(days)
	if frac < 0 {
		days--
		frac = v - float64(days)
	}
	return base.AddDate(0, 0, int(days)).Add(time.Duration(frac * 24 * float64(time.Hour)))
}

func timeToOleVariantTime(t time.Time) float64 {
	base := time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)
	return t.Sub(base).Hours() / 24
}

func readFloat64(mem *mmu.MMU, addr uint64) float64 {
	u, _ := mem.Read64(addr)
	return math.Float64frombits(u)
}

func writeFloat64(mem *mmu.MMU, addr uint64, value float64) {
	mem.Write64(addr, math.Float64bits(value))
}

func readFloat32(mem *mmu.MMU, addr uint64) float32 {
	u, _ := mem.Read32(addr)
	return math.Float32frombits(u)
}

func (cs *comState) addRefPtr(ptr uint64) {
	if obj := cs.objects[ptr]; obj != nil {
		cs.addRef(obj)
	}
}

func (cs *comState) releasePtr(ptr uint64) {
	if obj := cs.objects[ptr]; obj != nil {
		cs.release(obj)
	}
}

func (cs *comState) copyBytes(dst, src uint64, size uint32) {
	if size == 0 {
		return
	}
	data, err := cs.mem.ReadBytes(src, int(size))
	if err != nil {
		return
	}
	cs.mem.WriteBytes(dst, data)
}

func (cs *comState) variantToString(addr uint64) (string, bool) {
	vt := readVariantType(cs.mem, addr)
	if vt&VT_BYREF != 0 {
		ptr := readVariantValue(cs.mem, addr)
		switch variantBaseType(vt) {
		case VT_BSTR:
			val, _ := cs.mem.Read64(ptr)
			return readBSTRString(cs.mem, val), true
		case VT_I4, VT_INT:
			v, _ := cs.mem.Read32(ptr)
			return strconv.FormatInt(signExtend32(v), 10), true
		case VT_R8:
			return strconv.FormatFloat(readFloat64(cs.mem, ptr), 'f', -1, 64), true
		case VT_BOOL:
			v, _ := cs.mem.Read16(ptr)
			return strconv.FormatBool(v != 0), true
		}
	}
	switch variantBaseType(vt) {
	case VT_EMPTY:
		return "", true
	case VT_BSTR:
		return readBSTRString(cs.mem, readVariantValue(cs.mem, addr)), true
	case VT_I1:
		return strconv.FormatInt(int64(int8(readVariantValue(cs.mem, addr))), 10), true
	case VT_UI1:
		return strconv.FormatUint(uint64(uint8(readVariantValue(cs.mem, addr))), 10), true
	case VT_I2:
		return strconv.FormatInt(int64(int16(readVariantValue(cs.mem, addr))), 10), true
	case VT_UI2:
		return strconv.FormatUint(uint64(uint16(readVariantValue(cs.mem, addr))), 10), true
	case VT_I4, VT_INT:
		return strconv.FormatInt(int64(int32(readVariantValue(cs.mem, addr))), 10), true
	case VT_UI4, VT_UINT:
		return strconv.FormatUint(uint64(uint32(readVariantValue(cs.mem, addr))), 10), true
	case VT_I8:
		return strconv.FormatInt(int64(readVariantValue(cs.mem, addr)), 10), true
	case VT_UI8:
		return strconv.FormatUint(readVariantValue(cs.mem, addr), 10), true
	case VT_R4:
		return strconv.FormatFloat(float64(math.Float32frombits(uint32(readVariantValue(cs.mem, addr)))), 'f', -1, 32), true
	case VT_R8:
		return strconv.FormatFloat(math.Float64frombits(readVariantValue(cs.mem, addr)), 'f', -1, 64), true
	case VT_BOOL:
		return strconv.FormatBool(uint16(readVariantValue(cs.mem, addr)) != 0), true
	}
	return "", false
}

func (cs *comState) variantToInt64(addr uint64) (int64, bool) {
	vt := readVariantType(cs.mem, addr)
	if vt&VT_BYREF != 0 {
		ptr := readVariantValue(cs.mem, addr)
		switch variantBaseType(vt) {
		case VT_I4, VT_INT:
			v, _ := cs.mem.Read32(ptr)
			return int64(int32(v)), true
		case VT_I8:
			v, _ := cs.mem.Read64(ptr)
			return int64(v), true
		case VT_UI4, VT_UINT:
			v, _ := cs.mem.Read32(ptr)
			return int64(v), true
		case VT_BOOL:
			v, _ := cs.mem.Read16(ptr)
			if v != 0 {
				return -1, true
			}
			return 0, true
		}
	}
	switch variantBaseType(vt) {
	case VT_EMPTY:
		return 0, true
	case VT_I1:
		return int64(int8(readVariantValue(cs.mem, addr))), true
	case VT_UI1:
		return int64(uint8(readVariantValue(cs.mem, addr))), true
	case VT_I2:
		return int64(int16(readVariantValue(cs.mem, addr))), true
	case VT_UI2:
		return int64(uint16(readVariantValue(cs.mem, addr))), true
	case VT_I4, VT_INT:
		return int64(int32(readVariantValue(cs.mem, addr))), true
	case VT_UI4, VT_UINT:
		return int64(uint32(readVariantValue(cs.mem, addr))), true
	case VT_I8:
		return int64(readVariantValue(cs.mem, addr)), true
	case VT_UI8:
		return int64(readVariantValue(cs.mem, addr)), true
	case VT_R4:
		return int64(math.Float32frombits(uint32(readVariantValue(cs.mem, addr)))), true
	case VT_R8:
		return int64(math.Float64frombits(readVariantValue(cs.mem, addr))), true
	case VT_BOOL:
		if uint16(readVariantValue(cs.mem, addr)) != 0 {
			return -1, true
		}
		return 0, true
	case VT_BSTR:
		n, err := strconv.ParseInt(strings.TrimSpace(readBSTRString(cs.mem, readVariantValue(cs.mem, addr))), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func (cs *comState) variantToFloat64(addr uint64) (float64, bool) {
	vt := readVariantType(cs.mem, addr)
	if vt&VT_BYREF != 0 {
		ptr := readVariantValue(cs.mem, addr)
		switch variantBaseType(vt) {
		case VT_R8:
			return readFloat64(cs.mem, ptr), true
		case VT_R4:
			return float64(readFloat32(cs.mem, ptr)), true
		case VT_I4, VT_INT:
			v, _ := cs.mem.Read32(ptr)
			return float64(int32(v)), true
		}
	}
	switch variantBaseType(vt) {
	case VT_EMPTY:
		return 0, true
	case VT_R4:
		return float64(math.Float32frombits(uint32(readVariantValue(cs.mem, addr)))), true
	case VT_R8:
		return math.Float64frombits(readVariantValue(cs.mem, addr)), true
	case VT_I1:
		return float64(int8(readVariantValue(cs.mem, addr))), true
	case VT_UI1:
		return float64(uint8(readVariantValue(cs.mem, addr))), true
	case VT_I2:
		return float64(int16(readVariantValue(cs.mem, addr))), true
	case VT_UI2:
		return float64(uint16(readVariantValue(cs.mem, addr))), true
	case VT_I4, VT_INT:
		return float64(int32(readVariantValue(cs.mem, addr))), true
	case VT_UI4, VT_UINT:
		return float64(uint32(readVariantValue(cs.mem, addr))), true
	case VT_I8:
		return float64(int64(readVariantValue(cs.mem, addr))), true
	case VT_UI8:
		return float64(readVariantValue(cs.mem, addr)), true
	case VT_BOOL:
		if uint16(readVariantValue(cs.mem, addr)) != 0 {
			return -1, true
		}
		return 0, true
	case VT_BSTR:
		f, err := strconv.ParseFloat(strings.TrimSpace(readBSTRString(cs.mem, readVariantValue(cs.mem, addr))), 64)
		return f, err == nil
	}
	return 0, false
}

func (cs *comState) variantToBool(addr uint64) (bool, bool) {
	vt := readVariantType(cs.mem, addr)
	if vt&VT_BYREF != 0 {
		ptr := readVariantValue(cs.mem, addr)
		switch variantBaseType(vt) {
		case VT_BOOL:
			v, _ := cs.mem.Read16(ptr)
			return v != 0, true
		case VT_I4, VT_INT:
			v, _ := cs.mem.Read32(ptr)
			return v != 0, true
		}
	}
	switch variantBaseType(vt) {
	case VT_EMPTY:
		return false, true
	case VT_BOOL:
		return uint16(readVariantValue(cs.mem, addr)) != 0, true
	case VT_I1, VT_UI1, VT_I2, VT_UI2, VT_I4, VT_UI4, VT_INT, VT_UINT, VT_I8, VT_UI8:
		i, ok := cs.variantToInt64(addr)
		return i != 0, ok
	case VT_R4, VT_R8:
		f, ok := cs.variantToFloat64(addr)
		return f != 0, ok
	case VT_BSTR:
		switch normalizeBoolString(readBSTRString(cs.mem, readVariantValue(cs.mem, addr))) {
		case "", "0", "false", "no", "off":
			return false, true
		case "-1", "1", "true", "yes", "on":
			return true, true
		}
	}
	return false, false
}

func (cs *comState) variantToInterfacePtr(addr uint64, iid GUID) (uint64, bool) {
	if addr == 0 {
		return 0, false
	}
	vt := readVariantType(cs.mem, addr)
	if vt&VT_ARRAY != 0 {
		return 0, false
	}
	base := variantBaseType(vt)
	switch base {
	case VT_EMPTY, VT_NULL:
		return 0, true
	case VT_UNKNOWN, VT_DISPATCH:
		ptr := readVariantValue(cs.mem, addr)
		if vt&VT_BYREF != 0 {
			var err error
			ptr, err = cs.mem.Read64(ptr)
			if err != nil {
				return 0, false
			}
		}
		if ptr == 0 {
			return 0, true
		}
		obj := cs.objects[ptr]
		if obj == nil {
			switch {
			case guidEqual(iid, IID_IUnknown) && base == VT_UNKNOWN:
				return ptr, true
			case guidEqual(iid, IID_IDispatch) && base == VT_DISPATCH:
				return ptr, true
			default:
				return 0, false
			}
		}
		if guidEqual(iid, IID_IUnknown) || obj.supportedIIDs[iid] {
			return ptr, true
		}
		if alt := obj.altInterfaces[iid]; alt != 0 {
			return alt, true
		}
	}
	return 0, false
}

func safeArrayDescriptorSize(cDims uint16) uint64 {
	return 24 + uint64(cDims)*8
}

func (cs *comState) loadSafeArray(psa uint64) *safeArrayInfo {
	if psa == 0 {
		return nil
	}
	if sa := cs.safeArrays[psa]; sa != nil {
		return sa
	}
	cDims, err := cs.mem.Read16(psa)
	if err != nil || cDims == 0 {
		return nil
	}
	fFeatures, _ := cs.mem.Read16(psa + 2)
	cbElements, _ := cs.mem.Read32(psa + 4)
	cLocks, _ := cs.mem.Read32(psa + 8)
	pvData, _ := cs.mem.Read64(psa + 16)
	sa := &safeArrayInfo{
		addr:       psa,
		cDims:      cDims,
		fFeatures:  fFeatures,
		cbElements: cbElements,
		cLocks:     cLocks,
		pvData:     pvData,
	}
	sa.bounds = make([]safeArrayBound, cDims)
	for i := uint16(0); i < cDims; i++ {
		entry := psa + 24 + uint64(i)*8
		cElements, _ := cs.mem.Read32(entry)
		lBound, _ := cs.mem.Read32(entry + 4)
		sa.bounds[i] = safeArrayBound{cElements: cElements, lLbound: int32(lBound)}
	}
	if fFeatures&FADF_HAVEVARTYPE != 0 {
		vt, _ := cs.mem.Read16(psa + 12)
		sa.vt = vt
	}
	cs.safeArrays[psa] = sa
	return sa
}

func (cs *comState) syncSafeArray(sa *safeArrayInfo) {
	if sa == nil {
		return
	}
	cs.mem.Write16(sa.addr, sa.cDims)
	cs.mem.Write16(sa.addr+2, sa.fFeatures)
	cs.mem.Write32(sa.addr+4, sa.cbElements)
	cs.mem.Write32(sa.addr+8, sa.cLocks)
	cs.mem.Write16(sa.addr+12, sa.vt)
	cs.mem.Write64(sa.addr+16, sa.pvData)
	for i, b := range sa.bounds {
		entry := sa.addr + 24 + uint64(i)*8
		cs.mem.Write32(entry, b.cElements)
		cs.mem.Write32(entry+4, uint32(b.lLbound))
	}
}

func (cs *comState) safeArrayElementOffset(sa *safeArrayInfo, rgIndices uint64) (uint64, bool) {
	if sa == nil || rgIndices == 0 || len(sa.bounds) == 0 {
		return 0, false
	}
	var offset uint64
	stride := uint64(1)
	for dim := len(sa.bounds) - 1; dim >= 0; dim-- {
		raw, err := cs.mem.Read32(rgIndices + uint64(dim)*4)
		if err != nil {
			return 0, false
		}
		idx := int64(int32(raw))
		b := sa.bounds[dim]
		rel := idx - int64(b.lLbound)
		if rel < 0 || rel >= int64(b.cElements) {
			return 0, false
		}
		offset += uint64(rel) * stride
		stride *= uint64(b.cElements)
		if dim == 0 {
			break
		}
	}
	return offset * uint64(sa.cbElements), true
}

func (cs *comState) safeArrayTotalBytes(sa *safeArrayInfo) uint64 {
	if sa == nil {
		return 0
	}
	total := uint64(sa.cbElements)
	for _, b := range sa.bounds {
		total *= uint64(b.cElements)
	}
	return total
}

func (cs *comState) createSafeArray(vt uint16, cDims uint16, rgsabound uint64) uint64 {
	if cDims == 0 || rgsabound == 0 {
		return 0
	}
	sa := &safeArrayInfo{
		vt:         vt,
		cDims:      cDims,
		fFeatures:  FADF_HAVEVARTYPE,
		cbElements: vartypeElemSize(vt),
		bounds:     make([]safeArrayBound, cDims),
	}
	for i := uint16(0); i < cDims; i++ {
		entry := rgsabound + uint64(i)*8
		cElements, _ := cs.mem.Read32(entry)
		lBound, _ := cs.mem.Read32(entry + 4)
		sa.bounds[i] = safeArrayBound{cElements: cElements, lLbound: int32(lBound)}
	}
	desc := cs.heapAlloc(safeArrayDescriptorSize(cDims), true)
	if desc == 0 {
		return 0
	}
	sa.addr = desc
	totalBytes := cs.safeArrayTotalBytes(sa)
	if totalBytes == 0 {
		totalBytes = uint64(sa.cbElements)
	}
	data := cs.heapAlloc(totalBytes, true)
	if data == 0 {
		cs.heapFree(desc)
		return 0
	}
	sa.pvData = data
	cs.safeArrays[desc] = sa
	cs.syncSafeArray(sa)
	return desc
}

func (cs *comState) safeArrayDestroy(psa uint64, freeDesc bool) uint32 {
	sa := cs.loadSafeArray(psa)
	if sa == nil {
		return E_INVALIDARG
	}
	count := uint64(0)
	if sa.cbElements != 0 {
		count = cs.safeArrayTotalBytes(sa) / uint64(sa.cbElements)
	}
	switch variantElementType(sa.vt) {
	case VT_BSTR:
		for i := uint64(0); i < count; i++ {
			ptr, _ := cs.mem.Read64(sa.pvData + i*8)
			cs.freeBSTR(ptr)
		}
	case VT_UNKNOWN, VT_DISPATCH:
		for i := uint64(0); i < count; i++ {
			ptr, _ := cs.mem.Read64(sa.pvData + i*8)
			cs.releasePtr(ptr)
		}
	case VT_VARIANT:
		for i := uint64(0); i < count; i++ {
			cs.variantClear(sa.pvData + i*variantSize)
		}
	}
	if sa.pvData != 0 {
		cs.heapFree(sa.pvData)
		sa.pvData = 0
	}
	if freeDesc {
		delete(cs.safeArrays, psa)
		cs.heapFree(psa)
	} else {
		sa.cLocks = 0
		cs.syncSafeArray(sa)
	}
	return S_OK
}

func (cs *comState) variantClear(addr uint64) uint32 {
	if addr == 0 {
		return E_INVALIDARG
	}
	vt := readVariantType(cs.mem, addr)
	base := variantBaseType(vt)
	if vt&VT_BYREF == 0 {
		switch {
		case vt&VT_ARRAY != 0:
			cs.safeArrayDestroy(readVariantValue(cs.mem, addr), true)
		case base == VT_BSTR:
			cs.freeBSTR(readVariantValue(cs.mem, addr))
		case base == VT_UNKNOWN || base == VT_DISPATCH:
			cs.releasePtr(readVariantValue(cs.mem, addr))
		}
	}
	writeVariantEmpty(cs.mem, addr)
	return S_OK
}

func (cs *comState) variantCopy(dst, src uint64) uint32 {
	if dst == 0 || src == 0 {
		return E_INVALIDARG
	}
	if dst == src {
		return S_OK
	}
	if hr := cs.variantClear(dst); hr != S_OK {
		return hr
	}
	vt := readVariantType(cs.mem, src)
	base := variantBaseType(vt)
	switch {
	case vt&VT_BYREF != 0:
		cs.copyBytes(dst, src, variantSize)
	case vt&VT_ARRAY != 0:
		psa := readVariantValue(cs.mem, src)
		sa := cs.loadSafeArray(psa)
		if sa == nil {
			writeVariantScalar(cs.mem, dst, vt, 0)
			return S_OK
		}
		boundsPtr := cs.allocTaskMem(uint64(sa.cDims)*8, true)
		for i, b := range sa.bounds {
			cs.mem.Write32(boundsPtr+uint64(i)*8, b.cElements)
			cs.mem.Write32(boundsPtr+uint64(i)*8+4, uint32(b.lLbound))
		}
		newPSA := cs.createSafeArray(sa.vt, sa.cDims, boundsPtr)
		cs.freeTaskMem(boundsPtr)
		newSA := cs.loadSafeArray(newPSA)
		if newSA == nil {
			return E_OUTOFMEMORY
		}
		count := uint64(0)
		if sa.cbElements != 0 {
			count = cs.safeArrayTotalBytes(sa) / uint64(sa.cbElements)
		}
		switch variantElementType(sa.vt) {
		case VT_BSTR:
			for i := uint64(0); i < count; i++ {
				ptr, _ := cs.mem.Read64(sa.pvData + i*8)
				cs.mem.Write64(newSA.pvData+i*8, cs.allocBSTRString(readBSTRString(cs.mem, ptr)))
			}
		case VT_UNKNOWN, VT_DISPATCH:
			for i := uint64(0); i < count; i++ {
				ptr, _ := cs.mem.Read64(sa.pvData + i*8)
				cs.addRefPtr(ptr)
				cs.mem.Write64(newSA.pvData+i*8, ptr)
			}
		case VT_VARIANT:
			for i := uint64(0); i < count; i++ {
				if hr := cs.variantCopy(newSA.pvData+i*variantSize, sa.pvData+i*variantSize); hr != S_OK {
					return hr
				}
			}
		default:
			cs.copyBytes(newSA.pvData, sa.pvData, uint32(cs.safeArrayTotalBytes(sa)))
		}
		writeVariantScalar(cs.mem, dst, vt, newPSA)
	case base == VT_BSTR:
		writeVariantScalar(cs.mem, dst, vt, cs.allocBSTRString(readBSTRString(cs.mem, readVariantValue(cs.mem, src))))
	case base == VT_UNKNOWN || base == VT_DISPATCH:
		ptr := readVariantValue(cs.mem, src)
		cs.addRefPtr(ptr)
		writeVariantScalar(cs.mem, dst, vt, ptr)
	default:
		cs.copyBytes(dst, src, variantSize)
	}
	return S_OK
}

func (cs *comState) variantCopyIndirect(dst, src uint64) uint32 {
	if dst == 0 || src == 0 {
		return E_INVALIDARG
	}
	vt := readVariantType(cs.mem, src)
	if vt&VT_BYREF == 0 {
		return cs.variantCopy(dst, src)
	}
	ptr := readVariantValue(cs.mem, src)
	base := variantBaseType(vt)
	switch base {
	case VT_VARIANT:
		return cs.variantCopy(dst, ptr)
	case VT_BSTR:
		val, _ := cs.mem.Read64(ptr)
		writeVariantScalar(cs.mem, dst, VT_BSTR, cs.allocBSTRString(readBSTRString(cs.mem, val)))
	case VT_UNKNOWN, VT_DISPATCH:
		val, _ := cs.mem.Read64(ptr)
		cs.addRefPtr(val)
		writeVariantScalar(cs.mem, dst, base, val)
	case VT_I4, VT_INT, VT_UI4, VT_UINT, VT_ERROR, VT_HRESULT:
		val, _ := cs.mem.Read32(ptr)
		writeVariantScalar(cs.mem, dst, base, uint64(val))
	case VT_I2, VT_UI2, VT_BOOL:
		val, _ := cs.mem.Read16(ptr)
		writeVariantScalar(cs.mem, dst, base, uint64(val))
	case VT_I1, VT_UI1:
		val, _ := cs.mem.Read8(ptr)
		writeVariantScalar(cs.mem, dst, base, uint64(val))
	case VT_R4:
		val, _ := cs.mem.Read32(ptr)
		writeVariantScalar(cs.mem, dst, VT_R4, uint64(val))
	case VT_R8, VT_I8, VT_UI8:
		val, _ := cs.mem.Read64(ptr)
		writeVariantScalar(cs.mem, dst, base, val)
	default:
		return DISP_E_TYPEMISMATCH
	}
	return S_OK
}

func (cs *comState) variantChangeType(dst, src uint64, vt uint16) uint32 {
	if dst == 0 || src == 0 {
		return E_INVALIDARG
	}
	if vt == VT_VARIANT {
		return cs.variantCopy(dst, src)
	}
	if dst == src {
		tmp := cs.allocTaskMem(variantSize, true)
		if tmp == 0 {
			return E_OUTOFMEMORY
		}
		defer cs.freeTaskMem(tmp)
		if hr := cs.variantCopy(tmp, src); hr != S_OK {
			return hr
		}
		src = tmp
	}
	if hr := cs.variantClear(dst); hr != S_OK {
		return hr
	}
	switch vt {
	case VT_EMPTY:
		writeVariantEmpty(cs.mem, dst)
		return S_OK
	case VT_BSTR:
		s, ok := cs.variantToString(src)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		writeVariantScalar(cs.mem, dst, VT_BSTR, cs.allocBSTRString(s))
		return S_OK
	case VT_I4, VT_INT:
		i, ok := cs.variantToInt64(src)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		writeVariantScalar(cs.mem, dst, vt, uint64(uint32(int32(i))))
		return S_OK
	case VT_I2:
		i, ok := cs.variantToInt64(src)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		writeVariantScalar(cs.mem, dst, VT_I2, uint64(uint16(int16(i))))
		return S_OK
	case VT_R8:
		f, ok := cs.variantToFloat64(src)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		writeVariantScalar(cs.mem, dst, VT_R8, math.Float64bits(f))
		return S_OK
	case VT_BOOL:
		b, ok := cs.variantToBool(src)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		writeVariantScalar(cs.mem, dst, VT_BOOL, uint64(boolToVariantBool(b)))
		return S_OK
	case VT_UNKNOWN:
		ptr, ok := cs.variantToInterfacePtr(src, IID_IUnknown)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		cs.addRefPtr(ptr)
		writeVariantScalar(cs.mem, dst, VT_UNKNOWN, ptr)
		return S_OK
	case VT_DISPATCH:
		ptr, ok := cs.variantToInterfacePtr(src, IID_IDispatch)
		if !ok {
			return DISP_E_TYPEMISMATCH
		}
		cs.addRefPtr(ptr)
		writeVariantScalar(cs.mem, dst, VT_DISPATCH, ptr)
		return S_OK
	default:
		return DISP_E_TYPEMISMATCH
	}
}

func (cs *comState) typeInfoFor(ptr uint64) *typeInfoData {
	if obj := cs.objects[ptr]; obj != nil {
		if ti, ok := obj.data.(*typeInfoData); ok {
			return ti
		}
		if sd, ok := obj.data.(*stdDispatchData); ok {
			if typeObj := cs.objects[sd.typeInfo]; typeObj != nil {
				ti, _ := typeObj.data.(*typeInfoData)
				return ti
			}
		}
	}
	return nil
}

func (cs *comState) lookupDispID(typeInfo uint64, name string, create bool) (int32, bool) {
	ti := cs.typeInfoFor(typeInfo)
	if ti == nil {
		return 0, false
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if id, ok := ti.names[key]; ok {
		return id, true
	}
	if !create {
		return 0, false
	}
	if ti.nextID <= 0 {
		ti.nextID = 1
	}
	id := ti.nextID
	ti.nextID++
	ti.names[key] = id
	ti.dispToID[id] = name
	return id, true
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

func filetimeFromTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const epochDiff = uint64(11644473600) * 10000000
	return uint64(t.Unix())*10000000 + uint64(t.Nanosecond()/100) + epochDiff
}

func timeFromFiletime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	const epochDiff = int64(11644473600) * 10000000
	unix100ns := int64(ft) - epochDiff
	sec := unix100ns / 10000000
	nsec := (unix100ns % 10000000) * 100
	if nsec < 0 {
		sec--
		nsec += 1000000000
	}
	return time.Unix(sec, nsec)
}

func readFiletime(mem *mmu.MMU, ptr uint64) time.Time {
	if ptr == 0 {
		return time.Time{}
	}
	ft, _ := mem.Read64(ptr)
	return timeFromFiletime(ft)
}

func writeGuestUTF16String(mem *mmu.MMU, ptr uint64, s string) {
	runes := []rune(s)
	for i, r := range runes {
		mem.Write16(ptr+uint64(i)*2, uint16(r))
	}
	mem.Write16(ptr+uint64(len(runes))*2, 0)
}

func readGuestUTF16String(mem *mmu.MMU, ptr uint64) string {
	if ptr == 0 {
		return ""
	}
	var runes []rune
	for i := 0; i < 32768; i++ {
		w, err := mem.Read16(ptr + uint64(i)*2)
		if err != nil || w == 0 {
			break
		}
		runes = append(runes, rune(w))
	}
	return string(runes)
}

func readGuestANSIString(mem *mmu.MMU, ptr uint64) string {
	if ptr == 0 {
		return ""
	}
	var out []byte
	for i := 0; i < 32768; i++ {
		b, err := mem.Read8(ptr + uint64(i))
		if err != nil || b == 0 {
			break
		}
		out = append(out, b)
	}
	return string(out)
}

func writeGuestANSIString(mem *mmu.MMU, ptr uint64, s string) {
	for i := 0; i < len(s); i++ {
		mem.Write8(ptr+uint64(i), s[i])
	}
	mem.Write8(ptr+uint64(len(s)), 0)
}

func writeGuestUTF16StringN(mem *mmu.MMU, ptr uint64, s string, cch int) {
	if ptr == 0 || cch <= 0 {
		return
	}
	ws := utf16Encode(s)
	if len(ws) >= cch {
		ws = ws[:cch-1]
	}
	for i, w := range ws {
		mem.Write16(ptr+uint64(i)*2, w)
	}
	mem.Write16(ptr+uint64(len(ws))*2, 0)
}

func writeGuestANSIStringN(mem *mmu.MMU, ptr uint64, s string, cch int) {
	if ptr == 0 || cch <= 0 {
		return
	}
	if len(s) >= cch {
		s = s[:cch-1]
	}
	writeGuestANSIString(mem, ptr, s)
}

func mapStorageError(err error) uint32 {
	if err == nil {
		return S_OK
	}
	if os.IsNotExist(err) {
		return STG_E_FILENOTFOUND
	}
	if os.IsPermission(err) {
		return STG_E_ACCESSDENIED
	}
	var pathErr *os.PathError
	if ok := strings.Contains(strings.ToLower(err.Error()), "path"); ok {
		return STG_E_PATHNOTFOUND
	}
	_ = pathErr
	return E_FAIL
}

func storageHostPath(winPath string) (string, error) {
	winPath = strings.TrimSpace(winPath)
	if winPath == "" {
		return "", hresultError(STG_E_INVALIDNAME)
	}
	host := filepath.Clean(winPathToVFS(winPath))
	if host == "" || host == "." {
		return "", hresultError(STG_E_INVALIDNAME)
	}
	return host, nil
}

func storageElementPath(basePath, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return "", hresultError(STG_E_INVALIDNAME)
	}
	return filepath.Join(basePath, name), nil
}

func storageMarkerPath(path string) string {
	return filepath.Join(path, ".govm-storage")
}

func storageCLSIDPath(path string) string {
	return filepath.Join(path, ".govm-clsid")
}

func storageStateBitsPath(path string) string {
	return filepath.Join(path, ".govm-statebits")
}

func isStorageMetadataName(name string) bool {
	return strings.HasPrefix(name, ".govm-")
}

func loadStorageMetadata(ds *dirStorage) {
	if ds == nil {
		return
	}
	if data, err := os.ReadFile(storageCLSIDPath(ds.path)); err == nil {
		if guid, ok := parseGUIDString(strings.TrimSpace(string(data))); ok {
			ds.clsid = guid
		}
	}
	if data, err := os.ReadFile(storageStateBitsPath(ds.path)); err == nil {
		var stateBits uint32
		if _, scanErr := fmt.Sscanf(strings.TrimSpace(string(data)), "%x", &stateBits); scanErr == nil {
			ds.stateBits = stateBits
		}
	}
}

func persistStorageMetadata(ds *dirStorage) {
	if ds == nil || ds.path == "" {
		return
	}
	_ = os.MkdirAll(ds.path, 0755)
	_ = os.WriteFile(storageMarkerPath(ds.path), []byte("govm\n"), 0644)
	if ds.clsid != (GUID{}) {
		_ = os.WriteFile(storageCLSIDPath(ds.path), []byte(guidString(ds.clsid)), 0644)
	}
	_ = os.WriteFile(storageStateBitsPath(ds.path), []byte(fmt.Sprintf("%08X\n", ds.stateBits)), 0644)
}

func listStorageEntries(path string) ([]statStgEntry, error) {
	dirEntries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	entries := make([]statStgEntry, 0, len(dirEntries))
	for _, entry := range dirEntries {
		if isStorageMetadataName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		item := statStgEntry{
			name:    entry.Name(),
			modTime: info.ModTime(),
		}
		if entry.IsDir() {
			item.stgType = STGTY_STORAGE
			sub := &dirStorage{path: filepath.Join(path, entry.Name())}
			loadStorageMetadata(sub)
			item.clsid = sub.clsid
		} else {
			item.stgType = STGTY_STREAM
			item.size = uint64(info.Size())
		}
		entries = append(entries, item)
	}
	return entries, nil
}

func copyPathRecursive(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := os.MkdirAll(dst, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyPathRecursive(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func writeSTATSTG(mem *mmu.MMU, cs *comState, ptr uint64, entry statStgEntry, grfStatFlag uint32, stateBits uint32) {
	if ptr == 0 {
		return
	}
	mem.WriteBytes(ptr, make([]byte, 72))
	if grfStatFlag&STATFLAG_NONAME == 0 && entry.name != "" {
		nameRunes := []rune(entry.name)
		namePtr := cs.allocTaskMem(uint64(len(nameRunes)+1)*2, true)
		if namePtr != 0 {
			writeGuestUTF16String(mem, namePtr, entry.name)
			mem.Write64(ptr, namePtr)
		}
	}
	mem.Write32(ptr+8, entry.stgType)
	mem.Write64Raw(ptr+16, entry.size)
	ft := filetimeFromTime(entry.modTime)
	mem.Write64Raw(ptr+24, ft)
	mem.Write64Raw(ptr+32, ft)
	mem.Write64Raw(ptr+40, ft)
	writeGUID(mem, ptr+48, entry.clsid)
	mem.Write32(ptr+64, stateBits)
}

func mapStreamFlags(grfMode uint32, create bool) int {
	var flags int
	switch grfMode & 0x3 {
	case STGM_READWRITE:
		flags = os.O_RDWR
	case STGM_WRITE:
		flags = os.O_WRONLY
	default:
		flags = os.O_RDONLY
	}
	if create || grfMode&STGM_CREATE != 0 {
		flags |= os.O_CREATE
	}
	if grfMode&STGM_CREATE != 0 {
		flags |= os.O_TRUNC
	}
	return flags
}

func newMemoryBuffer(mem *mmu.MMU, hglobal uint64, deleteOnRelease bool) *memoryBuffer {
	buf := &memoryBuffer{
		hglobal:         hglobal,
		deleteOnRelease: deleteOnRelease,
		refs:            1,
	}
	if hglobal != 0 {
		_, size, mapped, _ := mem.QueryRegion(hglobal)
		if mapped && size > 0 {
			if data, err := mem.ReadBytes(hglobal, int(size)); err == nil {
				buf.data = append(buf.data, data...)
			}
		}
	}
	return buf
}

func (b *memoryBuffer) addRef() {
	if b != nil {
		b.refs++
	}
}

func (b *memoryBuffer) release(mem *mmu.MMU) {
	if b == nil {
		return
	}
	if b.refs > 0 {
		b.refs--
	}
	if b.refs == 0 && b.deleteOnRelease && b.hglobal != 0 {
		_, size, mapped, _ := mem.QueryRegion(b.hglobal)
		if mapped && size > 0 {
			mem.Munmap(b.hglobal, size)
		}
		b.hglobal = 0
	}
}

func (b *memoryBuffer) setSize(size int64) error {
	if size < 0 {
		return hresultError(E_INVALIDARG)
	}
	if size <= int64(len(b.data)) {
		b.data = b.data[:int(size)]
		return nil
	}
	growth := int(size) - len(b.data)
	b.data = append(b.data, make([]byte, growth)...)
	return nil
}

func (b *memoryBuffer) syncToHGlobal(mem *mmu.MMU) uint64 {
	if b == nil {
		return 0
	}
	sizeNeeded := uint64(len(b.data))
	if sizeNeeded == 0 {
		sizeNeeded = 1
	}
	if b.hglobal != 0 {
		_, curSize, mapped, _ := mem.QueryRegion(b.hglobal)
		if !mapped || curSize < sizeNeeded {
			if mapped && curSize > 0 && b.deleteOnRelease {
				mem.Munmap(b.hglobal, curSize)
			}
			b.hglobal = 0
		}
	}
	if b.hglobal == 0 {
		b.hglobal = mem.Mmap(0, sizeNeeded, mmu.PermRead|mmu.PermWrite)
	}
	if b.hglobal != 0 {
		if len(b.data) > 0 {
			mem.WriteBytes(b.hglobal, b.data)
		}
	}
	return b.hglobal
}

func streamSize(data interface{}) (int64, error) {
	switch s := data.(type) {
	case *memStream:
		return int64(len(s.buffer.data)), nil
	case *fileStream:
		info, err := s.file.Stat()
		if err != nil {
			return 0, err
		}
		return info.Size(), nil
	default:
		return 0, hresultError(E_INVALIDARG)
	}
}

func streamReadAt(data interface{}, pos int64, dst []byte) (int, error) {
	if pos < 0 {
		return 0, hresultError(E_INVALIDARG)
	}
	switch s := data.(type) {
	case *memStream:
		if pos >= int64(len(s.buffer.data)) {
			return 0, io.EOF
		}
		n := copy(dst, s.buffer.data[int(pos):])
		if n < len(dst) {
			return n, io.EOF
		}
		return n, nil
	case *fileStream:
		return s.file.ReadAt(dst, pos)
	default:
		return 0, hresultError(E_INVALIDARG)
	}
}

func streamWriteAt(data interface{}, pos int64, src []byte) (int, error) {
	if pos < 0 {
		return 0, hresultError(E_INVALIDARG)
	}
	switch s := data.(type) {
	case *memStream:
		end := pos + int64(len(src))
		if err := s.buffer.setSize(end); err != nil {
			return 0, err
		}
		return copy(s.buffer.data[int(pos):], src), nil
	case *fileStream:
		return s.file.WriteAt(src, pos)
	default:
		return 0, hresultError(E_INVALIDARG)
	}
}

func streamSetSize(data interface{}, size int64) error {
	switch s := data.(type) {
	case *memStream:
		return s.buffer.setSize(size)
	case *fileStream:
		return s.file.Truncate(size)
	default:
		return hresultError(E_INVALIDARG)
	}
}

func streamCommit(data interface{}) error {
	switch s := data.(type) {
	case *memStream:
		return nil
	case *fileStream:
		return s.file.Sync()
	default:
		return hresultError(E_INVALIDARG)
	}
}

func streamName(data interface{}) string {
	switch s := data.(type) {
	case *memStream:
		return s.name
	case *fileStream:
		return s.name
	default:
		return ""
	}
}

func streamModTime(data interface{}) time.Time {
	switch s := data.(type) {
	case *memStream:
		return time.Time{}
	case *fileStream:
		info, err := s.file.Stat()
		if err == nil {
			return info.ModTime()
		}
	}
	return time.Time{}
}

func (cs *comState) currentThreadToken() uint64 {
	if cs != nil && cs.hctx != nil && cs.hctx.CurrentCPU != nil {
		if tls := cs.hctx.CurrentCPU.GetTLS(); tls != 0 {
			return tls
		}
	}
	return 1
}

func (cs *comState) threadState() *comThreadState {
	token := cs.currentThreadToken()
	if state := cs.threadStates[token]; state != nil {
		return state
	}
	state := &comThreadState{apartmentType: COINIT_APARTMENTTHREADED}
	cs.threadStates[token] = state
	return state
}

func (cs *comState) initialize(apartmentType uint32) uint32 {
	state := cs.threadState()
	if state.initialized {
		if state.apartmentType != apartmentType {
			return RPC_E_CHANGED_MODE
		}
		state.initCount++
		cs.initialized = true
		cs.initCount = state.initCount
		cs.apartmentType = state.apartmentType
		return S_OK
	}
	state.initialized = true
	state.initCount = 1
	state.apartmentType = apartmentType
	cs.initialized = true
	cs.initCount = state.initCount
	cs.apartmentType = state.apartmentType
	return S_OK
}

func (cs *comState) uninitialize() {
	state := cs.threadState()
	if state.initCount > 0 {
		state.initCount--
	}
	if state.initCount == 0 {
		state.initialized = false
		state.apartmentType = COINIT_APARTMENTTHREADED
	}
	cs.initialized = state.initialized
	cs.initCount = state.initCount
	cs.apartmentType = state.apartmentType
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

func (cs *comState) createGuestObject(mem *mmu.MMU, iid GUID, methods int, stdcallArgs ...[]int) (*comObject, error) {
	if methods < 3 {
		methods = 3
	}
	// Use 64-bit layout for allocation; detect 32-bit from address range.
	totalSize := uint64(8 + methods*8 + methods*16)
	objAddr := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if objAddr == 0 {
		return nil, hresultError(E_OUTOFMEMORY)
	}
	// PE32 processes live entirely below 4 GB - use 4-byte vtable pointers.
	ptrSize := 8
	if objAddr < 0x100000000 {
		ptrSize = 4
	}
	vtableAddr := objAddr + uint64(ptrSize)
	stubBase := vtableAddr + uint64(methods*ptrSize)
	obj := &comObject{
		primaryIID:    iid,
		refCount:      1,
		vtableAddr:    vtableAddr,
		objectAddr:    objAddr,
		kind:          "iunknown",
		supportedIIDs: map[GUID]bool{IID_IUnknown: true, iid: true},
		altInterfaces: make(map[GUID]uint64),
	}
	cs.objects[objAddr] = obj
	for i := 0; i < methods; i++ {
		trapID := cs.nextTrapID
		cs.nextTrapID++
		methodIndex := i
		cs.disp.RegisterHandler(trapID, fmt.Sprintf("com!%s[%d]", guidString(iid), methodIndex), func(ctx *ntapi.TrapContext) uint32 {
			return cs.dispatchObjectMethod(ctx, methodIndex)
		})
		if len(stdcallArgs) > 0 && i < len(stdcallArgs[0]) {
			cs.disp.SetStdcallArgCount(trapID, stdcallArgs[0][i])
		}
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
		if ptrSize == 4 {
			mem.Write32(vtableAddr+uint64(i*4), uint32(stubAddr))
		} else {
			mem.Write64(vtableAddr+uint64(i*8), stubAddr)
		}
	}
	if ptrSize == 4 {
		mem.Write32(objAddr, uint32(vtableAddr))
	} else {
		mem.Write64(objAddr, vtableAddr)
	}
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

func (cs *comState) createMemoryAllocatorObject(iid GUID) (*comObject, error) {
	switch {
	case guidEqual(iid, IID_IUnknown), guidEqual(iid, IID_IMalloc):
		obj, err := cs.createIMallocObject()
		if err != nil {
			return nil, err
		}
		obj.clsid = CLSID_MemoryAllocator
		return obj, nil
	default:
		return nil, hresultError(E_NOINTERFACE)
	}
}

func (cs *comState) createShellFolderObject(winPath string) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IShellFolder, 13)
	if err != nil {
		return nil, err
	}
	obj.kind = "shell-folder"
	obj.data = &shellFolderData{path: canonicalizeWinPath(winPath)}
	obj.supportedIIDs[IID_IShellFolder] = true
	return obj, nil
}

func (cs *comState) createEnumIDListObject(items []string, start int) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IEnumIDList, 7)
	if err != nil {
		return nil, err
	}
	obj.kind = "enum-idlist"
	obj.data = &enumIDListData{items: items, index: start}
	obj.supportedIIDs[IID_IEnumIDList] = true
	return obj, nil
}

func (cs *comState) createShellLinkObjects(iid GUID) (*comObject, error) {
	switch {
	case guidEqual(iid, IID_IUnknown), guidEqual(iid, IID_IShellLinkW), guidEqual(iid, IID_IShellLinkA), guidEqual(iid, IID_IPersistFile), guidEqual(iid, IID_IPersist):
	default:
		return nil, hresultError(E_NOINTERFACE)
	}
	data := &shellLinkData{showCmd: 1}
	linkW, err := cs.createGuestObject(cs.mem, IID_IShellLinkW, 21)
	if err != nil {
		return nil, err
	}
	linkA, err := cs.createGuestObject(cs.mem, IID_IShellLinkA, 21)
	if err != nil {
		return nil, err
	}
	persist, err := cs.createGuestObject(cs.mem, IID_IPersistFile, 9)
	if err != nil {
		return nil, err
	}
	for _, obj := range []*comObject{linkW, linkA, persist} {
		obj.clsid = CLSID_ShellLink
		obj.data = data
	}
	linkW.kind = "shell-link-w"
	linkA.kind = "shell-link-a"
	persist.kind = "persist-file"
	linkW.supportedIIDs[IID_IShellLinkW] = true
	linkA.supportedIIDs[IID_IShellLinkA] = true
	persist.supportedIIDs[IID_IPersistFile] = true
	persist.supportedIIDs[IID_IPersist] = true
	linkW.altInterfaces[IID_IShellLinkA] = linkA.objectAddr
	linkW.altInterfaces[IID_IPersistFile] = persist.objectAddr
	linkW.altInterfaces[IID_IPersist] = persist.objectAddr
	linkA.altInterfaces[IID_IShellLinkW] = linkW.objectAddr
	linkA.altInterfaces[IID_IPersistFile] = persist.objectAddr
	linkA.altInterfaces[IID_IPersist] = persist.objectAddr
	persist.altInterfaces[IID_IShellLinkW] = linkW.objectAddr
	persist.altInterfaces[IID_IShellLinkA] = linkA.objectAddr
	switch {
	case guidEqual(iid, IID_IShellLinkA):
		return linkA, nil
	case guidEqual(iid, IID_IPersistFile), guidEqual(iid, IID_IPersist):
		return persist, nil
	default:
		return linkW, nil
	}
}

func (cs *comState) createMemoryStreamObject(buffer *memoryBuffer, name string) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IStream, 14)
	if err != nil {
		return nil, err
	}
	obj.kind = "istream"
	obj.data = &memStream{buffer: buffer, name: name}
	obj.supportedIIDs[IID_IStream] = true
	return obj, nil
}

func (cs *comState) createFileOpenDialogObject(iid GUID) (*comObject, error) {
	switch {
	case guidEqual(iid, IID_IUnknown), guidEqual(iid, IID_IModalWindow), guidEqual(iid, IID_IFileDialog), guidEqual(iid, IID_IFileOpenDialog):
	default:
		return nil, hresultError(E_NOINTERFACE)
	}
	obj, err := cs.createGuestObject(cs.mem, IID_IFileOpenDialog, 27)
	if err != nil {
		return nil, err
	}
	obj.clsid = CLSID_FileOpenDialog
	obj.kind = "file-open-dialog"
	obj.data = &fileOpenDialogData{fileTypeIndex: 1}
	obj.supportedIIDs[IID_IModalWindow] = true
	obj.supportedIIDs[IID_IFileDialog] = true
	obj.supportedIIDs[IID_IFileOpenDialog] = true
	return obj, nil
}

func (cs *comState) createFileStreamObject(path, name string, grfMode uint32, create bool) (*comObject, error) {
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(path, mapStreamFlags(grfMode, create), 0644)
	if err != nil {
		return nil, err
	}
	obj, err := cs.createGuestObject(cs.mem, IID_IStream, 14)
	if err != nil {
		file.Close()
		return nil, err
	}
	obj.kind = "istream"
	obj.data = &fileStream{path: path, file: file, name: name, grfMode: grfMode}
	obj.supportedIIDs[IID_IStream] = true
	return obj, nil
}

func (cs *comState) createStorageObject(path, name string, grfMode uint32, deleteOnRelease bool) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IStorage, 18)
	if err != nil {
		return nil, err
	}
	ds := &dirStorage{
		path:            path,
		name:            name,
		grfMode:         grfMode,
		deleteOnRelease: deleteOnRelease,
	}
	loadStorageMetadata(ds)
	obj.kind = "istorage"
	obj.data = ds
	obj.supportedIIDs[IID_IStorage] = true
	return obj, nil
}

func (cs *comState) createLockBytesObject(buffer *memoryBuffer) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ILockBytes, 10)
	if err != nil {
		return nil, err
	}
	obj.kind = "ilockbytes"
	obj.data = &lockBytes{buffer: buffer}
	obj.supportedIIDs[IID_ILockBytes] = true
	return obj, nil
}

func (cs *comState) createEnumSTATSTGObject(entries []statStgEntry) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IEnumSTATSTG, 7)
	if err != nil {
		return nil, err
	}
	obj.kind = "ienumstatstg"
	obj.data = &enumSTATSTG{entries: entries}
	obj.supportedIIDs[IID_IEnumSTATSTG] = true
	return obj, nil
}

func (cs *comState) createTypeInfoObject(lcid uint32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ITypeInfo, 22)
	if err != nil {
		return nil, err
	}
	obj.kind = "type-info"
	obj.supportedIIDs[IID_ITypeInfo] = true
	obj.data = &typeInfoData{
		lcid:     lcid,
		nextID:   1,
		names:    make(map[string]int32),
		dispToID: make(map[int32]string),
	}
	return obj, nil
}

func (cs *comState) createStdDispatchObject(instance, typeInfo uint64) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IDispatch, 7)
	if err != nil {
		return nil, err
	}
	obj.kind = "std-dispatch"
	obj.supportedIIDs[IID_IDispatch] = true
	obj.data = &stdDispatchData{instance: instance, typeInfo: typeInfo}
	return obj, nil
}

func (cs *comState) createTypeLibObject(path string) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_ITypeLib, 13)
	if err != nil {
		return nil, err
	}
	obj.kind = "type-lib"
	obj.supportedIIDs[IID_ITypeLib] = true
	obj.data = &typeLibData{path: path}
	return obj, nil
}

func (cs *comState) createErrorInfoObjects() (*comObject, *comObject, error) {
	createObj, err := cs.createGuestObject(cs.mem, IID_ICreateErrorInfo, 8)
	if err != nil {
		return nil, nil, err
	}
	readObj, err := cs.createGuestObject(cs.mem, IID_IErrorInfo, 8)
	if err != nil {
		delete(cs.objects, createObj.objectAddr)
		return nil, nil, err
	}
	createData := &errorInfoData{peer: readObj.objectAddr}
	readData := &errorInfoData{peer: createObj.objectAddr}
	createObj.kind = "create-error-info"
	createObj.data = createData
	createObj.supportedIIDs[IID_ICreateErrorInfo] = true
	createObj.supportedIIDs[IID_IErrorInfo] = true
	readObj.kind = "error-info"
	readObj.data = readData
	readObj.supportedIIDs[IID_IErrorInfo] = true
	readObj.supportedIIDs[IID_ICreateErrorInfo] = true
	return createObj, readObj, nil
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
		switch data := obj.data.(type) {
		case *memStream:
			if data.buffer != nil {
				data.buffer.release(cs.mem)
			}
		case *fileStream:
			if data.file != nil {
				_ = data.file.Close()
			}
		case *lockBytes:
			if data.buffer != nil {
				data.buffer.release(cs.mem)
			}
		case *dirStorage:
			if data.deleteOnRelease && data.path != "" {
				_ = os.RemoveAll(data.path)
			}
		case *wicStream:
			switch s := data.data.(type) {
			case *memStream:
				if s.buffer != nil {
					s.buffer.release(cs.mem)
				}
			case *fileStream:
				if s.file != nil {
					_ = s.file.Close()
				}
			}
		case *dsBufferObject:
			cleanupPendingLock(cs.mem, data.pendingLock)
			data.pendingLock = nil
		}
		delete(cs.objects, obj.objectAddr)
	}
	return uint32(obj.refCount)
}

// writeGuestPtr writes a pointer-sized value to guest memory, respecting PE32/PE64.
func writeGuestPtr(ctx *ntapi.TrapContext, addr, val uint64) {
	if ctx.State != nil && ctx.State.Is32 {
		ctx.Mem.Write32(addr, uint32(val))
	} else {
		ctx.Mem.Write64(addr, val)
	}
}

func (cs *comState) queryInterface(ctx *ntapi.TrapContext, obj *comObject) uint32 {
	riidPtr := ctx.Arg(1)
	ppv := ctx.Arg(2)
	if ppv == 0 {
		return E_POINTER
	}
	writeGuestPtr(ctx, ppv, 0)
	if riidPtr == 0 {
		return E_POINTER
	}
	iid := readGUID(ctx.Mem, riidPtr)
	if data, ok := obj.data.(*errorInfoData); ok {
		switch {
		case obj.kind == "create-error-info" && guidEqual(iid, IID_IErrorInfo):
			if peer := cs.objects[data.peer]; peer != nil {
				writeGuestPtr(ctx, ppv, peer.objectAddr)
				cs.addRef(peer)
				return S_OK
			}
		case obj.kind == "error-info" && guidEqual(iid, IID_ICreateErrorInfo):
			if peer := cs.objects[data.peer]; peer != nil {
				writeGuestPtr(ctx, ppv, peer.objectAddr)
				cs.addRef(peer)
				return S_OK
			}
		}
	}
	if alt, ok := obj.altInterfaces[iid]; ok && alt != 0 {
		if peer := cs.objects[alt]; peer != nil {
			writeGuestPtr(ctx, ppv, peer.objectAddr)
			cs.addRef(peer)
			return S_OK
		}
	}
	if obj.supportedIIDs[iid] || guidEqual(iid, IID_IUnknown) {
		writeGuestPtr(ctx, ppv, obj.objectAddr)
		cs.addRef(obj)
		return S_OK
	}
	return E_NOINTERFACE
}

func (cs *comState) dispatchIDispatch(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch method {
	case 3:
		pctinfo := ctx.Arg(1)
		if pctinfo != 0 {
			if obj.kind == "std-dispatch" {
				ctx.Mem.Write32(pctinfo, 1)
			} else {
				ctx.Mem.Write32(pctinfo, 0)
			}
		}
		return S_OK
	case 4:
		iTInfo := uint32(ctx.Arg(1))
		ppTInfo := ctx.Arg(3)
		if ppTInfo == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppTInfo, 0)
		if iTInfo != 0 {
			return DISP_E_BADPARAMCOUNT
		}
		if sd, ok := obj.data.(*stdDispatchData); ok && sd.typeInfo != 0 {
			ctx.Mem.Write64(ppTInfo, sd.typeInfo)
			cs.addRefPtr(sd.typeInfo)
			return S_OK
		}
		return E_NOTIMPL
	case 5:
		riid := ctx.Arg(1)
		rgszNames := ctx.Arg(2)
		cNames := int(ctx.Arg(3))
		rgDispID := ctx.Arg(4)
		if riid != 0 && !guidEqual(readGUID(ctx.Mem, riid), GUID{}) {
			return E_INVALIDARG
		}
		if rgszNames == 0 || rgDispID == 0 || cNames <= 0 {
			return E_INVALIDARG
		}
		tiPtr := obj.objectAddr
		if sd, ok := obj.data.(*stdDispatchData); ok {
			tiPtr = sd.typeInfo
		}
		for i := 0; i < cNames; i++ {
			namePtr, _ := ctx.Mem.Read64(rgszNames + uint64(i)*8)
			if namePtr == 0 {
				return DISP_E_UNKNOWNNAME
			}
			name := hctxReadUTF16(ctx.Mem, namePtr)
			id, ok := cs.lookupDispID(tiPtr, name, false)
			if !ok {
				return DISP_E_UNKNOWNNAME
			}
			ctx.Mem.Write32(rgDispID+uint64(i)*4, uint32(id))
		}
		return S_OK
	case 6:
		if obj.kind == "std-dispatch" {
			return DISP_E_MEMBERNOTFOUND
		}
		return E_NOTIMPL
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) allocTaskMemUTF16String(s string) uint64 {
	ws := utf16Encode(s)
	ptr := cs.allocTaskMem(uint64(len(ws)+1)*2, true)
	if ptr == 0 {
		return 0
	}
	for i, w := range ws {
		cs.mem.Write16(ptr+uint64(i)*2, w)
	}
	cs.mem.Write16(ptr+uint64(len(ws))*2, 0)
	return ptr
}

func (cs *comState) dispatchFileOpenDialog(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*fileOpenDialogData)
	if data == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		return 0x800704C7
	case 4:
		return S_OK
	case 5:
		data.fileTypeIndex = uint32(ctx.Arg(1))
		return S_OK
	case 6:
		piFileType := ctx.Arg(1)
		if piFileType == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(piFileType, data.fileTypeIndex)
		return S_OK
	case 7:
		pdwCookie := ctx.Arg(2)
		if pdwCookie == 0 {
			return E_POINTER
		}
		data.nextAdviseToken++
		if data.nextAdviseToken == 0 {
			data.nextAdviseToken = 1
		}
		ctx.Mem.Write32(pdwCookie, data.nextAdviseToken)
		return S_OK
	case 8:
		return S_OK
	case 9:
		data.options = uint32(ctx.Arg(1))
		return S_OK
	case 10:
		pfos := ctx.Arg(1)
		if pfos == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pfos, data.options)
		return S_OK
	case 14:
		data.fileName = readGuestUTF16String(cs.mem, ctx.Arg(1))
		return S_OK
	case 15:
		pszName := ctx.Arg(1)
		if pszName == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(pszName, 0)
		ptr := cs.allocTaskMemUTF16String(data.fileName)
		if ptr == 0 && data.fileName != "" {
			return E_OUTOFMEMORY
		}
		ctx.Mem.Write64(pszName, ptr)
		return S_OK
	case 16:
		data.title = readGuestUTF16String(cs.mem, ctx.Arg(1))
		return S_OK
	case 17:
		data.okButtonLabel = readGuestUTF16String(cs.mem, ctx.Arg(1))
		return S_OK
	case 18:
		data.fileNameLabel = readGuestUTF16String(cs.mem, ctx.Arg(1))
		return S_OK
	case 21:
		data.defaultExt = readGuestUTF16String(cs.mem, ctx.Arg(1))
		return S_OK
	case 22:
		return S_OK
	case 23:
		data.clientGUID = GUID{}
		data.nextAdviseToken = 0
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchTypeInfo(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	ti, _ := obj.data.(*typeInfoData)
	if ti == nil {
		return E_FAIL
	}
	switch method {
	case 10:
		rgszNames := ctx.Arg(1)
		cNames := int(ctx.Arg(2))
		rgMemID := ctx.Arg(3)
		if rgszNames == 0 || rgMemID == 0 || cNames <= 0 {
			return E_INVALIDARG
		}
		for i := 0; i < cNames; i++ {
			namePtr, _ := ctx.Mem.Read64(rgszNames + uint64(i)*8)
			if namePtr == 0 {
				return DISP_E_UNKNOWNNAME
			}
			name := hctxReadUTF16(ctx.Mem, namePtr)
			id, ok := cs.lookupDispID(obj.objectAddr, name, false)
			if !ok {
				return DISP_E_UNKNOWNNAME
			}
			ctx.Mem.Write32(rgMemID+uint64(i)*4, uint32(id))
		}
		return S_OK
	case 11:
		return DISP_E_MEMBERNOTFOUND
	case 12:
		helpString := ctx.Arg(2)
		if helpString != 0 {
			ctx.Mem.Write64(helpString, 0)
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func hctxReadUTF16(mem *mmu.MMU, addr uint64) string {
	if addr == 0 {
		return ""
	}
	var data []byte
	for i := uint64(0); ; i += 2 {
		w, _ := mem.Read16(addr + i)
		if w == 0 {
			break
		}
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], w)
		data = append(data, tmp[:]...)
	}
	return decodeUTF16LEString(data)
}

func (cs *comState) dispatchErrorInfo(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*errorInfoData)
	if data == nil {
		return E_FAIL
	}
	switch obj.kind {
	case "create-error-info":
		switch method {
		case 3:
			if guidPtr := ctx.Arg(1); guidPtr != 0 {
				data.guid = readGUID(ctx.Mem, guidPtr)
				if peerObj := cs.objects[data.peer]; peerObj != nil {
					if peer, _ := peerObj.data.(*errorInfoData); peer != nil {
						peer.guid = data.guid
					}
				}
			}
			return S_OK
		case 4:
			data.source = hctxReadUTF16(ctx.Mem, ctx.Arg(1))
		case 5:
			data.description = hctxReadUTF16(ctx.Mem, ctx.Arg(1))
		case 6:
			data.helpFile = hctxReadUTF16(ctx.Mem, ctx.Arg(1))
		case 7:
			data.helpContext = uint32(ctx.Arg(1))
		default:
			return E_NOTIMPL
		}
		if peerObj := cs.objects[data.peer]; peerObj != nil {
			if peer, _ := peerObj.data.(*errorInfoData); peer != nil {
				peer.source = data.source
				peer.description = data.description
				peer.helpFile = data.helpFile
				peer.helpContext = data.helpContext
			}
		}
		return S_OK
	case "error-info":
		switch method {
		case 3:
			if pguid := ctx.Arg(1); pguid != 0 {
				writeGUID(ctx.Mem, pguid, data.guid)
			}
			return S_OK
		case 4:
			if pp := ctx.Arg(1); pp != 0 {
				ctx.Mem.Write64(pp, cs.allocBSTRString(data.source))
			}
			return S_OK
		case 5:
			if pp := ctx.Arg(1); pp != 0 {
				ctx.Mem.Write64(pp, cs.allocBSTRString(data.description))
			}
			return S_OK
		case 6:
			if pp := ctx.Arg(1); pp != 0 {
				ctx.Mem.Write64(pp, cs.allocBSTRString(data.helpFile))
			}
			return S_OK
		case 7:
			if pctx := ctx.Arg(1); pctx != 0 {
				ctx.Mem.Write32(pctx, data.helpContext)
			}
			return S_OK
		}
	}
	return E_NOTIMPL
}

func (cs *comState) dispatchTypeLib(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	switch method {
	case 3:
		ctx.SetReturn(0)
		return 0
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

func (cs *comState) dispatchShellLink(ctx *ntapi.TrapContext, obj *comObject, method int, wide bool) uint32 {
	data, _ := obj.data.(*shellLinkData)
	if data == nil {
		return E_FAIL
	}
	readStr := func(ptr uint64) string {
		if wide {
			return readGuestUTF16String(cs.mem, ptr)
		}
		return readGuestANSIString(cs.mem, ptr)
	}
	writeStr := func(ptr uint64, s string, cch int) {
		if wide {
			writeGuestUTF16StringN(cs.mem, ptr, s, cch)
		} else {
			writeGuestANSIStringN(cs.mem, ptr, s, cch)
		}
	}
	switch method {
	case 3:
		writeStr(ctx.Arg(1), data.path, int(ctx.Arg(2)))
		if pfd := ctx.Arg(3); pfd != 0 {
			cs.mem.WriteBytes(pfd, make([]byte, 320))
		}
		return S_OK
	case 4:
		ppidl := ctx.Arg(1)
		if ppidl == 0 {
			return E_POINTER
		}
		pidl := allocPIDLFromPath(cs.mem, cs.allocTaskMem, data.path)
		if pidl == 0 {
			return E_OUTOFMEMORY
		}
		cs.mem.Write64(ppidl, pidl)
		return S_OK
	case 5:
		data.path = pidlPathFromMemory(cs.mem, ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 6:
		writeStr(ctx.Arg(1), data.description, int(ctx.Arg(2)))
		return S_OK
	case 7:
		data.description = readStr(ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 8:
		writeStr(ctx.Arg(1), data.workingDir, int(ctx.Arg(2)))
		return S_OK
	case 9:
		data.workingDir = readStr(ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 10:
		writeStr(ctx.Arg(1), data.arguments, int(ctx.Arg(2)))
		return S_OK
	case 11:
		data.arguments = readStr(ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 12:
		if ptr := ctx.Arg(1); ptr != 0 {
			cs.mem.Write16(ptr, data.hotkey)
		}
		return S_OK
	case 13:
		data.hotkey = uint16(ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 14:
		if ptr := ctx.Arg(1); ptr != 0 {
			cs.mem.Write32(ptr, uint32(data.showCmd))
		}
		return S_OK
	case 15:
		data.showCmd = int32(ctx.Arg(1))
		data.dirty = true
		return S_OK
	case 16:
		writeStr(ctx.Arg(1), data.iconLocation, int(ctx.Arg(2)))
		if pIndex := ctx.Arg(3); pIndex != 0 {
			cs.mem.Write32(pIndex, uint32(data.iconIndex))
		}
		return S_OK
	case 17:
		data.iconLocation = readStr(ctx.Arg(1))
		data.iconIndex = int32(ctx.Arg(2))
		data.dirty = true
		return S_OK
	case 18:
		return S_OK
	case 19:
		if data.path == "" {
			return S_FALSE
		}
		if !isAbsoluteWinPath(data.path) && data.currentFile != "" {
			base := filepath.Dir(data.currentFile)
			data.path = canonicalizeWinPath(base + `\` + data.path)
		}
		return S_OK
	case 20:
		data.path = readStr(ctx.Arg(1))
		data.dirty = true
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchPersistFile(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*shellLinkData)
	if data == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		if pClassID := ctx.Arg(1); pClassID != 0 {
			writeGUID(cs.mem, pClassID, CLSID_ShellLink)
			return S_OK
		}
		return E_POINTER
	case 4:
		if data.dirty {
			return S_OK
		}
		return S_FALSE
	case 5:
		path := readGuestUTF16String(cs.mem, ctx.Arg(1))
		if path == "" {
			return STG_E_INVALIDNAME
		}
		b, err := os.ReadFile(winToLinuxPath(path))
		if err != nil {
			if os.IsNotExist(err) {
				return STG_E_FILENOTFOUND
			}
			return E_FAIL
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			switch strings.TrimSpace(k) {
			case "Path":
				data.path = strings.TrimSpace(v)
			case "Description":
				data.description = strings.TrimSpace(v)
			case "WorkingDirectory":
				data.workingDir = strings.TrimSpace(v)
			case "Arguments":
				data.arguments = strings.TrimSpace(v)
			case "IconLocation":
				data.iconLocation = strings.TrimSpace(v)
			case "IconIndex":
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					data.iconIndex = int32(n)
				}
			case "ShowCmd":
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					data.showCmd = int32(n)
				}
			case "Hotkey":
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					data.hotkey = uint16(n)
				}
			}
		}
		data.currentFile = path
		data.dirty = false
		return S_OK
	case 6:
		path := readGuestUTF16String(cs.mem, ctx.Arg(1))
		if path == "" {
			path = data.currentFile
		}
		if path == "" {
			return STG_E_INVALIDNAME
		}
		host := winToLinuxPath(path)
		if err := os.MkdirAll(filepath.Dir(host), 0o755); err != nil {
			return STG_E_PATHNOTFOUND
		}
		content := strings.Join([]string{
			"[ShellLink]",
			"Path=" + data.path,
			"Description=" + data.description,
			"WorkingDirectory=" + data.workingDir,
			"Arguments=" + data.arguments,
			"IconLocation=" + data.iconLocation,
			"IconIndex=" + strconv.Itoa(int(data.iconIndex)),
			"ShowCmd=" + strconv.Itoa(int(data.showCmd)),
			"Hotkey=" + strconv.Itoa(int(data.hotkey)),
			"",
		}, "\n")
		if err := os.WriteFile(host, []byte(content), 0o644); err != nil {
			return E_FAIL
		}
		if ctx.Arg(2) != 0 {
			data.currentFile = path
		}
		data.dirty = false
		return S_OK
	case 7:
		if path := readGuestUTF16String(cs.mem, ctx.Arg(1)); path != "" {
			data.currentFile = path
		}
		data.dirty = false
		return S_OK
	case 8:
		ppszFile := ctx.Arg(1)
		if ppszFile == 0 {
			return E_POINTER
		}
		cur := data.currentFile
		if cur == "" {
			cur = data.path
		}
		buf := cs.allocTaskMem(uint64((len(utf16Encode(cur))+1)*2), true)
		if buf == 0 {
			return E_OUTOFMEMORY
		}
		writeGuestUTF16String(cs.mem, buf, cur)
		cs.mem.Write64(ppszFile, buf)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchShellFolder(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*shellFolderData)
	if data == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		name := readGuestUTF16String(cs.mem, ctx.Arg(3))
		if name == "" {
			name = data.path
		}
		if !isAbsoluteWinPath(name) {
			name = canonicalizeWinPath(data.path + `\` + name)
		}
		if pchEaten := ctx.Arg(4); pchEaten != 0 {
			cs.mem.Write32(pchEaten, uint32(len(utf16Encode(readGuestUTF16String(cs.mem, ctx.Arg(3))))))
		}
		if ppidl := ctx.Arg(5); ppidl != 0 {
			pidl := allocPIDLFromPath(cs.mem, cs.allocTaskMem, name)
			if pidl == 0 {
				return E_OUTOFMEMORY
			}
			cs.mem.Write64(ppidl, pidl)
		}
		if attrs := ctx.Arg(6); attrs != 0 {
			cs.mem.Write32(attrs, 0)
		}
		return S_OK
	case 4:
		ppenum := ctx.Arg(3)
		if ppenum == 0 {
			return E_POINTER
		}
		entries, err := os.ReadDir(winToLinuxPath(data.path))
		if err != nil {
			return E_FAIL
		}
		items := make([]string, 0, len(entries))
		for _, entry := range entries {
			items = append(items, canonicalizeWinPath(data.path+`\`+entry.Name()))
		}
		enumObj, err := cs.createEnumIDListObject(items, 0)
		if err != nil {
			return hresultFromError(err)
		}
		cs.mem.Write64(ppenum, enumObj.objectAddr)
		return S_OK
	case 5:
		pidl := ctx.Arg(1)
		riid := ctx.Arg(3)
		ppv := ctx.Arg(4)
		if ppv == 0 || riid == 0 {
			return E_POINTER
		}
		cs.mem.Write64(ppv, 0)
		reqIID := readGUID(cs.mem, riid)
		if !guidEqual(reqIID, IID_IShellFolder) && !guidEqual(reqIID, IID_IUnknown) {
			return E_NOINTERFACE
		}
		child := pidlPathFromMemory(cs.mem, pidl)
		if child == "" {
			return E_INVALIDARG
		}
		obj2, err := cs.createShellFolderObject(child)
		if err != nil {
			return hresultFromError(err)
		}
		cs.mem.Write64(ppv, obj2.objectAddr)
		return S_OK
	case 7:
		a := strings.ToLower(pidlPathFromMemory(cs.mem, ctx.Arg(2)))
		b := strings.ToLower(pidlPathFromMemory(cs.mem, ctx.Arg(3)))
		switch {
		case a == b:
			return S_OK
		case a < b:
			return uint32(0xFFFFFFFF)
		default:
			return 1
		}
	case 9:
		if rgf := ctx.Arg(3); rgf != 0 {
			cs.mem.Write32(rgf, 0)
		}
		return S_OK
	case 11:
		pidl := ctx.Arg(1)
		pName := ctx.Arg(3)
		if pName == 0 {
			return E_POINTER
		}
		name := filepath.Base(winToLinuxPath(pidlPathFromMemory(cs.mem, pidl)))
		if name == "." || name == "/" || name == "" {
			name = filepath.Base(winToLinuxPath(data.path))
		}
		ptr := cs.allocTaskMem(uint64((len(utf16Encode(name))+1)*2), true)
		if ptr == 0 {
			return E_OUTOFMEMORY
		}
		writeGuestUTF16String(cs.mem, ptr, name)
		cs.mem.Write32(pName, 0)
		cs.mem.Write64(pName+8, ptr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchEnumIDList(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*enumIDListData)
	if data == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		celt := int(ctx.Arg(1))
		rgelt := ctx.Arg(2)
		pceltFetched := ctx.Arg(3)
		if rgelt == 0 {
			return E_POINTER
		}
		if pceltFetched != 0 {
			cs.mem.Write32(pceltFetched, 0)
		}
		count := 0
		for count < celt && data.index < len(data.items) {
			pidl := allocPIDLFromPath(cs.mem, cs.allocTaskMem, data.items[data.index])
			if pidl == 0 {
				return E_OUTOFMEMORY
			}
			cs.mem.Write64(rgelt+uint64(count)*8, pidl)
			data.index++
			count++
		}
		if pceltFetched != 0 {
			cs.mem.Write32(pceltFetched, uint32(count))
		}
		if count == celt {
			return S_OK
		}
		return S_FALSE
	case 4:
		data.index += int(ctx.Arg(1))
		if data.index > len(data.items) {
			data.index = len(data.items)
			return S_FALSE
		}
		return S_OK
	case 5:
		data.index = 0
		return S_OK
	case 6:
		ppenum := ctx.Arg(1)
		if ppenum == 0 {
			return E_POINTER
		}
		clone, err := cs.createEnumIDListObject(append([]string(nil), data.items...), data.index)
		if err != nil {
			return hresultFromError(err)
		}
		cs.mem.Write64(ppenum, clone.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchIStream(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	var pos *int64
	switch s := obj.data.(type) {
	case *memStream:
		pos = &s.pos
	case *fileStream:
		pos = &s.pos
	}
	switch method {
	case 3:
		pv := ctx.Arg(1)
		cb := ctx.Arg(2)
		pcbRead := ctx.Arg(3)
		if pv == 0 && cb != 0 {
			return STG_E_INVALIDPOINTER
		}
		if pcbRead != 0 {
			ctx.Mem.Write32(pcbRead, 0)
		}
		tmp := make([]byte, int(cb))
		n, err := streamReadAt(obj.data, *pos, tmp)
		if n > 0 {
			ctx.Mem.WriteBytes(pv, tmp[:n])
			*pos += int64(n)
		}
		if pcbRead != 0 {
			ctx.Mem.Write32(pcbRead, uint32(n))
		}
		if err != nil && err != io.EOF {
			return hresultFromError(err)
		}
		if uint64(n) == cb {
			return S_OK
		}
		return S_FALSE
	case 4:
		pv := ctx.Arg(1)
		cb := ctx.Arg(2)
		pcbWritten := ctx.Arg(3)
		if pv == 0 && cb != 0 {
			return STG_E_INVALIDPOINTER
		}
		if pcbWritten != 0 {
			ctx.Mem.Write32(pcbWritten, 0)
		}
		src, err := ctx.Mem.ReadBytes(pv, int(cb))
		if err != nil && cb != 0 {
			return E_POINTER
		}
		n, err := streamWriteAt(obj.data, *pos, src)
		if err != nil {
			return hresultFromError(err)
		}
		*pos += int64(n)
		if pcbWritten != 0 {
			ctx.Mem.Write32(pcbWritten, uint32(n))
		}
		return S_OK
	case 5:
		dlibMove := int64(ctx.Arg(1))
		dwOrigin := uint32(ctx.Arg(2))
		plibNewPosition := ctx.Arg(3)
		size, err := streamSize(obj.data)
		if err != nil {
			return hresultFromError(err)
		}
		var base int64
		switch dwOrigin {
		case 0:
			base = 0
		case 1:
			base = *pos
		case 2:
			base = size
		default:
			return E_INVALIDARG
		}
		next := base + dlibMove
		if next < 0 {
			return E_INVALIDARG
		}
		*pos = next
		if plibNewPosition != 0 {
			ctx.Mem.Write64Raw(plibNewPosition, uint64(next))
		}
		return S_OK
	case 6:
		if err := streamSetSize(obj.data, int64(ctx.Arg(1))); err != nil {
			return hresultFromError(err)
		}
		return S_OK
	case 7:
		pstm := ctx.Arg(1)
		cb := ctx.Arg(2)
		pcbRead := ctx.Arg(3)
		pcbWritten := ctx.Arg(4)
		if pcbRead != 0 {
			ctx.Mem.Write64Raw(pcbRead, 0)
		}
		if pcbWritten != 0 {
			ctx.Mem.Write64Raw(pcbWritten, 0)
		}
		dest := cs.objects[pstm]
		if dest == nil || dest.kind != "istream" {
			return E_POINTER
		}
		var dstPos *int64
		switch s := dest.data.(type) {
		case *memStream:
			dstPos = &s.pos
		case *fileStream:
			dstPos = &s.pos
		default:
			return E_FAIL
		}
		remaining := cb
		buf := make([]byte, 64*1024)
		var total uint64
		for remaining > 0 {
			chunk := minU64(remaining, uint64(len(buf)))
			n, err := streamReadAt(obj.data, *pos, buf[:chunk])
			if n > 0 {
				written, writeErr := streamWriteAt(dest.data, *dstPos, buf[:n])
				if writeErr != nil {
					return hresultFromError(writeErr)
				}
				*pos += int64(n)
				*dstPos += int64(written)
				total += uint64(written)
				remaining -= uint64(written)
			}
			if err == io.EOF || n == 0 {
				break
			}
			if err != nil {
				return hresultFromError(err)
			}
		}
		if pcbRead != 0 {
			ctx.Mem.Write64Raw(pcbRead, total)
		}
		if pcbWritten != 0 {
			ctx.Mem.Write64Raw(pcbWritten, total)
		}
		if total == cb {
			return S_OK
		}
		return S_FALSE
	case 8:
		if err := streamCommit(obj.data); err != nil {
			return hresultFromError(err)
		}
		return S_OK
	case 9:
		return STG_E_REVERTED
	case 10, 11:
		return S_OK
	case 12:
		pstatstg := ctx.Arg(1)
		grfStatFlag := uint32(ctx.Arg(2))
		if pstatstg == 0 {
			return E_POINTER
		}
		size, err := streamSize(obj.data)
		if err != nil {
			return hresultFromError(err)
		}
		writeSTATSTG(ctx.Mem, cs, pstatstg, statStgEntry{
			name:    streamName(obj.data),
			stgType: STGTY_STREAM,
			size:    uint64(size),
			modTime: streamModTime(obj.data),
		}, grfStatFlag, 0)
		return S_OK
	case 13:
		ppstm := ctx.Arg(1)
		if ppstm == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppstm, 0)
		var clone *comObject
		var err error
		switch s := obj.data.(type) {
		case *memStream:
			s.buffer.addRef()
			clone, err = cs.createMemoryStreamObject(s.buffer, s.name)
			if err == nil {
				clone.data.(*memStream).pos = s.pos
			}
		case *fileStream:
			clone, err = cs.createFileStreamObject(s.path, s.name, s.grfMode, false)
			if err == nil {
				clone.data.(*fileStream).pos = s.pos
			}
		default:
			return E_FAIL
		}
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppstm, clone.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchILockBytes(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	lb, _ := obj.data.(*lockBytes)
	if lb == nil || lb.buffer == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		offset := int64(ctx.Arg(1))
		pv := ctx.Arg(2)
		cb := ctx.Arg(3)
		pcbRead := ctx.Arg(4)
		if pv == 0 && cb != 0 {
			return STG_E_INVALIDPOINTER
		}
		if pcbRead != 0 {
			ctx.Mem.Write32(pcbRead, 0)
		}
		if offset < 0 || offset >= int64(len(lb.buffer.data)) {
			return S_FALSE
		}
		chunk := lb.buffer.data[int(offset):]
		if uint64(len(chunk)) > cb {
			chunk = chunk[:cb]
		}
		if len(chunk) > 0 {
			ctx.Mem.WriteBytes(pv, chunk)
		}
		if pcbRead != 0 {
			ctx.Mem.Write32(pcbRead, uint32(len(chunk)))
		}
		if uint64(len(chunk)) == cb {
			return S_OK
		}
		return S_FALSE
	case 4:
		offset := int64(ctx.Arg(1))
		pv := ctx.Arg(2)
		cb := ctx.Arg(3)
		pcbWritten := ctx.Arg(4)
		if pv == 0 && cb != 0 {
			return STG_E_INVALIDPOINTER
		}
		if pcbWritten != 0 {
			ctx.Mem.Write32(pcbWritten, 0)
		}
		src, err := ctx.Mem.ReadBytes(pv, int(cb))
		if err != nil && cb != 0 {
			return E_POINTER
		}
		if err := lb.buffer.setSize(offset + int64(len(src))); err != nil {
			return hresultFromError(err)
		}
		copy(lb.buffer.data[int(offset):], src)
		if pcbWritten != 0 {
			ctx.Mem.Write32(pcbWritten, uint32(len(src)))
		}
		return S_OK
	case 5:
		return S_OK
	case 6:
		if err := lb.buffer.setSize(int64(ctx.Arg(1))); err != nil {
			return hresultFromError(err)
		}
		return S_OK
	case 7, 8:
		return S_OK
	case 9:
		pstatstg := ctx.Arg(1)
		grfStatFlag := uint32(ctx.Arg(2))
		if pstatstg == 0 {
			return E_POINTER
		}
		writeSTATSTG(ctx.Mem, cs, pstatstg, statStgEntry{
			stgType: STGTY_LOCKBYTES,
			size:    uint64(len(lb.buffer.data)),
		}, grfStatFlag, 0)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchIEnumSTATSTG(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	enumObj, _ := obj.data.(*enumSTATSTG)
	if enumObj == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		celt := int(ctx.Arg(1))
		rgelt := ctx.Arg(2)
		pceltFetched := ctx.Arg(3)
		if celt != 1 && pceltFetched == 0 {
			return E_POINTER
		}
		if pceltFetched != 0 {
			ctx.Mem.Write32(pceltFetched, 0)
		}
		fetched := 0
		for fetched < celt && enumObj.index < len(enumObj.entries) {
			writeSTATSTG(ctx.Mem, cs, rgelt+uint64(fetched*72), enumObj.entries[enumObj.index], 0, 0)
			enumObj.index++
			fetched++
		}
		if pceltFetched != 0 {
			ctx.Mem.Write32(pceltFetched, uint32(fetched))
		}
		if fetched == celt {
			return S_OK
		}
		return S_FALSE
	case 4:
		enumObj.index += int(ctx.Arg(1))
		if enumObj.index > len(enumObj.entries) {
			enumObj.index = len(enumObj.entries)
			return S_FALSE
		}
		return S_OK
	case 5:
		enumObj.index = 0
		return S_OK
	case 6:
		ppenum := ctx.Arg(1)
		if ppenum == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppenum, 0)
		cloneEntries := append([]statStgEntry(nil), enumObj.entries...)
		clone, err := cs.createEnumSTATSTGObject(cloneEntries)
		if err != nil {
			return hresultFromError(err)
		}
		clone.data.(*enumSTATSTG).index = enumObj.index
		ctx.Mem.Write64(ppenum, clone.objectAddr)
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchIStorage(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	ds, _ := obj.data.(*dirStorage)
	if ds == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		ppstm := ctx.Arg(5)
		if ppstm == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppstm, 0)
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		grfMode := uint32(ctx.Arg(2))
		path, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		stream, err := cs.createFileStreamObject(path, name, grfMode, true)
		if err != nil {
			return mapStorageError(err)
		}
		ctx.Mem.Write64(ppstm, stream.objectAddr)
		return S_OK
	case 4:
		ppstm := ctx.Arg(5)
		if ppstm == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppstm, 0)
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		grfMode := uint32(ctx.Arg(3))
		path, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		stream, err := cs.createFileStreamObject(path, name, grfMode, false)
		if err != nil {
			return mapStorageError(err)
		}
		ctx.Mem.Write64(ppstm, stream.objectAddr)
		return S_OK
	case 5:
		ppstg := ctx.Arg(5)
		if ppstg == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppstg, 0)
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		grfMode := uint32(ctx.Arg(2))
		path, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return mapStorageError(err)
		}
		child, err := cs.createStorageObject(path, name, grfMode, grfMode&STGM_DELETEONRELEASE != 0)
		if err != nil {
			return hresultFromError(err)
		}
		persistStorageMetadata(child.data.(*dirStorage))
		ctx.Mem.Write64(ppstg, child.objectAddr)
		return S_OK
	case 6:
		ppstg := ctx.Arg(6)
		if ppstg == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppstg, 0)
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		grfMode := uint32(ctx.Arg(3))
		path, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			return mapStorageError(err)
		}
		if !info.IsDir() {
			return STG_E_FILENOTFOUND
		}
		child, err := cs.createStorageObject(path, name, grfMode, false)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppstg, child.objectAddr)
		return S_OK
	case 7:
		dest := cs.objects[ctx.Arg(4)]
		if dest == nil || dest.kind != "istorage" {
			return E_POINTER
		}
		if err := copyPathRecursive(ds.path, dest.data.(*dirStorage).path); err != nil {
			return mapStorageError(err)
		}
		return S_OK
	case 8:
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		dest := cs.objects[ctx.Arg(2)]
		if dest == nil || dest.kind != "istorage" {
			return E_POINTER
		}
		newName := readGuestUTF16String(ctx.Mem, ctx.Arg(3))
		if strings.TrimSpace(newName) == "" {
			newName = name
		}
		srcPath, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		dstPath, err := storageElementPath(dest.data.(*dirStorage).path, newName)
		if err != nil {
			return hresultFromError(err)
		}
		if err := os.Rename(srcPath, dstPath); err != nil {
			if copyErr := copyPathRecursive(srcPath, dstPath); copyErr != nil {
				return mapStorageError(copyErr)
			}
			_ = os.RemoveAll(srcPath)
		}
		return S_OK
	case 9:
		persistStorageMetadata(ds)
		return S_OK
	case 10:
		return STG_E_REVERTED
	case 11:
		ppenum := ctx.Arg(4)
		if ppenum == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppenum, 0)
		entries, err := listStorageEntries(ds.path)
		if err != nil {
			return mapStorageError(err)
		}
		enumObj, err := cs.createEnumSTATSTGObject(entries)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppenum, enumObj.objectAddr)
		return S_OK
	case 12:
		name := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		path, err := storageElementPath(ds.path, name)
		if err != nil {
			return hresultFromError(err)
		}
		if err := os.RemoveAll(path); err != nil {
			return mapStorageError(err)
		}
		return S_OK
	case 13:
		oldName := readGuestUTF16String(ctx.Mem, ctx.Arg(1))
		newName := readGuestUTF16String(ctx.Mem, ctx.Arg(2))
		oldPath, err := storageElementPath(ds.path, oldName)
		if err != nil {
			return hresultFromError(err)
		}
		newPath, err := storageElementPath(ds.path, newName)
		if err != nil {
			return hresultFromError(err)
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			return mapStorageError(err)
		}
		return S_OK
	case 14:
		targetPath := ds.path
		if name := readGuestUTF16String(ctx.Mem, ctx.Arg(1)); strings.TrimSpace(name) != "" {
			var err error
			targetPath, err = storageElementPath(ds.path, name)
			if err != nil {
				return hresultFromError(err)
			}
		}
		modTime := readFiletime(ctx.Mem, ctx.Arg(4))
		accessTime := readFiletime(ctx.Mem, ctx.Arg(3))
		if accessTime.IsZero() {
			accessTime = modTime
		}
		if modTime.IsZero() {
			modTime = time.Now()
		}
		if accessTime.IsZero() {
			accessTime = modTime
		}
		if err := os.Chtimes(targetPath, accessTime, modTime); err != nil {
			return mapStorageError(err)
		}
		return S_OK
	case 15:
		clsidPtr := ctx.Arg(1)
		if clsidPtr == 0 {
			return E_POINTER
		}
		ds.clsid = readGUID(ctx.Mem, clsidPtr)
		persistStorageMetadata(ds)
		return S_OK
	case 16:
		grfStateBits := uint32(ctx.Arg(1))
		grfMask := uint32(ctx.Arg(2))
		ds.stateBits = (ds.stateBits &^ grfMask) | (grfStateBits & grfMask)
		persistStorageMetadata(ds)
		return S_OK
	case 17:
		pstatstg := ctx.Arg(1)
		grfStatFlag := uint32(ctx.Arg(2))
		if pstatstg == 0 {
			return E_POINTER
		}
		info, err := os.Stat(ds.path)
		if err != nil {
			return mapStorageError(err)
		}
		name := ds.name
		if name == "" {
			name = filepath.Base(ds.path)
		}
		writeSTATSTG(ctx.Mem, cs, pstatstg, statStgEntry{
			name:    name,
			stgType: STGTY_STORAGE,
			modTime: info.ModTime(),
			clsid:   ds.clsid,
		}, grfStatFlag, ds.stateBits)
		return S_OK
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
	case "shell-link-w":
		return cs.dispatchShellLink(ctx, obj, method, true)
	case "shell-link-a":
		return cs.dispatchShellLink(ctx, obj, method, false)
	case "persist-file":
		return cs.dispatchPersistFile(ctx, obj, method)
	case "shell-folder":
		return cs.dispatchShellFolder(ctx, obj, method)
	case "enum-idlist":
		return cs.dispatchEnumIDList(ctx, obj, method)
	case "idispatch", "std-dispatch":
		return cs.dispatchIDispatch(ctx, obj, method)
	case "type-info":
		return cs.dispatchTypeInfo(ctx, obj, method)
	case "create-error-info", "error-info":
		return cs.dispatchErrorInfo(ctx, obj, method)
	case "type-lib":
		return cs.dispatchTypeLib(ctx, obj, method)
	case "istream":
		return cs.dispatchIStream(ctx, obj, method)
	case "file-open-dialog":
		return cs.dispatchFileOpenDialog(ctx, obj, method)
	case "ilockbytes":
		return cs.dispatchILockBytes(ctx, obj, method)
	case "istorage":
		return cs.dispatchIStorage(ctx, obj, method)
	case "ienumstatstg":
		return cs.dispatchIEnumSTATSTG(ctx, obj, method)
	case "direct-sound-device":
		return cs.dispatchDirectSound(ctx, obj, method)
	case "direct-sound-capture":
		return cs.dispatchDirectSoundCapture(ctx, obj, method)
	case "direct-sound-buffer":
		return cs.dispatchDirectSoundBuffer(ctx, obj, method)
	case "direct-input8":
		return cs.dispatchDirectInput(ctx, obj, method)
	case "direct-input-device8":
		return cs.dispatchDirectInputDevice(ctx, obj, method)
	case "xml-document":
		return cs.dispatchXMLDocument(ctx, obj, method)
	case "xml-node":
		return cs.dispatchXMLNode(ctx, obj, method)
	case "xml-node-list":
		return cs.dispatchXMLNodeList(ctx, obj, method)
	case "xml-named-node-map":
		return cs.dispatchXMLNamedNodeMap(ctx, obj, method)
	case "xml-parse-error":
		return cs.dispatchXMLParseError(ctx, obj, method)
	case "wic-factory":
		return cs.dispatchWICFactory(ctx, obj, method)
	case "wic-decoder":
		return cs.dispatchWICDecoder(ctx, obj, method)
	case "wic-frame":
		return cs.dispatchWICFrame(ctx, obj, method)
	case "wic-format-converter":
		return cs.dispatchWICFormatConverter(ctx, obj, method)
	case "wic-bitmap":
		return cs.dispatchWICBitmap(ctx, obj, method)
	case "wic-stream":
		return cs.dispatchWICStream(ctx, obj, method)
	case "wic-component-info":
		return cs.dispatchWICComponentInfo(ctx, obj, method)
	case "d2d1-factory":
		return cs.dispatchD2D1Factory(ctx, obj, method)
	case "d2d1-solid-color-brush":
		return cs.dispatchD2D1SolidColorBrush(ctx, obj, method)
	case "d2d1-bitmap-brush":
		return cs.dispatchD2D1BitmapBrush(ctx, obj, method)
	case "d2d1-gradient-stops":
		return cs.dispatchD2D1GradientStops(ctx, obj, method)
	case "d2d1-linear-gradient-brush":
		return cs.dispatchD2D1LinearGradientBrush(ctx, obj, method)
	case "d2d1-radial-gradient-brush":
		return cs.dispatchD2D1RadialGradientBrush(ctx, obj, method)
	case "d2d1-bitmap":
		return cs.dispatchD2D1Bitmap(ctx, obj, method)
	case "d2d1-rectangle-geometry", "d2d1-rounded-geometry", "d2d1-ellipse-geometry", "d2d1-geometry-group", "d2d1-transformed-geometry", "d2d1-path-geometry":
		return cs.dispatchD2D1Geometry(ctx, obj, method)
	case "d2d1-geometry-sink":
		return cs.dispatchD2D1GeometrySink(ctx, obj, method)
	case "d2d1-hwnd-render-target", "d2d1-dc-render-target", "d2d1-bitmap-render-target":
		return cs.dispatchD2D1RenderTarget(ctx, obj, method)
	case "d2d1-stroke-style":
		return cs.dispatchD2D1StrokeStyle(ctx, obj, method)
	case "d2d1-drawing-state-block":
		return cs.dispatchD2D1DrawingState(ctx, obj, method)
	case "d2d1-layer":
		return cs.dispatchD2D1Layer(ctx, obj, method)
	case "d2d1-mesh":
		return cs.dispatchD2D1Mesh(ctx, obj, method)
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) instantiate(clsid, iid GUID) (*comObject, uint32) {
	cf, ok := cs.classFactories[clsid]
	if !ok {
		return nil, REGDB_E_CLASSNOTREG
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
		hGlobal := ctx.Arg(0)
		fDeleteOnRelease := ctx.Arg(1)
		ppstm := ctx.Arg(2)
		if ppstm == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppstm, 0)
		stream, err := cs.createMemoryStreamObject(newMemoryBuffer(mem, hGlobal, fDeleteOnRelease != 0), "")
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppstm, stream.objectAddr)
		ctx.SetReturn(S_OK)
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
		hGlobal := ctx.Arg(0)
		fDeleteOnRelease := ctx.Arg(1)
		pplkbyt := ctx.Arg(2)
		if pplkbyt == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(pplkbyt, 0)
		obj, err := cs.createLockBytesObject(newMemoryBuffer(mem, hGlobal, fDeleteOnRelease != 0))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(pplkbyt, obj.objectAddr)
		ctx.SetReturn(S_OK)
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
		punk := ctx.Arg(0)
		phglobal := ctx.Arg(1)
		if phglobal == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(phglobal, 0)
		obj := cs.objects[punk]
		if obj == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		lb, ok := obj.data.(*lockBytes)
		if !ok || lb.buffer == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		ctx.Mem.Write64(phglobal, lb.buffer.syncToHGlobal(mem))
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "GetHGlobalFromStream", func(ctx *ntapi.TrapContext) uint32 {
		pstm := ctx.Arg(0)
		phglobal := ctx.Arg(1)
		if phglobal == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(phglobal, 0)
		obj := cs.objects[pstm]
		if obj == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ms, ok := obj.data.(*memStream)
		if !ok || ms.buffer == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		ctx.Mem.Write64(phglobal, ms.buffer.syncToHGlobal(mem))
		ctx.SetReturn(S_OK)
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
	d.RegisterAutoStubHandler(ole32, "PropVariantInit", func(ctx *ntapi.TrapContext) uint32 {
		pvar := ctx.Arg(0)
		if pvar != 0 {
			ctx.Mem.WriteBytes(pvar, make([]byte, variantSize))
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropVariantClear", func(ctx *ntapi.TrapContext) uint32 {
		pvar := ctx.Arg(0)
		if pvar == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.WriteBytes(pvar, make([]byte, variantSize))
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "PropVariantCopy", func(ctx *ntapi.TrapContext) uint32 {
		dest := ctx.Arg(0)
		src := ctx.Arg(1)
		if dest == 0 || src == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if data, err := ctx.Mem.ReadBytes(src, variantSize); err == nil {
			ctx.Mem.WriteBytes(dest, data)
		}
		ctx.SetReturn(S_OK)
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
		pwcsName := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(1))
		ppstgOpen := ctx.Arg(3)
		if ppstgOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, 0)
		hostPath, err := storageHostPath(readGuestUTF16(pwcsName))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		if info, statErr := os.Stat(hostPath); statErr == nil && !info.IsDir() {
			ctx.SetReturn(uint64(STG_E_FILEALREADYEXISTS))
			return 0
		}
		if err := os.MkdirAll(hostPath, 0755); err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, grfMode&STGM_DELETEONRELEASE != 0)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		persistStorageMetadata(obj.data.(*dirStorage))
		ctx.Mem.Write64(ppstgOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreateDocfileOnILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		plkbyt := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(1))
		ppstgOpen := ctx.Arg(3)
		if ppstgOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, 0)
		if cs.objects[plkbyt] == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		hostPath := filepath.Join(".govm-ilockbytes-storage", fmt.Sprintf("%016X", plkbyt))
		if err := os.MkdirAll(hostPath, 0755); err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, grfMode&STGM_DELETEONRELEASE != 0)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		persistStorageMetadata(obj.data.(*dirStorage))
		ctx.Mem.Write64(ppstgOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreatePropSetStg", func(ctx *ntapi.TrapContext) uint32 {
		pstg := ctx.Arg(0)
		ppPropSetStg := ctx.Arg(2)
		if ppPropSetStg == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppPropSetStg, 0)
		obj := cs.objects[pstg]
		if obj == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppPropSetStg, pstg)
		cs.addRef(obj)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreatePropStg", func(ctx *ntapi.TrapContext) uint32 {
		punk := ctx.Arg(0)
		pfmtid := ctx.Arg(1)
		ppPropStg := ctx.Arg(5)
		if ppPropStg == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppPropStg, 0)
		obj := cs.objects[punk]
		if obj == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		stg, ok := obj.data.(*dirStorage)
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		name := "__prop_" + strings.Trim(guidString(readGUID(ctx.Mem, pfmtid)), "{}")
		path, err := storageElementPath(stg.path, name)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		stream, err := cs.createFileStreamObject(path, name, STGM_READWRITE|STGM_CREATE, true)
		if err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		ctx.Mem.Write64(ppPropStg, stream.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgCreateStorageEx", func(ctx *ntapi.TrapContext) uint32 {
		pwcsName := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(1))
		riid := ctx.Arg(6)
		ppObjectOpen := ctx.Arg(7)
		if ppObjectOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if riid != 0 {
			iid := readGUID(ctx.Mem, riid)
			if !guidEqual(iid, IID_IStorage) && !guidEqual(iid, IID_IUnknown) {
				ctx.SetReturn(uint64(E_NOINTERFACE))
				return 0
			}
		}
		ctx.Mem.Write64(ppObjectOpen, 0)
		hostPath, err := storageHostPath(readGuestUTF16(pwcsName))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		if err := os.MkdirAll(hostPath, 0755); err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, grfMode&STGM_DELETEONRELEASE != 0)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		persistStorageMetadata(obj.data.(*dirStorage))
		ctx.Mem.Write64(ppObjectOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgIsStorageFile", func(ctx *ntapi.TrapContext) uint32 {
		hostPath, err := storageHostPath(readGuestUTF16(ctx.Arg(0)))
		if err != nil {
			ctx.SetReturn(uint64(S_FALSE))
			return 0
		}
		info, statErr := os.Stat(hostPath)
		if statErr == nil && info.IsDir() {
			ctx.SetReturn(S_OK)
		} else {
			ctx.SetReturn(S_FALSE)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgIsStorageILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		obj := cs.objects[ctx.Arg(0)]
		if obj != nil && obj.kind == "ilockbytes" {
			ctx.SetReturn(S_OK)
		} else {
			ctx.SetReturn(S_FALSE)
		}
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenPropStg", func(ctx *ntapi.TrapContext) uint32 {
		punk := ctx.Arg(0)
		pfmtid := ctx.Arg(1)
		grfMode := uint32(ctx.Arg(2))
		ppPropStg := ctx.Arg(4)
		if ppPropStg == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppPropStg, 0)
		obj := cs.objects[punk]
		if obj == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		stg, ok := obj.data.(*dirStorage)
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		name := "__prop_" + strings.Trim(guidString(readGUID(ctx.Mem, pfmtid)), "{}")
		path, err := storageElementPath(stg.path, name)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		stream, err := cs.createFileStreamObject(path, name, grfMode, false)
		if err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		ctx.Mem.Write64(ppPropStg, stream.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorage", func(ctx *ntapi.TrapContext) uint32 {
		pwcsName := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(2))
		ppstgOpen := ctx.Arg(5)
		if ppstgOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, 0)
		hostPath, err := storageHostPath(readGuestUTF16(pwcsName))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		info, err := os.Stat(hostPath)
		if err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		if !info.IsDir() {
			ctx.SetReturn(uint64(STG_E_FILENOTFOUND))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, false)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorageEx", func(ctx *ntapi.TrapContext) uint32 {
		pwcsName := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(1))
		riid := ctx.Arg(6)
		ppObjectOpen := ctx.Arg(7)
		if ppObjectOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		if riid != 0 {
			iid := readGUID(ctx.Mem, riid)
			if !guidEqual(iid, IID_IStorage) && !guidEqual(iid, IID_IUnknown) {
				ctx.SetReturn(uint64(E_NOINTERFACE))
				return 0
			}
		}
		ctx.Mem.Write64(ppObjectOpen, 0)
		hostPath, err := storageHostPath(readGuestUTF16(pwcsName))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		info, err := os.Stat(hostPath)
		if err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		if !info.IsDir() {
			ctx.SetReturn(uint64(STG_E_FILENOTFOUND))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, false)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppObjectOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(ole32, "StgOpenStorageOnILockBytes", func(ctx *ntapi.TrapContext) uint32 {
		plkbyt := ctx.Arg(0)
		grfMode := uint32(ctx.Arg(2))
		ppstgOpen := ctx.Arg(5)
		if ppstgOpen == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, 0)
		if cs.objects[plkbyt] == nil {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		hostPath := filepath.Join(".govm-ilockbytes-storage", fmt.Sprintf("%016X", plkbyt))
		info, err := os.Stat(hostPath)
		if err != nil {
			ctx.SetReturn(uint64(mapStorageError(err)))
			return 0
		}
		if !info.IsDir() {
			ctx.SetReturn(uint64(STG_E_FILENOTFOUND))
			return 0
		}
		obj, err := cs.createStorageObject(hostPath, filepath.Base(hostPath), grfMode, false)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppstgOpen, obj.objectAddr)
		ctx.SetReturn(S_OK)
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
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	oleaut32, ok := hctx.SynthByName["oleaut32.dll"]
	if !ok {
		return
	}
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

	// VariantInit: zero the x64 VARIANT struct
	d.RegisterAutoStubHandler(oleaut32, "VariantInit", func(ctx *ntapi.TrapContext) uint32 {
		pVar := ctx.Arg(0)
		if pVar != 0 {
			writeVariantEmpty(ctx.Mem, pVar)
		}
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantClear", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.variantClear(ctx.Arg(0))))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantCopy", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.variantCopy(ctx.Arg(0), ctx.Arg(1))))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantChangeType", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.variantChangeType(ctx.Arg(0), ctx.Arg(1), uint16(ctx.Arg(3)))))
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
		pInterfaceData := ctx.Arg(0)
		lcid := uint32(ctx.Arg(1))
		ppTInfo := ctx.Arg(2)
		if ppTInfo == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppTInfo, 0)
		obj, err := cs.createTypeInfoObject(lcid)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ti, _ := obj.data.(*typeInfoData)
		if pInterfaceData != 0 && ti != nil {
			cMembers, _ := ctx.Mem.Read32(pInterfaceData + 8)
			namesPtr, _ := ctx.Mem.Read64(pInterfaceData + 16)
			for i := uint32(0); i < cMembers && namesPtr != 0; i++ {
				namePtr, _ := ctx.Mem.Read64(namesPtr + uint64(i)*8)
				name := hctxReadUTF16(ctx.Mem, namePtr)
				if strings.TrimSpace(name) != "" {
					cs.lookupDispID(obj.objectAddr, name, true)
				}
			}
		}
		ctx.Mem.Write64(ppTInfo, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		pperrinfo := ctx.Arg(0)
		if pperrinfo == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(pperrinfo, 0)
		createObj, readObj, err := cs.createErrorInfoObjects()
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		cs.errorInfo = readObj.objectAddr
		ctx.Mem.Write64(pperrinfo, createObj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "CreateStdDispatch", func(ctx *ntapi.TrapContext) uint32 {
		punkOuter := ctx.Arg(0)
		pvThis := ctx.Arg(1)
		ptinfo := ctx.Arg(2)
		ppunkStdDisp := ctx.Arg(3)
		if ppunkStdDisp == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppunkStdDisp, 0)
		if punkOuter != 0 {
			ctx.SetReturn(uint64(CLASS_E_NOAGGREGATION))
			return 0
		}
		obj, err := cs.createStdDispatchObject(pvThis, ptinfo)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppunkStdDisp, obj.objectAddr)
		ctx.SetReturn(S_OK)
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
		ptinfo := ctx.Arg(0)
		rgszNames := ctx.Arg(1)
		cNames := int(ctx.Arg(2))
		rgdispid := ctx.Arg(3)
		if rgszNames == 0 || rgdispid == 0 || cNames <= 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		for i := 0; i < cNames; i++ {
			namePtr, _ := ctx.Mem.Read64(rgszNames + uint64(i)*8)
			if namePtr == 0 {
				ctx.SetReturn(uint64(DISP_E_UNKNOWNNAME))
				return 0
			}
			name := hctxReadUTF16(ctx.Mem, namePtr)
			id, ok := cs.lookupDispID(ptinfo, name, false)
			if !ok {
				ctx.SetReturn(uint64(DISP_E_UNKNOWNNAME))
				return 0
			}
			ctx.Mem.Write32(rgdispid+uint64(i)*4, uint32(id))
		}
		ctx.SetReturn(S_OK)
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
		pvThis := ctx.Arg(0)
		ptinfo := ctx.Arg(1)
		dispid := int32(uint32(ctx.Arg(2)))
		pvarResult := ctx.Arg(5)
		pexcepinfo := ctx.Arg(6)
		puArgErr := ctx.Arg(7)
		if pvarResult != 0 {
			writeVariantEmpty(ctx.Mem, pvarResult)
		}
		if pexcepinfo != 0 {
			ctx.Mem.WriteBytes(pexcepinfo, make([]byte, 56))
		}
		if puArgErr != 0 {
			ctx.Mem.Write32(puArgErr, 0)
		}
		ti := cs.typeInfoFor(ptinfo)
		if ti == nil || pvThis == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		if _, ok := ti.dispToID[dispid]; !ok {
			ctx.SetReturn(uint64(DISP_E_MEMBERNOTFOUND))
			return 0
		}
		ctx.SetReturn(uint64(DISP_E_MEMBERNOTFOUND))
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
		_ = dwReserved
		if pperrinfo == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(pperrinfo, 0)
		if cs.errorInfo == 0 {
			ctx.SetReturn(S_FALSE)
			return 0
		}
		ctx.Mem.Write64(pperrinfo, cs.errorInfo)
		cs.addRefPtr(cs.errorInfo)
		cs.errorInfo = 0
		ctx.SetReturn(S_OK)
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
	d.RegisterAutoStubHandler(oleaut32, "LoadTypeLib", func(ctx *ntapi.TrapContext) uint32 {
		szFile := ctx.Arg(0)
		ppTLib := ctx.Arg(1)
		if ppTLib == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppTLib, 0)
		obj, err := cs.createTypeLibObject(hctxReadUTF16(ctx.Mem, szFile))
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppTLib, obj.objectAddr)
		ctx.SetReturn(S_OK)
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
		ctx.SetReturn(S_OK)
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
		psa := ctx.Arg(0)
		ppvData := ctx.Arg(1)
		if ppvData == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppvData, 0)
		sa := cs.loadSafeArray(psa)
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		sa.cLocks++
		cs.syncSafeArray(sa)
		ctx.Mem.Write64(ppvData, sa.pvData)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocData", func(ctx *ntapi.TrapContext) uint32 {
		psa := ctx.Arg(0)
		sa := cs.loadSafeArray(psa)
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		if sa.pvData == 0 {
			sa.pvData = cs.heapAlloc(cs.safeArrayTotalBytes(sa), true)
		}
		cs.syncSafeArray(sa)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		cDims := uint16(ctx.Arg(0))
		ppsa := ctx.Arg(1)
		if ppsa == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppsa, 0)
		if cDims == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		desc := cs.heapAlloc(safeArrayDescriptorSize(cDims), true)
		if desc == 0 {
			ctx.SetReturn(uint64(E_OUTOFMEMORY))
			return 0
		}
		sa := &safeArrayInfo{addr: desc, cDims: cDims, bounds: make([]safeArrayBound, cDims)}
		cs.safeArrays[desc] = sa
		cs.syncSafeArray(sa)
		ctx.Mem.Write64(ppsa, desc)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayAllocDescriptorEx", func(ctx *ntapi.TrapContext) uint32 {
		vt := uint16(ctx.Arg(0))
		cDims := uint16(ctx.Arg(1))
		ppsa := ctx.Arg(2)
		if ppsa == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppsa, 0)
		if cDims == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		desc := cs.heapAlloc(safeArrayDescriptorSize(cDims), true)
		if desc == 0 {
			ctx.SetReturn(uint64(E_OUTOFMEMORY))
			return 0
		}
		sa := &safeArrayInfo{
			addr:       desc,
			vt:         vt,
			cDims:      cDims,
			fFeatures:  FADF_HAVEVARTYPE,
			cbElements: vartypeElemSize(vt),
			bounds:     make([]safeArrayBound, cDims),
		}
		cs.safeArrays[desc] = sa
		cs.syncSafeArray(sa)
		ctx.Mem.Write64(ppsa, desc)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCopy", func(ctx *ntapi.TrapContext) uint32 {
		psa := ctx.Arg(0)
		ppsaOut := ctx.Arg(1)
		if ppsaOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(ppsaOut, 0)
		sa := cs.loadSafeArray(psa)
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		tmpIn := cs.allocTaskMem(variantSize, true)
		tmpOut := cs.allocTaskMem(variantSize, true)
		if tmpIn == 0 || tmpOut == 0 {
			if tmpIn != 0 {
				cs.freeTaskMem(tmpIn)
			}
			if tmpOut != 0 {
				cs.freeTaskMem(tmpOut)
			}
			ctx.SetReturn(uint64(E_OUTOFMEMORY))
			return 0
		}
		defer cs.freeTaskMem(tmpIn)
		defer cs.freeTaskMem(tmpOut)
		writeVariantScalar(ctx.Mem, tmpIn, VT_ARRAY|sa.vt, psa)
		writeVariantEmpty(ctx.Mem, tmpOut)
		if hr := cs.variantCopy(tmpOut, tmpIn); hr != S_OK {
			ctx.SetReturn(uint64(hr))
			return 0
		}
		ctx.Mem.Write64(ppsaOut, readVariantValue(ctx.Mem, tmpOut))
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCopyData", func(ctx *ntapi.TrapContext) uint32 {
		psaSrc := ctx.Arg(0)
		psaDst := ctx.Arg(1)
		saSrc := cs.loadSafeArray(psaSrc)
		saDst := cs.loadSafeArray(psaDst)
		if saSrc == nil || saDst == nil || saSrc.cbElements != saDst.cbElements || len(saSrc.bounds) != len(saDst.bounds) {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		if hr := cs.safeArrayDestroy(psaDst, false); hr != S_OK {
			ctx.SetReturn(uint64(hr))
			return 0
		}
		saDst.vt = saSrc.vt
		saDst.fFeatures = saSrc.fFeatures
		saDst.cbElements = saSrc.cbElements
		saDst.bounds = append(saDst.bounds[:0], saSrc.bounds...)
		saDst.pvData = cs.heapAlloc(cs.safeArrayTotalBytes(saSrc), true)
		cs.syncSafeArray(saDst)
		switch variantElementType(saSrc.vt) {
		case VT_VARIANT:
			count := cs.safeArrayTotalBytes(saSrc) / variantSize
			for i := uint64(0); i < count; i++ {
				if hr := cs.variantCopy(saDst.pvData+i*variantSize, saSrc.pvData+i*variantSize); hr != S_OK {
					ctx.SetReturn(uint64(hr))
					return 0
				}
			}
		default:
			cs.copyBytes(saDst.pvData, saSrc.pvData, uint32(cs.safeArrayTotalBytes(saSrc)))
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayCreate", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(cs.createSafeArray(uint16(ctx.Arg(0)), uint16(ctx.Arg(1)), ctx.Arg(2)))
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
		vt := uint16(ctx.Arg(0))
		lBound := int32(uint32(ctx.Arg(1)))
		cElements := uint32(ctx.Arg(2))
		bounds := cs.allocTaskMem(8, true)
		ctx.Mem.Write32(bounds, cElements)
		ctx.Mem.Write32(bounds+4, uint32(lBound))
		ctx.SetReturn(cs.createSafeArray(vt, 1, bounds))
		cs.freeTaskMem(bounds)
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
		ctx.SetReturn(uint64(cs.safeArrayDestroy(ctx.Arg(0), true)))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayDestroyData", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.safeArrayDestroy(ctx.Arg(0), false)))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayDestroyDescriptor", func(ctx *ntapi.TrapContext) uint32 {
		psa := ctx.Arg(0)
		if sa := cs.loadSafeArray(psa); sa != nil {
			delete(cs.safeArrays, psa)
			cs.heapFree(psa)
			ctx.SetReturn(S_OK)
		} else {
			ctx.SetReturn(uint64(E_INVALIDARG))
		}
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetDim", func(ctx *ntapi.TrapContext) uint32 {
		if sa := cs.loadSafeArray(ctx.Arg(0)); sa != nil {
			ctx.SetReturn(uint64(sa.cDims))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetElement", func(ctx *ntapi.TrapContext) uint32 {
		psa := ctx.Arg(0)
		rgIndices := ctx.Arg(1)
		pv := ctx.Arg(2)
		sa := cs.loadSafeArray(psa)
		if sa == nil || pv == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		offset, ok := cs.safeArrayElementOffset(sa, rgIndices)
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		elem := sa.pvData + offset
		switch variantElementType(sa.vt) {
		case VT_BSTR:
			bstr, _ := ctx.Mem.Read64(elem)
			ctx.Mem.Write64(pv, cs.allocBSTRString(readBSTRString(ctx.Mem, bstr)))
		case VT_UNKNOWN, VT_DISPATCH:
			ptr, _ := ctx.Mem.Read64(elem)
			cs.addRefPtr(ptr)
			ctx.Mem.Write64(pv, ptr)
		case VT_VARIANT:
			ctx.SetReturn(uint64(cs.variantCopy(pv, elem)))
			return 0
		default:
			cs.copyBytes(pv, elem, sa.cbElements)
		}
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetElemsize", func(ctx *ntapi.TrapContext) uint32 {
		if sa := cs.loadSafeArray(ctx.Arg(0)); sa != nil {
			ctx.SetReturn(uint64(sa.cbElements))
		} else {
			ctx.SetReturn(0)
		}
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
		sa := cs.loadSafeArray(ctx.Arg(0))
		nDim := int(ctx.Arg(1))
		plBound := ctx.Arg(2)
		if sa == nil || plBound == 0 || nDim < 1 || nDim > len(sa.bounds) {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		ctx.Mem.Write32(plBound, uint32(sa.bounds[nDim-1].lLbound))
		ctx.SetReturn(S_OK)
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
		sa := cs.loadSafeArray(ctx.Arg(0))
		nDim := int(ctx.Arg(1))
		plBound := ctx.Arg(2)
		if sa == nil || plBound == 0 || nDim < 1 || nDim > len(sa.bounds) {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		b := sa.bounds[nDim-1]
		ctx.Mem.Write32(plBound, uint32(int64(b.lLbound)+int64(b.cElements)-1))
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayGetVartype", func(ctx *ntapi.TrapContext) uint32 {
		sa := cs.loadSafeArray(ctx.Arg(0))
		pvt := ctx.Arg(1)
		if sa == nil || pvt == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		ctx.Mem.Write16(pvt, sa.vt)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayLock", func(ctx *ntapi.TrapContext) uint32 {
		sa := cs.loadSafeArray(ctx.Arg(0))
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		sa.cLocks++
		cs.syncSafeArray(sa)
		ctx.SetReturn(S_OK)
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
		psa := ctx.Arg(0)
		rgIndices := ctx.Arg(1)
		pv := ctx.Arg(2)
		sa := cs.loadSafeArray(psa)
		if sa == nil || pv == 0 {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		offset, ok := cs.safeArrayElementOffset(sa, rgIndices)
		if !ok {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		elem := sa.pvData + offset
		switch variantElementType(sa.vt) {
		case VT_BSTR:
			old, _ := ctx.Mem.Read64(elem)
			cs.freeBSTR(old)
			src, _ := ctx.Mem.Read64(pv)
			ctx.Mem.Write64(elem, cs.allocBSTRString(readBSTRString(ctx.Mem, src)))
		case VT_UNKNOWN, VT_DISPATCH:
			old, _ := ctx.Mem.Read64(elem)
			cs.releasePtr(old)
			src, _ := ctx.Mem.Read64(pv)
			cs.addRefPtr(src)
			ctx.Mem.Write64(elem, src)
		case VT_VARIANT:
			if hr := cs.variantClear(elem); hr != S_OK {
				ctx.SetReturn(uint64(hr))
				return 0
			}
			ctx.SetReturn(uint64(cs.variantCopy(elem, pv)))
			return 0
		default:
			cs.copyBytes(elem, pv, sa.cbElements)
		}
		ctx.SetReturn(S_OK)
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
		sa := cs.loadSafeArray(ctx.Arg(0))
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		if sa.cLocks > 0 {
			sa.cLocks--
		}
		cs.syncSafeArray(sa)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SafeArrayUnlock", func(ctx *ntapi.TrapContext) uint32 {
		sa := cs.loadSafeArray(ctx.Arg(0))
		if sa == nil {
			ctx.SetReturn(uint64(E_INVALIDARG))
			return 0
		}
		if sa.cLocks > 0 {
			sa.cLocks--
		}
		cs.syncSafeArray(sa)
		ctx.SetReturn(S_OK)
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "SetErrorInfo", func(ctx *ntapi.TrapContext) uint32 {
		dwReserved := ctx.Arg(0)
		perrinfo := ctx.Arg(1)
		_ = dwReserved
		cs.errorInfo = perrinfo
		if perrinfo != 0 {
			cs.addRefPtr(perrinfo)
		}
		ctx.SetReturn(S_OK)
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
	d.RegisterAutoStubHandler(oleaut32, "UnRegisterTypeLib", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_OK)
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
		bstrIn := ctx.Arg(0)
		pboolOut := ctx.Arg(3)
		if pboolOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		switch normalizeBoolString(readBSTRString(ctx.Mem, bstrIn)) {
		case "", "0", "false", "no", "off":
			ctx.Mem.Write16(pboolOut, VARIANT_FALSE)
		case "-1", "1", "true", "yes", "on":
			ctx.Mem.Write16(pboolOut, VARIANT_TRUE)
		default:
			ctx.SetReturn(uint64(DISP_E_TYPEMISMATCH))
			return 0
		}
		ctx.SetReturn(S_OK)
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
		dateVal := ctx.FloatArg(0)
		pbstrOut := ctx.Arg(3)
		if pbstrOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		t := oleVariantTimeToTime(dateVal).UTC()
		ctx.Mem.Write64(pbstrOut, cs.allocBSTRString(t.Format("2006-01-02 15:04:05")))
		ctx.SetReturn(S_OK)
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
		lVal := int32(uint32(ctx.Arg(0)))
		pbstrOut := ctx.Arg(3)
		if pbstrOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(pbstrOut, cs.allocBSTRString(strconv.FormatInt(int64(lVal), 10)))
		ctx.SetReturn(S_OK)
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
		dblVal := ctx.FloatArg(0)
		pbstrOut := ctx.Arg(3)
		if pbstrOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		ctx.Mem.Write64(pbstrOut, cs.allocBSTRString(strconv.FormatFloat(dblVal, 'f', -1, 64)))
		ctx.SetReturn(S_OK)
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
		bstrIn := ctx.Arg(0)
		plOut := ctx.Arg(3)
		if plOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		v, err := strconv.ParseInt(strings.TrimSpace(readBSTRString(ctx.Mem, bstrIn)), 10, 32)
		if err != nil {
			ctx.SetReturn(uint64(DISP_E_TYPEMISMATCH))
			return 0
		}
		ctx.Mem.Write32(plOut, uint32(int32(v)))
		ctx.SetReturn(S_OK)
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
		bstrIn := ctx.Arg(0)
		pdblOut := ctx.Arg(3)
		if pdblOut == 0 {
			ctx.SetReturn(uint64(E_POINTER))
			return 0
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(readBSTRString(ctx.Mem, bstrIn)), 64)
		if err != nil {
			ctx.SetReturn(uint64(DISP_E_TYPEMISMATCH))
			return 0
		}
		writeFloat64(ctx.Mem, pdblOut, v)
		ctx.SetReturn(S_OK)
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
		ctx.SetReturn(uint64(cs.variantChangeType(ctx.Arg(0), ctx.Arg(1), uint16(ctx.Arg(4)))))
		return 0
	})
	d.RegisterAutoStubHandler(oleaut32, "VariantCopyInd", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(cs.variantCopyIndirect(ctx.Arg(0), ctx.Arg(1))))
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
