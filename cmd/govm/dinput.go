package main

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	DI_OK                = 0x00000000
	DI_BUFFEROVERFLOW    = 0x00000001
	DIERR_INPUTLOST      = 0x8007001E
	DIERR_NOTACQUIRED    = 0x8007000C
	DIERR_NOTINITIALIZED = 0x80070015

	DISCL_EXCLUSIVE    = 0x00000001
	DISCL_NONEXCLUSIVE = 0x00000002
	DISCL_FOREGROUND   = 0x00000004
	DISCL_BACKGROUND   = 0x00000008

	DI8DEVTYPE_KEYBOARD = 0x61
	DI8DEVTYPE_MOUSE    = 0x82

	diDeviceInstanceWSize = 1100
	diObjectInstanceWSize = 576
	diMouseState2Size     = 24
)

var (
	IID_IDirectInput8A       = GUID{0xBF798030, 0x483A, 0x4DA2, [8]byte{0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00}}
	IID_IDirectInput8W       = GUID{0xBF798031, 0x483A, 0x4DA2, [8]byte{0xAA, 0x99, 0x5D, 0x64, 0xED, 0x36, 0x97, 0x00}}
	IID_IDirectInputDevice8A = GUID{0x54D41080, 0xDC15, 0x4833, [8]byte{0xA4, 0x1B, 0x74, 0x8F, 0x73, 0xA3, 0x81, 0x79}}
	IID_IDirectInputDevice8W = GUID{0x54D41081, 0xDC15, 0x4833, [8]byte{0xA4, 0x1B, 0x74, 0x8F, 0x73, 0xA3, 0x81, 0x79}}

	GUID_SysKeyboard = GUID{0x6F1D2B61, 0xD5A0, 0x11CF, [8]byte{0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}
	GUID_SysMouse    = GUID{0x6F1D2B60, 0xD5A0, 0x11CF, [8]byte{0xBF, 0xC7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}}
)

type directInputData struct {
	mu      sync.Mutex
	version uint32
}

type diDevice struct {
	mu        sync.Mutex
	guid      GUID
	devType   uint32
	acquired  bool
	dataFmt   uint32
	coopLevel uint32

	eventHandle uint64
	props       map[GUID]uint32

	kbState [256]byte

	mouseX, mouseY, mouseZ int32
	mouseButtons           [8]byte
}

func (cs *comState) createDirectInputObject() (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IDirectInput8W, 11)
	if err != nil {
		return nil, err
	}
	obj.kind = "direct-input8"
	obj.data = &directInputData{}
	obj.supportedIIDs[IID_IDirectInput8A] = true
	obj.supportedIIDs[IID_IDirectInput8W] = true
	return obj, nil
}

func (cs *comState) createDirectInputDeviceObject(guid GUID, devType uint32) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IDirectInputDevice8W, 32)
	if err != nil {
		return nil, err
	}
	obj.kind = "direct-input-device8"
	obj.data = &diDevice{
		guid:    guid,
		devType: devType,
		dataFmt: defaultDirectInputDataSize(devType),
		props:   make(map[GUID]uint32),
	}
	obj.supportedIIDs[IID_IDirectInputDevice8A] = true
	obj.supportedIIDs[IID_IDirectInputDevice8W] = true
	return obj, nil
}

func defaultDirectInputDataSize(devType uint32) uint32 {
	switch devType {
	case DI8DEVTYPE_KEYBOARD:
		return 256
	case DI8DEVTYPE_MOUSE:
		return diMouseState2Size
	default:
		return 0
	}
}

func directInputDeviceInfo(guid GUID) (uint32, string, string, bool) {
	switch {
	case guidEqual(guid, GUID_SysKeyboard):
		return DI8DEVTYPE_KEYBOARD, "System Keyboard", "go-vm Keyboard", true
	case guidEqual(guid, GUID_SysMouse):
		return DI8DEVTYPE_MOUSE, "System Mouse", "go-vm Mouse", true
	default:
		return 0, "", "", false
	}
}

func directInputEnumMatches(dwDevType, devType uint32) bool {
	if dwDevType == 0 || dwDevType == 1 {
		return true
	}
	class := (dwDevType >> 8) & 0xFF
	switch devType {
	case DI8DEVTYPE_KEYBOARD:
		return dwDevType == DI8DEVTYPE_KEYBOARD || (dwDevType&0xFF) == DI8DEVTYPE_KEYBOARD || dwDevType == 3 || class == 3
	case DI8DEVTYPE_MOUSE:
		return dwDevType == DI8DEVTYPE_MOUSE || (dwDevType&0xFF) == DI8DEVTYPE_MOUSE || dwDevType == 2 || class == 2
	default:
		return false
	}
}

func writeGuestBounded(mem *mmu.MMU, addr uint64, raw []byte, max uint32) {
	if addr == 0 || len(raw) == 0 {
		return
	}
	if max == 0 || max > uint32(len(raw)) {
		max = uint32(len(raw))
	}
	mem.WriteBytes(addr, raw[:max])
}

func writeDIDeviceInstanceW(mem *mmu.MMU, addr uint64, guid GUID, devType uint32, instanceName, productName string) {
	if addr == 0 {
		return
	}
	raw := make([]byte, diDeviceInstanceWSize)
	binary.LittleEndian.PutUint32(raw[0:4], diDeviceInstanceWSize)
	putGUIDBytes(raw[4:20], guid)
	putGUIDBytes(raw[20:36], guid)
	binary.LittleEndian.PutUint32(raw[36:40], devType)
	putWideStringBytes(raw[40:560], instanceName)
	putWideStringBytes(raw[560:1080], productName)
	mem.WriteBytes(addr, raw)
}

func writeDIDeviceInfo(mem *mmu.MMU, addr uint64, guid GUID, devType uint32, instanceName, productName string) {
	if addr == 0 {
		return
	}
	size, _ := mem.Read32(addr)
	raw := make([]byte, diDeviceInstanceWSize)
	binary.LittleEndian.PutUint32(raw[0:4], diDeviceInstanceWSize)
	putGUIDBytes(raw[4:20], guid)
	putGUIDBytes(raw[20:36], guid)
	binary.LittleEndian.PutUint32(raw[36:40], devType)
	putWideStringBytes(raw[40:560], instanceName)
	putWideStringBytes(raw[560:1080], productName)
	if size == 0 {
		size = diDeviceInstanceWSize
	}
	writeGuestBounded(mem, addr, raw, size)
}

func writeDIDeviceCaps(mem *mmu.MMU, addr uint64, devType uint32) {
	if addr == 0 {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = 44
	}
	raw := make([]byte, 44)
	binary.LittleEndian.PutUint32(raw[0:4], size)
	binary.LittleEndian.PutUint32(raw[8:12], devType)
	switch devType {
	case DI8DEVTYPE_KEYBOARD:
		binary.LittleEndian.PutUint32(raw[16:20], 256)
	case DI8DEVTYPE_MOUSE:
		binary.LittleEndian.PutUint32(raw[12:16], 3)
		binary.LittleEndian.PutUint32(raw[16:20], 8)
	}
	writeGuestBounded(mem, addr, raw, size)
}

func putGUIDBytes(dst []byte, g GUID) {
	if len(dst) < 16 {
		return
	}
	binary.LittleEndian.PutUint32(dst[0:4], g.Data1)
	binary.LittleEndian.PutUint16(dst[4:6], g.Data2)
	binary.LittleEndian.PutUint16(dst[6:8], g.Data3)
	copy(dst[8:16], g.Data4[:])
}

func putWideStringBytes(dst []byte, s string) {
	u16 := utf16Encode(s)
	limit := len(dst) / 2
	if limit == 0 {
		return
	}
	if len(u16) >= limit {
		u16 = u16[:limit-1]
	}
	for i, w := range u16 {
		binary.LittleEndian.PutUint16(dst[i*2:], w)
	}
}

func writeDIObjectInstanceW(mem *mmu.MMU, addr uint64, ofs, typ, flags uint32, name string) {
	if addr == 0 {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = diObjectInstanceWSize
	}
	raw := make([]byte, diObjectInstanceWSize)
	binary.LittleEndian.PutUint32(raw[0:4], diObjectInstanceWSize)
	binary.LittleEndian.PutUint32(raw[20:24], ofs)
	binary.LittleEndian.PutUint32(raw[24:28], typ)
	binary.LittleEndian.PutUint32(raw[28:32], flags)
	putWideStringBytes(raw[32:552], name)
	writeGuestBounded(mem, addr, raw, size)
}

func enumDirectInputDevices(ctx *ntapi.TrapContext, dwDevType uint32, callback, pvRef uint64) uint32 {
	if callback == 0 {
		return DI_OK
	}
	type deviceEntry struct {
		guid        GUID
		devType     uint32
		instance    string
		productName string
	}
	entries := []deviceEntry{
		{guid: GUID_SysKeyboard, devType: DI8DEVTYPE_KEYBOARD, instance: "System Keyboard", productName: "go-vm Keyboard"},
		{guid: GUID_SysMouse, devType: DI8DEVTYPE_MOUSE, instance: "System Mouse", productName: "go-vm Mouse"},
	}
	trampoline := ntapi.AllocTrampoline(ctx.Mem)
	for _, entry := range entries {
		if !directInputEnumMatches(dwDevType, entry.devType) {
			continue
		}
		tmp := ctx.Mem.Mmap(0, diDeviceInstanceWSize, mmu.PermRead|mmu.PermWrite)
		if tmp == 0 {
			return E_OUTOFMEMORY
		}
		writeDIDeviceInstanceW(ctx.Mem, tmp, entry.guid, entry.devType, entry.instance, entry.productName)
		ret, err := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, callback, []uint64{tmp, pvRef}, ctx.Trace)
		ctx.Mem.Munmap(tmp, diDeviceInstanceWSize)
		if err != nil {
			return E_FAIL
		}
		if ret == 0 {
			break
		}
	}
	return DI_OK
}

func (cs *comState) enumDirectInputDevicesBySemantics(ctx *ntapi.TrapContext, callback, pvRef uint64) uint32 {
	if callback == 0 {
		return DI_OK
	}
	type deviceEntry struct {
		guid        GUID
		devType     uint32
		instance    string
		productName string
	}
	entries := []deviceEntry{
		{guid: GUID_SysKeyboard, devType: DI8DEVTYPE_KEYBOARD, instance: "System Keyboard", productName: "go-vm Keyboard"},
		{guid: GUID_SysMouse, devType: DI8DEVTYPE_MOUSE, instance: "System Mouse", productName: "go-vm Mouse"},
	}
	trampoline := ntapi.AllocTrampoline(ctx.Mem)
	for i, entry := range entries {
		instPtr := ctx.Mem.Mmap(0, diDeviceInstanceWSize, mmu.PermRead|mmu.PermWrite)
		if instPtr == 0 {
			return E_OUTOFMEMORY
		}
		writeDIDeviceInstanceW(ctx.Mem, instPtr, entry.guid, entry.devType, entry.instance, entry.productName)
		devObj, err := cs.createDirectInputDeviceObject(entry.guid, entry.devType)
		if err != nil {
			ctx.Mem.Munmap(instPtr, diDeviceInstanceWSize)
			return hresultFromError(err)
		}
		remaining := uint64(len(entries) - i - 1)
		ret, callErr := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, callback, []uint64{instPtr, devObj.objectAddr, 0, remaining, pvRef}, ctx.Trace)
		ctx.Mem.Munmap(instPtr, diDeviceInstanceWSize)
		if callErr != nil {
			return E_FAIL
		}
		if ret == 0 {
			break
		}
	}
	return DI_OK
}

func (cs *comState) dispatchDirectInput(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*directInputData)
	if data == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		rguid := ctx.Arg(1)
		ppDevice := ctx.Arg(2)
		pUnkOuter := ctx.Arg(3)
		if ppDevice == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDevice, 0)
		if pUnkOuter != 0 {
			return CLASS_E_NOAGGREGATION
		}
		if rguid == 0 {
			return E_INVALIDARG
		}
		guid := readGUID(ctx.Mem, rguid)
		devType, _, _, ok := directInputDeviceInfo(guid)
		if !ok {
			return E_FAIL
		}
		devObj, err := cs.createDirectInputDeviceObject(guid, devType)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppDevice, devObj.objectAddr)
		return DI_OK
	case 4:
		return enumDirectInputDevices(ctx, uint32(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3))
	case 5:
		rguid := ctx.Arg(1)
		if rguid == 0 {
			return E_POINTER
		}
		_, _, _, ok := directInputDeviceInfo(readGUID(ctx.Mem, rguid))
		if ok {
			return DI_OK
		}
		return E_FAIL
	case 6:
		return DI_OK
	case 7:
		data.mu.Lock()
		data.version = uint32(ctx.Arg(2))
		data.mu.Unlock()
		return DI_OK
	case 8:
		pName := ctx.Arg(2)
		pguidInstance := ctx.Arg(3)
		if pguidInstance == 0 {
			return E_POINTER
		}
		name := hctxReadUTF16(ctx.Mem, pName)
		switch {
		case name == "", containsFold(name, "keyboard"):
			writeGUID(ctx.Mem, pguidInstance, GUID_SysKeyboard)
			return DI_OK
		case containsFold(name, "mouse"):
			writeGUID(ctx.Mem, pguidInstance, GUID_SysMouse)
			return DI_OK
		default:
			if rguidClass := ctx.Arg(1); rguidClass != 0 {
				guidClass := readGUID(ctx.Mem, rguidClass)
				if guidEqual(guidClass, GUID_SysKeyboard) {
					writeGUID(ctx.Mem, pguidInstance, GUID_SysKeyboard)
					return DI_OK
				}
				if guidEqual(guidClass, GUID_SysMouse) {
					writeGUID(ctx.Mem, pguidInstance, GUID_SysMouse)
					return DI_OK
				}
			}
		}
		writeGUID(ctx.Mem, pguidInstance, GUID{})
		return E_FAIL
	case 9:
		return cs.enumDirectInputDevicesBySemantics(ctx, ctx.Arg(3), ctx.Arg(4))
	case 10:
		return DI_OK
	default:
		return E_NOTIMPL
	}
}

func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	return fmt.Sprintf("%s", s) != "" && (containsFoldRunes(s, substr))
}

func containsFoldRunes(s, substr string) bool {
	sRunes := []rune(s)
	subRunes := []rune(substr)
	for i := 0; i+len(subRunes) <= len(sRunes); i++ {
		match := true
		for j := range subRunes {
			a := sRunes[i+j]
			b := subRunes[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func directInputDeviceState(dev *diDevice, mem *mmu.MMU, cbData uint32, out uint64) {
	if out == 0 || cbData == 0 {
		return
	}
	switch dev.devType {
	case DI8DEVTYPE_KEYBOARD:
		limit := cbData
		if limit > 256 {
			limit = 256
		}
		mem.WriteBytes(out, dev.kbState[:limit])
	case DI8DEVTYPE_MOUSE:
		raw := make([]byte, diMouseState2Size)
		binary.LittleEndian.PutUint32(raw[0:4], uint32(dev.mouseX))
		binary.LittleEndian.PutUint32(raw[4:8], uint32(dev.mouseY))
		binary.LittleEndian.PutUint32(raw[8:12], uint32(dev.mouseZ))
		copy(raw[12:20], dev.mouseButtons[:])
		if cbData < diMouseState2Size {
			raw = raw[:cbData]
		}
		mem.WriteBytes(out, raw)
	}
}

func directInputWriteBufferedData(dev *diDevice, mem *mmu.MMU, cbObjectData uint32, rgdod, pdwInOut uint64) {
	if pdwInOut == 0 {
		return
	}
	requested, _ := mem.Read32(pdwInOut)
	if requested == 0 || rgdod == 0 || cbObjectData == 0 {
		mem.Write32(pdwInOut, 0)
		return
	}
	mem.Write32(pdwInOut, 0)
}

func (cs *comState) enumDeviceObjects(ctx *ntapi.TrapContext, dev *diDevice, callback, pvRef uint64) uint32 {
	if callback == 0 {
		return DI_OK
	}
	type objectEntry struct {
		ofs   uint32
		typ   uint32
		flags uint32
		name  string
	}
	var entries []objectEntry
	switch dev.devType {
	case DI8DEVTYPE_KEYBOARD:
		entries = make([]objectEntry, 256)
		for i := range entries {
			entries[i] = objectEntry{
				ofs:  uint32(i),
				typ:  uint32(i),
				name: fmt.Sprintf("Key %d", i),
			}
		}
	case DI8DEVTYPE_MOUSE:
		entries = []objectEntry{
			{ofs: 0, typ: 0, name: "X Axis"},
			{ofs: 4, typ: 1, name: "Y Axis"},
			{ofs: 8, typ: 2, name: "Z Axis"},
		}
		for i := 0; i < 8; i++ {
			entries = append(entries, objectEntry{
				ofs:  uint32(12 + i),
				typ:  uint32(3 + i),
				name: fmt.Sprintf("Button %d", i),
			})
		}
	}
	trampoline := ntapi.AllocTrampoline(ctx.Mem)
	for _, entry := range entries {
		tmp := ctx.Mem.Mmap(0, diObjectInstanceWSize, mmu.PermRead|mmu.PermWrite)
		if tmp == 0 {
			return E_OUTOFMEMORY
		}
		writeDIObjectInstanceW(ctx.Mem, tmp, entry.ofs, entry.typ, entry.flags, entry.name)
		ret, err := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, callback, []uint64{tmp, pvRef}, ctx.Trace)
		ctx.Mem.Munmap(tmp, diObjectInstanceWSize)
		if err != nil {
			return E_FAIL
		}
		if ret == 0 {
			break
		}
	}
	return DI_OK
}

func directInputObjectInfo(dev *diDevice, dwObj uint32) (uint32, uint32, uint32, string, bool) {
	switch dev.devType {
	case DI8DEVTYPE_KEYBOARD:
		if dwObj >= 256 {
			return 0, 0, 0, "", false
		}
		return dwObj, dwObj, 0, fmt.Sprintf("Key %d", dwObj), true
	case DI8DEVTYPE_MOUSE:
		switch dwObj {
		case 0:
			return 0, 0, 0, "X Axis", true
		case 1:
			return 4, 1, 0, "Y Axis", true
		case 2:
			return 8, 2, 0, "Z Axis", true
		default:
			if dwObj >= 3 && dwObj < 11 {
				return 12 + (dwObj - 3), dwObj, 0, fmt.Sprintf("Button %d", dwObj-3), true
			}
		}
	}
	return 0, 0, 0, "", false
}

func (cs *comState) dispatchDirectInputDevice(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	dev, _ := obj.data.(*diDevice)
	if dev == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		dev.mu.Lock()
		writeDIDeviceCaps(ctx.Mem, ctx.Arg(1), dev.devType)
		dev.mu.Unlock()
		return DI_OK
	case 4:
		dev.mu.Lock()
		hr := cs.enumDeviceObjects(ctx, dev, ctx.Arg(1), ctx.Arg(2))
		dev.mu.Unlock()
		return hr
	case 5:
		rguidProp := ctx.Arg(1)
		pdiph := ctx.Arg(2)
		if rguidProp == 0 || pdiph == 0 {
			return E_POINTER
		}
		prop := readGUID(ctx.Mem, rguidProp)
		dev.mu.Lock()
		val := dev.props[prop]
		dev.mu.Unlock()
		ctx.Mem.Write32(pdiph+16, val)
		return DI_OK
	case 6:
		rguidProp := ctx.Arg(1)
		pdiph := ctx.Arg(2)
		if rguidProp == 0 || pdiph == 0 {
			return E_POINTER
		}
		prop := readGUID(ctx.Mem, rguidProp)
		val, _ := ctx.Mem.Read32(pdiph + 16)
		dev.mu.Lock()
		dev.props[prop] = val
		dev.mu.Unlock()
		return DI_OK
	case 7:
		dev.mu.Lock()
		dev.acquired = true
		dev.mu.Unlock()
		return DI_OK
	case 8:
		dev.mu.Lock()
		dev.acquired = false
		dev.mu.Unlock()
		return DI_OK
	case 9:
		cbData := uint32(ctx.Arg(1))
		lpvData := ctx.Arg(2)
		if lpvData == 0 {
			return E_POINTER
		}
		dev.mu.Lock()
		defer dev.mu.Unlock()
		if !dev.acquired {
			return DIERR_NOTACQUIRED
		}
		directInputDeviceState(dev, ctx.Mem, cbData, lpvData)
		return DI_OK
	case 10:
		dev.mu.Lock()
		defer dev.mu.Unlock()
		if !dev.acquired {
			return DIERR_NOTACQUIRED
		}
		directInputWriteBufferedData(dev, ctx.Mem, uint32(ctx.Arg(1)), ctx.Arg(2), ctx.Arg(3))
		return DI_OK
	case 11:
		lpdf := ctx.Arg(1)
		if lpdf == 0 {
			return E_POINTER
		}
		size, _ := ctx.Mem.Read32(lpdf + 12)
		dev.mu.Lock()
		dev.dataFmt = size
		dev.mu.Unlock()
		return DI_OK
	case 12:
		dev.mu.Lock()
		dev.eventHandle = ctx.Arg(1)
		dev.mu.Unlock()
		return DI_OK
	case 13:
		dev.mu.Lock()
		dev.coopLevel = uint32(ctx.Arg(2))
		dev.mu.Unlock()
		return DI_OK
	case 14:
		pdidoi := ctx.Arg(1)
		if pdidoi == 0 {
			return E_POINTER
		}
		dev.mu.Lock()
		ofs, typ, flags, name, ok := directInputObjectInfo(dev, uint32(ctx.Arg(2)))
		dev.mu.Unlock()
		if !ok {
			return E_INVALIDARG
		}
		writeDIObjectInstanceW(ctx.Mem, pdidoi, ofs, typ, flags, name)
		return DI_OK
	case 15:
		pdidi := ctx.Arg(1)
		if pdidi == 0 {
			return E_POINTER
		}
		dev.mu.Lock()
		_, instanceName, productName, _ := directInputDeviceInfo(dev.guid)
		writeDIDeviceInfo(ctx.Mem, pdidi, dev.guid, dev.devType, instanceName, productName)
		dev.mu.Unlock()
		return DI_OK
	case 16:
		return DI_OK
	case 17:
		dev.mu.Lock()
		dev.guid = readGUID(ctx.Mem, ctx.Arg(3))
		dev.mu.Unlock()
		return DI_OK
	case 18:
		ppdeff := ctx.Arg(3)
		if ppdeff != 0 {
			ctx.Mem.Write64(ppdeff, 0)
		}
		return DI_OK
	case 19:
		return DI_OK
	case 20:
		return DI_OK
	case 21:
		pdwOut := ctx.Arg(1)
		if pdwOut != 0 {
			ctx.Mem.Write32(pdwOut, 0)
		}
		return DI_OK
	case 22:
		return DI_OK
	case 23:
		return DI_OK
	case 24:
		return DI_OK
	case 25:
		return DI_OK
	case 26:
		pdwInOut := ctx.Arg(3)
		if pdwInOut != 0 {
			ctx.Mem.Write32(pdwInOut, 0)
		}
		return DI_OK
	case 27:
		return DI_OK
	case 28:
		return DI_OK
	case 29:
		return DI_OK
	case 30:
		return DI_OK
	case 31:
		return DI_OK
	default:
		return E_NOTIMPL
	}
}

func registerDinputHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["dinput8.dll"]
	if !ok {
		return
	}
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	d.RegisterAutoStubHandler(dll, "DirectInput8Create", func(ctx *ntapi.TrapContext) uint32 {
		riidltf := ctx.Arg(2)
		ppvOut := ctx.Arg(3)
		punkOuter := ctx.Arg(4)
		if ppvOut == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppvOut, 0)
		if punkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		reqIID := IID_IDirectInput8W
		if riidltf != 0 {
			reqIID = readGUID(ctx.Mem, riidltf)
		}
		if !guidEqual(reqIID, IID_IUnknown) && !guidEqual(reqIID, IID_IDirectInput8A) && !guidEqual(reqIID, IID_IDirectInput8W) {
			ctx.SetReturn(E_NOINTERFACE)
			return 0
		}
		obj, err := cs.createDirectInputObject()
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppvOut, obj.objectAddr)
		ctx.SetReturn(DI_OK)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		ppvOut := ctx.Arg(2)
		if ppvOut != 0 {
			ctx.Mem.Write64(ppvOut, 0)
		}
		ctx.SetReturn(CLASS_E_CLASSNOTAVAILABLE)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DllCanUnloadNow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(S_FALSE)
		return 0
	})
}
