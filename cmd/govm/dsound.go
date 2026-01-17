package main

import (
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/mirkobrombin/Raven/pkg/audio"
	dsoundpkg "github.com/mirkobrombin/Raven/pkg/dsound"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	dsBStatusPlaying = 0x00000001
	dsBStatusLooping = 0x00000004
	dsSpeakerStereo  = 0x00000004
	waveFormatPCM    = 0x0001
)

var (
	IID_IDirectSound  = GUID{0x279AFA83, 0x4981, 0x11CE, [8]byte{0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}}
	IID_IDirectSound8 = GUID{0xC50A7E93, 0xF395, 0x4834, [8]byte{0x9E, 0xF6, 0x7F, 0xA9, 0x9D, 0xE5, 0x09, 0x66}}

	IID_IDirectSoundBuffer = GUID{0x279AFA85, 0x4981, 0x11CE, [8]byte{0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}}

	IID_IDirectSoundCapture  = GUID{0xB0210781, 0x89CD, 0x11D0, [8]byte{0xAF, 0x08, 0x00, 0xA0, 0xC9, 0x25, 0xCD, 0x16}}
	IID_IDirectSoundCapture8 = GUID{0x00990DF4, 0x0DBB, 0x4872, [8]byte{0x83, 0x3E, 0x6D, 0x30, 0x3E, 0x80, 0xAE, 0xB6}}
)

type waveFormatEx struct {
	FormatTag      uint16
	Channels       uint16
	SamplesPerSec  uint32
	AvgBytesPerSec uint32
	BlockAlign     uint16
	BitsPerSample  uint16
	CbSize         uint16
}

type dsBufferDesc struct {
	Flags       uint32
	BufferBytes uint32
	Format      waveFormatEx
	HasFormat   bool
}

type dsPendingLock struct {
	guestPtr1    uint64
	bytes1       uint32
	offset1      uint32
	guestPtr2    uint64
	bytes2       uint32
	offset2      uint32
	nextWritePos uint32
}

type directSoundDeviceData struct {
	mu               sync.Mutex
	capture          bool
	cooperativeLevel uint32
	speakerConfig    uint32
	device           *dsoundpkg.DirectSound
}

type dsBufferObject struct {
	buffer      *dsoundpkg.Buffer
	parent      *directSoundDeviceData
	flags       uint32
	primary     bool
	pendingLock *dsPendingLock
}

func defaultWaveFormatEx() waveFormatEx {
	w := waveFormatEx{
		FormatTag:     waveFormatPCM,
		Channels:      2,
		SamplesPerSec: 44100,
		BitsPerSample: 16,
	}
	return normalizeWaveFormatEx(w)
}

func normalizeWaveFormatEx(w waveFormatEx) waveFormatEx {
	if w.FormatTag == 0 {
		w.FormatTag = waveFormatPCM
	}
	if w.Channels == 0 {
		w.Channels = 2
	}
	if w.SamplesPerSec == 0 {
		w.SamplesPerSec = 44100
	}
	if w.BitsPerSample == 0 {
		w.BitsPerSample = 16
	}
	blockAlign := uint32(w.Channels) * uint32(w.BitsPerSample) / 8
	if blockAlign == 0 {
		blockAlign = 4
	}
	w.BlockAlign = uint16(blockAlign)
	avg := uint64(w.SamplesPerSec) * uint64(w.BlockAlign)
	if avg == 0 {
		avg = 44100 * 4
	}
	w.AvgBytesPerSec = uint32(avg)
	return w
}

func toDSoundFormat(w waveFormatEx) dsoundpkg.WAVEFORMATEX {
	w = normalizeWaveFormatEx(w)
	return dsoundpkg.WAVEFORMATEX{
		WFormatTag:      w.FormatTag,
		NChannels:       w.Channels,
		NSamplesPerSec:  w.SamplesPerSec,
		NAvgBytesPerSec: w.AvgBytesPerSec,
		NBlockAlign:     w.BlockAlign,
		WBitsPerSample:  w.BitsPerSample,
		CbSize:          w.CbSize,
	}
}

func fromDSoundFormat(w dsoundpkg.WAVEFORMATEX) waveFormatEx {
	w = dsoundpkg.NormalizeFormat(w)
	return waveFormatEx{
		FormatTag:      w.WFormatTag,
		Channels:       w.NChannels,
		SamplesPerSec:  w.NSamplesPerSec,
		AvgBytesPerSec: w.NAvgBytesPerSec,
		BlockAlign:     w.NBlockAlign,
		BitsPerSample:  w.WBitsPerSample,
		CbSize:         w.CbSize,
	}
}

func readWaveFormatEx(mem *mmu.MMU, addr uint64) waveFormatEx {
	if addr == 0 {
		return defaultWaveFormatEx()
	}
	w := waveFormatEx{}
	w.FormatTag, _ = mem.Read16(addr + 0)
	w.Channels, _ = mem.Read16(addr + 2)
	w.SamplesPerSec, _ = mem.Read32(addr + 4)
	w.AvgBytesPerSec, _ = mem.Read32(addr + 8)
	w.BlockAlign, _ = mem.Read16(addr + 12)
	w.BitsPerSample, _ = mem.Read16(addr + 14)
	w.CbSize, _ = mem.Read16(addr + 16)
	return normalizeWaveFormatEx(w)
}

func waveFormatExSize(w waveFormatEx) uint32 {
	return 18 + uint32(w.CbSize)
}

func writeWaveFormatEx(mem *mmu.MMU, addr uint64, w waveFormatEx, max uint32) uint32 {
	if addr == 0 || max == 0 {
		return waveFormatExSize(w)
	}
	w = normalizeWaveFormatEx(w)
	raw := make([]byte, waveFormatExSize(w))
	binary.LittleEndian.PutUint16(raw[0:2], w.FormatTag)
	binary.LittleEndian.PutUint16(raw[2:4], w.Channels)
	binary.LittleEndian.PutUint32(raw[4:8], w.SamplesPerSec)
	binary.LittleEndian.PutUint32(raw[8:12], w.AvgBytesPerSec)
	binary.LittleEndian.PutUint16(raw[12:14], w.BlockAlign)
	binary.LittleEndian.PutUint16(raw[14:16], w.BitsPerSample)
	binary.LittleEndian.PutUint16(raw[16:18], w.CbSize)
	if uint32(len(raw)) > max {
		raw = raw[:max]
	}
	mem.WriteBytes(addr, raw)
	return waveFormatExSize(w)
}

func readDSBufferDesc(mem *mmu.MMU, addr uint64) dsBufferDesc {
	desc := dsBufferDesc{Format: defaultWaveFormatEx()}
	if addr == 0 {
		desc.BufferBytes = desc.Format.AvgBytesPerSec
		return desc
	}
	desc.Flags, _ = mem.Read32(addr + 4)
	desc.BufferBytes, _ = mem.Read32(addr + 8)
	wfxPtr, _ := mem.Read64(addr + 16)
	if wfxPtr != 0 {
		desc.Format = readWaveFormatEx(mem, wfxPtr)
		desc.HasFormat = true
	}
	desc.Format = normalizeWaveFormatEx(desc.Format)
	if desc.BufferBytes == 0 {
		desc.BufferBytes = desc.Format.AvgBytesPerSec
	}
	if desc.BufferBytes == 0 {
		desc.BufferBytes = 4096
	}
	return desc
}

func writeDSCaps(mem *mmu.MMU, addr uint64, device *dsoundpkg.DirectSound) {
	if addr == 0 {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = 96
	}
	caps := dsoundpkg.DSBCAPS{}
	if device != nil {
		caps = device.GetCaps()
	}
	mem.Write32(addr+0, size)
	mem.Write32(addr+4, caps.DwFlags)
	mem.Write32(addr+8, 100)
	mem.Write32(addr+12, 200000)
	mem.Write32(addr+16, 1)
	mem.Write32(addr+20, 16)
	mem.Write32(addr+24, 16)
	mem.Write32(addr+28, 16)
	mem.Write32(addr+32, 16)
	mem.Write32(addr+36, 0)
	mem.Write32(addr+40, 0)
}

func writeDSBufferCaps(mem *mmu.MMU, addr uint64, data *dsBufferObject) {
	if addr == 0 || data == nil || data.buffer == nil {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = 20
	}
	mem.Write32(addr+0, size)
	mem.Write32(addr+4, data.flags)
	mem.Write32(addr+8, data.buffer.Size)
	mem.Write32(addr+12, 0)
	mem.Write32(addr+16, 0)
}

func clampInt32(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func clampUint32(v, lo, hi uint32) uint32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func allocGuestTemp(mem *mmu.MMU, data []byte) (uint64, uint64) {
	if len(data) == 0 {
		return 0, 0
	}
	size := uint64(len(data))
	addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	if addr != 0 {
		mem.WriteBytes(addr, data)
	}
	return addr, size
}

func allocGuestUTF16(mem *mmu.MMU, s string) (uint64, uint64) {
	u16 := utf16Encode(s)
	raw := make([]byte, (len(u16)+1)*2)
	for i, w := range u16 {
		binary.LittleEndian.PutUint16(raw[i*2:], w)
	}
	return allocGuestTemp(mem, raw)
}

func cleanupPendingLock(mem *mmu.MMU, lock *dsPendingLock) {
	if lock == nil {
		return
	}
	if lock.guestPtr1 != 0 && lock.bytes1 != 0 {
		mem.Munmap(lock.guestPtr1, uint64(lock.bytes1))
	}
	if lock.guestPtr2 != 0 && lock.bytes2 != 0 {
		mem.Munmap(lock.guestPtr2, uint64(lock.bytes2))
	}
}

func copyFromGuestToBuffer(mem *mmu.MMU, buffer *dsoundpkg.Buffer, guestPtr uint64, offset, count uint32) {
	if buffer == nil || guestPtr == 0 || count == 0 || offset >= uint32(len(buffer.Data)) {
		return
	}
	raw, err := mem.ReadBytes(guestPtr, int(count))
	if err != nil {
		return
	}
	end := offset + uint32(len(raw))
	if end > uint32(len(buffer.Data)) {
		end = uint32(len(buffer.Data))
		raw = raw[:end-offset]
	}
	copy(buffer.Data[offset:end], raw)
}

func cloneDSBuffer(src *dsBufferObject) *dsBufferObject {
	if src == nil || src.buffer == nil {
		return nil
	}
	format := src.buffer.GetFormat()
	clone := &dsoundpkg.Buffer{
		Data:        append([]byte(nil), src.buffer.Data...),
		Size:        src.buffer.Size,
		Format:      format,
		PlayCursor:  src.buffer.PlayCursor,
		WriteCursor: src.buffer.WriteCursor,
		Playing:     src.buffer.Playing,
		Looping:     src.buffer.Looping,
		Volume:      src.buffer.GetVolume(),
		Frequency:   src.buffer.GetFrequency(),
		Pan:         src.buffer.GetPan(),
	}
	return &dsBufferObject{
		buffer:  clone,
		parent:  src.parent,
		flags:   src.flags,
		primary: src.primary,
	}
}

func bufferOffset(buffer *dsoundpkg.Buffer, ptr uintptr, length uint32) uint32 {
	if buffer == nil || ptr == 0 || length == 0 || len(buffer.Data) == 0 {
		return 0
	}
	base := uintptr(unsafe.Pointer(&buffer.Data[0]))
	return uint32(ptr - base)
}

func bufferBytes(ptr uintptr, length uint32) []byte {
	if ptr == 0 || length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), int(length))
}

func ensureDirectSoundAudio(hctx *HandlerCtx, device *dsoundpkg.DirectSound) {
	if hctx == nil || device == nil || hctx.AudioOutput != nil {
		return
	}
	format := dsoundpkg.NormalizeFormat(device.Format)
	out, err := audio.Init(int(format.NSamplesPerSec), int(format.NChannels), int(format.WBitsPerSample))
	if err != nil {
		ravelog.Logf("[dsound] host audio init failed: %v\n", err)
		return
	}
	hctx.AudioOutput = out
}

func attachDirectSoundMixer(hctx *HandlerCtx, device *dsoundpkg.DirectSound) {
	if hctx == nil || device == nil || hctx.AudioOutput == nil {
		return
	}
	hctx.AudioOutput.SetMixer(device.Mixer(device.Format))
}

func (cs *comState) createDirectSoundObject(capture bool, device *dsoundpkg.DirectSound) (*comObject, error) {
	iid := IID_IDirectSound8
	methods := 12
	kind := "direct-sound-device"
	if capture {
		iid = IID_IDirectSoundCapture8
		methods = 7
		kind = "direct-sound-capture"
	}
	obj, err := cs.createGuestObject(cs.mem, iid, methods)
	if err != nil {
		return nil, err
	}
	if device == nil {
		device = dsoundpkg.NewDirectSound()
	}
	obj.kind = kind
	obj.data = &directSoundDeviceData{
		capture:       capture,
		speakerConfig: dsSpeakerStereo,
		device:        device,
	}
	if capture {
		obj.supportedIIDs[IID_IDirectSoundCapture] = true
		obj.supportedIIDs[IID_IDirectSoundCapture8] = true
	} else {
		obj.supportedIIDs[IID_IDirectSound] = true
		obj.supportedIIDs[IID_IDirectSound8] = true
	}
	return obj, nil
}

func (cs *comState) createDirectSoundBufferObject(device *directSoundDeviceData, desc dsBufferDesc) (*comObject, error) {
	obj, err := cs.createGuestObject(cs.mem, IID_IDirectSoundBuffer, 21)
	if err != nil {
		return nil, err
	}
	if device == nil || device.device == nil {
		device = &directSoundDeviceData{speakerConfig: dsSpeakerStereo, device: dsoundpkg.NewDirectSound()}
	}
	pkgDesc := dsoundpkg.DSBUFFERDESC{
		DwSize:        20,
		DwFlags:       desc.Flags,
		DwBufferBytes: desc.BufferBytes,
	}
	if desc.HasFormat {
		format := toDSoundFormat(desc.Format)
		pkgDesc.LpwfxFormat = &format
	}
	buffer := device.device.CreateSoundBuffer(pkgDesc)
	attachDirectSoundMixer(cs.hctx, device.device)
	data := &dsBufferObject{
		buffer:  buffer,
		parent:  device,
		flags:   desc.Flags,
		primary: desc.Flags&dsoundpkg.DSBCAPS_PRIMARYBUFFER != 0,
	}
	obj.kind = "direct-sound-buffer"
	obj.data = data
	obj.supportedIIDs[IID_IDirectSoundBuffer] = true
	return obj, nil
}

func enumerateDirectSoundDevices(ctx *ntapi.TrapContext, callback, userCtx uint64, desc, module string) uint32 {
	if callback == 0 {
		return S_OK
	}
	trampoline := ntapi.AllocTrampoline(ctx.Mem)
	descPtr, descSize := allocGuestUTF16(ctx.Mem, desc)
	modPtr, modSize := allocGuestUTF16(ctx.Mem, module)
	if descPtr != 0 {
		defer ctx.Mem.Munmap(descPtr, descSize)
	}
	if modPtr != 0 {
		defer ctx.Mem.Munmap(modPtr, modSize)
	}
	_, err := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, callback, []uint64{0, descPtr, modPtr, userCtx}, ctx.Trace)
	if err != nil {
		return E_FAIL
	}
	return S_OK
}

func (cs *comState) dispatchDirectSound(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	device, _ := obj.data.(*directSoundDeviceData)
	if device == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		pDesc := ctx.Arg(1)
		ppBuffer := ctx.Arg(2)
		pUnkOuter := ctx.Arg(3)
		if ppBuffer == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBuffer, 0)
		if pUnkOuter != 0 {
			return CLASS_E_NOAGGREGATION
		}
		desc := readDSBufferDesc(ctx.Mem, pDesc)
		bufObj, err := cs.createDirectSoundBufferObject(device, desc)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBuffer, bufObj.objectAddr)
		return S_OK
	case 4:
		writeDSCaps(ctx.Mem, ctx.Arg(1), device.device)
		return S_OK
	case 5:
		origPtr := ctx.Arg(1)
		ppDup := ctx.Arg(2)
		if ppDup == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppDup, 0)
		origObj := cs.objects[origPtr]
		if origObj == nil {
			return E_INVALIDARG
		}
		origBuf, _ := origObj.data.(*dsBufferObject)
		if origBuf == nil {
			return E_INVALIDARG
		}
		clone := cloneDSBuffer(origBuf)
		dupObj, err := cs.createGuestObject(cs.mem, IID_IDirectSoundBuffer, 21)
		if err != nil {
			return hresultFromError(err)
		}
		dupObj.kind = "direct-sound-buffer"
		dupObj.data = clone
		dupObj.supportedIIDs[IID_IDirectSoundBuffer] = true
		if device.device != nil && clone != nil && !clone.primary {
			device.device.SecondaryBuffers = append(device.device.SecondaryBuffers, clone.buffer)
			attachDirectSoundMixer(cs.hctx, device.device)
		}
		ctx.Mem.Write64(ppDup, dupObj.objectAddr)
		return S_OK
	case 6:
		hwnd := uint32(ctx.Arg(1))
		level := uint32(ctx.Arg(2))
		device.mu.Lock()
		device.cooperativeLevel = level
		if device.device != nil {
			device.device.SetCooperativeLevel(hwnd, level)
		}
		device.mu.Unlock()
		return S_OK
	case 7:
		return S_OK
	case 8:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		device.mu.Lock()
		cfg := device.speakerConfig
		device.mu.Unlock()
		ctx.Mem.Write32(pOut, cfg)
		return S_OK
	case 9:
		device.mu.Lock()
		device.speakerConfig = uint32(ctx.Arg(1))
		device.mu.Unlock()
		return S_OK
	case 10:
		return S_OK
	case 11:
		pCertified := ctx.Arg(1)
		if pCertified != 0 {
			ctx.Mem.Write32(pCertified, 0)
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchDirectSoundCapture(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	device, _ := obj.data.(*directSoundDeviceData)
	if device == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		pDesc := ctx.Arg(1)
		ppBuffer := ctx.Arg(2)
		pUnkOuter := ctx.Arg(3)
		if ppBuffer == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(ppBuffer, 0)
		if pUnkOuter != 0 {
			return CLASS_E_NOAGGREGATION
		}
		desc := readDSBufferDesc(ctx.Mem, pDesc)
		bufObj, err := cs.createDirectSoundBufferObject(device, desc)
		if err != nil {
			return hresultFromError(err)
		}
		ctx.Mem.Write64(ppBuffer, bufObj.objectAddr)
		return S_OK
	case 4:
		writeDSCaps(ctx.Mem, ctx.Arg(1), device.device)
		return S_OK
	case 5:
		return S_OK
	case 6:
		pCertified := ctx.Arg(1)
		if pCertified != 0 {
			ctx.Mem.Write32(pCertified, 0)
		}
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func (cs *comState) dispatchDirectSoundBuffer(ctx *ntapi.TrapContext, obj *comObject, method int) uint32 {
	data, _ := obj.data.(*dsBufferObject)
	if data == nil || data.buffer == nil {
		return E_FAIL
	}
	buf := data.buffer
	switch method {
	case 3:
		writeDSBufferCaps(ctx.Mem, ctx.Arg(1), data)
		return S_OK
	case 4:
		playPos, writePos := buf.GetCurrentPosition()
		if playPtr := ctx.Arg(1); playPtr != 0 {
			ctx.Mem.Write32(playPtr, playPos)
		}
		if writePtr := ctx.Arg(2); writePtr != 0 {
			ctx.Mem.Write32(writePtr, writePos)
		}
		return S_OK
	case 5:
		pwfx := ctx.Arg(1)
		sizeAllocated := uint32(ctx.Arg(2))
		sizeWritten := ctx.Arg(3)
		written := writeWaveFormatEx(ctx.Mem, pwfx, fromDSoundFormat(buf.GetFormat()), sizeAllocated)
		if sizeWritten != 0 {
			ctx.Mem.Write32(sizeWritten, written)
		}
		return S_OK
	case 6:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pOut, uint32(buf.GetVolume()))
		return S_OK
	case 7:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pOut, uint32(buf.GetPan()))
		return S_OK
	case 8:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		ctx.Mem.Write32(pOut, buf.GetFrequency())
		return S_OK
	case 9:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		status := uint32(0)
		if buf.GetStatus()&dsoundpkg.DSBSTATUS_PLAYING != 0 {
			status |= dsBStatusPlaying
		}
		if buf.GetStatus()&dsoundpkg.DSBSTATUS_LOOPING != 0 {
			status |= dsBStatusLooping
		}
		ctx.Mem.Write32(pOut, status)
		return S_OK
	case 10:
		desc := readDSBufferDesc(ctx.Mem, ctx.Arg(2))
		cleanupPendingLock(ctx.Mem, data.pendingLock)
		data.pendingLock = nil
		buf.Stop()
		buf.Data = make([]byte, desc.BufferBytes)
		buf.Size = desc.BufferBytes
		buf.WriteCursor = 0
		buf.SetCurrentPosition(0)
		buf.SetVolume(0)
		buf.SetPan(0)
		buf.SetFormat(toDSoundFormat(desc.Format))
		buf.SetFrequency(toDSoundFormat(desc.Format).NSamplesPerSec)
		data.flags = desc.Flags
		data.primary = desc.Flags&dsoundpkg.DSBCAPS_PRIMARYBUFFER != 0
		if data.parent != nil && data.parent.device != nil && data.primary {
			data.parent.device.PrimaryBuffer = buf
			data.parent.device.Format = toDSoundFormat(desc.Format)
		}
		if data.parent != nil {
			attachDirectSoundMixer(cs.hctx, data.parent.device)
		}
		return S_OK
	case 11:
		offset := uint32(ctx.Arg(1))
		requested := uint32(ctx.Arg(2))
		pp1 := ctx.Arg(3)
		pb1 := ctx.Arg(4)
		pp2 := ctx.Arg(5)
		pb2 := ctx.Arg(6)
		flags := uint32(ctx.Arg(7))
		if pp1 == 0 || pb1 == 0 || pp2 == 0 || pb2 == 0 {
			return E_POINTER
		}
		ctx.Mem.Write64(pp1, 0)
		ctx.Mem.Write32(pb1, 0)
		ctx.Mem.Write64(pp2, 0)
		ctx.Mem.Write32(pb2, 0)
		if buf.Size == 0 {
			return E_FAIL
		}
		if flags&dsoundpkg.DSBLOCK_ENTIREBUFFER != 0 || requested == 0 || requested > buf.Size {
			requested = buf.Size
		}
		if flags&dsoundpkg.DSBLOCK_FROMWRITECURSOR != 0 {
			offset = buf.WriteCursor
		}
		if offset >= buf.Size {
			offset %= buf.Size
		}
		cleanupPendingLock(ctx.Mem, data.pendingLock)
		ptr1, len1, ptr2, len2 := buf.Lock(offset, requested, flags)
		pending := &dsPendingLock{
			offset1:      bufferOffset(buf, ptr1, len1),
			bytes1:       len1,
			offset2:      bufferOffset(buf, ptr2, len2),
			bytes2:       len2,
			nextWritePos: (offset + len1 + len2) % buf.Size,
		}
		if len1 != 0 {
			pending.guestPtr1, _ = allocGuestTemp(ctx.Mem, append([]byte(nil), bufferBytes(ptr1, len1)...))
		}
		if len2 != 0 {
			pending.guestPtr2, _ = allocGuestTemp(ctx.Mem, append([]byte(nil), bufferBytes(ptr2, len2)...))
		}
		data.pendingLock = pending
		ctx.Mem.Write64(pp1, pending.guestPtr1)
		ctx.Mem.Write32(pb1, pending.bytes1)
		ctx.Mem.Write64(pp2, pending.guestPtr2)
		ctx.Mem.Write32(pb2, pending.bytes2)
		return S_OK
	case 12:
		buf.Play(uint32(ctx.Arg(1)), uint32(ctx.Arg(2)), uint32(ctx.Arg(3)))
		if data.parent != nil {
			attachDirectSoundMixer(cs.hctx, data.parent.device)
		}
		return S_OK
	case 13:
		buf.SetCurrentPosition(uint32(ctx.Arg(1)))
		return S_OK
	case 14:
		format := toDSoundFormat(readWaveFormatEx(ctx.Mem, ctx.Arg(1)))
		buf.SetFormat(format)
		if data.primary && data.parent != nil && data.parent.device != nil {
			data.parent.device.Format = format
		}
		if data.parent != nil {
			attachDirectSoundMixer(cs.hctx, data.parent.device)
		}
		return S_OK
	case 15:
		buf.SetVolume(int32(ctx.Arg(1)))
		return S_OK
	case 16:
		buf.SetPan(int32(ctx.Arg(1)))
		return S_OK
	case 17:
		buf.SetFrequency(uint32(ctx.Arg(1)))
		return S_OK
	case 18:
		buf.Stop()
		return S_OK
	case 19:
		if data.pendingLock != nil {
			copyFromGuestToBuffer(ctx.Mem, buf, data.pendingLock.guestPtr1, data.pendingLock.offset1, data.pendingLock.bytes1)
			copyFromGuestToBuffer(ctx.Mem, buf, data.pendingLock.guestPtr2, data.pendingLock.offset2, data.pendingLock.bytes2)
			buf.WriteCursor = data.pendingLock.nextWritePos
			buf.Unlock(0, data.pendingLock.bytes1, 0, data.pendingLock.bytes2)
			cleanupPendingLock(ctx.Mem, data.pendingLock)
			data.pendingLock = nil
		}
		return S_OK
	case 20:
		return S_OK
	default:
		return E_NOTIMPL
	}
}

func registerDsoundHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["dsound.dll"]
	if !ok {
		return
	}
	cs := hctx.Com
	if cs == nil {
		cs = newCOMState(hctx)
		hctx.Com = cs
	}

	d.RegisterAutoStubHandler(dll, "DirectSoundCreate", func(ctx *ntapi.TrapContext) uint32 {
		ppDS := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		if ppDS == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppDS, 0)
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		device := dsoundpkg.NewDirectSound()
		hctx.DirectSound = device
		ensureDirectSoundAudio(hctx, device)
		obj, err := cs.createDirectSoundObject(false, device)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppDS, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DirectSoundCreate8", func(ctx *ntapi.TrapContext) uint32 {
		ppDS8 := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		if ppDS8 == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppDS8, 0)
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		device := dsoundpkg.NewDirectSound()
		hctx.DirectSound = device
		ensureDirectSoundAudio(hctx, device)
		obj, err := cs.createDirectSoundObject(false, device)
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppDS8, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DirectSoundEnumerateW", func(ctx *ntapi.TrapContext) uint32 {
		hr := enumerateDirectSoundDevices(ctx, ctx.Arg(0), ctx.Arg(1), "Primary Sound Driver", "dsound.dll")
		ctx.SetReturn(uint64(hr))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DirectSoundCaptureCreate", func(ctx *ntapi.TrapContext) uint32 {
		ppCapture := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		if ppCapture == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppCapture, 0)
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		obj, err := cs.createDirectSoundObject(true, dsoundpkg.NewDirectSound())
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppCapture, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DirectSoundCaptureCreate8", func(ctx *ntapi.TrapContext) uint32 {
		ppCapture8 := ctx.Arg(1)
		pUnkOuter := ctx.Arg(2)
		if ppCapture8 == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		ctx.Mem.Write64(ppCapture8, 0)
		if pUnkOuter != 0 {
			ctx.SetReturn(CLASS_E_NOAGGREGATION)
			return 0
		}
		obj, err := cs.createDirectSoundObject(true, dsoundpkg.NewDirectSound())
		if err != nil {
			ctx.SetReturn(uint64(hresultFromError(err)))
			return 0
		}
		ctx.Mem.Write64(ppCapture8, obj.objectAddr)
		ctx.SetReturn(S_OK)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DirectSoundCaptureEnumerateW", func(ctx *ntapi.TrapContext) uint32 {
		hr := enumerateDirectSoundDevices(ctx, ctx.Arg(0), ctx.Arg(1), "Primary Sound Capture Driver", "dsound.dll")
		ctx.SetReturn(uint64(hr))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "DllGetClassObject", func(ctx *ntapi.TrapContext) uint32 {
		ppv := ctx.Arg(2)
		if ppv != 0 {
			ctx.Mem.Write64(ppv, 0)
		}
		ctx.SetReturn(CLASS_E_CLASSNOTAVAILABLE)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "GetDeviceID", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		dst := ctx.Arg(1)
		if dst == 0 {
			ctx.SetReturn(E_POINTER)
			return 0
		}
		if src != 0 {
			writeGUID(ctx.Mem, dst, readGUID(ctx.Mem, src))
		} else {
			writeGUID(ctx.Mem, dst, GUID{})
		}
		ctx.SetReturn(S_OK)
		return 0
	})
}
