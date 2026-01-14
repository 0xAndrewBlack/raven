package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	dsBCapsPrimaryBuffer = 0x00000001
	dsBCapsCtrlVolume    = 0x00000080
	dsBCapsCtrlPan       = 0x00000040
	dsBCapsCtrlFrequency = 0x00000020

	dsBStatusPlaying = 0x00000001
	dsBStatusLooping = 0x00000004

	dsBPlayLooping = 0x00000001

	dsBLockFromWriteCursor = 0x00000001
	dsBLockEntireBuffer    = 0x00000002

	dsSpeakerStereo = 0x00000004

	waveFormatPCM = 0x0001
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
}

type dsPendingLock struct {
	ptr1         uint64
	bytes1       uint32
	offset1      uint32
	ptr2         uint64
	bytes2       uint32
	offset2      uint32
	nextWritePos uint32
}

type directSoundDeviceData struct {
	mu               sync.Mutex
	capture          bool
	cooperativeLevel uint32
	speakerConfig    uint32
	defaultFormat    waveFormatEx
}

type dsBuffer struct {
	mu sync.Mutex

	parent *directSoundDeviceData

	format    waveFormatEx
	size      uint32
	data      []byte
	playPos   uint32
	writePos  uint32
	playing   bool
	looping   bool
	volume    int32
	pan       int32
	frequency uint32
	flags     uint32
	primary   bool

	playStart    time.Time
	playStartPos uint32
	pendingLock  *dsPendingLock
}

type dsoundBackend struct {
	once sync.Once
	name string
}

var globalDsoundBackend dsoundBackend

func defaultWaveFormatEx() waveFormatEx {
	w := waveFormatEx{
		FormatTag:     waveFormatPCM,
		Channels:      2,
		SamplesPerSec: 44100,
		BitsPerSample: 16,
		CbSize:        0,
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
	if addr == 0 {
		return dsBufferDesc{
			Flags:       0,
			BufferBytes: defaultWaveFormatEx().AvgBytesPerSec,
			Format:      defaultWaveFormatEx(),
		}
	}
	flags, _ := mem.Read32(addr + 4)
	bufferBytes, _ := mem.Read32(addr + 8)
	wfxPtr, _ := mem.Read64(addr + 16)
	format := defaultWaveFormatEx()
	if wfxPtr != 0 {
		format = readWaveFormatEx(mem, wfxPtr)
	}
	format = normalizeWaveFormatEx(format)
	if bufferBytes == 0 {
		bufferBytes = format.AvgBytesPerSec
	}
	if flags&dsBCapsPrimaryBuffer != 0 && bufferBytes == 0 {
		bufferBytes = format.AvgBytesPerSec
	}
	if bufferBytes == 0 {
		bufferBytes = 4096
	}
	return dsBufferDesc{
		Flags:       flags,
		BufferBytes: bufferBytes,
		Format:      format,
	}
}

func writeDSCaps(mem *mmu.MMU, addr uint64) {
	if addr == 0 {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = 96
	}
	mem.Write32(addr+0, size)
	mem.Write32(addr+4, 0)
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

func writeDSBufferCaps(mem *mmu.MMU, addr uint64, buf *dsBuffer) {
	if addr == 0 || buf == nil {
		return
	}
	size, _ := mem.Read32(addr)
	if size == 0 {
		size = 20
	}
	mem.Write32(addr+0, size)
	mem.Write32(addr+4, buf.flags)
	mem.Write32(addr+8, buf.size)
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

func advancePlayCursorLocked(buf *dsBuffer) {
	if buf == nil || !buf.playing || buf.size == 0 || buf.playStart.IsZero() {
		return
	}
	bytesPerSec := uint64(buf.format.AvgBytesPerSec)
	if buf.format.SamplesPerSec != 0 && buf.frequency != 0 && buf.frequency != buf.format.SamplesPerSec {
		bytesPerSec = uint64(buf.format.AvgBytesPerSec) * uint64(buf.frequency) / uint64(buf.format.SamplesPerSec)
	}
	if bytesPerSec == 0 {
		return
	}
	elapsed := time.Since(buf.playStart)
	advanced := uint64(elapsed) * bytesPerSec / uint64(time.Second)
	buf.playPos = (buf.playStartPos + uint32(advanced%uint64(buf.size))) % buf.size
}

func (buf *dsBuffer) cleanupPendingLock(mem *mmu.MMU) {
	if buf == nil || buf.pendingLock == nil {
		return
	}
	if buf.pendingLock.ptr1 != 0 && buf.pendingLock.bytes1 != 0 {
		mem.Munmap(buf.pendingLock.ptr1, uint64(buf.pendingLock.bytes1))
	}
	if buf.pendingLock.ptr2 != 0 && buf.pendingLock.bytes2 != 0 {
		mem.Munmap(buf.pendingLock.ptr2, uint64(buf.pendingLock.bytes2))
	}
	buf.pendingLock = nil
}

func (buf *dsBuffer) writeRegionFromInternal(mem *mmu.MMU, ptr uint64, offset uint32, count uint32) {
	if buf == nil || ptr == 0 || count == 0 || buf.size == 0 {
		return
	}
	end := offset + count
	if end > uint32(len(buf.data)) {
		end = uint32(len(buf.data))
	}
	if end > offset {
		mem.WriteBytes(ptr, buf.data[offset:end])
	}
}

func (buf *dsBuffer) readRegionToInternal(mem *mmu.MMU, ptr uint64, offset uint32, count uint32) {
	if buf == nil || ptr == 0 || count == 0 || buf.size == 0 {
		return
	}
	raw, err := mem.ReadBytes(ptr, int(count))
	if err != nil {
		return
	}
	end := offset + uint32(len(raw))
	if end > uint32(len(buf.data)) {
		end = uint32(len(buf.data))
		raw = raw[:end-offset]
	}
	copy(buf.data[offset:end], raw)
}

func (cs *comState) createDirectSoundObject(capture bool) (*comObject, error) {
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
	obj.kind = kind
	obj.data = &directSoundDeviceData{
		capture:       capture,
		speakerConfig: dsSpeakerStereo,
		defaultFormat: defaultWaveFormatEx(),
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
	desc.Format = normalizeWaveFormatEx(desc.Format)
	if desc.BufferBytes == 0 {
		desc.BufferBytes = desc.Format.AvgBytesPerSec
	}
	data := &dsBuffer{
		parent:    device,
		format:    desc.Format,
		size:      desc.BufferBytes,
		data:      make([]byte, desc.BufferBytes),
		volume:    0,
		pan:       0,
		frequency: desc.Format.SamplesPerSec,
		flags:     desc.Flags,
		primary:   desc.Flags&dsBCapsPrimaryBuffer != 0,
	}
	obj.kind = "direct-sound-buffer"
	obj.data = data
	obj.supportedIIDs[IID_IDirectSoundBuffer] = true
	return obj, nil
}

func cloneDSBuffer(src *dsBuffer) *dsBuffer {
	if src == nil {
		return nil
	}
	return &dsBuffer{
		parent:       src.parent,
		format:       src.format,
		size:         src.size,
		data:         append([]byte(nil), src.data...),
		playPos:      src.playPos,
		writePos:     src.writePos,
		playing:      src.playing,
		looping:      src.looping,
		volume:       src.volume,
		pan:          src.pan,
		frequency:    src.frequency,
		flags:        src.flags,
		primary:      src.primary,
		playStart:    src.playStart,
		playStartPos: src.playStartPos,
	}
}

func dsoundBackendName() string {
	globalDsoundBackend.once.Do(func() {
		for _, name := range []string{"paplay", "aplay"} {
			if _, err := exec.LookPath(name); err == nil {
				globalDsoundBackend.name = name
				return
			}
		}
		globalDsoundBackend.name = ""
	})
	return globalDsoundBackend.name
}

func playPCMAsync(format waveFormatEx, pcm []byte) {
	if len(pcm) == 0 || format.FormatTag != waveFormatPCM {
		return
	}
	backend := dsoundBackendName()
	if backend == "" {
		return
	}
	var args []string
	switch backend {
	case "paplay":
		var paplayFmt string
		switch format.BitsPerSample {
		case 8:
			paplayFmt = "u8"
		case 16:
			paplayFmt = "s16le"
		default:
			return
		}
		args = []string{
			"--raw",
			fmt.Sprintf("--channels=%d", format.Channels),
			fmt.Sprintf("--rate=%d", format.SamplesPerSec),
			fmt.Sprintf("--format=%s", paplayFmt),
		}
	case "aplay":
		var aplayFmt string
		switch format.BitsPerSample {
		case 8:
			aplayFmt = "U8"
		case 16:
			aplayFmt = "S16_LE"
		default:
			return
		}
		args = []string{
			"-q",
			"-t", "raw",
			"-c", fmt.Sprintf("%d", format.Channels),
			"-r", fmt.Sprintf("%d", format.SamplesPerSec),
			"-f", aplayFmt,
		}
	default:
		return
	}
	cmd := exec.Command(backend, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return
	}
	payload := append([]byte(nil), pcm...)
	go func() {
		_, _ = stdin.Write(payload)
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
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
		writeDSCaps(ctx.Mem, ctx.Arg(1))
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
		origBuf, _ := origObj.data.(*dsBuffer)
		if origBuf == nil {
			return E_INVALIDARG
		}
		origBuf.mu.Lock()
		clone := cloneDSBuffer(origBuf)
		origBuf.mu.Unlock()
		dupObj, err := cs.createGuestObject(cs.mem, IID_IDirectSoundBuffer, 21)
		if err != nil {
			return hresultFromError(err)
		}
		dupObj.kind = "direct-sound-buffer"
		dupObj.data = clone
		dupObj.supportedIIDs[IID_IDirectSoundBuffer] = true
		ctx.Mem.Write64(ppDup, dupObj.objectAddr)
		return S_OK
	case 6:
		device.mu.Lock()
		device.cooperativeLevel = uint32(ctx.Arg(2))
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
		writeDSCaps(ctx.Mem, ctx.Arg(1))
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
	buf, _ := obj.data.(*dsBuffer)
	if buf == nil {
		return E_FAIL
	}
	switch method {
	case 3:
		buf.mu.Lock()
		writeDSBufferCaps(ctx.Mem, ctx.Arg(1), buf)
		buf.mu.Unlock()
		return S_OK
	case 4:
		playPtr := ctx.Arg(1)
		writePtr := ctx.Arg(2)
		buf.mu.Lock()
		advancePlayCursorLocked(buf)
		playPos := buf.playPos
		writePos := buf.writePos
		buf.mu.Unlock()
		if playPtr != 0 {
			ctx.Mem.Write32(playPtr, playPos)
		}
		if writePtr != 0 {
			ctx.Mem.Write32(writePtr, writePos)
		}
		return S_OK
	case 5:
		pwfx := ctx.Arg(1)
		sizeAllocated := uint32(ctx.Arg(2))
		sizeWritten := ctx.Arg(3)
		buf.mu.Lock()
		written := writeWaveFormatEx(ctx.Mem, pwfx, buf.format, sizeAllocated)
		buf.mu.Unlock()
		if sizeWritten != 0 {
			ctx.Mem.Write32(sizeWritten, written)
		}
		return S_OK
	case 6:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		buf.mu.Lock()
		ctx.Mem.Write32(pOut, uint32(buf.volume))
		buf.mu.Unlock()
		return S_OK
	case 7:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		buf.mu.Lock()
		ctx.Mem.Write32(pOut, uint32(buf.pan))
		buf.mu.Unlock()
		return S_OK
	case 8:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		buf.mu.Lock()
		ctx.Mem.Write32(pOut, buf.frequency)
		buf.mu.Unlock()
		return S_OK
	case 9:
		pOut := ctx.Arg(1)
		if pOut == 0 {
			return E_POINTER
		}
		buf.mu.Lock()
		advancePlayCursorLocked(buf)
		status := uint32(0)
		if buf.playing {
			status |= dsBStatusPlaying
		}
		if buf.looping {
			status |= dsBStatusLooping
		}
		buf.mu.Unlock()
		ctx.Mem.Write32(pOut, status)
		return S_OK
	case 10:
		desc := readDSBufferDesc(ctx.Mem, ctx.Arg(2))
		buf.mu.Lock()
		buf.cleanupPendingLock(ctx.Mem)
		buf.format = desc.Format
		buf.size = desc.BufferBytes
		buf.data = make([]byte, desc.BufferBytes)
		buf.playPos = 0
		buf.writePos = 0
		buf.playing = false
		buf.looping = false
		buf.volume = 0
		buf.pan = 0
		buf.frequency = desc.Format.SamplesPerSec
		buf.flags = desc.Flags
		buf.primary = desc.Flags&dsBCapsPrimaryBuffer != 0
		buf.mu.Unlock()
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
		buf.mu.Lock()
		defer buf.mu.Unlock()
		if buf.size == 0 {
			return E_FAIL
		}
		if flags&dsBLockEntireBuffer != 0 || requested == 0 || requested > buf.size {
			requested = buf.size
		}
		if flags&dsBLockFromWriteCursor != 0 {
			offset = buf.writePos
		}
		if offset >= buf.size {
			offset %= buf.size
		}
		buf.cleanupPendingLock(ctx.Mem)
		firstLen := requested
		secondLen := uint32(0)
		if offset+requested > buf.size {
			firstLen = buf.size - offset
			secondLen = requested - firstLen
		}
		pending := &dsPendingLock{
			offset1:      offset,
			bytes1:       firstLen,
			offset2:      0,
			bytes2:       secondLen,
			nextWritePos: (offset + requested) % buf.size,
		}
		if secondLen != 0 {
			pending.offset2 = 0
		}
		if firstLen != 0 {
			pending.ptr1, _ = allocGuestTemp(ctx.Mem, buf.data[offset:offset+firstLen])
		}
		if secondLen != 0 {
			pending.ptr2, _ = allocGuestTemp(ctx.Mem, buf.data[0:secondLen])
		}
		buf.pendingLock = pending
		ctx.Mem.Write64(pp1, pending.ptr1)
		ctx.Mem.Write32(pb1, pending.bytes1)
		ctx.Mem.Write64(pp2, pending.ptr2)
		ctx.Mem.Write32(pb2, pending.bytes2)
		return S_OK
	case 12:
		flags := uint32(ctx.Arg(3))
		var snapshot []byte
		var format waveFormatEx
		var primary bool
		buf.mu.Lock()
		advancePlayCursorLocked(buf)
		buf.playing = true
		buf.looping = flags&dsBPlayLooping != 0
		buf.playStartPos = buf.playPos
		buf.playStart = time.Now()
		format = buf.format
		primary = buf.primary
		snapshot = append(snapshot, buf.data...)
		buf.mu.Unlock()
		if !primary {
			playPCMAsync(format, snapshot)
		}
		return S_OK
	case 13:
		newPos := uint32(ctx.Arg(1))
		buf.mu.Lock()
		if buf.size != 0 {
			newPos %= buf.size
		} else {
			newPos = 0
		}
		buf.playPos = newPos
		buf.playStartPos = newPos
		buf.playStart = time.Now()
		buf.mu.Unlock()
		return S_OK
	case 14:
		wfx := ctx.Arg(1)
		buf.mu.Lock()
		buf.format = readWaveFormatEx(ctx.Mem, wfx)
		buf.frequency = buf.format.SamplesPerSec
		buf.mu.Unlock()
		return S_OK
	case 15:
		vol := int32(ctx.Arg(1))
		buf.mu.Lock()
		buf.volume = clampInt32(vol, -10000, 0)
		buf.mu.Unlock()
		return S_OK
	case 16:
		pan := int32(ctx.Arg(1))
		buf.mu.Lock()
		buf.pan = clampInt32(pan, -10000, 10000)
		buf.mu.Unlock()
		return S_OK
	case 17:
		freq := uint32(ctx.Arg(1))
		buf.mu.Lock()
		if freq == 0 {
			freq = buf.format.SamplesPerSec
		}
		buf.frequency = clampUint32(freq, 100, 200000)
		buf.mu.Unlock()
		return S_OK
	case 18:
		buf.mu.Lock()
		advancePlayCursorLocked(buf)
		buf.playing = false
		buf.looping = false
		buf.playStart = time.Time{}
		buf.mu.Unlock()
		return S_OK
	case 19:
		buf.mu.Lock()
		buf.readRegionToInternal(ctx.Mem, ctx.Arg(1), 0, 0)
		if buf.pendingLock != nil {
			buf.readRegionToInternal(ctx.Mem, buf.pendingLock.ptr1, buf.pendingLock.offset1, buf.pendingLock.bytes1)
			buf.readRegionToInternal(ctx.Mem, buf.pendingLock.ptr2, buf.pendingLock.offset2, buf.pendingLock.bytes2)
			buf.writePos = buf.pendingLock.nextWritePos
		}
		buf.cleanupPendingLock(ctx.Mem)
		buf.mu.Unlock()
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
		obj, err := cs.createDirectSoundObject(false)
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
		obj, err := cs.createDirectSoundObject(false)
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
		obj, err := cs.createDirectSoundObject(true)
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
		obj, err := cs.createDirectSoundObject(true)
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
