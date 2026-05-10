//go:build guest_windows

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mirkobrombin/Raven/pkg/arch"
	dsoundpkg "github.com/mirkobrombin/Raven/pkg/dsound"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

const (
	mmSysErrNoError      = 0
	mmSysErrError        = 1
	mmSysErrBadDeviceID  = 2
	mmSysErrInvalHandle  = 5
	mmSysErrNoDriver     = 6
	mmSysErrNoMem        = 7
	mmSysErrNotSupported = 8
	mmSysErrInvalParam   = 11

	wavErrBadFormat    = 32
	wavErrStillPlaying = 33

	timErrNoError = 0
	timErrNoCanDo = 97

	joyErrParms = 165

	waveFormatIEEEFloat = 3
	waveMapper          = 0xFFFFFFFF

	whdrDone     = 0x00000001
	whdrPrepared = 0x00000002

	timeOneShot  = 0x0000
	timePeriodic = 0x0001

	callbackFunction = 0x00030000

	mmTimeMS      = 0x0001
	mmTimeSamples = 0x0002
	mmTimeBytes   = 0x0004

	womOpen  = 0x03BB
	womClose = 0x03BC
	womDone  = 0x03BD
	wimOpen  = 0x03BE
	wimClose = 0x03BF
	wimData  = 0x03C0

	waveCapsVolume   = 0x0004
	waveCapsLRVolume = 0x0008

	waveFormat1M16 = 0x00000004
	waveFormat1S16 = 0x00000008
	waveFormat2M16 = 0x00000040
	waveFormat2S16 = 0x00000080
	waveFormat4M16 = 0x00000400
	waveFormat4S16 = 0x00000800

	sndAsync     = 0x0001
	sndNoDefault = 0x0002
	sndMemory    = 0x0004
	sndLoop      = 0x0008
	sndNoStop    = 0x0010
	sndAlias     = 0x00010000
	sndFilename  = 0x00020000
	sndResource  = 0x00040004

	mmioWriteFlag     = 0x00000001
	mmioReadWriteFlag = 0x00000002
	mmioCreateFlag    = 0x00001000
)

type waveHeader struct {
	dataPtr        uint64
	bufferLen      uint32
	bytesRecorded  uint32
	flags          uint32
	loops          uint32
	next           uint64
	reserved       uint64
	guestHeaderPtr uint64
}

type queuedWaveBuffer struct {
	headerPtr uint64
	header    waveHeader
	remaining uint32
}

type waveOutDevice struct {
	mu           sync.Mutex
	format       waveFormatEx
	buffers      []queuedWaveBuffer
	device       *dsoundpkg.DirectSound
	buffer       *dsoundpkg.SoundBuffer
	callback     uint64
	instance     uint64
	flags        uint32
	volume       uint32
	position     uint64
	pitch        uint32
	playbackRate uint32
	paused       bool
	playing      bool
	closed       bool
	lastTick     time.Time
	queuedBytes  uint64
	notify       chan struct{}
	stop         chan struct{}
	callbackCPU  arch.CPU
}

type playSoundPlayback struct {
	buffer   *dsoundpkg.SoundBuffer
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

type waveInDevice struct {
	mu          sync.Mutex
	readMu      sync.Mutex
	format      waveFormatEx
	buffers     []waveHeader
	cmd         *exec.Cmd
	pipe        io.ReadCloser
	callback    uint64
	instance    uint64
	flags       uint32
	position    uint64
	started     bool
	silent      bool
	callbackCPU arch.CPU
}

type mmioHandle struct {
	fd   int
	path string
}

type mmTimerEvent struct {
	id          uint32
	delay       uint32
	resolution  uint32
	callback    uint64
	user        uint64
	flags       uint32
	stop        chan struct{}
	callbackCPU arch.CPU
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func mmResultText(code uint32) string {
	switch code {
	case mmSysErrNoError:
		return "No error"
	case mmSysErrError:
		return "Unspecified multimedia error"
	case mmSysErrBadDeviceID:
		return "Invalid multimedia device ID"
	case mmSysErrInvalHandle:
		return "Invalid multimedia device handle"
	case mmSysErrNoDriver:
		return "No audio driver available"
	case mmSysErrNoMem:
		return "Not enough memory"
	case mmSysErrNotSupported:
		return "Function not supported"
	case mmSysErrInvalParam:
		return "Invalid parameter"
	case wavErrBadFormat:
		return "Unsupported waveform-audio format"
	default:
		return fmt.Sprintf("Multimedia error %d", code)
	}
}

func readWaveHeader(mem *mmu.MMU, addr uint64) (waveHeader, error) {
	if addr == 0 {
		return waveHeader{}, fmt.Errorf("nil WAVEHDR")
	}
	dataPtr, err := mem.Read64(addr)
	if err != nil {
		return waveHeader{}, err
	}
	bufferLen, err := mem.Read32(addr + 8)
	if err != nil {
		return waveHeader{}, err
	}
	bytesRecorded, err := mem.Read32(addr + 12)
	if err != nil {
		return waveHeader{}, err
	}
	flags, err := mem.Read32(addr + 24)
	if err != nil {
		return waveHeader{}, err
	}
	loops, err := mem.Read32(addr + 28)
	if err != nil {
		return waveHeader{}, err
	}
	next, _ := mem.Read64(addr + 32)
	reserved, _ := mem.Read64(addr + 40)
	return waveHeader{
		dataPtr:        dataPtr,
		bufferLen:      bufferLen,
		bytesRecorded:  bytesRecorded,
		flags:          flags,
		loops:          loops,
		next:           next,
		reserved:       reserved,
		guestHeaderPtr: addr,
	}, nil
}

func writeWaveHeader(mem *mmu.MMU, hdr waveHeader) {
	mem.Write64(hdr.guestHeaderPtr, hdr.dataPtr)
	mem.Write32(hdr.guestHeaderPtr+8, hdr.bufferLen)
	mem.Write32(hdr.guestHeaderPtr+12, hdr.bytesRecorded)
	mem.Write32(hdr.guestHeaderPtr+24, hdr.flags)
	mem.Write32(hdr.guestHeaderPtr+28, hdr.loops)
	mem.Write64(hdr.guestHeaderPtr+32, hdr.next)
	mem.Write64(hdr.guestHeaderPtr+40, hdr.reserved)
}

func writeMMTime(mem *mmu.MMU, addr uint64, typ uint32, value uint32) {
	if addr == 0 {
		return
	}
	mem.Write32(addr, typ)
	mem.Write32(addr+4, value)
	mem.Write32(addr+8, 0)
}

func writeTimeCaps(mem *mmu.MMU, addr uint64, cb uint32) {
	if addr == 0 || cb < 4 {
		return
	}
	mem.Write16(addr, 1)
	mem.Write16(addr+2, 0)
	if cb >= 8 {
		mem.Write16(addr+2, 0)
		mem.Write32(addr+4, 1000000)
	}
}

func writeWaveOutCapsW(mem *mmu.MMU, addr uint64, cb uint32) {
	if addr == 0 || cb == 0 {
		return
	}
	buf := make([]byte, 84)
	binary.LittleEndian.PutUint16(buf[0:], 1)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], 0x00010000)
	name := utf16Encode("Raven Audio")
	for i, w := range name {
		if 8+i*2+1 >= len(buf) || i >= 31 {
			break
		}
		binary.LittleEndian.PutUint16(buf[8+i*2:], w)
	}
	binary.LittleEndian.PutUint32(buf[72:], waveFormat1M16|waveFormat1S16|waveFormat2M16|waveFormat2S16|waveFormat4M16|waveFormat4S16)
	binary.LittleEndian.PutUint16(buf[76:], 2)
	binary.LittleEndian.PutUint32(buf[80:], waveCapsVolume|waveCapsLRVolume)
	mem.WriteBytes(addr, buf[:minU32(cb, uint32(len(buf)))])
}

func writeWaveOutCapsA(mem *mmu.MMU, addr uint64, cb uint32) {
	if addr == 0 || cb == 0 {
		return
	}
	buf := make([]byte, 52)
	binary.LittleEndian.PutUint16(buf[0:], 1)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], 0x00010000)
	copy(buf[8:40], []byte("Raven Audio"))
	binary.LittleEndian.PutUint32(buf[40:], waveFormat1M16|waveFormat1S16|waveFormat2M16|waveFormat2S16|waveFormat4M16|waveFormat4S16)
	binary.LittleEndian.PutUint16(buf[44:], 2)
	binary.LittleEndian.PutUint32(buf[48:], waveCapsVolume|waveCapsLRVolume)
	mem.WriteBytes(addr, buf[:minU32(cb, uint32(len(buf)))])
}

func ensureWinmmDirectSound(hctx *HandlerCtx) *dsoundpkg.DirectSound {
	if hctx.DirectSound == nil {
		hctx.DirectSound = dsoundpkg.NewDirectSound()
	}
	return hctx.DirectSound
}

func createWinmmSecondaryBuffer(hctx *HandlerCtx, format waveFormatEx, size uint32) *dsoundpkg.SoundBuffer {
	if size == 0 {
		size = format.AvgBytesPerSec
	}
	if size == 0 {
		size = 4096
	}
	dsFormat := toDSoundFormat(format)
	return ensureWinmmDirectSound(hctx).CreateSoundBuffer(dsoundpkg.DSBUFFERDESC{
		DwFlags:       dsoundpkg.DSBCAPS_CTRLVOLUME | dsoundpkg.DSBCAPS_GLOBALFOCUS | dsoundpkg.DSBCAPS_GETCURRENTPOSITION2,
		DwBufferBytes: size,
		LpwfxFormat:   &dsFormat,
	})
}

func writeToSoundBuffer(buffer *dsoundpkg.SoundBuffer, data []byte, offset uint32) uint32 {
	if buffer == nil || buffer.Size == 0 || len(buffer.Data) == 0 || len(data) == 0 {
		return offset
	}
	if offset >= buffer.Size {
		offset %= buffer.Size
	}
	pos := offset
	remaining := data
	for len(remaining) > 0 {
		chunk := int(buffer.Size - pos)
		if chunk > len(remaining) {
			chunk = len(remaining)
		}
		start := int(pos)
		copy(buffer.Data[start:start+chunk], remaining[:chunk])
		remaining = remaining[chunk:]
		pos = (pos + uint32(chunk)) % buffer.Size
	}
	buffer.WriteCursor = pos
	return pos
}

func waveOutDuration(format waveFormatEx, bytes uint32) time.Duration {
	if format.AvgBytesPerSec == 0 || bytes == 0 {
		return 0
	}
	return time.Duration((uint64(bytes) * uint64(time.Second)) / uint64(format.AvgBytesPerSec))
}

func waveVolumeToDS(vol uint32) int32 {
	left := vol & 0xFFFF
	right := (vol >> 16) & 0xFFFF
	level := (left + right) / 2
	if level >= 0xFFFF {
		return 0
	}
	return -10000 + int32((level*10000)/0xFFFF)
}

func dsVolumeToWave(vol int32) uint32 {
	if vol < -10000 {
		vol = -10000
	}
	if vol > 0 {
		vol = 0
	}
	level := uint32((int64(vol)+10000)*0xFFFF/10000) & 0xFFFF
	return level | (level << 16)
}

func parseWAV(data []byte) (waveFormatEx, []byte, error) {
	if len(data) < 12 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WAVE" {
		return waveFormatEx{}, nil, fmt.Errorf("invalid wav")
	}
	var format waveFormatEx
	var pcm []byte
	for off := 12; off+8 <= len(data); {
		chunkID := string(data[off : off+4])
		chunkSize := int(binary.LittleEndian.Uint32(data[off+4:]))
		off += 8
		if chunkSize < 0 || off+chunkSize > len(data) {
			return waveFormatEx{}, nil, fmt.Errorf("invalid wav chunk")
		}
		chunk := data[off : off+chunkSize]
		switch chunkID {
		case "fmt ":
			if len(chunk) < 16 {
				return waveFormatEx{}, nil, fmt.Errorf("short fmt chunk")
			}
			format = waveFormatEx{
				FormatTag:      binary.LittleEndian.Uint16(chunk[0:2]),
				Channels:       binary.LittleEndian.Uint16(chunk[2:4]),
				SamplesPerSec:  binary.LittleEndian.Uint32(chunk[4:8]),
				AvgBytesPerSec: binary.LittleEndian.Uint32(chunk[8:12]),
				BlockAlign:     binary.LittleEndian.Uint16(chunk[12:14]),
				BitsPerSample:  binary.LittleEndian.Uint16(chunk[14:16]),
			}
			if len(chunk) >= 18 {
				format.CbSize = binary.LittleEndian.Uint16(chunk[16:18])
			}
		case "data":
			pcm = append([]byte(nil), chunk...)
		}
		off += chunkSize
		if chunkSize&1 != 0 {
			off++
		}
	}
	if len(pcm) == 0 {
		return waveFormatEx{}, nil, fmt.Errorf("missing wav data")
	}
	format = normalizeWaveFormatEx(format)
	if format.FormatTag != waveFormatPCM && format.FormatTag != waveFormatIEEEFloat {
		return waveFormatEx{}, nil, fmt.Errorf("unsupported wav format")
	}
	return format, pcm, nil
}

func writeWaveInCapsW(mem *mmu.MMU, addr uint64, cb uint32) {
	if addr == 0 || cb == 0 {
		return
	}
	buf := make([]byte, 84)
	binary.LittleEndian.PutUint16(buf[0:], 1)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], 0x00010000)
	name := utf16Encode("go-vm WaveIn")
	for i, w := range name {
		if 8+i*2+1 >= len(buf) || i >= 31 {
			break
		}
		binary.LittleEndian.PutUint16(buf[8+i*2:], w)
	}
	binary.LittleEndian.PutUint32(buf[72:], 0)
	binary.LittleEndian.PutUint16(buf[76:], 2)
	binary.LittleEndian.PutUint32(buf[80:], 0)
	mem.WriteBytes(addr, buf[:minU32(cb, uint32(len(buf)))])
}

func writeWaveInCapsA(mem *mmu.MMU, addr uint64, cb uint32) {
	if addr == 0 || cb == 0 {
		return
	}
	buf := make([]byte, 52)
	binary.LittleEndian.PutUint16(buf[0:], 1)
	binary.LittleEndian.PutUint16(buf[2:], 1)
	binary.LittleEndian.PutUint32(buf[4:], 0x00010000)
	copy(buf[8:40], []byte("go-vm WaveIn"))
	binary.LittleEndian.PutUint32(buf[40:], 0)
	binary.LittleEndian.PutUint16(buf[44:], 2)
	binary.LittleEndian.PutUint32(buf[48:], 0)
	mem.WriteBytes(addr, buf[:minU32(cb, uint32(len(buf)))])
}

func paplayFormatArg(f waveFormatEx) (string, bool) {
	switch {
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 8:
		return "u8", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 16:
		return "s16le", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 24:
		return "s24le", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 32:
		return "s32le", true
	case f.FormatTag == waveFormatIEEEFloat && f.BitsPerSample == 32:
		return "float32le", true
	default:
		return "", false
	}
}

func aplayFormatArg(f waveFormatEx) (string, bool) {
	switch {
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 8:
		return "U8", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 16:
		return "S16_LE", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 24:
		return "S24_LE", true
	case f.FormatTag == waveFormatPCM && f.BitsPerSample == 32:
		return "S32_LE", true
	case f.FormatTag == waveFormatIEEEFloat && f.BitsPerSample == 32:
		return "FLOAT_LE", true
	default:
		return "", false
	}
}

func startAudioProcess(f waveFormatEx) (*exec.Cmd, io.WriteCloser, bool, error) {
	if f.Channels == 0 || f.SamplesPerSec == 0 {
		return nil, nil, true, nil
	}
	if formatArg, ok := paplayFormatArg(f); ok {
		if path, err := exec.LookPath("paplay"); err == nil {
			args := []string{
				"--raw",
				fmt.Sprintf("--rate=%d", f.SamplesPerSec),
				fmt.Sprintf("--channels=%d", f.Channels),
				fmt.Sprintf("--format=%s", formatArg),
				"-",
			}
			cmd := exec.Command(path, args...)
			pipe, err := cmd.StdinPipe()
			if err == nil && cmd.Start() == nil {
				return cmd, pipe, false, nil
			}
			if pipe != nil {
				_ = pipe.Close()
			}
		}
	}
	if formatArg, ok := aplayFormatArg(f); ok {
		if path, err := exec.LookPath("aplay"); err == nil {
			args := []string{
				"-q",
				"-t", "raw",
				"-f", formatArg,
				"-r", fmt.Sprintf("%d", f.SamplesPerSec),
				"-c", fmt.Sprintf("%d", f.Channels),
				"-",
			}
			cmd := exec.Command(path, args...)
			pipe, err := cmd.StdinPipe()
			if err == nil && cmd.Start() == nil {
				return cmd, pipe, false, nil
			}
			if pipe != nil {
				_ = pipe.Close()
			}
		}
	}
	return nil, nil, true, nil
}

func startCaptureProcess(f waveFormatEx) (*exec.Cmd, io.ReadCloser, bool, error) {
	if f.Channels == 0 || f.SamplesPerSec == 0 {
		return nil, nil, true, nil
	}
	if formatArg, ok := paplayFormatArg(f); ok {
		if path, err := exec.LookPath("parecord"); err == nil {
			args := []string{
				"--raw",
				fmt.Sprintf("--rate=%d", f.SamplesPerSec),
				fmt.Sprintf("--channels=%d", f.Channels),
				fmt.Sprintf("--format=%s", formatArg),
			}
			cmd := exec.Command(path, args...)
			pipe, err := cmd.StdoutPipe()
			if err == nil && cmd.Start() == nil {
				return cmd, pipe, false, nil
			}
			if pipe != nil {
				_ = pipe.Close()
			}
		}
	}
	if formatArg, ok := aplayFormatArg(f); ok {
		if path, err := exec.LookPath("arecord"); err == nil {
			args := []string{
				"-q",
				"-t", "raw",
				"-f", formatArg,
				"-r", fmt.Sprintf("%d", f.SamplesPerSec),
				"-c", fmt.Sprintf("%d", f.Channels),
			}
			cmd := exec.Command(path, args...)
			pipe, err := cmd.StdoutPipe()
			if err == nil && cmd.Start() == nil {
				return cmd, pipe, false, nil
			}
			if pipe != nil {
				_ = pipe.Close()
			}
		}
	}
	return nil, nil, true, nil
}

func stopCmd(cmd *exec.Cmd, closer io.Closer) {
	if closer != nil {
		_ = closer.Close()
	}
	if cmd == nil {
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

func parseMciAlias(cmd string) string {
	lower := strings.ToLower(cmd)
	if idx := strings.Index(lower, " alias "); idx >= 0 {
		return strings.TrimSpace(cmd[idx+7:])
	}
	fields := strings.Fields(cmd)
	if len(fields) >= 2 {
		return fields[1]
	}
	return ""
}

func extractFourCC(text string) uint32 {
	var b [4]byte
	copy(b[:], []byte(text))
	return binary.LittleEndian.Uint32(b[:])
}

func registerWinmmHandlers(hctx *HandlerCtx) {
	d := hctx.Disp
	dll, ok := hctx.SynthByName["winmm.dll"]
	if !ok {
		return
	}

	mem := hctx.Mem
	procState := hctx.ProcState
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestString := hctx.ReadGuestString
	guestCallTrampoline := ntapi.AllocTrampoline(mem)

	var callbackPoolMu sync.Mutex
	var freeCallbackStacks []struct {
		base uint64
		size uint64
	}
	var freeCallbackTEBs []uint64

	allocCallbackStack := func() (uint64, uint64) {
		callbackPoolMu.Lock()
		defer callbackPoolMu.Unlock()
		if n := len(freeCallbackStacks); n > 0 {
			s := freeCallbackStacks[n-1]
			freeCallbackStacks = freeCallbackStacks[:n-1]
			return s.base, s.size
		}
		size := uint64(256 * 1024)
		return mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite), size
	}

	releaseCallbackStack := func(base, size uint64) {
		if base == 0 || size == 0 {
			return
		}
		callbackPoolMu.Lock()
		freeCallbackStacks = append(freeCallbackStacks, struct {
			base uint64
			size uint64
		}{base: base, size: size})
		callbackPoolMu.Unlock()
	}

	allocCallbackTEB := func(stackBase, stackSize uint64) uint64 {
		callbackPoolMu.Lock()
		if n := len(freeCallbackTEBs); n > 0 {
			teb := freeCallbackTEBs[n-1]
			freeCallbackTEBs = freeCallbackTEBs[:n-1]
			callbackPoolMu.Unlock()
			mem.Write64(teb+ntapi.TebStackBase, stackBase+stackSize)
			mem.Write64(teb+ntapi.TebStackLimit, stackBase)
			return teb
		}
		callbackPoolMu.Unlock()
		teb := mem.Mmap(0, uint64(ntapi.TebSize), mmu.PermRead|mmu.PermWrite)
		if teb == 0 {
			return 0
		}
		tlsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebThreadLocalStorage)
		flsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
		heapBase, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
		heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
		mem.Write64(teb+ntapi.TebThreadLocalStorage, tlsPtr)
		mem.Write64(teb+ntapi.TebFlsData, flsPtr)
		mem.Write64(teb+ntapi.TebHeapBase, heapBase)
		mem.Write64(teb+ntapi.TebHeapOffset, heapOff)
		mem.Write64(teb+ntapi.TebSelf, teb)
		mem.Write64(teb+ntapi.TebPEB, procState.PEBAddr)
		mem.Write64(teb+ntapi.TebStackBase, stackBase+stackSize)
		mem.Write64(teb+ntapi.TebStackLimit, stackBase)
		mem.Write32(teb+ntapi.TebProcessId, uint32(procState.PEBAddr>>12))
		mem.Write64(teb+ntapi.TebExceptionList, 0xFFFFFFFFFFFFFFFF)
		return teb
	}

	releaseCallbackTEB := func(teb uint64) {
		if teb == 0 {
			return
		}
		callbackPoolMu.Lock()
		freeCallbackTEBs = append(freeCallbackTEBs, teb)
		callbackPoolMu.Unlock()
	}

	invokeGuestCallback := func(template arch.CPU, addr uint64, args ...uint64) {
		if addr == 0 || template == nil {
			return
		}
		go func() {
			cpu := template.CloneForThread()
			if cpu == nil {
				return
			}
			cpu.SetSyscallHandler(d.Handle)
			stackBase, stackSize := allocCallbackStack()
			if stackBase == 0 {
				return
			}
			defer releaseCallbackStack(stackBase, stackSize)
			cpu.SetSP(stackBase + stackSize - 8)
			teb := allocCallbackTEB(stackBase, stackSize)
			defer releaseCallbackTEB(teb)
			if xc, ok := cpu.(*x64.CPU); ok && teb != 0 {
				xc.SetGSBase(teb)
			}
			if _, err := ntapi.CallGuestFunction(cpu, mem, guestCallTrampoline, addr, args, false); err != nil {
				ravelog.Logf("[winmm] guest callback 0x%x failed: %v\n", addr, err)
			}
		}()
	}

	writeErrorTextA := func(ctx *ntapi.TrapContext, code uint32, buf uint64, cch uint64) {
		writeAnsiString(ctx.Mem, buf, mmResultText(code), int(cch))
	}
	writeErrorTextW := func(ctx *ntapi.TrapContext, code uint32, buf uint64, cch uint64) {
		writeWideString(ctx.Mem, buf, mmResultText(code), int(cch))
	}

	writeWaveOutDone := func(hwo uint64, dev *waveOutDevice, hdr waveHeader) {
		hdr.flags |= whdrDone
		writeWaveHeader(mem, hdr)
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, hwo, uint64(womDone), dev.instance, hdr.guestHeaderPtr, 0)
		}
	}

	advanceWaveOutLocked := func(hwo uint64, dev *waveOutDevice) {
		if dev == nil || dev.paused || !dev.playing || dev.lastTick.IsZero() || dev.format.AvgBytesPerSec == 0 {
			return
		}
		elapsed := time.Since(dev.lastTick)
		if elapsed <= 0 {
			return
		}
		advance := (uint64(elapsed) * uint64(dev.format.AvgBytesPerSec)) / uint64(time.Second)
		if advance == 0 {
			return
		}
		if advance > dev.queuedBytes {
			advance = dev.queuedBytes
		}
		consumed := advance
		dev.queuedBytes -= advance
		dev.position += advance
		if dev.buffer != nil && dev.buffer.Size != 0 {
			dev.buffer.PlayCursor = uint32(dev.position % uint64(dev.buffer.Size))
		}
		for advance > 0 && len(dev.buffers) > 0 {
			buf := &dev.buffers[0]
			if advance >= uint64(buf.remaining) {
				advance -= uint64(buf.remaining)
				buf.remaining = 0
				writeWaveOutDone(hwo, dev, buf.header)
				dev.buffers = dev.buffers[1:]
				continue
			}
			buf.remaining -= uint32(advance)
			advance = 0
		}
		consumedDur := time.Duration((consumed * uint64(time.Second)) / uint64(dev.format.AvgBytesPerSec))
		if consumedDur <= 0 {
			consumedDur = time.Nanosecond
		}
		dev.lastTick = dev.lastTick.Add(consumedDur)
		if dev.queuedBytes == 0 {
			dev.playing = false
			dev.lastTick = time.Time{}
			if dev.buffer != nil {
				dev.buffer.Stop()
			}
		}
	}

	signalWaveOut := func(dev *waveOutDevice) {
		if dev == nil || dev.notify == nil {
			return
		}
		select {
		case dev.notify <- struct{}{}:
		default:
		}
	}

	startWaveOutWorker := func(hwo uint64, dev *waveOutDevice) {
		go func() {
			var timer *time.Timer
			stopTimer := func() {
				if timer == nil {
					return
				}
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			for {
				dev.mu.Lock()
				if dev.closed {
					dev.mu.Unlock()
					stopTimer()
					return
				}
				advanceWaveOutLocked(hwo, dev)
				wait := time.Duration(0)
				if !dev.paused && dev.playing && len(dev.buffers) > 0 {
					wait = waveOutDuration(dev.format, dev.buffers[0].remaining)
					if wait <= 0 {
						wait = time.Millisecond
					}
				}
				dev.mu.Unlock()
				if wait == 0 {
					stopTimer()
					select {
					case <-dev.notify:
					case <-dev.stop:
						return
					}
					continue
				}
				if timer == nil {
					timer = time.NewTimer(wait)
				} else {
					stopTimer()
					timer.Reset(wait)
				}
				select {
				case <-timer.C:
				case <-dev.notify:
				case <-dev.stop:
					stopTimer()
					return
				}
			}
		}()
	}

	dispatchWaveInBuffer := func(hwi uint64, dev *waveInDevice, hdr waveHeader) {
		go func() {
			data := make([]byte, hdr.bufferLen)
			n := 0
			if !dev.silent && dev.pipe != nil && hdr.bufferLen > 0 {
				dev.readMu.Lock()
				n, _ = io.ReadFull(dev.pipe, data)
				dev.readMu.Unlock()
			}
			if n < 0 {
				n = 0
			}
			if hdr.dataPtr != 0 && len(data) > 0 {
				mem.WriteBytes(hdr.dataPtr, data)
			}
			dev.mu.Lock()
			hdr.bytesRecorded = uint32(n)
			hdr.flags |= whdrDone
			dev.position += uint64(n)
			writeWaveHeader(mem, hdr)
			if dev.flags&callbackFunction == callbackFunction {
				invokeGuestCallback(dev.callbackCPU, dev.callback, hwi, uint64(wimData), dev.instance, hdr.guestHeaderPtr, 0)
			}
			dev.mu.Unlock()
		}()
	}

	restartWaveIn := func(dev *waveInDevice) {
		stopCmd(dev.cmd, dev.pipe)
		dev.cmd = nil
		dev.pipe = nil
		cmd, pipe, silent, _ := startCaptureProcess(dev.format)
		dev.cmd = cmd
		dev.pipe = pipe
		dev.silent = silent
	}

	mciMu := sync.Mutex{}
	nextMciID := uint32(1)
	mciAliases := map[string]uint32{}
	mciStates := map[uint32]string{}

	timerMu := sync.Mutex{}
	nextTimerID := uint32(1)
	timerResolution := uint32(1)
	timerEvents := map[uint32]*mmTimerEvent{}

	winmmHandleMu := sync.Mutex{}
	nextWaveOutHandle := uint64(0x100000)
	nextWaveInHandle := uint64(0x200000)
	nextMMIOHandle := uint64(0x300000)
	waveOutDevices := map[uint64]*waveOutDevice{}
	waveInDevices := map[uint64]*waveInDevice{}
	mmioHandles := map[uint64]*mmioHandle{}

	allocWaveOutHandle := func(dev *waveOutDevice) uint64 {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		h := nextWaveOutHandle
		nextWaveOutHandle += 4
		waveOutDevices[h] = dev
		return h
	}
	getWaveOutHandle := func(h uint64) *waveOutDevice {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		return waveOutDevices[h]
	}
	closeWaveOutHandle := func(h uint64) {
		winmmHandleMu.Lock()
		delete(waveOutDevices, h)
		winmmHandleMu.Unlock()
	}
	allocWaveInHandle := func(dev *waveInDevice) uint64 {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		h := nextWaveInHandle
		nextWaveInHandle += 4
		waveInDevices[h] = dev
		return h
	}
	getWaveInHandle := func(h uint64) *waveInDevice {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		return waveInDevices[h]
	}
	closeWaveInHandle := func(h uint64) {
		winmmHandleMu.Lock()
		delete(waveInDevices, h)
		winmmHandleMu.Unlock()
	}
	allocMMIOHandle := func(obj *mmioHandle) uint64 {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		h := nextMMIOHandle
		nextMMIOHandle += 4
		mmioHandles[h] = obj
		return h
	}
	getMMIOHandle := func(h uint64) *mmioHandle {
		winmmHandleMu.Lock()
		defer winmmHandleMu.Unlock()
		return mmioHandles[h]
	}
	closeMMIOHandle := func(h uint64) {
		winmmHandleMu.Lock()
		delete(mmioHandles, h)
		winmmHandleMu.Unlock()
	}

	readAllVFS := func(fs *vfs.VFS, path string) ([]byte, error) {
		fd, err := fs.Open(path, vfs.O_RDONLY)
		if err != nil {
			return nil, err
		}
		defer fs.Close(fd)
		data := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := fs.Read(fd, buf)
			if n > 0 {
				data = append(data, buf[:n]...)
			}
			if err != nil || n == 0 {
				break
			}
		}
		return data, nil
	}

	resolvePlaySoundModule := func(hModule uint64) (uint64, uint32) {
		if hctx.MainModule == nil {
			return 0, 0
		}
		if hModule == 0 || hModule == hctx.MainModule.BaseAddr {
			return hctx.MainModule.BaseAddr, hctx.MainModule.ResourceDirRVA
		}
		return 0, 0
	}

	matchResourceEntry := func(dirAddr, rsrcBase uint64, wantString bool, wantName string, wantID uint32) (uint32, bool) {
		if dirAddr == 0 {
			return 0, false
		}
		namedCount, _ := mem.Read16(dirAddr + 12)
		idCount, _ := mem.Read16(dirAddr + 14)
		entryBase := dirAddr + 16
		total := uint64(namedCount) + uint64(idCount)
		wantUTF16 := utf16Encode(wantName)
		for i := uint64(0); i < total; i++ {
			nameRaw, _ := mem.Read32(entryBase + i*8)
			off, _ := mem.Read32(entryBase + i*8 + 4)
			if wantString {
				if nameRaw&0x80000000 == 0 {
					continue
				}
				nameAddr := rsrcBase + uint64(nameRaw&0x7FFFFFFF)
				nameLen, _ := mem.Read16(nameAddr)
				if int(nameLen) != len(wantUTF16) {
					continue
				}
				matched := true
				for j, wantRune := range wantUTF16 {
					got, _ := mem.Read16(nameAddr + 2 + uint64(j*2))
					if got != wantRune {
						matched = false
						break
					}
				}
				if matched {
					return off, true
				}
				continue
			}
			if nameRaw == wantID {
				return off, true
			}
		}
		return 0, false
	}

	firstResourceEntry := func(dirAddr uint64) (uint32, bool) {
		if dirAddr == 0 {
			return 0, false
		}
		namedCount, _ := mem.Read16(dirAddr + 12)
		idCount, _ := mem.Read16(dirAddr + 14)
		if namedCount == 0 && idCount == 0 {
			return 0, false
		}
		off, _ := mem.Read32(dirAddr + 20)
		return off, true
	}

	loadPlaySoundResource := func(hModule, namePtr uint64, wide bool) ([]byte, error) {
		baseAddr, rsrcRVA := resolvePlaySoundModule(hModule)
		if baseAddr == 0 || rsrcRVA == 0 {
			return nil, fmt.Errorf("resource module unavailable")
		}
		if namePtr <= 0xFFFF && hctx.PeLoadRawResource != nil {
			if dataAddr, dataSize, ok := hctx.PeLoadRawResource(baseAddr, rsrcRVA, 10, uint32(namePtr)); ok && dataAddr != 0 {
				return mem.ReadBytes(dataAddr, int(dataSize))
			}
		}
		rsrcBase := baseAddr + uint64(rsrcRVA)
		typeOff, ok := matchResourceEntry(rsrcBase, rsrcBase, true, "WAVE", 0)
		if !ok || typeOff&0x80000000 == 0 {
			return nil, fmt.Errorf("wave resource type not found")
		}
		typeDir := rsrcBase + uint64(typeOff&0x7FFFFFFF)
		wantString := namePtr > 0xFFFF
		wantName := ""
		if wantString {
			if wide {
				wantName = readGuestUTF16(namePtr)
			} else {
				wantName = readGuestString(namePtr)
			}
		}
		nameOff, ok := matchResourceEntry(typeDir, rsrcBase, wantString, wantName, uint32(namePtr))
		if !ok || nameOff&0x80000000 == 0 {
			return nil, fmt.Errorf("wave resource not found")
		}
		langDir := rsrcBase + uint64(nameOff&0x7FFFFFFF)
		dataOff, ok := firstResourceEntry(langDir)
		if !ok || dataOff&0x80000000 != 0 {
			return nil, fmt.Errorf("wave resource language missing")
		}
		dataEntry := rsrcBase + uint64(dataOff)
		dataRVA, _ := mem.Read32(dataEntry)
		dataSize, _ := mem.Read32(dataEntry + 4)
		if dataRVA == 0 || dataSize == 0 {
			return nil, fmt.Errorf("wave resource empty")
		}
		return mem.ReadBytes(baseAddr+uint64(dataRVA), int(dataSize))
	}

	playSoundMu := sync.Mutex{}
	var activePlaySound *playSoundPlayback

	stopPlaySound := func(playback *playSoundPlayback) {
		if playback == nil {
			return
		}
		playback.stopOnce.Do(func() {
			close(playback.stop)
		})
	}

	playSoundData := func(format waveFormatEx, pcm []byte, flags uint32) *playSoundPlayback {
		buffer := createWinmmSecondaryBuffer(hctx, format, uint32(len(pcm)))
		if buffer != nil {
			buffer.SetFormat(toDSoundFormat(format))
			buffer.Data = make([]byte, len(pcm))
			copy(buffer.Data, pcm)
			buffer.Size = uint32(len(pcm))
			buffer.WriteCursor = uint32(len(pcm))
			buffer.SetCurrentPosition(0)
		}
		playback := &playSoundPlayback{
			buffer: buffer,
			stop:   make(chan struct{}),
			done:   make(chan struct{}),
		}
		go func() {
			defer close(playback.done)
			if playback.buffer != nil {
				playFlags := uint32(0)
				if flags&sndLoop != 0 {
					playFlags = dsoundpkg.DSBPLAY_LOOPING
				}
				playback.buffer.Play(0, 0, playFlags)
			}
			if flags&sndLoop != 0 {
				<-playback.stop
			} else {
				wait := waveOutDuration(format, uint32(len(pcm)))
				if wait <= 0 {
					wait = time.Millisecond
				}
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-playback.stop:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
				}
			}
			if playback.buffer != nil {
				playback.buffer.Stop()
				ensureWinmmDirectSound(hctx).ReleaseSoundBuffer(playback.buffer)
			}
			playSoundMu.Lock()
			if activePlaySound == playback {
				activePlaySound = nil
			}
			playSoundMu.Unlock()
		}()
		return playback
	}

	handlePlaySound := func(ctx *ntapi.TrapContext, wide bool, hmodArgIndex, flagsArgIndex int) uint64 {
		flags := uint32(ctx.Arg(flagsArgIndex))
		hmod := uint64(0)
		if hmodArgIndex >= 0 {
			hmod = ctx.Arg(hmodArgIndex)
		}
		if ctx.Arg(0) == 0 {
			playSoundMu.Lock()
			cur := activePlaySound
			activePlaySound = nil
			playSoundMu.Unlock()
			stopPlaySound(cur)
			return 1
		}
		if flags&sndAlias != 0 {
			return 0
		}
		var raw []byte
		var err error
		switch {
		case flags&sndFilename != 0:
			name := readGuestString(ctx.Arg(0))
			if wide {
				name = readGuestUTF16(ctx.Arg(0))
			}
			raw, err = readAllVFS(ctx.FS, winPathToVFS(name))
		case flags&sndResource == sndResource:
			raw, err = loadPlaySoundResource(hmod, ctx.Arg(0), wide)
		case flags&sndMemory != 0:
			return 0
		default:
			name := readGuestString(ctx.Arg(0))
			if wide {
				name = readGuestUTF16(ctx.Arg(0))
			}
			raw, err = readAllVFS(ctx.FS, winPathToVFS(name))
		}
		if err != nil || len(raw) == 0 {
			if flags&sndNoDefault != 0 {
				return 0
			}
			return 0
		}
		format, pcm, err := parseWAV(raw)
		if err != nil {
			return 0
		}
		playSoundMu.Lock()
		if activePlaySound != nil && flags&sndNoStop != 0 {
			playSoundMu.Unlock()
			return 0
		}
		prev := activePlaySound
		activePlaySound = nil
		playSoundMu.Unlock()
		stopPlaySound(prev)
		playback := playSoundData(format, pcm, flags)
		playSoundMu.Lock()
		activePlaySound = playback
		playSoundMu.Unlock()
		if flags&sndAsync == 0 && flags&sndLoop == 0 {
			<-playback.done
		}
		return 1
	}

	registerFixed := func(name string, ret uint64) {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(ret)
			return 0
		})
	}

	registerFixed("CloseDriver", 1)
	registerFixed("DefDriverProc", 0)
	registerFixed("DriverCallback", 0)
	registerFixed("DrvClose", 0)
	registerFixed("DrvDefDriverProc", 0)
	registerFixed("DrvGetModuleHandle", 0)
	registerFixed("DrvOpen", 0)
	registerFixed("DrvOpenA", 0)
	registerFixed("DrvSendMessage", 0)
	registerFixed("GetDriverFlags", 0)
	registerFixed("GetDriverModuleHandle", 0)
	registerFixed("OpenDriver", 0)
	registerFixed("OpenDriverA", 0)
	registerFixed("SendDriverMessage", 0)
	registerFixed("mmsystemGetVersion", 0x0500)
	registerFixed("-stub", 0)

	d.RegisterAutoStubHandler(dll, "PlaySoundA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySoundA\n")
		ctx.SetReturn(handlePlaySound(ctx, false, 1, 2))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PlaySoundW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySoundW\n")
		ctx.SetReturn(handlePlaySound(ctx, true, 1, 2))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "PlaySound", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] PlaySound\n")
		ctx.SetReturn(handlePlaySound(ctx, false, 1, 2))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "sndPlaySoundA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] sndPlaySoundA\n")
		ctx.SetReturn(handlePlaySound(ctx, false, -1, 1))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "sndPlaySoundW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] sndPlaySoundW\n")
		ctx.SetReturn(handlePlaySound(ctx, true, -1, 1))
		return 0
	})

	registerFixed("auxGetNumDevs", 0)
	registerFixed("auxGetVolume", 0)
	registerFixed("auxOutMessage", 0)
	registerFixed("auxSetVolume", 0)
	for _, name := range []string{"auxGetDevCapsA", "auxGetDevCapsW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		})
	}

	registerFixed("joyConfigChanged", joyErrParms)
	registerFixed("joyGetNumDevs", 0)
	registerFixed("joyGetPos", joyErrParms)
	registerFixed("joyGetPosEx", joyErrParms)
	registerFixed("joyGetThreshold", joyErrParms)
	registerFixed("joyReleaseCapture", joyErrParms)
	registerFixed("joySetCapture", joyErrParms)
	registerFixed("joySetThreshold", joyErrParms)
	for _, name := range []string{"joyGetDevCapsA", "joyGetDevCapsW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(joyErrParms)
			return 0
		})
	}

	for _, name := range []string{
		"mixerClose", "mixerGetControlDetailsA", "mixerGetControlDetailsW", "mixerGetID",
		"mixerGetLineControlsA", "mixerGetLineControlsW", "mixerGetLineInfoA", "mixerGetLineInfoW",
		"mixerMessage", "mixerOpen", "mixerSetControlDetails", "mmGetCurrentTask", "mmTaskBlock",
		"mmTaskCreate", "mmTaskSignal", "mmTaskYield", "mmioAdvance", "mmioAscend", "mmioCreateChunk",
		"mmioDescend", "mmioFlush", "mmioGetInfo", "mmioInstallIOProcA", "mmioInstallIOProcW",
		"mmioRenameA", "mmioRenameW", "mmioSendMessage", "mmioSetBuffer", "mmioSetInfo",
		"mciDriverNotify", "mciDriverYield", "mciExecute", "mciFreeCommandResource", "mciGetCreatorTask",
		"mciGetDriverData", "mciGetYieldProc", "mciLoadCommandResource", "mciSetDriverData", "mciSetYieldProc",
		"midiConnect", "midiDisconnect", "midiInMessage", "midiOutCacheDrumPatches", "midiOutCachePatches",
		"midiOutClose", "midiOutLongMsg", "midiOutMessage", "midiOutPrepareHeader", "midiOutReset",
		"midiOutShortMsg", "midiOutUnprepareHeader", "midiStreamClose", "midiStreamOpen", "midiStreamOut",
		"midiStreamPause", "midiStreamPosition", "midiStreamProperty", "midiStreamRestart", "midiStreamStop",
		"waveOutBreakLoop", "waveOutMessage", "waveInMessage",
	} {
		registerFixed(name, 0)
	}
	registerFixed("mixerGetNumDevs", 0)
	for _, name := range []string{"mixerGetDevCapsA", "mixerGetDevCapsW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		})
	}

	for _, name := range []string{"midiOutGetNumDevs", "midiInGetNumDevs"} {
		registerFixed(name, 0)
	}

	for _, name := range []string{"midiOutOpen", "midiInOpen"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			if ctx.Arg(0) != 0 {
				ctx.Mem.Write64(ctx.Arg(0), 0)
			}
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		})
	}
	for _, name := range []string{"midiOutGetDevCapsA", "midiOutGetDevCapsW", "midiInGetDevCapsA", "midiInGetDevCapsW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		})
	}
	for _, name := range []string{"midiOutGetErrorTextA", "midiInGetErrorTextA"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			writeErrorTextA(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	for _, name := range []string{"midiOutGetErrorTextW", "midiInGetErrorTextW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			writeErrorTextW(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	registerFixed("midiOutGetID", mmSysErrBadDeviceID)
	registerFixed("midiInGetID", mmSysErrBadDeviceID)
	registerFixed("midiOutGetVolume", mmSysErrBadDeviceID)
	registerFixed("midiOutSetVolume", mmSysErrBadDeviceID)

	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDA\n")
		alias := strings.ToLower(strings.TrimSpace(readGuestString(ctx.Arg(0))))
		mciMu.Lock()
		id := mciAliases[alias]
		if id == 0 {
			id = 1
		}
		mciMu.Unlock()
		ctx.SetReturn(uint64(id))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetDeviceIDW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetDeviceIDW\n")
		alias := strings.ToLower(strings.TrimSpace(readGuestUTF16(ctx.Arg(0))))
		mciMu.Lock()
		id := mciAliases[alias]
		if id == 0 {
			id = 1
		}
		mciMu.Unlock()
		ctx.SetReturn(uint64(id))
		return 0
	})
	for _, name := range []string{"mciGetDeviceIDFromElementIDA", "mciGetDeviceIDFromElementIDW"} {
		registerFixed(name, 1)
	}
	d.RegisterAutoStubHandler(dll, "mciGetErrorStringA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetErrorStringA\n")
		writeAnsiString(ctx.Mem, ctx.Arg(1), mmResultText(uint32(ctx.Arg(0))), int(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciGetErrorStringW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciGetErrorStringW\n")
		writeWideString(ctx.Mem, ctx.Arg(1), mmResultText(uint32(ctx.Arg(0))), int(ctx.Arg(2)))
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{"mciSendCommandA", "mciSendCommandW"} {
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			ctx.SetReturn(0)
			return 0
		})
	}
	d.RegisterAutoStubHandler(dll, "mciSendStringA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendStringA\n")
		cmd := strings.TrimSpace(readGuestString(ctx.Arg(0)))
		lower := strings.ToLower(cmd)
		mciMu.Lock()
		switch {
		case strings.HasPrefix(lower, "open "):
			alias := strings.ToLower(parseMciAlias(cmd))
			if alias == "" {
				alias = fmt.Sprintf("mci%d", nextMciID)
			}
			id := nextMciID
			nextMciID++
			mciAliases[alias] = id
			mciStates[id] = "stopped"
		case strings.HasPrefix(lower, "close all"):
			mciAliases = map[string]uint32{}
			mciStates = map[uint32]string{}
		case strings.HasPrefix(lower, "close "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("close "):]))
			delete(mciStates, mciAliases[alias])
			delete(mciAliases, alias)
		case strings.HasPrefix(lower, "play "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("play "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "playing"
			}
		case strings.HasPrefix(lower, "stop "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("stop "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "stopped"
			}
		case strings.HasPrefix(lower, "pause "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("pause "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "paused"
			}
		case strings.HasPrefix(lower, "status "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("status "):]))
			state := "stopped"
			if id := mciAliases[alias]; id != 0 && mciStates[id] != "" {
				state = mciStates[id]
			}
			writeAnsiString(ctx.Mem, ctx.Arg(1), state, int(ctx.Arg(2)))
		}
		mciMu.Unlock()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mciSendStringW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mciSendStringW\n")
		cmd := strings.TrimSpace(readGuestUTF16(ctx.Arg(0)))
		lower := strings.ToLower(cmd)
		mciMu.Lock()
		switch {
		case strings.HasPrefix(lower, "open "):
			alias := strings.ToLower(parseMciAlias(cmd))
			if alias == "" {
				alias = fmt.Sprintf("mci%d", nextMciID)
			}
			id := nextMciID
			nextMciID++
			mciAliases[alias] = id
			mciStates[id] = "stopped"
		case strings.HasPrefix(lower, "close all"):
			mciAliases = map[string]uint32{}
			mciStates = map[uint32]string{}
		case strings.HasPrefix(lower, "close "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("close "):]))
			delete(mciStates, mciAliases[alias])
			delete(mciAliases, alias)
		case strings.HasPrefix(lower, "play "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("play "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "playing"
			}
		case strings.HasPrefix(lower, "stop "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("stop "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "stopped"
			}
		case strings.HasPrefix(lower, "pause "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("pause "):]))
			if id := mciAliases[alias]; id != 0 {
				mciStates[id] = "paused"
			}
		case strings.HasPrefix(lower, "status "):
			alias := strings.ToLower(strings.TrimSpace(cmd[len("status "):]))
			state := "stopped"
			if id := mciAliases[alias]; id != 0 && mciStates[id] != "" {
				state = mciStates[id]
			}
			writeWideString(ctx.Mem, ctx.Arg(1), state, int(ctx.Arg(2)))
		}
		mciMu.Unlock()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "mmioOpenA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioOpenA\n")
		name := readGuestString(ctx.Arg(0))
		openFlags := uint32(ctx.Arg(2))
		flags := vfs.O_RDONLY
		if openFlags&mmioReadWriteFlag != 0 || openFlags&mmioWriteFlag != 0 {
			flags = vfs.O_RDWR
		}
		if openFlags&mmioCreateFlag != 0 {
			flags |= vfs.O_CREAT
		}
		fd, err := ctx.FS.Open(winPathToVFS(name), flags)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		h := allocMMIOHandle(&mmioHandle{fd: fd, path: name})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioOpenW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioOpenW\n")
		name := readGuestUTF16(ctx.Arg(0))
		openFlags := uint32(ctx.Arg(2))
		flags := vfs.O_RDONLY
		if openFlags&mmioReadWriteFlag != 0 || openFlags&mmioWriteFlag != 0 {
			flags = vfs.O_RDWR
		}
		if openFlags&mmioCreateFlag != 0 {
			flags |= vfs.O_CREAT
		}
		fd, err := ctx.FS.Open(winPathToVFS(name), flags)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		h := allocMMIOHandle(&mmioHandle{fd: fd, path: name})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioClose\n")
		h := ctx.Arg(0)
		obj := getMMIOHandle(h)
		if obj == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		_ = ctx.FS.Close(obj.fd)
		closeMMIOHandle(h)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioRead", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioRead\n")
		obj := getMMIOHandle(ctx.Arg(0))
		if obj == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		count := int(ctx.Arg(2))
		if count < 0 {
			count = 0
		}
		buf := make([]byte, count)
		n, _ := ctx.FS.Read(obj.fd, buf)
		if n > 0 && ctx.Arg(1) != 0 {
			ctx.Mem.WriteBytes(ctx.Arg(1), buf[:n])
		}
		ctx.SetReturn(uint64(int32(n)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioWrite", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioWrite\n")
		obj := getMMIOHandle(ctx.Arg(0))
		if obj == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		count := int(ctx.Arg(2))
		if count < 0 {
			count = 0
		}
		data, _ := ctx.Mem.ReadBytes(ctx.Arg(1), count)
		n, _ := ctx.FS.Write(obj.fd, data)
		ctx.SetReturn(uint64(int32(n)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioSeek", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioSeek\n")
		obj := getMMIOHandle(ctx.Arg(0))
		if obj == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		pos, err := ctx.FS.Lseek(obj.fd, int64(int32(ctx.Arg(1))), int(ctx.Arg(2)))
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(uint64(int32(pos)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioStringToFOURCCA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioStringToFOURCCA\n")
		ctx.SetReturn(uint64(extractFourCC(readGuestString(ctx.Arg(0)))))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "mmioStringToFOURCCW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] mmioStringToFOURCCW\n")
		ctx.SetReturn(uint64(extractFourCC(readGuestUTF16(ctx.Arg(0)))))
		return 0
	})

	d.RegisterAutoStubHandler(dll, "timeBeginPeriod", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeBeginPeriod\n")
		period := uint32(ctx.Arg(0))
		if period == 0 {
			ctx.SetReturn(timErrNoCanDo)
			return 0
		}
		timerMu.Lock()
		if period < timerResolution || timerResolution == 0 {
			timerResolution = period
		}
		timerMu.Unlock()
		ctx.SetReturn(timErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeEndPeriod", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeEndPeriod\n")
		timerMu.Lock()
		timerResolution = 1
		timerMu.Unlock()
		ctx.SetReturn(timErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetDevCaps", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeGetDevCaps\n")
		writeTimeCaps(ctx.Mem, ctx.Arg(0), uint32(ctx.Arg(1)))
		ctx.SetReturn(timErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeGetSystemTime\n")
		elapsed := uint32(time.Since(hctx.StartTime) / time.Millisecond)
		writeMMTime(ctx.Mem, ctx.Arg(0), mmTimeMS, elapsed)
		ctx.SetReturn(timErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeGetTime", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(uint32(time.Since(hctx.StartTime) / time.Millisecond)))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeSetEvent", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeSetEvent\n")
		delay := uint32(ctx.Arg(0))
		resolution := uint32(ctx.Arg(1))
		callback := ctx.Arg(2)
		user := ctx.Arg(3)
		flags := uint32(ctx.Arg(4))
		if delay == 0 {
			delay = 1
		}
		timerMu.Lock()
		id := nextTimerID
		nextTimerID++
		evt := &mmTimerEvent{
			id:          id,
			delay:       delay,
			resolution:  resolution,
			callback:    callback,
			user:        user,
			flags:       flags,
			stop:        make(chan struct{}),
			callbackCPU: ctx.CPU.CloneForThread(),
		}
		timerEvents[id] = evt
		timerMu.Unlock()
		go func(ev *mmTimerEvent) {
			if ev.flags&timePeriodic != 0 {
				ticker := time.NewTicker(time.Duration(ev.delay) * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ev.stop:
						return
					case <-ticker.C:
						if ev.callback != 0 {
							invokeGuestCallback(ev.callbackCPU, ev.callback, uint64(ev.id), 0, ev.user, 0, 0)
						}
					}
				}
			}
			timer := time.NewTimer(time.Duration(ev.delay) * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ev.stop:
				return
			case <-timer.C:
				if ev.callback != 0 {
					invokeGuestCallback(ev.callbackCPU, ev.callback, uint64(ev.id), 0, ev.user, 0, 0)
				}
				timerMu.Lock()
				delete(timerEvents, ev.id)
				timerMu.Unlock()
			}
		}(evt)
		ctx.SetReturn(uint64(id))
		return 0
	})
	d.RegisterAutoStubHandler(dll, "timeKillEvent", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] timeKillEvent\n")
		id := uint32(ctx.Arg(0))
		timerMu.Lock()
		evt := timerEvents[id]
		delete(timerEvents, id)
		timerMu.Unlock()
		if evt != nil {
			close(evt.stop)
		}
		ctx.SetReturn(timErrNoError)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "waveOutGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetNumDevs\n")
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{"waveOutGetDevCapsA", "waveOutGetDevCapsW"} {
		isWide := strings.HasSuffix(name, "W")
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			deviceID := uint32(ctx.Arg(0))
			if deviceID != 0 && deviceID != waveMapper {
				ctx.SetReturn(mmSysErrBadDeviceID)
				return 0
			}
			if isWide {
				writeWaveOutCapsW(ctx.Mem, ctx.Arg(1), uint32(ctx.Arg(2)))
			} else {
				writeWaveOutCapsA(ctx.Mem, ctx.Arg(1), uint32(ctx.Arg(2)))
			}
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	for _, name := range []string{"waveOutGetErrorTextA", "waveOutGetErrorTextW"} {
		isWide := strings.HasSuffix(name, "W")
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			if isWide {
				writeErrorTextW(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			} else {
				writeErrorTextA(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			}
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	d.RegisterAutoStubHandler(dll, "waveOutOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutOpen\n")
		phwo := ctx.Arg(0)
		deviceID := uint32(ctx.Arg(1))
		pwfx := ctx.Arg(2)
		if phwo == 0 || pwfx == 0 {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		if deviceID != 0 && deviceID != waveMapper {
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		}
		format := readWaveFormatEx(ctx.Mem, pwfx)
		if format.Channels == 0 || format.SamplesPerSec == 0 || format.BitsPerSample == 0 {
			ctx.SetReturn(wavErrBadFormat)
			return 0
		}
		if format.FormatTag != waveFormatPCM && format.FormatTag != waveFormatIEEEFloat {
			ctx.SetReturn(wavErrBadFormat)
			return 0
		}
		buffer := createWinmmSecondaryBuffer(hctx, format, format.AvgBytesPerSec)
		if buffer == nil {
			ctx.SetReturn(mmSysErrNoMem)
			return 0
		}
		dev := &waveOutDevice{
			format:       format,
			device:       ensureWinmmDirectSound(hctx),
			buffer:       buffer,
			callback:     ctx.Arg(3),
			instance:     ctx.Arg(4),
			flags:        uint32(ctx.Arg(5)),
			volume:       0xFFFFFFFF,
			pitch:        0x10000,
			playbackRate: 0x10000,
			notify:       make(chan struct{}, 1),
			stop:         make(chan struct{}),
			callbackCPU:  ctx.CPU.CloneForThread(),
		}
		dev.buffer.SetVolume(waveVolumeToDS(dev.volume))
		h := allocWaveOutHandle(dev)
		startWaveOutWorker(h, dev)
		ctx.Mem.Write64(phwo, h)
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, h, uint64(womOpen), dev.instance, 0, 0)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutClose\n")
		h := ctx.Arg(0)
		dev := getWaveOutHandle(h)
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.closed = true
		dev.playing = false
		dev.paused = false
		dev.queuedBytes = 0
		dev.buffers = nil
		if dev.buffer != nil {
			dev.buffer.Stop()
			dev.buffer.SetCurrentPosition(0)
			dev.buffer.PlayCursor = 0
			dev.buffer.WriteCursor = 0
		}
		close(dev.stop)
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, h, uint64(womClose), dev.instance, 0, 0)
		}
		dev.mu.Unlock()
		if dev.device != nil && dev.buffer != nil {
			dev.device.ReleaseSoundBuffer(dev.buffer)
		}
		closeWaveOutHandle(h)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutPrepareHeader\n")
		if getWaveOutHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		hdr.flags |= whdrPrepared
		hdr.flags &^= whdrDone
		writeWaveHeader(ctx.Mem, hdr)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutUnprepareHeader\n")
		if getWaveOutHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		hdr.flags &^= whdrPrepared
		writeWaveHeader(ctx.Mem, hdr)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutWrite", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutWrite\n")
		h := ctx.Arg(0)
		dev := getWaveOutHandle(h)
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		data, _ := ctx.Mem.ReadBytes(hdr.dataPtr, int(hdr.bufferLen))
		dev.mu.Lock()
		advanceWaveOutLocked(h, dev)
		hdr.flags &^= whdrDone
		writeWaveHeader(ctx.Mem, hdr)
		if dev.buffer != nil {
			dev.buffer.SetFormat(toDSoundFormat(dev.format))
			dev.buffer.WriteCursor = writeToSoundBuffer(dev.buffer, data, dev.buffer.WriteCursor)
		}
		dev.buffers = append(dev.buffers, queuedWaveBuffer{
			headerPtr: hdr.guestHeaderPtr,
			header:    hdr,
			remaining: uint32(len(data)),
		})
		dev.queuedBytes += uint64(len(data))
		if !dev.paused && dev.queuedBytes > 0 {
			if !dev.playing {
				dev.playing = true
				dev.lastTick = time.Now()
				if dev.buffer != nil {
					dev.buffer.Play(0, 0, 0)
				}
			} else if dev.lastTick.IsZero() {
				dev.lastTick = time.Now()
			}
		}
		dev.mu.Unlock()
		signalWaveOut(dev)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutPause", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutPause\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		advanceWaveOutLocked(ctx.Arg(0), dev)
		dev.paused = true
		if dev.buffer != nil {
			dev.buffer.Stop()
		}
		dev.mu.Unlock()
		signalWaveOut(dev)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutRestart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutRestart\n")
		h := ctx.Arg(0)
		dev := getWaveOutHandle(h)
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		advanceWaveOutLocked(h, dev)
		dev.paused = false
		if dev.queuedBytes > 0 {
			dev.playing = true
			dev.lastTick = time.Now()
			if dev.buffer != nil {
				dev.buffer.Play(0, 0, 0)
			}
		}
		dev.mu.Unlock()
		signalWaveOut(dev)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutReset\n")
		h := ctx.Arg(0)
		dev := getWaveOutHandle(h)
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		advanceWaveOutLocked(h, dev)
		for _, buf := range dev.buffers {
			writeWaveOutDone(h, dev, buf.header)
		}
		dev.buffers = nil
		dev.position = 0
		dev.queuedBytes = 0
		dev.playing = false
		dev.lastTick = time.Time{}
		dev.paused = false
		if dev.buffer != nil {
			dev.buffer.Stop()
			dev.buffer.SetCurrentPosition(0)
			dev.buffer.PlayCursor = 0
			dev.buffer.WriteCursor = 0
		}
		dev.mu.Unlock()
		signalWaveOut(dev)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetVolume\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		if ctx.Arg(1) != 0 {
			vol := dev.volume
			if dev.buffer != nil {
				vol = dsVolumeToWave(dev.buffer.GetVolume())
			}
			ctx.Mem.Write32(ctx.Arg(1), vol)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetVolume", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetVolume\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.volume = uint32(ctx.Arg(1))
		if dev.buffer != nil {
			dev.buffer.SetVolume(waveVolumeToDS(dev.volume))
		}
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPosition", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPosition\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		advanceWaveOutLocked(ctx.Arg(0), dev)
		reqType, _ := ctx.Mem.Read32(ctx.Arg(1))
		valType := reqType
		if valType == 0 {
			valType = mmTimeBytes
		}
		value := uint32(dev.position)
		if valType == mmTimeMS && dev.format.AvgBytesPerSec != 0 {
			value = uint32((dev.position * 1000) / uint64(dev.format.AvgBytesPerSec))
		} else if valType == mmTimeSamples && dev.format.BlockAlign != 0 {
			value = uint32(dev.position / uint64(dev.format.BlockAlign))
		} else {
			valType = mmTimeBytes
			value = uint32(dev.position)
		}
		dev.mu.Unlock()
		writeMMTime(ctx.Mem, ctx.Arg(1), valType, value)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPitch", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPitch\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write32(ctx.Arg(1), dev.pitch)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetPitch", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetPitch\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.pitch = uint32(ctx.Arg(1))
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetPlaybackRate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetPlaybackRate\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write32(ctx.Arg(1), dev.playbackRate)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutSetPlaybackRate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutSetPlaybackRate\n")
		dev := getWaveOutHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.playbackRate = uint32(ctx.Arg(1))
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveOutGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveOutGetID\n")
		if getWaveOutHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write32(ctx.Arg(1), 0)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})

	d.RegisterAutoStubHandler(dll, "waveInGetNumDevs", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetNumDevs\n")
		ctx.SetReturn(1)
		return 0
	})
	for _, name := range []string{"waveInGetDevCapsA", "waveInGetDevCapsW"} {
		isWide := strings.HasSuffix(name, "W")
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			deviceID := uint32(ctx.Arg(0))
			if deviceID != 0 && deviceID != waveMapper {
				ctx.SetReturn(mmSysErrBadDeviceID)
				return 0
			}
			if isWide {
				writeWaveInCapsW(ctx.Mem, ctx.Arg(1), uint32(ctx.Arg(2)))
			} else {
				writeWaveInCapsA(ctx.Mem, ctx.Arg(1), uint32(ctx.Arg(2)))
			}
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	for _, name := range []string{"waveInGetErrorTextA", "waveInGetErrorTextW"} {
		isWide := strings.HasSuffix(name, "W")
		d.RegisterAutoStubHandler(dll, name, func(ctx *ntapi.TrapContext) uint32 {
			ravelog.Logf("[winmm] %s\n", name)
			if isWide {
				writeErrorTextW(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			} else {
				writeErrorTextA(ctx, uint32(ctx.Arg(0)), ctx.Arg(1), ctx.Arg(2))
			}
			ctx.SetReturn(mmSysErrNoError)
			return 0
		})
	}
	d.RegisterAutoStubHandler(dll, "waveInOpen", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInOpen\n")
		phwi := ctx.Arg(0)
		deviceID := uint32(ctx.Arg(1))
		pwfx := ctx.Arg(2)
		if phwi == 0 || pwfx == 0 {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		if deviceID != 0 && deviceID != waveMapper {
			ctx.SetReturn(mmSysErrBadDeviceID)
			return 0
		}
		format := readWaveFormatEx(ctx.Mem, pwfx)
		if format.Channels == 0 || format.SamplesPerSec == 0 || format.BitsPerSample == 0 {
			ctx.SetReturn(wavErrBadFormat)
			return 0
		}
		cmd, pipe, silent, _ := startCaptureProcess(format)
		dev := &waveInDevice{
			format:      format,
			cmd:         cmd,
			pipe:        pipe,
			callback:    ctx.Arg(3),
			instance:    ctx.Arg(4),
			flags:       uint32(ctx.Arg(5)),
			silent:      silent,
			callbackCPU: ctx.CPU.CloneForThread(),
		}
		h := allocWaveInHandle(dev)
		ctx.Mem.Write64(phwi, h)
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, h, uint64(wimOpen), dev.instance, 0, 0)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInClose", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInClose\n")
		h := ctx.Arg(0)
		dev := getWaveInHandle(h)
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		stopCmd(dev.cmd, dev.pipe)
		dev.cmd = nil
		dev.pipe = nil
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, h, uint64(wimClose), dev.instance, 0, 0)
		}
		dev.mu.Unlock()
		closeWaveInHandle(h)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInPrepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInPrepareHeader\n")
		if getWaveInHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		hdr.flags |= whdrPrepared
		hdr.flags &^= whdrDone
		writeWaveHeader(ctx.Mem, hdr)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInUnprepareHeader", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInUnprepareHeader\n")
		if getWaveInHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		hdr.flags &^= whdrPrepared
		writeWaveHeader(ctx.Mem, hdr)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInAddBuffer", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInAddBuffer\n")
		dev := getWaveInHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		hdr, err := readWaveHeader(ctx.Mem, ctx.Arg(1))
		if err != nil {
			ctx.SetReturn(mmSysErrInvalParam)
			return 0
		}
		dev.mu.Lock()
		if dev.started {
			dispatchWaveInBuffer(ctx.Arg(0), dev, hdr)
		} else {
			dev.buffers = append(dev.buffers, hdr)
		}
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInStart", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInStart\n")
		dev := getWaveInHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.started = true
		pending := append([]waveHeader(nil), dev.buffers...)
		dev.buffers = nil
		dev.mu.Unlock()
		for _, hdr := range pending {
			dispatchWaveInBuffer(ctx.Arg(0), dev, hdr)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInStop", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInStop\n")
		dev := getWaveInHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		dev.started = false
		if dev.cmd != nil && dev.cmd.Process != nil {
			_ = dev.cmd.Process.Signal(syscall.SIGSTOP)
		}
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInReset", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInReset\n")
		dev := getWaveInHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		dev.mu.Lock()
		for _, hdr := range dev.buffers {
			hdr.flags |= whdrDone
			hdr.bytesRecorded = 0
			writeWaveHeader(mem, hdr)
		}
		dev.buffers = nil
		dev.started = false
		restartWaveIn(dev)
		dev.mu.Unlock()
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetPosition", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetPosition\n")
		dev := getWaveInHandle(ctx.Arg(0))
		if dev == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		reqType, _ := ctx.Mem.Read32(ctx.Arg(1))
		valType := reqType
		if valType == 0 {
			valType = mmTimeBytes
		}
		value := uint32(dev.position)
		if valType == mmTimeMS && dev.format.AvgBytesPerSec != 0 {
			value = uint32((dev.position * 1000) / uint64(dev.format.AvgBytesPerSec))
		} else {
			valType = mmTimeBytes
			value = uint32(dev.position)
		}
		writeMMTime(ctx.Mem, ctx.Arg(1), valType, value)
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
	d.RegisterAutoStubHandler(dll, "waveInGetID", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[winmm] waveInGetID\n")
		if getWaveInHandle(ctx.Arg(0)) == nil {
			ctx.SetReturn(mmSysErrInvalHandle)
			return 0
		}
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write32(ctx.Arg(1), 0)
		}
		ctx.SetReturn(mmSysErrNoError)
		return 0
	})
}
