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

	wavErrBadFormat = 32

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

	mmTimeMS    = 0x0001
	mmTimeBytes = 0x0004

	womOpen  = 0x03BB
	womClose = 0x03BC
	womDone  = 0x03BD
	wimOpen  = 0x03BE
	wimClose = 0x03BF
	wimData  = 0x03C0

	waveCapsVolume   = 0x0004
	waveCapsLRVolume = 0x0008

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
	data      []byte
}

type waveOutDevice struct {
	mu           sync.Mutex
	format       waveFormatEx
	buffers      []queuedWaveBuffer
	cmd          *exec.Cmd
	pipe         io.WriteCloser
	callback     uint64
	instance     uint64
	flags        uint32
	volume       uint32
	position     uint64
	pitch        uint32
	playbackRate uint32
	paused       bool
	silent       bool
	callbackCPU  arch.CPU
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
	name := utf16Encode("go-vm WaveOut")
	for i, w := range name {
		if 8+i*2+1 >= len(buf) || i >= 31 {
			break
		}
		binary.LittleEndian.PutUint16(buf[8+i*2:], w)
	}
	binary.LittleEndian.PutUint32(buf[72:], 0)
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
	copy(buf[8:40], []byte("go-vm WaveOut"))
	binary.LittleEndian.PutUint32(buf[40:], 0)
	binary.LittleEndian.PutUint16(buf[44:], 2)
	binary.LittleEndian.PutUint32(buf[48:], waveCapsVolume|waveCapsLRVolume)
	mem.WriteBytes(addr, buf[:minU32(cb, uint32(len(buf)))])
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

	flushWaveOutLocked := func(hwo uint64, dev *waveOutDevice) {
		if dev.paused {
			return
		}
		for len(dev.buffers) > 0 {
			buf := dev.buffers[0]
			dev.buffers = dev.buffers[1:]
			if !dev.silent && dev.pipe != nil && len(buf.data) > 0 {
				if _, err := dev.pipe.Write(buf.data); err != nil {
					dev.silent = true
				}
			}
			dev.position += uint64(len(buf.data))
			writeWaveOutDone(hwo, dev, buf.header)
		}
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

	restartWaveOut := func(dev *waveOutDevice) {
		stopCmd(dev.cmd, dev.pipe)
		dev.cmd = nil
		dev.pipe = nil
		cmd, pipe, silent, _ := startAudioProcess(dev.format)
		dev.cmd = cmd
		dev.pipe = pipe
		dev.silent = silent
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
	registerFixed("PlaySound", 1)
	registerFixed("PlaySoundA", 1)
	registerFixed("PlaySoundW", 1)
	registerFixed("SendDriverMessage", 0)
	registerFixed("sndPlaySoundA", 1)
	registerFixed("sndPlaySoundW", 1)
	registerFixed("mmsystemGetVersion", 0x0500)
	registerFixed("-stub", 0)

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
		ravelog.Logf("[winmm] timeGetTime\n")
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
		cmd, pipe, silent, _ := startAudioProcess(format)
		dev := &waveOutDevice{
			format:       format,
			cmd:          cmd,
			pipe:         pipe,
			callback:     ctx.Arg(3),
			instance:     ctx.Arg(4),
			flags:        uint32(ctx.Arg(5)),
			volume:       0xFFFFFFFF,
			pitch:        0x10000,
			playbackRate: 0x10000,
			silent:       silent,
			callbackCPU:  ctx.CPU.CloneForThread(),
		}
		h := allocWaveOutHandle(dev)
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
		stopCmd(dev.cmd, dev.pipe)
		dev.cmd = nil
		dev.pipe = nil
		if dev.flags&callbackFunction == callbackFunction {
			invokeGuestCallback(dev.callbackCPU, dev.callback, h, uint64(womClose), dev.instance, 0, 0)
		}
		dev.mu.Unlock()
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
		hdr.flags &^= whdrDone
		writeWaveHeader(ctx.Mem, hdr)
		if dev.paused {
			dev.buffers = append(dev.buffers, queuedWaveBuffer{
				headerPtr: hdr.guestHeaderPtr,
				header:    hdr,
				data:      data,
			})
		} else {
			if !dev.silent && dev.pipe != nil && len(data) > 0 {
				if _, err := dev.pipe.Write(data); err != nil {
					dev.silent = true
				}
			}
			dev.position += uint64(len(data))
			writeWaveOutDone(h, dev, hdr)
		}
		dev.mu.Unlock()
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
		dev.paused = true
		if dev.cmd != nil && dev.cmd.Process != nil {
			_ = dev.cmd.Process.Signal(syscall.SIGSTOP)
		}
		dev.mu.Unlock()
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
		dev.paused = false
		if dev.cmd != nil && dev.cmd.Process != nil {
			_ = dev.cmd.Process.Signal(syscall.SIGCONT)
		}
		flushWaveOutLocked(uint64(h), dev)
		dev.mu.Unlock()
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
		for _, buf := range dev.buffers {
			writeWaveOutDone(uint64(h), dev, buf.header)
		}
		dev.buffers = nil
		restartWaveOut(dev)
		dev.paused = false
		dev.mu.Unlock()
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
			ctx.Mem.Write32(ctx.Arg(1), dev.volume)
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
