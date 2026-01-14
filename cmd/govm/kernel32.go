package main

import (
	"fmt"
	"github.com/mirkobrombin/Raven/pkg/arch"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

func registerKernel32Handlers(hctx *HandlerCtx) {
	addAtomGlobal := hctx.AddAtomGlobal
	addAtomLocal := hctx.AddAtomLocal
	cmdLine := hctx.CmdLine
	d := hctx.Disp
	doCreateFileMapping := hctx.DoCreateFileMapping
	doMapView := hctx.DoMapView
	doUnmapView := hctx.DoUnmapView
	envVars := hctx.EnvVars
	exceptionTable := hctx.ExTable
	globalAtomNames := hctx.GlobalAtomNames
	globalAtomTable := hctx.GlobalAtomTable
	handles := hctx.Handles
	imagePath := hctx.ImagePath
	iniRead := hctx.IniRead
	iniWrite := hctx.IniWrite
	localAtomNames := hctx.LocalAtomNames
	localAtomTable := hctx.LocalAtomTable
	mem := hctx.Mem
	procState := hctx.ProcState
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	readGuestUTF16N := hctx.ReadGuestUTF16N
	regHive := hctx.RegHive
	regKeyPath := hctx.RegKeyPath
	regQueryValue := hctx.RegQueryValue
	regIsProbeKey := hctx.RegIsProbeKey
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree
	startTime := hctx.StartTime
	stdinReader := hctx.StdinReader
	synthByName := hctx.SynthByName
	tmPtr := hctx.TMPtr
	wlDisplay := hctx.WlDisplay
	mainModule := hctx.MainModule
	peLoadRawResource := hctx.PeLoadRawResource
	// HRSRC tracking: map from fake handle → {dataAddr, dataSize}
	type hrsrcEntry struct {
		dataAddr uint64
		dataSize uint32
	}
	hrsrcTable := map[uint64]hrsrcEntry{}
	var hrsrcNext uint64 = 0xF0000001
	// Fiber tracking: map from fiber address → fiber data pointer.
	// Each ConvertThreadToFiber/CreateFiber(Ex) allocates a unique guest
	// page so callers that compare fiber addresses see distinct values.
	var fiberMu sync.Mutex
	fiberMap := map[uint64]uint64{} // fiberAddr → lpParameter
	var nextFiberAddr uint64
	// Standard handle overrides for SetStdHandle/GetStdHandle.
	stdHandleMap := map[uint32]uint64{
		0xFFFFFFF6: 0x100, // STD_INPUT_HANDLE
		0xFFFFFFF5: 0x101, // STD_OUTPUT_HANDLE
		0xFFFFFFF4: 0x102, // STD_ERROR_HANDLE
	}
	var stdHandleMu sync.Mutex
	// Process error mode for SetErrorMode/GetErrorMode.
	var processErrorMode uint32
	var errorModeMu sync.Mutex
	// Per-thread error mode for SetThreadErrorMode.
	var threadErrorMode uint32
	var threadErrorModeMu sync.Mutex
	// Handle flags for Set/GetHandleInformation.
	handleFlagsMap := map[ntapi.Handle]uint32{}
	var handleFlagsMu sync.Mutex
	fileApisANSI := true
	_ = fileApisANSI
	var systemFileCacheMin uint64
	var systemFileCacheMax uint64
	var systemFileCacheFlags uint32
	var processWorkingSetMin uint64 = 1 << 20
	var processWorkingSetMax uint64 = 16 << 20
	var processWorkingSetFlags uint32
	// Stateful implementations for legacy kernel32 auto-stubs.
	type trivialKernel32Call struct {
		Count      uint64
		LastArgs   []uint64
		LastReturn uint64
		LastError  uint32
	}
	var trivialKernel32Mu sync.Mutex
	trivialKernel32Calls := map[string]*trivialKernel32Call{}

	type boundaryDescriptorInfo struct {
		Name  string
		Flags uint32
	}
	var boundaryDescriptorMu sync.Mutex
	boundaryDescriptorInfoMap := map[uint64]boundaryDescriptorInfo{}

	type syncBarrierInfo struct {
		Participants uint32
		SpinCount    uint32
		EnterCount   uint64
	}
	var syncBarrierMu sync.Mutex
	syncBarriers := map[uint64]*syncBarrierInfo{}

	type timerQueueInfo struct {
		Queue     uint64
		Callback  uint64
		Parameter uint64
		DueTime   uint32
		Period    uint32
		Flags     uint32
	}
	var timerQueueMu sync.Mutex
	timerQueues := map[uint64]*timerQueueInfo{}

	var preferredUILanguagesMu sync.Mutex
	processPreferredUILanguages := "en-US"
	const defaultLocaleLCID uint32 = 0x0409
	const defaultLocaleName = "en-US"
	const defaultAnsiCodePage uint32 = 1252
	const defaultOEMCodePage uint32 = 437
	var threadLocaleMu sync.Mutex
	threadLocale := defaultLocaleLCID
	stateScalars := map[string]uint64{
		"activeConsoleSessionID": 1,
		"daylightFlag":           0,
		"nlsCacheGeneration":     0,
		"nlsUserCacheNotify":     0,
		"processAffinityMode":    0,
		"searchPathMode":         0,
		"termsrvAppInstallMode":  0,
		"userGeoID":              244,
	}
	var timePeriodMu sync.Mutex
	timePeriodRequests := map[uint32]uint32{}
	var userGeoName string = "United States"
	var handleContextMu sync.Mutex
	handleContexts := map[uint64]uint64{}
	var dosDeviceMu sync.Mutex
	dosDeviceMap := map[string]string{"C:": `\\Device\\HarddiskVolume1`}
	var volumeMu sync.Mutex
	volumeLabels := map[string]string{}
	volumeMountPoints := map[string]string{}
	var cachedSigningLevelMu sync.Mutex
	cachedSigningLevels := map[uint64]uint32{}
	var werMu sync.Mutex
	var werFlags uint32
	werMetadata := map[string]string{}
	werFiles := map[string]uint32{}
	werRuntimeModules := map[string]uint64{}
	guestCallTrampoline := ntapi.AllocTrampoline(mem)

	setLastErrorValue := func(code uint32) {
		mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, code)
	}
	captureKernel32Args := func(ctx *ntapi.TrapContext, argc int) []uint64 {
		if argc < 0 {
			argc = 0
		}
		if argc > 8 {
			argc = 8
		}
		args := make([]uint64, argc)
		for i := 0; i < argc; i++ {
			args[i] = ctx.Arg(i)
		}
		return args
	}
	callGuest := func(ctx *ntapi.TrapContext, addr uint64, args []uint64) (uint64, error) {
		return ntapi.CallGuestFunction(ctx.CPU, mem, guestCallTrampoline, addr, args, ctx.Trace)
	}
	formatKernel32Args := func(args []uint64) string {
		if len(args) == 0 {
			return ""
		}
		parts := make([]string, len(args))
		for i, arg := range args {
			parts[i] = fmt.Sprintf("arg%d=0x%x", i, arg)
		}
		return strings.Join(parts, ", ")
	}
	recordKernel32Call := func(name string, args []uint64, ret uint64, lastErr uint32) {
		trivialKernel32Mu.Lock()
		entry := trivialKernel32Calls[name]
		if entry == nil {
			entry = &trivialKernel32Call{}
			trivialKernel32Calls[name] = entry
		}
		entry.Count++
		entry.LastArgs = append(entry.LastArgs[:0], args...)
		entry.LastReturn = ret
		entry.LastError = lastErr
		trivialKernel32Mu.Unlock()
	}
	writeANSIString := func(addr uint64, s string, cch uint64) uint64 {
		required := uint64(len(s) + 1)
		if addr == 0 || cch == 0 {
			return required
		}
		limit := uint64(len(s))
		if limit+1 > cch {
			limit = cch - 1
		}
		for i := uint64(0); i < limit; i++ {
			mem.Write8(addr+i, s[i])
		}
		mem.Write8(addr+limit, 0)
		return required
	}
	writeUTF16String := func(addr uint64, s string, cch uint64) uint64 {
		ws := utf16Encode(s)
		required := uint64(len(ws) + 1)
		if addr == 0 || cch == 0 {
			return required
		}
		limit := uint64(len(ws))
		if limit+1 > cch {
			limit = cch - 1
		}
		for i := uint64(0); i < limit; i++ {
			mem.Write16(addr+i*2, ws[i])
		}
		mem.Write16(addr+limit*2, 0)
		return required
	}
	writeANSIStringCount := func(addr uint64, s string, cch uint64) uint64 {
		required := uint64(len(s) + 1)
		if addr == 0 || cch == 0 {
			return required
		}
		written := required
		if written > cch {
			written = cch
		}
		limit := uint64(len(s))
		if limit+1 > written {
			limit = written - 1
		}
		for i := uint64(0); i < limit; i++ {
			mem.Write8(addr+i, s[i])
		}
		mem.Write8(addr+limit, 0)
		return written
	}
	writeUTF16StringCount := func(addr uint64, s string, cch uint64) uint64 {
		ws := utf16Encode(s)
		required := uint64(len(ws) + 1)
		if addr == 0 || cch == 0 {
			return required
		}
		written := required
		if written > cch {
			written = cch
		}
		limit := uint64(len(ws))
		if limit+1 > written {
			limit = written - 1
		}
		for i := uint64(0); i < limit; i++ {
			mem.Write16(addr+i*2, ws[i])
		}
		mem.Write16(addr+limit*2, 0)
		return written
	}
	readANSIBytesArg := func(ptr uint64, cb int32) []byte {
		if ptr == 0 {
			return nil
		}
		if cb == -1 {
			var out []byte
			for i := uint64(0); ; i++ {
				b, _ := mem.Read8(ptr + i)
				out = append(out, b)
				if b == 0 {
					break
				}
			}
			return out
		}
		if cb <= 0 {
			return nil
		}
		out := make([]byte, cb)
		for i := int32(0); i < cb; i++ {
			out[i], _ = mem.Read8(ptr + uint64(i))
		}
		return out
	}
	readUTF16UnitsArg := func(ptr uint64, cch int32) []uint16 {
		if ptr == 0 {
			return nil
		}
		if cch == -1 {
			var out []uint16
			for i := uint64(0); ; i++ {
				w, _ := mem.Read16(ptr + i*2)
				out = append(out, w)
				if w == 0 {
					break
				}
			}
			return out
		}
		if cch <= 0 {
			return nil
		}
		out := make([]uint16, cch)
		for i := int32(0); i < cch; i++ {
			out[i], _ = mem.Read16(ptr + uint64(i)*2)
		}
		return out
	}
	readWideStringArg := func(ptr uint64, cch int32) string {
		units := readUTF16UnitsArg(ptr, cch)
		if len(units) == 0 {
			return ""
		}
		if cch == -1 && units[len(units)-1] == 0 {
			units = units[:len(units)-1]
		}
		return string(utf16.Decode(units))
	}
	normalizeLocaleName := func(name string) string {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "", "!x-sys-default-locale", "!x-user-default-locale":
			return defaultLocaleName
		case "en":
			return "en"
		case "en-us":
			return defaultLocaleName
		case "en-gb":
			return "en-GB"
		case "en-au":
			return "en-AU"
		case "en-ca":
			return "en-CA"
		case "de-de":
			return "de-DE"
		case "fr-fr":
			return "fr-FR"
		case "it-it":
			return "it-IT"
		case "ja-jp":
			return "ja-JP"
		case "ko-kr":
			return "ko-KR"
		case "zh-cn":
			return "zh-CN"
		case "zh-tw":
			return "zh-TW"
		case "pt-br":
			return "pt-BR"
		case "es-es":
			return "es-ES"
		case "ru-ru":
			return "ru-RU"
		default:
			return defaultLocaleName
		}
	}
	resolveLocaleNameValue := func(name string) string {
		normalized := normalizeLocaleName(name)
		if normalized == "en" {
			return defaultLocaleName
		}
		return normalized
	}
	lcidToLocaleNameValue := func(lcid uint32) string {
		switch lcid {
		case 0x0409, 0x0000, 0x0400, 0x0800:
			return defaultLocaleName
		case 0x0809:
			return "en-GB"
		case 0x0C09:
			return "en-AU"
		case 0x1009:
			return "en-CA"
		case 0x0009:
			return "en"
		case 0x0407:
			return "de-DE"
		case 0x040C:
			return "fr-FR"
		case 0x0410:
			return "it-IT"
		case 0x0411:
			return "ja-JP"
		case 0x0412:
			return "ko-KR"
		case 0x0804:
			return "zh-CN"
		case 0x0404:
			return "zh-TW"
		case 0x0416:
			return "pt-BR"
		case 0x0C0A:
			return "es-ES"
		case 0x0419:
			return "ru-RU"
		default:
			return defaultLocaleName
		}
	}
	localeNameToLCIDValue := func(name string) uint32 {
		switch normalizeLocaleName(name) {
		case "en":
			return 0x0009
		case "en-GB":
			return 0x0809
		case "en-AU":
			return 0x0C09
		case "en-CA":
			return 0x1009
		case "de-DE":
			return 0x0407
		case "fr-FR":
			return 0x040C
		case "it-IT":
			return 0x0410
		case "ja-JP":
			return 0x0411
		case "ko-KR":
			return 0x0412
		case "zh-CN":
			return 0x0804
		case "zh-TW":
			return 0x0404
		case "pt-BR":
			return 0x0416
		case "es-ES":
			return 0x0C0A
		case "ru-RU":
			return 0x0419
		default:
			return defaultLocaleLCID
		}
	}
	codePageInfo := func(codePage uint32) (uint32, string, uint32, bool) {
		switch codePage {
		case 0, defaultAnsiCodePage:
			return 1, "1252 (ANSI - Latin I)", defaultAnsiCodePage, true
		case defaultOEMCodePage:
			return 1, "437 (OEM - United States)", defaultOEMCodePage, true
		case 850:
			return 1, "850 (OEM - Multilingual Latin I)", 850, true
		case 1200:
			return 2, "1200 (UTF-16LE)", 1200, true
		case 65001:
			return 4, "65001 (UTF-8)", 65001, true
		default:
			return 0, "", codePage, false
		}
	}
	writeCPInfoData := func(addr uint64, codePage uint32) bool {
		maxCharSize, _, cp, ok := codePageInfo(codePage)
		if !ok || addr == 0 {
			return false
		}
		mem.Write32(addr, maxCharSize)
		mem.Write8(addr+4, 0x3F)
		mem.Write8(addr+5, 0)
		for i := uint64(0); i < 12; i++ {
			mem.Write8(addr+6+i, 0)
		}
		if cp == 1200 {
			mem.Write8(addr+4, 0)
			mem.Write8(addr+5, 0)
		}
		return true
	}
	writeCPInfoExAData := func(addr uint64, codePage uint32) bool {
		maxCharSize, cpName, cp, ok := codePageInfo(codePage)
		if !ok || addr == 0 {
			return false
		}
		mem.Write32(addr, maxCharSize)
		mem.Write8(addr+4, 0x3F)
		mem.Write8(addr+5, 0)
		for i := uint64(0); i < 12; i++ {
			mem.Write8(addr+6+i, 0)
		}
		mem.Write16(addr+18, 0x003F)
		mem.Write32(addr+20, cp)
		for i := 0; i < len(cpName) && i < 260; i++ {
			mem.Write8(addr+24+uint64(i), cpName[i])
		}
		if len(cpName) < 260 {
			mem.Write8(addr+24+uint64(len(cpName)), 0)
		}
		return true
	}
	writeCPInfoExWData := func(addr uint64, codePage uint32) bool {
		maxCharSize, cpName, cp, ok := codePageInfo(codePage)
		if !ok || addr == 0 {
			return false
		}
		mem.Write32(addr, maxCharSize)
		mem.Write8(addr+4, 0x3F)
		mem.Write8(addr+5, 0)
		for i := uint64(0); i < 12; i++ {
			mem.Write8(addr+6+i, 0)
		}
		mem.Write16(addr+18, 0x003F)
		mem.Write32(addr+20, cp)
		nameW := utf16Encode(cpName)
		for i, w := range nameW {
			if i >= 260 {
				break
			}
			mem.Write16(addr+24+uint64(i)*2, w)
		}
		if len(nameW) < 260 {
			mem.Write16(addr+24+uint64(len(nameW))*2, 0)
		}
		return true
	}
	writeNLSVersionInfoData := func(addr uint64, ex bool) bool {
		if addr == 0 {
			return false
		}
		size := uint32(16)
		if ex {
			size = 32
		}
		mem.Write32(addr, size)
		mem.Write32(addr+4, 0x00060201)
		mem.Write32(addr+8, 0x00060201)
		mem.Write32(addr+12, defaultLocaleLCID)
		if ex {
			for i := uint64(0); i < 16; i++ {
				mem.Write8(addr+16+i, 0)
			}
		}
		return true
	}
	isCommonNLSRune := func(r rune) bool {
		switch {
		case r == 0:
			return true
		case r >= 0x20 && r <= 0x7E:
			return true
		case r >= 0x00A0 && r <= 0x024F:
			return true
		case r >= 0x0370 && r <= 0x03FF:
			return true
		case r >= 0x0400 && r <= 0x052F:
			return true
		case r >= 0x2000 && r <= 0x206F:
			return true
		case r >= 0x3040 && r <= 0x30FF:
			return true
		case r >= 0x4E00 && r <= 0x9FFF:
			return true
		default:
			return false
		}
	}
	type consoleInputEvent struct {
		KeyDown         bool
		RepeatCount     uint16
		VirtualKeyCode  uint16
		VirtualScanCode uint16
		UnicodeChar     uint16
		AsciiChar       byte
		ControlKeyState uint32
	}
	const (
		consolePseudoHWND           = uint64(0xC0DE0001)
		stdInputHandleValue         = uint64(0x100)
		stdOutputHandleValue        = uint64(0x101)
		stdErrorHandleValue         = uint64(0x102)
		enableVTProcessing   uint32 = 0x0004
		keyEventRecordType   uint16 = 0x0001
	)
	var consoleStateMu sync.Mutex
	activeConsoleState := ntapi.GlobalConsole
	consoleTitle := ntapi.GlobalConsole.Title
	consoleAttached := true
	consoleInputMode := uint32(0x0007)
	consoleOutputModes := map[uint64]uint32{
		stdOutputHandleValue: 0x0007,
		stdErrorHandleValue:  0x0007,
	}
	var consoleSavedCursorX int
	var consoleSavedCursorY int
	var consoleInputMu sync.Mutex
	consoleInputCond := sync.NewCond(&consoleInputMu)
	consoleInputQueue := make([]consoleInputEvent, 0, 32)
	var consoleCtrlMu sync.Mutex
	consoleCtrlHandlers := map[uint64]struct{}{}
	consoleCtrlIgnore := false
	clampInt := func(v, minV, maxV int) int {
		if v < minV {
			return minV
		}
		if v > maxV {
			return maxV
		}
		return v
	}
	makeConsoleCells := func(width, height int, attr uint16) []ntapi.ConsoleCellAttr {
		if width <= 0 {
			width = 120
		}
		if height <= 0 {
			height = 30
		}
		cells := make([]ntapi.ConsoleCellAttr, width*height)
		for i := range cells {
			cells[i] = ntapi.ConsoleCellAttr{Char: ' ', Attr: attr}
		}
		return cells
	}
	resizeConsoleState := func(cs *ntapi.ConsoleState, width, height int) {
		if cs == nil {
			return
		}
		if width <= 0 {
			width = 120
		}
		if height <= 0 {
			height = 30
		}
		oldWidth, oldHeight := cs.Width, cs.Height
		oldCells := append([]ntapi.ConsoleCellAttr(nil), cs.Cells...)
		if cs.Attr == 0 {
			cs.Attr = 0x07
		}
		cs.Width = width
		cs.Height = height
		cs.Cells = makeConsoleCells(width, height, cs.Attr)
		copyW := width
		if oldWidth < copyW {
			copyW = oldWidth
		}
		copyH := height
		if oldHeight < copyH {
			copyH = oldHeight
		}
		for y := 0; y < copyH; y++ {
			for x := 0; x < copyW; x++ {
				cs.Cells[y*width+x] = oldCells[y*oldWidth+x]
			}
		}
		if width > 0 {
			cs.CursorX = clampInt(cs.CursorX, 0, width-1)
		} else {
			cs.CursorX = 0
		}
		if height > 0 {
			cs.CursorY = clampInt(cs.CursorY, 0, height-1)
		} else {
			cs.CursorY = 0
		}
	}
	if consoleTitle == "" {
		consoleTitle = "Raven Console"
	}
	if activeConsoleState.Attr == 0 {
		activeConsoleState.Attr = 0x07
	}
	activeConsoleState.Title = consoleTitle
	activeConsoleState.Mode = consoleOutputModes[stdOutputHandleValue]
	activeConsoleState.CursorVisible = true
	if activeConsoleState.CursorSize == 0 {
		activeConsoleState.CursorSize = 25
	}
	resizeConsoleState(activeConsoleState, 120, 30)
	colorNibbleToANSI := func(nibble uint16, background bool) int {
		fgMap := []int{30, 34, 32, 36, 31, 35, 33, 37}
		bgMap := []int{40, 44, 42, 46, 41, 45, 43, 47}
		idx := int(nibble & 0x7)
		code := fgMap[idx]
		if background {
			code = bgMap[idx]
		}
		if nibble&0x8 != 0 {
			code += 60
		}
		return code
	}
	attrToANSI := func(attr uint16) string {
		fg := colorNibbleToANSI(attr&0x0F, false)
		bg := colorNibbleToANSI((attr>>4)&0x0F, true)
		return fmt.Sprintf("\x1b[0;%d;%dm", fg, bg)
	}
	ansiToColorNibble := func(code int, background bool) (uint16, bool) {
		var idx int
		bright := false
		switch {
		case !background && code >= 30 && code <= 37:
			idx = code - 30
		case !background && code >= 90 && code <= 97:
			idx = code - 90
			bright = true
		case background && code >= 40 && code <= 47:
			idx = code - 40
		case background && code >= 100 && code <= 107:
			idx = code - 100
			bright = true
		default:
			return 0, false
		}
		var nibble uint16
		switch idx {
		case 0:
			nibble = 0
		case 1:
			nibble = 4
		case 2:
			nibble = 2
		case 3:
			nibble = 6
		case 4:
			nibble = 1
		case 5:
			nibble = 5
		case 6:
			nibble = 3
		case 7:
			nibble = 7
		}
		if bright {
			nibble |= 0x8
		}
		return nibble, true
	}
	resolveConsoleState := func(handle uint64) *ntapi.ConsoleState {
		consoleStateMu.Lock()
		defer consoleStateMu.Unlock()
		switch handle {
		case 0, stdOutputHandleValue, stdErrorHandleValue:
			return activeConsoleState
		}
		if sb, ok := handles.Get(ntapi.Handle(handle)).(*ntapi.ConsoleScreenBufferHandle); ok && sb != nil && sb.State != nil {
			return sb.State
		}
		return activeConsoleState
	}
	isVisibleConsoleState := func(cs *ntapi.ConsoleState) bool {
		consoleStateMu.Lock()
		defer consoleStateMu.Unlock()
		return consoleAttached && cs != nil && cs == activeConsoleState
	}
	outputModeForHandle := func(handle uint64) uint32 {
		consoleStateMu.Lock()
		defer consoleStateMu.Unlock()
		if handle == stdInputHandleValue {
			return consoleInputMode
		}
		if mode, ok := consoleOutputModes[handle]; ok {
			return mode
		}
		return 0x0007
	}
	setOutputModeForHandle := func(handle uint64, mode uint32) {
		consoleStateMu.Lock()
		if handle == stdInputHandleValue {
			consoleInputMode = mode
			consoleStateMu.Unlock()
			return
		}
		consoleOutputModes[handle] = mode
		var cs *ntapi.ConsoleState
		switch handle {
		case 0, stdOutputHandleValue, stdErrorHandleValue:
			cs = activeConsoleState
		default:
			if sb, ok := handles.Get(ntapi.Handle(handle)).(*ntapi.ConsoleScreenBufferHandle); ok && sb != nil {
				cs = sb.State
			}
		}
		consoleStateMu.Unlock()
		if cs != nil {
			cs.Mode = mode
		}
	}
	scrollConsoleState := func(cs *ntapi.ConsoleState, lines int) {
		if cs == nil || lines <= 0 || cs.Width <= 0 || cs.Height <= 0 {
			return
		}
		if lines > cs.Height {
			lines = cs.Height
		}
		copy(cs.Cells, cs.Cells[lines*cs.Width:])
		fillStart := (cs.Height - lines) * cs.Width
		for i := fillStart; i < len(cs.Cells); i++ {
			cs.Cells[i] = ntapi.ConsoleCellAttr{Char: ' ', Attr: cs.Attr}
		}
		cs.CursorY -= lines
		if cs.CursorY < 0 {
			cs.CursorY = 0
		}
	}
	var putConsoleRune func(cs *ntapi.ConsoleState, r rune)
	putConsoleRune = func(cs *ntapi.ConsoleState, r rune) {
		if cs == nil || cs.Width <= 0 || cs.Height <= 0 {
			return
		}
		switch r {
		case '\r':
			cs.CursorX = 0
			return
		case '\n':
			cs.CursorX = 0
			cs.CursorY++
			if cs.CursorY >= cs.Height {
				scrollConsoleState(cs, 1)
				cs.CursorY = cs.Height - 1
			}
			return
		case '\b':
			if cs.CursorX > 0 {
				cs.CursorX--
			}
			return
		case '\t':
			nextTab := ((cs.CursorX / 8) + 1) * 8
			for cs.CursorX < nextTab {
				putConsoleRune(cs, ' ')
			}
			return
		}
		if cs.CursorX >= cs.Width {
			cs.CursorX = 0
			cs.CursorY++
		}
		if cs.CursorY >= cs.Height {
			scrollConsoleState(cs, 1)
			cs.CursorY = cs.Height - 1
		}
		idx := cs.CursorY*cs.Width + cs.CursorX
		if idx >= 0 && idx < len(cs.Cells) {
			ch := uint16('?')
			if r >= 0 && r <= 0xFFFF {
				ch = uint16(r)
			}
			cs.Cells[idx] = ntapi.ConsoleCellAttr{Char: ch, Attr: cs.Attr}
		}
		cs.CursorX++
		if cs.CursorX >= cs.Width {
			cs.CursorX = 0
			cs.CursorY++
			if cs.CursorY >= cs.Height {
				scrollConsoleState(cs, 1)
				cs.CursorY = cs.Height - 1
			}
		}
	}
	consoleCSIParams := func(raw string) []int {
		if raw == "" {
			return nil
		}
		raw = strings.TrimPrefix(raw, "?")
		parts := strings.Split(raw, ";")
		params := make([]int, 0, len(parts))
		for _, part := range parts {
			if part == "" {
				params = append(params, 0)
				continue
			}
			n, err := strconv.Atoi(part)
			if err != nil {
				params = append(params, 0)
				continue
			}
			params = append(params, n)
		}
		return params
	}
	applyConsoleCSI := func(cs *ntapi.ConsoleState, raw string, final byte) {
		if cs == nil {
			return
		}
		params := consoleCSIParams(raw)
		first := func(def int) int {
			if len(params) == 0 || params[0] == 0 {
				return def
			}
			return params[0]
		}
		switch final {
		case 'A':
			cs.CursorY = clampInt(cs.CursorY-first(1), 0, cs.Height-1)
		case 'B':
			cs.CursorY = clampInt(cs.CursorY+first(1), 0, cs.Height-1)
		case 'C':
			cs.CursorX = clampInt(cs.CursorX+first(1), 0, cs.Width-1)
		case 'D':
			cs.CursorX = clampInt(cs.CursorX-first(1), 0, cs.Width-1)
		case 'G':
			cs.CursorX = clampInt(first(1)-1, 0, cs.Width-1)
		case 'H', 'f':
			row, col := 1, 1
			if len(params) > 0 && params[0] > 0 {
				row = params[0]
			}
			if len(params) > 1 && params[1] > 0 {
				col = params[1]
			}
			cs.CursorY = clampInt(row-1, 0, cs.Height-1)
			cs.CursorX = clampInt(col-1, 0, cs.Width-1)
		case 'J':
			mode := first(0)
			if mode == 2 {
				for i := range cs.Cells {
					cs.Cells[i] = ntapi.ConsoleCellAttr{Char: ' ', Attr: cs.Attr}
				}
				cs.CursorX, cs.CursorY = 0, 0
			}
		case 'K':
			mode := first(0)
			start, end := cs.CursorX, cs.Width-1
			if mode == 1 {
				start = 0
				end = cs.CursorX
			} else if mode == 2 {
				start = 0
			}
			for x := start; x <= end && x < cs.Width; x++ {
				idx := cs.CursorY*cs.Width + x
				if idx >= 0 && idx < len(cs.Cells) {
					cs.Cells[idx] = ntapi.ConsoleCellAttr{Char: ' ', Attr: cs.Attr}
				}
			}
		case 'm':
			if len(params) == 0 {
				params = []int{0}
			}
			attr := cs.Attr
			for _, code := range params {
				switch code {
				case 0:
					attr = 0x07
				case 1:
					attr |= 0x08
				case 22:
					attr &^= 0x08
				case 39:
					attr = (attr & 0xF0) | 0x07
				case 49:
					attr &= 0x0F
				default:
					if nibble, ok := ansiToColorNibble(code, false); ok {
						attr = (attr & 0xF0) | nibble
					} else if nibble, ok := ansiToColorNibble(code, true); ok {
						attr = (attr & 0x0F) | (nibble << 4)
					}
				}
			}
			cs.Attr = attr
		case 's':
			consoleSavedCursorX = cs.CursorX
			consoleSavedCursorY = cs.CursorY
		case 'u':
			cs.CursorX = clampInt(consoleSavedCursorX, 0, cs.Width-1)
			cs.CursorY = clampInt(consoleSavedCursorY, 0, cs.Height-1)
		}
	}
	applyConsoleText := func(cs *ntapi.ConsoleState, text string) {
		if cs == nil || text == "" {
			return
		}
		for i := 0; i < len(text); {
			if text[i] == 0x1b && i+1 < len(text) {
				switch text[i+1] {
				case '[':
					j := i + 2
					for j < len(text) && (text[j] < 0x40 || text[j] > 0x7E) {
						j++
					}
					if j < len(text) {
						applyConsoleCSI(cs, text[i+2:j], text[j])
						i = j + 1
						continue
					}
				case ']':
					j := i + 2
					for j < len(text) && text[j] != 0x07 {
						if text[j] == 0x1b && j+1 < len(text) && text[j+1] == '\\' {
							break
						}
						j++
					}
					payload := text[i+2 : j]
					if strings.HasPrefix(payload, "0;") || strings.HasPrefix(payload, "2;") {
						consoleTitle = payload[2:]
						cs.Title = consoleTitle
						ntapi.GlobalConsole.Title = consoleTitle
					}
					if j < len(text) && text[j] == 0x07 {
						i = j + 1
					} else if j+1 < len(text) && text[j] == 0x1b && text[j+1] == '\\' {
						i = j + 2
					} else {
						i = j
					}
					continue
				}
			}
			r, size := utf8.DecodeRuneInString(text[i:])
			if r == utf8.RuneError && size == 1 {
				r = rune(text[i])
			}
			putConsoleRune(cs, r)
			i += size
		}
	}
	renderConsoleState := func(f *os.File, cs *ntapi.ConsoleState) {
		if f == nil || cs == nil || !consoleAttached {
			return
		}
		_, _ = f.WriteString("\x1b[2J\x1b[H")
		lastAttr := uint16(0xFFFF)
		for y := 0; y < cs.Height; y++ {
			for x := 0; x < cs.Width; x++ {
				cell := cs.Cells[y*cs.Width+x]
				if cell.Attr != lastAttr {
					_, _ = f.WriteString(attrToANSI(cell.Attr))
					lastAttr = cell.Attr
				}
				r := rune(cell.Char)
				if r == 0 {
					r = ' '
				}
				_, _ = f.WriteString(string(r))
			}
			if y+1 < cs.Height {
				_, _ = f.WriteString("\n")
			}
		}
		_, _ = f.WriteString(attrToANSI(cs.Attr))
		_, _ = f.WriteString(fmt.Sprintf("\x1b[%d;%dH", cs.CursorY+1, cs.CursorX+1))
	}
	refreshVisibleConsole := func(cs *ntapi.ConsoleState) {
		if isVisibleConsoleState(cs) {
			renderConsoleState(os.Stdout, cs)
		}
	}
	emitConsoleTitle := func(title string) {
		if !consoleAttached {
			return
		}
		_, _ = os.Stdout.WriteString("\x1b]0;" + title + "\x07")
	}
	writeConsoleString := func(handle uint64, text string, rawBytes []byte) int {
		cs := resolveConsoleState(handle)
		if cs == nil {
			return 0
		}
		applyConsoleText(cs, text)
		if !consoleAttached {
			return len(text)
		}
		var out *os.File
		if handle == stdErrorHandleValue {
			out = os.Stderr
		} else {
			out = os.Stdout
		}
		mode := outputModeForHandle(handle)
		if len(rawBytes) > 0 {
			_, _ = out.Write(rawBytes)
			return len(rawBytes)
		}
		if mode&enableVTProcessing != 0 || true {
			_, _ = out.WriteString(text)
			return len(text)
		}
		return len(text)
	}
	consoleFillStateChars := func(cs *ntapi.ConsoleState, x, y, n int, ch uint16, attr uint16) int {
		if cs == nil || cs.Width <= 0 || cs.Height <= 0 || n <= 0 {
			return 0
		}
		wrote := 0
		for i := 0; i < n; i++ {
			cx := x + i
			cy := y
			for cx >= cs.Width {
				cx -= cs.Width
				cy++
			}
			if cy < 0 || cy >= cs.Height || cx < 0 || cx >= cs.Width {
				break
			}
			cs.Cells[cy*cs.Width+cx] = ntapi.ConsoleCellAttr{Char: ch, Attr: attr}
			wrote++
		}
		return wrote
	}
	consoleFillStateAttrs := func(cs *ntapi.ConsoleState, x, y, n int, attr uint16) int {
		if cs == nil || cs.Width <= 0 || cs.Height <= 0 || n <= 0 {
			return 0
		}
		wrote := 0
		for i := 0; i < n; i++ {
			cx := x + i
			cy := y
			for cx >= cs.Width {
				cx -= cs.Width
				cy++
			}
			if cy < 0 || cy >= cs.Height || cx < 0 || cx >= cs.Width {
				break
			}
			cell := &cs.Cells[cy*cs.Width+cx]
			cell.Attr = attr
			wrote++
		}
		return wrote
	}
	consoleVKForRune := func(r rune) uint16 {
		switch r {
		case '\b':
			return 0x08
		case '\t':
			return 0x09
		case '\n', '\r':
			return 0x0D
		case 0x1b:
			return 0x1B
		}
		if r >= 'a' && r <= 'z' {
			return uint16(r - 'a' + 'A')
		}
		if r >= 'A' && r <= 'Z' {
			return uint16(r)
		}
		if r >= '0' && r <= '9' {
			return uint16(r)
		}
		return uint16(r)
	}
	makeConsoleKeyEvent := func(r rune) consoleInputEvent {
		ascii := byte(0)
		if r >= 0 && r <= 0xFF {
			ascii = byte(r)
		}
		u := uint16('?')
		if r >= 0 && r <= 0xFFFF {
			u = uint16(r)
		}
		return consoleInputEvent{
			KeyDown:         true,
			RepeatCount:     1,
			VirtualKeyCode:  consoleVKForRune(r),
			UnicodeChar:     u,
			AsciiChar:       ascii,
			ControlKeyState: 0,
		}
	}
	makeSpecialConsoleKeyEvent := func(vk uint16, unicode rune) consoleInputEvent {
		evt := makeConsoleKeyEvent(unicode)
		evt.VirtualKeyCode = vk
		if unicode == 0 {
			evt.UnicodeChar = 0
			evt.AsciiChar = 0
		}
		return evt
	}
	enqueueConsoleEvent := func(evt consoleInputEvent) {
		consoleInputMu.Lock()
		consoleInputQueue = append(consoleInputQueue, evt)
		consoleInputCond.Broadcast()
		consoleInputMu.Unlock()
	}
	writeConsoleInputRecord := func(addr uint64, evt consoleInputEvent) {
		ctxBool := uint32(0)
		if evt.KeyDown {
			ctxBool = 1
		}
		mem.Write16(addr+0, keyEventRecordType)
		mem.Write16(addr+2, 0)
		mem.Write32(addr+4, ctxBool)
		mem.Write16(addr+8, evt.RepeatCount)
		mem.Write16(addr+10, evt.VirtualKeyCode)
		mem.Write16(addr+12, evt.VirtualScanCode)
		mem.Write16(addr+14, evt.UnicodeChar)
		mem.Write32(addr+16, evt.ControlKeyState)
	}
	dequeueConsoleEvent := func(block bool) (consoleInputEvent, bool) {
		consoleInputMu.Lock()
		defer consoleInputMu.Unlock()
		for len(consoleInputQueue) == 0 {
			if !block {
				return consoleInputEvent{}, false
			}
			consoleInputCond.Wait()
		}
		evt := consoleInputQueue[0]
		consoleInputQueue = append(consoleInputQueue[:0], consoleInputQueue[1:]...)
		return evt, true
	}
	peekConsoleEvents := func(limit int) []consoleInputEvent {
		consoleInputMu.Lock()
		defer consoleInputMu.Unlock()
		if limit <= 0 || limit > len(consoleInputQueue) {
			limit = len(consoleInputQueue)
		}
		out := make([]consoleInputEvent, limit)
		copy(out, consoleInputQueue[:limit])
		return out
	}
	readConsoleText := func(maxChars int, ansi bool) ([]byte, []uint16) {
		if maxChars <= 0 {
			return nil, nil
		}
		ans := make([]byte, 0, maxChars)
		wide := make([]uint16, 0, maxChars)
		for len(wide) < maxChars {
			evt, ok := dequeueConsoleEvent(true)
			if !ok {
				break
			}
			if evt.UnicodeChar == 0 && evt.AsciiChar == 0 {
				continue
			}
			ch := evt.UnicodeChar
			if ch == '\r' {
				ch = '\n'
			}
			wide = append(wide, ch)
			if ansi {
				b := evt.AsciiChar
				if b == 0 {
					b = '?'
				}
				if ch == '\n' {
					b = '\n'
				}
				ans = append(ans, b)
			}
			if ch == '\n' {
				break
			}
		}
		return ans, wide
	}
	readConsoleEventFromReader := func() (consoleInputEvent, bool) {
		if stdinReader == nil {
			return consoleInputEvent{}, false
		}
		b, err := stdinReader.ReadByte()
		if err != nil {
			return consoleInputEvent{}, false
		}
		if b == 0x1b {
			if stdinReader.Buffered() > 0 {
				next, err := stdinReader.ReadByte()
				if err != nil {
					return makeSpecialConsoleKeyEvent(0x1B, 0x1b), true
				}
				if next == '[' || next == 'O' {
					seq := []byte{next}
					for stdinReader.Buffered() > 0 {
						part, err := stdinReader.ReadByte()
						if err != nil {
							break
						}
						seq = append(seq, part)
						if part >= 0x40 && part <= 0x7E {
							break
						}
					}
					if len(seq) >= 2 {
						final := seq[len(seq)-1]
						switch final {
						case 'A':
							return makeSpecialConsoleKeyEvent(0x26, 0), true
						case 'B':
							return makeSpecialConsoleKeyEvent(0x28, 0), true
						case 'C':
							return makeSpecialConsoleKeyEvent(0x27, 0), true
						case 'D':
							return makeSpecialConsoleKeyEvent(0x25, 0), true
						case 'H':
							return makeSpecialConsoleKeyEvent(0x24, 0), true
						case 'F':
							return makeSpecialConsoleKeyEvent(0x23, 0), true
						case '~':
							param := string(seq[1 : len(seq)-1])
							switch param {
							case "1", "7":
								return makeSpecialConsoleKeyEvent(0x24, 0), true
							case "4", "8":
								return makeSpecialConsoleKeyEvent(0x23, 0), true
							case "3":
								return makeSpecialConsoleKeyEvent(0x2E, 0), true
							}
						}
					}
				} else {
					_ = stdinReader.UnreadByte()
				}
			}
			return makeSpecialConsoleKeyEvent(0x1B, 0x1b), true
		}
		if b < utf8.RuneSelf {
			if b == '\r' {
				b = '\n'
			}
			return makeConsoleKeyEvent(rune(b)), true
		}
		buf := []byte{b}
		for !utf8.FullRune(buf) {
			next, err := stdinReader.ReadByte()
			if err != nil {
				break
			}
			buf = append(buf, next)
		}
		r, _ := utf8.DecodeRune(buf)
		if r == utf8.RuneError {
			r = rune(buf[0])
		}
		return makeConsoleKeyEvent(r), true
	}
	go func() {
		for {
			evt, ok := readConsoleEventFromReader()
			if !ok {
				return
			}
			enqueueConsoleEvent(evt)
		}
	}()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		for range sigCh {
			consoleCtrlMu.Lock()
			ignore := consoleCtrlIgnore
			hasAny := ignore || len(consoleCtrlHandlers) > 0
			consoleCtrlMu.Unlock()
			if hasAny {
				evt := makeSpecialConsoleKeyEvent(0x03, 0x03)
				evt.ControlKeyState = 0x0008
				enqueueConsoleEvent(evt)
			}
		}
	}()
	readEnvironmentBlockA := func(addr uint64) map[string]string {
		env := map[string]string{}
		if addr == 0 {
			return env
		}
		var entry []byte
		for off := uint64(0); ; off++ {
			b, err := mem.Read8(addr + off)
			if err != nil {
				break
			}
			if b == 0 {
				if len(entry) == 0 {
					break
				}
				line := string(entry)
				if eq := strings.IndexByte(line, '='); eq > 0 {
					env[line[:eq]] = line[eq+1:]
				}
				entry = entry[:0]
				continue
			}
			entry = append(entry, b)
		}
		return env
	}
	readEnvironmentBlockW := func(addr uint64) map[string]string {
		env := map[string]string{}
		if addr == 0 {
			return env
		}
		var entry []uint16
		for off := uint64(0); ; off += 2 {
			w, err := mem.Read16(addr + off)
			if err != nil {
				break
			}
			if w == 0 {
				if len(entry) == 0 {
					break
				}
				line := string(utf16.Decode(entry))
				if eq := strings.IndexByte(line, '='); eq > 0 {
					env[line[:eq]] = line[eq+1:]
				}
				entry = entry[:0]
				continue
			}
			entry = append(entry, w)
		}
		return env
	}
	runKernel32TrivialHandler := func(ctx *ntapi.TrapContext, name string, argc int, defaultRet uint64) uint32 {
		args := captureKernel32Args(ctx, argc)
		ret := defaultRet
		lastErr := uint32(0)

		switch name {
		case "CloseConsoleHandle", "CloseSystemHandle", "CloseThreadpool", "CloseThreadpoolCleanupGroup":
			if len(args) > 0 && args[0] != 0 {
				handles.Close(ntapi.Handle(args[0]))
			}
		case "CloseThreadpoolCleanupGroupMembers":
			if len(args) > 0 && args[0] != 0 {
				handles.Close(ntapi.Handle(args[0]))
			}
		case "CreateBoundaryDescriptorA":
			nameA := ""
			if len(args) > 0 && args[0] != 0 {
				nameA = readGuestString(args[0])
			}
			flags := uint32(0)
			if len(args) > 1 {
				flags = uint32(args[1])
			}
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "boundary_descriptor"})
			boundaryDescriptorMu.Lock()
			boundaryDescriptorInfoMap[uint64(h)] = boundaryDescriptorInfo{Name: nameA, Flags: flags}
			boundaryDescriptorMu.Unlock()
			ret = uint64(h)
		case "CreateBoundaryDescriptorW":
			nameW := ""
			if len(args) > 0 && args[0] != 0 {
				nameW = readGuestUTF16(args[0])
			}
			flags := uint32(0)
			if len(args) > 1 {
				flags = uint32(args[1])
			}
			h := handles.Alloc(&ntapi.GenericHandle{Kind: "boundary_descriptor"})
			boundaryDescriptorMu.Lock()
			boundaryDescriptorInfoMap[uint64(h)] = boundaryDescriptorInfo{Name: nameW, Flags: flags}
			boundaryDescriptorMu.Unlock()
			ret = uint64(h)
		case "DeleteSynchronizationBarrier":
			if len(args) > 0 && args[0] != 0 {
				syncBarrierMu.Lock()
				delete(syncBarriers, args[0])
				syncBarrierMu.Unlock()
			}
		case "InitializeSynchronizationBarrier":
			if len(args) >= 3 && args[0] != 0 {
				syncBarrierMu.Lock()
				syncBarriers[args[0]] = &syncBarrierInfo{Participants: uint32(args[1]), SpinCount: uint32(args[2])}
				syncBarrierMu.Unlock()
			}
		case "EnterSynchronizationBarrier":
			if len(args) > 0 && args[0] != 0 {
				syncBarrierMu.Lock()
				if barrier := syncBarriers[args[0]]; barrier != nil {
					barrier.EnterCount++
				}
				syncBarrierMu.Unlock()
			}
		case "SetTimerQueueTimer":
			if len(args) >= 7 {
				h := handles.Alloc(&ntapi.GenericHandle{Kind: "timerqueue_timer"})
				timerQueueMu.Lock()
				timerQueues[uint64(h)] = &timerQueueInfo{Queue: args[1], Callback: args[2], Parameter: args[3], DueTime: uint32(args[4]), Period: uint32(args[5]), Flags: uint32(args[6])}
				timerQueueMu.Unlock()
				if args[0] != 0 {
					ctx.Mem.Write64(args[0], uint64(h))
				}
				ret = 1
			}
		case "ChangeTimerQueueTimer":
			if len(args) >= 4 {
				timerQueueMu.Lock()
				if timer := timerQueues[args[1]]; timer != nil {
					timer.Queue = args[0]
					timer.DueTime = uint32(args[2])
					timer.Period = uint32(args[3])
				}
				timerQueueMu.Unlock()
			}
		case "CancelTimerQueueTimer":
			if len(args) >= 2 {
				timerQueueMu.Lock()
				delete(timerQueues, args[1])
				timerQueueMu.Unlock()
				handles.Close(ntapi.Handle(args[1]))
			}
		case "GetThreadErrorMode":
			threadErrorModeMu.Lock()
			ret = uint64(threadErrorMode)
			threadErrorModeMu.Unlock()
		case "SetFileApisToANSI":
			fileApisANSI = true
		case "SetFileApisToOEM":
			fileApisANSI = false
		case "AreFileApisANSI":
			if fileApisANSI {
				ret = 1
			} else {
				ret = 0
			}
		case "GetActiveProcessorCount", "GetMaximumProcessorCount":
			count := runtime.NumCPU()
			if count < 1 {
				count = 1
			}
			ret = uint64(count)
		case "GetActiveProcessorGroupCount", "GetMaximumProcessorGroupCount":
			ret = 1
		case "GetCurrentProcessorNumber":
			count := runtime.NumCPU()
			if count < 1 {
				count = 1
			}
			ret = uint64(time.Since(startTime).Nanoseconds()) % uint64(count)
		case "SetStdHandleEx":
			if len(args) >= 3 {
				stdHandleMu.Lock()
				prev := stdHandleMap[uint32(args[0])]
				stdHandleMap[uint32(args[0])] = args[1]
				stdHandleMu.Unlock()
				if args[2] != 0 {
					ctx.Mem.Write64(args[2], prev)
				}
				ret = 1
			}
		case "SetProcessPreferredUILanguages":
			if len(args) >= 3 {
				lang := ""
				if args[1] != 0 {
					lang = readGuestUTF16(args[1])
				}
				if lang == "" {
					lang = "en-US"
				}
				preferredUILanguagesMu.Lock()
				processPreferredUILanguages = lang
				preferredUILanguagesMu.Unlock()
				if args[2] != 0 {
					ctx.Mem.Write32(args[2], 1)
				}
				ret = 1
			}
		case "GetProcessPreferredUILanguages":
			preferredUILanguagesMu.Lock()
			lang := processPreferredUILanguages
			preferredUILanguagesMu.Unlock()
			if lang == "" {
				lang = "en-US"
			}
			if len(args) >= 4 {
				if args[0]&4 != 0 {
					lang = "0409"
				}
				required := uint32(len(utf16Encode(lang)) + 2)
				if args[1] != 0 {
					ctx.Mem.Write32(args[1], 1)
				}
				if args[3] != 0 {
					ctx.Mem.Write32(args[3], required)
				}
				if args[2] != 0 {
					writeUTF16String(args[2], lang, uint64(required))
					ctx.Mem.Write16(args[2]+uint64(len(utf16Encode(lang))+1)*2, 0)
				}
				ret = 1
			}
		case "GetSystemFileCacheSize":
			if len(args) >= 3 {
				if args[0] != 0 {
					ctx.Mem.Write64(args[0], systemFileCacheMin)
				}
				if args[1] != 0 {
					ctx.Mem.Write64(args[1], systemFileCacheMax)
				}
				if args[2] != 0 {
					ctx.Mem.Write32(args[2], systemFileCacheFlags)
				}
				ret = 1
			}
		case "SetSystemFileCacheSize":
			if len(args) >= 3 {
				systemFileCacheMin = args[0]
				systemFileCacheMax = args[1]
				systemFileCacheFlags = uint32(args[2])
				ret = 1
			}
		case "GetProcessWorkingSetSizeEx":
			if len(args) >= 4 {
				if args[1] != 0 {
					ctx.Mem.Write64(args[1], processWorkingSetMin)
				}
				if args[2] != 0 {
					ctx.Mem.Write64(args[2], processWorkingSetMax)
				}
				if args[3] != 0 {
					ctx.Mem.Write32(args[3], processWorkingSetFlags)
				}
				ret = 1
			}
		case "SetProcessWorkingSetSizeEx":
			if len(args) >= 4 {
				processWorkingSetMin = args[1]
				processWorkingSetMax = args[2]
				processWorkingSetFlags = uint32(args[3])
				ret = 1
			}
		case "GetThreadIOPendingFlag":
			if len(args) >= 2 && args[1] != 0 {
				ctx.Mem.Write32(args[1], 0)
			}
			ret = 1
		case "GetHandleContext":
			if len(args) > 0 {
				handleContextMu.Lock()
				ret = handleContexts[args[0]]
				handleContextMu.Unlock()
			}
		case "SetHandleContext":
			if len(args) >= 2 {
				handleContextMu.Lock()
				handleContexts[args[0]] = args[1]
				handleContextMu.Unlock()
			}
		case "GetDaylightFlag":
			ret = stateScalars["daylightFlag"]
		case "SetDaylightFlag":
			if len(args) > 0 {
				stateScalars["daylightFlag"] = args[0] & 1
			}
		case "SetProcessAffinityUpdateMode":
			if len(args) > 0 {
				stateScalars["processAffinityMode"] = args[len(args)-1]
			}
			ret = 1
		case "SetSearchPathMode":
			if len(args) > 0 {
				stateScalars["searchPathMode"] = args[0]
			}
			ret = 1
		case "WTSGetActiveConsoleSessionId":
			ret = stateScalars["activeConsoleSessionID"]
		case "GetVolumePathNameA":
			if len(args) >= 3 {
				writeANSIString(args[1], "C:\\", args[2])
				ret = 1
			}
		case "SetVolumeLabelA":
			if len(args) >= 2 {
				volumeMu.Lock()
				volumeLabels[strings.ToLower(readGuestString(args[0]))] = readGuestString(args[1])
				volumeMu.Unlock()
				ret = 1
			}
		case "SetVolumeLabelW":
			if len(args) >= 2 {
				volumeMu.Lock()
				volumeLabels[strings.ToLower(readGuestUTF16(args[0]))] = readGuestUTF16(args[1])
				volumeMu.Unlock()
				ret = 1
			}
		case "SetVolumeMountPointA":
			if len(args) >= 2 {
				volumeMu.Lock()
				volumeMountPoints[strings.ToLower(readGuestString(args[0]))] = readGuestString(args[1])
				volumeMu.Unlock()
				ret = 1
			}
		case "SetVolumeMountPointW":
			if len(args) >= 2 {
				volumeMu.Lock()
				volumeMountPoints[strings.ToLower(readGuestUTF16(args[0]))] = readGuestUTF16(args[1])
				volumeMu.Unlock()
				ret = 1
			}
		case "DeleteVolumeMountPointA":
			if len(args) > 0 {
				volumeMu.Lock()
				delete(volumeMountPoints, strings.ToLower(readGuestString(args[0])))
				volumeMu.Unlock()
				ret = 1
			}
		case "DeleteVolumeMountPointW":
			if len(args) > 0 {
				volumeMu.Lock()
				delete(volumeMountPoints, strings.ToLower(readGuestUTF16(args[0])))
				volumeMu.Unlock()
				ret = 1
			}
		case "DefineDosDeviceA":
			if len(args) >= 3 {
				devName := strings.ToUpper(readGuestString(args[1]))
				target := readGuestString(args[2])
				dosDeviceMu.Lock()
				if uint32(args[0])&0x2 != 0 {
					delete(dosDeviceMap, devName)
				} else if devName != "" {
					dosDeviceMap[devName] = target
				}
				dosDeviceMu.Unlock()
				ret = 1
			}
		case "DefineDosDeviceW":
			if len(args) >= 3 {
				devName := strings.ToUpper(readGuestUTF16(args[1]))
				target := readGuestUTF16(args[2])
				dosDeviceMu.Lock()
				if uint32(args[0])&0x2 != 0 {
					delete(dosDeviceMap, devName)
				} else if devName != "" {
					dosDeviceMap[devName] = target
				}
				dosDeviceMu.Unlock()
				ret = 1
			}
		case "QueryDosDeviceA":
			if len(args) >= 3 {
				devName := "C:"
				if args[0] != 0 {
					devName = strings.ToUpper(readGuestString(args[0]))
				}
				dosDeviceMu.Lock()
				target := dosDeviceMap[devName]
				dosDeviceMu.Unlock()
				if target == "" {
					target = `\\Device\\HarddiskVolume1`
				}
				ret = writeANSIString(args[1], target, args[2]) - 1
			}
		case "QueryDosDeviceW":
			if len(args) >= 3 {
				devName := "C:"
				if args[0] != 0 {
					devName = strings.ToUpper(readGuestUTF16(args[0]))
				}
				dosDeviceMu.Lock()
				target := dosDeviceMap[devName]
				dosDeviceMu.Unlock()
				if target == "" {
					target = `\\Device\\HarddiskVolume1`
				}
				ret = writeUTF16String(args[1], target, args[2]) - 1
			}
		case "SetEnvironmentStringsA":
			if len(args) > 0 {
				newEnv := readEnvironmentBlockA(args[0])
				for k := range envVars {
					delete(envVars, k)
				}
				for k, v := range newEnv {
					envVars[k] = v
				}
				ret = 1
			}
		case "SetEnvironmentStringsW":
			if len(args) > 0 {
				newEnv := readEnvironmentBlockW(args[0])
				for k := range envVars {
					delete(envVars, k)
				}
				for k, v := range newEnv {
					envVars[k] = v
				}
				ret = 1
			}
		case "NeedCurrentDirectoryForExePathA":
			ret = 1
			if len(args) > 0 && args[0] != 0 {
				if strings.ContainsAny(readGuestString(args[0]), `\/:`) {
					ret = 0
				}
			}
		case "NeedCurrentDirectoryForExePathW":
			ret = 1
			if len(args) > 0 && args[0] != 0 {
				if strings.ContainsAny(readGuestUTF16(args[0]), `\/:`) {
					ret = 0
				}
			}
		case "GetDynamicTimeZoneInformationEffectiveYears":
			year := uint16(time.Now().Year())
			if len(args) >= 2 {
				if args[0] != 0 {
					ctx.Mem.Write16(args[0], year)
				}
				if args[1] != 0 {
					ctx.Mem.Write16(args[1], year)
				}
				ret = 1
			}
		case "SetUserGeoID":
			if len(args) > 0 {
				stateScalars["userGeoID"] = args[0]
			}
			ret = 1
		case "SetUserGeoName":
			if len(args) > 0 && args[0] != 0 {
				userGeoName = readGuestUTF16(args[0])
			}
			ret = 1
		case "GetNamedPipeClientProcessId", "GetNamedPipeServerProcessId":
			if len(args) >= 2 && args[1] != 0 {
				ctx.Mem.Write32(args[1], 1)
				ret = 1
			}
		case "GetNamedPipeClientSessionId", "GetNamedPipeServerSessionId":
			if len(args) >= 2 && args[1] != 0 {
				ctx.Mem.Write32(args[1], uint32(stateScalars["activeConsoleSessionID"]))
				ret = 1
			}
		case "QueryIdleProcessorCycleTimeEx":
			if len(args) >= 3 {
				if args[1] != 0 {
					ctx.Mem.Write32(args[1], 1)
				}
				if args[2] != 0 {
					ctx.Mem.Write64(args[2], uint64(time.Since(startTime).Nanoseconds()))
				}
				ret = 1
			}
		case "QueryNumberOfEventLogRecords":
			if len(args) >= 2 && args[1] != 0 {
				ctx.Mem.Write32(args[1], 0)
			}
			ret = 1
		case "QueryOldestEventLogRecord":
			if len(args) >= 2 && args[1] != 0 {
				ctx.Mem.Write32(args[1], 1)
			}
			ret = 1
		case "InvalidateNLSCache":
			stateScalars["nlsCacheGeneration"]++
		case "NotifyNLSUserCache":
			stateScalars["nlsUserCacheNotify"]++
		case "SetCachedSigningLevel":
			if len(args) >= 5 {
				cachedSigningLevelMu.Lock()
				cachedSigningLevels[args[4]] = uint32(args[1])
				cachedSigningLevelMu.Unlock()
				ret = 1
			}
		case "RtlAddFunctionTable":
			if len(args) >= 3 && ntapi.AddDynamicFunctionTable(ctx.Mem, args[0], uint32(args[1]), args[2]) {
				ret = 1
			}
		case "RtlDeleteFunctionTable":
			if len(args) > 0 && ntapi.DeleteDynamicFunctionTable(args[0]) {
				ret = 1
			}
		case "RtlInstallFunctionTableCallback":
			if len(args) >= 5 && ntapi.InstallDynamicFunctionTableCallback(args[0], args[1], args[2], args[3], args[4]) {
				ret = 1
			}
		case "RtlLookupFunctionEntry":
			if len(args) >= 3 {
				_, imageBase, entryAddr := ntapi.LookupFunctionEntry(ctx.Mem, args[0], func(addr uint64, callArgs []uint64) (uint64, error) {
					return callGuest(ctx, addr, callArgs)
				})
				if args[1] != 0 {
					ctx.Mem.Write64(args[1], imageBase)
				}
				ret = entryAddr
			}
		case "RtlVirtualUnwind":
			if len(args) >= 8 {
				contextRecord, err := ntapi.ReadAMD64Context(ctx.Mem, args[4])
				if err == nil {
					functionEntry := ntapi.ReadRuntimeFunctionEntry(ctx.Mem, args[3])
					if functionEntry == nil {
						functionEntry, _, _ = ntapi.LookupFunctionEntry(ctx.Mem, args[2], func(addr uint64, callArgs []uint64) (uint64, error) {
							return callGuest(ctx, addr, callArgs)
						})
					}
					handlerAddr, handlerData, establisherFrame, err := ntapi.VirtualUnwind(
						ctx.Mem,
						uint32(args[0]),
						args[1],
						args[2],
						functionEntry,
						contextRecord,
					)
					if err == nil {
						_ = ntapi.WriteAMD64Context(ctx.Mem, args[4], contextRecord)
						if args[5] != 0 {
							ctx.Mem.Write64(args[5], handlerData)
						}
						if args[6] != 0 {
							ctx.Mem.Write64(args[6], establisherFrame)
						}
						ret = handlerAddr
					}
				}
			}
		case "GetWriteWatch":
			if len(args) >= 6 {
				if args[4] != 0 {
					ctx.Mem.Write64(args[4], 0)
				}
				if args[5] != 0 {
					ctx.Mem.Write32(args[5], 4096)
				}
				ret = 0
			}
		case "WerGetFlags":
			if len(args) >= 2 && args[1] != 0 {
				werMu.Lock()
				ctx.Mem.Write32(args[1], werFlags)
				werMu.Unlock()
			}
			ret = 0
		case "WerSetFlags":
			if len(args) > 0 {
				werMu.Lock()
				werFlags = uint32(args[0])
				werMu.Unlock()
			}
			ret = 0
		case "WerRegisterCustomMetadata":
			if len(args) >= 2 {
				werMu.Lock()
				werMetadata[readGuestUTF16(args[0])] = readGuestUTF16(args[1])
				werMu.Unlock()
			}
			ret = 0
		case "WerUnregisterCustomMetadata":
			if len(args) > 0 {
				werMu.Lock()
				delete(werMetadata, readGuestUTF16(args[0]))
				werMu.Unlock()
			}
			ret = 0
		case "WerRegisterFile":
			if len(args) >= 2 {
				werMu.Lock()
				werFiles[readGuestUTF16(args[0])] = uint32(args[1])
				werMu.Unlock()
			}
			ret = 0
		case "WerUnregisterFile":
			if len(args) > 0 {
				werMu.Lock()
				delete(werFiles, readGuestUTF16(args[0]))
				werMu.Unlock()
			}
			ret = 0
		case "WerRegisterRuntimeExceptionModule":
			if len(args) >= 2 {
				werMu.Lock()
				werRuntimeModules[readGuestUTF16(args[0])] = args[1]
				werMu.Unlock()
			}
			ret = 0
		case "WerUnregisterRuntimeExceptionModule":
			if len(args) > 0 {
				werMu.Lock()
				delete(werRuntimeModules, readGuestUTF16(args[0]))
				werMu.Unlock()
			}
			ret = 0
		case "RegisterServiceProcess":
			if len(args) >= 2 {
				stateScalars["termsrvAppInstallMode"] = args[1]
			}
			ret = 1
		case "TermsrvAppInstallMode":
			ret = stateScalars["termsrvAppInstallMode"]
		case "SetTermsrvAppInstallMode":
			if len(args) > 0 {
				stateScalars["termsrvAppInstallMode"] = args[0]
			}
		case "timeBeginPeriod":
			if len(args) > 0 {
				timePeriodMu.Lock()
				timePeriodRequests[uint32(args[0])]++
				timePeriodMu.Unlock()
			}
			ret = 0
		case "timeEndPeriod":
			if len(args) > 0 {
				timePeriodMu.Lock()
				period := uint32(args[0])
				if timePeriodRequests[period] > 1 {
					timePeriodRequests[period]--
				} else {
					delete(timePeriodRequests, period)
				}
				timePeriodMu.Unlock()
			}
			ret = 0
		case "GetACP":
			ret = 1252
		case "GetOEMCP":
			ret = 437
		case "GetGeoInfoEx":
			if len(args) >= 4 {
				ret = writeUTF16String(args[2], userGeoName, args[3]) - 1
			}
		case "_DebugOut", "_DebugPrintf", "dprintf":
			if len(args) > 0 && args[0] != 0 {
				ravelog.Logf("[kernel32] %s message=%q\n", name, readGuestString(args[0]))
			}
		case "wine_get_dos_file_name":
			if len(args) > 0 && args[0] != 0 {
				unixPath := readGuestString(args[0])
				winPath := strings.ReplaceAll(filepath.Clean(unixPath), "/", "\\")
				if strings.HasPrefix(winPath, "\\") {
					winPath = "Z:" + winPath
				} else if !strings.Contains(winPath, ":") {
					winPath = "Z:\\" + winPath
				}
				buf := sharedHeapAlloc(uint64((len(utf16Encode(winPath))+1)*2), true)
				writeUTF16String(buf, winPath, uint64(len(utf16Encode(winPath))+1))
				ret = buf
			}
		case "wine_get_unix_file_name":
			if len(args) > 0 && args[0] != 0 {
				winPath := readGuestUTF16(args[0])
				unixPath := strings.ReplaceAll(winPath, "\\", "/")
				if len(unixPath) >= 2 && unixPath[1] == ':' {
					unixPath = unixPath[2:]
				}
				if !strings.HasPrefix(unixPath, "/") {
					unixPath = "/" + unixPath
				}
				buf := sharedHeapAlloc(uint64(len(unixPath)+1), true)
				writeANSIString(buf, unixPath, uint64(len(unixPath)+1))
				ret = buf
			}
		}

		recordKernel32Call(name, args, ret, lastErr)
		if ret != 0 || lastErr != 0 {
			setLastErrorValue(lastErr)
		}
		if argsText := formatKernel32Args(args); argsText != "" {
			ravelog.Logf("[kernel32] %s(%s) => 0x%x\n", name, argsText, ret)
		} else {
			ravelog.Logf("[kernel32] %s() => 0x%x\n", name, ret)
		}
		ctx.SetReturn(ret)
		return 0
	}

	// resolveResourceModule returns (baseAddr, rsrcDirRVA) for the given hModule.
	// If hModule is 0 or matches the main module, use MainModule's fields.
	resolveResourceModule := func(hModule uint64) (uint64, uint32) {
		if mainModule == nil {
			return 0, 0
		}
		if hModule == 0 || hModule == mainModule.BaseAddr {
			return mainModule.BaseAddr, mainModule.ResourceDirRVA
		}
		// For other modules we don't have resource directory info; return zero.
		return hModule, 0
	}
	// rsrcDirEntries reads the ID entries from a resource directory at dirAddr.
	// Returns a slice of entry IDs (only ID entries, not named entries).
	rsrcDirEntries := func(dirAddr uint64) []uint32 {
		if dirAddr == 0 {
			return nil
		}
		namedCount, _ := mem.Read16(dirAddr + 12)
		idCount, _ := mem.Read16(dirAddr + 14)
		entryBase := dirAddr + 16 + uint64(namedCount)*8
		ids := make([]uint32, 0, idCount)
		for i := uint16(0); i < idCount; i++ {
			eID, _ := mem.Read32(entryBase + uint64(i)*8)
			ids = append(ids, eID)
		}
		return ids
	}
	// rsrcFindSubdir finds a subdirectory entry by ID within a resource directory.
	// Returns the subdirectory address, or 0 if not found.
	rsrcFindSubdir := func(dirAddr, rsrcBase uint64, id uint32) uint64 {
		if dirAddr == 0 {
			return 0
		}
		namedCount, _ := mem.Read16(dirAddr + 12)
		idCount, _ := mem.Read16(dirAddr + 14)
		entryBase := dirAddr + 16 + uint64(namedCount)*8
		for i := uint16(0); i < idCount; i++ {
			eID, _ := mem.Read32(entryBase + uint64(i)*8)
			eOff, _ := mem.Read32(entryBase + uint64(i)*8 + 4)
			if eID == id && eOff&0x80000000 != 0 {
				return rsrcBase + uint64(eOff&0x7FFFFFFF)
			}
		}
		return 0
	}
	kernel32, ok := hctx.SynthByName["kernel32.dll"]
	if !ok {
		return
	}
	_ = kernel32
	d.RegisterAutoStubHandler(kernel32, "GetStdHandle", func(ctx *ntapi.TrapContext) uint32 {
		nStdHandle := uint32(ctx.Arg(0))
		stdHandleMu.Lock()
		h, ok := stdHandleMap[nStdHandle]
		stdHandleMu.Unlock()
		if ok {
			ctx.SetReturn(h)
		} else {
			ctx.SetReturn(^uint64(0)) // INVALID_HANDLE_VALUE
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLastError", func(ctx *ntapi.TrapContext) uint32 {
		v, _ := ctx.Mem.Read32(procState.TEBAddr + ntapi.TebLastErrorValue)
		ctx.SetReturn(uint64(v))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetLastError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, uint32(ctx.Arg(0)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentProcess", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentProcess", 0, uint64(^uint64(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "IsDebuggerPresent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsDebuggerPresent", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetTickCount", func(ctx *ntapi.TrapContext) uint32 {
		ms := uint32(time.Since(hctx.BootTime).Milliseconds())
		ctx.SetReturn(uint64(ms))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetModuleHandleA", func(ctx *ntapi.TrapContext) uint32 {
		name := ctx.Arg(0)
		if name == 0 {
			// Read ImageBase from PEB
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
			ctx.SetReturn(imageBase)
		} else {
			modName := strings.ToLower(readGuestString(name))
			if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
				modName += ".dll"
			}
			if s, ok := synthByName[modName]; ok {
				ctx.SetReturn(s.BaseAddr)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetModuleHandleW", func(ctx *ntapi.TrapContext) uint32 {
		name := ctx.Arg(0)
		if name == 0 {
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
			ctx.SetReturn(imageBase)
		} else {
			modName := strings.ToLower(readGuestUTF16(name))
			if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
				modName += ".dll"
			}
			if s, ok := synthByName[modName]; ok {
				ctx.SetReturn(s.BaseAddr)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetModuleHandleExW", func(ctx *ntapi.TrapContext) uint32 {
		// dwFlags=arg0, lpModuleName=arg1, phModule=arg2
		modNamePtr := ctx.Arg(1)
		phModule := ctx.Arg(2)
		if modNamePtr == 0 {
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
			if phModule != 0 {
				ctx.Mem.Write64Raw(phModule, imageBase)
			}
			ctx.SetReturn(1) // TRUE
		} else {
			modName := strings.ToLower(readGuestUTF16(modNamePtr))
			if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
				modName += ".dll"
			}
			if s, ok := synthByName[modName]; ok {
				if phModule != 0 {
					ctx.Mem.Write64Raw(phModule, s.BaseAddr)
				}
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetStartupInfoA", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		for i := uint64(0); i < 104; i++ {
			ctx.Mem.Write8(addr+i, 0)
		}
		ctx.Mem.Write32(addr, 104)       // cb = sizeof(STARTUPINFOA) on x64
		ctx.Mem.Write32(addr+60, 0x0001) // dwFlags = STARTF_USESHOWWINDOW
		ctx.Mem.Write16(addr+64, 0x0001) // wShowWindow = SW_SHOWNORMAL
		return 0
	})
	// Win32 protection ↔ MMU permission helpers
	win32ProtToMMU := func(prot uint64) uint8 {
		switch prot & 0xFF {
		case 0x01: // PAGE_NOACCESS
			return 0
		case 0x02: // PAGE_READONLY
			return mmu.PermRead
		case 0x04: // PAGE_READWRITE
			return mmu.PermRead | mmu.PermWrite
		case 0x08: // PAGE_WRITECOPY → treat as RW
			return mmu.PermRead | mmu.PermWrite
		case 0x10: // PAGE_EXECUTE
			return mmu.PermExecute
		case 0x20: // PAGE_EXECUTE_READ
			return mmu.PermRead | mmu.PermExecute
		case 0x40: // PAGE_EXECUTE_READWRITE
			return mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		case 0x80: // PAGE_EXECUTE_WRITECOPY → treat as RWX
			return mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		default:
			return mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		}
	}
	mmuPermToWin32 := func(perms uint8) uint32 {
		switch {
		case perms&(mmu.PermRead|mmu.PermWrite|mmu.PermExecute) == mmu.PermRead|mmu.PermWrite|mmu.PermExecute:
			return 0x40 // PAGE_EXECUTE_READWRITE
		case perms&(mmu.PermRead|mmu.PermExecute) == mmu.PermRead|mmu.PermExecute:
			return 0x20 // PAGE_EXECUTE_READ
		case perms&(mmu.PermRead|mmu.PermWrite) == mmu.PermRead|mmu.PermWrite:
			return 0x04 // PAGE_READWRITE
		case perms&mmu.PermExecute != 0:
			return 0x10 // PAGE_EXECUTE
		case perms&mmu.PermRead != 0:
			return 0x02 // PAGE_READONLY
		default:
			return 0x01 // PAGE_NOACCESS
		}
	}
	d.RegisterAutoStubHandler(kernel32, "VirtualProtect", func(ctx *ntapi.TrapContext) uint32 {
		lpAddress := ctx.Arg(0)
		dwSize := ctx.Arg(1)
		flNewProtect := ctx.Arg(2)
		lpflOldProtect := ctx.Arg(3)
		// Query old permissions before changing
		_, _, mapped, oldPerms := mem.QueryRegion(lpAddress)
		if lpflOldProtect != 0 {
			if mapped {
				ctx.Mem.Write32(lpflOldProtect, mmuPermToWin32(oldPerms))
			} else {
				ctx.Mem.Write32(lpflOldProtect, 0x01) // PAGE_NOACCESS
			}
		}
		newPerms := win32ProtToMMU(flNewProtect)
		mem.Mprotect(lpAddress, dwSize, newPerms)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// InitializeCriticalSection / DeleteCriticalSection / EnterCriticalSection / LeaveCriticalSection: no-ops
	for _, name := range []string{"DeleteCriticalSection", "EnterCriticalSection", "LeaveCriticalSection"} {
		d.RegisterAutoStubHandler(kernel32, name, func(ctx *ntapi.TrapContext) uint32 {
			return 0
		})
	}
	d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSectionAndSpinCount", func(ctx *ntapi.TrapContext) uint32 {
		lp := ctx.Arg(0)
		spinCount := ctx.Arg(1)
		if lp != 0 {
			ctx.Mem.Write64(lp, 0)
			ctx.Mem.Write32(lp+8, 0xFFFFFFFF) // LockCount = -1
			ctx.Mem.Write32(lp+12, 0)
			ctx.Mem.Write64(lp+16, 0)
			ctx.Mem.Write64(lp+24, 0)
			ctx.Mem.Write64(lp+32, spinCount)
		}
		ctx.SetReturn(1) // TRUE = success
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSectionEx", func(ctx *ntapi.TrapContext) uint32 {
		lp := ctx.Arg(0)
		spinCount := ctx.Arg(1)
		if lp != 0 {
			ctx.Mem.Write64(lp, 0)
			ctx.Mem.Write32(lp+8, 0xFFFFFFFF) // LockCount = -1
			ctx.Mem.Write32(lp+12, 0)
			ctx.Mem.Write64(lp+16, 0)
			ctx.Mem.Write64(lp+24, 0)
			ctx.Mem.Write64(lp+32, spinCount)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// InterlockedXxx - atomic in-memory operations
	d.RegisterAutoStubHandler(kernel32, "InterlockedIncrement", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		v, _ := ctx.Mem.Read32(ptr)
		v++
		ctx.Mem.Write32(ptr, v)
		ctx.SetReturn(uint64(v))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedDecrement", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		v, _ := ctx.Mem.Read32(ptr)
		v--
		ctx.Mem.Write32(ptr, v)
		ctx.SetReturn(uint64(v))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedExchange", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		newVal := ctx.Arg(1)
		old, _ := ctx.Mem.Read32(ptr)
		ctx.Mem.Write32(ptr, uint32(newVal))
		ctx.SetReturn(uint64(old))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedCompareExchange", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		exchange := ctx.Arg(1)
		comparand := ctx.Arg(2)
		cur, _ := ctx.Mem.Read32(ptr)
		if uint64(cur) == comparand {
			ctx.Mem.Write32(ptr, uint32(exchange))
		}
		ctx.SetReturn(uint64(cur))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedExchangeAdd", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		addend := ctx.Arg(1)
		old, _ := ctx.Mem.Read32(ptr)
		ctx.Mem.Write32(ptr, old+uint32(addend))
		ctx.SetReturn(uint64(old))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedIncrement64", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		v, _ := ctx.Mem.Read64(ptr)
		v++
		ctx.Mem.Write64Raw(ptr, v)
		ctx.SetReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedDecrement64", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		v, _ := ctx.Mem.Read64(ptr)
		v--
		ctx.Mem.Write64Raw(ptr, v)
		ctx.SetReturn(v)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedExchange64", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		newVal := ctx.Arg(1)
		old, _ := ctx.Mem.Read64(ptr)
		ctx.Mem.Write64Raw(ptr, newVal)
		ctx.SetReturn(old)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedCompareExchange64", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		exchange := ctx.Arg(1)
		comparand := ctx.Arg(2)
		cur, _ := ctx.Mem.Read64(ptr)
		if cur == comparand {
			ctx.Mem.Write64Raw(ptr, exchange)
		}
		ctx.SetReturn(cur)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentThreadId", func(ctx *ntapi.TrapContext) uint32 {
		if *tmPtr != nil {
			tid := (*tmPtr).GetTID(ctx.CPU)
			ctx.SetReturn(uint64(tid))
		} else {
			ctx.SetReturn(1) // main thread TID=1
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentProcessId", 0, uint64(uint64(os.Getpid())))
	})
	d.RegisterAutoStubHandler(kernel32, "QueryPerformanceCounter", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		if ptr != 0 {
			// 10 MHz counter (100ns resolution) matching QueryPerformanceFrequency
			ns := time.Since(hctx.BootTime).Nanoseconds() / 100
			ctx.Mem.Write64Raw(ptr, uint64(ns))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryPerformanceFrequency", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(0)
		if ptr != 0 {
			ctx.Mem.Write64Raw(ptr, 10000000) // 10 MHz
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsProcessorFeaturePresent", func(ctx *ntapi.TrapContext) uint32 {
		feature := uint32(ctx.Arg(0))
		// Standard x86-64 features that are always present on any 64-bit CPU
		supported := map[uint32]bool{
			0:  true,  // PF_FLOATING_POINT_PRECISION_ERRATA (no errata)
			3:  true,  // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
			6:  true,  // PF_PAE_ENABLED
			7:  true,  // PF_NX_ENABLED
			8:  true,  // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2 - required for x64)
			9:  false, // PF_SSE3_INSTRUCTIONS_AVAILABLE
			10: true,  // PF_COMPARE_EXCHANGE128
			12: true,  // PF_CHANNELS_ENABLED
			13: true,  // PF_XSAVE_ENABLED
			17: true,  // PF_SSSE3_INSTRUCTIONS_AVAILABLE
			20: true,  // PF_FASTFAIL_AVAILABLE
			23: true,  // PF_RDTSC_INSTRUCTION_AVAILABLE
			36: true,  // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
			37: true,  // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
		}
		if supported[feature] {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// resolveApiSetDLL maps Windows API set names to their host DLL.
	// On real Windows, api-ms-win-core-* are virtual DLLs that redirect
	// to kernel32, user32, etc. We replicate this so GetProcAddress
	// finds the functions in the correct synth DLL.
	resolveApiSetDLL := func(name string) string {
		if !strings.HasPrefix(name, "api-ms-win-") && !strings.HasPrefix(name, "ext-ms-") {
			return name
		}
		// Map common API sets to their implementing DLL
		switch {
		case strings.HasPrefix(name, "api-ms-win-core-"):
			return "kernel32.dll"
		case strings.HasPrefix(name, "api-ms-win-crt-"):
			if _, ok := synthByName["ucrtbase.dll"]; ok {
				return "ucrtbase.dll"
			}
			return "msvcrt.dll"
		case strings.HasPrefix(name, "api-ms-win-security-"):
			return "advapi32.dll"
		case strings.HasPrefix(name, "api-ms-win-shcore-"):
			return "shcore.dll"
		default:
			return "kernel32.dll"
		}
	}
	d.RegisterAutoStubHandler(kernel32, "LoadLibraryExW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := strings.ToLower(readGuestUTF16(namePtr))
		if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
			name = name[idx+1:]
		}
		if !strings.HasSuffix(name, ".dll") {
			name += ".dll"
		}
		// Redirect API set DLLs to their real implementation
		resolved := resolveApiSetDLL(name)
		if resolved != name {
			if synth, ok := synthByName[resolved]; ok {
				synthByName[name] = synth // cache redirect
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		if synth, ok := synthByName[name]; ok {
			ctx.SetReturn(synth.BaseAddr)
			return 0
		}
		newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
		synthByName[name] = newSynth
		ravelog.Logf("[win32] LoadLibraryExW: auto-created stub for %q\n", name)
		ctx.SetReturn(newSynth.BaseAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LoadLibraryW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := strings.ToLower(readGuestUTF16(namePtr))
		if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
			name = name[idx+1:]
		}
		if !strings.HasSuffix(name, ".dll") {
			name += ".dll"
		}
		resolved := resolveApiSetDLL(name)
		if resolved != name {
			if synth, ok := synthByName[resolved]; ok {
				synthByName[name] = synth
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		if synth, ok := synthByName[name]; ok {
			ctx.SetReturn(synth.BaseAddr)
			return 0
		}
		newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
		synthByName[name] = newSynth
		ravelog.Logf("[win32] LoadLibraryW: auto-created stub for %q\n", name)
		ctx.SetReturn(newSynth.BaseAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LoadLibraryA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := strings.ToLower(readGuestString(namePtr))
		if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
			name = name[idx+1:]
		}
		if !strings.HasSuffix(name, ".dll") {
			name += ".dll"
		}
		resolved := resolveApiSetDLL(name)
		if resolved != name {
			if synth, ok := synthByName[resolved]; ok {
				synthByName[name] = synth
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		if synth, ok := synthByName[name]; ok {
			ctx.SetReturn(synth.BaseAddr)
			return 0
		}
		newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
		synthByName[name] = newSynth
		ravelog.Logf("[win32] LoadLibraryA: auto-created stub for %q\n", name)
		ctx.SetReturn(newSynth.BaseAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FreeLibrary", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL FreeLibrary(HMODULE hLibModule);
		// ReactOS: dll/win32/kernel32/client/loader.c
		// We use synthesized DLLs with no real ref-counting; always succeed.
		hModule := ctx.Arg(0)
		if hModule == 0 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcAddress", func(ctx *ntapi.TrapContext) uint32 {
		hModule := ctx.Arg(0)
		procNamePtr := ctx.Arg(1)
		if hModule == 0 || procNamePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Detect ordinal import (high word of pointer is 0 → low word is ordinal)
		hi, _ := ctx.Mem.Read32(procNamePtr + 2)
		var funcName string
		isOrdinal := hi == 0
		if isOrdinal {
			ordinal := uint16(procNamePtr & 0xFFFF)
			// Search all synths for this ordinal
			for _, s := range hctx.Dlls {
				if s.BaseAddr == hModule {
					if addr, ok := s.ExportOrds[ordinal]; ok {
						ctx.SetReturn(addr)
						return 0
					}
				}
			}
			for _, s := range synthByName {
				if s.BaseAddr == hModule {
					if addr, ok := s.ExportOrds[ordinal]; ok {
						ctx.SetReturn(addr)
						return 0
					}
				}
			}
			ctx.SetReturn(0)
			return 0
		}
		funcName = readGuestString(procNamePtr)
		// Search pre-loaded dlls slice first
		for _, s := range hctx.Dlls {
			if s.BaseAddr == hModule {
				if addr, ok := s.Exports[funcName]; ok {
					ctx.SetReturn(addr)
					return 0
				}
			}
		}
		// Also search synthByName (covers DLLs loaded via LoadLibraryW at runtime)
		for _, s := range synthByName {
			if s.BaseAddr == hModule {
				if addr, ok := s.Exports[funcName]; ok {
					ctx.SetReturn(addr)
					return 0
				}
			}
		}
		ravelog.Logf("[win32] GetProcAddress(0x%x, %q) → not found\n", hModule, funcName)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UnhandledExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
		if procState.UnhandledExceptionFilter == 0 || ctx.Arg(0) == 0 {
			ctx.SetReturn(ntapi.ExceptionContinueSearch)
			return 0
		}
		ret, err := callGuest(ctx, procState.UnhandledExceptionFilter, []uint64{ctx.Arg(0)})
		if err != nil {
			ctx.SetReturn(ntapi.ExceptionContinueSearch)
			return 0
		}
		ctx.SetReturn(ret)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlCaptureContext", func(ctx *ntapi.TrapContext) uint32 {
		if addr := ctx.Arg(0); addr != 0 {
			if cm, ok := ctx.CPU.(ntapi.ContextMarshaler); ok {
				_ = cm.SaveContext(ctx.Mem, addr)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlLookupFunctionEntry", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlLookupFunctionEntry", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlVirtualUnwind", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlVirtualUnwind", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetUnhandledExceptionFilter", func(ctx *ntapi.TrapContext) uint32 {
		// LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(
		//   LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
		// Store the new filter and return the previous one.
		// ReactOS: sdk/lib/rtl/except.c - RtlSetUnhandledExceptionFilter
		newFilter := ctx.Arg(0)
		prev := procState.UnhandledExceptionFilter
		procState.UnhandledExceptionFilter = newFilter
		ctx.SetReturn(prev)
		return 0
	})
	// TLS (Thread Local Storage) emulation
	var tlsNextSlot uint32 = 1           // start at 1, 0 reserved
	tlsValues := make(map[uint32]uint64) // slot → value
	tlsFreeSlots := make(map[uint32]bool)
	d.RegisterAutoStubHandler(kernel32, "TlsAlloc", func(ctx *ntapi.TrapContext) uint32 {
		slot := tlsNextSlot
		tlsNextSlot++
		ctx.SetReturn(uint64(slot))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		ctx.SetReturn(tlsValues[slot])
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TlsSetValue", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		val := ctx.Arg(1)
		tlsValues[slot] = val
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TlsFree", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		delete(tlsValues, slot)
		tlsFreeSlots[slot] = true
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// FLS (Fiber Local Storage) - FlsGetValue/FlsSetValue are patched inline,
	// FlsAlloc still traps to allocate slot indices.
	var flsNextSlot uint32 = 1
	d.RegisterAutoStubHandler(kernel32, "FlsAlloc", func(ctx *ntapi.TrapContext) uint32 {
		slot := flsNextSlot
		flsNextSlot++
		ctx.SetReturn(uint64(slot))
		return 0
	})
	// FlsGetValue/FlsSetValue: patched inline, these are fallback if not patched
	d.RegisterAutoStubHandler(kernel32, "FlsGetValue", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		// Read from guest FLS array
		flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
		val, _ := ctx.Mem.Read64(flsArr + uint64(slot)*8)
		ctx.SetReturn(val)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FlsSetValue", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		val := ctx.Arg(1)
		flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
		ctx.Mem.Write64(flsArr+uint64(slot)*8, val)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FlsFree", func(ctx *ntapi.TrapContext) uint32 {
		slot := uint32(ctx.Arg(0))
		// Zero the slot in guest memory
		flsArr, _ := ctx.Mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
		ctx.Mem.Write64(flsArr+uint64(slot)*8, 0)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "Sleep", func(ctx *ntapi.TrapContext) uint32 {
		ms := ctx.Arg(0)
		if ms > 0 && ms < 60000 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		return 0
	})
	// Heap emulation - bump allocator with free-list recycling.
	// Each allocation has a 16-byte header: [totalBlockSize:8][reserved:8][userData...]
	const heapHandle = 0xBEEF0001
	d.RegisterAutoStubHandler(kernel32, "GetProcessHeap", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessHeap", 0, uint64(heapHandle))
	})
	d.RegisterAutoStubHandler(kernel32, "HeapCreate", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapCreate", 3, uint64(heapHandle))
	})
	d.RegisterAutoStubHandler(kernel32, "HeapDestroy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapDestroy", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapAlloc", func(ctx *ntapi.TrapContext) uint32 {
		size := ctx.Arg(2)
		flags := ctx.Arg(1)
		zeroInit := flags&0x08 != 0 // HEAP_ZERO_MEMORY
		ptr := sharedHeapAlloc(size, zeroInit)
		ctx.SetReturn(ptr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "HeapFree", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(2)
		sharedHeapFree(ptr)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "HeapReAlloc", func(ctx *ntapi.TrapContext) uint32 {
		oldPtr := ctx.Arg(2)
		newSize := ctx.Arg(3)
		flags := ctx.Arg(1)
		zeroInit := flags&0x08 != 0
		newPtr := sharedHeapAlloc(newSize, zeroInit)
		if newPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if oldPtr != 0 {
			oldBlockSize, _ := ctx.Mem.Read64(oldPtr - 16)
			oldUserSize := oldBlockSize - 16
			copyLen := oldUserSize
			if newSize < copyLen {
				copyLen = newSize
			}
			for i := uint64(0); i < copyLen; i++ {
				b, _ := ctx.Mem.Read8(oldPtr + i)
				ctx.Mem.Write8(newPtr+i, b)
			}
			sharedHeapFree(oldPtr)
		}
		ctx.SetReturn(newPtr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "HeapSize", func(ctx *ntapi.TrapContext) uint32 {
		ptr := ctx.Arg(2)
		if ptr == 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		totalBlock, _ := ctx.Mem.Read64(ptr - 16)
		if totalBlock >= 16 {
			ctx.SetReturn(totalBlock - 16)
		} else {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemInfo", func(ctx *ntapi.TrapContext) uint32 {
		si := ctx.Arg(0)
		// SYSTEM_INFO on x64 (48 bytes)
		for i := uint64(0); i < 48; i++ {
			ctx.Mem.Write8(si+i, 0)
		}
		ctx.Mem.Write16(si+0, 9)                   // wProcessorArchitecture = AMD64
		ctx.Mem.Write16(si+2, 0)                   // wReserved
		ctx.Mem.Write32(si+4, 4096)                // dwPageSize
		ctx.Mem.Write64(si+8, 0x10000)             // lpMinimumApplicationAddress
		ctx.Mem.Write64(si+16, 0x00007FFFFFFEFFFF) // lpMaximumApplicationAddress
		ctx.Mem.Write64(si+24, 0xF)                // dwActiveProcessorMask (4 CPUs)
		ctx.Mem.Write32(si+32, 4)                  // dwNumberOfProcessors
		ctx.Mem.Write32(si+36, 8664)               // dwProcessorType = PROCESSOR_AMD_X8664
		ctx.Mem.Write32(si+40, 65536)              // dwAllocationGranularity
		ctx.Mem.Write16(si+44, 6)                  // wProcessorLevel
		ctx.Mem.Write16(si+46, 0x5E03)             // wProcessorRevision (Skylake stepping 3)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVersionExA", func(ctx *ntapi.TrapContext) uint32 {
		info := ctx.Arg(0)
		// OSVERSIONINFOEXA layout (156 bytes for Ex, 148 for base):
		//   +0x00 DWORD dwOSVersionInfoSize
		//   +0x04 DWORD dwMajorVersion
		//   +0x08 DWORD dwMinorVersion
		//   +0x0C DWORD dwBuildNumber
		//   +0x10 DWORD dwPlatformId
		//   +0x14 CHAR  szCSDVersion[128]  (128 bytes, offset 20..147)
		//   +0x94 WORD  wServicePackMajor  (offset 148)
		//   +0x96 WORD  wServicePackMinor
		//   +0x98 WORD  wSuiteMask
		//   +0x9A BYTE  wProductType
		//   +0x9B BYTE  wReserved
		structSize, _ := ctx.Mem.Read32(info)
		ctx.Mem.Write32(info+4, 10)     // dwMajorVersion = 10
		ctx.Mem.Write32(info+8, 0)      // dwMinorVersion = 0
		ctx.Mem.Write32(info+12, 19041) // dwBuildNumber
		ctx.Mem.Write32(info+16, 2)     // dwPlatformId = VER_PLATFORM_WIN32_NT
		// szCSDVersion[128]: empty string (zero first byte, rest already 0)
		ctx.Mem.Write8(info+20, 0)
		if structSize >= 156 { // OSVERSIONINFOEXA
			ctx.Mem.Write16(info+148, 0)     // wServicePackMajor
			ctx.Mem.Write16(info+150, 0)     // wServicePackMinor
			ctx.Mem.Write16(info+152, 0x300) // wSuiteMask: VER_SUITE_SINGLEUSERTS|VER_SUITE_TERMINAL
			ctx.Mem.Write8(info+154, 1)      // wProductType = VER_NT_WORKSTATION
			ctx.Mem.Write8(info+155, 0)      // wReserved
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsValidCodePage", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: dll/win32/kernel32/winnls/string/nls.c
		cp := uint32(ctx.Arg(0))
		switch cp {
		case 1200: // UTF-16LE
			ctx.SetReturn(1)
		case 437, 850, 852, 855, 857, 860, 861, 862, 863, 865, 866, 869: // OEM code pages
			ctx.SetReturn(1)
		case 874, 932, 936, 949, 950: // CJK/Thai code pages
			ctx.SetReturn(1)
		case 1250, 1251, 1252, 1253, 1254, 1255, 1256, 1257, 1258: // Windows ANSI
			ctx.SetReturn(1)
		case 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10010, 10017, 10029, 10079, 10081: // Mac
			ctx.SetReturn(1)
		case 20127: // US-ASCII
			ctx.SetReturn(1)
		case 20866, 21866: // KOI8-R, KOI8-U
			ctx.SetReturn(1)
		case 28591, 28592, 28593, 28594, 28595, 28596, 28597, 28598, 28599, 28603, 28605: // ISO-8859-*
			ctx.SetReturn(1)
		case 65000: // UTF-7
			ctx.SetReturn(1)
		case 65001: // UTF-8
			ctx.SetReturn(1)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleMode", func(ctx *ntapi.TrapContext) uint32 {
		lpMode := ctx.Arg(1)
		if lpMode != 0 {
			ctx.Mem.Write32(lpMode, outputModeForHandle(ctx.Arg(0)))
		}
		ctx.SetReturn(1) // TRUE = is a console
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleMode", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		mode := uint32(ctx.Arg(1))
		setOutputModeForHandle(handle, mode)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCPInfo", func(ctx *ntapi.TrapContext) uint32 {
		codePage := uint32(ctx.Arg(0))
		lpCPInfo := ctx.Arg(1) // CPINFO*: MaxCharSize(4) + DefaultChar(2) + LeadByte(12)
		if !writeCPInfoData(lpCPInfo, codePage) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCP", 0, 65001)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleOutputCP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleOutputCP", 0, 65001)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemTimeAsFileTime", func(ctx *ntapi.TrapContext) uint32 {
		ft := ctx.Arg(0)
		if ft != 0 {
			const epochDiff = uint64(11644473600) * 10000000
			v := uint64(time.Now().UnixNano()/100) + epochDiff
			ctx.Mem.Write64Raw(ft, v)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MultiByteToWideChar", func(ctx *ntapi.TrapContext) uint32 {
		codePage := uint32(ctx.Arg(0))
		srcStr := ctx.Arg(2)
		srcLen := int64(int32(ctx.Arg(3)))
		dstBuf := ctx.Arg(4)
		dstLen := int64(int32(ctx.Arg(5)))
		if srcStr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		raw := readANSIBytesArg(srcStr, int32(srcLen))
		var wchars []uint16
		switch codePage {
		case 65001:
			wchars = utf16.Encode([]rune(string(raw)))
		case 0, 1252:
			wchars = make([]uint16, len(raw))
			for i, b := range raw {
				wchars[i] = uint16(b)
			}
		default:
			ctx.SetReturn(0)
			return 0
		}
		if dstLen == 0 {
			ctx.SetReturn(uint64(len(wchars)))
			return 0
		}
		if int64(len(wchars)) > dstLen {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
			ctx.SetReturn(0)
			return 0
		}
		for i, w := range wchars {
			ctx.Mem.Write16(dstBuf+uint64(i)*2, w)
		}
		ctx.SetReturn(uint64(len(wchars)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WideCharToMultiByte", func(ctx *ntapi.TrapContext) uint32 {
		codePage := uint32(ctx.Arg(0))
		srcStr := ctx.Arg(2)
		srcLen := int64(int32(ctx.Arg(3)))
		dstBuf := ctx.Arg(4)
		dstLen := int64(int32(ctx.Arg(5)))
		lpUsedDefaultChar := ctx.Arg(7)
		if srcStr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		units := readUTF16UnitsArg(srcStr, int32(srcLen))
		var out []byte
		if dstLen == 0 {
			switch codePage {
			case 65001:
				ctx.SetReturn(uint64(len([]byte(string(utf16.Decode(units))))))
			case 0, 1252:
				ctx.SetReturn(uint64(len(units)))
			default:
				ctx.SetReturn(0)
			}
			return 0
		}
		usedDefault := false
		switch codePage {
		case 65001:
			out = []byte(string(utf16.Decode(units)))
		case 0, 1252:
			out = make([]byte, len(units))
			for i, w := range units {
				if w > 0x00FF {
					out[i] = '?'
					usedDefault = true
				} else {
					out[i] = byte(w)
				}
			}
		default:
			ctx.SetReturn(0)
			return 0
		}
		if int64(len(out)) > dstLen {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
			ctx.SetReturn(0)
			return 0
		}
		for i, b := range out {
			ctx.Mem.Write8(dstBuf+uint64(i), b)
		}
		if lpUsedDefaultChar != 0 {
			ctx.Mem.Write32(lpUsedDefaultChar, 0)
			if usedDefault {
				ctx.Mem.Write8(lpUsedDefaultChar, 1)
			}
		}
		ctx.SetReturn(uint64(len(out)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocalAlloc", func(ctx *ntapi.TrapContext) uint32 {
		size := ctx.Arg(1)
		if size == 0 {
			size = 1
		}
		buf := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocalFree", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		if hMem != 0 {
			_, size, mapped, _ := mem.QueryRegion(hMem)
			if mapped && size > 0 {
				mem.Munmap(hMem, size)
			}
		}
		ctx.SetReturn(0) // NULL = success
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetModuleFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		hModule := ctx.Arg(0)
		buf := ctx.Arg(1)
		size := ctx.Arg(2)
		var path string
		imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
		if hModule == 0 || hModule == imageBase {
			path = imagePath
		} else {
			path = "C:\\Windows\\System32\\unknown.dll"
		}
		name := []byte(path)
		n := uint64(len(name))
		if n >= size {
			n = size - 1
		}
		for i := uint64(0); i < n; i++ {
			ctx.Mem.Write8(buf+i, name[i])
		}
		ctx.Mem.Write8(buf+n, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		if pathPtr == 0 {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		path := winPathToVFS(readGuestString(pathPtr))
		info, err := os.Stat(path)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		var attrs uint32 = 0x20 // FILE_ATTRIBUTE_NORMAL
		if info.IsDir() {
			attrs = 0x10
		} // FILE_ATTRIBUTE_DIRECTORY
		ctx.SetReturn(uint64(attrs))
		return 0
	})
	// ExitProcess: cleanly terminate emulation
	d.RegisterAutoStubHandler(kernel32, "ExitProcess", func(ctx *ntapi.TrapContext) uint32 {
		code := ctx.Arg(0)
		ravelog.Logf("[win32] ExitProcess(%d)\n", code)
		if wlDisplay != nil {
			wlDisplay.Close()
		}
		pprof.StopCPUProfile()
		os.Exit(int(code))
		return 0
	})
	// GetCommandLineA: return pointer to ASCII command line
	var cmdLineAAddr uint64
	d.RegisterAutoStubHandler(kernel32, "GetCommandLineA", func(ctx *ntapi.TrapContext) uint32 {
		if cmdLineAAddr == 0 {
			cl := []byte(cmdLine)
			cmdLineAAddr = ctx.Mem.Mmap(0, uint64(len(cl)+1), mmu.PermRead|mmu.PermWrite)
			ctx.Mem.WriteBytes(cmdLineAAddr, append(cl, 0))
		}
		ctx.SetReturn(cmdLineAAddr)
		return 0
	})
	// GetCommandLineW: return pointer to UTF-16LE command line
	var cmdLineWAddr uint64
	d.RegisterAutoStubHandler(kernel32, "GetCommandLineW", func(ctx *ntapi.TrapContext) uint32 {
		if cmdLineWAddr == 0 {
			utf16 := make([]byte, 0, (len(cmdLine)+1)*2)
			for _, b := range []byte(cmdLine) {
				utf16 = append(utf16, b, 0)
			}
			utf16 = append(utf16, 0, 0) // null terminator
			cmdLineWAddr = ctx.Mem.Mmap(0, uint64(len(utf16)), mmu.PermRead|mmu.PermWrite)
			ctx.Mem.WriteBytes(cmdLineWAddr, utf16)
		}
		ctx.SetReturn(cmdLineWAddr)
		return 0
	})
	// GetStartupInfoW: fill STARTUPINFOW (104 bytes on x64)
	d.RegisterAutoStubHandler(kernel32, "GetStartupInfoW", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		for i := uint64(0); i < 104; i++ {
			ctx.Mem.Write8(addr+i, 0)
		}
		ctx.Mem.Write32(addr, 104)       // cb
		ctx.Mem.Write32(addr+60, 0x0001) // dwFlags = STARTF_USESHOWWINDOW
		ctx.Mem.Write16(addr+64, 0x0001) // wShowWindow = SW_SHOWNORMAL
		return 0
	})
	// GetFileType: FILE_TYPE_CHAR for std handles, FILE_TYPE_DISK for files, FILE_TYPE_PIPE for pipes
	d.RegisterAutoStubHandler(kernel32, "GetFileType", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		h := ntapi.Handle(handle)
		switch handle {
		case 0x100, 0x101, 0x102, 0x103: // stdin, stdout, stderr, and extra console handle
			ctx.SetReturn(0x0002) // FILE_TYPE_CHAR
		default:
			if handles.GetNamedPipe(h) != nil {
				ctx.SetReturn(0x0003) // FILE_TYPE_PIPE
			} else if handles.GetFile(h) != nil {
				ctx.SetReturn(0x0001) // FILE_TYPE_DISK
			} else {
				ctx.SetReturn(0x0000) // FILE_TYPE_UNKNOWN
			}
		}
		return 0
	})
	// WriteFile: write to stdout/stderr for console handles
	d.RegisterAutoStubHandler(kernel32, "WriteFile", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		bufAddr := ctx.Arg(1)
		nBytes := ctx.Arg(2)
		lpWritten := ctx.Arg(3)
		lpOverlapped := ctx.Arg(4)
		data, _ := ctx.Mem.ReadBytes(bufAddr, int(nBytes))
		var written int
		switch hFile {
		case 0x101: // stdout
			written = writeConsoleString(uint64(hFile), string(data), data)
		case 0x102: // stderr
			written = writeConsoleString(uint64(hFile), string(data), data)
		default:
			obj := handles.Get(hFile)
			if _, ok := obj.(*ntapi.ConsoleScreenBufferHandle); ok {
				written = writeConsoleString(uint64(hFile), string(data), data)
				break
			}
			// Named pipe write
			if ph, ok := obj.(*ntapi.NamedPipeHandle); ok {
				if ph.PipeWrite(data) {
					written = len(data)
				}
				break
			}
			fh, ok := obj.(*ntapi.FileHandle)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			if lpOverlapped != 0 {
				off32, _ := ctx.Mem.Read32(lpOverlapped + 16)
				offHi, _ := ctx.Mem.Read32(lpOverlapped + 20)
				offset := int64(off32) | (int64(offHi) << 32)
				if off32 == 0xFFFFFFFF && offHi == 0xFFFFFFFF {
					written, _ = ctx.FS.Write(fh.FD, data)
				} else {
					written, _ = ctx.FS.Pwrite(fh.FD, data, offset)
				}
				// Fill OVERLAPPED: Internal=STATUS_SUCCESS, InternalHigh=bytes
				ctx.Mem.Write64(lpOverlapped, 0)
				ctx.Mem.Write64(lpOverlapped+8, uint64(written))
				// Signal hEvent if set
				evHandle, _ := ctx.Mem.Read64(lpOverlapped + 24)
				if evHandle != 0 {
					if eh := handles.GetEvent(ntapi.Handle(evHandle)); eh != nil {
						eh.Set()
					}
				}
			} else {
				written, _ = ctx.FS.Write(fh.FD, data)
			}
		}
		if lpWritten != 0 {
			ctx.Mem.Write32(lpWritten, uint32(written))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleW", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		buf := ctx.Arg(1)
		nChars := ctx.Arg(2)
		lpWritten := ctx.Arg(3)
		// Decode UTF-16LE buffer to UTF-8
		utf16Chars := make([]uint16, nChars)
		for i := uint64(0); i < nChars; i++ {
			utf16Chars[i], _ = ctx.Mem.Read16(buf + i*2)
		}
		text := string(utf16Decode(utf16Chars))
		writeConsoleString(handle, text, nil)
		if lpWritten != 0 {
			ctx.Mem.Write32(lpWritten, uint32(nChars))
		}
		ctx.SetReturn(1)
		return 0
	})
	// GetACP: return Windows-1252 code page
	d.RegisterAutoStubHandler(kernel32, "GetACP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetACP", 8, 1252)
	})
	// GetModuleFileNameW: write image path as UTF-16LE
	d.RegisterAutoStubHandler(kernel32, "GetModuleFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		hModule := ctx.Arg(0)
		buf := ctx.Arg(1)
		size := ctx.Arg(2)
		var path string
		imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
		if hModule == 0 || hModule == imageBase {
			path = imagePath
		} else {
			path = "C:\\Windows\\System32\\unknown.dll"
		}
		n := uint64(len(path))
		if n >= size {
			n = size - 1
		}
		for i := uint64(0); i < n; i++ {
			ctx.Mem.Write16(buf+i*2, uint16(path[i]))
		}
		ctx.Mem.Write16(buf+n*2, 0) // null terminator
		ctx.SetReturn(n)
		return 0
	})
	// InitializeSListHead: zero 16 bytes
	d.RegisterAutoStubHandler(kernel32, "InitializeSListHead", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		if addr != 0 {
			ctx.Mem.Write64(addr, 0)
			ctx.Mem.Write64(addr+8, 0)
		}
		return 0
	})
	// GetEnvironmentStringsW: return pointer to env block from PEB
	d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		paramsAddr, _ := ctx.Mem.Read64(ctx.State.PEBAddr + ntapi.PebProcessParameters)
		envPtr, _ := ctx.Mem.Read64(paramsAddr + ntapi.ProcessParamsEnvironment)
		ctx.SetReturn(envPtr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FreeEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeEnvironmentStringsW", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCtrlHandler", func(ctx *ntapi.TrapContext) uint32 {
		handler := ctx.Arg(0)
		add := ctx.Arg(1) != 0
		consoleCtrlMu.Lock()
		if handler == 0 {
			consoleCtrlIgnore = add
		} else if add {
			consoleCtrlHandlers[handler] = struct{}{}
		} else {
			delete(consoleCtrlHandlers, handler)
		}
		consoleCtrlMu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	// EncodePointer/DecodePointer: just return the pointer as-is
	d.RegisterAutoStubHandler(kernel32, "EncodePointer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EncodePointer", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "DecodePointer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DecodePointer", 1, uint64(ctx.Arg(0)))
	})
	// --- String functions ---
	d.RegisterAutoStubHandler(kernel32, "lstrcpynA", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		maxLen := int64(int32(ctx.Arg(2)))
		if maxLen <= 0 {
			ctx.SetReturn(dst)
			return 0
		}
		for i := int64(0); i < maxLen-1; i++ {
			b, _ := ctx.Mem.Read8(src + uint64(i))
			ctx.Mem.Write8(dst+uint64(i), b)
			if b == 0 {
				ctx.SetReturn(dst)
				return 0
			}
		}
		ctx.Mem.Write8(dst+uint64(maxLen-1), 0)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcpyW", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(src + i)
			ctx.Mem.Write16(dst+i, w)
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcpynW", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		maxLen := int64(int32(ctx.Arg(2)))
		if maxLen <= 0 {
			ctx.SetReturn(dst)
			return 0
		}
		for i := int64(0); i < maxLen-1; i++ {
			w, _ := ctx.Mem.Read16(src + uint64(i*2))
			ctx.Mem.Write16(dst+uint64(i*2), w)
			if w == 0 {
				ctx.SetReturn(dst)
				return 0
			}
		}
		ctx.Mem.Write16(dst+uint64((maxLen-1)*2), 0)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrlenW", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		if s == 0 {
			ctx.SetReturn(0)
			return 0
		}
		n := uint64(0)
		for {
			w, _ := ctx.Mem.Read16(s + n*2)
			if w == 0 {
				break
			}
			n++
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmpW", func(ctx *ntapi.TrapContext) uint32 {
		a := ctx.Arg(0)
		b := ctx.Arg(1)
		for i := uint64(0); ; i += 2 {
			wa, _ := ctx.Mem.Read16(a + i)
			wb, _ := ctx.Mem.Read16(b + i)
			if wa < wb {
				ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF)) // -1
				return 0
			}
			if wa > wb {
				ctx.SetReturn(1)
				return 0
			}
			if wa == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmpiA", func(ctx *ntapi.TrapContext) uint32 {
		a := ctx.Arg(0)
		b := ctx.Arg(1)
		for i := uint64(0); ; i++ {
			ba, _ := ctx.Mem.Read8(a + i)
			bb, _ := ctx.Mem.Read8(b + i)
			la := ba
			if la >= 'A' && la <= 'Z' {
				la += 32
			}
			lb := bb
			if lb >= 'A' && lb <= 'Z' {
				lb += 32
			}
			if la < lb {
				ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF))
				return 0
			}
			if la > lb {
				ctx.SetReturn(1)
				return 0
			}
			if la == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmpiW", func(ctx *ntapi.TrapContext) uint32 {
		a := ctx.Arg(0)
		b := ctx.Arg(1)
		for i := uint64(0); ; i += 2 {
			wa, _ := ctx.Mem.Read16(a + i)
			wb, _ := ctx.Mem.Read16(b + i)
			la := wa
			if la >= 'A' && la <= 'Z' {
				la += 32
			}
			lb := wb
			if lb >= 'A' && lb <= 'Z' {
				lb += 32
			}
			if la < lb {
				ctx.SetReturn(uint64(0xFFFFFFFFFFFFFFFF))
				return 0
			}
			if la > lb {
				ctx.SetReturn(1)
				return 0
			}
			if la == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	// --- Directory / path functions ---
	d.RegisterAutoStubHandler(kernel32, "GetCurrentDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		bufSize := ctx.Arg(0)
		buf := ctx.Arg(1)
		dir := `C:\`
		needed := uint64(len(dir) + 1)
		if bufSize < needed {
			ctx.SetReturn(needed)
			return 0
		}
		for i, ch := range dir {
			ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(dir)*2), 0)
		ctx.SetReturn(uint64(len(dir)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetCurrentDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		dir := winPathToVFS(readGuestUTF16(pathPtr))
		if err := os.Chdir(dir); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		if pathPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestUTF16(pathPtr))
		if err := os.MkdirAll(path, 0755); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFullPathNameW", func(ctx *ntapi.TrapContext) uint32 {
		fileNamePtr := ctx.Arg(0)
		bufLen := ctx.Arg(1)
		buf := ctx.Arg(2)
		// Read the input filename
		var chars []uint16
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(fileNamePtr + i)
			chars = append(chars, w)
			if w == 0 {
				break
			}
		}
		needed := uint64(len(chars))
		if bufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		for i, w := range chars {
			ctx.Mem.Write16(buf+uint64(i*2), w)
		}
		ctx.SetReturn(needed - 1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLongPathNameW", func(ctx *ntapi.TrapContext) uint32 {
		shortPath := ctx.Arg(0)
		buf := ctx.Arg(1)
		bufLen := ctx.Arg(2)
		var chars []uint16
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(shortPath + i)
			chars = append(chars, w)
			if w == 0 {
				break
			}
		}
		needed := uint64(len(chars))
		if bufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		for i, w := range chars {
			ctx.Mem.Write16(buf+uint64(i*2), w)
		}
		ctx.SetReturn(needed - 1)
		return 0
	})
	// --- Version / system info ---
	d.RegisterAutoStubHandler(kernel32, "GetVersionExW", func(ctx *ntapi.TrapContext) uint32 {
		lpInfo := ctx.Arg(0)
		// OSVERSIONINFOEXW layout (284 bytes for Ex, 276 for base):
		//   +0x00  DWORD dwOSVersionInfoSize
		//   +0x04  DWORD dwMajorVersion
		//   +0x08  DWORD dwMinorVersion
		//   +0x0C  DWORD dwBuildNumber
		//   +0x10  DWORD dwPlatformId
		//   +0x14  WCHAR szCSDVersion[128]  (256 bytes, offsets 20..275)
		//   +0x114 WORD  wServicePackMajor  (offset 276)
		//   +0x116 WORD  wServicePackMinor
		//   +0x118 WORD  wSuiteMask
		//   +0x11A BYTE  wProductType
		//   +0x11B BYTE  wReserved
		structSize, _ := ctx.Mem.Read32(lpInfo)
		ctx.Mem.Write32(lpInfo+4, 10)     // dwMajorVersion
		ctx.Mem.Write32(lpInfo+8, 0)      // dwMinorVersion
		ctx.Mem.Write32(lpInfo+12, 19041) // dwBuildNumber
		ctx.Mem.Write32(lpInfo+16, 2)     // dwPlatformId = VER_PLATFORM_WIN32_NT
		// szCSDVersion[128]: empty string (null-terminate first WCHAR)
		ctx.Mem.Write16(lpInfo+20, 0)
		if structSize >= 284 { // OSVERSIONINFOEXW
			ctx.Mem.Write16(lpInfo+276, 0)     // wServicePackMajor
			ctx.Mem.Write16(lpInfo+278, 0)     // wServicePackMinor
			ctx.Mem.Write16(lpInfo+280, 0x300) // wSuiteMask: VER_SUITE_SINGLEUSERTS|VER_SUITE_TERMINAL
			ctx.Mem.Write8(lpInfo+282, 1)      // wProductType = VER_NT_WORKSTATION
			ctx.Mem.Write8(lpInfo+283, 0)      // wReserved
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVersion", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVersion", 0, uint64(uint64(19045<<16|0<<8|10)))
	})
	d.RegisterAutoStubHandler(kernel32, "GetNativeSystemInfo", func(ctx *ntapi.TrapContext) uint32 {
		si := ctx.Arg(0)
		for i := uint64(0); i < 48; i++ {
			ctx.Mem.Write8(si+i, 0)
		}
		ctx.Mem.Write16(si+0, 9)                   // wProcessorArchitecture = AMD64
		ctx.Mem.Write16(si+2, 0)                   // wReserved
		ctx.Mem.Write32(si+4, 4096)                // dwPageSize
		ctx.Mem.Write64(si+8, 0x10000)             // lpMinimumApplicationAddress
		ctx.Mem.Write64(si+16, 0x00007FFFFFFEFFFF) // lpMaximumApplicationAddress
		ctx.Mem.Write64(si+24, 0xF)                // dwActiveProcessorMask (4 CPUs)
		ctx.Mem.Write32(si+32, 4)                  // dwNumberOfProcessors
		ctx.Mem.Write32(si+36, 8664)               // dwProcessorType = PROCESSOR_AMD_X8664
		ctx.Mem.Write32(si+40, 65536)              // dwAllocationGranularity
		ctx.Mem.Write16(si+44, 6)                  // wProcessorLevel
		ctx.Mem.Write16(si+46, 0x5E03)             // wProcessorRevision (Skylake stepping 3)
		ctx.SetReturn(0)
		return 0
	})
	// --- Sync primitives ---
	d.RegisterAutoStubHandler(kernel32, "CreateMutexW", func(ctx *ntapi.TrapContext) uint32 {
		bInitialOwner := ctx.Arg(1) != 0
		mh := &ntapi.MutantHandle{}
		if bInitialOwner {
			var tid uint32 = 1
			if *tmPtr != nil {
				tid = uint32((*tmPtr).GetTID(ctx.CPU))
			}
			mh.WaitTimeout(tid, 0)
		}
		h := handles.Alloc(mh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseMutex", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		if mh := handles.GetMutant(h); mh != nil {
			if mh.Release(tid) {
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
		} else {
			ctx.SetReturn(1) // unknown handle: no-op success
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForSingleObject", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		ms := ctx.Arg(1)
		timeout := msToTimeout(ms)
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		ctx.SetReturn(uint64(waitOneWin32(handles, h, tid, timeout)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForMultipleObjects", func(ctx *ntapi.TrapContext) uint32 {
		nCount := ctx.Arg(0)
		pHandles := ctx.Arg(1)
		waitAll := ctx.Arg(2) != 0
		ms := ctx.Arg(3)
		timeout := msToTimeout(ms)
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		if nCount == 0 || pHandles == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if nCount > 64 {
			nCount = 64
		}
		if !waitAll {
			// WaitAny: return index of first signaled
			for i := uint64(0); i < nCount; i++ {
				hv, _ := ctx.Mem.Read64(pHandles + i*8)
				res := waitOneWin32(handles, ntapi.Handle(hv), tid, timeout)
				if res != 0x102 { // not WAIT_TIMEOUT
					ctx.SetReturn(uint64(res))
					return 0
				}
			}
			ctx.SetReturn(0x102)
			return 0
		}
		// WaitAll: wait for all in sequence
		for i := uint64(0); i < nCount; i++ {
			hv, _ := ctx.Mem.Read64(pHandles + i*8)
			res := waitOneWin32(handles, ntapi.Handle(hv), tid, timeout)
			if res == 0x102 {
				ctx.SetReturn(0x102)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AcquireSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TryAcquireSRWLockExclusive", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TryAcquireSRWLockExclusive", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WakeAllConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
		ntapi.GlobalCondVars.Get(ctx.Arg(0)).Broadcast()
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SleepConditionVariableSRW", func(ctx *ntapi.TrapContext) uint32 {
		// SleepConditionVariableSRW(CondVar, SRWLock, dwMilliseconds, Flags)
		addr := ctx.Arg(0)
		ms := ctx.Arg(2)
		entry := ntapi.GlobalCondVars.Get(addr)
		if ms == 0xFFFFFFFF { // INFINITE
			entry.Sleep(10 * time.Second) // cap to avoid deadlocks
		} else {
			entry.Sleep(time.Duration(ms) * time.Millisecond)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SleepEx", func(ctx *ntapi.TrapContext) uint32 {
		ms := ctx.Arg(0)
		if ms > 0 && ms < 60000 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateEventW", func(ctx *ntapi.TrapContext) uint32 {
		// CreateEventW(lpAttr, bManualReset, bInitialState, lpName)
		manualReset := ctx.Arg(1) != 0
		initialState := ctx.Arg(2) != 0
		h := handles.Alloc(ntapi.NewEvent(manualReset, initialState))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetEvent", func(ctx *ntapi.TrapContext) uint32 {
		if eh := handles.GetEvent(ntapi.Handle(ctx.Arg(0))); eh != nil {
			eh.Set()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ResetEvent", func(ctx *ntapi.TrapContext) uint32 {
		if eh := handles.GetEvent(ntapi.Handle(ctx.Arg(0))); eh != nil {
			eh.Reset()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitOnceBeginInitialize", func(ctx *ntapi.TrapContext) uint32 {
		// Single-threaded: always succeed, set fPending=TRUE via arg2 pointer
		pending := ctx.Arg(2)
		if pending != 0 {
			ctx.Mem.Write32(pending, 1) // fPending = TRUE
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitOnceComplete", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitOnceComplete", 3, 1)
	})
	// Thread stack pool for reuse (avoids Mmap leak)
	type threadStack struct {
		base uint64
		size uint64
	}
	var freeStacks []threadStack
	var stackMu sync.Mutex
	// tpAllocStack allocates (or reuses) a stack for a threadpool callback thread.
	tpAllocStack := func(sz uint64) (base, size uint64) {
		if sz == 0 {
			sz = 1 << 20
		}
		stackMu.Lock()
		for i, s := range freeStacks {
			if s.size >= sz {
				base = s.base
				size = s.size
				freeStacks[i] = freeStacks[len(freeStacks)-1]
				freeStacks = freeStacks[:len(freeStacks)-1]
				stackMu.Unlock()
				return
			}
		}
		stackMu.Unlock()
		base = mem.Mmap(0, sz, mmu.PermRead|mmu.PermWrite)
		size = sz
		return
	}
	// tpRecycleStack returns a stack to the free list when a threadpool thread exits.
	tpRecycleStack := func(done <-chan struct{}, base, size uint64) {
		go func() {
			<-done
			stackMu.Lock()
			freeStacks = append(freeStacks, threadStack{base: base, size: size})
			stackMu.Unlock()
		}()
	}
	// tpAllocTEB creates a per-thread TEB for a threadpool callback thread.
	tpAllocTEB := func(stackBase, stackSz uint64) uint64 {
		teb := mem.Mmap(0, uint64(ntapi.TebSize), mmu.PermRead|mmu.PermWrite)
		if teb != 0 {
			tlsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebThreadLocalStorage)
			mem.Write64(teb+ntapi.TebThreadLocalStorage, tlsPtr)
			flsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			mem.Write64(teb+ntapi.TebFlsData, flsPtr)
			heapBase, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
			mem.Write64(teb+ntapi.TebHeapBase, heapBase)
			heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			mem.Write64(teb+ntapi.TebHeapOffset, heapOff)
			mem.Write64(teb+ntapi.TebSelf, teb)
			mem.Write64(teb+ntapi.TebPEB, procState.PEBAddr)
			mem.Write64(teb+ntapi.TebStackBase, stackBase+stackSz)
			mem.Write64(teb+ntapi.TebStackLimit, stackBase)
			mem.Write32(teb+ntapi.TebProcessId, uint32(procState.PEBAddr>>12))
			mem.Write64(teb+ntapi.TebExceptionList, 0xFFFFFFFFFFFFFFFF)
		}
		return teb
	}
	// tpLaunchCallback launches a threadpool callback on a new guest thread.
	// args are mapped to RCX, RDX, R8, R9 per the Microsoft x64 calling convention.
	tpLaunchCallback := func(cpuTemplate arch.CPU, callbackAddr uint64, args ...uint64) <-chan struct{} {
		tm := *tmPtr
		if tm == nil {
			return nil
		}
		stackBase, stackSz := tpAllocStack(0)
		teb := tpAllocTEB(stackBase, stackSz)
		_, done, err := tm.CloneWin32ThreadEx(cpuTemplate, callbackAddr, stackBase, stackSz, teb, args...)
		if err != nil {
			ravelog.Logf("[threadpool] failed to launch callback: %v\n", err)
			return nil
		}
		tpRecycleStack(done, stackBase, stackSz)
		return done
	}
	// Prevent unused-variable errors when no threadpool API is actually called.
	_ = tpLaunchCallback
	d.RegisterAutoStubHandler(kernel32, "CreateThread", func(ctx *ntapi.TrapContext) uint32 {
		dwStackSize := ctx.Arg(1)
		lpStartAddress := ctx.Arg(2)
		lpParameter := ctx.Arg(3)
		lpThreadId := ctx.Arg(5)
		stackSz := dwStackSize
		if stackSz == 0 {
			stackSz = 1 << 20 // 1 MB default
		}
		// Try to reuse a freed stack of matching size
		var stackBase uint64
		stackMu.Lock()
		for i, s := range freeStacks {
			if s.size >= stackSz {
				stackBase = s.base
				stackSz = s.size
				freeStacks[i] = freeStacks[len(freeStacks)-1]
				freeStacks = freeStacks[:len(freeStacks)-1]
				break
			}
		}
		stackMu.Unlock()
		if stackBase == 0 {
			stackBase = mem.Mmap(0, stackSz, mmu.PermRead|mmu.PermWrite)
		}
		tm := *tmPtr
		if tm == nil {
			th := &ntapi.ThreadHandle{TID: 0, Done: make(chan struct{})}
			close(th.Done)
			h := handles.Alloc(th)
			ctx.SetReturn(uint64(h))
			return 0
		}
		// Allocate a per-thread TEB so each thread has its own GS-based
		// storage (LastError, stack bounds, TLS slots, exception chain).
		// We copy the invariant process-wide fields from the main TEB and
		// fill in thread-specific ones (TID, stack bounds, self pointer).
		threadTEB := mem.Mmap(0, uint64(ntapi.TebSize), mmu.PermRead|mmu.PermWrite)
		if threadTEB != 0 {
			// Copy TLS/FLS-related fields from main TEB
			tlsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebThreadLocalStorage)
			mem.Write64(threadTEB+ntapi.TebThreadLocalStorage, tlsPtr)
			flsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			mem.Write64(threadTEB+ntapi.TebFlsData, flsPtr)
			// Copy inline heap pointers so GS:[0x1800] reads work
			heapBase, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
			mem.Write64(threadTEB+ntapi.TebHeapBase, heapBase)
			heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			mem.Write64(threadTEB+ntapi.TebHeapOffset, heapOff)
			// Thread-specific fields
			mem.Write64(threadTEB+ntapi.TebSelf, threadTEB)
			mem.Write64(threadTEB+ntapi.TebPEB, procState.PEBAddr)
			mem.Write64(threadTEB+ntapi.TebStackBase, stackBase+stackSz)
			mem.Write64(threadTEB+ntapi.TebStackLimit, stackBase)
			mem.Write32(threadTEB+ntapi.TebProcessId, uint32(procState.PEBAddr>>12))
			mem.Write64(threadTEB+ntapi.TebExceptionList, 0xFFFFFFFFFFFFFFFF)
		}
		tid, done, err := tm.CloneWin32Thread(ctx.CPU, lpStartAddress, lpParameter, stackBase, stackSz, threadTEB)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		if threadTEB != 0 {
			mem.Write32(threadTEB+ntapi.TebThreadId, uint32(tid))
		}
		if lpThreadId != 0 {
			ctx.Mem.Write32(lpThreadId, uint32(tid))
		}
		// Recycle stack when thread exits
		capturedBase := stackBase
		capturedSize := stackSz
		go func() {
			<-done
			stackMu.Lock()
			freeStacks = append(freeStacks, threadStack{base: capturedBase, size: capturedSize})
			stackMu.Unlock()
		}()
		h := handles.Alloc(&ntapi.ThreadHandle{TID: tid, Done: done})
		ctx.SetReturn(uint64(h))
		return 0
	})
	// --- File I/O ---
	d.RegisterAutoStubHandler(kernel32, "CreateFileW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		desiredAccess := ctx.Arg(1)
		creationDisp := ctx.Arg(4) // CREATE_NEW=1, CREATE_ALWAYS=2, OPEN_EXISTING=3, OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
		var fname []uint16
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(namePtr + i)
			if w == 0 {
				break
			}
			fname = append(fname, w)
		}
		name := string(utf16Decode(fname))
		if ctx.Trace {
			ravelog.Logf("[win32] CreateFileW: %q access=0x%x disp=%d\n", name, desiredAccess, creationDisp)
		}
		// Named pipe client connect: \\.\pipe\<name>
		if isPipePath(name) {
			pipeName := normalizePipeName(name)
			server := ntapi.LookupNamedPipe(pipeName)
			if server == nil {
				ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
				procState.LastError = 2 // ERROR_FILE_NOT_FOUND
				return 0
			}
			ch := ntapi.NewClientPipe(server)
			h := handles.Alloc(ch)
			server.Connected = true
			if ctx.Trace {
				ravelog.Logf("[win32] CreateFileW: pipe %q client → handle=0x%x\n", name, uint64(h))
			}
			ctx.SetReturn(uint64(h))
			return 0
		}
		// Convert Windows path to VFS path
		vfsPath := winPathToVFS(name)
		// Fallback: if path like /AppName/file.xml doesn't exist,
		// try replacing first directory component with the PE's dir
		lastBS := strings.LastIndex(imagePath, `\`)
		peWinDir := imagePath
		if lastBS >= 0 {
			peWinDir = imagePath[:lastBS]
		}
		peVfsDir := winPathToVFS(peWinDir)
		var flags int
		switch creationDisp {
		case 1: // CREATE_NEW
			flags = vfs.O_CREAT | vfs.O_RDWR
		case 2: // CREATE_ALWAYS
			flags = vfs.O_CREAT | vfs.O_TRUNC | vfs.O_RDWR
		case 3: // OPEN_EXISTING
			flags = vfs.O_RDONLY
			if desiredAccess&0x40000000 != 0 { // GENERIC_WRITE
				flags = vfs.O_RDWR
			}
		case 4: // OPEN_ALWAYS
			flags = vfs.O_CREAT | vfs.O_RDWR
		case 5: // TRUNCATE_EXISTING
			flags = vfs.O_TRUNC | vfs.O_RDWR
		default:
			flags = vfs.O_RDONLY
		}
		fd, err := ctx.FS.Open(vfsPath, flags)
		if err != nil {
			// Try remapping first directory component to PE directory
			parts := strings.SplitN(strings.TrimPrefix(vfsPath, "/"), "/", 2)
			if len(parts) == 2 {
				altPath := peVfsDir + "/" + parts[1]
				fd2, err2 := ctx.FS.Open(altPath, flags)
				if err2 == nil {
					fd = fd2
					err = nil
					vfsPath = altPath
				}
			}
		}
		if err != nil {
			if ctx.Trace {
				ravelog.Logf("[win32] CreateFileW: %q → INVALID_HANDLE_VALUE (%v)\n", name, err)
			}
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			procState.LastError = 2           // ERROR_FILE_NOT_FOUND
			return 0
		}
		h := handles.Alloc(&ntapi.FileHandle{FD: fd, Path: vfsPath})
		if ctx.Trace {
			ravelog.Logf("[win32] CreateFileW: %q → handle=0x%x (fd=%d)\n", name, uint64(h), fd)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadFile", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		bufAddr := ctx.Arg(1)
		nBytesToRead := uint32(ctx.Arg(2))
		lpBytesRead := ctx.Arg(3)
		lpOverlapped := ctx.Arg(4)
		// stdin handle
		if hFile == 0x100 {
			buf := make([]byte, nBytesToRead)
			n, err := os.Stdin.Read(buf)
			ctx.Mem.WriteBytes(bufAddr, buf[:n])
			if lpBytesRead != 0 {
				ctx.Mem.Write32(lpBytesRead, uint32(n))
			}
			if err != nil {
				ctx.SetReturn(0)
			} else {
				ctx.SetReturn(1)
			}
			return 0
		}
		obj := handles.Get(hFile)
		// Named pipe read
		if ph, ok := obj.(*ntapi.NamedPipeHandle); ok {
			buf := make([]byte, nBytesToRead)
			n := ph.PipeRead(buf)
			ctx.Mem.WriteBytes(bufAddr, buf[:n])
			if lpBytesRead != 0 {
				ctx.Mem.Write32(lpBytesRead, uint32(n))
			}
			ctx.SetReturn(1)
			return 0
		}
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			if lpBytesRead != 0 {
				ctx.Mem.Write32(lpBytesRead, 0)
			}
			ctx.SetReturn(0) // FALSE
			return 0
		}
		buf := make([]byte, nBytesToRead)
		var n int
		if lpOverlapped != 0 {
			off32, _ := ctx.Mem.Read32(lpOverlapped + 16)
			offHi, _ := ctx.Mem.Read32(lpOverlapped + 20)
			offset := int64(off32) | (int64(offHi) << 32)
			if off32 == 0xFFFFFFFF && offHi == 0xFFFFFFFF {
				n, _ = ctx.FS.Read(fh.FD, buf)
			} else {
				n, _ = ctx.FS.Pread(fh.FD, buf, offset)
			}
			// Fill OVERLAPPED: Internal=STATUS_SUCCESS, InternalHigh=bytes
			ctx.Mem.Write64(lpOverlapped, 0)
			ctx.Mem.Write64(lpOverlapped+8, uint64(n))
			// Signal hEvent if set
			evHandle, _ := ctx.Mem.Read64(lpOverlapped + 24)
			if evHandle != 0 {
				if eh := handles.GetEvent(ntapi.Handle(evHandle)); eh != nil {
					eh.Set()
				}
			}
		} else {
			n, _ = ctx.FS.Read(fh.FD, buf)
		}
		ctx.Mem.WriteBytes(bufAddr, buf[:n])
		if lpBytesRead != 0 {
			ctx.Mem.Write32(lpBytesRead, uint32(n))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetFilePointerEx", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		distance := int64(ctx.Arg(1))
		newPosPtr := ctx.Arg(2)
		method := uint32(ctx.Arg(3)) // 0=BEGIN, 1=CURRENT, 2=END
		obj := handles.Get(hFile)
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		whence := int(method) // maps directly: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2
		newPos, err := ctx.FS.Lseek(fh.FD, distance, whence)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		if newPosPtr != 0 {
			ctx.Mem.Write64(newPosPtr, uint64(newPos))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileSizeEx", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		sizePtr := ctx.Arg(1)
		obj := handles.Get(hFile)
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		node := ctx.FS.Stat(fh.FD)
		if node == nil {
			ctx.SetReturn(0)
			return 0
		}
		if sizePtr != 0 {
			ctx.Mem.Write64(sizePtr, uint64(node.Size))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CloseHandle", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		obj := handles.Get(h)
		if fh, ok := obj.(*ntapi.FileHandle); ok {
			ctx.FS.Close(fh.FD)
		}
		handles.Close(h)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FlushFileBuffers", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		fh := handles.GetFile(hFile)
		if fh != nil {
			unix.Fsync(fh.FD)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		if pathPtr == 0 {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		winPath := readGuestUTF16(pathPtr)
		path := winPathToVFS(winPath)
		info, err := os.Stat(path)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFF) // INVALID_FILE_ATTRIBUTES
			return 0
		}
		var attrs uint32 = 0x20 // FILE_ATTRIBUTE_NORMAL
		if info.IsDir() {
			attrs = 0x10
		} // FILE_ATTRIBUTE_DIRECTORY
		if strings.HasPrefix(info.Name(), ".") {
			attrs |= 0x02
		} // FILE_ATTRIBUTE_HIDDEN
		ctx.SetReturn(uint64(attrs))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesExW", func(ctx *ntapi.TrapContext) uint32 {
		lpFileName := ctx.Arg(0)
		// fInfoLevelId := ctx.Arg(1) // always GetFileExInfoStandard (0)
		lpFileInfo := ctx.Arg(2)
		path := winPathToVFS(readGuestUTF16(lpFileName))
		info, err := os.Stat(path)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		// WIN32_FILE_ATTRIBUTE_DATA layout:
		// dwFileAttributes(4), ftCreationTime(8), ftLastAccessTime(8),
		// ftLastWriteTime(8), nFileSizeHigh(4), nFileSizeLow(4)
		var attrs uint32
		if info.IsDir() {
			attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
		} else {
			attrs = 0x80 // FILE_ATTRIBUTE_NORMAL
		}
		ctx.Mem.Write32(lpFileInfo, attrs)
		// File times - use ModTime for all three (creation, access, write)
		const epochDiff = uint64(11644473600) * 10000000
		ft := uint64(info.ModTime().UnixNano())/100 + epochDiff
		ctx.Mem.Write32(lpFileInfo+4, uint32(ft))
		ctx.Mem.Write32(lpFileInfo+8, uint32(ft>>32))
		ctx.Mem.Write32(lpFileInfo+12, uint32(ft))
		ctx.Mem.Write32(lpFileInfo+16, uint32(ft>>32))
		ctx.Mem.Write32(lpFileInfo+20, uint32(ft))
		ctx.Mem.Write32(lpFileInfo+24, uint32(ft>>32))
		// File size
		size := uint64(info.Size())
		ctx.Mem.Write32(lpFileInfo+28, uint32(size>>32))
		ctx.Mem.Write32(lpFileInfo+32, uint32(size))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		dataPtr := ctx.Arg(1)
		pattern := readGuestUTF16(pathPtr)
		vfsPattern := winPathToVFS(pattern)
		dir := filepath.Dir(vfsPattern)
		glob := filepath.Base(vfsPattern)
		entries, err := os.ReadDir(dir)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // INVALID_HANDLE_VALUE
			return 0
		}
		var matched []os.DirEntry
		for _, e := range entries {
			ok, _ := filepath.Match(glob, e.Name())
			if ok {
				matched = append(matched, e)
			}
		}
		if len(matched) == 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		fh := &ntapi.FindHandle{Entries: matched, Idx: 1, Dir: dir}
		if dataPtr != 0 {
			writeFindData(ctx.Mem, dataPtr, dir, matched[0])
		}
		h := handles.Alloc(fh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileExW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		dataPtr := ctx.Arg(4)
		pattern := readGuestUTF16(pathPtr)
		vfsPattern := winPathToVFS(pattern)
		dir := filepath.Dir(vfsPattern)
		glob := filepath.Base(vfsPattern)
		entries, err := os.ReadDir(dir)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		var matched []os.DirEntry
		for _, e := range entries {
			ok, _ := filepath.Match(glob, e.Name())
			if ok {
				matched = append(matched, e)
			}
		}
		if len(matched) == 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		fh := &ntapi.FindHandle{Entries: matched, Idx: 1, Dir: dir}
		if dataPtr != 0 {
			writeFindData(ctx.Mem, dataPtr, dir, matched[0])
		}
		h := handles.Alloc(fh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextFileW", func(ctx *ntapi.TrapContext) uint32 {
		hFind := ctx.Arg(0)
		dataPtr := ctx.Arg(1)
		obj := handles.Get(ntapi.Handle(hFind))
		fh, ok := obj.(*ntapi.FindHandle)
		if !ok || fh.Idx >= len(fh.Entries) {
			ctx.SetReturn(0)
			return 0
		}
		if dataPtr != 0 {
			writeFindData(ctx.Mem, dataPtr, fh.Dir, fh.Entries[fh.Idx])
		}
		fh.Idx++
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindClose", func(ctx *ntapi.TrapContext) uint32 {
		handles.Close(ntapi.Handle(ctx.Arg(0)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CopyFileW", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
		in, err := os.Open(src)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		defer out.Close()
		if _, err = io.Copy(out, in); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CopyFileExW", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
		in, err := os.Open(src)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		defer out.Close()
		io.Copy(out, in)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteFileW", func(ctx *ntapi.TrapContext) uint32 {
		path := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		if err := os.Remove(path); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileExW", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
		if err := os.Rename(src, dst); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileAttributesW", func(ctx *ntapi.TrapContext) uint32 {
		lpFileName := ctx.Arg(0)
		dwFileAttributes := uint32(ctx.Arg(1))
		if lpFileName == 0 {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 87) // ERROR_INVALID_PARAMETER
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestUTF16(lpFileName))
		info, err := os.Stat(path)
		if err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2) // ERROR_FILE_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		}
		mode := info.Mode()
		if dwFileAttributes&0x01 != 0 { // FILE_ATTRIBUTE_READONLY
			mode &^= 0222 // remove write bits
		} else {
			mode |= 0200 // add owner write bit
		}
		if err := os.Chmod(path, mode); err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5) // ERROR_ACCESS_DENIED
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetStdHandle", func(ctx *ntapi.TrapContext) uint32 {
		nStdHandle := uint32(ctx.Arg(0))
		hHandle := ctx.Arg(1)
		stdHandleMu.Lock()
		stdHandleMap[nStdHandle] = hHandle
		stdHandleMu.Unlock()
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// --- Memory ---
	d.RegisterAutoStubHandler(kernel32, "GlobalAlloc", func(ctx *ntapi.TrapContext) uint32 {
		flags := ctx.Arg(0)
		size := ctx.Arg(1)
		if size == 0 {
			size = 1
		}
		addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
		if flags&0x0040 != 0 { // GMEM_ZEROINIT
			for i := uint64(0); i < size; i++ {
				mem.Write8(addr+i, 0)
			}
		}
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalLock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalLock", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalUnlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalUnlock", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalFree", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		if hMem != 0 {
			_, size, mapped, _ := mem.QueryRegion(hMem)
			if mapped && size > 0 {
				mem.Munmap(hMem, size)
			}
		}
		ctx.SetReturn(0) // NULL = success
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalSize", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		if hMem == 0 {
			ctx.SetReturn(0)
			return 0
		}
		_, size, mapped, _ := mem.QueryRegion(hMem)
		if mapped {
			ctx.SetReturn(size)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	// --- Locale / string classification ---
	classifyCharType := func(dwInfoType uint64, r rune) uint16 {
		switch dwInfoType {
		case 1: // CT_CTYPE1
			var flags uint16
			if unicode.IsUpper(r) {
				flags |= 0x0001 // C1_UPPER
			}
			if unicode.IsLower(r) {
				flags |= 0x0002 // C1_LOWER
			}
			if unicode.IsDigit(r) {
				flags |= 0x0004 // C1_DIGIT
			}
			if unicode.IsSpace(r) {
				flags |= 0x0008 // C1_SPACE
			}
			if unicode.IsPunct(r) {
				flags |= 0x0010 // C1_PUNCT
			}
			if unicode.IsControl(r) {
				flags |= 0x0020 // C1_CNTRL
			}
			if r == ' ' || r == '\t' {
				flags |= 0x0040 // C1_BLANK
			}
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				flags |= 0x0080 // C1_XDIGIT
			}
			if unicode.IsLetter(r) {
				flags |= 0x0100 // C1_ALPHA
			}
			if r >= 0x20 {
				flags |= 0x0200 // C1_DEFINED
			}
			return flags
		case 2: // CT_CTYPE2
			if unicode.IsDigit(r) {
				return 3 // C2_EUROPENUMBER
			}
			if unicode.IsSpace(r) {
				return 10 // C2_WHITESPACE
			}
			if unicode.Is(unicode.Arabic, r) || unicode.Is(unicode.Hebrew, r) {
				return 2 // C2_RIGHTTOLEFT
			}
			return 1 // C2_LEFTTORIGHT
		case 4: // CT_CTYPE3
			var flags uint16
			if unicode.Is(unicode.Mn, r) {
				flags |= 0x0001 // C3_NONSPACING
			}
			if unicode.IsSymbol(r) || unicode.IsSpace(r) {
				flags |= 0x0008 // C3_SYMBOL
			}
			if unicode.IsLetter(r) {
				flags |= 0x8000 // C3_ALPHA
			}
			if r >= 0x30A0 && r <= 0x30FF {
				flags |= 0x0010 // C3_KATAKANA
			}
			if r >= 0x3040 && r <= 0x309F {
				flags |= 0x0020 // C3_HIRAGANA
			}
			if r >= 0x4E00 && r <= 0x9FAF {
				flags |= 0x0080 // C3_IDEOGRAPH
			}
			if r >= 0xD800 && r <= 0xDBFF {
				flags |= 0x0400 // C3_HIGHSURROGATE
			}
			if r >= 0xDC00 && r <= 0xDFFF {
				flags |= 0x0800 // C3_LOWSURROGATE
			}
			if r >= 0xFF00 && r <= 0xFF60 {
				flags |= 0x2000 // C3_FULLWIDTH
			}
			if r >= 0xFF61 && r <= 0xFFDC {
				flags |= 0x1000 // C3_HALFWIDTH
			}
			return flags
		}
		return 0
	}
	d.RegisterAutoStubHandler(kernel32, "GetStringTypeW", func(ctx *ntapi.TrapContext) uint32 {
		dwInfoType := ctx.Arg(0)
		lpSrcStr := ctx.Arg(1)
		cchSrc := int32(ctx.Arg(2))
		lpCharType := ctx.Arg(3)
		if lpSrcStr == 0 || lpCharType == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if cchSrc == -1 {
			cchSrc = 0
			for i := uint64(0); i < 65536; i++ {
				w, _ := ctx.Mem.Read16(lpSrcStr + i*2)
				cchSrc++
				if w == 0 {
					break
				}
			}
		}
		for i := int32(0); i < cchSrc; i++ {
			w, _ := ctx.Mem.Read16(lpSrcStr + uint64(i)*2)
			ct := classifyCharType(dwInfoType, rune(w))
			ctx.Mem.Write16(lpCharType+uint64(i)*2, ct)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetStringTypeExA", func(ctx *ntapi.TrapContext) uint32 {
		// Locale = Arg(0) (ignored)
		dwInfoType := ctx.Arg(1)
		lpSrcStr := ctx.Arg(2)
		cchSrc := int32(ctx.Arg(3))
		lpCharType := ctx.Arg(4)
		if lpSrcStr == 0 || lpCharType == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if cchSrc == -1 {
			cchSrc = 0
			for i := uint64(0); i < 65536; i++ {
				b, _ := ctx.Mem.Read8(lpSrcStr + i)
				cchSrc++
				if b == 0 {
					break
				}
			}
		}
		for i := int32(0); i < cchSrc; i++ {
			b, _ := ctx.Mem.Read8(lpSrcStr + uint64(i))
			ct := classifyCharType(dwInfoType, rune(b))
			ctx.Mem.Write16(lpCharType+uint64(i)*2, ct)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetStringTypeExW", func(ctx *ntapi.TrapContext) uint32 {
		// Locale = Arg(0) (ignored)
		dwInfoType := ctx.Arg(1)
		lpSrcStr := ctx.Arg(2)
		cchSrc := int32(ctx.Arg(3))
		lpCharType := ctx.Arg(4)
		if lpSrcStr == 0 || lpCharType == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if cchSrc == -1 {
			cchSrc = 0
			for i := uint64(0); i < 65536; i++ {
				w, _ := ctx.Mem.Read16(lpSrcStr + i*2)
				cchSrc++
				if w == 0 {
					break
				}
			}
		}
		for i := int32(0); i < cchSrc; i++ {
			w, _ := ctx.Mem.Read16(lpSrcStr + uint64(i)*2)
			ct := classifyCharType(dwInfoType, rune(w))
			ctx.Mem.Write16(lpCharType+uint64(i)*2, ct)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LCMapStringW", func(ctx *ntapi.TrapContext) uint32 {
		dwMapFlags := ctx.Arg(1)
		srcStr := ctx.Arg(2)
		srcLen := int32(ctx.Arg(3))
		dstBuf := ctx.Arg(4)
		dstLen := int32(ctx.Arg(5))
		var src []uint16
		if srcLen < 0 {
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(srcStr + i)
				if w == 0 {
					break
				}
				src = append(src, w)
			}
		} else {
			for i := int32(0); i < srcLen; i++ {
				w, _ := ctx.Mem.Read16(srcStr + uint64(i)*2)
				src = append(src, w)
			}
		}
		s := string(utf16Decode(src))
		var result string
		if dwMapFlags&0x200 != 0 {
			result = strings.ToUpper(s)
		} else if dwMapFlags&0x100 != 0 {
			result = strings.ToLower(s)
		} else {
			result = s
		}
		ws := utf16Encode(result)
		if dstBuf == 0 {
			ctx.SetReturn(uint64(len(ws)))
			return 0
		}
		n := int32(len(ws))
		if dstLen > 0 && n > dstLen {
			n = dstLen
		}
		for i := int32(0); i < n; i++ {
			ctx.Mem.Write16(dstBuf+uint64(i)*2, ws[i])
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CharUpperW", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		if arg <= 0xFFFF {
			r := unicode.ToUpper(rune(uint16(arg)))
			ctx.SetReturn(uint64(uint16(r)))
			return 0
		}
		s := readGuestUTF16(arg)
		ws := utf16Encode(strings.ToUpper(s))
		for i, w := range ws {
			ctx.Mem.Write16(arg+uint64(i)*2, w)
		}
		ctx.Mem.Write16(arg+uint64(len(ws))*2, 0)
		ctx.SetReturn(arg)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CharLowerW", func(ctx *ntapi.TrapContext) uint32 {
		arg := ctx.Arg(0)
		if arg <= 0xFFFF {
			r := unicode.ToLower(rune(uint16(arg)))
			ctx.SetReturn(uint64(uint16(r)))
			return 0
		}
		s := readGuestUTF16(arg)
		ws := utf16Encode(strings.ToLower(s))
		for i, w := range ws {
			ctx.Mem.Write16(arg+uint64(i)*2, w)
		}
		ctx.Mem.Write16(arg+uint64(len(ws))*2, 0)
		ctx.SetReturn(arg)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsCharAlphaW", func(ctx *ntapi.TrapContext) uint32 {
		if unicode.IsLetter(rune(uint16(ctx.Arg(0)))) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsCharAlphaNumericW", func(ctx *ntapi.TrapContext) uint32 {
		r := rune(uint16(ctx.Arg(0)))
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LCMapStringA", func(ctx *ntapi.TrapContext) uint32 {
		dwMapFlags := ctx.Arg(1)
		srcStr := ctx.Arg(2)
		srcLen := int32(ctx.Arg(3))
		dstBuf := ctx.Arg(4)
		dstLen := int32(ctx.Arg(5))
		var src []byte
		if srcLen < 0 {
			for i := uint64(0); ; i++ {
				b, _ := ctx.Mem.Read8(srcStr + i)
				if b == 0 {
					break
				}
				src = append(src, b)
			}
		} else {
			for i := int32(0); i < srcLen; i++ {
				b, _ := ctx.Mem.Read8(srcStr + uint64(i))
				src = append(src, b)
			}
		}
		s := string(src)
		var result string
		if dwMapFlags&0x200 != 0 {
			result = strings.ToUpper(s)
		} else if dwMapFlags&0x100 != 0 {
			result = strings.ToLower(s)
		} else {
			result = s
		}
		if dstBuf == 0 {
			ctx.SetReturn(uint64(len(result)))
			return 0
		}
		n := int32(len(result))
		if dstLen > 0 && n > dstLen {
			n = dstLen
		}
		for i := int32(0); i < n; i++ {
			ctx.Mem.Write8(dstBuf+uint64(i), result[i])
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LCMapStringEx", func(ctx *ntapi.TrapContext) uint32 {
		dwMapFlags := ctx.Arg(2)
		srcStr := ctx.Arg(3)
		srcLen := int32(ctx.Arg(4))
		dstBuf := ctx.Arg(5)
		dstLen := int32(ctx.Arg(6))
		var src []uint16
		if srcLen < 0 {
			for i := uint64(0); ; i += 2 {
				w, _ := ctx.Mem.Read16(srcStr + i)
				if w == 0 {
					break
				}
				src = append(src, w)
			}
		} else {
			for i := int32(0); i < srcLen; i++ {
				w, _ := ctx.Mem.Read16(srcStr + uint64(i)*2)
				src = append(src, w)
			}
		}
		s := string(utf16Decode(src))
		var result string
		if dwMapFlags&0x200 != 0 {
			result = strings.ToUpper(s)
		} else if dwMapFlags&0x100 != 0 {
			result = strings.ToLower(s)
		} else {
			result = s
		}
		ws := utf16Encode(result)
		if dstBuf == 0 {
			ctx.SetReturn(uint64(len(ws)))
			return 0
		}
		n := int32(len(ws))
		if dstLen > 0 && n > dstLen {
			n = dstLen
		}
		for i := int32(0); i < n; i++ {
			ctx.Mem.Write16(dstBuf+uint64(i)*2, ws[i])
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	// Helper: write locale info strings to guest buffers.
	writeLocaleInfoW := func(buf uint64, cchBuf uint64, val string) uint32 {
		return uint32(writeUTF16StringCount(buf, val, cchBuf))
	}
	writeLocaleInfoA := func(buf uint64, cchBuf uint64, val string) uint32 {
		return uint32(writeANSIStringCount(buf, val, cchBuf))
	}
	getLocaleInfoValue := func(lctype uint32) (string, bool) {
		// ReactOS: dll/win32/kernel32/winnls/string/locale.c
		// LCTYPE constants from winnls.h for en-US locale
		switch lctype {
		case 0x1001: // LOCALE_SENGLANGUAGE
			return "English", true
		case 0x1002: // LOCALE_SENGCOUNTRY
			return "United States", true
		case 0x1003: // LOCALE_STIMEFORMAT
			return "h:mm:ss tt", true
		case 0x1004: // LOCALE_IDEFAULTANSICODEPAGE
			return "1252", true
		case 0x100A: // LOCALE_IPAPERSIZE
			return "1", true
		case 0x1011: // LOCALE_IDEFAULTMACCODEPAGE
			return "10000", true
		case 0x1012: // LOCALE_IDEFAULTEBCDICCODEPAGE
			return "037", true
		}
		switch lctype & 0xFFFF {
		case 0x01: // LOCALE_ILANGUAGE
			return "0409", true
		case 0x02: // LOCALE_SLANGUAGE
			return "English (United States)", true
		case 0x03: // LOCALE_SABBREVLANGNAME
			return "ENU", true
		case 0x04: // LOCALE_SNATIVELANGNAME
			return "English", true
		case 0x05: // LOCALE_ICOUNTRY
			return "1", true
		case 0x06: // LOCALE_SCOUNTRY
			return "United States", true
		case 0x07: // LOCALE_SABBREVCTRYNAME
			return "USA", true
		case 0x08: // LOCALE_SNATIVECTRYNAME
			return "United States", true
		case 0x09: // LOCALE_IDEFAULTLANGUAGE
			return "0409", true
		case 0x0A: // LOCALE_IDEFAULTCOUNTRY
			return "1", true
		case 0x0B: // LOCALE_IDEFAULTCODEPAGE (OEM)
			return "437", true
		case 0x0C: // LOCALE_SLIST
			return ",", true
		case 0x0D: // LOCALE_IMEASURE (1=US/imperial)
			return "1", true
		case 0x0E: // LOCALE_SDECIMAL
			return ".", true
		case 0x0F: // LOCALE_STHOUSAND
			return ",", true
		case 0x10: // LOCALE_SGROUPING
			return "3;0", true
		case 0x11: // LOCALE_IDIGITS
			return "2", true
		case 0x12: // LOCALE_ILZERO
			return "1", true
		case 0x13: // LOCALE_SNATIVEDIGITS
			return "0123456789", true
		case 0x14: // LOCALE_SCURRENCY
			return "$", true
		case 0x15: // LOCALE_SINTLSYMBOL
			return "USD", true
		case 0x16: // LOCALE_SMONDECIMALSEP
			return ".", true
		case 0x17: // LOCALE_SMONTHOUSANDSEP
			return ",", true
		case 0x18: // LOCALE_SMONGROUPING
			return "3;0", true
		case 0x19: // LOCALE_ICURRDIGITS
			return "2", true
		case 0x1B: // LOCALE_ICURRENCY
			return "0", true
		case 0x1C: // LOCALE_INEGCURR
			return "0", true
		case 0x1D: // LOCALE_SDATE
			return "/", true
		case 0x1E: // LOCALE_STIME
			return ":", true
		case 0x1F: // LOCALE_SSHORTDATE
			return "M/d/yyyy", true
		case 0x20: // LOCALE_SLONGDATE
			return "dddd, MMMM d, yyyy", true
		case 0x21: // LOCALE_IDATE
			return "0", true
		case 0x23: // LOCALE_ITIME
			return "0", true
		case 0x25: // LOCALE_ITLZERO
			return "0", true
		case 0x28: // LOCALE_S1159
			return "AM", true
		case 0x29: // LOCALE_S2359
			return "PM", true
		case 0x2A: // LOCALE_SDAYNAME1 (Monday)
			return "Monday", true
		case 0x2B: // LOCALE_SDAYNAME2
			return "Tuesday", true
		case 0x2C: // LOCALE_SDAYNAME3
			return "Wednesday", true
		case 0x2D: // LOCALE_SDAYNAME4
			return "Thursday", true
		case 0x2E: // LOCALE_SDAYNAME5
			return "Friday", true
		case 0x2F: // LOCALE_SDAYNAME6
			return "Saturday", true
		case 0x30: // LOCALE_SDAYNAME7
			return "Sunday", true
		case 0x31: // LOCALE_SABBREVDAYNAME1
			return "Mon", true
		case 0x32: // LOCALE_SABBREVDAYNAME2
			return "Tue", true
		case 0x33: // LOCALE_SABBREVDAYNAME3
			return "Wed", true
		case 0x34: // LOCALE_SABBREVDAYNAME4
			return "Thu", true
		case 0x35: // LOCALE_SABBREVDAYNAME5
			return "Fri", true
		case 0x36: // LOCALE_SABBREVDAYNAME6
			return "Sat", true
		case 0x37: // LOCALE_SABBREVDAYNAME7
			return "Sun", true
		case 0x38: // LOCALE_SMONTHNAME1
			return "January", true
		case 0x39: // LOCALE_SMONTHNAME2
			return "February", true
		case 0x3A: // LOCALE_SMONTHNAME3
			return "March", true
		case 0x3B: // LOCALE_SMONTHNAME4
			return "April", true
		case 0x3C: // LOCALE_SMONTHNAME5
			return "May", true
		case 0x3D: // LOCALE_SMONTHNAME6
			return "June", true
		case 0x3E: // LOCALE_SMONTHNAME7
			return "July", true
		case 0x3F: // LOCALE_SMONTHNAME8
			return "August", true
		case 0x40: // LOCALE_SMONTHNAME9
			return "September", true
		case 0x41: // LOCALE_SMONTHNAME10
			return "October", true
		case 0x42: // LOCALE_SMONTHNAME11
			return "November", true
		case 0x43: // LOCALE_SMONTHNAME12
			return "December", true
		case 0x44: // LOCALE_SABBREVMONTHNAME1
			return "Jan", true
		case 0x45: // LOCALE_SABBREVMONTHNAME2
			return "Feb", true
		case 0x46: // LOCALE_SABBREVMONTHNAME3
			return "Mar", true
		case 0x47: // LOCALE_SABBREVMONTHNAME4
			return "Apr", true
		case 0x48: // LOCALE_SABBREVMONTHNAME5
			return "May", true
		case 0x49: // LOCALE_SABBREVMONTHNAME6
			return "Jun", true
		case 0x4A: // LOCALE_SABBREVMONTHNAME7
			return "Jul", true
		case 0x4B: // LOCALE_SABBREVMONTHNAME8
			return "Aug", true
		case 0x4C: // LOCALE_SABBREVMONTHNAME9
			return "Sep", true
		case 0x4D: // LOCALE_SABBREVMONTHNAME10
			return "Oct", true
		case 0x4E: // LOCALE_SABBREVMONTHNAME11
			return "Nov", true
		case 0x4F: // LOCALE_SABBREVMONTHNAME12
			return "Dec", true
		case 0x50: // LOCALE_SPOSITIVESIGN
			return "", true
		case 0x51: // LOCALE_SNEGATIVESIGN
			return "-", true
		case 0x59: // LOCALE_SISO639LANGNAME
			return "en", true
		case 0x5A: // LOCALE_SISO3166CTRYNAME
			return "US", true
		case 0x5C: // LOCALE_SNAME (Vista+)
			return defaultLocaleName, true
		case 0x5D: // LOCALE_SDURATION
			return "h:mm:ss", true
		case 0x60: // LOCALE_SSHORTESTDAYNAME1
			return "Mo", true
		case 0x61: // LOCALE_SSHORTESTDAYNAME2
			return "Tu", true
		case 0x62: // LOCALE_SSHORTESTDAYNAME3
			return "We", true
		case 0x63: // LOCALE_SSHORTESTDAYNAME4
			return "Th", true
		case 0x64: // LOCALE_SSHORTESTDAYNAME5
			return "Fr", true
		case 0x65: // LOCALE_SSHORTESTDAYNAME6
			return "Sa", true
		case 0x66: // LOCALE_SSHORTESTDAYNAME7
			return "Su", true
		case 0x6C: // LOCALE_SSCRIPTS
			return "Latn;", true
		case 0x6D: // LOCALE_SPARENT
			return "en", true
		case 0x72: // LOCALE_SENGLISHDISPLAYNAME
			return "English (United States)", true
		case 0x73: // LOCALE_SNATIVEDISPLAYNAME
			return "English (United States)", true
		case 0x76: // LOCALE_SPERCENT
			return "%", true
		case 0x79: // LOCALE_SSHORTTIME
			return "h:mm tt", true
		default:
			return "", false
		}
	}
	d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoA", func(ctx *ntapi.TrapContext) uint32 {
		locale := uint32(ctx.Arg(0))
		lctype := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		cchBuf := ctx.Arg(3)
		_ = lcidToLocaleNameValue(locale)
		val, ok := getLocaleInfoValue(lctype)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(writeLocaleInfoA(buf, cchBuf, val)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoW", func(ctx *ntapi.TrapContext) uint32 {
		locale := uint32(ctx.Arg(0))
		lctype := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		cchBuf := ctx.Arg(3)
		_ = lcidToLocaleNameValue(locale)
		val, ok := getLocaleInfoValue(lctype)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(writeLocaleInfoW(buf, cchBuf, val)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLocaleInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		_ = normalizeLocaleName(readGuestUTF16(ctx.Arg(0)))
		lctype := uint32(ctx.Arg(2))
		buf := ctx.Arg(3)
		cchBuf := ctx.Arg(4)
		val, ok := getLocaleInfoValue(lctype)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(uint64(writeLocaleInfoW(buf, cchBuf, val)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CompareStringEx", func(ctx *ntapi.TrapContext) uint32 {
		// CompareStringEx(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2, ...)
		dwFlags := uint32(ctx.Arg(1))
		s1Ptr := ctx.Arg(2)
		cch1 := int32(ctx.Arg(3))
		s2Ptr := ctx.Arg(4)
		cch2 := int32(ctx.Arg(5))
		s1 := readWideStringArg(s1Ptr, cch1)
		s2 := readWideStringArg(s2Ptr, cch2)
		if dwFlags&1 != 0 { // NORM_IGNORECASE
			s1 = strings.ToLower(s1)
			s2 = strings.ToLower(s2)
		}
		if s1 < s2 {
			ctx.SetReturn(1)
		} else if s1 > s2 {
			ctx.SetReturn(3)
		} else {
			ctx.SetReturn(2)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CompareStringW", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := uint32(ctx.Arg(1))
		s1Ptr := ctx.Arg(2)
		cch1 := int32(ctx.Arg(3))
		s2Ptr := ctx.Arg(4)
		cch2 := int32(ctx.Arg(5))
		s1 := readWideStringArg(s1Ptr, cch1)
		s2 := readWideStringArg(s2Ptr, cch2)
		if dwFlags&1 != 0 {
			s1 = strings.ToLower(s1)
			s2 = strings.ToLower(s2)
		}
		if s1 < s2 {
			ctx.SetReturn(1)
		} else if s1 > s2 {
			ctx.SetReturn(3)
		} else {
			ctx.SetReturn(2)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLCID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetUserDefaultLCID", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "IsValidLocale", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: dll/win32/kernel32/winnls/string/locale.c
		lcid := uint32(ctx.Arg(0))
		switch lcid {
		case 0x0409, // en-US
			0x0809, // en-GB
			0x0C09, // en-AU
			0x1009, // en-CA
			0x1409, // en-NZ
			0x0009, // en (neutral)
			0x0000, // LOCALE_NEUTRAL
			0x0400, // LOCALE_USER_DEFAULT
			0x0800, // LOCALE_SYSTEM_DEFAULT
			0x007F, // LOCALE_INVARIANT
			0x0407, // de-DE
			0x040C, // fr-FR
			0x0410, // it-IT
			0x0411, // ja-JP
			0x0412, // ko-KR
			0x0804, // zh-CN
			0x0404, // zh-TW
			0x0416, // pt-BR
			0x0C0A, // es-ES
			0x0419: // ru-RU
			ctx.SetReturn(1)
		default:
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemLocalesW", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetOEMCP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetOEMCP", 8, uint64(defaultOEMCodePage))
	})
	// --- Time functions ---
	d.RegisterAutoStubHandler(kernel32, "GetTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
		tz := ctx.Arg(0)
		// TIME_ZONE_INFORMATION (172 bytes):
		//   +0x00 LONG  Bias                   (4 bytes)
		//   +0x04 WCHAR StandardName[32]       (64 bytes, offsets 4..67)
		//   +0x44 SYSTEMTIME StandardDate      (16 bytes, offsets 68..83)
		//   +0x54 LONG  StandardBias           (4 bytes)
		//   +0x58 WCHAR DaylightName[32]       (64 bytes, offsets 88..151)
		//   +0x98 SYSTEMTIME DaylightDate      (16 bytes, offsets 152..167)
		//   +0xA8 LONG  DaylightBias           (4 bytes)
		for i := uint64(0); i < 172; i++ {
			ctx.Mem.Write8(tz+i, 0)
		}
		// Bias = -60 (UTC+1, Central European) as signed int32
		biasSigned := int32(-60)
		ctx.Mem.Write32(tz+0, uint32(biasSigned))
		// StandardName = "UTC" (UTF-16LE)
		for i, r := range "UTC" {
			ctx.Mem.Write16(tz+4+uint64(i)*2, uint16(r))
		}
		// StandardDate SYSTEMTIME: {wYear=0, wMonth=10, wDayOfWeek=0, wDay=5, wHour=3, ...}
		ctx.Mem.Write16(tz+68, 0)  // wYear
		ctx.Mem.Write16(tz+70, 10) // wMonth = October
		ctx.Mem.Write16(tz+72, 0)  // wDayOfWeek = Sunday
		ctx.Mem.Write16(tz+74, 5)  // wDay = last occurrence
		ctx.Mem.Write16(tz+76, 3)  // wHour = 3:00
		// StandardBias = 0
		ctx.Mem.Write32(tz+84, 0)
		// DaylightName = "UTC+1" (UTF-16LE)
		for i, r := range "UTC+1" {
			ctx.Mem.Write16(tz+88+uint64(i)*2, uint16(r))
		}
		// DaylightDate SYSTEMTIME: {wYear=0, wMonth=3, wDayOfWeek=0, wDay=5, wHour=2, ...}
		ctx.Mem.Write16(tz+152, 0) // wYear
		ctx.Mem.Write16(tz+154, 3) // wMonth = March
		ctx.Mem.Write16(tz+156, 0) // wDayOfWeek = Sunday
		ctx.Mem.Write16(tz+158, 5) // wDay = last occurrence
		ctx.Mem.Write16(tz+160, 2) // wHour = 2:00
		// DaylightBias = -60
		ctx.Mem.Write32(tz+168, uint32(biasSigned))
		// Determine if currently in DST (Northern Hemisphere: April-October)
		month := int(time.Now().Month())
		if month >= 4 && month <= 10 {
			ctx.SetReturn(2) // TIME_ZONE_ID_DAYLIGHT
		} else {
			ctx.SetReturn(1) // TIME_ZONE_ID_STANDARD
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLocalTime", func(ctx *ntapi.TrapContext) uint32 {
		st := ctx.Arg(0)
		now := time.Now()
		ctx.Mem.Write16(st+0, uint16(now.Year()))
		ctx.Mem.Write16(st+2, uint16(now.Month()))
		ctx.Mem.Write16(st+4, uint16(now.Weekday()))
		ctx.Mem.Write16(st+6, uint16(now.Day()))
		ctx.Mem.Write16(st+8, uint16(now.Hour()))
		ctx.Mem.Write16(st+10, uint16(now.Minute()))
		ctx.Mem.Write16(st+12, uint16(now.Second()))
		ctx.Mem.Write16(st+14, uint16(now.Nanosecond()/1e6))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FileTimeToSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		ft := ctx.Arg(0)
		st := ctx.Arg(1)
		lo, _ := ctx.Mem.Read32(ft)
		hi, _ := ctx.Mem.Read32(ft + 4)
		ticks := int64(hi)<<32 | int64(lo)
		// Convert from 100ns intervals since 1601 to Go time
		t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(ticks) * 100)
		ctx.Mem.Write16(st+0, uint16(t.Year()))
		ctx.Mem.Write16(st+2, uint16(t.Month()))
		ctx.Mem.Write16(st+4, uint16(t.Weekday()))
		ctx.Mem.Write16(st+6, uint16(t.Day()))
		ctx.Mem.Write16(st+8, uint16(t.Hour()))
		ctx.Mem.Write16(st+10, uint16(t.Minute()))
		ctx.Mem.Write16(st+12, uint16(t.Second()))
		ctx.Mem.Write16(st+14, uint16(t.Nanosecond()/1e6))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SystemTimeToTzSpecificLocalTime", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(1)
		dst := ctx.Arg(2)
		// Copy SYSTEMTIME (16 bytes) as-is
		for i := uint64(0); i < 16; i++ {
			b, _ := ctx.Mem.Read8(src + i)
			ctx.Mem.Write8(dst+i, b)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDateFormatW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		cchDate := ctx.Arg(5)
		now := time.Now()
		s := fmt.Sprintf("%02d/%02d/%04d", now.Month(), now.Day(), now.Year())
		ws := utf16Encode(s)
		if buf == 0 || cchDate == 0 {
			ctx.SetReturn(uint64(len(ws) + 1))
			return 0
		}
		n := uint64(len(ws) + 1)
		if n > cchDate {
			n = cchDate
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(buf+i*2, ws[i])
		}
		ctx.Mem.Write16(buf+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTimeFormatW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		cchTime := ctx.Arg(5)
		now := time.Now()
		s := fmt.Sprintf("%02d:%02d:%02d", now.Hour(), now.Minute(), now.Second())
		ws := utf16Encode(s)
		if buf == 0 || cchTime == 0 {
			ctx.SetReturn(uint64(len(ws) + 1))
			return 0
		}
		n := uint64(len(ws) + 1)
		if n > cchTime {
			n = cchTime
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(buf+i*2, ws[i])
		}
		ctx.Mem.Write16(buf+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDateFormatEx", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		cchDate := ctx.Arg(5)
		now := time.Now()
		s := fmt.Sprintf("%02d/%02d/%04d", now.Month(), now.Day(), now.Year())
		ws := utf16Encode(s)
		if buf == 0 || cchDate == 0 {
			ctx.SetReturn(uint64(len(ws) + 1))
			return 0
		}
		n := uint64(len(ws) + 1)
		if n > cchDate {
			n = cchDate
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(buf+i*2, ws[i])
		}
		ctx.Mem.Write16(buf+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTimeFormatEx", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		cchTime := ctx.Arg(5)
		now := time.Now()
		s := fmt.Sprintf("%02d:%02d:%02d", now.Hour(), now.Minute(), now.Second())
		ws := utf16Encode(s)
		if buf == 0 || cchTime == 0 {
			ctx.SetReturn(uint64(len(ws) + 1))
			return 0
		}
		n := uint64(len(ws) + 1)
		if n > cchTime {
			n = cchTime
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(buf+i*2, ws[i])
		}
		ctx.Mem.Write16(buf+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	// --- Exception handling ---
	d.RegisterAutoStubHandler(kernel32, "RtlPcToFileHeader", func(ctx *ntapi.TrapContext) uint32 {
		headerOut := ctx.Arg(1)
		imageBase, _ := ctx.Mem.Read64(procState.PEBAddr + 0x10)
		if headerOut != 0 {
			ctx.Mem.Write64(headerOut, imageBase)
		}
		ctx.SetReturn(imageBase)
		return 0
	})
	// Allocate a vmcall trampoline for catch funclet returns.
	// When a catch funclet does RET, it lands here.
	// The trampoline saves RAX (funclet return) in RCX, then does vmcall.
	catchReturnTrampoline := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	off := catchReturnTrampoline
	// mov rcx, rax    (48 89 C1) - save funclet return value
	mem.Write8(off, 0x48)
	mem.Write8(off+1, 0x89)
	mem.Write8(off+2, 0xC1)
	off += 3
	// mov eax, CatchReturnID  (B8 xx xx xx xx)
	mem.Write8(off, 0xB8)
	mem.Write32(off+1, ntapi.CatchReturnID)
	off += 5
	// vmcall  (0F 01 C1)
	mem.Write8(off, 0x0F)
	mem.Write8(off+1, 0x01)
	mem.Write8(off+2, 0xC1)
	off += 3
	// ret (C3) - shouldn't reach here
	mem.Write8(off, 0xC3)
	d.RegisterHandler(ntapi.CatchReturnID, "CatchReturn", func(ctx *ntapi.TrapContext) uint32 {
		// RCX = funclet's return value (continuation address)
		continuation := ctx.Arg(0) // Arg(0) = RCX in Win64 ABI
		if continuation != 0 {
			ravelog.Logf("[seh] catch funclet → continuation at 0x%x\n", continuation)
			ctx.CPU.SetPC(continuation)
		} else {
			// RAX=0: funclet didn't provide a continuation.
			// Use the pre-computed FH4 continuation from IP-to-state map.
			savedCont, _ := mem.Read64(catchReturnTrampoline + 80)
			bodyRSP, _ := mem.Read64(catchReturnTrampoline + 152)
			if savedCont != 0 {
				ravelog.Logf("[seh] catch funclet → RAX=0, using FH4 continuation at 0x%x bodyRSP=0x%x\n", savedCont, bodyRSP)
				// Restore non-volatile registers from unwind context
				if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
					nonVolRegs := []int{3, 5, 6, 7, 12, 13, 14, 15}
					for i, reg := range nonVolRegs {
						val, _ := mem.Read64(catchReturnTrampoline + 88 + uint64(i*8))
						rw.WriteReg(reg, val)
					}
					// Restore R11 = entry RSP (establisher - 8), used as frame pointer by some functions
					establisher, _ := mem.Read64(catchReturnTrampoline + 160)
					if establisher != 0 {
						rw.WriteReg(11, establisher-8) // R11
					}
				}
				ctx.CPU.SetPC(savedCont)
				ctx.CPU.SetSP(bodyRSP)
			} else {
				// No continuation available - resume at RaiseException caller
				savedRIP, _ := mem.Read64(catchReturnTrampoline + 64)
				savedRSP, _ := mem.Read64(catchReturnTrampoline + 72)
				ravelog.Logf("[seh] catch funclet → RAX=0, resuming at RIP=0x%x RSP=0x%x\n", savedRIP, savedRSP)
				ctx.CPU.SetPC(savedRIP)
				ctx.CPU.SetSP(savedRSP)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RaiseException", func(ctx *ntapi.TrapContext) uint32 {
		code := ctx.Arg(0)
		flags := ctx.Arg(1)
		ravelog.Logf("[win32] RaiseException: code=0x%x flags=0x%x\n", code, flags)
		if code == 0x406D1388 {
			return 0 // MS_VC_EXCEPTION (SetThreadName) - ignore
		}
		if code == 0xe06d7363 {
			// MSVC C++ exception - try SEH dispatch to find catch handler
			rsp := ctx.CPU.GetSP()
			rip := ctx.CPU.GetPC()
			handler := ntapi.CxxDispatchException(ctx.Mem, exceptionTable, rsp, rip, ctx.Trace)
			if handler != nil {
				imageBase := uint64(0)
				if exceptionTable != nil {
					imageBase = exceptionTable.ImageBase
				}
				if handler.IsFallback {
					// FH4 format: can't parse catch blocks, unwind past the handler frame
					ravelog.Logf("[seh] C++ exception → FH4 fallback unwind to RIP=0x%x RSP=0x%x\n",
						handler.FallbackRIP, handler.FallbackRSP)
					if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
						rw.WriteReg(0, 0) // RAX = 0 (error return)
						// Restore saved non-volatile registers
						for reg, val := range handler.SavedRegs {
							rw.WriteReg(reg, val)
						}
					}
					ctx.CPU.SetSP(handler.FallbackRSP)
					ctx.CPU.SetPC(handler.FallbackRIP)
					return 0
				}
				catchAddr := imageBase + uint64(handler.FuncletRVA)
				ravelog.Logf("[seh] C++ exception → catch funclet at 0x%x, establisher=0x%x contRVA=0x%x catchObjOffset=%d\n",
					catchAddr, handler.EstablisherRBP, handler.ContinuationRVA, handler.CatchObjOffset)
				// Place the thrown object (or reference) at [EstablisherRBP + CatchObjOffset].
				// RaiseException args layout for 0xe06d7363:
				//   args[0] = magic (0x19930520 / 0x19930521)
				//   args[1] = pointer to thrown object
				//   args[2] = pointer to _ThrowInfo
				nParams := ctx.Arg(2)
				pArgs := ctx.Arg(3)
				if handler.CatchObjOffset != 0 && nParams >= 2 && pArgs != 0 {
					thrownObjPtr, _ := mem.Read64(pArgs + 8) // args[1]
					dest := handler.EstablisherRBP + uint64(int64(handler.CatchObjOffset))
					ravelog.Logf("[seh] placing thrown obj ptr=0x%x at [establisher+offset]=0x%x\n", thrownObjPtr, dest)
					mem.Write64(dest, thrownObjPtr)
				}
				// If no funclet but we have a continuation, jump directly there
				if handler.FuncletRVA == 0 && handler.ContinuationRVA != 0 {
					contAddr := imageBase + uint64(handler.ContinuationRVA)
					ravelog.Logf("[seh] no funclet, jumping to continuation at 0x%x bodyRSP=0x%x\n", contAddr, handler.BodyRSP)
					if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
						if handler.SavedRegs != nil {
							for reg, val := range handler.SavedRegs {
								rw.WriteReg(reg, val)
							}
						}
					}
					// Resume at continuation with the function's body RSP
					ctx.CPU.SetPC(contAddr)
					ctx.CPU.SetSP(handler.BodyRSP)
					return 0
				}
				if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
					// Restore saved non-volatile registers from unwind
					if handler.SavedRegs != nil {
						for reg, val := range handler.SavedRegs {
							rw.WriteReg(reg, val)
						}
					}
					rw.WriteReg(2, handler.EstablisherRBP) // RDX = establisher frame (funclet uses mov rbp, rdx)
				}
				// Save the current RSP/RIP so CatchReturn can resume here if RAX=0.
				// The RaiseException stub's RET will pop the return address from rsp.
				// We save that return address + the RSP after the pop.
				raiseRetAddr, _ := mem.Read64(rsp)
				mem.Write64(catchReturnTrampoline+64, raiseRetAddr)
				mem.Write64(catchReturnTrampoline+72, rsp+8) // RSP after RaiseException RET
				// Save FH4 continuation address (if available)
				if handler.ContinuationRVA != 0 {
					mem.Write64(catchReturnTrampoline+80, imageBase+uint64(handler.ContinuationRVA))
				} else {
					mem.Write64(catchReturnTrampoline+80, 0)
				}
				// Save body RSP for continuation (function's RSP after prologue)
				mem.Write64(catchReturnTrampoline+152, handler.BodyRSP)
				// Save establisher (for R11 restore: entry RSP = establisher - 8)
				mem.Write64(catchReturnTrampoline+160, handler.EstablisherRBP)
				// Save non-volatile registers for continuation restore
				// Layout: [88]=RBX [96]=RBP [104]=RSI [112]=RDI [120]=R12 [128]=R13 [136]=R14 [144]=R15
				nonVolRegs := []int{3, 5, 6, 7, 12, 13, 14, 15} // RBX,RBP,RSI,RDI,R12-R15
				if handler.SavedRegs != nil {
					for i, reg := range nonVolRegs {
						if val, ok := handler.SavedRegs[reg]; ok {
							mem.Write64(catchReturnTrampoline+88+uint64(i*8), val)
						} else {
							mem.Write64(catchReturnTrampoline+88+uint64(i*8), 0)
						}
					}
				}
				// Set up a proper call frame: push catch-return trampoline
				// so funclet's RET lands on our vmcall trampoline.
				sp := handler.EstablisherRBP
				sp -= 8
				mem.Write64(sp, catchReturnTrampoline)
				ctx.CPU.SetSP(sp)
				ctx.CPU.SetPC(catchAddr)
				return 0
			}
			// No handler found - log and continue (best effort)
			ravelog.Logf("[win32] RaiseException: C++ exception (0xe06d7363) - no SEH handler, continuing\n")
			return 0
		}
		exceptionRecordAddr := mem.Mmap(0, 0x100, mmu.PermRead|mmu.PermWrite)
		contextRecordAddr := mem.Mmap(0, 1232, mmu.PermRead|mmu.PermWrite)
		mem.Write32(exceptionRecordAddr+0x00, uint32(code))
		mem.Write32(exceptionRecordAddr+0x04, uint32(flags))
		mem.Write64(exceptionRecordAddr+0x08, 0)
		mem.Write64(exceptionRecordAddr+0x10, ctx.CPU.GetPC())
		nParams := uint32(ctx.Arg(2))
		if nParams > 15 {
			nParams = 15
		}
		mem.Write32(exceptionRecordAddr+0x18, nParams)
		if pArgs := ctx.Arg(3); pArgs != 0 {
			for i := uint32(0); i < nParams; i++ {
				v, _ := mem.Read64(pArgs + uint64(i)*8)
				mem.Write64(exceptionRecordAddr+0x20+uint64(i)*8, v)
			}
		}
		if cm, ok := ctx.CPU.(ntapi.ContextMarshaler); ok {
			_ = cm.SaveContext(mem, contextRecordAddr)
		}
		handled, _ := ntapi.DispatchException(ctx.Mem, exceptionRecordAddr, contextRecordAddr, func(addr uint64, args []uint64) (uint64, error) {
			return callGuest(ctx, addr, args)
		}, ctx.Trace)
		if handled {
			if cm, ok := ctx.CPU.(ntapi.ContextMarshaler); ok {
				_ = cm.RestoreContext(mem, contextRecordAddr)
			}
			return 0
		}
		if procState.UnhandledExceptionFilter != 0 {
			exceptionPointersAddr := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
			mem.Write64(exceptionPointersAddr+0, exceptionRecordAddr)
			mem.Write64(exceptionPointersAddr+8, contextRecordAddr)
			ret, err := callGuest(ctx, procState.UnhandledExceptionFilter, []uint64{exceptionPointersAddr})
			if err == nil && uint32(ret) == ntapi.ExceptionContinueExecution {
				if cm, ok := ctx.CPU.(ntapi.ContextMarshaler); ok {
					_ = cm.RestoreContext(mem, contextRecordAddr)
				}
				return 0
			}
		}
		fmt.Fprintf(os.Stderr, "govm: RaiseException code=0x%x flags=0x%x - aborting\n", code, flags)
		os.Exit(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlUnwindEx", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlUnwind", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TerminateProcess", func(ctx *ntapi.TrapContext) uint32 {
		code := ctx.Arg(1)
		// Log guest call stack
		sp := ctx.CPU.GetSP()
		fmt.Fprintf(os.Stderr, "govm: TerminateProcess code=%d (0x%x) RSP=0x%x\n", code, code, sp)
		for i := uint64(0); i < 8; i++ {
			ret, _ := ctx.Mem.Read64(sp + i*8)
			fmt.Fprintf(os.Stderr, "  [RSP+0x%02x] = 0x%x\n", i*8, ret)
		}
		// STATUS_STACK_BUFFER_OVERRUN (GS cookie failure) - try to survive by
		// rewinding the stack to the message loop if possible.
		if code == 0xC0000417 {
			fmt.Fprintf(os.Stderr, "govm: GS cookie failure - attempting to survive\n")
			// Return 0 from TerminateProcess; caller (__report_gsfailure) will
			// return as well. Execution continues from the instruction after CALL.
			ctx.SetReturn(0)
			return 0
		}
		os.Exit(int(code))
		return 0
	})
	// --- Miscellaneous ---
	d.RegisterAutoStubHandler(kernel32, "MulDiv", func(ctx *ntapi.TrapContext) uint32 {
		a := int64(int32(ctx.Arg(0)))
		b := int64(int32(ctx.Arg(1)))
		c := int64(int32(ctx.Arg(2)))
		if c == 0 {
			ctx.SetReturn(uint64(0xFFFFFFFF)) // -1
			return 0
		}
		result := (a * b) / c
		ctx.SetReturn(uint64(int32(result)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ExpandEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		srcPtr := ctx.Arg(0)
		dst := ctx.Arg(1)
		size := ctx.Arg(2)
		src := readGuestUTF16(srcPtr)
		// Expand common Windows environment variables
		src = strings.ReplaceAll(src, `%APPDATA%`, `C:\Users\User\AppData\Roaming`)
		src = strings.ReplaceAll(src, `%LOCALAPPDATA%`, `C:\Users\User\AppData\Local`)
		src = strings.ReplaceAll(src, `%TEMP%`, `C:\Windows\Temp`)
		src = strings.ReplaceAll(src, `%TMP%`, `C:\Windows\Temp`)
		src = strings.ReplaceAll(src, `%USERPROFILE%`, `C:\Users\User`)
		src = strings.ReplaceAll(src, `%WINDIR%`, `C:\Windows`)
		src = strings.ReplaceAll(src, `%SYSTEMROOT%`, `C:\Windows`)
		src = strings.ReplaceAll(src, `%SYSTEMDRIVE%`, `C:`)
		src = strings.ReplaceAll(src, `%PROGRAMFILES%`, `C:\Program Files`)
		src = strings.ReplaceAll(src, `%USERNAME%`, `User`)
		// Write result
		runes := []rune(src)
		n := uint64(0)
		for i, r := range runes {
			if n < size {
				ctx.Mem.Write16(dst+n*2, uint16(r))
			}
			n++
			_ = i
		}
		if n < size {
			ctx.Mem.Write16(dst+n*2, 0)
		}
		ctx.SetReturn(n + 1) // length including null
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		valPtr := ctx.Arg(1)
		if valPtr == 0 {
			delete(envVars, name)
		} else {
			envVars[name] = readGuestUTF16(valPtr)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceExW", func(ctx *ntapi.TrapContext) uint32 {
		free := ctx.Arg(1)
		total := ctx.Arg(2)
		totalFree := ctx.Arg(3)
		var st unix.Statfs_t
		freeBytesAvail := uint64(50 * 1024 * 1024 * 1024)
		totalBytes := uint64(100 * 1024 * 1024 * 1024)
		totalFreeBytes := uint64(50 * 1024 * 1024 * 1024)
		if unix.Statfs("/", &st) == nil {
			totalBytes = st.Blocks * uint64(st.Bsize)
			totalFreeBytes = st.Bfree * uint64(st.Bsize)
			freeBytesAvail = st.Bavail * uint64(st.Bsize)
		}
		if free != 0 {
			ctx.Mem.Write64(free, freeBytesAvail)
		}
		if total != 0 {
			ctx.Mem.Write64(total, totalBytes)
		}
		if totalFree != 0 {
			ctx.Mem.Write64(totalFree, totalFreeBytes)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VerSetConditionMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VerSetConditionMask", 4, uint64(ctx.Arg(0)|1))
	})
	d.RegisterAutoStubHandler(kernel32, "VerifyVersionInfoW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VerifyVersionInfoW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetApplicationRestartSettings", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetApplicationRestartSettings", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "UnregisterApplicationRestart", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UnregisterApplicationRestart", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterApplicationRestart", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterApplicationRestart", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FormatMessageW", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		dwMessageId := ctx.Arg(2)
		lpBuffer := ctx.Arg(4)
		nSize := ctx.Arg(5)
		const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
		const FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
		// ReactOS: dll/win32/kernel32/client/except.c - FormatMessageW
		// Map common Win32 error codes to human-readable messages
		var msg string
		if dwFlags&FORMAT_MESSAGE_FROM_SYSTEM != 0 {
			switch uint32(dwMessageId) {
			case 0:
				msg = "The operation completed successfully."
			case 1:
				msg = "Incorrect function."
			case 2:
				msg = "The system cannot find the file specified."
			case 3:
				msg = "The system cannot find the path specified."
			case 4:
				msg = "The system cannot open the file."
			case 5:
				msg = "Access is denied."
			case 6:
				msg = "The handle is invalid."
			case 8:
				msg = "Not enough storage is available to process this command."
			case 11:
				msg = "An attempt was made to load a program with an incorrect format."
			case 12:
				msg = "The access code is invalid."
			case 13:
				msg = "The data is invalid."
			case 14:
				msg = "Not enough storage is available to complete this operation."
			case 15:
				msg = "The system cannot find the drive specified."
			case 17:
				msg = "The system cannot move the file to a different disk drive."
			case 18:
				msg = "There are no more files."
			case 21:
				msg = "The device is not ready."
			case 29:
				msg = "The system cannot write to the specified device."
			case 30:
				msg = "The system cannot read from the specified device."
			case 32:
				msg = "The process cannot access the file because it is being used by another process."
			case 33:
				msg = "The process cannot access the file because another process has locked a portion of the file."
			case 36:
				msg = "Too many files opened for sharing."
			case 38:
				msg = "Reached the end of the file."
			case 50:
				msg = "The request is not supported."
			case 80:
				msg = "The file exists."
			case 87:
				msg = "The parameter is incorrect."
			case 109:
				msg = "The pipe has been ended."
			case 110:
				msg = "The system cannot open the device or file specified."
			case 111:
				msg = "The file name is too long."
			case 120:
				msg = "This function is not supported on this system."
			case 122:
				msg = "The data area passed to a system call is too small."
			case 123:
				msg = "The filename, directory name, or volume label syntax is incorrect."
			case 126:
				msg = "The specified module could not be found."
			case 127:
				msg = "The specified procedure could not be found."
			case 128:
				msg = "There are no child processes to wait for."
			case 183:
				msg = "Cannot create a file when that file already exists."
			case 203:
				msg = "The system could not find the environment option that was entered."
			case 230:
				msg = "The pipe state is invalid."
			case 231:
				msg = "All pipe instances are busy."
			case 232:
				msg = "The pipe is being closed."
			case 233:
				msg = "No process is on the other end of the pipe."
			case 234:
				msg = "More data is available."
			case 267:
				msg = "The directory name is invalid."
			case 534:
				msg = "Arithmetic result exceeded 32 bits."
			case 995:
				msg = "The I/O operation has been aborted because of either a thread exit or an application request."
			case 996:
				msg = "Overlapped I/O event is not in a signaled state."
			case 997:
				msg = "Overlapped I/O operation is in progress."
			case 998:
				msg = "Invalid access to memory location."
			case 1004:
				msg = "Invalid flags."
			case 1008:
				msg = "An attempt was made to reference a token that does not exist."
			case 1113:
				msg = "No mapping for the Unicode character exists in the target multi-byte code page."
			case 1114:
				msg = "A dynamic link library (DLL) initialization routine failed."
			case 1150:
				msg = "The specified program requires a newer version of Windows."
			case 1155:
				msg = "No application is associated with the specified file for this operation."
			default:
				msg = fmt.Sprintf("Error 0x%X", dwMessageId)
			}
		} else {
			msg = fmt.Sprintf("Error 0x%X", dwMessageId)
		}
		ws := utf16Encode(msg)
		n := uint64(len(ws))
		if dwFlags&FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
			bufSize := (n + 2) * 2
			addr := mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)
			for i, w := range ws {
				ctx.Mem.Write16(addr+uint64(i)*2, w)
			}
			mem.Write16(addr+n*2, 0)
			if lpBuffer != 0 {
				ctx.Mem.Write64(lpBuffer, addr)
			}
		} else if lpBuffer != 0 && nSize > 0 {
			maxN := nSize - 1
			if n > maxN {
				n = maxN
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write16(lpBuffer+i*2, ws[i])
			}
			ctx.Mem.Write16(lpBuffer+n*2, 0)
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FormatMessageA", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		dwMessageId := ctx.Arg(2)
		lpBuffer := ctx.Arg(4)
		nSize := ctx.Arg(5)
		const FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100
		const FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
		var msg string
		if dwFlags&FORMAT_MESSAGE_FROM_SYSTEM != 0 {
			switch uint32(dwMessageId) {
			case 0:
				msg = "The operation completed successfully."
			case 2:
				msg = "The system cannot find the file specified."
			case 3:
				msg = "The system cannot find the path specified."
			case 5:
				msg = "Access is denied."
			case 6:
				msg = "The handle is invalid."
			case 8:
				msg = "Not enough storage is available to process this command."
			case 13:
				msg = "The data is invalid."
			case 14:
				msg = "Not enough storage is available to complete this operation."
			case 18:
				msg = "There are no more files."
			case 32:
				msg = "The process cannot access the file because it is being used by another process."
			case 87:
				msg = "The parameter is incorrect."
			case 109:
				msg = "The pipe has been ended."
			case 122:
				msg = "The data area passed to a system call is too small."
			case 126:
				msg = "The specified module could not be found."
			case 127:
				msg = "The specified procedure could not be found."
			case 183:
				msg = "Cannot create a file when that file already exists."
			case 234:
				msg = "More data is available."
			case 267:
				msg = "The directory name is invalid."
			case 997:
				msg = "Overlapped I/O operation is in progress."
			case 998:
				msg = "Invalid access to memory location."
			default:
				msg = fmt.Sprintf("Error 0x%X", dwMessageId)
			}
		} else {
			msg = fmt.Sprintf("Error 0x%X", dwMessageId)
		}
		n := uint64(len(msg))
		if dwFlags&FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
			addr := mem.Mmap(0, n+2, mmu.PermRead|mmu.PermWrite)
			for i := range msg {
				ctx.Mem.Write8(addr+uint64(i), msg[i])
			}
			mem.Write8(addr+n, 0)
			if lpBuffer != 0 {
				ctx.Mem.Write64(lpBuffer, addr)
			}
		} else if lpBuffer != 0 && nSize > 0 {
			maxN := nSize - 1
			if n > maxN {
				n = maxN
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write8(lpBuffer+i, msg[i])
			}
			ctx.Mem.Write8(lpBuffer+n, 0)
		}
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LoadResource", func(ctx *ntapi.TrapContext) uint32 {
		// HGLOBAL LoadResource(HMODULE hModule, HRSRC hResInfo)
		hResInfo := ctx.Arg(1)
		if e, ok := hrsrcTable[hResInfo]; ok {
			ctx.SetReturn(e.dataAddr)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindResourceW", func(ctx *ntapi.TrapContext) uint32 {
		// HRSRC FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType)
		hModule := ctx.Arg(0)
		lpName := ctx.Arg(1)
		lpType := ctx.Arg(2)
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 || peLoadRawResource == nil {
			ctx.SetReturn(0)
			return 0
		}
		// IS_INTRESOURCE: if value < 0x10000, it's an integer resource ID
		typeID := uint32(lpType)
		if lpType > 0xFFFF {
			typeID = 0 // named type - not supported yet
		}
		resID := uint32(lpName)
		if lpName > 0xFFFF {
			resID = 0 // named resource - not supported yet
		}
		if typeID == 0 || resID == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dataAddr, dataSize, ok := peLoadRawResource(baseAddr, rsrcRVA, typeID, resID)
		if !ok || dataAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		h := hrsrcNext
		hrsrcNext++
		hrsrcTable[h] = hrsrcEntry{dataAddr: dataAddr, dataSize: dataSize}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LockResource", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LockResource", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "SizeofResource", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD SizeofResource(HMODULE hModule, HRSRC hResInfo)
		hResInfo := ctx.Arg(1)
		if e, ok := hrsrcTable[hResInfo]; ok {
			ctx.SetReturn(uint64(e.dataSize))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempPathW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		tmp := `C:\Windows\TEMP\`
		for i, ch := range tmp {
			ctx.Mem.Write16(buf+uint64(i*2), uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(tmp)*2), 0)
		ctx.SetReturn(uint64(len(tmp)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EnterCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LeaveCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		nCharsToRead := uint32(ctx.Arg(2))
		charsRead := ctx.Arg(3)
		_, wide := readConsoleText(int(nCharsToRead), false)
		if uint32(len(wide)) > nCharsToRead {
			wide = wide[:nCharsToRead]
		}
		for i, r := range wide {
			ctx.Mem.Write16(buf+uint64(i)*2, r)
		}
		if charsRead != 0 {
			ctx.Mem.Write32(charsRead, uint32(len(wide)))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileMappingW", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		flProtect := uint32(ctx.Arg(2))
		szHigh := uint32(ctx.Arg(3))
		szLow := uint32(ctx.Arg(4))
		name := readGuestUTF16(ctx.Arg(5))
		h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
		hMapping := ntapi.Handle(ctx.Arg(0))
		dwDesiredAccess := uint32(ctx.Arg(1))
		offHigh := uint32(ctx.Arg(2))
		offLow := uint32(ctx.Arg(3))
		numBytes := ctx.Arg(4)
		guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
		ctx.SetReturn(guestAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UnmapViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
		doUnmapView(ctx, ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FreeLibraryAndExitThread", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ExitThread", func(ctx *ntapi.TrapContext) uint32 {
		exitCode := ctx.Arg(0)
		_ = exitCode
		ctx.SetReturn(0)
		return 0
	})
	// IsWow64Process: always return FALSE (native 64-bit)
	d.RegisterAutoStubHandler(kernel32, "IsWow64Process", func(ctx *ntapi.TrapContext) uint32 {
		lpIsWow64 := ctx.Arg(1)
		if lpIsWow64 != 0 {
			mem.Write32(lpIsWow64, 0) // FALSE
		}
		ctx.SetReturn(1) // success
		return 0
	})
	// ResolveDelayLoadedAPI: resolve delay-loaded imports to our synth stubs
	d.RegisterAutoStubHandler(kernel32, "ResolveDelayLoadedAPI", func(ctx *ntapi.TrapContext) uint32 {
		callerBase := ctx.Arg(0)
		pDescriptor := ctx.Arg(1)
		pThunkAddr := ctx.Arg(4)
		dllNameRVA, _ := mem.Read32(pDescriptor + 4)
		iatRVA, _ := mem.Read32(pDescriptor + 0x0C)
		intRVA, _ := mem.Read32(pDescriptor + 0x10)
		// Read DLL name
		var dllName string
		if dllNameRVA != 0 {
			nameAddr := callerBase + uint64(dllNameRVA)
			var buf []byte
			for i := uint64(0); i < 260; i++ {
				b, _ := mem.Read8(nameAddr + i)
				if b == 0 {
					break
				}
				buf = append(buf, b)
			}
			dllName = strings.ToLower(string(buf))
		}
		// Find function name from thunk
		iatBase := callerBase + uint64(iatRVA)
		intBase := callerBase + uint64(intRVA)
		var funcName string
		if pThunkAddr >= iatBase {
			idx := (pThunkAddr - iatBase) / 8
			intEntry, _ := mem.Read64(intBase + idx*8)
			if intEntry != 0 && intEntry&(1<<63) == 0 {
				nameAddr := callerBase + intEntry + 2
				var buf []byte
				for i := uint64(0); i < 260; i++ {
					b, _ := mem.Read8(nameAddr + i)
					if b == 0 {
						break
					}
					buf = append(buf, b)
				}
				funcName = string(buf)
			}
		}
		if dllName == "" || funcName == "" {
			goto fallback
		}
		// If synth DLL doesn't exist yet, create it from all INT entries
		if _, ok := synthByName[dllName]; !ok {
			var allFuncs []string
			for i := uint64(0); ; i++ {
				entry, _ := mem.Read64(intBase + i*8)
				if entry == 0 {
					break
				}
				if entry&(1<<63) != 0 {
					continue
				} // ordinal
				addr := callerBase + entry + 2
				var buf []byte
				for j := uint64(0); j < 260; j++ {
					b, _ := mem.Read8(addr + j)
					if b == 0 {
						break
					}
					buf = append(buf, b)
				}
				if len(buf) > 0 {
					allFuncs = append(allFuncs, string(buf))
				}
			}
			if len(allFuncs) > 0 {
				synth := ntapi.GenerateSynthDLL(mem, dllName, allFuncs, hctx.NextDelayID)
				synthByName[dllName] = synth
				d.RegisterAutoStubNames(synth)
				ravelog.Logf("[pe] delay-synth %s: %d stubs (id base 0x%X) funcs=%v\n",
					dllName, len(allFuncs), hctx.NextDelayID, allFuncs)
				hctx.NextDelayID += uint32(len(allFuncs))
				// Re-run all handler registrars so newly synthesized DLL gets handlers
				for _, reg := range hctx.DelayHandlerRegistrars {
					reg()
				}
			}
		}
		if synth, ok := synthByName[dllName]; ok {
			if addr, ok2 := synth.Exports[funcName]; ok2 {
				mem.Write64(pThunkAddr, addr)
				ctx.SetReturn(addr)
				return 0
			}
		}
		ravelog.Logf("[delay] unresolved: %s!%s\n", dllName, funcName)
	fallback:
		if hctx.DelayLoadFallback == 0 {
			hctx.DelayLoadFallback = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			mem.Write8(hctx.DelayLoadFallback, 0x31)
			mem.Write8(hctx.DelayLoadFallback+1, 0xC0)
			mem.Write8(hctx.DelayLoadFallback+2, 0xC3)
		}
		if pThunkAddr != 0 {
			mem.Write64(pThunkAddr, hctx.DelayLoadFallback)
		}
		ctx.SetReturn(hctx.DelayLoadFallback)
		return 0
	})
	// GetEnvironmentVariableA: look up in envVars, then os.Getenv
	d.RegisterAutoStubHandler(kernel32, "GetEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		buf := ctx.Arg(1)
		size := ctx.Arg(2)
		var val string
		if v, ok := envVars[name]; ok {
			val = v
		} else {
			val = os.Getenv(name)
		}
		if val == "" {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 203)
			ctx.SetReturn(0)
			return 0
		}
		needed := uint64(len(val) + 1)
		if buf == 0 || size == 0 {
			ctx.SetReturn(needed)
			return 0
		}
		if needed > size {
			ctx.SetReturn(needed)
			return 0
		}
		for i := range val {
			ctx.Mem.Write8(buf+uint64(i), val[i])
		}
		ctx.Mem.Write8(buf+uint64(len(val)), 0)
		ctx.SetReturn(uint64(len(val)))
		return 0
	})
	// GetComputerNameW
	d.RegisterAutoStubHandler(kernel32, "GetComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
		lpBuffer := ctx.Arg(0)
		nSize := ctx.Arg(1)
		name := "RAVEN-PC"
		if lpBuffer != 0 && nSize != 0 {
			maxLen, _ := mem.Read32(nSize)
			for i, ch := range name {
				if uint32(i) >= maxLen {
					break
				}
				mem.Write16(lpBuffer+uint64(i)*2, uint16(ch))
			}
			mem.Write16(lpBuffer+uint64(len(name))*2, 0)
			mem.Write32(nSize, uint32(len(name)))
		}
		ctx.SetReturn(1)
		return 0
	})
	// CreateFileA: convert ANSI filename to UTF-16 then delegate to CreateFileW logic
	d.RegisterAutoStubHandler(kernel32, "CreateFileA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		desiredAccess := ctx.Arg(1)
		creationDisp := ctx.Arg(4)
		name := readGuestString(namePtr)
		vfsPath := winPathToVFS(name)
		lastBS := strings.LastIndex(imagePath, `\`)
		peWinDir := imagePath
		if lastBS >= 0 {
			peWinDir = imagePath[:lastBS]
		}
		peVfsDir := winPathToVFS(peWinDir)
		var flags int
		switch creationDisp {
		case 1:
			flags = vfs.O_CREAT | vfs.O_RDWR
		case 2:
			flags = vfs.O_CREAT | vfs.O_TRUNC | vfs.O_RDWR
		case 3:
			flags = vfs.O_RDONLY
			if desiredAccess&0x40000000 != 0 {
				flags = vfs.O_RDWR
			}
		case 4:
			flags = vfs.O_CREAT | vfs.O_RDWR
		case 5:
			flags = vfs.O_TRUNC | vfs.O_RDWR
		default:
			flags = vfs.O_RDONLY
		}
		fd, err := ctx.FS.Open(vfsPath, flags)
		if err != nil {
			parts := strings.SplitN(strings.TrimPrefix(vfsPath, "/"), "/", 2)
			if len(parts) == 2 {
				altPath := peVfsDir + "/" + parts[1]
				if fd2, err2 := ctx.FS.Open(altPath, flags); err2 == nil {
					fd = fd2
					err = nil
					vfsPath = altPath
				}
			}
		}
		if err != nil {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			procState.LastError = 2
			return 0
		}
		h := handles.Alloc(&ntapi.FileHandle{FD: fd, Path: vfsPath})
		ctx.SetReturn(uint64(h))
		return 0
	})
	// CreateToolhelp32Snapshot: no process enumeration support
	d.RegisterAutoStubHandler(kernel32, "CreateToolhelp32Snapshot", func(ctx *ntapi.TrapContext) uint32 {
		mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 18) // ERROR_NO_MORE_FILES
		ctx.SetReturn(0xFFFFFFFFFFFFFFFF)                          // INVALID_HANDLE_VALUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeviceIoControl", func(ctx *ntapi.TrapContext) uint32 {
		// hDevice := ctx.Arg(0)
		ioctl := uint32(ctx.Arg(1))
		// lpInBuffer := ctx.Arg(2)
		// nInBufferSize := ctx.Arg(3)
		lpOutBuffer := ctx.Arg(4)
		nOutBufferSize := uint32(ctx.Arg(5))
		lpBytesReturned := ctx.Arg(6)
		// lpOverlapped := ctx.Arg(7)
		switch ioctl {
		case 0x00070000: // IOCTL_DISK_GET_DRIVE_GEOMETRY
			if lpOutBuffer != 0 && nOutBufferSize >= 24 {
				ctx.Mem.Write64(lpOutBuffer, 10000)  // Cylinders
				ctx.Mem.Write32(lpOutBuffer+8, 3)    // MediaType (FixedMedia)
				ctx.Mem.Write32(lpOutBuffer+12, 255) // TracksPerCylinder
				ctx.Mem.Write32(lpOutBuffer+16, 63)  // SectorsPerTrack
				ctx.Mem.Write32(lpOutBuffer+20, 512) // BytesPerSector
				if lpBytesReturned != 0 {
					ctx.Mem.Write32(lpBytesReturned, 24)
				}
				ctx.SetReturn(1)
				return 0
			}
		case 0x002D1080: // IOCTL_STORAGE_GET_DEVICE_NUMBER
			if lpOutBuffer != 0 && nOutBufferSize >= 12 {
				ctx.Mem.Write32(lpOutBuffer, 7)   // DeviceType (FILE_DEVICE_DISK)
				ctx.Mem.Write32(lpOutBuffer+4, 0) // DeviceNumber
				ctx.Mem.Write32(lpOutBuffer+8, 1) // PartitionNumber
				if lpBytesReturned != 0 {
					ctx.Mem.Write32(lpBytesReturned, 12)
				}
				ctx.SetReturn(1)
				return 0
			}
		case 0x000900A8: // FSCTL_GET_REPARSE_POINT
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 4390) // ERROR_NOT_A_REPARSE_POINT
			if lpBytesReturned != 0 {
				ctx.Mem.Write32(lpBytesReturned, 0)
			}
			ctx.SetReturn(0)
			return 0
		}
		// Default: unsupported IOCTL
		mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 1) // ERROR_INVALID_FUNCTION
		if lpBytesReturned != 0 {
			ctx.Mem.Write32(lpBytesReturned, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	// GetConsoleScreenBufferInfo: return reasonable 80x25 defaults
	d.RegisterAutoStubHandler(kernel32, "GetConsoleScreenBufferInfo", func(ctx *ntapi.TrapContext) uint32 {
		cs := resolveConsoleState(ctx.Arg(0))
		pInfo := ctx.Arg(1)
		if pInfo != 0 && cs != nil {
			mem.Write16(pInfo+0, uint16(cs.Width))
			mem.Write16(pInfo+2, uint16(cs.Height))
			mem.Write16(pInfo+4, uint16(cs.CursorX))
			mem.Write16(pInfo+6, uint16(cs.CursorY))
			mem.Write16(pInfo+8, cs.Attr)
			mem.Write16(pInfo+10, 0)
			mem.Write16(pInfo+12, 0)
			mem.Write16(pInfo+14, uint16(cs.Width-1))
			mem.Write16(pInfo+16, uint16(cs.Height-1))
			mem.Write16(pInfo+18, uint16(cs.Width))
			mem.Write16(pInfo+20, uint16(cs.Height))
		}
		ctx.SetReturn(1)
		return 0
	})
	// GetConsoleWindow: return hctx.MainHWND for apps that need a window handle
	d.RegisterAutoStubHandler(kernel32, "GetConsoleWindow", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(consolePseudoHWND)
		return 0
	})
	// GetDiskFreeSpaceExA: use real host disk space via statfs
	d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceExA", func(ctx *ntapi.TrapContext) uint32 {
		free := ctx.Arg(1)
		total := ctx.Arg(2)
		totalFree := ctx.Arg(3)
		var st unix.Statfs_t
		freeBytesAvail := uint64(50 * 1024 * 1024 * 1024)
		totalBytes := uint64(100 * 1024 * 1024 * 1024)
		totalFreeBytes := uint64(50 * 1024 * 1024 * 1024)
		if unix.Statfs("/", &st) == nil {
			totalBytes = st.Blocks * uint64(st.Bsize)
			totalFreeBytes = st.Bfree * uint64(st.Bsize)
			freeBytesAvail = st.Bavail * uint64(st.Bsize)
		}
		if free != 0 {
			ctx.Mem.Write64(free, freeBytesAvail)
		}
		if total != 0 {
			ctx.Mem.Write64(total, totalBytes)
		}
		if totalFree != 0 {
			ctx.Mem.Write64(totalFree, totalFreeBytes)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// GetLogicalDriveStringsA: return "C:\\\0\0" as ANSI
	d.RegisterAutoStubHandler(kernel32, "GetLogicalDriveStringsA", func(ctx *ntapi.TrapContext) uint32 {
		nBuf := uint32(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		driveStr := []byte{'C', ':', '\\', 0, 0}
		if lpBuf != 0 && nBuf >= uint32(len(driveStr)) {
			ctx.Mem.WriteBytes(lpBuf, driveStr)
		}
		ctx.SetReturn(uint64(len(driveStr) - 1)) // chars written, excluding final null
		return 0
	})
	// GetDriveTypeA: return DRIVE_FIXED (3) for C:\, DRIVE_NO_ROOT_DIR (1) otherwise
	d.RegisterAutoStubHandler(kernel32, "GetDriveTypeA", func(ctx *ntapi.TrapContext) uint32 {
		lpRootPathName := ctx.Arg(0)
		driveType := uint64(1) // DRIVE_NO_ROOT_DIR
		if lpRootPathName != 0 {
			path := ctx.Mem.ReadCString(lpRootPathName, 16)
			if len(path) > 0 && (path[0] == 'C' || path[0] == 'c') {
				driveType = 3 // DRIVE_FIXED
			}
		}
		ravelog.Logf("[kernel32] GetDriveTypeA → %d\n", driveType)
		ctx.SetReturn(driveType)
		return 0
	})
	// GlobalMemoryStatusEx: fill MEMORYSTATUSEX with 8 GB total / 5 GB free
	d.RegisterAutoStubHandler(kernel32, "GlobalMemoryStatusEx", func(ctx *ntapi.TrapContext) uint32 {
		pBuf := ctx.Arg(0)
		if pBuf != 0 {
			// MEMORYSTATUSEX layout (64 bytes total):
			// DWORD  dwLength                 +0
			// DWORD  dwMemoryLoad             +4
			// DWORDLONG ullTotalPhys           +8
			// DWORDLONG ullAvailPhys           +16
			// DWORDLONG ullTotalPageFile       +24
			// DWORDLONG ullAvailPageFile       +32
			// DWORDLONG ullTotalVirtual        +40
			// DWORDLONG ullAvailVirtual        +48
			// DWORDLONG ullAvailExtendedVirtual +56
			mem.Write32(pBuf+0, 64)                  // dwLength
			mem.Write32(pBuf+4, 40)                  // dwMemoryLoad (40%)
			mem.Write64(pBuf+8, 8*1024*1024*1024)    // ullTotalPhys = 8 GB
			mem.Write64(pBuf+16, 5*1024*1024*1024)   // ullAvailPhys = 5 GB
			mem.Write64(pBuf+24, 16*1024*1024*1024)  // ullTotalPageFile = 16 GB
			mem.Write64(pBuf+32, 12*1024*1024*1024)  // ullAvailPageFile = 12 GB
			mem.Write64(pBuf+40, 0x00007FFFFFFEFFFF) // ullTotalVirtual = ~128 TB
			mem.Write64(pBuf+48, 0x00007FFFFFDEFFFF) // ullAvailVirtual
			mem.Write64(pBuf+56, 0)                  // ullAvailExtendedVirtual
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// Process32First: no processes to enumerate
	d.RegisterAutoStubHandler(kernel32, "Process32First", func(ctx *ntapi.TrapContext) uint32 {
		mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 18) // ERROR_NO_MORE_FILES
		ctx.SetReturn(0)                                           // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleTextAttribute", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		attr := uint16(ctx.Arg(1))
		cs := resolveConsoleState(handle)
		if cs != nil {
			cs.Attr = attr
		}
		if isVisibleConsoleState(cs) {
			_, _ = os.Stdout.WriteString(attrToANSI(attr))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AcquireSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AcquireSRWLockShared", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ActivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
		// ActivateActCtx(hActCtx, lpCookie) - write a nonzero cookie
		lpCookie := ctx.Arg(1)
		if lpCookie != 0 {
			ctx.Mem.Write64(lpCookie, 1)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AddAtomA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		ctx.SetReturn(uint64(addAtomLocal(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AddAtomW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		ctx.SetReturn(uint64(addAtomLocal(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AddConsoleAliasA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AddConsoleAliasA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "AddConsoleAliasW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AddConsoleAliasW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "AddDllDirectory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AddDllDirectory", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "AddRefActCtx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AddRefActCtx", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "AddVectoredContinueHandler", func(ctx *ntapi.TrapContext) uint32 {
		// AddVectoredContinueHandler(First, Handler)
		first := ctx.Arg(0) != 0
		handler := ctx.Arg(1)
		h := ntapi.GlobalVCH.Add(handler, first)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AddVectoredExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
		// AddVectoredExceptionHandler(First, Handler)
		first := ctx.Arg(0) != 0
		handler := ctx.Arg(1)
		h := ntapi.GlobalVEH.Add(handler, first)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AllocConsole", func(ctx *ntapi.TrapContext) uint32 {
		consoleStateMu.Lock()
		consoleAttached = true
		consoleStateMu.Unlock()
		emitConsoleTitle(consoleTitle)
		refreshVisibleConsole(activeConsoleState)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AllocateUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AllocateUserPhysicalPages", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "AllocateUserPhysicalPagesNuma", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AllocateUserPhysicalPagesNuma", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "AppPolicyGetMediaFoundationCodecLoading", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AppPolicyGetMediaFoundationCodecLoading", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "AppPolicyGetWindowingModel", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AppPolicyGetWindowingModel", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ApplicationRecoveryFinished", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ApplicationRecoveryFinished", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ApplicationRecoveryInProgress", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ApplicationRecoveryInProgress", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "AreFileApisANSI", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AreFileApisANSI", 0, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "AssignProcessToJobObject", func(ctx *ntapi.TrapContext) uint32 {
		jh := ntapi.Handle(ctx.Arg(0))
		// pid 1 since we're single-process
		if j := handles.GetJob(jh); j != nil {
			j.AddProcess(1)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "AttachConsole", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "AttachConsole", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "BackupRead", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BackupRead", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BackupSeek", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BackupSeek", 6, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BackupWrite", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BackupWrite", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseAttachCompleteThunk", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseAttachCompleteThunk", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseCheckAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseCheckAppcompatCache", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseCleanupAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseCleanupAppcompatCache", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseCleanupAppcompatCacheSupport", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseCleanupAppcompatCacheSupport", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseDumpAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseDumpAppcompatCache", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseFlushAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseFlushAppcompatCache", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseGetNamedObjectDirectory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseGetNamedObjectDirectory", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseInitAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseInitAppcompatCache", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseInitAppcompatCacheSupport", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseInitAppcompatCacheSupport", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseProcessInitPostImport", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseProcessInitPostImport", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseThreadInitThunk", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseThreadInitThunk", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BaseUpdateAppcompatCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BaseUpdateAppcompatCache", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Beep", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Beep", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "BeginUpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BeginUpdateResourceA", 2, uint64(0x2001))
	})
	d.RegisterAutoStubHandler(kernel32, "BeginUpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BeginUpdateResourceW", 2, uint64(0x2001))
	})
	d.RegisterAutoStubHandler(kernel32, "BindIoCompletionCallback", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BindIoCompletionCallback", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "BuildCommDCBA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BuildCommDCBA", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BuildCommDCBAndTimeoutsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BuildCommDCBAndTimeoutsA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BuildCommDCBAndTimeoutsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BuildCommDCBAndTimeoutsW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "BuildCommDCBW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "BuildCommDCBW", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CallNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CallNamedPipeA", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CallNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CallNamedPipeW", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CallbackMayRunLong", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CallbackMayRunLong", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelDeviceWakeupRequest", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelDeviceWakeupRequest", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelIo", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelIoEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelIoEx", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelSynchronousIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelSynchronousIo", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelThreadpoolIo", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CancelTimerQueueTimer", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CancelWaitableTimer", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if wt, ok := handles.Get(h).(*ntapi.WaitableTimerHandle); ok && wt != nil {
			wt.Cancel()
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ChangeTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ChangeTimerQueueTimer", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CheckNameLegalDOS8Dot3A", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CheckNameLegalDOS8Dot3A", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CheckNameLegalDOS8Dot3W", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CheckNameLegalDOS8Dot3W", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CheckRemoteDebuggerPresent", func(ctx *ntapi.TrapContext) uint32 {
		pbDebuggerPresent := ctx.Arg(1)
		if pbDebuggerPresent != 0 {
			ctx.Mem.Write32(pbDebuggerPresent, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ClearCommBreak", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ClearCommBreak", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ClearCommError", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ClearCommError", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseConsoleHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseConsoleHandle", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseProfileUserMapping", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseProfileUserMapping", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ClosePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ClosePseudoConsole", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseSystemHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseSystemHandle", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpool", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseThreadpool", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolCleanupGroup", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseThreadpoolCleanupGroup", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolCleanupGroupMembers", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseThreadpoolCleanupGroupMembers", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CloseThreadpoolIo", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if tt := handles.GetTpTimer(h); tt != nil {
			tt.Shutdown()
		}
		handles.Close(h)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if tw := handles.GetTpWait(h); tw != nil {
			tw.Shutdown()
		}
		handles.Close(h)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CloseThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if tw := handles.GetTpWork(h); tw != nil {
			tw.Shutdown()
		}
		handles.Close(h)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CmdBatNotification", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CmdBatNotification", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CommConfigDialogA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CommConfigDialogA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CommConfigDialogW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CommConfigDialogW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CompareFileTime", func(ctx *ntapi.TrapContext) uint32 {
		ft1, _ := ctx.Mem.Read64(ctx.Arg(0))
		ft2, _ := ctx.Mem.Read64(ctx.Arg(1))
		if ft1 < ft2 {
			ctx.SetReturn(uint64(0xFFFFFFFF))
		} else if ft1 > ft2 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CompareStringA", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := uint32(ctx.Arg(1))
		s1Ptr := ctx.Arg(2)
		cch1 := int32(ctx.Arg(3))
		s2Ptr := ctx.Arg(4)
		cch2 := int32(ctx.Arg(5))
		readA := func(ptr uint64, cch int32) string {
			if ptr == 0 {
				return ""
			}
			if cch == -1 {
				return readGuestString(ptr)
			}
			b, _ := mem.ReadBytes(ptr, int(cch))
			return string(b)
		}
		s1 := readA(s1Ptr, cch1)
		s2 := readA(s2Ptr, cch2)
		if dwFlags&1 != 0 {
			s1 = strings.ToLower(s1)
			s2 = strings.ToLower(s2)
		}
		if s1 < s2 {
			ctx.SetReturn(1)
		} else if s1 > s2 {
			ctx.SetReturn(3)
		} else {
			ctx.SetReturn(2)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CompareStringOrdinal", func(ctx *ntapi.TrapContext) uint32 {
		s1Ptr := ctx.Arg(0)
		cch1 := int32(ctx.Arg(1))
		s2Ptr := ctx.Arg(2)
		cch2 := int32(ctx.Arg(3))
		bIgnoreCase := ctx.Arg(4) != 0
		readW := func(ptr uint64, cch int32) string {
			if ptr == 0 {
				return ""
			}
			if cch == -1 {
				return readGuestUTF16(ptr)
			}
			data := make([]uint16, cch)
			for i := 0; i < int(cch); i++ {
				w, _ := mem.Read16(ptr + uint64(i)*2)
				data[i] = w
			}
			return string(utf16.Decode(data))
		}
		s1 := readW(s1Ptr, cch1)
		s2 := readW(s2Ptr, cch2)
		if bIgnoreCase {
			s1 = strings.ToLower(s1)
			s2 = strings.ToLower(s2)
		}
		if s1 < s2 {
			ctx.SetReturn(1)
		} else if s1 > s2 {
			ctx.SetReturn(3)
		} else {
			ctx.SetReturn(2)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ConnectNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
		hPipe := ntapi.Handle(ctx.Arg(0))
		ph := handles.GetNamedPipe(hPipe)
		if ph == nil {
			ctx.SetReturn(0)
			return 0
		}
		ph.Connected = true
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ConsoleMenuControl", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ConsoleMenuControl", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ConsoleSubst", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ConsoleSubst", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ContinueDebugEvent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ContinueDebugEvent", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ConvertDefaultLocale", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ConvertDefaultLocale", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "ConvertFiberToThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ConvertFiberToThread", 0, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ConvertThreadToFiber", func(ctx *ntapi.TrapContext) uint32 {
		// LPVOID ConvertThreadToFiber(LPVOID lpParameter);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		lpParam := ctx.Arg(0)
		fiberMu.Lock()
		if nextFiberAddr == 0 {
			nextFiberAddr = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		} else {
			nextFiberAddr = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		}
		addr := nextFiberAddr
		fiberMap[addr] = lpParam
		// Store lpParameter at the start of the fiber data block
		mem.Write64(addr, lpParam)
		fiberMu.Unlock()
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ConvertThreadToFiberEx", func(ctx *ntapi.TrapContext) uint32 {
		// LPVOID ConvertThreadToFiberEx(LPVOID lpParameter, DWORD dwFlags);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		lpParam := ctx.Arg(0)
		fiberMu.Lock()
		nextFiberAddr = mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		addr := nextFiberAddr
		fiberMap[addr] = lpParam
		mem.Write64(addr, lpParam)
		fiberMu.Unlock()
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ConvertToGlobalHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ConvertToGlobalHandle", 4, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "CopyContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CopyContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CopyFile2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CopyFile2", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CopyFileA", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestString(ctx.Arg(0)))
		dst := winPathToVFS(readGuestString(ctx.Arg(1)))
		failIfExists := ctx.Arg(2) != 0
		if failIfExists {
			if _, err := os.Stat(dst); err == nil {
				mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
				ctx.SetReturn(0)
				return 0
			}
		}
		in, err := os.Open(src)
		if err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2)
			ctx.SetReturn(0)
			return 0
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CopyFileExA", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestString(ctx.Arg(0)))
		dst := winPathToVFS(readGuestString(ctx.Arg(1)))
		flags := ctx.Arg(5)
		if flags&1 != 0 { // COPY_FILE_FAIL_IF_EXISTS
			if _, err := os.Stat(dst); err == nil {
				mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
				ctx.SetReturn(0)
				return 0
			}
		}
		in, err := os.Open(src)
		if err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2)
			ctx.SetReturn(0)
			return 0
		}
		defer in.Close()
		out, err := os.Create(dst)
		if err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		defer out.Close()
		if _, err := io.Copy(out, in); err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CopyLZFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CopyLZFile", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateActCtxA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateActCtxA(ACTCTXA*) - return a fake valid handle
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "actctx"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateActCtxW", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "actctx"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateBoundaryDescriptorA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateBoundaryDescriptorA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateBoundaryDescriptorW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateBoundaryDescriptorW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateConsoleScreenBuffer", func(ctx *ntapi.TrapContext) uint32 {
		sb := ntapi.NewConsoleScreenBuffer()
		if sb.State != nil {
			resizeConsoleState(sb.State, activeConsoleState.Width, activeConsoleState.Height)
			sb.State.Attr = activeConsoleState.Attr
			sb.State.Mode = outputModeForHandle(stdOutputHandleValue)
			sb.State.Title = consoleTitle
			sb.State.CursorVisible = activeConsoleState.CursorVisible
			sb.State.CursorSize = activeConsoleState.CursorSize
		}
		h := handles.Alloc(sb)
		consoleStateMu.Lock()
		consoleOutputModes[uint64(h)] = sb.State.Mode
		consoleStateMu.Unlock()
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		if pathPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestString(pathPtr))
		if err := os.MkdirAll(path, 0755); err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 183) // ERROR_ALREADY_EXISTS
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryExA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(1)
		if pathPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestString(pathPtr))
		if err := os.MkdirAll(path, 0755); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryExW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(1)
		if pathPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestUTF16(pathPtr))
		if err := os.MkdirAll(path, 0755); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateDirectoryTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateDirectoryTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateDirectoryTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateEventA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateEventA(lpAttr, bManualReset, bInitialState, lpName)
		manualReset := ctx.Arg(1) != 0
		initialState := ctx.Arg(2) != 0
		h := handles.Alloc(ntapi.NewEvent(manualReset, initialState))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateEventExA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateEventExA(lpAttr, lpName, dwFlags, dwDesiredAccess)
		// dwFlags: 1=CREATE_EVENT_INITIAL_SET, 2=CREATE_EVENT_MANUAL_RESET
		dwFlags := ctx.Arg(2)
		h := handles.Alloc(ntapi.NewEvent(dwFlags&2 != 0, dwFlags&1 != 0))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateEventExW", func(ctx *ntapi.TrapContext) uint32 {
		// CreateEventExW(lpAttr, lpName, dwFlags, dwDesiredAccess)
		dwFlags := ctx.Arg(2)
		h := handles.Alloc(ntapi.NewEvent(dwFlags&2 != 0, dwFlags&1 != 0))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFiber", func(ctx *ntapi.TrapContext) uint32 {
		// LPVOID CreateFiber(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress,
		//                    LPVOID lpParameter);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		lpParam := ctx.Arg(2)
		fiberMu.Lock()
		addr := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		fiberMap[addr] = lpParam
		mem.Write64(addr, lpParam)
		// Store start address at offset 8 for potential future dispatch
		mem.Write64(addr+8, ctx.Arg(1))
		fiberMu.Unlock()
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFiberEx", func(ctx *ntapi.TrapContext) uint32 {
		// LPVOID CreateFiberEx(SIZE_T dwStackCommitSize, SIZE_T dwStackReserveSize,
		//                      DWORD dwFlags, LPFIBER_START_ROUTINE lpStartAddress,
		//                      LPVOID lpParameter);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		lpParam := ctx.Arg(4)
		fiberMu.Lock()
		addr := mem.Mmap(0, 4096, mmu.PermRead|mmu.PermWrite)
		fiberMap[addr] = lpParam
		mem.Write64(addr, lpParam)
		mem.Write64(addr+8, ctx.Arg(3)) // lpStartAddress
		fiberMu.Unlock()
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFile2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateFile2", 7, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileMappingA", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		flProtect := uint32(ctx.Arg(2))
		szHigh := uint32(ctx.Arg(3))
		szLow := uint32(ctx.Arg(4))
		name := readGuestString(ctx.Arg(5))
		h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileMappingFromApp", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		flProtect := uint32(ctx.Arg(1))
		size := ctx.Arg(2)
		name := readGuestUTF16(ctx.Arg(3))
		szHigh := uint32(size >> 32)
		szLow := uint32(size)
		h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileMappingNumaW", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		flProtect := uint32(ctx.Arg(2))
		szHigh := uint32(ctx.Arg(3))
		szLow := uint32(ctx.Arg(4))
		name := readGuestUTF16(ctx.Arg(5))
		// ctx.Arg(6) = nndPreferred NUMA node (ignored)
		h := doCreateFileMapping(ctx, hFile, flProtect, szHigh, szLow, name)
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateFileTransactedA", 10, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateFileTransactedW", 10, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateHardLinkA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateHardLinkA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateHardLinkTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateHardLinkTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateHardLinkTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateHardLinkTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateHardLinkW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateHardLinkW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateIoCompletionPort", func(ctx *ntapi.TrapContext) uint32 {
		// CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads)
		// INVALID_HANDLE_VALUE (-1) as FileHandle means "create a new IOCP".
		fileHandle := ntapi.Handle(ctx.Arg(0))
		existingPort := ntapi.Handle(ctx.Arg(1))
		if existingPort != 0 {
			// Associate file with existing port - just return the existing port handle.
			ctx.SetReturn(uint64(existingPort))
			return 0
		}
		if fileHandle == ntapi.InvalidHandle {
			// Create a new IOCP.
			h := handles.Alloc(&ntapi.IoCompletionPortHandle{})
			ctx.SetReturn(uint64(h))
			return 0
		}
		// Associate a file handle with a new IOCP (simplified: create new IOCP).
		h := handles.Alloc(&ntapi.IoCompletionPortHandle{})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateJobObjectA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		name := ""
		if namePtr != 0 {
			name = readGuestString(namePtr)
		}
		j := ntapi.NewJobHandle(name)
		var h ntapi.Handle
		if name != "" {
			h, _ = handles.AllocNamed(name, j)
		} else {
			h = handles.Alloc(j)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateJobObjectW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		name := ""
		if namePtr != 0 {
			name = readGuestUTF16(namePtr)
		}
		j := ntapi.NewJobHandle(name)
		var h ntapi.Handle
		if name != "" {
			h, _ = handles.AllocNamed(name, j)
		} else {
			h = handles.Alloc(j)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateKernelThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateKernelThread", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMailslotA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateMailslotA(lpName, nMaxMessageSize, lReadTimeout, sa)
		namePtr := ctx.Arg(0)
		maxMsg := uint32(ctx.Arg(1))
		readTimeout := uint32(ctx.Arg(2))
		name := ""
		if namePtr != 0 {
			name = readGuestString(namePtr)
		}
		if maxMsg == 0 {
			maxMsg = 4096
		}
		m := ntapi.NewMailslot(name, maxMsg, readTimeout)
		h := handles.Alloc(m)
		if name != "" {
			ntapi.RegisterMailslot(name, m)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMailslotW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		maxMsg := uint32(ctx.Arg(1))
		readTimeout := uint32(ctx.Arg(2))
		name := ""
		if namePtr != 0 {
			name = readGuestUTF16(namePtr)
		}
		if maxMsg == 0 {
			maxMsg = 4096
		}
		m := ntapi.NewMailslot(name, maxMsg, readTimeout)
		h := handles.Alloc(m)
		if name != "" {
			ntapi.RegisterMailslot(name, m)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMemoryResourceNotification", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "memresource"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMutexA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateMutexA(lpAttr, bInitialOwner, lpName)
		bInitialOwner := ctx.Arg(1) != 0
		mh := &ntapi.MutantHandle{}
		if bInitialOwner {
			var tid uint32 = 1
			if *tmPtr != nil {
				tid = uint32((*tmPtr).GetTID(ctx.CPU))
			}
			mh.WaitTimeout(tid, 0)
		}
		h := handles.Alloc(mh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMutexExA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateMutexExA(lpAttr, lpName, dwFlags, dwDesiredAccess)
		// dwFlags: 1 = CREATE_MUTEX_INITIAL_OWNER
		dwFlags := ctx.Arg(2)
		mh := &ntapi.MutantHandle{}
		if dwFlags&1 != 0 {
			var tid uint32 = 1
			if *tmPtr != nil {
				tid = uint32((*tmPtr).GetTID(ctx.CPU))
			}
			mh.WaitTimeout(tid, 0)
		}
		h := handles.Alloc(mh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateMutexExW", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(2)
		mh := &ntapi.MutantHandle{}
		if dwFlags&1 != 0 {
			var tid uint32 = 1
			if *tmPtr != nil {
				tid = uint32((*tmPtr).GetTID(ctx.CPU))
			}
			mh.WaitTimeout(tid, 0)
		}
		h := handles.Alloc(mh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		pipeName := normalizePipeName(name)
		ph := ntapi.NewServerPipe(pipeName)
		ntapi.RegisterNamedPipe(pipeName, ph)
		h := handles.Alloc(ph)
		if ctx.Trace {
			ravelog.Logf("[win32] CreateNamedPipeA: %q → handle=0x%x\n", name, uint64(h))
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		pipeName := normalizePipeName(name)
		ph := ntapi.NewServerPipe(pipeName)
		ntapi.RegisterNamedPipe(pipeName, ph)
		h := handles.Alloc(ph)
		if ctx.Trace {
			ravelog.Logf("[win32] CreateNamedPipeW: %q → handle=0x%x\n", name, uint64(h))
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreatePipe", func(ctx *ntapi.TrapContext) uint32 {
		hReadPipe := ctx.Arg(0)
		hWritePipe := ctx.Arg(1)
		rfile, wfile, err := os.Pipe()
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		rh := uint64(handles.Alloc(&ntapi.FileHandle{FD: int(rfile.Fd()), Path: "pipe:read"}))
		wh := uint64(handles.Alloc(&ntapi.FileHandle{FD: int(wfile.Fd()), Path: "pipe:write"}))
		ctx.Mem.Write64(hReadPipe, rh)
		ctx.Mem.Write64(hWritePipe, wh)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessA", 10, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessAsUserA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessAsUserA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessAsUserW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessAsUserW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessInternalA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessInternalA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessInternalW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessInternalW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateProcessW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateProcessW", 10, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreatePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreatePseudoConsole", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateRemoteThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateRemoteThread", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateRemoteThreadEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateRemoteThreadEx", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateSemaphoreA(lpAttr, lInitialCount, lMaximumCount, lpName)
		initial := int32(ctx.Arg(1))
		maxCount := int32(ctx.Arg(2))
		if maxCount <= 0 {
			maxCount = 0x7fffffff
		}
		h := handles.Alloc(ntapi.NewSemaphore(initial, maxCount))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreExA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateSemaphoreExA(lpAttr, lInitialCount, lMaximumCount, lpName, dwFlags, dwDesiredAccess)
		initial := int32(ctx.Arg(1))
		maxCount := int32(ctx.Arg(2))
		if maxCount <= 0 {
			maxCount = 0x7fffffff
		}
		h := handles.Alloc(ntapi.NewSemaphore(initial, maxCount))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreExW", func(ctx *ntapi.TrapContext) uint32 {
		initial := int32(ctx.Arg(1))
		maxCount := int32(ctx.Arg(2))
		if maxCount <= 0 {
			maxCount = 0x7fffffff
		}
		h := handles.Alloc(ntapi.NewSemaphore(initial, maxCount))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSemaphoreW", func(ctx *ntapi.TrapContext) uint32 {
		// CreateSemaphoreW(lpAttr, lInitialCount, lMaximumCount, lpName)
		initial := int32(ctx.Arg(1))
		maxCount := int32(ctx.Arg(2))
		if maxCount <= 0 {
			maxCount = 0x7fffffff
		}
		h := handles.Alloc(ntapi.NewSemaphore(initial, maxCount))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSocketHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateSocketHandle", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSymbolicLinkA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateSymbolicLinkA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateSymbolicLinkW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateSymbolicLinkW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateTapePartition", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateTapePartition", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpool", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(&ntapi.TpPool{MinThreads: 1, MaxThreads: 500})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolCleanupGroup", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "tpcleanup"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateThreadpoolIo", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
		callback := ctx.Arg(0)
		context := ctx.Arg(1)
		h := handles.Alloc(&ntapi.TpTimer{Callback: callback, Context: context})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
		callback := ctx.Arg(0)
		context := ctx.Arg(1)
		h := handles.Alloc(&ntapi.TpWait{Callback: callback, Context: context})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
		callback := ctx.Arg(0)
		context := ctx.Arg(1)
		h := handles.Alloc(&ntapi.TpWork{Callback: callback, Context: context})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateTimerQueue", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(&ntapi.GenericHandle{Kind: "timerqueue"})
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		// CreateTimerQueueTimer(phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags)
		phTimer := ctx.Arg(0)
		callback := ctx.Arg(2)
		param := ctx.Arg(3)
		dueTimeMs := uint32(ctx.Arg(4))
		period := uint32(ctx.Arg(5))
		tqt := &ntapi.TimerQueueTimer{
			Callback: callback,
			Param:    param,
			Period:   period,
			StopCh:   make(chan struct{}),
		}
		h := handles.Alloc(tqt)
		if phTimer != 0 {
			ctx.Mem.Write64(phTimer, uint64(h))
		}
		if callback != 0 {
			cpuSnap := ctx.CPU
			due := time.Duration(dueTimeMs) * time.Millisecond
			hCopy := h
			tqt.Arm(due, func() {
				done := tpLaunchCallback(cpuSnap, callback, param, 0 /*TimerOrWaitFired=FALSE*/)
				if done != nil {
					<-done
				}
				_ = hCopy
			})
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateUmsCompletionList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateUmsCompletionList", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateUmsThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateUmsThreadContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CreateVirtualBuffer", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerA", func(ctx *ntapi.TrapContext) uint32 {
		// CreateWaitableTimerA(sa, bManualReset, lpName)
		manualReset := ctx.Arg(1) != 0
		namePtr := ctx.Arg(2)
		wt := ntapi.NewWaitableTimer(manualReset)
		var h ntapi.Handle
		if namePtr != 0 {
			name := readGuestString(namePtr)
			h, _ = handles.AllocNamed(name, wt)
		} else {
			h = handles.Alloc(wt)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerExA", func(ctx *ntapi.TrapContext) uint32 {
		manualReset := (ctx.Arg(3) & 1) == 0 // CREATE_WAITABLE_TIMER_MANUAL_RESET = 1
		namePtr := ctx.Arg(1)
		wt := ntapi.NewWaitableTimer(manualReset)
		var h ntapi.Handle
		if namePtr != 0 {
			name := readGuestString(namePtr)
			h, _ = handles.AllocNamed(name, wt)
		} else {
			h = handles.Alloc(wt)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerExW", func(ctx *ntapi.TrapContext) uint32 {
		manualReset := (ctx.Arg(3) & 1) == 0
		namePtr := ctx.Arg(1)
		wt := ntapi.NewWaitableTimer(manualReset)
		var h ntapi.Handle
		if namePtr != 0 {
			name := readGuestUTF16(namePtr)
			h, _ = handles.AllocNamed(name, wt)
		} else {
			h = handles.Alloc(wt)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CreateWaitableTimerW", func(ctx *ntapi.TrapContext) uint32 {
		manualReset := ctx.Arg(1) != 0
		namePtr := ctx.Arg(2)
		wt := ntapi.NewWaitableTimer(manualReset)
		var h ntapi.Handle
		if namePtr != 0 {
			name := readGuestUTF16(namePtr)
			h, _ = handles.AllocNamed(name, wt)
		} else {
			h = handles.Alloc(wt)
		}
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "CtrlRoutine", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "CtrlRoutine", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeactivateActCtx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeactivateActCtx", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DebugActiveProcess", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DebugActiveProcess", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DebugActiveProcessStop", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DebugActiveProcessStop", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DebugBreak", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DebugBreak", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DebugBreakProcess", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DebugBreakProcess", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DebugSetProcessKillOnExit", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DebugSetProcessKillOnExit", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DecodeSystemPointer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DecodeSystemPointer", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "DefineDosDeviceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DefineDosDeviceA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DefineDosDeviceW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DefineDosDeviceW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DelayLoadFailureHook", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DelayLoadFailureHook", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteAtom", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		if name, ok := localAtomNames[atom]; ok {
			delete(localAtomTable, strings.ToLower(name))
			delete(localAtomNames, atom)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteFiber", func(ctx *ntapi.TrapContext) uint32 {
		// VOID DeleteFiber(LPVOID lpFiber);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		lpFiber := ctx.Arg(0)
		fiberMu.Lock()
		delete(fiberMap, lpFiber)
		fiberMu.Unlock()
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteFileA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteFileA", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteFileTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteFileTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteProcThreadAttributeList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteProcThreadAttributeList", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteSynchronizationBarrier", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueue", func(ctx *ntapi.TrapContext) uint32 {
		// DeleteTimerQueue(TimerQueue) - deprecated, use DeleteTimerQueueEx
		hQueue := ntapi.Handle(ctx.Arg(0))
		handles.Close(hQueue)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueueEx", func(ctx *ntapi.TrapContext) uint32 {
		// DeleteTimerQueueEx(TimerQueue, CompletionEvent)
		hQueue := ntapi.Handle(ctx.Arg(0))
		handles.Close(hQueue)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		// DeleteTimerQueueTimer(TimerQueue, Timer, CompletionEvent)
		timerH := ntapi.Handle(ctx.Arg(1))
		if tqt := handles.GetTimerQueueTimer(timerH); tqt != nil {
			tqt.Stop()
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteUmsCompletionList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteUmsCompletionList", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteUmsThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteUmsThreadContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteVolumeMountPointA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DeleteVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DeleteVolumeMountPointW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DequeueUmsCompletionListItems", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DequeueUmsCompletionListItems", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DisableThreadLibraryCalls", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DisableThreadLibraryCalls", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DisassociateCurrentThreadFromCallback", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DisassociateCurrentThreadFromCallback", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DiscardVirtualMemory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DiscardVirtualMemory", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "DisconnectNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
		hPipe := ntapi.Handle(ctx.Arg(0))
		ph := handles.GetNamedPipe(hPipe)
		if ph == nil {
			ctx.SetReturn(0)
			return 0
		}
		ph.Connected = false
		ph.DrainAll()
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DnsHostnameToComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
		name := "RAVEN"
		buf := ctx.Arg(1)
		if buf != 0 {
			for i := 0; i < len(name); i++ {
				ctx.Mem.Write8(buf+uint64(i), name[i])
			}
			ctx.Mem.Write8(buf+uint64(len(name)), 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DnsHostnameToComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
		name := "RAVEN"
		ws := utf16Encode(name)
		buf := ctx.Arg(1)
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "DosDateTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DosDateTimeToFileTime", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "DuplicateConsoleHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "DuplicateConsoleHandle", 4, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "DuplicateHandle", func(ctx *ntapi.TrapContext) uint32 {
		// DuplicateHandle(hSourceProcess, hSource, hTargetProcess, lpTargetHandle,
		//                 dwDesiredAccess, bInheritHandle, dwOptions)
		hSource := ntapi.Handle(ctx.Arg(1))
		lpTargetHandle := ctx.Arg(3)
		dwOptions := uint32(ctx.Arg(6))
		const DUPLICATE_CLOSE_SOURCE = 0x00000001
		obj := handles.Get(hSource)
		if obj == nil {
			// Unknown handle - return the same numeric value (best effort)
			if lpTargetHandle != 0 {
				ctx.Mem.Write64(lpTargetHandle, uint64(hSource))
			}
			ctx.SetReturn(1)
			return 0
		}
		newH := handles.Alloc(obj)
		if lpTargetHandle != 0 {
			ctx.Mem.Write64(lpTargetHandle, uint64(newH))
		}
		if dwOptions&DUPLICATE_CLOSE_SOURCE != 0 {
			handles.Close(hSource)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EncodeSystemPointer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EncodeSystemPointer", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "EndUpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EndUpdateResourceA", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EndUpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EndUpdateResourceW", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnterSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnterSynchronizationBarrier", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnterUmsSchedulingMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnterUmsSchedulingMode", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumCalendarInfoA", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumCalendarInfoExA", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumCalendarInfoExEx", 6, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumCalendarInfoExW", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumCalendarInfoW", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumDateFormatsA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumDateFormatsExA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumDateFormatsExEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumDateFormatsExW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumDateFormatsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumDateFormatsW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumLanguageGroupLocalesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumLanguageGroupLocalesA", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumLanguageGroupLocalesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumLanguageGroupLocalesW", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceLanguagesA", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceLanguagesExA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceLanguagesExW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceLanguagesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceLanguagesW", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceNamesA", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceNamesExA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceNamesExW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceNamesW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumResourceNamesW(HMODULE hModule, LPCWSTR lpType, ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam)
		// Callback: BOOL CALLBACK EnumResNameProcW(HMODULE hModule, LPCWSTR lpType, LPWSTR lpName, LONG_PTR lParam)
		hModule := ctx.Arg(0)
		lpType := ctx.Arg(1)
		lpEnumFunc := ctx.Arg(2)
		lParam := ctx.Arg(3)
		if lpEnumFunc == 0 || hctx.SyncTrampoline == 0 {
			ctx.SetReturn(1)
			return 0
		}
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rsrcBase := baseAddr + uint64(rsrcRVA)
		typeID := uint32(lpType)
		if lpType > 0xFFFF {
			ctx.SetReturn(1)
			return 0
		}
		typeDir := rsrcFindSubdir(rsrcBase, rsrcBase, typeID)
		if typeDir == 0 {
			ctx.SetReturn(1)
			return 0
		}
		nameIDs := rsrcDirEntries(typeDir)
		if len(nameIDs) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if !okW || !okR {
			ctx.SetReturn(1)
			return 0
		}
		queue := make([]syncDispatch, len(nameIDs))
		for i, nid := range nameIDs {
			queue[i] = syncDispatch{
				wndProc: lpEnumFunc,
				hwnd:    baseAddr,    // RCX = hModule
				msg:     lpType,      // RDX = lpType (MAKEINTRESOURCE)
				wParam:  uint64(nid), // R8  = lpName (MAKEINTRESOURCE)
				lParam:  lParam,      // R9  = lParam
			}
		}
		first := queue[0]
		rest := queue[1:]
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:               rest,
			retAddr:             retAddr,
			hwnd:                1,
			returnWndProcResult: true,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(1, first.hwnd)
		rw.WriteReg(2, first.msg)
		rw.WriteReg(8, first.wParam)
		rw.WriteReg(9, first.lParam)
		ctx.CPU.SetPC(first.wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceTypesA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceTypesExA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumResourceTypesExW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumResourceTypesW", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumResourceTypesW(HMODULE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam)
		// Callback: BOOL CALLBACK EnumResTypeProcW(HMODULE hModule, LPWSTR lpType, LONG_PTR lParam)
		hModule := ctx.Arg(0)
		lpEnumFunc := ctx.Arg(1)
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 || hctx.SyncTrampoline == 0 {
			ctx.SetReturn(1)
			return 0
		}
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rsrcBase := baseAddr + uint64(rsrcRVA)
		typeIDs := rsrcDirEntries(rsrcBase)
		if len(typeIDs) == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if !okW || !okR {
			ctx.SetReturn(1)
			return 0
		}
		// Build syncDispatch queue: callback(hModule, MAKEINTRESOURCE(typeID), lParam)
		queue := make([]syncDispatch, len(typeIDs))
		for i, tid := range typeIDs {
			queue[i] = syncDispatch{
				wndProc: lpEnumFunc,
				hwnd:    baseAddr,    // RCX = hModule
				msg:     uint64(tid), // RDX = lpType (MAKEINTRESOURCE)
				wParam:  lParam,      // R8  = lParam
				lParam:  0,           // R9  = unused
			}
		}
		first := queue[0]
		rest := queue[1:]
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:               rest,
			retAddr:             retAddr,
			hwnd:                1,
			returnWndProcResult: true,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(1, first.hwnd)
		rw.WriteReg(2, first.msg)
		rw.WriteReg(8, first.wParam)
		rw.WriteReg(9, first.lParam)
		ctx.CPU.SetPC(first.wndProc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemCodePagesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemCodePagesA", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemCodePagesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemCodePagesW", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemFirmwareTables", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemFirmwareTables", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemGeoID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemGeoID", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemLanguageGroupsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemLanguageGroupsA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemLanguageGroupsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemLanguageGroupsW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumSystemLocalesA", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumSystemLocalesEx", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL EnumSystemLocalesEx(LOCALE_ENUMPROCEX lpLocaleEnumProcEx, DWORD dwFlags, LPARAM lParam, LPVOID lpReserved)
		// Callback: BOOL CALLBACK EnumLocalesProcEx(LPWSTR lpLocaleString, DWORD dwFlags, LPARAM lParam)
		lpEnumFunc := ctx.Arg(0)
		_ = ctx.Arg(1) // dwFlags
		lParam := ctx.Arg(2)
		if lpEnumFunc == 0 || hctx.SyncTrampoline == 0 {
			ctx.SetReturn(1)
			return 0
		}
		rw, okW := ctx.CPU.(ntapi.RegisterWriter)
		rr, okR := ctx.CPU.(ntapi.RegisterReader)
		if !okW || !okR {
			ctx.SetReturn(1)
			return 0
		}
		// Write "en-US\0" into guest memory for the callback argument
		locStr := utf16Encode("en-US")
		locBuf := mem.Mmap(0, uint64((len(locStr)+1)*2), mmu.PermRead|mmu.PermWrite)
		for i, ch := range locStr {
			mem.Write16(locBuf+uint64(i)*2, ch)
		}
		mem.Write16(locBuf+uint64(len(locStr))*2, 0)
		// Set up syncDispatch: callback(lpLocaleString=RCX, dwFlags=RDX, lParam=R8)
		rsp := rr.ReadReg(4)
		retAddr, _ := mem.Read64(rsp)
		hctx.SyncStack = append(hctx.SyncStack, syncDispatchFrame{
			queue:               nil,
			retAddr:             retAddr,
			hwnd:                1,
			returnWndProcResult: true,
		})
		mem.Write64(rsp, hctx.SyncTrampoline)
		rw.WriteReg(1, locBuf) // RCX = lpLocaleString
		rw.WriteReg(2, 0)      // RDX = dwFlags
		rw.WriteReg(8, lParam) // R8  = lParam
		rw.WriteReg(9, 0)      // R9  = unused
		ctx.CPU.SetPC(lpEnumFunc)
		ctx.ReturnOverridden = true
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumTimeFormatsA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumTimeFormatsEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumTimeFormatsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumTimeFormatsW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumUILanguagesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumUILanguagesA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EnumUILanguagesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EnumUILanguagesW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EraseTape", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EraseTape", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "EscapeCommFunction", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "EscapeCommFunction", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ExecuteUmsThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ExecuteUmsThread", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ExitVDM", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ExitVDM", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ExpandEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		src := readGuestString(ctx.Arg(0))
		dst := ctx.Arg(1)
		maxChars := ctx.Arg(2)
		expanded := os.ExpandEnv(src)
		if dst != 0 && maxChars > 0 {
			data := []byte(expanded)
			if uint64(len(data)) >= maxChars {
				data = data[:maxChars-1]
			}
			ctx.Mem.WriteBytes(dst, append(data, 0))
		}
		ctx.SetReturn(uint64(len(expanded) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ExpungeConsoleCommandHistoryA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ExpungeConsoleCommandHistoryA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ExpungeConsoleCommandHistoryW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ExpungeConsoleCommandHistoryW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ExtendVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ExtendVirtualBuffer", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FatalAppExitA", func(ctx *ntapi.TrapContext) uint32 {
		msg := readGuestString(ctx.Arg(1))
		ravelog.Logf("[win32] FatalAppExitA: %s\n", msg)
		os.Exit(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FatalAppExitW", func(ctx *ntapi.TrapContext) uint32 {
		msg := readGuestUTF16(ctx.Arg(1))
		ravelog.Logf("[win32] FatalAppExitW: %s\n", msg)
		os.Exit(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FatalExit", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[win32] FatalExit(%d)\n", ctx.Arg(0))
		os.Exit(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FileTimeToDosDateTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FileTimeToDosDateTime", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FileTimeToLocalFileTime", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		dst := ctx.Arg(1)
		if src != 0 && dst != 0 {
			v, _ := ctx.Mem.Read64(src)
			ctx.Mem.Write64(dst, v)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
		// FillConsoleOutputAttribute(hConsole, wAttr, nLength, dwWriteCoord, lpNumWritten)
		cs := resolveConsoleState(ctx.Arg(0))
		attr := uint16(ctx.Arg(1))
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3) // COORD as DWORD: low=X, high=Y
		numWritten := ctx.Arg(4)
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		wrote := consoleFillStateAttrs(cs, x, y, n, attr)
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		refreshVisibleConsole(cs)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
		// FillConsoleOutputCharacterA(hConsole, cChar, nLength, dwWriteCoord, lpNumWritten)
		cs := resolveConsoleState(ctx.Arg(0))
		ch := uint16(ctx.Arg(1) & 0xFF)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numWritten := ctx.Arg(4)
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		attr := uint16(0x07)
		if cs != nil {
			attr = cs.Attr
		}
		wrote := consoleFillStateChars(cs, x, y, n, ch, attr)
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		refreshVisibleConsole(cs)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FillConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
		cs := resolveConsoleState(ctx.Arg(0))
		ch := uint16(ctx.Arg(1))
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numWritten := ctx.Arg(4)
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		attr := uint16(0x07)
		if cs != nil {
			attr = cs.Attr
		}
		wrote := consoleFillStateChars(cs, x, y, n, ch, attr)
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		refreshVisibleConsole(cs)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionGuid", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindActCtxSectionGuid", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionStringA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindActCtxSectionStringA", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindActCtxSectionStringW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindActCtxSectionStringW", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindAtomA", func(ctx *ntapi.TrapContext) uint32 {
		key := strings.ToLower(readGuestString(ctx.Arg(0)))
		if a, ok := localAtomTable[key]; ok {
			ctx.SetReturn(uint64(a))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindAtomW", func(ctx *ntapi.TrapContext) uint32 {
		key := strings.ToLower(readGuestUTF16(ctx.Arg(0)))
		if a, ok := localAtomTable[key]; ok {
			ctx.SetReturn(uint64(a))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindCloseChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindCloseChangeNotification", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstChangeNotificationA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstChangeNotificationA", 3, uint64(0x1234))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstChangeNotificationW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstChangeNotificationW", 3, uint64(0x1234))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		dataPtr := ctx.Arg(1)
		pattern := readGuestString(pathPtr)
		vfsPattern := winPathToVFS(pattern)
		dir := filepath.Dir(vfsPattern)
		glob := filepath.Base(vfsPattern)
		entries, err := os.ReadDir(dir)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		var matched []os.DirEntry
		for _, e := range entries {
			ok, _ := filepath.Match(glob, e.Name())
			if ok {
				matched = append(matched, e)
			}
		}
		if len(matched) == 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF)
			return 0
		}
		fh := &ntapi.FindHandle{Entries: matched, Idx: 1, Dir: dir}
		if dataPtr != 0 {
			writeFindDataA(mem, dataPtr, dir, matched[0])
		}
		h := handles.Alloc(fh)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstFileExA", 6, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstFileNameW", 4, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstFileTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstFileTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstStreamW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstStreamW", 4, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstVolumeA", 2, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstVolumeMountPointA", 3, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstVolumeMountPointW", 3, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindFirstVolumeW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindFirstVolumeW", 2, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindNLSString", func(ctx *ntapi.TrapContext) uint32 {
		flags := ctx.Arg(1)
		lpSrc := ctx.Arg(2)
		cchSrc := int32(ctx.Arg(3))
		lpVal := ctx.Arg(4)
		cchVal := int32(ctx.Arg(5))
		pcchFound := ctx.Arg(6)
		src := readGuestUTF16N(lpSrc, int(cchSrc))
		val := readGuestUTF16N(lpVal, int(cchVal))
		srcS, valS := src, val
		if flags&1 != 0 { // NORM_IGNORECASE
			srcS = strings.ToLower(src)
			valS = strings.ToLower(val)
		}
		var byteIdx int
		if flags&0x800000 != 0 { // FIND_FROMEND
			byteIdx = strings.LastIndex(srcS, valS)
		} else {
			byteIdx = strings.Index(srcS, valS)
		}
		if byteIdx < 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // -1: not found
			return 0
		}
		utf16Idx := len(utf16Encode(src[:byteIdx]))
		if pcchFound != 0 {
			ctx.Mem.Write32(pcchFound, uint32(len(utf16Encode(val))))
		}
		ctx.SetReturn(uint64(utf16Idx))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindNLSStringEx", func(ctx *ntapi.TrapContext) uint32 {
		// lpLocaleName = Arg(0) (ignored)
		flags := ctx.Arg(1)
		lpSrc := ctx.Arg(2)
		cchSrc := int32(ctx.Arg(3))
		lpVal := ctx.Arg(4)
		cchVal := int32(ctx.Arg(5))
		pcchFound := ctx.Arg(6)
		src := readGuestUTF16N(lpSrc, int(cchSrc))
		val := readGuestUTF16N(lpVal, int(cchVal))
		srcS, valS := src, val
		if flags&1 != 0 {
			srcS = strings.ToLower(src)
			valS = strings.ToLower(val)
		}
		var byteIdx int
		if flags&0x800000 != 0 {
			byteIdx = strings.LastIndex(srcS, valS)
		} else {
			byteIdx = strings.Index(srcS, valS)
		}
		if byteIdx < 0 {
			ctx.SetReturn(0xFFFFFFFFFFFFFFFF) // -1: not found
			return 0
		}
		utf16Idx := len(utf16Encode(src[:byteIdx]))
		if pcchFound != 0 {
			ctx.Mem.Write32(pcchFound, uint32(len(utf16Encode(val))))
		}
		ctx.SetReturn(uint64(utf16Idx))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextChangeNotification", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextChangeNotification", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextFileA", func(ctx *ntapi.TrapContext) uint32 {
		hFind := ctx.Arg(0)
		dataPtr := ctx.Arg(1)
		obj := handles.Get(ntapi.Handle(hFind))
		fh, ok := obj.(*ntapi.FindHandle)
		if !ok || fh.Idx >= len(fh.Entries) {
			ctx.SetReturn(0)
			return 0
		}
		if dataPtr != 0 {
			writeFindDataA(mem, dataPtr, fh.Dir, fh.Entries[fh.Idx])
		}
		fh.Idx++
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextStreamW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextStreamW", 2, uint64(0xFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextVolumeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextVolumeA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextVolumeMountPointA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextVolumeMountPointW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindNextVolumeW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindNextVolumeW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindResourceA", func(ctx *ntapi.TrapContext) uint32 {
		// HRSRC FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType)
		hModule := ctx.Arg(0)
		lpName := ctx.Arg(1)
		lpType := ctx.Arg(2)
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 || peLoadRawResource == nil {
			ctx.SetReturn(0)
			return 0
		}
		typeID := uint32(lpType)
		if lpType > 0xFFFF {
			typeID = 0
		}
		resID := uint32(lpName)
		if lpName > 0xFFFF {
			resID = 0
		}
		if typeID == 0 || resID == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dataAddr, dataSize, ok := peLoadRawResource(baseAddr, rsrcRVA, typeID, resID)
		if !ok || dataAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		h := hrsrcNext
		hrsrcNext++
		hrsrcTable[h] = hrsrcEntry{dataAddr: dataAddr, dataSize: dataSize}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindResourceExA", func(ctx *ntapi.TrapContext) uint32 {
		// HRSRC FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage)
		hModule := ctx.Arg(0)
		lpType := ctx.Arg(1)
		lpName := ctx.Arg(2)
		// wLanguage := uint16(ctx.Arg(3)) - ignored, we pick best lang internally
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 || peLoadRawResource == nil {
			ctx.SetReturn(0)
			return 0
		}
		typeID := uint32(lpType)
		if lpType > 0xFFFF {
			typeID = 0
		}
		resID := uint32(lpName)
		if lpName > 0xFFFF {
			resID = 0
		}
		if typeID == 0 || resID == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dataAddr, dataSize, ok := peLoadRawResource(baseAddr, rsrcRVA, typeID, resID)
		if !ok || dataAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		h := hrsrcNext
		hrsrcNext++
		hrsrcTable[h] = hrsrcEntry{dataAddr: dataAddr, dataSize: dataSize}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindResourceExW", func(ctx *ntapi.TrapContext) uint32 {
		// HRSRC FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage)
		hModule := ctx.Arg(0)
		lpType := ctx.Arg(1)
		lpName := ctx.Arg(2)
		// wLanguage := uint16(ctx.Arg(3)) - ignored, we pick best lang internally
		baseAddr, rsrcRVA := resolveResourceModule(hModule)
		if rsrcRVA == 0 || peLoadRawResource == nil {
			ctx.SetReturn(0)
			return 0
		}
		typeID := uint32(lpType)
		if lpType > 0xFFFF {
			typeID = 0
		}
		resID := uint32(lpName)
		if lpName > 0xFFFF {
			resID = 0
		}
		if typeID == 0 || resID == 0 {
			ctx.SetReturn(0)
			return 0
		}
		dataAddr, dataSize, ok := peLoadRawResource(baseAddr, rsrcRVA, typeID, resID)
		if !ok || dataAddr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		h := hrsrcNext
		hrsrcNext++
		hrsrcTable[h] = hrsrcEntry{dataAddr: dataAddr, dataSize: dataSize}
		ctx.SetReturn(h)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FindStringOrdinal", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindStringOrdinal", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FindVolumeClose", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindVolumeClose", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FindVolumeMountPointClose", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FindVolumeMountPointClose", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FlushConsoleInputBuffer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FlushConsoleInputBuffer", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FlushInstructionCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FlushInstructionCache", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FlushProcessWriteBuffers", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FlushProcessWriteBuffers", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FlushViewOfFile", func(ctx *ntapi.TrapContext) uint32 {
		lpBase := ctx.Arg(0)
		flushSize := ctx.Arg(1)
		for _, vm := range hctx.ViewMappings {
			if vm.GuestAddr != lpBase {
				continue
			}
			sz := flushSize
			if sz == 0 || sz > vm.Size {
				sz = vm.Size
			}
			if guestData, err := ctx.Mem.ReadBytes(vm.GuestAddr, int(sz)); err == nil {
				copy(vm.HostBuf[:sz], guestData)
				if vm.FileFD >= 0 {
					ctx.FS.Pwrite(vm.FileFD, guestData, int64(vm.Offset))
				}
			}
			break
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FoldStringA", func(ctx *ntapi.TrapContext) uint32 {
		cchSrc := ctx.Arg(3)
		lpSrc := ctx.Arg(2)
		lpDst := ctx.Arg(4)
		if lpDst != 0 && cchSrc > 0 {
			buf, _ := ctx.Mem.ReadBytes(lpSrc, int(cchSrc))
			ctx.Mem.WriteBytes(lpDst, buf)
		}
		ctx.SetReturn(cchSrc)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FoldStringW", func(ctx *ntapi.TrapContext) uint32 {
		cchSrc := ctx.Arg(3)
		lpSrc := ctx.Arg(2)
		lpDst := ctx.Arg(4)
		if lpDst != 0 && cchSrc > 0 {
			buf, _ := ctx.Mem.ReadBytes(lpSrc, int(cchSrc*2))
			ctx.Mem.WriteBytes(lpDst, buf)
		}
		ctx.SetReturn(cchSrc)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FreeConsole", func(ctx *ntapi.TrapContext) uint32 {
		consoleStateMu.Lock()
		consoleAttached = false
		consoleStateMu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "FreeEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeEnvironmentStringsA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "FreeLibraryWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeLibraryWhenCallbackReturns", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FreeResource", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeResource", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FreeUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeUserPhysicalPages", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "FreeVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "FreeVirtualBuffer", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GenerateConsoleCtrlEvent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GenerateConsoleCtrlEvent", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetActiveProcessorCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetActiveProcessorCount", 8, 4)
	})
	d.RegisterAutoStubHandler(kernel32, "GetActiveProcessorGroupCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetActiveProcessorGroupCount", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetAtomNameA", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		buf := ctx.Arg(1)
		sz := ctx.Arg(2)
		if name, ok := localAtomNames[atom]; ok && buf != 0 && sz > 0 {
			b := append([]byte(name), 0)
			if uint64(len(b)) > sz {
				b = b[:sz]
			}
			for i, c := range b {
				mem.Write8(buf+uint64(i), c)
			}
			ctx.SetReturn(uint64(len(b) - 1))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetAtomNameW", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		buf := ctx.Arg(1)
		sz := ctx.Arg(2)
		if name, ok := localAtomNames[atom]; ok && buf != 0 && sz > 0 {
			ws := utf16Encode(name)
			maxW := uint64(sz) - 1
			if uint64(len(ws)) > maxW {
				ws = ws[:maxW]
			}
			for i, w := range ws {
				mem.Write16(buf+uint64(i)*2, w)
			}
			mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.SetReturn(uint64(len(ws)))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetBinaryType", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetBinaryType", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetBinaryTypeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetBinaryTypeA", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetBinaryTypeW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetBinaryTypeW", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCPInfoExA", func(ctx *ntapi.TrapContext) uint32 {
		codePage := uint32(ctx.Arg(0))
		lpCPInfoEx := ctx.Arg(2)
		if !writeCPInfoExAData(lpCPInfoEx, codePage) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCPInfoExW", func(ctx *ntapi.TrapContext) uint32 {
		codePage := uint32(ctx.Arg(0))
		lpCPInfoEx := ctx.Arg(2)
		if !writeCPInfoExWData(lpCPInfoEx, codePage) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
		// GetCalendarInfoA(Locale, Calendar, CalType, lpCalData, cchData, lpValue)
		calType := ctx.Arg(2)
		lpCalData := ctx.Arg(3)
		cchData := ctx.Arg(4)
		now := time.Now()
		var s string
		switch calType & 0xFFFF {
		case 0x0001:
			s = "1" // CAL_ICALINTVALUE
		case 0x0002:
			s = "1" // CAL_SCALNAME (Gregorian)
		case 0x0004:
			s = fmt.Sprintf("%d", now.Year()) // CAL_SYEAROFFSET
		case 0x0005:
			s = "12" // CAL_ITWODIGITYEARMAX
		default:
			s = "1"
		}
		if lpCalData != 0 && cchData > 0 {
			b := []byte(s)
			if uint64(len(b)+1) > cchData {
				b = b[:cchData-1]
			}
			ctx.Mem.WriteBytes(lpCalData, append(b, 0))
		}
		ctx.SetReturn(uint64(len(s) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		calType := ctx.Arg(2)
		lpCalData := ctx.Arg(3)
		cchData := ctx.Arg(4)
		now := time.Now()
		var s string
		switch calType & 0xFFFF {
		case 0x0004:
			s = fmt.Sprintf("%d", now.Year())
		default:
			s = "1"
		}
		ws := utf16Encode(s)
		if lpCalData != 0 && cchData > 0 {
			n := uint64(len(ws))
			if n+1 > cchData {
				n = cchData - 1
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write16(lpCalData+i*2, ws[i])
			}
			ctx.Mem.Write16(lpCalData+n*2, 0)
		}
		ctx.SetReturn(uint64(len(ws) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
		calType := ctx.Arg(2)
		lpCalData := ctx.Arg(3)
		cchData := ctx.Arg(4)
		now := time.Now()
		var s string
		switch calType & 0xFFFF {
		case 0x0001:
			s = "1"
		case 0x0002:
			s = "Gregorian"
		case 0x0004:
			s = fmt.Sprintf("%d", now.Year())
		case 0x0005:
			s = "2029"
		case 0x0006:
			s = "1" // CAL_SABBREVIATEDLOCALNAME
		case 0x0007:
			s = "CAL" // CAL_SALTERNATESORTING
		default:
			s = ""
		}
		ws := utf16Encode(s)
		if lpCalData != 0 && cchData > 0 {
			n := uint64(len(ws))
			if n+1 > cchData {
				n = cchData - 1
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write16(lpCalData+i*2, ws[i])
			}
			ctx.Mem.Write16(lpCalData+n*2, 0)
		}
		ctx.SetReturn(uint64(len(ws) + 1))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommConfig", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommConfig", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommMask", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommModemStatus", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommModemStatus", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommProperties", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommProperties", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommState", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCommTimeouts", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCommTimeouts", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCompressedFileSizeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCompressedFileSizeA", 2, uint64(0xFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "GetCompressedFileSizeW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCompressedFileSizeW", 2, uint64(0xFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "GetComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		sizePtr := ctx.Arg(1)
		name := "RAVEN-PC"
		ctx.Mem.WriteBytes(buf, append([]byte(name), 0))
		ctx.Mem.Write32(sizePtr, uint32(len(name)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetComputerNameExA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		sizePtr := ctx.Arg(2)
		name := "RAVEN"
		ctx.Mem.WriteBytes(buf, append([]byte(name), 0))
		ctx.Mem.Write32(sizePtr, uint32(len(name)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetComputerNameExW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		sizePtr := ctx.Arg(2)
		name := "RAVEN"
		ws := utf16Encode(name)
		for i, r := range ws {
			ctx.Mem.Write16(buf+uint64(i)*2, r)
		}
		ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		ctx.Mem.Write32(sizePtr, uint32(len(name)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasExesA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesLengthA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasExesLengthA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesLengthW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasExesLengthW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasExesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasExesW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasesA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesLengthA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasesLengthA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesLengthW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasesLengthW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleAliasesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleAliasesW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCharType", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCharType", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCommandHistoryA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryLengthA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCommandHistoryLengthA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryLengthW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCommandHistoryLengthW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCommandHistoryW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCommandHistoryW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
		// GetConsoleCursorInfo(hConsole, lpConsoleCursorInfo)
		// CONSOLE_CURSOR_INFO: dwSize(DWORD), bVisible(BOOL)
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			ctx.Mem.Write32(pInfo+0, ntapi.GlobalConsole.CursorSize)
			visible := uint32(0)
			if ntapi.GlobalConsole.CursorVisible {
				visible = 1
			}
			ctx.Mem.Write32(pInfo+4, visible)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleCursorMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleCursorMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleDisplayMode", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleFontInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleFontInfo", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleFontSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleFontSize", 2, uint64(0x000C000A))
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleHardwareState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleHardwareState", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleInputExeNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleInputExeNameA", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleInputExeNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleInputExeNameW", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleInputWaitHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleInputWaitHandle", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleKeyboardLayoutNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleKeyboardLayoutNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleKeyboardLayoutNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleKeyboardLayoutNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleNlsMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleNlsMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleOriginalTitleA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		if buf != 0 {
			ctx.Mem.WriteBytes(buf, []byte("Raven\x00"))
		}
		ctx.SetReturn(5)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleOriginalTitleW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		if buf != 0 {
			for i, c := range []uint16{'R', 'a', 'v', 'e', 'n', 0} {
				ctx.Mem.Write16(buf+uint64(i)*2, c)
			}
		}
		ctx.SetReturn(5)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleProcessList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetConsoleProcessList", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleScreenBufferInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		cs := resolveConsoleState(ctx.Arg(0))
		pInfo := ctx.Arg(1)
		if pInfo != 0 && cs != nil {
			ctx.Mem.Write32(pInfo+0, 96)                   // cbSize = sizeof(CONSOLE_SCREEN_BUFFER_INFOEX)
			ctx.Mem.Write16(pInfo+4, uint16(cs.Width))     // dwSize.X
			ctx.Mem.Write16(pInfo+6, uint16(cs.Height))    // dwSize.Y
			ctx.Mem.Write16(pInfo+8, uint16(cs.CursorX))   // dwCursorPosition.X
			ctx.Mem.Write16(pInfo+10, uint16(cs.CursorY))  // dwCursorPosition.Y
			ctx.Mem.Write16(pInfo+12, cs.Attr)             // wAttributes
			ctx.Mem.Write16(pInfo+14, 0)                   // srWindow.Left
			ctx.Mem.Write16(pInfo+16, 0)                   // srWindow.Top
			ctx.Mem.Write16(pInfo+18, uint16(cs.Width-1))  // srWindow.Right
			ctx.Mem.Write16(pInfo+20, uint16(cs.Height-1)) // srWindow.Bottom
			ctx.Mem.Write16(pInfo+22, uint16(cs.Width))    // dwMaximumWindowSize.X
			ctx.Mem.Write16(pInfo+24, uint16(cs.Height))   // dwMaximumWindowSize.Y
			ctx.Mem.Write16(pInfo+26, 0)                   // wPopupAttributes
			ctx.Mem.Write32(pInfo+28, 0)                   // bFullscreenSupported
			// ColorTable[16] at offset 32: fill with default 16-color palette
			palette := []uint32{
				0x000000, 0x800000, 0x008000, 0x808000, 0x000080, 0x800080, 0x008080, 0xC0C0C0,
				0x808080, 0xFF0000, 0x00FF00, 0xFFFF00, 0x0000FF, 0xFF00FF, 0x00FFFF, 0xFFFFFF,
			}
			for i, c := range palette {
				ctx.Mem.Write32(pInfo+32+uint64(i)*4, c)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleTitleA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		nSz := ctx.Arg(1)
		title := consoleTitle
		if buf != 0 && nSz > 0 {
			b := []byte(title)
			if uint64(len(b)+1) > nSz {
				b = b[:nSz-1]
			}
			ctx.Mem.WriteBytes(buf, append(b, 0))
		}
		ctx.SetReturn(uint64(len(title)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetConsoleTitleW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		nSz := ctx.Arg(1)
		title := consoleTitle
		ws := utf16Encode(title)
		if buf != 0 && nSz > 0 {
			limit := uint64(len(ws))
			if limit+1 > nSz {
				limit = nSz - 1
			}
			for i := uint64(0); i < limit; i++ {
				ctx.Mem.Write16(buf+i*2, ws[i])
			}
			ctx.Mem.Write16(buf+limit*2, 0)
		}
		ctx.SetReturn(uint64(len(ws)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatA", func(ctx *ntapi.TrapContext) uint32 {
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestString(lpValue)
		n := uint64(len(s) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write8(lpOut+i, s[i])
		}
		ctx.Mem.Write8(lpOut+n-1, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatEx", func(ctx *ntapi.TrapContext) uint32 {
		// lpLocaleName, dwFlags, lpValue, lpFormat, lpCurrencyStr, cchCurrency
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestUTF16(lpValue)
		ws := utf16Encode(s)
		n := uint64(len(ws) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(lpOut+i*2, ws[i])
		}
		ctx.Mem.Write16(lpOut+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrencyFormatW", func(ctx *ntapi.TrapContext) uint32 {
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestUTF16(lpValue)
		ws := utf16Encode(s)
		n := uint64(len(ws) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(lpOut+i*2, ws[i])
		}
		ctx.Mem.Write16(lpOut+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentActCtx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentActCtx", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentApplicationUserModelId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentApplicationUserModelId", 2, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentConsoleFont", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentConsoleFont", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentConsoleFontEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentConsoleFontEx", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\"
		ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageFamilyName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentPackageFamilyName", 2, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageFullName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentPackageFullName", 4, 15700)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentPackageId", 2, 15700)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentPackageInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentPackageInfo", 4, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentPackagePath", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentPackagePath", 4, 15700)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessorNumber", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentProcessorNumber", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentProcessorNumberEx", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.Mem.Write64(ctx.Arg(0), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentThread", 0, uint64(0xFFFFFFFFFFFFFFFE))
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentThreadStackLimits", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.Mem.Write64(ctx.Arg(0), 0x10000)
		}
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write64(ctx.Arg(1), 0x800000)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetCurrentUmsThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetCurrentUmsThread", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDateFormatA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		s := "03/09/2026"
		if buf != 0 {
			for i := 0; i < len(s); i++ {
				ctx.Mem.Write8(buf+uint64(i), s[i])
			}
			ctx.Mem.Write8(buf+uint64(len(s)), 0)
		}
		ctx.SetReturn(11)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDaylightFlag", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDaylightFlag", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDefaultCommConfigA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDefaultCommConfigA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDefaultCommConfigW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDefaultCommConfigW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDefaultSortkeySize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDefaultSortkeySize", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDevicePowerState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDevicePowerState", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDiskFreeSpaceA", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDiskFreeSpaceW", func(ctx *ntapi.TrapContext) uint32 {
		// Report 100 GB free on a 200 GB disk
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write32(ctx.Arg(1), 8)
		}
		if ctx.Arg(2) != 0 {
			ctx.Mem.Write32(ctx.Arg(2), 512)
		}
		if ctx.Arg(3) != 0 {
			ctx.Mem.Write32(ctx.Arg(3), 25600000)
		}
		if ctx.Arg(4) != 0 {
			ctx.Mem.Write32(ctx.Arg(4), 51200000)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDiskSpaceInformationA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDiskSpaceInformationA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDiskSpaceInformationW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDiskSpaceInformationW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetDllDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write8(ctx.Arg(1), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDllDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write16(ctx.Arg(1), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDriveTypeW", func(ctx *ntapi.TrapContext) uint32 {
		lpRootPathName := ctx.Arg(0)
		driveType := uint64(1) // DRIVE_NO_ROOT_DIR
		if lpRootPathName != 0 {
			path := readGuestUTF16(lpRootPathName)
			if len(path) > 0 && (path[0] == 'C' || path[0] == 'c') {
				driveType = 3 // DRIVE_FIXED
			}
		}
		ctx.SetReturn(driveType)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDynamicTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		if buf != 0 {
			zeros := make([]byte, 172)
			ctx.Mem.WriteBytes(buf, zeros)
		}
		ctx.SetReturn(0) // TIME_ZONE_ID_UNKNOWN
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetDynamicTimeZoneInformationEffectiveYears", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetDynamicTimeZoneInformationEffectiveYears", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetEnabledXStateFeatures", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetEnabledXStateFeatures", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStrings", func(ctx *ntapi.TrapContext) uint32 {
		block := []byte("PATH=\x00\x00")
		buf := mem.Mmap(0, uint64(len(block)), mmu.PermRead|mmu.PermWrite)
		ctx.Mem.WriteBytes(buf, block)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		block := []byte("PATH=\x00\x00")
		buf := mem.Mmap(0, uint64(len(block)), mmu.PermRead|mmu.PermWrite)
		ctx.Mem.WriteBytes(buf, block)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		buf := ctx.Arg(1)
		size := ctx.Arg(2)
		var val string
		if v, ok := envVars[name]; ok {
			val = v
		} else {
			val = os.Getenv(name)
		}
		if val == "" {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 203) // ERROR_ENVVAR_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		}
		ws := utf16Encode(val)
		needed := uint64(len(ws) + 1)
		if buf == 0 || size == 0 {
			ctx.SetReturn(needed)
			return 0
		}
		if needed > size {
			ctx.SetReturn(needed)
			return 0
		}
		for i, w := range ws {
			ctx.Mem.Write16(buf+uint64(i)*2, w)
		}
		ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		ctx.SetReturn(uint64(len(ws)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetExitCodeProcess", func(ctx *ntapi.TrapContext) uint32 {
		lpExitCode := ctx.Arg(1)
		if lpExitCode != 0 {
			ctx.Mem.Write32(lpExitCode, 259)
		} // STILL_ACTIVE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetExitCodeThread", func(ctx *ntapi.TrapContext) uint32 {
		lpExitCode := ctx.Arg(1)
		if lpExitCode != 0 {
			ctx.Mem.Write32(lpExitCode, 259)
		} // STILL_ACTIVE
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetExpandedNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetExpandedNameA", 2, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "GetExpandedNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetExpandedNameW", 2, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesExA", func(ctx *ntapi.TrapContext) uint32 {
		lpFileName := ctx.Arg(0)
		lpFileInfo := ctx.Arg(2)
		path := winPathToVFS(readGuestString(lpFileName))
		info, err := os.Stat(path)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		var attrs uint32
		if info.IsDir() {
			attrs = 0x10
		} else {
			attrs = 0x80
		}
		mem.Write32(lpFileInfo, attrs)
		const epochDiff = uint64(11644473600) * 10000000
		ft := uint64(info.ModTime().UnixNano())/100 + epochDiff
		mem.Write32(lpFileInfo+4, uint32(ft))
		mem.Write32(lpFileInfo+8, uint32(ft>>32))
		mem.Write32(lpFileInfo+12, uint32(ft))
		mem.Write32(lpFileInfo+16, uint32(ft>>32))
		mem.Write32(lpFileInfo+20, uint32(ft))
		mem.Write32(lpFileInfo+24, uint32(ft>>32))
		size := uint64(info.Size())
		mem.Write32(lpFileInfo+28, uint32(size>>32))
		mem.Write32(lpFileInfo+32, uint32(size))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFileAttributesTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileAttributesTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFileAttributesTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileInformationByHandle", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: dll/win32/kernel32/client/file/fileinfo.c - GetFileInformationByHandle
		// Queries FileBasicInformation, FileInternalInformation, FileStandardInformation
		// and FileFsVolumeInformation, populates BY_HANDLE_FILE_INFORMATION.
		hFile := ntapi.Handle(ctx.Arg(0))
		lpInfo := ctx.Arg(1)
		if lpInfo == 0 {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		fh := handles.GetFile(hFile)
		if fh == nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		node := ctx.FS.Stat(fh.FD)
		if node == nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2) // ERROR_FILE_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		}
		toFT := func(t time.Time) uint64 {
			return uint64(t.UnixNano()/100) + 116444736000000000
		}
		// BY_HANDLE_FILE_INFORMATION layout (52 bytes):
		//  +0x00  DWORD  dwFileAttributes
		//  +0x04  FILETIME ftCreationTime   (8)
		//  +0x0C  FILETIME ftLastAccessTime  (8)
		//  +0x14  FILETIME ftLastWriteTime   (8)
		//  +0x1C  DWORD  dwVolumeSerialNumber
		//  +0x20  DWORD  nFileSizeHigh
		//  +0x24  DWORD  nFileSizeLow
		//  +0x28  DWORD  nNumberOfLinks
		//  +0x2C  DWORD  nFileIndexHigh
		//  +0x30  DWORD  nFileIndexLow
		var attrs uint32 = 0x80 // FILE_ATTRIBUTE_NORMAL
		if node.IsDir {
			attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
		}
		if len(node.Name) > 0 && node.Name[0] == '.' {
			attrs |= 0x02 // FILE_ATTRIBUTE_HIDDEN
		}
		if node.FileMode&0200 == 0 {
			attrs |= 0x01 // FILE_ATTRIBUTE_READONLY
		}
		mem.Write32(lpInfo+0x00, attrs)
		ct := toFT(node.Ctime)
		mem.Write32(lpInfo+0x04, uint32(ct))
		mem.Write32(lpInfo+0x08, uint32(ct>>32))
		at := toFT(node.Atime)
		mem.Write32(lpInfo+0x0C, uint32(at))
		mem.Write32(lpInfo+0x10, uint32(at>>32))
		wt := toFT(node.Mtime)
		mem.Write32(lpInfo+0x14, uint32(wt))
		mem.Write32(lpInfo+0x18, uint32(wt>>32))
		mem.Write32(lpInfo+0x1C, 0x12345678) // dwVolumeSerialNumber (synthetic)
		mem.Write32(lpInfo+0x20, uint32(node.Size>>32))
		mem.Write32(lpInfo+0x24, uint32(node.Size))
		nlinks := node.Nlink
		if nlinks == 0 {
			nlinks = 1
		}
		mem.Write32(lpInfo+0x28, nlinks)
		mem.Write32(lpInfo+0x2C, uint32(node.Ino>>32))
		mem.Write32(lpInfo+0x30, uint32(node.Ino))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileInformationByHandleEx", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		infoClass := uint32(ctx.Arg(1))
		lpInfo := ctx.Arg(2)
		dwBufSize := uint32(ctx.Arg(3))
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		node := ctx.FS.Stat(fh.FD)
		if node == nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2) // ERROR_FILE_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		}
		toFT := func(t time.Time) uint64 {
			return uint64(t.UnixNano()/100) + 116444736000000000
		}
		var attrs uint32 = 0x80 // FILE_ATTRIBUTE_NORMAL
		if node.IsDir {
			attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
		}
		if len(node.Name) > 0 && node.Name[0] == '.' {
			attrs |= 0x02 // FILE_ATTRIBUTE_HIDDEN
		}
		if node.FileMode&0200 == 0 {
			attrs |= 0x01 // FILE_ATTRIBUTE_READONLY
		}
		switch infoClass {
		case 0: // FileBasicInfo (40 bytes)
			if dwBufSize < 40 {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122) // ERROR_INSUFFICIENT_BUFFER
				ctx.SetReturn(0)
				return 0
			}
			ctx.Mem.Write64(lpInfo+0, toFT(node.Ctime))  // CreationTime
			ctx.Mem.Write64(lpInfo+8, toFT(node.Atime))  // LastAccessTime
			ctx.Mem.Write64(lpInfo+16, toFT(node.Mtime)) // LastWriteTime
			ctx.Mem.Write64(lpInfo+24, toFT(node.Mtime)) // ChangeTime
			ctx.Mem.Write32(lpInfo+32, attrs)            // FileAttributes
			ctx.Mem.Write32(lpInfo+36, 0)                // padding
		case 1: // FileStandardInfo (24 bytes)
			if dwBufSize < 24 {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
				ctx.SetReturn(0)
				return 0
			}
			allocSize := (node.Size + 4095) & ^int64(4095)
			ctx.Mem.Write64(lpInfo+0, uint64(allocSize)) // AllocationSize
			ctx.Mem.Write64(lpInfo+8, uint64(node.Size)) // EndOfFile
			nlinks := node.Nlink
			if nlinks == 0 {
				nlinks = 1
			}
			ctx.Mem.Write32(lpInfo+16, nlinks) // NumberOfLinks
			var deletePending uint8
			var isDir uint8
			if node.IsDir {
				isDir = 1
			}
			ctx.Mem.Write8(lpInfo+20, deletePending) // DeletePending
			ctx.Mem.Write8(lpInfo+21, isDir)         // Directory
			ctx.Mem.Write16(lpInfo+22, 0)            // padding
		case 2: // FileNameInfo (4 + wchar[])
			winPath := strings.ReplaceAll(fh.Path, "/", `\`)
			if !strings.HasPrefix(winPath, `\`) {
				winPath = `\` + winPath
			}
			nameUTF16 := utf16.Encode([]rune(winPath))
			nameBytes := uint32(len(nameUTF16) * 2)
			needed := 4 + nameBytes
			if dwBufSize < needed {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
				ctx.SetReturn(0)
				return 0
			}
			ctx.Mem.Write32(lpInfo+0, nameBytes) // FileNameLength in bytes
			for i, ch := range nameUTF16 {
				ctx.Mem.Write16(lpInfo+4+uint64(i)*2, ch)
			}
		case 9: // FileAttributeTagInfo (8 bytes)
			if dwBufSize < 8 {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
				ctx.SetReturn(0)
				return 0
			}
			ctx.Mem.Write32(lpInfo+0, attrs) // FileAttributes
			ctx.Mem.Write32(lpInfo+4, 0)     // ReparseTag
		case 18: // FileIdInfo (24 bytes)
			if dwBufSize < 24 {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122)
				ctx.SetReturn(0)
				return 0
			}
			ctx.Mem.Write64(lpInfo+0, 0x12345678) // VolumeSerialNumber
			ctx.Mem.Write64(lpInfo+8, node.Ino)   // FileId low 8 bytes
			ctx.Mem.Write64(lpInfo+16, 0)         // FileId high 8 bytes
		default:
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 87) // ERROR_INVALID_PARAMETER
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileMUIInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFileMUIInfo", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileMUIPath", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFileMUIPath", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileSize", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		lpFileSizeHigh := ctx.Arg(1)
		obj := handles.Get(hFile)
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		node := ctx.FS.Stat(fh.FD)
		if node == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		sz := node.Size
		if lpFileSizeHigh != 0 {
			ctx.Mem.Write32(lpFileSizeHigh, uint32(sz>>32))
		}
		ctx.SetReturn(uint64(uint32(sz)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFileTime", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		lpCreation := ctx.Arg(1)
		lpLastAccess := ctx.Arg(2)
		lpLastWrite := ctx.Arg(3)
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		node := ctx.FS.Stat(fh.FD)
		if node == nil {
			ctx.SetReturn(0)
			return 0
		}
		toFT := func(t time.Time) uint64 {
			return uint64(t.UnixNano()/100) + 116444736000000000
		}
		if lpCreation != 0 {
			ctx.Mem.Write64(lpCreation, toFT(node.Ctime))
		}
		if lpLastAccess != 0 {
			ctx.Mem.Write64(lpLastAccess, toFT(node.Atime))
		}
		if lpLastWrite != 0 {
			ctx.Mem.Write64(lpLastWrite, toFT(node.Mtime))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFinalPathNameByHandleA", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		lpszFilePath := ctx.Arg(1)
		cchFilePath := uint32(ctx.Arg(2))
		dwFlags := uint32(ctx.Arg(3))
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		vfsPath := fh.Path
		winPath := strings.ReplaceAll(vfsPath, "/", `\`)
		if !strings.HasPrefix(winPath, `\`) {
			winPath = `\` + winPath
		}
		var result string
		if dwFlags&0x8 != 0 { // VOLUME_NAME_NONE
			result = winPath
		} else {
			result = `\\?\C:` + winPath
		}
		if lpszFilePath != 0 && cchFilePath > 0 {
			toWrite := result
			if uint32(len(toWrite)) >= cchFilePath {
				toWrite = toWrite[:cchFilePath-1]
			}
			ctx.Mem.WriteBytes(lpszFilePath, append([]byte(toWrite), 0))
		}
		ctx.SetReturn(uint64(len(result)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFinalPathNameByHandleW", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		lpszFilePath := ctx.Arg(1)
		cchFilePath := uint32(ctx.Arg(2))
		dwFlags := uint32(ctx.Arg(3))
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		vfsPath := fh.Path
		winPath := strings.ReplaceAll(vfsPath, "/", `\`)
		if !strings.HasPrefix(winPath, `\`) {
			winPath = `\` + winPath
		}
		var result string
		if dwFlags&0x8 != 0 { // VOLUME_NAME_NONE
			result = winPath
		} else {
			result = `\\?\C:` + winPath
		}
		runes := utf16.Encode([]rune(result))
		if lpszFilePath != 0 && cchFilePath > 0 {
			n := len(runes)
			if uint32(n) >= cchFilePath {
				n = int(cchFilePath) - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(lpszFilePath+uint64(i)*2, runes[i])
			}
			ctx.Mem.Write16(lpszFilePath+uint64(n)*2, 0) // null terminator
		}
		ctx.SetReturn(uint64(len(runes)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetFirmwareEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFirmwareEnvironmentVariableA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFirmwareEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFirmwareEnvironmentVariableW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFirmwareType", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetFirmwareType", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetFullPathNameA", func(ctx *ntapi.TrapContext) uint32 {
		fileNamePtr := ctx.Arg(0)
		bufLen := ctx.Arg(1)
		buf := ctx.Arg(2)
		name := readGuestString(fileNamePtr)
		needed := uint64(len(name) + 1) // include null
		if bufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		mem.WriteBytes(buf, []byte(name))
		mem.Write8(buf+uint64(len(name)), 0)
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetGeoInfoA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetGeoInfoA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetGeoInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetGeoInfoEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetGeoInfoW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetGeoInfoW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetHandleContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetHandleContext", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetHandleInformation", func(ctx *ntapi.TrapContext) uint32 {
		// GetHandleInformation(hObject, lpdwFlags)
		hObject := ntapi.Handle(ctx.Arg(0))
		lpdwFlags := ctx.Arg(1)
		handleFlagsMu.Lock()
		flags := handleFlagsMap[hObject]
		handleFlagsMu.Unlock()
		if lpdwFlags != 0 {
			ctx.Mem.Write32(lpdwFlags, flags)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLargePageMinimum", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetLargePageMinimum", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetLargestConsoleWindowSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetLargestConsoleWindowSize", 1, uint64(uint64(80|(25<<16))))
	})
	d.RegisterAutoStubHandler(kernel32, "GetLinguistLangSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetLinguistLangSize", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetLogicalDriveStringsW", func(ctx *ntapi.TrapContext) uint32 {
		nBuf := uint32(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		// "C:\\\0\0" in UTF-16: 'C' ':' '\\' '\0' '\0' = 5 wchars, but API returns 4 (char count without final NUL)
		driveStr := []uint16{'C', ':', '\\', 0, 0}
		if lpBuf != 0 && nBuf >= uint32(len(driveStr)) {
			for i, ch := range driveStr {
				ctx.Mem.Write16(lpBuf+uint64(i)*2, ch)
			}
		}
		ctx.SetReturn(4) // 4 chars for "C:\\\0" (excluding final double-NUL)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLogicalDrives", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetLogicalDrives", 0, 4)
	})
	d.RegisterAutoStubHandler(kernel32, "GetLogicalProcessorInformation", func(ctx *ntapi.TrapContext) uint32 {
		retLen := ctx.Arg(1)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLogicalProcessorInformationEx", func(ctx *ntapi.TrapContext) uint32 {
		retLen := ctx.Arg(1)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetLongPathNameA", func(ctx *ntapi.TrapContext) uint32 {
		shortPath := ctx.Arg(0)
		buf := ctx.Arg(1)
		bufLen := ctx.Arg(2)
		name := readGuestString(shortPath)
		needed := uint64(len(name) + 1)
		if bufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		mem.WriteBytes(buf, []byte(name))
		mem.Write8(buf+uint64(len(name)), 0)
		ctx.SetReturn(uint64(len(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetMailslotInfo", func(ctx *ntapi.TrapContext) uint32 {
		// GetMailslotInfo(hMailslot, lpMaxMessageSize, lpNextSize, lpMessageCount, lpReadTimeout)
		h := ntapi.Handle(ctx.Arg(0))
		m := handles.GetMailslot(h)
		if m == nil {
			ctx.SetReturn(0)
			return 0
		}
		if p := ctx.Arg(1); p != 0 {
			ctx.Mem.Write32(p, m.MaxMsgSize)
		}
		count := m.Count()
		if count > 0 {
			nextMsg := m.Read() // peek - re-enqueue
			if nextMsg != nil {
				m.Write(nextMsg) // put back
				if p := ctx.Arg(2); p != 0 {
					ctx.Mem.Write32(p, uint32(len(nextMsg)))
				}
			}
		} else {
			if p := ctx.Arg(2); p != 0 {
				ctx.Mem.Write32(p, 0xFFFFFFFF) // MAILSLOT_NO_MESSAGE
			}
		}
		if p := ctx.Arg(3); p != 0 {
			ctx.Mem.Write32(p, uint32(count))
		}
		if p := ctx.Arg(4); p != 0 {
			ctx.Mem.Write32(p, m.ReadTimeout)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetMaximumProcessorCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetMaximumProcessorCount", 8, 4)
	})
	d.RegisterAutoStubHandler(kernel32, "GetMaximumProcessorGroupCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetMaximumProcessorGroupCount", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetModuleHandleExA", func(ctx *ntapi.TrapContext) uint32 {
		modNamePtr := ctx.Arg(1)
		phModule := ctx.Arg(2)
		if modNamePtr == 0 {
			imageBase, _ := mem.Read64(procState.PEBAddr + 0x10)
			if phModule != 0 {
				mem.Write64Raw(phModule, imageBase)
			}
			ctx.SetReturn(1)
		} else {
			modName := strings.ToLower(readGuestString(modNamePtr))
			if !strings.HasSuffix(modName, ".dll") && !strings.HasSuffix(modName, ".exe") {
				modName += ".dll"
			}
			if s, ok := synthByName[modName]; ok {
				if phModule != 0 {
					mem.Write64Raw(phModule, s.BaseAddr)
				}
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNLSVersion", func(ctx *ntapi.TrapContext) uint32 {
		lpVersionInfo := ctx.Arg(2)
		if !writeNLSVersionInfoData(lpVersionInfo, false) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNLSVersionEx", func(ctx *ntapi.TrapContext) uint32 {
		lpVersionInfo := ctx.Arg(2)
		if !writeNLSVersionInfoData(lpVersionInfo, true) {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeClientProcessId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeClientProcessId", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeClientSessionId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeClientSessionId", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeHandleStateA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeHandleStateA", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeHandleStateW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeHandleStateW", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeInfo", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeServerProcessId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeServerProcessId", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNamedPipeServerSessionId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNamedPipeServerSessionId", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNextUmsListItem", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNextUmsListItem", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNextVDMCommand", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNextVDMCommand", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNlsSectionName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNlsSectionName", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaAvailableMemoryNode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaAvailableMemoryNode", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaAvailableMemoryNodeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaAvailableMemoryNodeEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaHighestNodeNumber", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaHighestNodeNumber", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaNodeProcessorMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaNodeProcessorMask", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaNodeProcessorMaskEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaNodeProcessorMaskEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaProcessorNode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaProcessorNode", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaProcessorNodeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaProcessorNodeEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaProximityNode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaProximityNode", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumaProximityNodeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumaProximityNodeEx", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberFormatA", func(ctx *ntapi.TrapContext) uint32 {
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestString(lpValue)
		n := uint64(len(s) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write8(lpOut+i, s[i])
		}
		ctx.Mem.Write8(lpOut+n-1, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberFormatEx", func(ctx *ntapi.TrapContext) uint32 {
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestUTF16(lpValue)
		ws := utf16Encode(s)
		n := uint64(len(ws) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(lpOut+i*2, ws[i])
		}
		ctx.Mem.Write16(lpOut+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberFormatW", func(ctx *ntapi.TrapContext) uint32 {
		lpValue := ctx.Arg(2)
		lpOut := ctx.Arg(4)
		cch := ctx.Arg(5)
		if lpValue == 0 || lpOut == 0 || cch == 0 {
			ctx.SetReturn(0)
			return 0
		}
		s := readGuestUTF16(lpValue)
		ws := utf16Encode(s)
		n := uint64(len(ws) + 1)
		if n > cch {
			n = cch
		}
		for i := uint64(0); i+1 < n; i++ {
			ctx.Mem.Write16(lpOut+i*2, ws[i])
		}
		ctx.Mem.Write16(lpOut+(n-1)*2, 0)
		ctx.SetReturn(n)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleFonts", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumberOfConsoleFonts", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleInputEvents", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: dll/win32/kernel32/client/console.c
		// BOOL GetNumberOfConsoleInputEvents(HANDLE hConsoleInput, LPDWORD lpcNumberOfEvents)
		lpNumEvents := ctx.Arg(1)
		if lpNumEvents != 0 {
			consoleInputMu.Lock()
			n := uint32(len(consoleInputQueue))
			consoleInputMu.Unlock()
			ctx.Mem.Write32(lpNumEvents, n)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetNumberOfConsoleMouseButtons", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetNumberOfConsoleMouseButtons", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetOverlappedResult", func(ctx *ntapi.TrapContext) uint32 {
		// GetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait)
		lpOverlapped := ctx.Arg(1)
		lpBytes := ctx.Arg(2)
		// bWait := ctx.Arg(3)  // we do sync I/O so always complete
		if lpOverlapped == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// Internal = NTSTATUS, InternalHigh = bytes transferred
		status, _ := ctx.Mem.Read64(lpOverlapped)
		nBytes, _ := ctx.Mem.Read64(lpOverlapped + 8)
		if lpBytes != 0 {
			ctx.Mem.Write32(lpBytes, uint32(nBytes))
		}
		if status == 0 { // STATUS_SUCCESS
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0) // FALSE
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetOverlappedResultEx", func(ctx *ntapi.TrapContext) uint32 {
		// GetOverlappedResultEx(hFile, lpOverlapped, lpNumberOfBytesTransferred, dwMilliseconds, bAlertable)
		lpOverlapped := ctx.Arg(1)
		lpBytes := ctx.Arg(2)
		if lpOverlapped == 0 {
			ctx.SetReturn(0)
			return 0
		}
		status, _ := ctx.Mem.Read64(lpOverlapped)
		nBytes, _ := ctx.Mem.Read64(lpOverlapped + 8)
		if lpBytes != 0 {
			ctx.Mem.Write32(lpBytes, uint32(nBytes))
		}
		if status == 0 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPackageFamilyName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPackageFamilyName", 4, 15700)
	})
	d.RegisterAutoStubHandler(kernel32, "GetPackageFullName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPackageFullName", 4, 15700)
	})
	d.RegisterAutoStubHandler(kernel32, "GetPackagePathByFullName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPackagePathByFullName", 3, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "GetPackagesByPackageFamily", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPackagesByPackageFamily", 4, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "GetPhysicallyInstalledSystemMemory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPhysicallyInstalledSystemMemory", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetPriorityClass", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPriorityClass", 1, uint64(0x20))
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileIntA", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestString(ctx.Arg(0))
		key := readGuestString(ctx.Arg(1))
		nDefault := int32(ctx.Arg(2))
		filePath := readGuestString(ctx.Arg(3))
		sections := iniRead(winPathToVFS(filePath))
		if s, ok := sections[strings.ToLower(section)]; ok {
			if v, ok2 := s[strings.ToLower(key)]; ok2 {
				var n int64
				fmt.Sscan(v, &n)
				ctx.SetReturn(uint64(int32(n)))
				return 0
			}
		}
		ctx.SetReturn(uint64(uint32(nDefault)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileIntW", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestUTF16(ctx.Arg(0))
		key := readGuestUTF16(ctx.Arg(1))
		nDefault := int32(ctx.Arg(2))
		filePath := readGuestUTF16(ctx.Arg(3))
		sections := iniRead(winPathToVFS(filePath))
		if s, ok := sections[strings.ToLower(section)]; ok {
			if v, ok2 := s[strings.ToLower(key)]; ok2 {
				var n int64
				fmt.Sscan(v, &n)
				ctx.SetReturn(uint64(int32(n)))
				return 0
			}
		}
		ctx.SetReturn(uint64(uint32(nDefault)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
		if buf := ctx.Arg(2); buf != 0 {
			ctx.Mem.Write16(buf, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionNamesA", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.Mem.Write8(ctx.Arg(0), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionNamesW", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.Mem.Write16(ctx.Arg(0), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
		if buf := ctx.Arg(2); buf != 0 {
			ctx.Mem.Write16(buf, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestString(ctx.Arg(0))
		key := readGuestString(ctx.Arg(1))
		defVal := readGuestString(ctx.Arg(2))
		outBuf := ctx.Arg(3)
		nSize := ctx.Arg(4)
		filePath := readGuestString(ctx.Arg(5))
		sections := iniRead(winPathToVFS(filePath))
		val := defVal
		if s, ok := sections[strings.ToLower(section)]; ok {
			if v, ok2 := s[strings.ToLower(key)]; ok2 {
				val = v
			}
		}
		b := append([]byte(val), 0)
		if uint64(len(b)) > nSize {
			b = b[:nSize]
		}
		if outBuf != 0 {
			for i, c := range b {
				mem.Write8(outBuf+uint64(i), c)
			}
		}
		ctx.SetReturn(uint64(len(b) - 1))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestUTF16(ctx.Arg(0))
		key := readGuestUTF16(ctx.Arg(1))
		defVal := readGuestUTF16(ctx.Arg(2))
		outBuf := ctx.Arg(3)
		nSize := ctx.Arg(4)
		filePath := readGuestUTF16(ctx.Arg(5))
		sections := iniRead(winPathToVFS(filePath))
		val := defVal
		if s, ok := sections[strings.ToLower(section)]; ok {
			if v, ok2 := s[strings.ToLower(key)]; ok2 {
				val = v
			}
		}
		ws := utf16Encode(val)
		if outBuf != 0 && nSize > 0 {
			n := uint64(len(ws))
			if n >= nSize {
				n = nSize - 1
			}
			for i := uint64(0); i < n; i++ {
				mem.Write16(outBuf+i*2, ws[i])
			}
			mem.Write16(outBuf+n*2, 0)
			ctx.SetReturn(n)
		} else {
			ctx.SetReturn(uint64(len(ws)))
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStructA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPrivateProfileStructA", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetPrivateProfileStructW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetPrivateProfileStructW", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
		lpProcessAffinityMask := ctx.Arg(1)
		lpSystemAffinityMask := ctx.Arg(2)
		if lpProcessAffinityMask != 0 {
			ctx.Mem.Write64(lpProcessAffinityMask, 0xF)
		}
		if lpSystemAffinityMask != 0 {
			ctx.Mem.Write64(lpSystemAffinityMask, 0xF)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
		lpFlags := ctx.Arg(1)
		lpPermanent := ctx.Arg(2)
		if lpFlags != 0 {
			ctx.Mem.Write32(lpFlags, 0)
		}
		if lpPermanent != 0 {
			ctx.Mem.Write32(lpPermanent, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessGroupAffinity", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessHandleCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessHandleCount", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessHeaps", func(ctx *ntapi.TrapContext) uint32 {
		numHeaps := uint32(ctx.Arg(0))
		heapsBuf := ctx.Arg(1)
		if numHeaps >= 1 && heapsBuf != 0 {
			ctx.Mem.Write64(heapsBuf, heapHandle)
		}
		ctx.SetReturn(1) // 1 heap
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessId", 1, uint64(uint64(os.Getpid())))
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessIdOfThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessIdOfThread", 1, uint64(uint64(os.Getpid())))
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessInformation", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessIoCounters", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessIoCounters", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessMitigationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessMitigationPolicy", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessPreferredUILanguages", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessPriorityBoost", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessShutdownParameters", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessShutdownParameters", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessTimes", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessTimes", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessVersion", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessVersion", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessWorkingSetSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessWorkingSetSize", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProcessWorkingSetSizeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProcessWorkingSetSizeEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProductInfo", func(ctx *ntapi.TrapContext) uint32 {
		pdwReturnedProductType := ctx.Arg(3)
		if pdwReturnedProductType != 0 {
			ctx.Mem.Write32(pdwReturnedProductType, 0x30) // PRODUCT_PROFESSIONAL
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProductName", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		if buf != 0 {
			s := "Windows"
			for i := 0; i < len(s); i++ {
				ctx.Mem.Write8(buf+uint64(i), s[i])
			}
			ctx.Mem.Write8(buf+uint64(len(s)), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileIntA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProfileIntA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileIntW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetProfileIntW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write8(ctx.Arg(1), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write16(ctx.Arg(1), 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
		def := readGuestString(ctx.Arg(3))
		if buf := ctx.Arg(4); buf != 0 {
			for i := 0; i < len(def); i++ {
				ctx.Mem.Write8(buf+uint64(i), def[i])
			}
			ctx.Mem.Write8(buf+uint64(len(def)), 0)
		}
		ctx.SetReturn(uint64(len(def)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
		def := readGuestUTF16(ctx.Arg(3))
		ws := utf16Encode(def)
		buf, maxChars := ctx.Arg(4), ctx.Arg(5)
		if buf != 0 && maxChars > 0 {
			n := uint64(len(ws))
			if n >= maxChars {
				n = maxChars - 1
			}
			for i := uint64(0); i < n; i++ {
				ctx.Mem.Write16(buf+i*2, ws[i])
			}
			ctx.Mem.Write16(buf+n*2, 0)
			ctx.SetReturn(n)
		} else {
			ctx.SetReturn(uint64(len(ws)))
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetQueuedCompletionStatus", func(ctx *ntapi.TrapContext) uint32 {
		// GetQueuedCompletionStatus(CompletionPort, lpNumberOfBytesTransferred,
		//   lpCompletionKey, lpOverlapped, dwMilliseconds)
		iocpHandle := ntapi.Handle(ctx.Arg(0))
		pBytes := ctx.Arg(1)
		pKey := ctx.Arg(2)
		pOverlapped := ctx.Arg(3)
		ms := ctx.Arg(4)
		var timeout time.Duration
		if ms == 0xFFFFFFFF {
			timeout = -1
		} else {
			timeout = time.Duration(ms) * time.Millisecond
		}
		if ic := handles.GetIoCompletion(iocpHandle); ic != nil {
			pkt, ok := ic.Remove(timeout)
			if !ok {
				ctx.SetReturn(0) // FALSE - timeout
				return 0
			}
			ctx.Mem.Write32(pBytes, pkt.BytesTransferred)
			ctx.Mem.Write64(pKey, pkt.CompletionKey)
			ctx.Mem.Write64(pOverlapped, pkt.Overlapped)
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0) // FALSE - unknown handle
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetQueuedCompletionStatusEx", func(ctx *ntapi.TrapContext) uint32 {
		// GetQueuedCompletionStatusEx(CompletionPort, lpCompletionPortEntries,
		//   ulCount, ulNumEntriesRemoved, dwMilliseconds, fAlertable)
		iocpHandle := ntapi.Handle(ctx.Arg(0))
		pEntries := ctx.Arg(1)
		// ulCount := ctx.Arg(2)
		pRemoved := ctx.Arg(3)
		ms := ctx.Arg(4)
		var timeout time.Duration
		if ms == 0xFFFFFFFF {
			timeout = -1
		} else {
			timeout = time.Duration(ms) * time.Millisecond
		}
		if ic := handles.GetIoCompletion(iocpHandle); ic != nil {
			pkt, ok := ic.Remove(timeout)
			if !ok {
				ctx.SetReturn(0)
				return 0
			}
			// OVERLAPPED_ENTRY: {key, overlapped*, internal, bytes}
			// Write one entry: key(8) overlapped*(8) internal(8) bytes(4)
			ctx.Mem.Write64(pEntries+0, pkt.CompletionKey)
			ctx.Mem.Write64(pEntries+8, pkt.Overlapped)
			ctx.Mem.Write64(pEntries+16, 0)
			ctx.Mem.Write32(pEntries+24, pkt.BytesTransferred)
			if pRemoved != 0 {
				ctx.Mem.Write32(pRemoved, 1)
			}
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetShortPathNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetShortPathNameA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetShortPathNameW", func(ctx *ntapi.TrapContext) uint32 {
		longPath := ctx.Arg(0)
		buf := ctx.Arg(1)
		bufLen := ctx.Arg(2)
		// No 8.3 short names on Linux; copy input to output unchanged.
		var chars []uint16
		for i := uint64(0); ; i += 2 {
			w, _ := ctx.Mem.Read16(longPath + i)
			chars = append(chars, w)
			if w == 0 {
				break
			}
		}
		needed := uint64(len(chars))
		if buf == 0 || bufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		for i, w := range chars {
			ctx.Mem.Write16(buf+uint64(i*2), w)
		}
		ctx.SetReturn(needed - 1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetStringTypeA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetStringTypeA", 5, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemCpuSetInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemCpuSetInformation", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemDEPPolicy", 4, 3)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLCID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemDefaultLCID", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLangID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemDefaultLangID", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(writeUTF16StringCount(ctx.Arg(0), defaultLocaleName, ctx.Arg(1)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDefaultUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemDefaultUILanguage", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows\\System32"
		ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows\\System32"
		for i, r := range utf16Encode(path) {
			ctx.Mem.Write16(buf+uint64(i)*2, r)
		}
		ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemFileCacheSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemFileCacheSize", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemFirmwareTable", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemFirmwareTable", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemPowerStatus", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemPowerStatus", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		pulNum := ctx.Arg(1)
		buf := ctx.Arg(2)
		pcch := ctx.Arg(3)
		var lang string
		if dwFlags&4 != 0 { // MUI_LANGUAGE_ID
			lang = "0409"
		} else {
			lang = "en-US"
		}
		ws := utf16Encode(lang)
		required := uint32(len(ws) + 2) // string + null + double-null
		if pulNum != 0 {
			ctx.Mem.Write32(pulNum, 1)
		}
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.Mem.Write16(buf+uint64(len(ws)+1)*2, 0)
		}
		if pcch != 0 {
			ctx.Mem.Write32(pcch, required)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemRegistryQuota", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemRegistryQuota", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		st := ctx.Arg(0)
		if st == 0 {
			return 0
		}
		now := time.Now().UTC()
		ctx.Mem.Write16(st+0, uint16(now.Year()))
		ctx.Mem.Write16(st+2, uint16(now.Month()))
		ctx.Mem.Write16(st+4, uint16(now.Weekday()))
		ctx.Mem.Write16(st+6, uint16(now.Day()))
		ctx.Mem.Write16(st+8, uint16(now.Hour()))
		ctx.Mem.Write16(st+10, uint16(now.Minute()))
		ctx.Mem.Write16(st+12, uint16(now.Second()))
		ctx.Mem.Write16(st+14, uint16(now.Nanosecond()/1e6))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemTimeAdjustment", func(ctx *ntapi.TrapContext) uint32 {
		adj := ctx.Arg(0)
		inc := ctx.Arg(1)
		disabled := ctx.Arg(2)
		if adj != 0 {
			ctx.Mem.Write32(adj, 156250)
		}
		if inc != 0 {
			ctx.Mem.Write32(inc, 156250)
		}
		if disabled != 0 {
			ctx.Mem.Write32(disabled, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemTimePreciseAsFileTime", func(ctx *ntapi.TrapContext) uint32 {
		ft := ctx.Arg(0)
		if ft != 0 {
			const epochDiff = uint64(11644473600) * 10000000
			v := uint64(time.Now().UnixNano()/100) + epochDiff
			ctx.Mem.Write64Raw(ft, v)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemTimes", func(ctx *ntapi.TrapContext) uint32 {
		idle := ctx.Arg(0)
		kernel := ctx.Arg(1)
		user := ctx.Arg(2)
		if idle != 0 {
			ctx.Mem.Write64(idle, 0)
		}
		if kernel != 0 {
			ctx.Mem.Write64(kernel, 0)
		}
		if user != 0 {
			ctx.Mem.Write64(user, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows"
		ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows"
		for i, r := range utf16Encode(path) {
			ctx.Mem.Write16(buf+uint64(i)*2, r)
		}
		ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemWow64DirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemWow64DirectoryA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetSystemWow64DirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetSystemWow64DirectoryW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetTapeParameters", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetTapeParameters", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetTapePosition", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetTapePosition", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetTapeStatus", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetTapeStatus", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		pathArg := readGuestString(ctx.Arg(0))
		if pathArg == "" {
			pathArg = `C:\Windows\Temp`
		}
		prefix := readGuestString(ctx.Arg(1))
		if len(prefix) > 3 {
			prefix = prefix[:3]
		}
		uUnique := ctx.Arg(2)
		lpTempFileName := ctx.Arg(3)
		if uUnique == 0 {
			for n := uint64(1); n <= 0xFFFF; n++ {
				name := fmt.Sprintf("%s\\%s%04X.tmp", pathArg, prefix, n)
				if _, err := os.Stat(winPathToVFS(name)); os.IsNotExist(err) {
					uUnique = n
					break
				}
			}
			if uUnique == 0 {
				uUnique = 1
			}
		}
		name := fmt.Sprintf("%s\\%s%04X.tmp", pathArg, prefix, uUnique)
		if lpTempFileName != 0 {
			for i := 0; i < len(name); i++ {
				mem.Write8(lpTempFileName+uint64(i), name[i])
			}
			mem.Write8(lpTempFileName+uint64(len(name)), 0)
		}
		ctx.SetReturn(uUnique)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		lpTempFileName := ctx.Arg(3)
		uUnique := ctx.Arg(2)
		prefix := readGuestUTF16(ctx.Arg(1))
		if len(prefix) > 3 {
			prefix = prefix[:3]
		}
		uniqueN := uUnique
		if uniqueN == 0 {
			uniqueN = uint64(time.Now().UnixNano() & 0xFFFF)
		}
		name := fmt.Sprintf("C:\\Windows\\Temp\\%s%04X.tmp", prefix, uniqueN)
		if lpTempFileName != 0 {
			ws := utf16Encode(name)
			for i, w := range ws {
				ctx.Mem.Write16(lpTempFileName+uint64(i)*2, w)
			}
			ctx.Mem.Write16(lpTempFileName+uint64(len(ws))*2, 0)
		}
		ctx.SetReturn(uniqueN)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempPath2A", func(ctx *ntapi.TrapContext) uint32 {
		s := "C:\\Temp\\"
		if buf := ctx.Arg(1); buf != 0 {
			for i := 0; i < len(s); i++ {
				ctx.Mem.Write8(buf+uint64(i), s[i])
			}
			ctx.Mem.Write8(buf+uint64(len(s)), 0)
		}
		ctx.SetReturn(uint64(len(s)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempPath2W", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		s := `C:\Windows\Temp\`
		ws := utf16Encode(s)
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		}
		ctx.SetReturn(uint64(len(ws)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTempPathA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		s := `C:\Windows\Temp\`
		if buf != 0 {
			for i := 0; i < len(s); i++ {
				ctx.Mem.Write8(buf+uint64(i), s[i])
			}
			ctx.Mem.Write8(buf+uint64(len(s)), 0)
		}
		ctx.SetReturn(uint64(len(s)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
		// ReactOS: dll/win32/kernel32/client/except.c → NtGetContextThread
		// For the current-thread pseudo-handle we can fill in registers from
		// the calling CPU state. For other threads we return TRUE with zeroed
		// context (the thread's CPU is running on another goroutine and we
		// cannot safely snapshot it).
		hThread := ctx.Arg(0)
		lpContext := ctx.Arg(1)
		if lpContext == 0 {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		const contextSize = 1232
		// Zero-fill the CONTEXT first
		for i := uint64(0); i < contextSize; i += 8 {
			ctx.Mem.Write64Raw(lpContext+i, 0)
		}
		// Current-thread pseudo-handle (0xFFFFFFFFFFFFFFFE) or main TID
		isCurrent := hThread == 0xFFFFFFFFFFFFFFFE
		if !isCurrent {
			th := handles.GetThread(ntapi.Handle(hThread))
			if th != nil {
				tid, _ := ctx.Mem.Read32(procState.TEBAddr + ntapi.TebThreadId)
				if th.TID == int(tid) {
					isCurrent = true
				}
			}
		}
		if isCurrent {
			// CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER
			ctx.Mem.Write32(lpContext+0x30, 0x10000B)
			if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
				ctx.Mem.Write64(lpContext+0x78, rr.ReadReg(0))  // Rax
				ctx.Mem.Write64(lpContext+0x80, rr.ReadReg(1))  // Rcx
				ctx.Mem.Write64(lpContext+0x88, rr.ReadReg(2))  // Rdx
				ctx.Mem.Write64(lpContext+0x90, rr.ReadReg(3))  // Rbx
				ctx.Mem.Write64(lpContext+0x98, rr.ReadReg(4))  // Rsp
				ctx.Mem.Write64(lpContext+0xA0, rr.ReadReg(5))  // Rbp
				ctx.Mem.Write64(lpContext+0xA8, rr.ReadReg(6))  // Rsi
				ctx.Mem.Write64(lpContext+0xB0, rr.ReadReg(7))  // Rdi
				ctx.Mem.Write64(lpContext+0xB8, rr.ReadReg(8))  // R8
				ctx.Mem.Write64(lpContext+0xC0, rr.ReadReg(9))  // R9
				ctx.Mem.Write64(lpContext+0xC8, rr.ReadReg(10)) // R10
				ctx.Mem.Write64(lpContext+0xD0, rr.ReadReg(11)) // R11
				ctx.Mem.Write64(lpContext+0xD8, rr.ReadReg(12)) // R12
				ctx.Mem.Write64(lpContext+0xE0, rr.ReadReg(13)) // R13
				ctx.Mem.Write64(lpContext+0xE8, rr.ReadReg(14)) // R14
				ctx.Mem.Write64(lpContext+0xF0, rr.ReadReg(15)) // R15
			}
			ctx.Mem.Write64(lpContext+0xF8, ctx.CPU.GetPC()) // Rip
			ctx.Mem.Write64(lpContext+0x98, ctx.CPU.GetSP()) // Rsp (overwrite with canonical)
			// SegCs and SegSs for long mode
			ctx.Mem.Write16(lpContext+0x38, 0x33) // SegCs
			ctx.Mem.Write16(lpContext+0x42, 0x2B) // SegSs
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadDescription", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadDescription", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadErrorMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadErrorMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadGroupAffinity", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadIOPendingFlag", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadIOPendingFlag", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadId", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadIdealProcessorEx", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(1) != 0 {
			ctx.Mem.Write64(ctx.Arg(1), 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadLocale", func(ctx *ntapi.TrapContext) uint32 {
		threadLocaleMu.Lock()
		locale := threadLocale
		threadLocaleMu.Unlock()
		ctx.SetReturn(uint64(locale))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		pulNum := ctx.Arg(1)
		buf := ctx.Arg(2)
		pcch := ctx.Arg(3)
		var lang string
		if dwFlags&4 != 0 {
			lang = "0409"
		} else {
			lang = "en-US"
		}
		ws := utf16Encode(lang)
		required := uint32(len(ws) + 2)
		if pulNum != 0 {
			ctx.Mem.Write32(pulNum, 1)
		}
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.Mem.Write16(buf+uint64(len(ws)+1)*2, 0)
		}
		if pcch != 0 {
			ctx.Mem.Write32(pcch, required)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadPriority", func(ctx *ntapi.TrapContext) uint32 {
		// int GetThreadPriority(HANDLE hThread);
		// ReactOS: dll/win32/kernel32/client/thread.c
		hThread := ctx.Arg(0)
		if hThread == 0xFFFFFFFFFFFFFFFE {
			ctx.SetReturn(0) // THREAD_PRIORITY_NORMAL for current thread
			return 0
		}
		th := handles.GetThread(ntapi.Handle(hThread))
		if th != nil {
			ctx.SetReturn(uint64(int64(th.Priority)))
			return 0
		}
		ctx.SetReturn(0) // THREAD_PRIORITY_NORMAL
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadPriorityBoost", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadSelectorEntry", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadSelectorEntry", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadTimes", func(ctx *ntapi.TrapContext) uint32 {
		for i := int(1); i <= 4; i++ {
			p := ctx.Arg(i)
			if p != 0 {
				ctx.Mem.Write64(p, 0)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetThreadUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetThreadUILanguage", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetTickCount64", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetTickCount64", 0, uint64(uint64(time.Since(startTime).Milliseconds())))
	})
	d.RegisterAutoStubHandler(kernel32, "GetTimeFormatA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(4)
		s := "12:00:00"
		if buf != 0 {
			for i := 0; i < len(s); i++ {
				ctx.Mem.Write8(buf+uint64(i), s[i])
			}
			ctx.Mem.Write8(buf+uint64(len(s)), 0)
		}
		ctx.SetReturn(9)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetTimeZoneInformationForYear", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetTimeZoneInformationForYear", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetUmsCompletionListEvent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetUmsCompletionListEvent", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserDefaultGeoName", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		ws := utf16Encode("US")
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
		}
		ctx.SetReturn(2)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLangID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetUserDefaultLangID", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserDefaultLocaleName", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(writeUTF16StringCount(ctx.Arg(0), defaultLocaleName, ctx.Arg(1)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserDefaultUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetUserDefaultUILanguage", 0, uint64(defaultLocaleLCID))
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserGeoID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetUserGeoID", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetUserPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		dwFlags := ctx.Arg(0)
		pulNum := ctx.Arg(1)
		buf := ctx.Arg(2)
		pcch := ctx.Arg(3)
		var lang string
		if dwFlags&4 != 0 {
			lang = "0409"
		} else {
			lang = "en-US"
		}
		ws := utf16Encode(lang)
		required := uint32(len(ws) + 2)
		if pulNum != 0 {
			ctx.Mem.Write32(pulNum, 1)
		}
		if buf != 0 {
			for i, w := range ws {
				ctx.Mem.Write16(buf+uint64(i)*2, w)
			}
			ctx.Mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.Mem.Write16(buf+uint64(len(ws)+1)*2, 0)
		}
		if pcch != 0 {
			ctx.Mem.Write32(pcch, required)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVDMCurrentDirectories", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVDMCurrentDirectories", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationA", func(ctx *ntapi.TrapContext) uint32 {
		// lpRootPathName=0, lpVolumeNameBuf=1, nVolNameSize=2,
		// lpSerialNum=3, lpMaxComponentLen=4, lpFSFlags=5, lpFSNameBuf=6, nFSNameSize=7
		volNameBuf := ctx.Arg(1)
		volNameSize := ctx.Arg(2)
		lpSerialNum := ctx.Arg(3)
		lpMaxComponentLen := ctx.Arg(4)
		lpFSFlags := ctx.Arg(5)
		fsBuf := ctx.Arg(6)
		fsBufSize := ctx.Arg(7)
		if volNameBuf != 0 && volNameSize > 0 {
			volName := "Windows"
			toWrite := volName
			if uint64(len(toWrite)) >= volNameSize {
				toWrite = toWrite[:volNameSize-1]
			}
			ctx.Mem.WriteBytes(volNameBuf, append([]byte(toWrite), 0))
		}
		if lpSerialNum != 0 {
			ctx.Mem.Write32(lpSerialNum, 0xDEADBEEF)
		}
		if lpMaxComponentLen != 0 {
			ctx.Mem.Write32(lpMaxComponentLen, 255)
		}
		if lpFSFlags != 0 {
			ctx.Mem.Write32(lpFSFlags, 0x00020003)
		}
		if fsBuf != 0 && fsBufSize > 0 {
			fsName := "NTFS"
			toWrite := fsName
			if uint64(len(toWrite)) >= fsBufSize {
				toWrite = toWrite[:fsBufSize-1]
			}
			ctx.Mem.WriteBytes(fsBuf, append([]byte(toWrite), 0))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationByHandleW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumeInformationByHandleW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumeInformationW", func(ctx *ntapi.TrapContext) uint32 {
		// lpRootPathName=0, lpVolumeNameBuf=1, nVolNameSize=2,
		// lpSerialNum=3, lpMaxComponentLen=4, lpFSFlags=5, lpFSNameBuf=6, nFSNameSize=7
		volNameBuf := ctx.Arg(1)
		volNameSize := ctx.Arg(2)
		lpSerialNum := ctx.Arg(3)
		lpMaxComponentLen := ctx.Arg(4)
		lpFSFlags := ctx.Arg(5)
		fsBuf := ctx.Arg(6)
		fsBufSize := ctx.Arg(7)
		if volNameBuf != 0 && volNameSize > 0 {
			for i, r := range []rune("Windows") {
				if uint64(i) >= volNameSize-1 {
					break
				}
				ctx.Mem.Write16(volNameBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(volNameBuf+uint64(len("Windows"))*2, 0)
		}
		if lpSerialNum != 0 {
			ctx.Mem.Write32(lpSerialNum, 0xDEADBEEF)
		}
		if lpMaxComponentLen != 0 {
			ctx.Mem.Write32(lpMaxComponentLen, 255)
		}
		if lpFSFlags != 0 {
			ctx.Mem.Write32(lpFSFlags, 0x00020003)
		}
		if fsBuf != 0 && fsBufSize > 0 {
			for i, r := range []rune("NTFS") {
				if uint64(i) >= fsBufSize-1 {
					break
				}
				ctx.Mem.Write16(fsBuf+uint64(i)*2, uint16(r))
			}
			ctx.Mem.Write16(fsBuf+uint64(len("NTFS"))*2, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumeNameForVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumeNameForVolumeMountPointA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumeNameForVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumeNameForVolumeMountPointW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumePathNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumePathNameA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumePathNameW", func(ctx *ntapi.TrapContext) uint32 {
		// lpszFileName=0, lpszVolumePathName=1, cchBufferLength=2
		lpszVolumePathName := ctx.Arg(1)
		cchBufferLength := ctx.Arg(2)
		if lpszVolumePathName != 0 && cchBufferLength >= 4 {
			// Write "C:\" in UTF-16
			ctx.Mem.Write16(lpszVolumePathName+0, 'C')
			ctx.Mem.Write16(lpszVolumePathName+2, ':')
			ctx.Mem.Write16(lpszVolumePathName+4, '\\')
			ctx.Mem.Write16(lpszVolumePathName+6, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumePathNamesForVolumeNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumePathNamesForVolumeNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetVolumePathNamesForVolumeNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetVolumePathNamesForVolumeNameW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetWindowsDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows"
		ctx.Mem.WriteBytes(buf, append([]byte(path), 0))
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetWindowsDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		path := "C:\\Windows"
		for i, r := range utf16Encode(path) {
			ctx.Mem.Write16(buf+uint64(i)*2, r)
		}
		ctx.Mem.Write16(buf+uint64(len(path))*2, 0)
		ctx.SetReturn(uint64(len(path)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GetWriteWatch", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetWriteWatch", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GetXStateFeaturesMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GetXStateFeaturesMask", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalAddAtomA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		ctx.SetReturn(uint64(addAtomGlobal(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalAddAtomW", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestUTF16(ctx.Arg(0))
		ctx.SetReturn(uint64(addAtomGlobal(name)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalCompact", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalCompact", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalDeleteAtom", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		if name, ok := globalAtomNames[atom]; ok {
			delete(globalAtomTable, strings.ToLower(name))
			delete(globalAtomNames, atom)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalFindAtomA", func(ctx *ntapi.TrapContext) uint32 {
		key := strings.ToLower(readGuestString(ctx.Arg(0)))
		if a, ok := globalAtomTable[key]; ok {
			ctx.SetReturn(uint64(a))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalFindAtomW", func(ctx *ntapi.TrapContext) uint32 {
		key := strings.ToLower(readGuestUTF16(ctx.Arg(0)))
		if a, ok := globalAtomTable[key]; ok {
			ctx.SetReturn(uint64(a))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalFix", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalFix", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalGetAtomNameA", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		buf := ctx.Arg(1)
		sz := ctx.Arg(2)
		if name, ok := globalAtomNames[atom]; ok && buf != 0 && sz > 0 {
			b := append([]byte(name), 0)
			if uint64(len(b)) > sz {
				b = b[:sz]
			}
			for i, c := range b {
				mem.Write8(buf+uint64(i), c)
			}
			ctx.SetReturn(uint64(len(b) - 1))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalGetAtomNameW", func(ctx *ntapi.TrapContext) uint32 {
		atom := uint16(ctx.Arg(0))
		buf := ctx.Arg(1)
		sz := ctx.Arg(2)
		if name, ok := globalAtomNames[atom]; ok && buf != 0 && sz > 0 {
			ws := utf16Encode(name)
			maxW := uint64(sz) - 1
			if uint64(len(ws)) > maxW {
				ws = ws[:maxW]
			}
			for i, w := range ws {
				mem.Write16(buf+uint64(i)*2, w)
			}
			mem.Write16(buf+uint64(len(ws))*2, 0)
			ctx.SetReturn(uint64(len(ws)))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalHandle", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalMemoryStatus", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalMemoryStatus", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalReAlloc", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		dwBytes := ctx.Arg(1)
		if dwBytes == 0 {
			dwBytes = 1
		}
		newPtr := mem.Mmap(0, dwBytes, mmu.PermRead|mmu.PermWrite)
		if hMem != 0 && newPtr != 0 {
			_, oldSize, mapped, _ := mem.QueryRegion(hMem)
			if mapped && oldSize > 0 {
				copySize := oldSize
				if dwBytes < copySize {
					copySize = dwBytes
				}
				old, _ := ctx.Mem.ReadBytes(hMem, int(copySize))
				if len(old) > 0 {
					ctx.Mem.WriteBytes(newPtr, old)
				}
				mem.Munmap(hMem, oldSize)
			}
		}
		ctx.SetReturn(newPtr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalUnWire", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalUnWire", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalUnfix", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalUnfix", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "GlobalWire", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "GlobalWire", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Heap32First", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Heap32First", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Heap32ListFirst", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Heap32ListFirst", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Heap32ListNext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Heap32ListNext", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Heap32Next", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Heap32Next", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapCompact", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapCompact", 2, uint64(0x10000))
	})
	d.RegisterAutoStubHandler(kernel32, "HeapCreateTagsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapCreateTagsW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapExtend", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapExtend", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapLock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapLock", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapQueryInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapQueryInformation", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapQueryTagW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapQueryTagW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapSetFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapSetFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapSetInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapSetInformation", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapSummary", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapSummary", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapUnlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapUnlock", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapUsage", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "HeapUsage", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "HeapValidate", func(ctx *ntapi.TrapContext) uint32 {
		// HeapValidate(hHeap, dwFlags, lpMem)
		lpMem := ctx.Arg(2)
		if lpMem != 0 {
			// Check that the 16-byte header has a sane block size
			blockSize, _ := mem.Read64(lpMem - 16)
			if blockSize == 0 || blockSize >= 1<<30 {
				ctx.SetReturn(0) // FALSE - invalid
				return 0
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "HeapWalk", func(ctx *ntapi.TrapContext) uint32 {
		mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 259) // ERROR_NO_MORE_ITEMS
		ctx.SetReturn(0)                                            // FALSE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IdnToAscii", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(1)
		cchSrc := int32(ctx.Arg(2))
		lpDst := ctx.Arg(3)
		cchDst := int32(ctx.Arg(4))
		var srcChars []uint16
		if cchSrc == -1 {
			s := readGuestUTF16(lpSrc)
			srcChars = append(utf16Encode(s), 0)
		} else {
			srcChars = make([]uint16, cchSrc)
			for i := int32(0); i < cchSrc; i++ {
				w, _ := ctx.Mem.Read16(lpSrc + uint64(i)*2)
				srcChars[i] = w
			}
		}
		required := len(srcChars)
		if lpDst == 0 || cchDst == 0 {
			ctx.SetReturn(uint64(required))
			return 0
		}
		n := required
		if int(cchDst) < n {
			n = int(cchDst)
		}
		for i := 0; i < n; i++ {
			ctx.Mem.Write16(lpDst+uint64(i)*2, srcChars[i])
		}
		ctx.SetReturn(uint64(required))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IdnToNameprepUnicode", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(1)
		cchSrc := int32(ctx.Arg(2))
		lpDst := ctx.Arg(3)
		cchDst := int32(ctx.Arg(4))
		var srcChars []uint16
		if cchSrc == -1 {
			s := readGuestUTF16(lpSrc)
			srcChars = append(utf16Encode(s), 0)
		} else {
			srcChars = make([]uint16, cchSrc)
			for i := int32(0); i < cchSrc; i++ {
				w, _ := ctx.Mem.Read16(lpSrc + uint64(i)*2)
				srcChars[i] = w
			}
		}
		required := len(srcChars)
		if lpDst == 0 || cchDst == 0 {
			ctx.SetReturn(uint64(required))
			return 0
		}
		n := required
		if int(cchDst) < n {
			n = int(cchDst)
		}
		for i := 0; i < n; i++ {
			ctx.Mem.Write16(lpDst+uint64(i)*2, srcChars[i])
		}
		ctx.SetReturn(uint64(required))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IdnToUnicode", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(1)
		cchSrc := int32(ctx.Arg(2))
		lpDst := ctx.Arg(3)
		cchDst := int32(ctx.Arg(4))
		var srcChars []uint16
		if cchSrc == -1 {
			s := readGuestUTF16(lpSrc)
			srcChars = append(utf16Encode(s), 0)
		} else {
			srcChars = make([]uint16, cchSrc)
			for i := int32(0); i < cchSrc; i++ {
				w, _ := ctx.Mem.Read16(lpSrc + uint64(i)*2)
				srcChars[i] = w
			}
		}
		required := len(srcChars)
		if lpDst == 0 || cchDst == 0 {
			ctx.SetReturn(uint64(required))
			return 0
		}
		n := required
		if int(cchDst) < n {
			n = int(cchDst)
		}
		for i := 0; i < n; i++ {
			ctx.Mem.Write16(lpDst+uint64(i)*2, srcChars[i])
		}
		ctx.SetReturn(uint64(required))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitAtomTable", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitAtomTable", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "InitOnceExecuteOnce", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitOnceExecuteOnce", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "InitOnceInitialize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitOnceInitialize", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitializeConditionVariable", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitializeContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeContext2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitializeContext2", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		lp := ctx.Arg(0)
		if lp != 0 {
			// Win64 CRITICAL_SECTION: DebugInfo=0, LockCount=-1, RecursionCount=0, OwningThread=0, LockSemaphore=0, SpinCount=0
			ctx.Mem.Write64(lp, 0)            // DebugInfo
			ctx.Mem.Write32(lp+8, 0xFFFFFFFF) // LockCount = -1 (unlocked)
			ctx.Mem.Write32(lp+12, 0)         // RecursionCount
			ctx.Mem.Write64(lp+16, 0)         // OwningThread
			ctx.Mem.Write64(lp+24, 0)         // LockSemaphore
			ctx.Mem.Write64(lp+32, 0)         // SpinCount
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeProcThreadAttributeList", func(ctx *ntapi.TrapContext) uint32 {
		lpAttr := ctx.Arg(0)
		lpSize := ctx.Arg(3)
		if lpAttr == 0 && lpSize != 0 {
			ctx.Mem.Write64(lpSize, 64)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeSRWLock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitializeSRWLock", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InitializeSynchronizationBarrier", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InitializeSynchronizationBarrier", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedFlushSList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InterlockedFlushSList", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedPopEntrySList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InterlockedPopEntrySList", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedPushEntrySList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InterlockedPushEntrySList", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedPushListSList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InterlockedPushListSList", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InterlockedPushListSListEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InterlockedPushListSListEx", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InvalidateConsoleDIBits", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InvalidateConsoleDIBits", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "InvalidateNLSCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "InvalidateNLSCache", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadCodePtr", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadCodePtr", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadHugeReadPtr", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadHugeReadPtr", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadHugeWritePtr", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadHugeWritePtr", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadReadPtr", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadReadPtr", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadStringPtrA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadStringPtrA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadStringPtrW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadStringPtrW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsBadWritePtr", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsBadWritePtr", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsDBCSLeadByte", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsDBCSLeadByteEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsDBCSLeadByteEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsNLSDefinedString", func(ctx *ntapi.TrapContext) uint32 {
		src := readWideStringArg(ctx.Arg(3), int32(ctx.Arg(4)))
		for _, r := range src {
			if !isCommonNLSRune(r) {
				ctx.SetReturn(0)
				return 0
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsNormalizedString", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsNormalizedString", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "IsProcessInJob", func(ctx *ntapi.TrapContext) uint32 {
		// IsProcessInJob(hProcess, hJob, pbResult)
		hJob := ntapi.Handle(ctx.Arg(1))
		pbResult := ctx.Arg(2)
		inJob := false
		if j := handles.GetJob(hJob); j != nil {
			pid := uint32(os.Getpid())
			for _, p := range j.PIDs {
				if p == pid {
					inJob = true
					break
				}
			}
		}
		if pbResult != 0 {
			v := uint32(0)
			if inJob {
				v = 1
			}
			mem.Write32(pbResult, v)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsSystemResumeAutomatic", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsSystemResumeAutomatic", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsThreadAFiber", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsThreadAFiber", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "IsThreadpoolTimerSet", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if tt := handles.GetTpTimer(h); tt != nil && tt.IsSet() {
			ctx.SetReturn(1) // TRUE
		} else {
			ctx.SetReturn(0) // FALSE
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "IsValidLanguageGroup", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsValidLanguageGroup", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "IsValidLocaleName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsValidLocaleName", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "IsValidNLSVersion", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsValidNLSVersion", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "IsWow64Process2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "IsWow64Process2", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EmptyWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EmptyWorkingSet", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumDeviceDrivers", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumDeviceDrivers", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumPageFilesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumPageFilesA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumPageFilesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumPageFilesW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumProcessModules", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumProcessModules", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumProcessModulesEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumProcessModulesEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32EnumProcesses", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32EnumProcesses", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetDeviceDriverBaseNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetDeviceDriverBaseNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetDeviceDriverFileNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetDeviceDriverFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetDeviceDriverFileNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetMappedFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetMappedFileNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetMappedFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetMappedFileNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetModuleBaseNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetModuleBaseNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetModuleBaseNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetModuleBaseNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetModuleFileNameExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetModuleFileNameExA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetModuleFileNameExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetModuleFileNameExW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetModuleInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetModuleInformation", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetPerformanceInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetPerformanceInfo", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetProcessImageFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetProcessImageFileNameA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetProcessImageFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetProcessImageFileNameW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetProcessMemoryInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetProcessMemoryInfo", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetWsChanges", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetWsChanges", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32GetWsChangesEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32GetWsChangesEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32InitializeProcessForWsWatch", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32InitializeProcessForWsWatch", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32QueryWorkingSet", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32QueryWorkingSet", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "K32QueryWorkingSetEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "K32QueryWorkingSetEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LCIDToLocaleName", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(writeUTF16StringCount(ctx.Arg(1), lcidToLocaleNameValue(uint32(ctx.Arg(0))), ctx.Arg(2)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LZClose", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZClose", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZCopy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZCopy", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZDone", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZDone", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZInit", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZInit", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZOpenFileA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZOpenFileA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZOpenFileW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZOpenFileW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZRead", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZRead", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZSeek", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZSeek", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LZStart", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LZStart", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LeaveCriticalSectionWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LeaveCriticalSectionWhenCallbackReturns", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LoadAppInitDlls", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LoadAppInitDlls", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LoadLibraryExA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := strings.ToLower(readGuestString(namePtr))
		if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
			name = name[idx+1:]
		}
		if !strings.HasSuffix(name, ".dll") {
			name += ".dll"
		}
		if synth, ok := synthByName[name]; ok {
			ctx.SetReturn(synth.BaseAddr)
			return 0
		}
		newSynth := ntapi.GenerateSynthDLL(mem, name, []string{}, 0)
		synthByName[name] = newSynth
		ravelog.Logf("[win32] LoadLibraryExA: auto-created stub for %q\n", name)
		ctx.SetReturn(newSynth.BaseAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LoadModule", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LoadModule", 2, 2)
	})
	d.RegisterAutoStubHandler(kernel32, "LoadPackagedLibrary", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LoadPackagedLibrary", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LocalCompact", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalCompact", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LocalFileTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0)
		dst := ctx.Arg(1)
		if src != 0 && dst != 0 {
			v, _ := ctx.Mem.Read64(src)
			ctx.Mem.Write64(dst, v)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocalFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LocalHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalHandle", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LocalLock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalLock", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "LocalReAlloc", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		size := ctx.Arg(1)
		if size == 0 {
			size = 1
		}
		addr := mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
		if hMem != 0 && addr != 0 {
			_, oldSize, mapped, _ := mem.QueryRegion(hMem)
			if mapped && oldSize > 0 {
				copySize := oldSize
				if size < copySize {
					copySize = size
				}
				old, _ := ctx.Mem.ReadBytes(hMem, int(copySize))
				if len(old) > 0 {
					ctx.Mem.WriteBytes(addr, old)
				}
				mem.Munmap(hMem, oldSize)
			}
		}
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocalShrink", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalShrink", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LocalSize", func(ctx *ntapi.TrapContext) uint32 {
		hMem := ctx.Arg(0)
		if hMem == 0 {
			ctx.SetReturn(0)
			return 0
		}
		_, size, mapped, _ := mem.QueryRegion(hMem)
		if mapped {
			ctx.SetReturn(size)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocalUnlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocalUnlock", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "LocaleNameToLCID", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(localeNameToLCIDValue(readGuestUTF16(ctx.Arg(0)))))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LocateXStateFeature", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "LocateXStateFeature", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "LockFile", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.SetReturn(1) // best effort for non-file handles
			return 0
		}
		err := unix.Flock(fh.FD, unix.LOCK_EX|unix.LOCK_NB)
		if err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 33) // ERROR_LOCK_VIOLATION
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "LockFileEx", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		dwFlags := uint32(ctx.Arg(1))
		// arg2 = dwReserved
		// arg3 = nNumberOfBytesToLockLow
		// arg4 = nNumberOfBytesToLockHigh
		lpOverlapped := ctx.Arg(5)
		fh := handles.GetFile(hFile)
		if fh == nil {
			if lpOverlapped != 0 {
				ctx.Mem.Write64(lpOverlapped, 0) // Internal = STATUS_SUCCESS
			}
			ctx.SetReturn(1)
			return 0
		}
		lockType := unix.LOCK_SH // shared by default
		if dwFlags&0x02 != 0 {   // LOCKFILE_EXCLUSIVE_LOCK
			lockType = unix.LOCK_EX
		}
		if dwFlags&0x01 != 0 { // LOCKFILE_FAIL_IMMEDIATELY
			lockType |= unix.LOCK_NB
		}
		err := unix.Flock(fh.FD, lockType)
		if err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 33) // ERROR_LOCK_VIOLATION
			ctx.SetReturn(0)
			return 0
		}
		if lpOverlapped != 0 {
			ctx.Mem.Write64(lpOverlapped, 0) // Internal = STATUS_SUCCESS
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MakeCriticalSectionGlobal", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "MakeCriticalSectionGlobal", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "MapUserPhysicalPages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "MapUserPhysicalPages", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "MapViewOfFileEx", func(ctx *ntapi.TrapContext) uint32 {
		hMapping := ntapi.Handle(ctx.Arg(0))
		dwDesiredAccess := uint32(ctx.Arg(1))
		offHigh := uint32(ctx.Arg(2))
		offLow := uint32(ctx.Arg(3))
		numBytes := ctx.Arg(4)
		// ctx.Arg(5) = lpBaseAddress hint (ignored; we allocate freely)
		guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
		ctx.SetReturn(guestAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MapViewOfFileExNuma", func(ctx *ntapi.TrapContext) uint32 {
		hMapping := ntapi.Handle(ctx.Arg(0))
		dwDesiredAccess := uint32(ctx.Arg(1))
		offHigh := uint32(ctx.Arg(2))
		offLow := uint32(ctx.Arg(3))
		numBytes := ctx.Arg(4)
		// ctx.Arg(5) = lpBaseAddress hint, ctx.Arg(6) = nndPreferred (both ignored)
		guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
		ctx.SetReturn(guestAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MapViewOfFileFromApp", func(ctx *ntapi.TrapContext) uint32 {
		hMapping := ntapi.Handle(ctx.Arg(0))
		dwDesiredAccess := uint32(ctx.Arg(1))
		offHigh := uint32(ctx.Arg(2))
		offLow := uint32(ctx.Arg(3))
		numBytes := ctx.Arg(4)
		guestAddr := doMapView(ctx, hMapping, dwDesiredAccess, offHigh, offLow, numBytes)
		ctx.SetReturn(guestAddr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "Module32First", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Module32First", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Module32FirstW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Module32FirstW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Module32Next", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Module32Next", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Module32NextW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Module32NextW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileA", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestString(ctx.Arg(0)))
		dst := winPathToVFS(readGuestString(ctx.Arg(1)))
		if err := os.Rename(src, dst); err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileExA", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestString(ctx.Arg(0)))
		dst := winPathToVFS(readGuestString(ctx.Arg(1)))
		_ = os.Rename(src, dst)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "MoveFileTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "MoveFileTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileW", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestUTF16(ctx.Arg(0)))
		dst := winPathToVFS(readGuestUTF16(ctx.Arg(1)))
		if err := os.Rename(src, dst); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileWithProgressA", func(ctx *ntapi.TrapContext) uint32 {
		src := winPathToVFS(readGuestString(ctx.Arg(0)))
		dst := winPathToVFS(readGuestString(ctx.Arg(1)))
		if err := os.Rename(src, dst); err != nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 5)
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "MoveFileWithProgressW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "MoveFileWithProgressW", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "NeedCurrentDirectoryForExePathA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "NeedCurrentDirectoryForExePathA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "NeedCurrentDirectoryForExePathW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "NeedCurrentDirectoryForExePathW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "NormalizeString", func(ctx *ntapi.TrapContext) uint32 {
		lpSrc := ctx.Arg(1)
		cwSrc := int32(ctx.Arg(2))
		lpDst := ctx.Arg(3)
		cwDst := int32(ctx.Arg(4))
		var srcChars []uint16
		if cwSrc == -1 {
			s := readGuestUTF16(lpSrc)
			srcChars = append(utf16Encode(s), 0)
		} else {
			srcChars = make([]uint16, cwSrc)
			for i := int32(0); i < cwSrc; i++ {
				w, _ := ctx.Mem.Read16(lpSrc + uint64(i)*2)
				srcChars[i] = w
			}
		}
		required := len(srcChars)
		if cwDst == 0 {
			ctx.SetReturn(uint64(required))
			return 0
		}
		if int(cwDst) < required {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 122) // ERROR_INSUFFICIENT_BUFFER
			ctx.SetReturn(uint64(int64(-int64(required))))
			return 0
		}
		for i, w := range srcChars {
			ctx.Mem.Write16(lpDst+uint64(i)*2, w)
		}
		ctx.SetReturn(uint64(required))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "NotifyNLSUserCache", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "NotifyNLSUserCache", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "OpenConsoleW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenConsoleW", 4, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "OpenDataFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenDataFile", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "OpenEventA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenEventW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenFile", 3, uint64(0xFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "OpenFileById", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenFileById", 6, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "OpenFileMappingA", func(ctx *ntapi.TrapContext) uint32 {
		// OpenFileMappingA(dwDesiredAccess, bInheritHandle, lpName)
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenFileMappingW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenJobObjectA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenJobObjectW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenMutexA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenMutexW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenProcess", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenProcess", 3, uint64(0x1000))
	})
	d.RegisterAutoStubHandler(kernel32, "OpenProcessToken", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenProcessToken", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "OpenProfileUserMapping", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenProfileUserMapping", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "OpenSemaphoreA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenSemaphoreW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(2)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenThread", 3, uint64(0x1001))
	})
	d.RegisterAutoStubHandler(kernel32, "OpenThreadToken", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "OpenThreadToken", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "OpenWaitableTimerA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OpenWaitableTimerW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(1)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestUTF16(namePtr)
		h := handles.GetNamed(name)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OutputDebugStringA", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ravelog.Logf("[debug] %s\n", readGuestString(ctx.Arg(0)))
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "OutputDebugStringW", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ravelog.Logf("[debug] %s\n", readGuestUTF16(ctx.Arg(0)))
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PackageIdFromFullName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PackageIdFromFullName", 3, uint64(0x3D54))
	})
	d.RegisterAutoStubHandler(kernel32, "PeekConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
		lpNumRead := ctx.Arg(3)
		if lpNumRead != 0 {
			ctx.Mem.Write32(lpNumRead, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PeekConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
		// ReactOS: dll/win32/kernel32/client/console.c
		// BOOL PeekConsoleInputW(HANDLE hConsoleInput, PINPUT_RECORD lpBuffer,
		//     DWORD nLength, LPDWORD lpNumberOfEventsRead)
		lpBuffer := ctx.Arg(1)
		nLength := int(ctx.Arg(2))
		lpNumRead := ctx.Arg(3)
		events := peekConsoleEvents(nLength)
		for i, evt := range events {
			writeConsoleInputRecord(lpBuffer+uint64(i)*20, evt)
		}
		if lpNumRead != 0 {
			ctx.Mem.Write32(lpNumRead, uint32(len(events)))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PeekNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
		// PeekNamedPipe(hPipe, lpBuf, nBufSize, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMsg)
		hPipe := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nBufSize := int(ctx.Arg(2))
		lpBytesRead := ctx.Arg(3)
		lpTotalAvail := ctx.Arg(4)
		lpBytesLeft := ctx.Arg(5)
		pipe := handles.GetNamedPipe(hPipe)
		if pipe == nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0)
			return 0
		}
		avail := pipe.AvailableBytes()
		nr := 0
		if lpBuf != 0 && nBufSize > 0 && avail > 0 {
			peek := make([]byte, nBufSize)
			n := copy(peek, pipe.ReadBuf())
			mem.WriteBytes(lpBuf, peek[:n])
			nr = n
		}
		if lpBytesRead != 0 {
			mem.Write32(lpBytesRead, uint32(nr))
		}
		if lpTotalAvail != 0 {
			mem.Write32(lpTotalAvail, uint32(avail))
		}
		if lpBytesLeft != 0 {
			mem.Write32(lpBytesLeft, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PostQueuedCompletionStatus", func(ctx *ntapi.TrapContext) uint32 {
		// PostQueuedCompletionStatus(CompletionPort, dwNumberOfBytesTransferred, dwCompletionKey, lpOverlapped)
		iocpHandle := ntapi.Handle(ctx.Arg(0))
		bytes := uint32(ctx.Arg(1))
		key := ctx.Arg(2)
		overlapped := ctx.Arg(3)
		if ic := handles.GetIoCompletion(iocpHandle); ic != nil {
			ic.Post(key, overlapped, bytes, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PowerClearRequest", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PowerClearRequest", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "PowerCreateRequest", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PowerCreateRequest", 1, uint64(0x1005))
	})
	d.RegisterAutoStubHandler(kernel32, "PowerSetRequest", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PowerSetRequest", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "PrefetchVirtualMemory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PrefetchVirtualMemory", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "PrepareTape", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PrepareTape", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "PrivCopyFileExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PrivCopyFileExW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "PrivMoveFileIdentityW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PrivMoveFileIdentityW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Process32FirstW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Process32FirstW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Process32Next", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Process32Next", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Process32NextW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Process32NextW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ProcessIdToSessionId", func(ctx *ntapi.TrapContext) uint32 {
		lpdwSessionId := ctx.Arg(1)
		if lpdwSessionId != 0 {
			ctx.Mem.Write32(lpdwSessionId, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PulseEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if ev := handles.GetEvent(h); ev != nil {
			ev.Set()
			ev.Reset()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "PurgeComm", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "PurgeComm", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryActCtxSettingsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryActCtxSettingsW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryActCtxW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryActCtxW", 7, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryDepthSList", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryDepthSList", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryDosDeviceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryDosDeviceA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryDosDeviceW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryDosDeviceW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryFullProcessImageNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryFullProcessImageNameA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryFullProcessImageNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryFullProcessImageNameW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryIdleProcessorCycleTime", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) != 0 {
			ctx.Mem.Write32(ctx.Arg(0), 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryIdleProcessorCycleTimeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryIdleProcessorCycleTimeEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryInformationJobObject", func(ctx *ntapi.TrapContext) uint32 {
		// QueryInformationJobObject(hJob, JobObjectInfoClass, lpJobObjectInfo, cbJobObjectInfoLength, lpReturnLength)
		hJob := ntapi.Handle(ctx.Arg(0))
		class := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		bufLen := uint32(ctx.Arg(3))
		retLen := ctx.Arg(4)
		j := handles.GetJob(hJob)
		if j == nil {
			ctx.SetReturn(0)
			return 0
		}
		switch class {
		case 1: // JobObjectBasicAccountingInformation (48 bytes)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, 48)
			}
			if buf != 0 && bufLen >= 48 {
				// All zeros (no accounting data)
				for i := uint64(0); i < 48; i++ {
					ctx.Mem.Write8(buf+i, 0)
				}
			}
		case 2: // JobObjectBasicLimitInformation (56 bytes)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, 56)
			}
			if buf != 0 && bufLen >= 56 {
				ctx.Mem.Write32(buf+44, j.Limits.ActiveProcessLimit)
				ctx.Mem.Write32(buf+48, j.Limits.PriorityClass)
				ctx.Mem.Write32(buf+52, j.Limits.SchedulingClass)
			}
		case 4: // JobObjectBasicProcessIdList
			const hdrSize = 8
			needed := uint32(hdrSize + len(j.PIDs)*8)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, needed)
			}
			if buf != 0 && bufLen >= needed {
				ctx.Mem.Write32(buf+0, uint32(len(j.PIDs)))
				ctx.Mem.Write32(buf+4, uint32(len(j.PIDs)))
				for i, pid := range j.PIDs {
					ctx.Mem.Write64(buf+8+uint64(i)*8, uint64(pid))
				}
			}
		case 9: // JobObjectExtendedLimitInformation (96 bytes)
			if retLen != 0 {
				ctx.Mem.Write32(retLen, 96)
			}
			if buf != 0 && bufLen >= 96 {
				ctx.Mem.Write32(buf+52, j.Limits.ActiveProcessLimit)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryMemoryResourceNotification", func(ctx *ntapi.TrapContext) uint32 {
		if state := ctx.Arg(1); state != 0 {
			ctx.Mem.Write32(state, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryNumberOfEventLogRecords", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryNumberOfEventLogRecords", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryOldestEventLogRecord", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryOldestEventLogRecord", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryProcessCycleTime", func(ctx *ntapi.TrapContext) uint32 {
		lpCycleTime := ctx.Arg(1)
		if lpCycleTime != 0 {
			ctx.Mem.Write64(lpCycleTime, uint64(time.Since(startTime).Nanoseconds()/100))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryThreadCycleTime", func(ctx *ntapi.TrapContext) uint32 {
		lpCycleTime := ctx.Arg(1)
		if lpCycleTime != 0 {
			ctx.Mem.Write64(lpCycleTime, uint64(time.Since(startTime).Nanoseconds()/100))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryThreadpoolStackInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryThreadpoolStackInformation", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryUmsThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryUmsThreadInformation", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueryUnbiasedInterruptTime", func(ctx *ntapi.TrapContext) uint32 {
		lpTime := ctx.Arg(0)
		if lpTime != 0 {
			ctx.Mem.Write64(lpTime, uint64(time.Since(startTime).Nanoseconds()/100))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueryWin31IniFilesMappedToRegistry", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueryWin31IniFilesMappedToRegistry", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "QueueUserAPC", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
		// ReactOS: dll/win32/kernel32/client/thread.c → NtQueueApcThread
		// We do not dispatch APCs yet, but return success so callers proceed.
		pfnAPC := ctx.Arg(0)
		hThread := ctx.Arg(1)
		dwData := ctx.Arg(2)
		ravelog.Logf("[win32] QueueUserAPC(func=0x%x, thread=0x%x, data=0x%x) → stub TRUE\n", pfnAPC, hThread, dwData)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "QueueUserAPC2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "QueueUserAPC2", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "QueueUserWorkItem", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL QueueUserWorkItem(LPTHREAD_START_ROUTINE Function,
		//                        PVOID Context, ULONG Flags);
		// ReactOS: dll/win32/kernel32/client/thread.c → RtlQueueWorkItem
		function := ctx.Arg(0)
		context := ctx.Arg(1)
		flags := ctx.Arg(2)
		ravelog.Logf("[win32] QueueUserWorkItem(func=0x%x, ctx=0x%x, flags=0x%x) → stub TRUE\n", function, context, flags)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RaiseFailFastException", func(ctx *ntapi.TrapContext) uint32 {
		os.Exit(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReOpenFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReOpenFile", 4, uint64(0xFFFFFFFFFFFFFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		nCharsToRead := uint32(ctx.Arg(2))
		charsRead := ctx.Arg(3)
		ansi, _ := readConsoleText(int(nCharsToRead), true)
		if uint32(len(ansi)) > nCharsToRead {
			ansi = ansi[:nCharsToRead]
		}
		for i := 0; i < len(ansi); i++ {
			ctx.Mem.Write8(buf+uint64(i), ansi[i])
		}
		if charsRead != 0 {
			ctx.Mem.Write32(charsRead, uint32(len(ansi)))
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	// ReadConsoleInput: synthesize a KEY_EVENT record for each character read from stdin.
	// INPUT_RECORD layout: EventType(2) + pad(2) + KeyEvent(16): bKeyDown(4)+wRepeatCount(2)+wVirtualKeyCode(2)+wVirtualScanCode(2)+pad(2)+Char(2)+dwControlKeyState(4)
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		// nLength := ctx.Arg(2) // max records to fill
		lpEventsRead := ctx.Arg(3)
		b := make([]byte, 1)
		n, _ := os.Stdin.Read(b)
		if n == 0 {
			if lpEventsRead != 0 {
				ctx.Mem.Write32(lpEventsRead, 0)
			}
			ctx.SetReturn(1)
			return 0
		}
		ch := b[0]
		// Write KEY_DOWN INPUT_RECORD (20 bytes) at buf
		ctx.Mem.Write16(buf+0, 0x0001)      // EventType = KEY_EVENT
		ctx.Mem.Write32(buf+4, 1)           // bKeyDown = TRUE
		ctx.Mem.Write16(buf+8, 1)           // wRepeatCount
		ctx.Mem.Write16(buf+10, uint16(ch)) // wVirtualKeyCode (approx)
		ctx.Mem.Write8(buf+14, ch)          // AsciiChar
		if lpEventsRead != 0 {
			ctx.Mem.Write32(lpEventsRead, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReadConsoleInputExA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReadConsoleInputExW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		nLength := int(ctx.Arg(2))
		lpEventsRead := ctx.Arg(3)
		if nLength <= 0 {
			if lpEventsRead != 0 {
				ctx.Mem.Write32(lpEventsRead, 0)
			}
			ctx.SetReturn(1)
			return 0
		}
		eventsRead := 0
		for eventsRead < nLength {
			evt, ok := dequeueConsoleEvent(eventsRead == 0)
			if !ok {
				break
			}
			writeConsoleInputRecord(buf+uint64(eventsRead)*20, evt)
			eventsRead++
		}
		if lpEventsRead != 0 {
			ctx.Mem.Write32(lpEventsRead, uint32(eventsRead))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputA", func(ctx *ntapi.TrapContext) uint32 {
		// ReadConsoleOutputA(hConsole, lpBuffer, dwBufferSize, dwBufferCoord, lpReadRegion)
		buf := ctx.Arg(1)
		bufW := int(ctx.Arg(2) & 0xFFFF)
		bufCoordX := int(ctx.Arg(3) & 0xFFFF)
		bufCoordY := int((ctx.Arg(3) >> 16) & 0xFFFF)
		readRgn := ctx.Arg(4)
		if buf == 0 || readRgn == 0 {
			ctx.SetReturn(1)
			return 0
		}
		left, _ := ctx.Mem.Read16(readRgn + 0)
		top, _ := ctx.Mem.Read16(readRgn + 2)
		right, _ := ctx.Mem.Read16(readRgn + 4)
		bottom, _ := ctx.Mem.Read16(readRgn + 6)
		for y := int(top); y <= int(bottom); y++ {
			for x := int(left); x <= int(right); x++ {
				bx := x - int(left) + bufCoordX
				by := y - int(top) + bufCoordY
				idx := uint64(by*bufW+bx) * 4
				if c := ntapi.GlobalConsole.Cell(x, y); c != nil {
					ctx.Mem.Write8(buf+idx, uint8(c.Char))
					ctx.Mem.Write8(buf+idx+1, 0)
					ctx.Mem.Write16(buf+idx+2, c.Attr)
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
		lpAttr := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numRead := ctx.Arg(4)
		if lpAttr == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		read := 0
		for i := 0; i < n; i++ {
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			attr := uint16(0x07)
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				attr = c.Attr
			}
			ctx.Mem.Write16(lpAttr+uint64(i)*2, attr)
			read++
		}
		if numRead != 0 {
			ctx.Mem.Write32(numRead, uint32(read))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
		lpChar := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numRead := ctx.Arg(4)
		if lpChar == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		read := 0
		for i := 0; i < n; i++ {
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			ch := byte(' ')
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				if c.Char < 128 {
					ch = byte(c.Char)
				}
			}
			ctx.Mem.Write8(lpChar+uint64(i), ch)
			read++
		}
		if numRead != 0 {
			ctx.Mem.Write32(numRead, uint32(read))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
		lpChar := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numRead := ctx.Arg(4)
		if lpChar == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		read := 0
		for i := 0; i < n; i++ {
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			ch := uint16(' ')
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				ch = c.Char
			}
			ctx.Mem.Write16(lpChar+uint64(i)*2, ch)
			read++
		}
		if numRead != 0 {
			ctx.Mem.Write32(numRead, uint32(read))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadConsoleOutputW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		bufW := int(ctx.Arg(2) & 0xFFFF)
		bufCoordX := int(ctx.Arg(3) & 0xFFFF)
		bufCoordY := int((ctx.Arg(3) >> 16) & 0xFFFF)
		readRgn := ctx.Arg(4)
		if buf == 0 || readRgn == 0 {
			ctx.SetReturn(1)
			return 0
		}
		left, _ := ctx.Mem.Read16(readRgn + 0)
		top, _ := ctx.Mem.Read16(readRgn + 2)
		right, _ := ctx.Mem.Read16(readRgn + 4)
		bottom, _ := ctx.Mem.Read16(readRgn + 6)
		for y := int(top); y <= int(bottom); y++ {
			for x := int(left); x <= int(right); x++ {
				bx := x - int(left) + bufCoordX
				by := y - int(top) + bufCoordY
				idx := uint64(by*bufW+bx) * 4
				if c := ntapi.GlobalConsole.Cell(x, y); c != nil {
					ctx.Mem.Write16(buf+idx, c.Char)
					ctx.Mem.Write16(buf+idx+2, c.Attr)
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReadDirectoryChangesW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReadDirectoryChangesW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ReadFileEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReadFileEx", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReadFileScatter", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReadFileScatter", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ReadProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
		nSize := ctx.Arg(3)
		if nSize > 0 {
			data, _ := ctx.Mem.ReadBytes(ctx.Arg(1), int(nSize))
			ctx.Mem.WriteBytes(ctx.Arg(2), data)
		}
		if bw := ctx.Arg(4); bw != 0 {
			ctx.Mem.Write64(bw, nSize)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegCloseKey", func(ctx *ntapi.TrapContext) uint32 {
		hKey := ctx.Arg(0)
		handles.Close(ntapi.Handle(hKey))
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegCreateKeyExA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegCreateKeyExW", func(ctx *ntapi.TrapContext) uint32 {
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
				ctx.Mem.Write32(disp, 2) // REG_OPENED_EXISTING_KEY
			} else {
				ctx.Mem.Write32(disp, 1) // REG_CREATED_NEW_KEY
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegCreateKeyA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegCreateKeyW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.CreateKey(path)
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(2); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteKeyW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteTreeA", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteTreeW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		ctx.Reg.DeleteKey(path)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteValueA", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		if rk != nil && rk.Key != nil {
			name := readGuestString(ctx.Arg(1))
			delete(rk.Key.Values, name)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegDeleteValueW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegEnumKeyExA", func(ctx *ntapi.TrapContext) uint32 {
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
		name := names[idx]
		if buf := ctx.Arg(2); buf != 0 {
			for i := 0; i < len(name); i++ {
				ctx.Mem.Write8(buf+uint64(i), name[i])
			}
			ctx.Mem.Write8(buf+uint64(len(name)), 0)
		}
		if lp := ctx.Arg(3); lp != 0 {
			ctx.Mem.Write32(lp, uint32(len(name)))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegEnumKeyExW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegEnumValueA", func(ctx *ntapi.TrapContext) uint32 {
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
		if buf := ctx.Arg(2); buf != 0 {
			for i := 0; i < len(name); i++ {
				ctx.Mem.Write8(buf+uint64(i), name[i])
			}
			ctx.Mem.Write8(buf+uint64(len(name)), 0)
		}
		if lp := ctx.Arg(3); lp != 0 {
			ctx.Mem.Write32(lp, uint32(len(name)))
		}
		if lpType := ctx.Arg(5); lpType != 0 {
			ctx.Mem.Write32(lpType, val.Type)
		}
		needed := uint32(len(val.Data))
		if lpcb := ctx.Arg(7); lpcb != 0 {
			ctx.Mem.Write32(lpcb, needed)
		}
		if lpData := ctx.Arg(6); lpData != 0 {
			ctx.Mem.WriteBytes(lpData, val.Data)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegEnumValueW", func(ctx *ntapi.TrapContext) uint32 {
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
		if lpcbData := ctx.Arg(7); lpcbData != 0 {
			avail, _ := ctx.Mem.Read32(lpcbData)
			ctx.Mem.Write32(lpcbData, needed)
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
	d.RegisterAutoStubHandler(kernel32, "RegFlushKey", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegFlushKey", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegGetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
		// RegGetKeySecurity(hKey, SecurityInformation, pSecurityDescriptor, lpcbSecurityDescriptor)
		pSD := ctx.Arg(2)
		lpcb := ctx.Arg(3)
		// Minimal self-relative security descriptor: 20 bytes header
		var needed uint32 = 20
		if lpcb != 0 {
			avail, _ := ctx.Mem.Read32(lpcb)
			ctx.Mem.Write32(lpcb, needed)
			if pSD == 0 || avail < needed {
				ctx.SetReturn(122) // ERROR_INSUFFICIENT_BUFFER
				return 0
			}
		}
		if pSD != 0 {
			// SECURITY_DESCRIPTOR_RELATIVE: Revision=1, Sbz1=0, Control=SE_SELF_RELATIVE(0x8000)
			ctx.Mem.Write8(pSD, 1)         // Revision
			ctx.Mem.Write8(pSD+1, 0)       // Sbz1
			ctx.Mem.Write16(pSD+2, 0x8000) // Control: SE_SELF_RELATIVE
			ctx.Mem.Write32(pSD+4, 0)      // OffsetOwner
			ctx.Mem.Write32(pSD+8, 0)      // OffsetGroup
			ctx.Mem.Write32(pSD+12, 0)     // OffsetSacl
			ctx.Mem.Write32(pSD+16, 0)     // OffsetDacl
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegGetValueA", func(ctx *ntapi.TrapContext) uint32 {
		// RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData)
		subKey := readGuestString(ctx.Arg(1))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			ctx.SetReturn(2)
			return 0
		}
		tmpH := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		defer handles.Close(ntapi.Handle(tmpH))
		old0 := ctx.Arg(0)
		_ = old0
		// reuse regQueryValue by temporarily patching args
		valueName := readGuestString(ctx.Arg(2))
		_ = valueName
		ctx.SetReturn(2) // simplified: just not found for now
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegGetValueW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
		valueName := readGuestUTF16(ctx.Arg(2))
		path := regKeyPath(ctx.Arg(0), subKey)
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			ctx.SetReturn(2)
			return 0
		}
		var val *ntapi.RegistryValue
		for k, v := range key.Values {
			if strings.EqualFold(k, valueName) {
				val = v
				break
			}
		}
		if val == nil {
			ctx.SetReturn(2)
			return 0
		}
		lpType := ctx.Arg(4)
		pvData := ctx.Arg(5)
		pcbData := ctx.Arg(6)
		if lpType != 0 {
			ctx.Mem.Write32(lpType, val.Type)
		}
		needed := uint32(len(val.Data))
		if pcbData != 0 {
			avail, _ := ctx.Mem.Read32(pcbData)
			ctx.Mem.Write32(pcbData, needed)
			if pvData != 0 && avail < needed {
				ctx.SetReturn(234)
				return 0
			}
		}
		if pvData != 0 {
			ctx.Mem.WriteBytes(pvData, val.Data)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegLoadKeyA", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegLoadKeyW", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegLoadMUIStringA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegLoadMUIStringA", 4, 2)
	})
	d.RegisterAutoStubHandler(kernel32, "RegLoadMUIStringW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegLoadMUIStringW", 4, 2)
	})
	d.RegisterAutoStubHandler(kernel32, "RegNotifyChangeKeyValue", func(ctx *ntapi.TrapContext) uint32 {
		// RegNotifyChangeKeyValue(hKey, bWatchSubtree, dwNotifyFilter, hEvent, fAsynchronous)
		hEvent := ntapi.Handle(ctx.Arg(3))
		fAsync := ctx.Arg(4)
		if hEvent != 0 && fAsync != 0 {
			evt := handles.GetEvent(hEvent)
			if evt != nil {
				go func() {
					time.Sleep(5 * time.Second)
					evt.Signal()
				}()
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegOpenCurrentUser", func(ctx *ntapi.TrapContext) uint32 {
		path := `HKEY_CURRENT_USER`
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			key = ctx.Reg.CreateKey(path)
		}
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(1); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegOpenKeyExA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegOpenKeyExW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegOpenKeyA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegOpenKeyW", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegOpenUserClassesRoot", func(ctx *ntapi.TrapContext) uint32 {
		path := `HKEY_CLASSES_ROOT`
		key := ctx.Reg.OpenKey(path)
		if key == nil {
			key = ctx.Reg.CreateKey(path)
		}
		h := handles.Alloc(&ntapi.RegistryKeyHandle{Hive: regHive, Key: key, Path: path})
		if phk := ctx.Arg(1); phk != 0 {
			ctx.Mem.Write64(phk, uint64(h))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegQueryInfoKeyA", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		var nSubKeys, nValues uint32
		if rk != nil && rk.Key != nil {
			nSubKeys = uint32(len(rk.Key.Children))
			nValues = uint32(len(rk.Key.Values))
		}
		if p := ctx.Arg(4); p != 0 {
			ctx.Mem.Write32(p, nSubKeys)
		}
		if p := ctx.Arg(7); p != 0 {
			ctx.Mem.Write32(p, nValues)
		}
		for _, i := range []int{2, 3, 5, 6, 8, 9, 10} {
			if p := ctx.Arg(i); p != 0 {
				ctx.Mem.Write32(p, 0)
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegQueryInfoKeyW", func(ctx *ntapi.TrapContext) uint32 {
		rk := handles.GetRegKey(ntapi.Handle(ctx.Arg(0)))
		var nSubKeys, nValues uint32
		if rk != nil && rk.Key != nil {
			nSubKeys = uint32(len(rk.Key.Children))
			nValues = uint32(len(rk.Key.Values))
		}
		if p := ctx.Arg(4); p != 0 {
			ctx.Mem.Write32(p, nSubKeys)
		}
		if p := ctx.Arg(7); p != 0 {
			ctx.Mem.Write32(p, nValues)
		}
		for _, i := range []int{2, 3, 5, 6, 8, 9, 10} {
			if p := ctx.Arg(i); p != 0 {
				ctx.Mem.Write32(p, 0)
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegQueryValueExA", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestString(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegQueryValueExW", func(ctx *ntapi.TrapContext) uint32 {
		valueName := readGuestUTF16(ctx.Arg(1))
		ctx.SetReturn(uint64(regQueryValue(ctx, ctx.Arg(0), valueName)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegRestoreKeyA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegRestoreKeyA", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegRestoreKeyW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegRestoreKeyW", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegSaveKeyExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegSaveKeyExA", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegSaveKeyExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegSaveKeyExW", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegSetKeySecurity", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegSetKeySecurity", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegSetValueExA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegSetValueExW", func(ctx *ntapi.TrapContext) uint32 {
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
	// RegQueryValueA/W: older API that queries the default value of a subkey.
	d.RegisterAutoStubHandler(kernel32, "RegQueryValueA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegQueryValueW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
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
	// RegSetValueA/W: older API that sets the default value of a subkey.
	d.RegisterAutoStubHandler(kernel32, "RegSetValueA", func(ctx *ntapi.TrapContext) uint32 {
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
	d.RegisterAutoStubHandler(kernel32, "RegSetValueW", func(ctx *ntapi.TrapContext) uint32 {
		subKey := readGuestUTF16(ctx.Arg(1))
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
	d.RegisterAutoStubHandler(kernel32, "RegUnLoadKeyA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegUnLoadKeyA", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegUnLoadKeyW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegUnLoadKeyW", 4, 5)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterApplicationRecoveryCallback", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterApplicationRecoveryCallback", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterConsoleIME", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterConsoleIME", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterConsoleOS2", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterConsoleOS2", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterConsoleVDM", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterConsoleVDM", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterServiceProcess", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterServiceProcess", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterSysMsgHandler", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterSysMsgHandler", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterWaitForInputIdle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterWaitForInputIdle", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterWaitForSingleObject", func(ctx *ntapi.TrapContext) uint32 {
		if phNew := ctx.Arg(0); phNew != 0 {
			ctx.Mem.Write64(phNew, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterWaitForSingleObjectEx", func(ctx *ntapi.TrapContext) uint32 {
		if phNew := ctx.Arg(0); phNew != 0 {
			ctx.Mem.Write64(phNew, 1)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterWowBaseHandlers", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterWowBaseHandlers", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RegisterWowExec", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RegisterWowExec", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReinitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReinitializeCriticalSection", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseActCtx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReleaseActCtx", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseMutexWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReleaseMutexWhenCallbackReturns", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReleaseSRWLockShared", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseSemaphore", func(ctx *ntapi.TrapContext) uint32 {
		// ReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount)
		h := ntapi.Handle(ctx.Arg(0))
		releaseCount := int32(ctx.Arg(1))
		pPrevious := ctx.Arg(2)
		if sh := handles.GetSemaphore(h); sh != nil {
			prev, ok := sh.Release(releaseCount)
			if ok {
				if pPrevious != 0 {
					ctx.Mem.Write32(pPrevious, uint32(prev))
				}
				ctx.SetReturn(1)
			} else {
				ctx.SetReturn(0)
			}
		} else {
			ctx.SetReturn(1) // unknown handle: no-op success
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReleaseSemaphoreWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReleaseSemaphoreWhenCallbackReturns", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RemoveDirectoryA", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryTransactedA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RemoveDirectoryTransactedA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryTransactedW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RemoveDirectoryTransactedW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		if pathPtr == 0 {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 87) // ERROR_INVALID_PARAMETER
			ctx.SetReturn(0)
			return 0
		}
		path := winPathToVFS(readGuestUTF16(pathPtr))
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2) // ERROR_FILE_NOT_FOUND
			} else {
				ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 145) // ERROR_DIR_NOT_EMPTY
			}
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveDllDirectory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RemoveDllDirectory", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveVectoredContinueHandler", func(ctx *ntapi.TrapContext) uint32 {
		ntapi.GlobalVCH.Remove(ctx.Arg(0))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RemoveVectoredExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
		ntapi.GlobalVEH.Remove(ctx.Arg(0))
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ReplaceFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReplaceFile", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReplaceFileA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReplaceFileA", 6, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ReplaceFileW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ReplaceFileW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RequestDeviceWakeup", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RequestDeviceWakeup", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RequestWakeupLatency", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RequestWakeupLatency", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ResetWriteWatch", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ResetWriteWatch", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ResizePseudoConsole", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ResizePseudoConsole", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ResolveLocaleName", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(writeUTF16StringCount(ctx.Arg(1), resolveLocaleNameValue(readGuestUTF16(ctx.Arg(0))), ctx.Arg(2)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RestoreLastError", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RestoreLastError", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ResumeThread", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD ResumeThread(HANDLE hThread);
		// ReactOS: dll/win32/kernel32/client/thread.c → NtResumeThread
		// Returns previous suspend count. We don't track true suspension, so
		// return 1 (was suspended, now resumed) for real handles, 0 for
		// the current-thread pseudo-handle.
		hThread := ctx.Arg(0)
		if hThread == 0xFFFFFFFFFFFFFFFE {
			ctx.SetReturn(0) // current thread was not suspended
			return 0
		}
		th := handles.GetThread(ntapi.Handle(hThread))
		if th == nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0xFFFFFFFF)                                 // (DWORD)-1 on error
			return 0
		}
		ctx.SetReturn(1) // prior suspend count = 1
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlAddFunctionTable", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlAddFunctionTable", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlCaptureStackBackTrace", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlCaptureStackBackTrace", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlCompareMemory", func(ctx *ntapi.TrapContext) uint32 {
		src1 := ctx.Arg(0)
		src2 := ctx.Arg(1)
		length := ctx.Arg(2)
		b1, _ := ctx.Mem.ReadBytes(src1, int(length))
		b2, _ := ctx.Mem.ReadBytes(src2, int(length))
		count := uint64(0)
		for i := uint64(0); i < length && i < uint64(len(b1)) && i < uint64(len(b2)); i++ {
			if b1[i] != b2[i] {
				break
			}
			count++
		}
		ctx.SetReturn(count)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlCopyMemory", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		length := ctx.Arg(2)
		data, _ := ctx.Mem.ReadBytes(src, int(length))
		ctx.Mem.WriteBytes(dst, data)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlDeleteFunctionTable", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlDeleteFunctionTable", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlFillMemory", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		length := ctx.Arg(1)
		fill := byte(ctx.Arg(2))
		buf := make([]byte, length)
		for i := range buf {
			buf[i] = fill
		}
		ctx.Mem.WriteBytes(dst, buf)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlInstallFunctionTableCallback", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlInstallFunctionTableCallback", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlIsEcCode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlIsEcCode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlMoveMemory", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		length := ctx.Arg(2)
		data, _ := ctx.Mem.ReadBytes(src, int(length))
		ctx.Mem.WriteBytes(dst, data)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "RtlRaiseException", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlRaiseException", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlRestoreContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "RtlRestoreContext", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "RtlZeroMemory", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		length := ctx.Arg(1)
		ctx.Mem.WriteBytes(dst, make([]byte, length))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ScrollConsoleScreenBufferA", func(ctx *ntapi.TrapContext) uint32 {
		// ScrollConsoleScreenBufferA(hConsole, lpScrollRect, lpClipRect, dwDestOriginChar, lpFill)
		scrollRect := ctx.Arg(1)
		destCoord := ctx.Arg(3) // COORD packed as DWORD
		fillPtr := ctx.Arg(4)
		if scrollRect != 0 {
			left, _ := ctx.Mem.Read16(scrollRect + 0)
			top, _ := ctx.Mem.Read16(scrollRect + 2)
			right, _ := ctx.Mem.Read16(scrollRect + 4)
			bottom, _ := ctx.Mem.Read16(scrollRect + 6)
			dstX := int(destCoord & 0xFFFF)
			dstY := int((destCoord >> 16) & 0xFFFF)
			dx := dstX - int(left)
			dy := dstY - int(top)
			fillCh := uint16(' ')
			fillAttr := ntapi.GlobalConsole.Attr
			if fillPtr != 0 {
				fillCh, _ = ctx.Mem.Read16(fillPtr)
				fa, _ := ctx.Mem.Read16(fillPtr + 2)
				fillAttr = fa
			}
			ntapi.GlobalConsole.Scroll(int(left), int(top), int(right), int(bottom), dx, dy, fillCh, fillAttr)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "ScrollConsoleScreenBufferW", func(ctx *ntapi.TrapContext) uint32 {
		scrollRect := ctx.Arg(1)
		destCoord := ctx.Arg(3)
		fillPtr := ctx.Arg(4)
		if scrollRect != 0 {
			left, _ := ctx.Mem.Read16(scrollRect + 0)
			top, _ := ctx.Mem.Read16(scrollRect + 2)
			right, _ := ctx.Mem.Read16(scrollRect + 4)
			bottom, _ := ctx.Mem.Read16(scrollRect + 6)
			dstX := int(destCoord & 0xFFFF)
			dstY := int((destCoord >> 16) & 0xFFFF)
			dx := dstX - int(left)
			dy := dstY - int(top)
			fillCh := uint16(' ')
			fillAttr := ntapi.GlobalConsole.Attr
			if fillPtr != 0 {
				fillCh, _ = ctx.Mem.Read16(fillPtr)
				fa, _ := ctx.Mem.Read16(fillPtr + 2)
				fillAttr = fa
			}
			ntapi.GlobalConsole.Scroll(int(left), int(top), int(right), int(bottom), dx, dy, fillCh, fillAttr)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SearchPathA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SearchPathA", 6, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SearchPathW", func(ctx *ntapi.TrapContext) uint32 {
		// SearchPathW(lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, lpFilePart)
		lpPath := ctx.Arg(0)
		lpFileName := ctx.Arg(1)
		lpExtension := ctx.Arg(2)
		nBufLen := ctx.Arg(3)
		lpBuffer := ctx.Arg(4)
		lpFilePart := ctx.Arg(5)
		fileName := readGuestUTF16(lpFileName)
		if fileName == "" {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 87) // ERROR_INVALID_PARAMETER
			ctx.SetReturn(0)
			return 0
		}
		ext := ""
		if lpExtension != 0 {
			ext = readGuestUTF16(lpExtension)
		}
		// Append extension if the filename has no extension and one was supplied.
		if ext != "" && !strings.Contains(filepath.Base(fileName), ".") {
			fileName += ext
		}
		// Build list of directories to search.
		var dirs []string
		if lpPath != 0 {
			searchDir := readGuestUTF16(lpPath)
			if searchDir != "" {
				dirs = append(dirs, winPathToVFS(searchDir))
			}
		}
		if len(dirs) == 0 {
			// Per ReactOS: search exe dir, current dir, system, windows, then PATH.
			lastBS := strings.LastIndex(imagePath, `\`)
			if lastBS >= 0 {
				dirs = append(dirs, winPathToVFS(imagePath[:lastBS]))
			}
			dirs = append(dirs, winPathToVFS("."))
		}
		var found string
		vfsName := winPathToVFS(fileName)
		// If the filename is already an absolute path, check it directly.
		if strings.ContainsAny(fileName, `/\`) && (len(fileName) >= 2 && fileName[1] == ':' || fileName[0] == '\\' || fileName[0] == '/') {
			if _, err := os.Stat(vfsName); err == nil {
				found = vfsName
			}
		}
		if found == "" {
			baseName := filepath.Base(vfsName)
			for _, dir := range dirs {
				candidate := filepath.Join(dir, baseName)
				if _, err := os.Stat(candidate); err == nil {
					found = candidate
					break
				}
			}
		}
		if found == "" {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 2) // ERROR_FILE_NOT_FOUND
			ctx.SetReturn(0)
			return 0
		}
		// Convert host path back to a Windows-style path for the guest.
		winResult := strings.ReplaceAll(found, "/", `\`)
		if !strings.HasPrefix(winResult, `\`) {
			winResult = `\` + winResult
		}
		winResult = `C:` + winResult
		ws := utf16Encode(winResult)
		needed := uint64(len(ws)) + 1 // include null terminator
		if lpBuffer == 0 || nBufLen < needed {
			ctx.SetReturn(needed)
			return 0
		}
		for i, w := range ws {
			ctx.Mem.Write16(lpBuffer+uint64(i*2), w)
		}
		ctx.Mem.Write16(lpBuffer+uint64(len(ws))*2, 0) // null-terminate
		// Set lpFilePart to point at the filename component.
		if lpFilePart != 0 {
			base := filepath.Base(winResult)
			baseWs := utf16Encode(base)
			offset := uint64(len(ws)-len(baseWs)) * 2
			ctx.Mem.Write64(lpFilePart, lpBuffer+offset)
		}
		ctx.SetReturn(uint64(len(ws))) // return length without null
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetCPGlobal", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCPGlobal", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCachedSigningLevel", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCachedSigningLevel", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCalendarInfoA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCalendarInfoA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCalendarInfoW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCalendarInfoW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCommBreak", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCommBreak", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCommConfig", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCommConfig", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCommMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCommMask", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCommState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCommState", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCommTimeouts", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCommTimeouts", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetComputerNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetComputerNameA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetComputerNameExA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetComputerNameExA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetComputerNameExW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetComputerNameExW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetComputerNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetComputerNameW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleActiveScreenBuffer", func(ctx *ntapi.TrapContext) uint32 {
		handle := ntapi.Handle(ctx.Arg(0))
		sb, ok := handles.Get(handle).(*ntapi.ConsoleScreenBufferHandle)
		if !ok || sb == nil || sb.State == nil {
			ctx.SetReturn(0)
			return 0
		}
		consoleStateMu.Lock()
		activeConsoleState = sb.State
		if mode, ok := consoleOutputModes[uint64(handle)]; ok {
			consoleOutputModes[stdOutputHandleValue] = mode
		}
		consoleStateMu.Unlock()
		refreshVisibleConsole(sb.State)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleCP", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCommandHistoryMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleCommandHistoryMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCursor", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleCursor", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorInfo", func(ctx *ntapi.TrapContext) uint32 {
		pInfo := ctx.Arg(1)
		if pInfo != 0 {
			sz, _ := ctx.Mem.Read32(pInfo + 0)
			vis, _ := ctx.Mem.Read32(pInfo + 4)
			ntapi.GlobalConsole.CursorSize = sz
			ntapi.GlobalConsole.CursorVisible = vis != 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleCursorMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleCursorPosition", func(ctx *ntapi.TrapContext) uint32 {
		// SetConsoleCursorPosition(hConsole, dwCursorPosition)
		// dwCursorPosition is passed as a DWORD: X in low 16 bits, Y in high 16
		cs := resolveConsoleState(ctx.Arg(0))
		coord := ctx.Arg(1)
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		if cs != nil {
			cs.CursorX = clampInt(x, 0, cs.Width-1)
			cs.CursorY = clampInt(y, 0, cs.Height-1)
			if isVisibleConsoleState(cs) {
				_, _ = os.Stdout.WriteString(fmt.Sprintf("\x1b[%d;%dH", cs.CursorY+1, cs.CursorX+1))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleDisplayMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleDisplayMode", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleFont", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleFont", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleHardwareState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleHardwareState", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleIcon", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleIcon", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleInputExeNameA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleInputExeNameA", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleInputExeNameW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleInputExeNameW", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleKeyShortcuts", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleKeyShortcuts", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleLocalEUDC", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleLocalEUDC", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleMaximumWindowSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleMaximumWindowSize", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleMenuClose", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleMenuClose", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleNlsMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleNlsMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleNumberOfCommandsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleNumberOfCommandsA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleNumberOfCommandsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleNumberOfCommandsW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleOS2OemFormat", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleOS2OemFormat", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleOutputCP", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleOutputCP", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsolePalette", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsolePalette", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleScreenBufferInfoEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleScreenBufferInfoEx", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleScreenBufferSize", func(ctx *ntapi.TrapContext) uint32 {
		cs := resolveConsoleState(ctx.Arg(0))
		coord := ctx.Arg(1)
		w := int(coord & 0xFFFF)
		h := int((coord >> 16) & 0xFFFF)
		resizeConsoleState(cs, w, h)
		refreshVisibleConsole(cs)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleTitleA", func(ctx *ntapi.TrapContext) uint32 {
		if p := ctx.Arg(0); p != 0 {
			consoleTitle = readGuestString(p)
			ntapi.GlobalConsole.Title = consoleTitle
			if activeConsoleState != nil {
				activeConsoleState.Title = consoleTitle
			}
			emitConsoleTitle(consoleTitle)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleTitleW", func(ctx *ntapi.TrapContext) uint32 {
		if p := ctx.Arg(0); p != 0 {
			consoleTitle = readGuestUTF16(p)
			ntapi.GlobalConsole.Title = consoleTitle
			if activeConsoleState != nil {
				activeConsoleState.Title = consoleTitle
			}
			emitConsoleTitle(consoleTitle)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetConsoleWindowInfo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetConsoleWindowInfo", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCriticalSectionSpinCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCriticalSectionSpinCount", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCurrentConsoleFontEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetCurrentConsoleFontEx", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetCurrentDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		pathPtr := ctx.Arg(0)
		dir := winPathToVFS(readGuestString(pathPtr))
		if err := os.Chdir(dir); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetDaylightFlag", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDaylightFlag", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetDefaultCommConfigA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDefaultCommConfigA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetDefaultCommConfigW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDefaultCommConfigW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetDefaultDllDirectories", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDefaultDllDirectories", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetDllDirectoryA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDllDirectoryA", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetDllDirectoryW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetDllDirectoryW", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetEndOfFile", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		obj := handles.Get(hFile)
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		pos, err := ctx.FS.Lseek(fh.FD, 0, io.SeekCurrent)
		if err != nil {
			ctx.SetReturn(0)
			return 0
		}
		if err := ctx.FS.Ftruncate(fh.FD, pos); err != nil {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetEnvironmentStringsA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetEnvironmentStringsA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetEnvironmentStringsW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetEnvironmentStringsW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
		name := readGuestString(ctx.Arg(0))
		valPtr := ctx.Arg(1)
		if valPtr == 0 {
			delete(envVars, name)
		} else {
			envVars[name] = readGuestString(valPtr)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetErrorMode", func(ctx *ntapi.TrapContext) uint32 {
		uMode := uint32(ctx.Arg(0))
		errorModeMu.Lock()
		prev := processErrorMode
		processErrorMode = uMode
		errorModeMu.Unlock()
		ctx.SetReturn(uint64(prev))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetEventWhenCallbackReturns", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetEventWhenCallbackReturns", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileApisToANSI", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileApisToANSI", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileApisToOEM", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileApisToOEM", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileAttributesA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileAttributesA", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileCompletionNotificationModes", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileCompletionNotificationModes", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileInformationByHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileInformationByHandle", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFilePointer", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		lDistLow := int32(ctx.Arg(1))
		lpDistHigh := ctx.Arg(2)
		dwMoveMethod := ctx.Arg(3)
		obj := handles.Get(hFile)
		fh, ok := obj.(*ntapi.FileHandle)
		if !ok {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		var dist int64 = int64(lDistLow)
		if lpDistHigh != 0 {
			hi, _ := ctx.Mem.Read32(lpDistHigh)
			dist = int64(hi)<<32 | int64(uint32(lDistLow))
		}
		var whence int
		switch dwMoveMethod {
		case 0:
			whence = io.SeekStart
		case 1:
			whence = io.SeekCurrent
		case 2:
			whence = io.SeekEnd
		default:
			whence = io.SeekStart
		}
		newPos, err := ctx.FS.Lseek(fh.FD, dist, whence)
		if err != nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		if lpDistHigh != 0 {
			ctx.Mem.Write32(lpDistHigh, uint32(newPos>>32))
		}
		ctx.SetReturn(uint64(uint32(newPos)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileTime", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFileValidData", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFileValidData", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFirmwareEnvironmentVariableA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFirmwareEnvironmentVariableA", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetFirmwareEnvironmentVariableW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetFirmwareEnvironmentVariableW", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetHandleContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetHandleContext", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetHandleCount", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetHandleCount", 1, uint64(ctx.Arg(0)))
	})
	d.RegisterAutoStubHandler(kernel32, "SetHandleInformation", func(ctx *ntapi.TrapContext) uint32 {
		// SetHandleInformation(hObject, dwMask, dwFlags)
		hObject := ntapi.Handle(ctx.Arg(0))
		dwMask := uint32(ctx.Arg(1))
		dwFlags := uint32(ctx.Arg(2))
		handleFlagsMu.Lock()
		prev := handleFlagsMap[hObject]
		handleFlagsMap[hObject] = (prev &^ dwMask) | (dwFlags & dwMask)
		handleFlagsMu.Unlock()
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetInformationJobObject", func(ctx *ntapi.TrapContext) uint32 {
		// SetInformationJobObject(hJob, JobObjectInfoClass, lpJobObjectInfo, cbJobObjectInfoLength)
		hJob := ntapi.Handle(ctx.Arg(0))
		class := uint32(ctx.Arg(1))
		buf := ctx.Arg(2)
		j := handles.GetJob(hJob)
		if j == nil || buf == 0 {
			ctx.SetReturn(1)
			return 0
		}
		switch class {
		case 2: // JobObjectBasicLimitInformation
			limitFlags, _ := ctx.Mem.Read32(buf + 32)
			if limitFlags&0x8 != 0 { // JOB_OBJECT_LIMIT_ACTIVE_PROCESS
				v, _ := ctx.Mem.Read32(buf + 44)
				j.Limits.ActiveProcessLimit = v
			}
			if limitFlags&0x20 != 0 { // JOB_OBJECT_LIMIT_PRIORITY_CLASS
				v, _ := ctx.Mem.Read32(buf + 48)
				j.Limits.PriorityClass = v
			}
			if limitFlags&0x200 != 0 { // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
				j.Limits.KillOnJobClose = true
			}
		case 9: // JobObjectExtendedLimitInformation
			limitFlags, _ := ctx.Mem.Read32(buf + 32)
			if limitFlags&0x8 != 0 {
				v, _ := ctx.Mem.Read32(buf + 52)
				j.Limits.ActiveProcessLimit = v
			}
			wsMin, _ := ctx.Mem.Read64(buf + 56)
			wsMax, _ := ctx.Mem.Read64(buf + 64)
			j.Limits.MinWorkingSetSize = wsMin
			j.Limits.MaxWorkingSetSize = wsMax
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetLastConsoleEventActive", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetLastConsoleEventActive", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetLocalTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetLocalTime", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetLocaleInfoA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetLocaleInfoA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetLocaleInfoW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetLocaleInfoW", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetMailslotInfo", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		readTimeout := uint32(ctx.Arg(1))
		if m := handles.GetMailslot(h); m != nil {
			m.ReadTimeout = readTimeout
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetMessageWaitingIndicator", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetMessageWaitingIndicator", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetNamedPipeHandleState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetNamedPipeHandleState", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetPriorityClass", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetPriorityClass", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessAffinityMask", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessAffinityUpdateMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessAffinityUpdateMode", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessDEPPolicy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessDEPPolicy", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessDefaultCpuSets", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessDefaultCpuSets", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessInformation", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessMitigationPolicy", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessMitigationPolicy", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessPreferredUILanguages", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessPriorityBoost", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessShutdownParameters", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessShutdownParameters", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessWorkingSetSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessWorkingSetSize", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetProcessWorkingSetSizeEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetProcessWorkingSetSizeEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetSearchPathMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetSearchPathMode", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetStdHandleEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetStdHandleEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetSystemFileCacheSize", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetSystemFileCacheSize", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetSystemPowerState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetSystemPowerState", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetSystemTime", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetSystemTimeAdjustment", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetSystemTimeAdjustment", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetTapeParameters", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetTapeParameters", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetTapePosition", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetTapePosition", 6, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetTermsrvAppInstallMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetTermsrvAppInstallMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadAffinityMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadAffinityMask", 2, uint64(ctx.Arg(1)))
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetThreadContext(HANDLE hThread, const CONTEXT *lpContext);
		// ReactOS: dll/win32/kernel32/client/except.c → NtSetContextThread
		// For the current-thread pseudo-handle, apply integer registers from
		// the CONTEXT structure. For other threads we accept but don't apply
		// (their CPU runs on another goroutine).
		hThread := ctx.Arg(0)
		lpContext := ctx.Arg(1)
		if lpContext == 0 {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		isCurrent := hThread == 0xFFFFFFFFFFFFFFFE
		if !isCurrent {
			th := handles.GetThread(ntapi.Handle(hThread))
			if th != nil {
				tid, _ := ctx.Mem.Read32(procState.TEBAddr + ntapi.TebThreadId)
				if th.TID == int(tid) {
					isCurrent = true
				}
			}
		}
		if isCurrent {
			flags, _ := ctx.Mem.Read32(lpContext + 0x30)
			if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok && flags&0x02 != 0 {
				// CONTEXT_INTEGER - restore GPRs
				rax, _ := ctx.Mem.Read64(lpContext + 0x78)
				rw.WriteReg(0, rax)
				rcx, _ := ctx.Mem.Read64(lpContext + 0x80)
				rw.WriteReg(1, rcx)
				rdx, _ := ctx.Mem.Read64(lpContext + 0x88)
				rw.WriteReg(2, rdx)
				rbx, _ := ctx.Mem.Read64(lpContext + 0x90)
				rw.WriteReg(3, rbx)
				rbp, _ := ctx.Mem.Read64(lpContext + 0xA0)
				rw.WriteReg(5, rbp)
				rsi, _ := ctx.Mem.Read64(lpContext + 0xA8)
				rw.WriteReg(6, rsi)
				rdi, _ := ctx.Mem.Read64(lpContext + 0xB0)
				rw.WriteReg(7, rdi)
				r8, _ := ctx.Mem.Read64(lpContext + 0xB8)
				rw.WriteReg(8, r8)
				r9, _ := ctx.Mem.Read64(lpContext + 0xC0)
				rw.WriteReg(9, r9)
				r10, _ := ctx.Mem.Read64(lpContext + 0xC8)
				rw.WriteReg(10, r10)
				r11, _ := ctx.Mem.Read64(lpContext + 0xD0)
				rw.WriteReg(11, r11)
				r12, _ := ctx.Mem.Read64(lpContext + 0xD8)
				rw.WriteReg(12, r12)
				r13, _ := ctx.Mem.Read64(lpContext + 0xE0)
				rw.WriteReg(13, r13)
				r14, _ := ctx.Mem.Read64(lpContext + 0xE8)
				rw.WriteReg(14, r14)
				r15, _ := ctx.Mem.Read64(lpContext + 0xF0)
				rw.WriteReg(15, r15)
			}
			if flags&0x01 != 0 {
				// CONTEXT_CONTROL - restore RIP, RSP
				rip, _ := ctx.Mem.Read64(lpContext + 0xF8)
				if rip != 0 {
					ctx.CPU.SetPC(rip)
				}
				rsp, _ := ctx.Mem.Read64(lpContext + 0x98)
				if rsp != 0 {
					ctx.CPU.SetSP(rsp)
				}
			}
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadDescription", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadDescription", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadErrorMode", func(ctx *ntapi.TrapContext) uint32 {
		// SetThreadErrorMode(dwNewMode, lpOldMode)
		dwNewMode := uint32(ctx.Arg(0))
		lpOldMode := ctx.Arg(1)
		threadErrorModeMu.Lock()
		prev := threadErrorMode
		threadErrorMode = dwNewMode
		threadErrorModeMu.Unlock()
		if lpOldMode != 0 {
			ctx.Mem.Write32(lpOldMode, prev)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadExecutionState", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadExecutionState", 1, uint64(0x80000001))
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadGroupAffinity", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadGroupAffinity", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadIdealProcessor", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadIdealProcessor", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadIdealProcessorEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadIdealProcessorEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadInformation", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadLocale", func(ctx *ntapi.TrapContext) uint32 {
		threadLocaleMu.Lock()
		threadLocale = uint32(ctx.Arg(0))
		threadLocaleMu.Unlock()
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadPreferredUILanguages", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadPreferredUILanguages", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadPriority", func(ctx *ntapi.TrapContext) uint32 {
		// BOOL SetThreadPriority(HANDLE hThread, int nPriority);
		// ReactOS: dll/win32/kernel32/client/thread.c → NtSetInformationThread
		hThread := ctx.Arg(0)
		nPriority := int32(ctx.Arg(1))
		if hThread == 0xFFFFFFFFFFFFFFFE {
			// Current thread pseudo-handle - accept silently
			ctx.SetReturn(1) // TRUE
			return 0
		}
		th := handles.GetThread(ntapi.Handle(hThread))
		if th != nil {
			th.Priority = nPriority
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadPriorityBoost", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadPriorityBoost", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadSelectedCpuSets", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadSelectedCpuSets", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadStackGuarantee", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadStackGuarantee", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadToken", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadToken", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadUILanguage", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadUILanguage", 1, uint64(0x0409))
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadpoolStackInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetThreadpoolStackInformation", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadpoolThreadMaximum", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		max := ctx.Arg(1)
		if tp := handles.GetTpPool(h); tp != nil {
			tp.MaxThreads = int32(max)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadpoolThreadMinimum", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		min := ctx.Arg(1)
		if tp := handles.GetTpPool(h); tp != nil {
			tp.MinThreads = int32(min)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadpoolTimer", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		pftDueTime := ctx.Arg(1) // PFILETIME (pointer, may be NULL)
		msPeriod := ctx.Arg(2)   // DWORD milliseconds
		tt := handles.GetTpTimer(h)
		if tt == nil {
			ctx.SetReturn(0)
			return 0
		}
		tt.Stop()
		if pftDueTime == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lo, _ := ctx.Mem.Read32(pftDueTime)
		hi, _ := ctx.Mem.Read32(pftDueTime + 4)
		dueTime := int64(uint64(hi)<<32 | uint64(lo))
		var delay time.Duration
		if dueTime < 0 {
			delay = time.Duration(-dueTime) * 100
		} else if dueTime == 0 {
			delay = 0
		} else {
			now := time.Now()
			const epochDiff = 11644473600
			ftNow := (now.Unix()+epochDiff)*10000000 + int64(now.Nanosecond()/100)
			rel := dueTime - ftNow
			if rel <= 0 {
				delay = 0
			} else {
				delay = time.Duration(rel) * 100
			}
		}
		period := time.Duration(msPeriod) * time.Millisecond
		cpuSnap := ctx.CPU
		cb := tt.Callback
		ctxVal := tt.Context
		tt.Arm(delay, period, func() {
			done := tpLaunchCallback(cpuSnap, cb, 0, ctxVal, uint64(h))
			if done != nil {
				<-done
			}
		})
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetThreadpoolWait", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		waitHandle := ntapi.Handle(ctx.Arg(1))
		pftTimeout := ctx.Arg(2)
		tw := handles.GetTpWait(h)
		if tw == nil {
			ctx.SetReturn(0)
			return 0
		}
		tw.Stop()
		if waitHandle == 0 {
			ctx.SetReturn(0)
			return 0
		}
		var timeout time.Duration
		infinite := true
		if pftTimeout != 0 {
			lo, _ := ctx.Mem.Read32(pftTimeout)
			hi, _ := ctx.Mem.Read32(pftTimeout + 4)
			ft := int64(uint64(hi)<<32 | uint64(lo))
			if ft < 0 {
				timeout = time.Duration(-ft) * 100
				infinite = false
			} else if ft == 0 {
				timeout = 0
				infinite = false
			} else {
				const epochDiff = 11644473600
				now := time.Now()
				ftNow := (now.Unix()+epochDiff)*10000000 + int64(now.Nanosecond()/100)
				rel := ft - ftNow
				if rel <= 0 {
					timeout = 0
				} else {
					timeout = time.Duration(rel) * 100
				}
				infinite = false
			}
		}
		stopCh := tw.ArmStopCh(waitHandle)
		cpuSnap := ctx.CPU
		cb := tw.Callback
		ctxVal := tw.Context
		markDone := tw.TrackCallback()
		go func() {
			defer markDone()
			const WAIT_OBJECT_0 = 0
			const WAIT_TIMEOUT = 0x102
			var waitResult uint64 = WAIT_TIMEOUT
			if eh := handles.GetEvent(waitHandle); eh != nil {
				if infinite {
					select {
					case <-stopCh:
						return
					case <-eh.WaitChan():
						waitResult = WAIT_OBJECT_0
					}
				} else if timeout == 0 {
					if eh.IsSignaled() {
						waitResult = WAIT_OBJECT_0
					}
				} else {
					select {
					case <-stopCh:
						return
					case <-eh.WaitChan():
						waitResult = WAIT_OBJECT_0
					case <-time.After(timeout):
						waitResult = WAIT_TIMEOUT
					}
				}
			} else if mh := handles.GetMutant(waitHandle); mh != nil {
				if mh.WaitTimeout(0, timeout) == 0 {
					waitResult = WAIT_OBJECT_0
				}
			} else if sh := handles.GetSemaphore(waitHandle); sh != nil {
				if sh.WaitTimeout(timeout) == 0 {
					waitResult = WAIT_OBJECT_0
				}
			} else {
				if !infinite && timeout > 0 {
					select {
					case <-stopCh:
						return
					case <-time.After(timeout):
					}
				}
			}
			if tw.IsClosed() {
				return
			}
			// WaitCallback(Instance=0, Context, PTP_WAIT=handle, WaitResult)
			done := tpLaunchCallback(cpuSnap, cb, 0, ctxVal, uint64(h), waitResult)
			if done != nil {
				<-done
			}
		}()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetTimeZoneInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetTimeZoneInformation", 1, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetTimerQueueTimer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetTimerQueueTimer", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetUmsThreadInformation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetUmsThreadInformation", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetUserGeoID", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetUserGeoID", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetUserGeoName", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetUserGeoName", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetVDMCurrentDirectories", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetVDMCurrentDirectories", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetVolumeLabelA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetVolumeLabelA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetVolumeLabelW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetVolumeLabelW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetVolumeMountPointA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetVolumeMountPointA", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetVolumeMountPointW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetVolumeMountPointW", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "SetWaitableTimer", func(ctx *ntapi.TrapContext) uint32 {
		// SetWaitableTimer(hTimer, lpDueTime, lPeriod, pfnCompletionRoutine, lpArgToCompletionRoutine, fResume)
		h := ntapi.Handle(ctx.Arg(0))
		duePtr := ctx.Arg(1)
		periodMs := int32(ctx.Arg(2))
		wt, ok := handles.Get(h).(*ntapi.WaitableTimerHandle)
		if !ok || wt == nil {
			ctx.SetReturn(0) // FALSE
			return 0
		}
		var due time.Duration
		if duePtr != 0 {
			val, _ := ctx.Mem.Read64(duePtr)
			if int64(val) < 0 {
				due = time.Duration(-int64(val)) * 100 * time.Nanosecond
			} else if val == 0 {
				due = 0
			} else {
				nowFT := uint64(time.Now().UnixNano()/100 + 116444736000000000)
				if val > nowFT {
					due = time.Duration(val-nowFT) * 100 * time.Nanosecond
				}
			}
		}
		period := time.Duration(0)
		if periodMs > 0 {
			period = time.Duration(periodMs) * time.Millisecond
		}
		wt.Set(due, period)
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetWaitableTimerEx", func(ctx *ntapi.TrapContext) uint32 {
		// Same as SetWaitableTimer but with extra args (tolerable delay, etc.)
		h := ntapi.Handle(ctx.Arg(0))
		duePtr := ctx.Arg(1)
		periodMs := int32(ctx.Arg(2))
		wt, ok := handles.Get(h).(*ntapi.WaitableTimerHandle)
		if !ok || wt == nil {
			ctx.SetReturn(0)
			return 0
		}
		var due time.Duration
		if duePtr != 0 {
			val, _ := ctx.Mem.Read64(duePtr)
			if int64(val) < 0 {
				due = time.Duration(-int64(val)) * 100 * time.Nanosecond
			} else if val == 0 {
				due = 0
			} else {
				nowFT := uint64(time.Now().UnixNano()/100 + 116444736000000000)
				if val > nowFT {
					due = time.Duration(val-nowFT) * 100 * time.Nanosecond
				}
			}
		}
		period := time.Duration(0)
		if periodMs > 0 {
			period = time.Duration(periodMs) * time.Millisecond
		}
		wt.Set(due, period)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SetXStateFeaturesMask", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetXStateFeaturesMask", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SetupComm", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SetupComm", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ShowConsoleCursor", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ShowConsoleCursor", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SignalObjectAndWait", func(ctx *ntapi.TrapContext) uint32 {
		// SignalObjectAndWait(hObjectToSignal, hObjectToWaitOn, dwMs, bAlertable)
		sigH := ntapi.Handle(ctx.Arg(0))
		waitH := ntapi.Handle(ctx.Arg(1))
		ms := ctx.Arg(2)
		timeout := msToTimeout(ms)
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		// Signal the first object
		sigObj := handles.Get(sigH)
		switch v := sigObj.(type) {
		case *ntapi.EventHandle:
			v.Set()
		case *ntapi.MutantHandle:
			v.Release(tid)
		case *ntapi.SemaphoreHandle:
			v.Release(1)
		}
		// Wait on the second object
		ctx.SetReturn(waitOneWin32(handles, waitH, tid, timeout))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SleepConditionVariableCS", func(ctx *ntapi.TrapContext) uint32 {
		// SleepConditionVariableCS(CondVar, CriticalSection, dwMilliseconds)
		addr := ctx.Arg(0)
		ms := ctx.Arg(2)
		entry := ntapi.GlobalCondVars.Get(addr)
		if ms == 0xFFFFFFFF { // INFINITE
			entry.Sleep(10 * time.Second) // cap to avoid deadlocks
		} else {
			entry.Sleep(time.Duration(ms) * time.Millisecond)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "StartThreadpoolIo", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "StartThreadpoolIo", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SubmitThreadpoolWork", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		tw := handles.GetTpWork(h)
		if tw == nil {
			ctx.SetReturn(0)
			return 0
		}
		done, ok := tw.Submit()
		if !ok {
			ctx.SetReturn(0)
			return 0
		}
		// WorkCallback(Instance=0, Context, PTP_WORK=handle)
		cpuSnap := ctx.CPU
		cb := tw.Callback
		ctxVal := tw.Context
		go func() {
			defer done()
			ch := tpLaunchCallback(cpuSnap, cb, 0, ctxVal, uint64(h))
			if ch != nil {
				<-ch
			}
		}()
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SuspendThread", func(ctx *ntapi.TrapContext) uint32 {
		// DWORD SuspendThread(HANDLE hThread);
		// ReactOS: dll/win32/kernel32/client/thread.c → NtSuspendThread
		// Returns previous suspend count. We don't truly suspend threads.
		hThread := ctx.Arg(0)
		if hThread == 0xFFFFFFFFFFFFFFFE {
			ctx.SetReturn(0) // current thread, suspend count was 0
			return 0
		}
		th := handles.GetThread(ntapi.Handle(hThread))
		if th == nil {
			mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 6) // ERROR_INVALID_HANDLE
			ctx.SetReturn(0xFFFFFFFF)                                 // (DWORD)-1 on error
			return 0
		}
		ctx.SetReturn(0) // previous suspend count = 0
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SwitchToFiber", func(ctx *ntapi.TrapContext) uint32 {
		// VOID SwitchToFiber(LPVOID lpFiber);
		// ReactOS: dll/win32/kernel32/client/fiber.c
		// True fiber switching requires full coroutine support. For now, log
		// the attempt and no-op (the calling fiber continues).
		lpFiber := ctx.Arg(0)
		ravelog.Logf("[win32] SwitchToFiber(0x%x) → stub no-op\n", lpFiber)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "SwitchToThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "SwitchToThread", 0, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "SystemTimeToFileTime", func(ctx *ntapi.TrapContext) uint32 {
		lpST := ctx.Arg(0)
		lpFT := ctx.Arg(1)
		if lpST == 0 || lpFT == 0 {
			ctx.SetReturn(0)
			return 0
		}
		year, _ := ctx.Mem.Read16(lpST)
		month, _ := ctx.Mem.Read16(lpST + 2)
		day, _ := ctx.Mem.Read16(lpST + 6)
		hour, _ := ctx.Mem.Read16(lpST + 8)
		min, _ := ctx.Mem.Read16(lpST + 10)
		sec, _ := ctx.Mem.Read16(lpST + 12)
		ms, _ := ctx.Mem.Read16(lpST + 14)
		t := time.Date(int(year), time.Month(month), int(day), int(hour), int(min), int(sec), int(ms)*1e6, time.UTC)
		epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
		ft := uint64(t.Sub(epoch).Nanoseconds() / 100)
		ctx.Mem.Write64(lpFT, ft)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TerminateJobObject", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TerminateJobObject", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "TerminateThread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TerminateThread", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "TermsrvAppInstallMode", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TermsrvAppInstallMode", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Thread32First", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Thread32First", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Thread32Next", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Thread32Next", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "TlsAllocInternal", func(ctx *ntapi.TrapContext) uint32 {
		slot := tlsNextSlot
		tlsNextSlot++
		ctx.SetReturn(uint64(slot))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TlsFreeInternal", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TlsFreeInternal", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "Toolhelp32ReadProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Toolhelp32ReadProcessMemory", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "TransactNamedPipe", func(ctx *ntapi.TrapContext) uint32 {
		// TransactNamedPipe(hNamedPipe, lpInBuf, nInBufSize, lpOutBuf, nOutBufSize, lpBytesRead, lpOverlapped)
		hPipe := ntapi.Handle(ctx.Arg(0))
		inBuf := ctx.Arg(1)
		inSz := ctx.Arg(2)
		outBuf := ctx.Arg(3)
		outSz := ctx.Arg(4)
		bytesRead := ctx.Arg(5)
		ph := handles.GetNamedPipe(hPipe)
		if ph == nil {
			ctx.SetReturn(0)
			return 0
		}
		// Write inBuf to pipe
		if inSz > 0 && inBuf != 0 {
			data, _ := ctx.Mem.ReadBytes(inBuf, int(inSz))
			ph.PipeWrite(data)
		}
		// Read response from pipe
		if outBuf != 0 && outSz > 0 {
			buf := make([]byte, outSz)
			n := ph.PipeRead(buf)
			if n > 0 {
				ctx.Mem.WriteBytes(outBuf, buf[:n])
			}
			if bytesRead != 0 {
				ctx.Mem.Write32(bytesRead, uint32(n))
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TransmitCommChar", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TransmitCommChar", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "TrimVirtualBuffer", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TrimVirtualBuffer", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "TryAcquireSRWLockShared", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TryAcquireSRWLockShared", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "TryEnterCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "TryEnterCriticalSection", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "TrySubmitThreadpoolCallback", func(ctx *ntapi.TrapContext) uint32 {
		callback := ctx.Arg(0) // PTP_SIMPLE_CALLBACK
		context := ctx.Arg(1)  // PVOID
		// SimpleCallback(Instance=0, Context)
		cpuSnap := ctx.CPU
		go func() {
			done := tpLaunchCallback(cpuSnap, callback, 0, context)
			if done != nil {
				<-done
			}
		}()
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "TzSpecificLocalTimeToSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(1)
		dst := ctx.Arg(2)
		if src != 0 && dst != 0 {
			for i := uint64(0); i < 16; i++ {
				b, _ := ctx.Mem.Read8(src + i)
				ctx.Mem.Write8(dst+i, b)
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UmsThreadYield", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UmsThreadYield", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "UninitializeCriticalSection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UninitializeCriticalSection", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "UnlockFile", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		fh := handles.GetFile(hFile)
		if fh == nil {
			ctx.SetReturn(1) // best effort
			return 0
		}
		err := unix.Flock(fh.FD, unix.LOCK_UN)
		if err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 158) // ERROR_NOT_LOCKED
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UnlockFileEx", func(ctx *ntapi.TrapContext) uint32 {
		hFile := ntapi.Handle(ctx.Arg(0))
		// arg1 = dwReserved, arg2 = nNumberOfBytesToUnlockLow
		// arg3 = nNumberOfBytesToUnlockHigh, arg4 = lpOverlapped
		lpOverlapped := ctx.Arg(4)
		fh := handles.GetFile(hFile)
		if fh == nil {
			if lpOverlapped != 0 {
				ctx.Mem.Write64(lpOverlapped, 0)
			}
			ctx.SetReturn(1)
			return 0
		}
		err := unix.Flock(fh.FD, unix.LOCK_UN)
		if err != nil {
			ctx.Mem.Write32(procState.TEBAddr+ntapi.TebLastErrorValue, 158) // ERROR_NOT_LOCKED
			ctx.SetReturn(0)
			return 0
		}
		if lpOverlapped != 0 {
			ctx.Mem.Write64(lpOverlapped, 0)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UnmapViewOfFileEx", func(ctx *ntapi.TrapContext) uint32 {
		doUnmapView(ctx, ctx.Arg(0))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "UnregisterWait", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UnregisterWait", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "UnregisterWaitEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UnregisterWaitEx", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "UpdateProcThreadAttribute", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UpdateProcThreadAttribute", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "UpdateResourceA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UpdateResourceA", 6, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "UpdateResourceW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "UpdateResourceW", 6, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "VDMConsoleOperation", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VDMConsoleOperation", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "VDMOperationStarted", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VDMOperationStarted", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "ValidateLCType", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ValidateLCType", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ValidateLocale", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ValidateLocale", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "VerLanguageNameA", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		if buf != 0 {
			ctx.Mem.WriteBytes(buf, []byte("English\x00"))
		}
		ctx.SetReturn(7)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VerLanguageNameW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		if buf != 0 {
			for i, c := range []uint16{'E', 'n', 'g', 'l', 'i', 's', 'h', 0} {
				ctx.Mem.Write16(buf+uint64(i)*2, c)
			}
		}
		ctx.SetReturn(7)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VerifyConsoleIoHandle", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VerifyConsoleIoHandle", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "VerifyVersionInfoA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VerifyVersionInfoA", 3, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualAlloc", func(ctx *ntapi.TrapContext) uint32 {
		lpAddress := ctx.Arg(0)
		dwSize := ctx.Arg(1)
		// flAllocationType := ctx.Arg(2) // MEM_COMMIT=0x1000, MEM_RESERVE=0x2000
		// flProtect := ctx.Arg(3)        // PAGE_READWRITE=0x04, etc.
		if dwSize == 0 {
			dwSize = 0x1000
		}
		dwSize = (dwSize + 0xFFF) &^ 0xFFF // page-align
		perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		addr := mem.Mmap(lpAddress, dwSize, perms)
		if addr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ravelog.Logf("[win32] VirtualAlloc(0x%x, 0x%x) → 0x%x\n", lpAddress, dwSize, addr)
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualAllocEx", func(ctx *ntapi.TrapContext) uint32 {
		// hProcess := ctx.Arg(0) // ignored - always current process
		lpAddress := ctx.Arg(1)
		dwSize := ctx.Arg(2)
		// flAllocationType := ctx.Arg(3)
		flProtect := ctx.Arg(4)
		if dwSize == 0 {
			dwSize = 0x1000
		}
		dwSize = (dwSize + 0xFFF) &^ 0xFFF
		perms := win32ProtToMMU(flProtect)
		if perms == 0 {
			perms = mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		}
		addr := mem.Mmap(lpAddress, dwSize, perms)
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualAllocExNuma", func(ctx *ntapi.TrapContext) uint32 {
		lpAddress := ctx.Arg(1)
		dwSize := ctx.Arg(2)
		if dwSize == 0 {
			dwSize = 0x1000
		}
		dwSize = (dwSize + 0xFFF) &^ 0xFFF
		perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
		addr := mem.Mmap(lpAddress, dwSize, perms)
		ctx.SetReturn(addr)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualBufferExceptionHandler", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VirtualBufferExceptionHandler", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualFree", func(ctx *ntapi.TrapContext) uint32 {
		lpAddress := ctx.Arg(0)
		dwSize := ctx.Arg(1)
		dwFreeType := ctx.Arg(2)
		if dwFreeType&0x8000 != 0 { // MEM_RELEASE
			if lpAddress != 0 {
				_, regionSize, mapped, _ := mem.QueryRegion(lpAddress)
				if mapped && regionSize > 0 {
					mem.Munmap(lpAddress, regionSize)
				}
			}
		} else if dwFreeType&0x4000 != 0 && dwSize > 0 { // MEM_DECOMMIT
			mem.Munmap(lpAddress, dwSize)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualFreeEx", func(ctx *ntapi.TrapContext) uint32 {
		// hProcess := ctx.Arg(0) // ignored - always current process
		lpAddress := ctx.Arg(1)
		dwSize := ctx.Arg(2)
		dwFreeType := ctx.Arg(3)
		if dwFreeType&0x8000 != 0 { // MEM_RELEASE
			if lpAddress != 0 {
				_, regionSize, mapped, _ := mem.QueryRegion(lpAddress)
				if mapped && regionSize > 0 {
					mem.Munmap(lpAddress, regionSize)
				}
			}
		} else if dwFreeType&0x4000 != 0 && dwSize > 0 { // MEM_DECOMMIT
			mem.Munmap(lpAddress, dwSize)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualLock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VirtualLock", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualProtectEx", func(ctx *ntapi.TrapContext) uint32 {
		// hProcess := ctx.Arg(0) // ignored
		lpAddress := ctx.Arg(1)
		dwSize := ctx.Arg(2)
		flNewProtect := ctx.Arg(3)
		lpflOldProtect := ctx.Arg(4)
		_, _, mapped, oldPerms := mem.QueryRegion(lpAddress)
		if lpflOldProtect != 0 {
			if mapped {
				ctx.Mem.Write32(lpflOldProtect, mmuPermToWin32(oldPerms))
			} else {
				ctx.Mem.Write32(lpflOldProtect, 0x01) // PAGE_NOACCESS
			}
		}
		newPerms := win32ProtToMMU(flNewProtect)
		mem.Mprotect(lpAddress, dwSize, newPerms)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualQuery", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		bufPtr := ctx.Arg(1)
		bufLen := ctx.Arg(2)
		if bufPtr == 0 || bufLen < 48 {
			ctx.SetReturn(0)
			return 0
		}
		base, size, mapped, perms := mem.QueryRegion(addr)
		var protect uint32
		if !mapped {
			protect = 0x01 // PAGE_NOACCESS
		} else {
			switch {
			case perms&(mmu.PermRead|mmu.PermWrite|mmu.PermExecute) == mmu.PermRead|mmu.PermWrite|mmu.PermExecute:
				protect = 0x40
			case perms&(mmu.PermRead|mmu.PermExecute) == mmu.PermRead|mmu.PermExecute:
				protect = 0x20
			case perms&(mmu.PermRead|mmu.PermWrite) == mmu.PermRead|mmu.PermWrite:
				protect = 0x04
			default:
				protect = 0x02
			}
		}
		state, typ := uint32(0x1000), uint32(0x20000) // MEM_COMMIT, MEM_PRIVATE
		if !mapped {
			state, typ, protect = 0x10000, 0, 0x01 // MEM_FREE, PAGE_NOACCESS
		}
		ctx.Mem.Write64Raw(bufPtr+0, base)
		ctx.Mem.Write64Raw(bufPtr+8, base)
		ctx.Mem.Write32(bufPtr+16, protect)
		ctx.Mem.Write32(bufPtr+20, 0)
		ctx.Mem.Write64Raw(bufPtr+24, size)
		ctx.Mem.Write32(bufPtr+32, state)
		ctx.Mem.Write32(bufPtr+36, protect)
		ctx.Mem.Write32(bufPtr+40, typ)
		ctx.Mem.Write32(bufPtr+44, 0)
		ctx.SetReturn(48)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualQueryEx", func(ctx *ntapi.TrapContext) uint32 {
		lpBuffer := ctx.Arg(2)
		dwLength := ctx.Arg(3)
		if lpBuffer == 0 || dwLength < 48 {
			ctx.SetReturn(0)
			return 0
		}
		addr := ctx.Arg(1)
		base, size, mapped, perms := mem.QueryRegion(addr)
		var protect uint32
		if !mapped {
			protect = 0x01
		} else {
			switch {
			case perms&(mmu.PermRead|mmu.PermWrite|mmu.PermExecute) == mmu.PermRead|mmu.PermWrite|mmu.PermExecute:
				protect = 0x40
			case perms&(mmu.PermRead|mmu.PermExecute) == mmu.PermRead|mmu.PermExecute:
				protect = 0x20
			case perms&(mmu.PermRead|mmu.PermWrite) == mmu.PermRead|mmu.PermWrite:
				protect = 0x04
			default:
				protect = 0x02
			}
		}
		state, typ := uint32(0x1000), uint32(0x20000)
		if !mapped {
			state, typ, protect = 0x10000, 0, 0x01
		}
		ctx.Mem.Write64(lpBuffer+0, base)
		ctx.Mem.Write64(lpBuffer+8, base)
		ctx.Mem.Write32(lpBuffer+16, protect)
		ctx.Mem.Write32(lpBuffer+20, 0)
		ctx.Mem.Write64(lpBuffer+24, size)
		ctx.Mem.Write32(lpBuffer+32, state)
		ctx.Mem.Write32(lpBuffer+36, protect)
		ctx.Mem.Write32(lpBuffer+40, typ)
		ctx.Mem.Write32(lpBuffer+44, 0)
		ctx.SetReturn(48)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "VirtualUnlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "VirtualUnlock", 2, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WTSGetActiveConsoleSessionId", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WTSGetActiveConsoleSessionId", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WaitCommEvent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WaitCommEvent", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForDebugEvent", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WaitForDebugEvent", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForDebugEventEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WaitForDebugEventEx", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForMultipleObjectsEx", func(ctx *ntapi.TrapContext) uint32 {
		// Delegate to WaitForMultipleObjects logic (ignore alertable flag)
		nCount := ctx.Arg(0)
		pHandles := ctx.Arg(1)
		ms := ctx.Arg(3)
		var timeout time.Duration
		if ms == 0xFFFFFFFF {
			timeout = -1
		} else if ms == 0 {
			timeout = 0
		} else {
			timeout = time.Duration(ms) * time.Millisecond
		}
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		type idxChan2 struct {
			idx int
			ch  <-chan struct{}
		}
		var cases2 []idxChan2
		for i := uint64(0); i < nCount && i < 64; i++ {
			hv, _ := ctx.Mem.Read64(pHandles + i*8)
			h := ntapi.Handle(hv)
			if th := handles.GetThread(h); th != nil && th.Done != nil {
				cases2 = append(cases2, idxChan2{int(i), th.Done})
			} else if eh := handles.GetEvent(h); eh != nil {
				cases2 = append(cases2, idxChan2{int(i), eh.WaitChan()})
			} else if mh := handles.GetMutant(h); mh != nil {
				cases2 = append(cases2, idxChan2{int(i), mh.WaitChan(tid)})
			} else if sh := handles.GetSemaphore(h); sh != nil {
				cases2 = append(cases2, idxChan2{int(i), sh.WaitChan()})
			}
		}
		if len(cases2) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		selCases2 := make([]reflect.SelectCase, 0, len(cases2)+1)
		for _, ic := range cases2 {
			selCases2 = append(selCases2, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ic.ch)})
		}
		if timeout == 0 {
			selCases2 = append(selCases2, reflect.SelectCase{Dir: reflect.SelectDefault})
		} else if timeout > 0 {
			selCases2 = append(selCases2, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(time.After(timeout))})
		}
		chosen2, _, _ := reflect.Select(selCases2)
		if chosen2 >= len(cases2) {
			ctx.SetReturn(0x102)
		} else {
			ctx.SetReturn(uint64(cases2[chosen2].idx))
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForSingleObjectEx", func(ctx *ntapi.TrapContext) uint32 {
		// Delegate to WaitForSingleObject logic (ignore alertable flag)
		h := ntapi.Handle(ctx.Arg(0))
		ms := ctx.Arg(1)
		var timeout time.Duration
		if ms == 0xFFFFFFFF {
			timeout = -1
		} else if ms == 0 {
			timeout = 0
		} else {
			timeout = time.Duration(ms) * time.Millisecond
		}
		var tid uint32 = 1
		if *tmPtr != nil {
			tid = uint32((*tmPtr).GetTID(ctx.CPU))
		}
		if th := handles.GetThread(h); th != nil && th.Done != nil {
			if timeout < 0 {
				<-th.Done
				ctx.SetReturn(0)
			} else if timeout == 0 {
				select {
				case <-th.Done:
					ctx.SetReturn(0)
				default:
					ctx.SetReturn(0x102)
				}
			} else {
				select {
				case <-th.Done:
					ctx.SetReturn(0)
				case <-time.After(timeout):
					ctx.SetReturn(0x102)
				}
			}
			return 0
		}
		if eh := handles.GetEvent(h); eh != nil {
			if eh.WaitTimeout(timeout) {
				ctx.SetReturn(0)
			} else {
				ctx.SetReturn(0x102)
			}
			return 0
		}
		if mh := handles.GetMutant(h); mh != nil {
			ctx.SetReturn(uint64(mh.WaitTimeout(tid, timeout)))
			return 0
		}
		if sh := handles.GetSemaphore(h); sh != nil {
			ctx.SetReturn(uint64(sh.WaitTimeout(timeout)))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolIoCallbacks", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WaitForThreadpoolIoCallbacks", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolTimerCallbacks", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		cancelPending := ctx.Arg(1) // fCancelPendingCallbacks
		if tt := handles.GetTpTimer(h); tt != nil {
			if cancelPending != 0 {
				tt.Stop()
			}
			tt.WaitAll()
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolWaitCallbacks", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		cancelPending := ctx.Arg(1)
		if tw := handles.GetTpWait(h); tw != nil {
			if cancelPending != 0 {
				tw.Stop()
			}
			tw.WaitAll()
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitForThreadpoolWorkCallbacks", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		cancelPending := ctx.Arg(1)
		if tw := handles.GetTpWork(h); tw != nil {
			if cancelPending != 0 {
				tw.Shutdown()
			}
			tw.WaitAll()
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitNamedPipeA", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := normalizePipeName(readGuestString(namePtr))
		if ntapi.LookupNamedPipe(name) != nil {
			ctx.SetReturn(1) // TRUE: pipe exists
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WaitNamedPipeW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := normalizePipeName(readGuestUTF16(namePtr))
		if ntapi.LookupNamedPipe(name) != nil {
			ctx.SetReturn(1) // TRUE: pipe exists
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WakeConditionVariable", func(ctx *ntapi.TrapContext) uint32 {
		ntapi.GlobalCondVars.Get(ctx.Arg(0)).Signal()
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WerGetFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerGetFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerRegisterCustomMetadata", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerRegisterCustomMetadata", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerRegisterFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerRegisterFile", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerRegisterMemoryBlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerRegisterMemoryBlock", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerRegisterRuntimeExceptionModule", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerRegisterRuntimeExceptionModule", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerSetFlags", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerSetFlags", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerUnregisterCustomMetadata", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerUnregisterCustomMetadata", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerUnregisterFile", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerUnregisterFile", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerUnregisterMemoryBlock", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerUnregisterMemoryBlock", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WerUnregisterRuntimeExceptionModule", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WerUnregisterRuntimeExceptionModule", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WinExec", func(ctx *ntapi.TrapContext) uint32 {
		cmd := readGuestString(ctx.Arg(0))
		ravelog.Logf("[win32] WinExec: %s\n", cmd)
		ctx.SetReturn(32) // > 31 = success
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64DisableWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64DisableWow64FsRedirection", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64EnableWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64EnableWow64FsRedirection", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64GetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64GetThreadContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64GetThreadSelectorEntry", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64GetThreadSelectorEntry", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64RevertWow64FsRedirection", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64RevertWow64FsRedirection", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "Wow64SetThreadContext", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "Wow64SetThreadContext", 4, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleA", func(ctx *ntapi.TrapContext) uint32 {
		handle := ctx.Arg(0)
		buf := ctx.Arg(1)
		nChars := ctx.Arg(2)
		lpWritten := ctx.Arg(3)
		if buf != 0 && nChars > 0 {
			data := make([]byte, nChars)
			for i := uint64(0); i < nChars; i++ {
				b, _ := ctx.Mem.Read8(buf + i)
				data[i] = b
			}
			writeConsoleString(handle, string(data), data)
		}
		if lpWritten != 0 {
			ctx.Mem.Write32(lpWritten, uint32(nChars))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteConsoleInputA", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputVDMA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteConsoleInputVDMA", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputVDMW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteConsoleInputVDMW", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleInputW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteConsoleInputW", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputA", func(ctx *ntapi.TrapContext) uint32 {
		// WriteConsoleOutputA(hConsole, lpBuffer, dwBufferSize, dwBufferCoord, lpWriteRegion)
		// lpBuffer is array of CHAR_INFO: {Char.AsciiChar/UnicodeChar (2 bytes), Attributes (2 bytes)}
		buf := ctx.Arg(1)
		bufW := int(ctx.Arg(2) & 0xFFFF)
		bufH := int((ctx.Arg(2) >> 16) & 0xFFFF)
		// bufCoord: top-left of buffer to start reading from
		bufCoordX := int(ctx.Arg(3) & 0xFFFF)
		bufCoordY := int((ctx.Arg(3) >> 16) & 0xFFFF)
		writeRgn := ctx.Arg(4)
		if buf == 0 || writeRgn == 0 {
			ctx.SetReturn(1)
			return 0
		}
		left, _ := ctx.Mem.Read16(writeRgn + 0)
		top, _ := ctx.Mem.Read16(writeRgn + 2)
		right, _ := ctx.Mem.Read16(writeRgn + 4)
		bottom, _ := ctx.Mem.Read16(writeRgn + 6)
		for y := int(top); y <= int(bottom); y++ {
			for x := int(left); x <= int(right); x++ {
				bx := x - int(left) + bufCoordX
				by := y - int(top) + bufCoordY
				if bx < 0 || bx >= bufW || by < 0 || by >= bufH {
					continue
				}
				idx := uint64(by*bufW+bx) * 4
				ch, _ := ctx.Mem.Read8(buf + idx)
				attr, _ := ctx.Mem.Read16(buf + idx + 2)
				if c := ntapi.GlobalConsole.Cell(x, y); c != nil {
					c.Char = uint16(ch)
					c.Attr = attr
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputAttribute", func(ctx *ntapi.TrapContext) uint32 {
		// WriteConsoleOutputAttribute(hConsole, lpAttr, nLength, dwWriteCoord, lpNumWritten)
		lpAttr := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numWritten := ctx.Arg(4)
		if lpAttr == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		wrote := 0
		for i := 0; i < n; i++ {
			attr, _ := ctx.Mem.Read16(lpAttr + uint64(i)*2)
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				c.Attr = attr
				wrote++
			}
		}
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputCharacterA", func(ctx *ntapi.TrapContext) uint32 {
		// WriteConsoleOutputCharacterA(hConsole, lpCharacter, nLength, dwWriteCoord, lpNumWritten)
		lpChar := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numWritten := ctx.Arg(4)
		if lpChar == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		wrote := 0
		for i := 0; i < n; i++ {
			ch, _ := ctx.Mem.Read8(lpChar + uint64(i))
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				c.Char = uint16(ch)
				wrote++
			}
		}
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputCharacterW", func(ctx *ntapi.TrapContext) uint32 {
		lpChar := ctx.Arg(1)
		n := int(ctx.Arg(2))
		coord := ctx.Arg(3)
		numWritten := ctx.Arg(4)
		if lpChar == 0 {
			ctx.SetReturn(1)
			return 0
		}
		x := int(coord & 0xFFFF)
		y := int((coord >> 16) & 0xFFFF)
		wrote := 0
		for i := 0; i < n; i++ {
			ch, _ := ctx.Mem.Read16(lpChar + uint64(i)*2)
			cx := (x + i) % ntapi.GlobalConsole.Width
			cy := y + (x+i)/ntapi.GlobalConsole.Width
			if c := ntapi.GlobalConsole.Cell(cx, cy); c != nil {
				c.Char = ch
				wrote++
			}
		}
		if numWritten != 0 {
			ctx.Mem.Write32(numWritten, uint32(wrote))
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteConsoleOutputW", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(1)
		bufW := int(ctx.Arg(2) & 0xFFFF)
		bufH := int((ctx.Arg(2) >> 16) & 0xFFFF)
		bufCoordX := int(ctx.Arg(3) & 0xFFFF)
		bufCoordY := int((ctx.Arg(3) >> 16) & 0xFFFF)
		writeRgn := ctx.Arg(4)
		if buf == 0 || writeRgn == 0 {
			ctx.SetReturn(1)
			return 0
		}
		left, _ := ctx.Mem.Read16(writeRgn + 0)
		top, _ := ctx.Mem.Read16(writeRgn + 2)
		right, _ := ctx.Mem.Read16(writeRgn + 4)
		bottom, _ := ctx.Mem.Read16(writeRgn + 6)
		for y := int(top); y <= int(bottom); y++ {
			for x := int(left); x <= int(right); x++ {
				bx := x - int(left) + bufCoordX
				by := y - int(top) + bufCoordY
				if bx < 0 || bx >= bufW || by < 0 || by >= bufH {
					continue
				}
				idx := uint64(by*bufW+bx) * 4
				ch, _ := ctx.Mem.Read16(buf + idx)
				attr, _ := ctx.Mem.Read16(buf + idx + 2)
				if c := ntapi.GlobalConsole.Cell(x, y); c != nil {
					c.Char = ch
					c.Attr = attr
				}
			}
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteFileEx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteFileEx", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteFileGather", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteFileGather", 8, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WritePrivateProfileSectionA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WritePrivateProfileSectionW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestString(ctx.Arg(0))
		key := readGuestString(ctx.Arg(1))
		value := readGuestString(ctx.Arg(2))
		filePath := readGuestString(ctx.Arg(3))
		iniWrite(winPathToVFS(filePath), section, key, value)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
		section := readGuestUTF16(ctx.Arg(0))
		key := readGuestUTF16(ctx.Arg(1))
		value := readGuestUTF16(ctx.Arg(2))
		filePath := readGuestUTF16(ctx.Arg(3))
		iniWrite(winPathToVFS(filePath), section, key, value)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStructA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WritePrivateProfileStructA", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WritePrivateProfileStructW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WritePrivateProfileStructW", 5, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteProcessMemory", func(ctx *ntapi.TrapContext) uint32 {
		nSize := ctx.Arg(3)
		if nSize > 0 {
			data, _ := ctx.Mem.ReadBytes(ctx.Arg(2), int(nSize))
			ctx.Mem.WriteBytes(ctx.Arg(1), data)
		}
		if bw := ctx.Arg(4); bw != 0 {
			ctx.Mem.Write64(bw, nSize)
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "WriteProfileSectionA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteProfileSectionA", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteProfileSectionW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteProfileSectionW", 2, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteProfileStringA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteProfileStringA", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteProfileStringW", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteProfileStringW", 3, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "WriteTapemark", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "WriteTapemark", 4, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "ZombifyActCtx", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "ZombifyActCtx", 1, 1)
	})
	d.RegisterAutoStubHandler(kernel32, "_DebugOut", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_DebugOut", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "_DebugPrintf", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_DebugPrintf", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
		exceptionRecord := ctx.Arg(0)
		dispatcherContext, err := ntapi.ReadDispatcherContext(ctx.Mem, ctx.Arg(3))
		if err != nil || dispatcherContext == nil || dispatcherContext.HandlerData == 0 {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		controlRVA := uint32(0)
		if dispatcherContext.ControlPc >= dispatcherContext.ImageBase {
			controlRVA = uint32(dispatcherContext.ControlPc - dispatcherContext.ImageBase)
		}
		scopeCount, _ := ctx.Mem.Read32(dispatcherContext.HandlerData)
		for i := uint32(0); i < scopeCount; i++ {
			recordAddr := dispatcherContext.HandlerData + 4 + uint64(i)*16
			beginRVA, _ := ctx.Mem.Read32(recordAddr)
			endRVA, _ := ctx.Mem.Read32(recordAddr + 4)
			handlerRVA, _ := ctx.Mem.Read32(recordAddr + 8)
			jumpTarget, _ := ctx.Mem.Read32(recordAddr + 12)
			if controlRVA < beginRVA || controlRVA >= endRVA || jumpTarget == 0 {
				continue
			}
			filterResult := uint32(ntapi.ExceptionContinueSearch)
			switch handlerRVA {
			case 0:
				filterResult = ntapi.ExceptionContinueSearch
			case 1:
				filterResult = ntapi.ExceptionExecuteHandler
			default:
				exceptionPointersAddr := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
				mem.Write64(exceptionPointersAddr+0, exceptionRecord)
				mem.Write64(exceptionPointersAddr+8, dispatcherContext.ContextRecord)
				ret, err := callGuest(ctx, dispatcherContext.ImageBase+uint64(handlerRVA), []uint64{exceptionPointersAddr})
				if err == nil {
					filterResult = uint32(ret)
				}
			}
			if filterResult == ntapi.ExceptionContinueExecution {
				ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
				return 0
			}
			if filterResult != ntapi.ExceptionExecuteHandler {
				continue
			}
			contextRecord, err := ntapi.ReadAMD64Context(ctx.Mem, dispatcherContext.ContextRecord)
			if err != nil {
				break
			}
			dispatcherContext.TargetIp = dispatcherContext.ImageBase + uint64(jumpTarget)
			_ = ntapi.WriteDispatcherContext(ctx.Mem, ctx.Arg(3), dispatcherContext)
			contextRecord.Rip = dispatcherContext.TargetIp
			contextRecord.Regs[4] = dispatcherContext.EstablisherFrame
			_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
			return 0
		}
		ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "__chkstk", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "__chkstk", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "_hread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_hread", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "_hwrite", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_hwrite", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "_lclose", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_lclose", 1, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "_lcreat", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_lcreat", 2, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "_llseek", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_llseek", 3, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "_local_unwind", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_local_unwind", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "_lopen", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_lopen", 2, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "_lread", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_lread", 3, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "_lwrite", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "_lwrite", 3, uint64(0xFFFF))
	})
	d.RegisterAutoStubHandler(kernel32, "dprintf", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "dprintf", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcat", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		s1 := readGuestString(dst)
		s2 := readGuestString(src)
		combined := s1 + s2
		ctx.Mem.WriteBytes(dst+uint64(len(s1)), append([]byte(s2), 0))
		ctx.SetReturn(uint64(len(combined)))
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcatA", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		s1 := readGuestString(dst)
		s2 := readGuestString(src)
		ctx.Mem.WriteBytes(dst+uint64(len(s1)), append([]byte(s2), 0))
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcatW", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		// Find end of dst (null terminator)
		dstEnd := dst
		for i := uint64(0); i < 65536; i++ {
			w, _ := ctx.Mem.Read16(dstEnd)
			if w == 0 {
				break
			}
			dstEnd += 2
		}
		// Copy src wide chars to end of dst
		for i := uint64(0); i < 65536; i++ {
			w, _ := ctx.Mem.Read16(src + i*2)
			ctx.Mem.Write16(dstEnd+i*2, w)
			if w == 0 {
				break
			}
		}
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmp", func(ctx *ntapi.TrapContext) uint32 {
		s1 := readGuestString(ctx.Arg(0))
		s2 := readGuestString(ctx.Arg(1))
		if s1 < s2 {
			ctx.SetReturn(0xFFFFFFFF)
		} else if s1 > s2 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmpA", func(ctx *ntapi.TrapContext) uint32 {
		s1 := readGuestString(ctx.Arg(0))
		s2 := readGuestString(ctx.Arg(1))
		if s1 < s2 {
			ctx.SetReturn(0xFFFFFFFF)
		} else if s1 > s2 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcmpi", func(ctx *ntapi.TrapContext) uint32 {
		s1 := strings.ToLower(readGuestString(ctx.Arg(0)))
		s2 := strings.ToLower(readGuestString(ctx.Arg(1)))
		if s1 < s2 {
			ctx.SetReturn(0xFFFFFFFF)
		} else if s1 > s2 {
			ctx.SetReturn(1)
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := readGuestString(ctx.Arg(1))
		ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcpyA", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := readGuestString(ctx.Arg(1))
		ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrcpyn", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := readGuestString(ctx.Arg(1))
		n := int(ctx.Arg(2))
		if n <= 0 {
			ctx.SetReturn(dst)
			return 0
		}
		if len(src) >= n {
			src = src[:n-1]
		}
		ctx.Mem.WriteBytes(dst, append([]byte(src), 0))
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "lstrlen", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "lstrlen", 1, uint64(uint64(len(readGuestString(ctx.Arg(0))))))
	})
	d.RegisterAutoStubHandler(kernel32, "lstrlenA", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "lstrlenA", 1, uint64(uint64(len(readGuestString(ctx.Arg(0))))))
	})
	d.RegisterAutoStubHandler(kernel32, "timeBeginPeriod", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "timeBeginPeriod", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "timeEndPeriod", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "timeEndPeriod", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "timeGetDevCaps", func(ctx *ntapi.TrapContext) uint32 {
		ptc := ctx.Arg(0)
		if ptc != 0 {
			ctx.Mem.Write32(ptc, 1)
			ctx.Mem.Write32(ptc+4, 0xFFFFFFFF)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "timeGetSystemTime", func(ctx *ntapi.TrapContext) uint32 {
		pmmt := ctx.Arg(0)
		if pmmt != 0 {
			ctx.Mem.Write32(pmmt, uint32(time.Since(startTime).Milliseconds()))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(kernel32, "timeGetTime", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "timeGetTime", 4, uint64(uint64(time.Since(startTime).Milliseconds())))
	})
	d.RegisterAutoStubHandler(kernel32, "wine_get_dos_file_name", func(ctx *ntapi.TrapContext) uint32 {
		return runKernel32TrivialHandler(ctx, "wine_get_dos_file_name", 8, 0)
	})
	d.RegisterAutoStubHandler(kernel32, "wine_get_unix_file_name", func(ctx *ntapi.TrapContext) uint32 {
		// Wine internal: converts DOS path → Unix path. Return NULL since
		// we don't have a Wine-style path mapping.
		ravelog.Logf("[kernel32] wine_get_unix_file_name called (not supported)\n")
		ctx.SetReturn(0)
		return 0
	})
}
