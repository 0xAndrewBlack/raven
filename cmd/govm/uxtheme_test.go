//go:build guest_windows

package main

import (
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/gdi"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

type themeTestEnv struct {
	mem        *mmu.MMU
	dispatcher *ntapi.Dispatcher
	uxtheme    *ntapi.SynthPE
	dwmapi     *ntapi.SynthPE
	is32       bool
}

func newThemeTestEnv(t *testing.T, is32 bool) *themeTestEnv {
	t.Helper()
	resetDarkModeState()
	mem := mmu.New()
	mem.Mode32 = is32
	state := &ntapi.ProcessState{Is32: is32}
	dispatcher := ntapi.NewDispatcher(
		mem,
		vfs.New(),
		ntapi.NewHandleTable(),
		nil,
		state,
		ntapi.GenerateNtdll(mem),
		ntapi.GenerateWin32u(mem),
	)
	uxtheme := ntapi.GenerateSynthDLL(mem, "uxtheme.dll", []string{
		"OpenThemeData",
		"SetWindowTheme",
	}, 0x4000)
	dwmapi := ntapi.GenerateSynthDLL(mem, "dwmapi.dll", []string{
		"DwmGetWindowAttribute",
		"DwmSetWindowAttribute",
	}, 0x4100)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		SynthByName: map[string]*ntapi.SynthPE{"uxtheme.dll": uxtheme, "dwmapi.dll": dwmapi},
		NextDelayID: 0x5000,
		ReadGuestUTF16: func(addr uint64) string {
			value, _ := readOptionalThemeString(mem, addr)
			return value
		},
	}
	registerUxthemeHandlers(hctx)
	registerDwmapiHandlers(hctx)
	return &themeTestEnv{
		mem:        mem,
		dispatcher: dispatcher,
		uxtheme:    uxtheme,
		dwmapi:     dwmapi,
		is32:       is32,
	}
}

func (env *themeTestEnv) call(t *testing.T, synth *ntapi.SynthPE, name string, args ...uint64) uint64 {
	t.Helper()
	stub := synth.Exports[name]
	if stub == 0 {
		t.Fatalf("%s has no synthetic export", name)
	}
	id, ok := synth.StubIDs[stub]
	if !ok {
		t.Fatalf("%s has no trap ID", name)
	}
	stack := env.mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	cpu := x64.New(env.mem)
	cpu.Mode32 = env.is32
	cpu.SetSP(stack + 0x100)
	if env.is32 {
		for i, arg := range args {
			if err := env.mem.Write32(cpu.GetSP()+4+uint64(i)*4, uint32(arg)); err != nil {
				t.Fatal(err)
			}
		}
	} else {
		for i, arg := range args {
			switch i {
			case 0:
				cpu.Regs[x64.RCX] = arg
			case 1:
				cpu.Regs[x64.RDX] = arg
			case 2:
				cpu.Regs[x64.R8] = arg
			case 3:
				cpu.Regs[x64.R9] = arg
			default:
				if err := env.mem.Write64(cpu.GetSP()+0x28+uint64(i-4)*8, arg); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	cpu.Regs[x64.RAX] = uint64(id)
	env.dispatcher.Handle(cpu)
	return cpu.Regs[x64.RAX]
}

func (env *themeTestEnv) allocUTF16(t *testing.T, value string) uint64 {
	t.Helper()
	encoded := append(utf16Encode(value), 0)
	addr := env.mem.Mmap(0, uint64(len(encoded)*2), mmu.PermRead|mmu.PermWrite)
	for i, char := range encoded {
		if err := env.mem.Write16(addr+uint64(i)*2, char); err != nil {
			t.Fatal(err)
		}
	}
	return addr
}

func resetDarkModeState() {
	darkModeGlobal.mu.Lock()
	darkModeGlobal.preferredMode = preferredAppModeDefault
	darkModeGlobal.legacyAppAllowed = false
	darkModeGlobal.appsUseDark = false
	darkModeGlobal.systemUsesDark = false
	darkModeGlobal.windowAllowed = make(map[uint64]bool)
	darkModeGlobal.windowThemes = make(map[uint64]windowThemeSelection)
	darkModeGlobal.windowImmersiveDWM = make(map[uint64]bool)
	darkModeGlobal.mu.Unlock()
}

func TestEffectiveDarkModeInheritsWindowStateAndCleansUp(t *testing.T) {
	resetDarkModeState()
	const (
		dialog = uint64(0x4100)
		child  = uint64(0x4200)
	)
	children := map[uint64]*controlState{
		dialog: {parentHWND: 0},
		child:  {parentHWND: dialog},
	}
	allowDarkModeForApp(true)
	setTestAppsUseDarkMode(true)
	if !allowDarkModeForWindow(dialog, true) {
		t.Fatal("failed to enable dark mode for dialog")
	}
	if !effectiveDarkModeForWindow(child, children) {
		t.Fatal("child did not inherit dialog dark mode")
	}

	setWindowThemeSelection(child, windowThemeSelection{SubAppName: "DarkMode_Explorer"})
	clearDarkModeWindowState(dialog)
	if !effectiveDarkModeForWindow(child, children) {
		t.Fatal("dark window theme was not recognized")
	}
	clearDarkModeWindowState(child)
	if effectiveDarkModeForWindow(child, children) {
		t.Fatal("destroy cleanup left dark mode state behind")
	}
}

func TestDarkThemePixelRemapIsStable(t *testing.T) {
	surface := gdi.NewSurface(3, 1)
	dc := gdi.NewScreenDC(surface)
	surface.SetPixel(0, 0, 0xF0F0F0)
	surface.SetPixel(1, 0, 0x000000)
	surface.SetPixel(2, 0, 0x0078D7)

	remapDCRectForDarkMode(dc, 0, 0, 3, 1)
	remapDCRectForDarkMode(dc, 0, 0, 3, 1)

	want := []uint32{darkPalette.Control, darkPalette.Text, 0x0078D7}
	for x, color := range want {
		if got := surface.GetPixel(int32(x), 0); got != color {
			t.Fatalf("pixel %d = %#06x, want %#06x", x, got, color)
		}
	}
}

func setTestSystemDarkMode(dark bool) {
	darkModeGlobal.mu.Lock()
	darkModeGlobal.systemUsesDark = dark
	darkModeGlobal.mu.Unlock()
}

func setTestAppsUseDarkMode(dark bool) {
	darkModeGlobal.mu.Lock()
	darkModeGlobal.appsUseDark = dark
	darkModeGlobal.mu.Unlock()
}

func TestUxthemeDarkModeOrdinalHandlersPE32AndPE64(t *testing.T) {
	wantOrdinals := map[uint16]string{
		49:  "OpenNcThemeData",
		104: "RefreshImmersiveColorPolicyState",
		106: "GetIsImmersiveColorUsingHighContrast",
		132: "ShouldAppsUseDarkMode",
		133: "AllowDarkModeForWindow",
		135: "SetPreferredAppMode",
		136: "FlushMenuThemes",
		137: "IsDarkModeAllowedForWindow",
	}
	for _, test := range []struct {
		name string
		is32 bool
	}{
		{name: "PE32", is32: true},
		{name: "PE64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newThemeTestEnv(t, test.is32)
			for ordinal, name := range wantOrdinals {
				if got := env.uxtheme.ExportOrds[ordinal]; got != env.uxtheme.Exports[name] {
					t.Fatalf("ordinal %d = %#x, want %s at %#x", ordinal, got, name, env.uxtheme.Exports[name])
				}
			}

			if previous := env.call(t, env.uxtheme, "SetPreferredAppMode", uint64(preferredAppModeForceDark)); previous != uint64(preferredAppModeDefault) {
				t.Fatalf("previous app mode = %d", previous)
			}
			if got := env.call(t, env.uxtheme, "ShouldAppsUseDarkMode"); got != 1 {
				t.Fatalf("ShouldAppsUseDarkMode = %d", got)
			}
			if !darkModeAllowedForApp() {
				t.Fatal("forced dark mode did not opt in the process")
			}
			if previous := env.call(t, env.uxtheme, "SetPreferredAppMode", uint64(preferredAppModeForceLight)); previous != uint64(preferredAppModeForceDark) {
				t.Fatalf("second previous app mode = %d", previous)
			}
			if got := env.call(t, env.uxtheme, "ShouldAppsUseDarkMode"); got != 0 {
				t.Fatalf("forced light ShouldAppsUseDarkMode = %d", got)
			}
			if darkModeAllowedForApp() {
				t.Fatal("forced light mode left the process opted in")
			}

			const hwnd = uint64(0x1234)
			if got := env.call(t, env.uxtheme, "AllowDarkModeForWindow", hwnd, 1); got != 1 {
				t.Fatalf("AllowDarkModeForWindow = %d", got)
			}
			if got := env.call(t, env.uxtheme, "IsDarkModeAllowedForWindow", hwnd); got != 1 {
				t.Fatalf("IsDarkModeAllowedForWindow = %d", got)
			}
			if got := env.call(t, env.uxtheme, "AllowDarkModeForWindow", hwnd, 0); got != 1 {
				t.Fatalf("disable window dark mode = %d", got)
			}
			if darkModeAllowedForWindow(hwnd) {
				t.Fatal("window dark mode remained enabled")
			}

			setTestAppsUseDarkMode(true)
			setTestSystemDarkMode(true)
			if got := env.call(t, env.uxtheme, "AllowDarkModeForApp", 1); got != 1 {
				t.Fatalf("AllowDarkModeForApp = %d", got)
			}
			if !darkModeAllowedForApp() {
				t.Fatal("legacy API did not opt in the process")
			}
			if got := env.call(t, env.uxtheme, "ShouldAppsUseDarkMode"); got != 1 {
				t.Fatalf("legacy ShouldAppsUseDarkMode = %d", got)
			}
			if got := env.call(t, env.uxtheme, "ShouldSystemUseDarkMode"); got != 1 {
				t.Fatalf("ShouldSystemUseDarkMode = %d", got)
			}
			setTestSystemDarkMode(false)
			if got := env.call(t, env.uxtheme, "ShouldAppsUseDarkMode"); got != 1 {
				t.Fatalf("app preference followed system preference: %d", got)
			}
			if got := env.call(t, env.uxtheme, "ShouldSystemUseDarkMode"); got != 0 {
				t.Fatalf("system preference remained dark: %d", got)
			}
			if got := env.call(t, env.uxtheme, "GetIsImmersiveColorUsingHighContrast", 1); got != 0 {
				t.Fatalf("high contrast query = %d", got)
			}
			if got := env.call(t, env.uxtheme, "RefreshImmersiveColorPolicyState"); got != 0 {
				t.Fatalf("refresh result = %d", got)
			}
			if got := env.call(t, env.uxtheme, "FlushMenuThemes"); got != 0 {
				t.Fatalf("flush result = %d", got)
			}
			className := env.allocUTF16(t, "ScrollBar")
			if got := env.call(t, env.uxtheme, "OpenNcThemeData", hwnd, className); got == 0 {
				t.Fatal("OpenNcThemeData returned null")
			}
		})
	}
}

func TestSetPreferredAppModeRejectsOutOfRangeMode(t *testing.T) {
	env := newThemeTestEnv(t, false)
	env.call(t, env.uxtheme, "SetPreferredAppMode", uint64(preferredAppModeForceDark))
	if previous := env.call(t, env.uxtheme, "SetPreferredAppMode", uint64(preferredAppModeMax)); previous != uint64(preferredAppModeForceDark) {
		t.Fatalf("previous mode = %d", previous)
	}
	if !shouldAppsUseDarkMode() {
		t.Fatal("invalid mode changed process state")
	}
}

func TestDarkRepaintRootsDeduplicateDialogDescendants(t *testing.T) {
	const (
		main   = uint64(0x50001)
		dialog = uint64(0x50010)
		page   = uint64(0x50011)
		button = uint64(0x50012)
	)
	hctx := &HandlerCtx{
		MainHWND: main,
		HwndChildren: map[uint64]*controlState{
			main:   {className: "Notepad++", visible: true},
			dialog: {className: "dialog", parentHWND: main, visible: true},
			page:   {className: "dialog", parentHWND: dialog, style: 0x40000000, visible: true},
			button: {className: "button", parentHWND: page, visible: true},
		},
	}
	roots := darkRepaintWindowRoots(hctx)
	if len(roots) != 2 || roots[0] != main || roots[1] != dialog {
		t.Fatalf("dark repaint roots = %#v", roots)
	}
}

func TestSetWindowThemePersistsNamesAndValidatesPointers(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		env := newThemeTestEnv(t, is32)
		const hwnd = uint64(0x2200)
		subApp := env.allocUTF16(t, "DarkMode_Explorer")
		subID := env.allocUTF16(t, "ItemsView")
		if got := env.call(t, env.uxtheme, "SetWindowTheme", hwnd, subApp, subID); got != sOK {
			t.Fatalf("PE32=%v SetWindowTheme = %#x", is32, got)
		}
		selection, ok := windowThemeSelectionFor(hwnd)
		if !ok || selection.SubAppName != "DarkMode_Explorer" || selection.SubIDList != "ItemsView" {
			t.Fatalf("PE32=%v selection = %+v, present=%v", is32, selection, ok)
		}
		if got := env.call(t, env.uxtheme, "SetWindowTheme", hwnd, 0xdead0000, 0); got != eInvalidArg {
			t.Fatalf("PE32=%v invalid pointer result = %#x", is32, got)
		}
		if got := env.call(t, env.uxtheme, "SetWindowTheme", 0, 0, 0); got != eInvalidArg {
			t.Fatalf("PE32=%v invalid HWND result = %#x", is32, got)
		}
	}
}

func TestDwmImmersiveDarkModeStateAndValidation(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		env := newThemeTestEnv(t, is32)
		const hwnd = uint64(0x3300)
		value := env.mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		if err := env.mem.Write32(value, 1); err != nil {
			t.Fatal(err)
		}
		for _, attr := range []uint32{dwmwaUseImmersiveDarkModeBefore20H1, dwmwaUseImmersiveDarkMode} {
			if got := env.call(t, env.dwmapi, "DwmSetWindowAttribute", hwnd, uint64(attr), value, 4); got != sOK {
				t.Fatalf("PE32=%v attr=%d set result = %#x", is32, attr, got)
			}
			dark, ok := immersiveDarkModeForWindow(hwnd)
			if !ok || !dark {
				t.Fatalf("PE32=%v attr=%d state = (%v, %v)", is32, attr, dark, ok)
			}
			if err := env.mem.Write32(value, 0); err != nil {
				t.Fatal(err)
			}
			if got := env.call(t, env.dwmapi, "DwmGetWindowAttribute", hwnd, uint64(attr), value, 4); got != sOK {
				t.Fatalf("PE32=%v attr=%d get result = %#x", is32, attr, got)
			}
			if got, err := env.mem.Read32(value); err != nil || got != 1 {
				t.Fatalf("PE32=%v attr=%d value = %d, err=%v", is32, attr, got, err)
			}
		}
		if got := env.call(t, env.dwmapi, "DwmSetWindowAttribute", hwnd, uint64(dwmwaUseImmersiveDarkMode), 0, 4); got != eInvalidArg {
			t.Fatalf("PE32=%v null value result = %#x", is32, got)
		}
		if got := env.call(t, env.dwmapi, "DwmSetWindowAttribute", hwnd, uint64(dwmwaUseImmersiveDarkMode), value, 1); got != eInvalidArg {
			t.Fatalf("PE32=%v short value result = %#x", is32, got)
		}
		if got := env.call(t, env.dwmapi, "DwmSetWindowAttribute", hwnd, uint64(dwmwaUseImmersiveDarkMode), 0xdead0000, 4); got != eInvalidArg {
			t.Fatalf("PE32=%v unmapped value result = %#x", is32, got)
		}
		if got := env.call(t, env.dwmapi, "DwmSetWindowAttribute", 0, uint64(dwmwaUseImmersiveDarkMode), value, 4); got != eInvalidArg {
			t.Fatalf("PE32=%v invalid HWND result = %#x", is32, got)
		}
		readonly := env.mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		if err := env.mem.Mprotect(readonly, 4, mmu.PermRead); err != nil {
			t.Fatal(err)
		}
		if got := env.call(t, env.dwmapi, "DwmGetWindowAttribute", hwnd, uint64(dwmwaUseImmersiveDarkMode), readonly, 4); got != eInvalidArg {
			t.Fatalf("PE32=%v read-only output result = %#x", is32, got)
		}
	}
}

func TestDarkModeStateConcurrentAccess(t *testing.T) {
	resetDarkModeState()
	const workers = 16
	const iterations = 200
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			hwnd := uint64(worker + 1)
			for i := 0; i < iterations; i++ {
				dark := i%2 == 0
				setPreferredDarkAppMode(preferredAppMode(uint32(i) % uint32(preferredAppModeMax)))
				allowDarkModeForApp(dark)
				allowDarkModeForWindow(hwnd, dark)
				setWindowThemeSelection(hwnd, windowThemeSelection{
					SubAppName: "Explorer",
					SubIDList:  "ItemsView",
				})
				setImmersiveDarkModeForWindow(hwnd, dark)
				_ = shouldAppsUseDarkMode()
				_ = darkModeAllowedForApp()
				_ = shouldSystemUseDarkMode()
				_ = darkModeAllowedForWindow(hwnd)
				_, _ = windowThemeSelectionFor(hwnd)
				_, _ = immersiveDarkModeForWindow(hwnd)
			}
		}(worker)
	}
	wait.Wait()
}
