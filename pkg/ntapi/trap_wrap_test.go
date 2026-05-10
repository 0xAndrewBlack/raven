//go:build guest_windows

package ntapi

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestWrapAutoStubHandler(t *testing.T) {
	const (
		addr = uint64(0x1000)
		id   = uint32(0x2000)
	)
	synth := &SynthPE{
		Exports: map[string]uint64{"Example": addr},
		StubIDs: map[uint64]uint32{addr: id},
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
	}
	calls := 0
	dispatcher.handlers[id] = func(ctx *TrapContext) uint32 {
		calls++
		return 3
	}

	if !dispatcher.WrapAutoStubHandler(synth, "Example", func(previous TrapHandler) TrapHandler {
		return func(ctx *TrapContext) uint32 {
			status := previous(ctx)
			return status + 2
		}
	}) {
		t.Fatal("WrapAutoStubHandler returned false")
	}

	ctx := &TrapContext{}
	if status := dispatcher.handlers[id](ctx); status != 5 || calls != 1 {
		t.Fatalf("wrapped handler = status %d, calls %d", status, calls)
	}
	if dispatcher.handlersByModule[""]["Example"] == nil {
		t.Fatal("wrapped handler was not registered by name")
	}
}

func TestWrapAutoStubHandlerRejectsMissingHandler(t *testing.T) {
	synth := &SynthPE{
		Exports: map[string]uint64{"Example": 0x1000},
		StubIDs: map[uint64]uint32{0x1000: 0x2000},
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
	}
	if dispatcher.WrapAutoStubHandler(synth, "Example", func(previous TrapHandler) TrapHandler {
		return previous
	}) {
		t.Fatal("missing handler was wrapped")
	}
}

func TestDeferWindowStdcallArgCounts(t *testing.T) {
	want := map[string]int{
		"BeginDeferWindowPos":    1,
		"DeferWindowPos":         8,
		"EndDeferWindowPos":      1,
		"GetEffectiveClientRect": 3,
		"RtlGetNtVersionNumbers": 3,
	}
	for name, count := range want {
		if got := win32ArgCounts[name]; got != count {
			t.Errorf("%s arg count = %d, want %d", name, got, count)
		}
	}
}

func TestHiddenNtdllExport(t *testing.T) {
	if !IsHiddenNtdllExport("wine_get_version") || !IsHiddenNtdllExport("WINE_GET_VERSION") {
		t.Fatal("Wine detection export was visible")
	}
	if IsHiddenNtdllExport("RtlGetNtVersionNumbers") {
		t.Fatal("native NT version export was hidden")
	}
}

func TestLookupExportByModuleHidesOnlyNtdllWineProbe(t *testing.T) {
	const (
		ntdllBase = uint64(0x100000)
		appBase   = uint64(0x200000)
	)
	dispatcher := &Dispatcher{
		ntdll: &SynthPE{
			BaseAddr: ntdllBase,
			Exports: map[string]uint64{
				"RtlGetNtVersionNumbers": 0x101000,
				"wine_get_version":       0x102000,
			},
		},
		moduleExports: map[uint64]map[string]uint64{
			appBase: {"wine_get_version": 0x201000},
		},
	}

	if got := dispatcher.LookupExportByModule(ntdllBase, "RtlGetNtVersionNumbers", 0); got != 0x101000 {
		t.Fatalf("RtlGetNtVersionNumbers address = 0x%x", got)
	}
	if got := dispatcher.LookupExportByModule(ntdllBase, "wine_get_version", 0); got != 0 {
		t.Fatalf("ntdll wine_get_version address = 0x%x", got)
	}
	if got := dispatcher.LookupExportByModule(appBase, "wine_get_version", 0); got != 0x201000 {
		t.Fatalf("application wine_get_version address = 0x%x", got)
	}
}

func TestLookupExportByModuleAppliesOrdinalPolicy(t *testing.T) {
	const ntdllBase = uint64(0x100000)
	dispatcher := &Dispatcher{
		ntdll: &SynthPE{
			BaseAddr: ntdllBase,
			Exports: map[string]uint64{
				"RtlGetNtVersionNumbers": 0x101000,
				"wine_get_version":       0x102000,
			},
			ExportOrds: map[uint16]uint64{
				7: 0x102000,
				8: 0x101000,
			},
		},
		moduleExports:    make(map[uint64]map[string]uint64),
		moduleOrdExports: make(map[uint64]map[uint16]uint64),
	}

	if got := dispatcher.LookupExportByModule(ntdllBase, "", 7); got != 0 {
		t.Fatalf("hidden ordinal address = 0x%x", got)
	}
	if got := dispatcher.LookupExportByModule(ntdllBase, "", 8); got != 0x101000 {
		t.Fatalf("native ordinal address = 0x%x", got)
	}
	if got := dispatcher.LookupExportByModule(ntdllBase, "Missing", 8); got != 0x101000 {
		t.Fatalf("fallback ordinal address = 0x%x", got)
	}
	if got := dispatcher.LookupExportByModule(ntdllBase, "wine_get_version", 8); got != 0 {
		t.Fatalf("hidden named lookup fell back to ordinal: 0x%x", got)
	}
}

func TestMaterializeNamedHandlerIsModuleScoped(t *testing.T) {
	mem := mmu.New()
	first := &SynthPE{
		Name:       "first.dll",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	second := &SynthPE{
		Name:       "second.dll",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	reloadedFirst := &SynthPE{
		Name:       "FIRST.DLL",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
		names:            make(map[uint32]string),
		stdcallArgs:      make(map[uint32]int),
	}
	dispatcher.RegisterAutoStubHandler(first, "Example", func(*TrapContext) uint32 { return 1 })

	if addr, _ := dispatcher.MaterializeNamedHandler(mem, second, "Example", DynExportIDBase); addr != 0 {
		t.Fatalf("handler leaked into second.dll at 0x%x", addr)
	}
	if addr, _ := dispatcher.MaterializeNamedHandler(mem, first, "Example", DynExportIDBase); addr == 0 {
		t.Fatal("handler was not materialized in first.dll")
	}
	if addr, _ := dispatcher.MaterializeNamedHandler(mem, reloadedFirst, "Example", DynExportIDBase); addr == 0 {
		t.Fatal("handler was not inherited by a reloaded first.dll synth")
	}
}

func TestMaterializeNamedHandlerConcurrent(t *testing.T) {
	mem := mmu.New()
	synth := &SynthPE{
		Name:       "example.dll",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
		names:            make(map[uint32]string),
		stdcallArgs:      make(map[uint32]int),
	}
	dispatcher.RegisterAutoStubHandler(synth, "Example", func(*TrapContext) uint32 { return 1 })

	const workers = 32
	addresses := make(chan uint64, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			addr, _ := dispatcher.MaterializeNamedHandler(mem, synth, "Example", DynExportIDBase)
			addresses <- addr
		}()
	}
	group.Wait()
	close(addresses)

	var expected uint64
	for addr := range addresses {
		if addr == 0 {
			t.Fatal("concurrent materialization returned zero")
		}
		if expected == 0 {
			expected = addr
		} else if addr != expected {
			t.Fatalf("materialized addresses differ: 0x%x and 0x%x", expected, addr)
		}
	}
	if len(synth.Exports) != 1 || len(synth.StubIDs) != 1 {
		t.Fatalf("materialization created duplicate exports: %d names, %d stubs", len(synth.Exports), len(synth.StubIDs))
	}
}

func TestMaterializeNamedHandlerSkipsNamedTrapIDs(t *testing.T) {
	mem := mmu.New()
	synth := &SynthPE{
		Name:       "example.dll",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
		names:            map[uint32]string{DynExportIDBase: "occupied.dll!Missing"},
		stdcallArgs:      make(map[uint32]int),
	}
	dispatcher.RegisterAutoStubHandler(synth, "Example", func(*TrapContext) uint32 { return 1 })

	addr, _ := dispatcher.MaterializeNamedHandler(mem, synth, "Example", DynExportIDBase)
	if addr == 0 {
		t.Fatal("handler was not materialized")
	}
	if got := synth.StubIDs[addr]; got != DynExportIDBase+1 {
		t.Fatalf("dynamic trap ID = 0x%x", got)
	}
}

func TestMaterializeNamedHandlerPreservesModuleCdecl(t *testing.T) {
	mem := mmu.New()
	synth := &SynthPE{
		Name:       "msvcrt.dll",
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}
	dispatcher := &Dispatcher{
		handlers:         make(map[uint32]TrapHandler),
		handlersByModule: make(map[string]map[string]TrapHandler),
		names:            make(map[uint32]string),
		stdcallArgs:      make(map[uint32]int),
	}
	dispatcher.MarkCdeclModule(synth)
	dispatcher.RegisterAutoStubHandler(synth, "wcslen", func(*TrapContext) uint32 { return 1 })

	addr, _ := dispatcher.MaterializeNamedHandler(mem, synth, "wcslen", DynExportIDBase)
	if addr == 0 {
		t.Fatal("cdecl handler was not materialized")
	}
	id := synth.StubIDs[addr]
	if !dispatcher.cdeclIDs[id] {
		t.Fatalf("dynamic trap ID 0x%x was not marked cdecl", id)
	}
}

func TestLoadNlsFileConcurrent(t *testing.T) {
	root := t.TempDir()
	want := []byte{1, 2, 3, 4}
	if err := os.WriteFile(filepath.Join(root, "c_1252.nls"), want, 0600); err != nil {
		t.Fatal(err)
	}
	dispatcher := &Dispatcher{
		sysRoot:  root,
		nlsCache: make(map[uint32][]byte),
	}

	const workers = 32
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := dispatcher.loadNlsFile(1252)
			if err == nil && len(got) != len(want) {
				err = os.ErrInvalid
			}
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}
