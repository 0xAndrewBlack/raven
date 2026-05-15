//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

type crtLocaleTrackingCPU struct {
	*x64.CPU
	stopped bool
}

func (cpu *crtLocaleTrackingCPU) Stop() {
	cpu.stopped = true
	cpu.CPU.Stop()
}

func newCRTLocaleInvocation(t *testing.T, name string, is32 bool) (*crtContractInvocation, *mmu.MMU) {
	t.Helper()
	dispatcher, synth, mem := newCRTDispatcher(t, "ucrtbase.dll", name, is32)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		SynthByName: map[string]*ntapi.SynthPE{"ucrtbase.dll": synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	return &crtContractInvocation{
		Dispatcher: dispatcher,
		Synth:      synth,
		Mem:        mem,
		Is32:       is32,
		Module:     "ucrtbase.dll",
		Name:       name,
	}, mem
}

func newCRTLocaleInvocations(t *testing.T, names []string, is32 bool) (map[string]*crtContractInvocation, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	mem.Mode32 = is32
	state := &ntapi.ProcessState{Is32: is32}
	dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
	synth := ntapi.GenerateSynthDLL(mem, "ucrtbase.dll", names, ntapi.AutoSynthIDBase)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		ProcState:   state,
		SynthByName: map[string]*ntapi.SynthPE{"ucrtbase.dll": synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	invocations := make(map[string]*crtContractInvocation, len(names))
	for _, name := range names {
		invocations[name] = &crtContractInvocation{
			Dispatcher: dispatcher,
			Synth:      synth,
			Mem:        mem,
			Is32:       is32,
			Module:     "ucrtbase.dll",
			Name:       name,
		}
	}
	return invocations, mem
}

func writeCRTLocaleTestData(t *testing.T, mem *mmu.MMU, value []byte) uint64 {
	t.Helper()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if address == 0 {
		t.Fatal("locale test allocation failed")
	}
	if err := mem.WriteBytes(address, value); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestCRTLocaleContracts(t *testing.T) {
	memoryOutputs := map[string]bool{
		"mbtowc":   true,
		"wctomb":   true,
		"mbstowcs": true,
		"wcstombs": true,
	}
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtLocaleSemantics {
			semantic := semantic
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				dispatcher, synth, mem := newCRTDispatcher(t, "ucrtbase.dll", semantic.name, is32)
				hctx := &HandlerCtx{
					Disp:        dispatcher,
					Mem:         mem,
					SynthByName: map[string]*ntapi.SynthPE{"ucrtbase.dll": synth},
				}
				registerCRTDefinitions(hctx, crtSemanticDefinitions())
				run := newCRTContractRun()
				run.Execute(hctx)
				key := crtContractKey{
					Module:           "ucrtbase.dll",
					Name:             semantic.name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: semantic.id,
					Signature:        semantic.signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed {
					t.Fatalf("%s contract failed: %#v", semantic.name, evidence)
				}
				if evidence.callCount < 2 || evidence.distinctInputs < 2 || evidence.distinctObservations < 2 {
					t.Fatalf("%s lacks input-dependent calls: %#v", semantic.name, evidence)
				}
				if evidence.assertionCount < evidence.callCount {
					t.Fatalf("%s lacks dispatched assertions: %#v", semantic.name, evidence)
				}
				if memoryOutputs[semantic.name] && !evidence.memoryChanged {
					t.Fatalf("%s did not produce guest memory output: %#v", semantic.name, evidence)
				}
			})
		}
	}
}

func TestCRTLocaleStateTransitions(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocation, mem := newCRTLocaleInvocation(t, "setlocale", is32)
			result, err := invocation.Call(0, 0)
			if err != nil || result == 0 {
				t.Fatalf("setlocale initial query result=%#x err=%v", result, err)
			}
			name, ok := crtReadNarrowString(mem, result)
			if !ok || string(name) != "C" {
				t.Fatalf("setlocale initial query returned %q", name)
			}
			empty := writeCRTLocaleTestData(t, mem, []byte{0})
			result, err = invocation.Call(0, empty)
			if err != nil || result == 0 {
				t.Fatalf("setlocale empty result=%#x err=%v", result, err)
			}
			name, ok = crtReadNarrowString(mem, result)
			if !ok || string(name) != "English_United States.1252" {
				t.Fatalf("setlocale empty returned %q", name)
			}
			runtime := crtLocaleContractRuntime(invocation)
			if runtime == nil {
				t.Fatal("setlocale runtime is absent")
			}
			runtime.mu.Lock()
			runtimeName, codePage := runtime.name, runtime.codePage
			runtime.mu.Unlock()
			if runtimeName != "English_United States.1252" || codePage != 1252 {
				t.Fatalf("setlocale runtime name=%q codepage=%d", runtimeName, codePage)
			}

			windowsName := writeCRTLocaleTestData(t, mem, []byte("German_Germany.1252\x00"))
			result, err = invocation.Call(0, windowsName)
			name, ok = crtReadNarrowString(mem, result)
			if err != nil || result == 0 || !ok || string(name) != "German_Germany.1252" {
				t.Fatalf("setlocale Windows name result=%#x name=%q err=%v", result, name, err)
			}

			invocations, mem := newCRTLocaleInvocations(t, []string{"_setmbcp", "mbtowc"}, is32)
			setmbcp := invocations["_setmbcp"]
			result, err = setmbcp.Call(0)
			runtime = crtLocaleContractRuntime(setmbcp)
			if err != nil || result != 0 || runtime == nil {
				t.Fatalf("_setmbcp(0) result=%#x runtime=%v err=%v", result, runtime, err)
			}
			runtime.mu.Lock()
			codePage = runtime.codePage
			runtime.mu.Unlock()
			if codePage != 20127 {
				t.Fatalf("_setmbcp(0) codepage=%d", codePage)
			}
			result, err = setmbcp.Call(1252)
			runtime.mu.Lock()
			codePage = runtime.codePage
			runtime.mu.Unlock()
			if err != nil || result != 0 || codePage != 1252 {
				t.Fatalf("_setmbcp(1252) result=%#x codepage=%d err=%v", result, codePage, err)
			}
			source := writeCRTLocaleTestData(t, mem, []byte{0x80, 0})
			destination := writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc})
			result, err = invocations["mbtowc"].Call(destination, source, 1)
			unit, readErr := mem.Read16(destination)
			if err != nil || readErr != nil || result != 1 || unit != 0x20ac {
				t.Fatalf("CP1252 mbtowc result=%#x unit=%#x callErr=%v readErr=%v", result, unit, err, readErr)
			}

			invocation, _ = newCRTLocaleInvocation(t, "wctomb", is32)
			result, err = invocation.Call(0, 0x20ac)
			if err != nil || result != 0 {
				t.Fatalf("wctomb reset result=%#x err=%v", result, err)
			}
		})
	}
}

func TestCRTLocaleWctombResetDoesNotStopCPU(t *testing.T) {
	mem := mmu.New()
	base := x64.New(mem)
	cpu := &crtLocaleTrackingCPU{CPU: base}
	cpu.Resume()
	cpu.Regs[x64.RCX] = 0
	cpu.Regs[x64.RDX] = 0x20ac
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}
	crtWctomb(ctx)
	if cpu.stopped || cpu.Regs[x64.RAX] != 0 {
		t.Fatalf("wctomb reset stopped=%v result=%#x", cpu.stopped, cpu.Regs[x64.RAX])
	}
}

func TestCRTLocaleSizeQueriesAndUTF8Boundaries(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocation, mem := newCRTLocaleInvocation(t, "mbstowcs", is32)
			source := writeCRTLocaleTestData(t, mem, []byte("text\x00"))
			result, err := invocation.Call(0, source, 0)
			if err != nil || result != 4 {
				t.Fatalf("mbstowcs size result=%d err=%v", result, err)
			}
			source = writeCRTLocaleTestData(t, mem, []byte{'A', 0x80, 0})
			destination := writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc, 0xcc, 0xcc})
			crtWriteErrno(&ntapi.TrapContext{Mem: mem}, 0x1234)
			result, err = invocation.Call(destination, source, 1)
			unit, readErr := mem.Read16(destination)
			if err != nil || readErr != nil || result != 1 || unit != 'A' || crtReadErrno(mem, 0) != 0x1234 {
				t.Fatalf("mbstowcs bounded result=%d unit=%#x errno=%d callErr=%v readErr=%v", result, unit, crtReadErrno(mem, 0), err, readErr)
			}
			source = writeCRTLocaleTestData(t, mem, []byte("A\x00"))
			result, err = invocation.Call(destination, source, math.MaxUint64)
			actual, readErr := mem.ReadBytes(destination, 4)
			if err != nil || readErr != nil || result != 1 || !bytes.Equal(actual, []byte{'A', 0, 0, 0}) {
				t.Fatalf("mbstowcs large limit result=%d output=%x callErr=%v readErr=%v", result, actual, err, readErr)
			}

			invocation, mem = newCRTLocaleInvocation(t, "wcstombs", is32)
			source = writeCRTLocaleTestData(t, mem, crtWideASCII("text"))
			result, err = invocation.Call(0, source, 0)
			if err != nil || result != 4 {
				t.Fatalf("wcstombs size result=%d err=%v", result, err)
			}
			source = writeCRTLocaleTestData(t, mem, crtWideBytes([]uint16{'A', 0x20ac}, true))
			destination = writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc, 0xcc, 0xcc})
			crtWriteErrno(&ntapi.TrapContext{Mem: mem}, 0x1234)
			result, err = invocation.Call(destination, source, 1)
			actual, readErr = mem.ReadBytes(destination, 4)
			if err != nil || readErr != nil || result != 1 || !bytes.Equal(actual, []byte{'A', 0xcc, 0xcc, 0xcc}) || crtReadErrno(mem, 0) != 0x1234 {
				t.Fatalf("wcstombs bounded result=%d output=%x errno=%d callErr=%v readErr=%v", result, actual, crtReadErrno(mem, 0), err, readErr)
			}
			source = writeCRTLocaleTestData(t, mem, crtWideASCII("A"))
			result, err = invocation.Call(destination, source, math.MaxUint64)
			actual, readErr = mem.ReadBytes(destination, 4)
			if err != nil || readErr != nil || result != 1 || !bytes.Equal(actual, []byte{'A', 0, 0xcc, 0xcc}) {
				t.Fatalf("wcstombs large limit result=%d output=%x callErr=%v readErr=%v", result, actual, err, readErr)
			}
			if !crtLocaleContractSetCodePage(invocation, 65001) {
				t.Fatal("unable to select UTF-8 test code page")
			}
			source = writeCRTLocaleTestData(t, mem, crtWideBytes([]uint16{0x20ac}, true))
			destination = writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc, 0xcc, 0xcc})
			result, err = invocation.Call(destination, source, 2)
			actual, readErr = mem.ReadBytes(destination, 4)
			if err != nil || readErr != nil || result != 0 || !bytes.Equal(actual, []byte{0xcc, 0xcc, 0xcc, 0xcc}) {
				t.Fatalf("wcstombs split result=%d output=%x callErr=%v readErr=%v", result, actual, err, readErr)
			}
			result, err = invocation.Call(destination, source, 3)
			actual, readErr = mem.ReadBytes(destination, 4)
			if err != nil || readErr != nil || result != 3 || !bytes.Equal(actual, []byte{0xe2, 0x82, 0xac, 0xcc}) {
				t.Fatalf("wcstombs full result=%d output=%x callErr=%v readErr=%v", result, actual, err, readErr)
			}
		})
	}
}

func TestCRTLocaleConversionFailuresSetErrno(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			wantFailure := uint64(math.MaxUint64)
			if is32 {
				wantFailure = uint64(math.MaxUint32)
			}
			cases := []struct {
				name string
				call func(*testing.T, *crtContractInvocation, *mmu.MMU) (uint64, error)
				want uint64
			}{
				{
					name: "mblen",
					call: func(t *testing.T, invocation *crtContractInvocation, mem *mmu.MMU) (uint64, error) {
						source := writeCRTLocaleTestData(t, mem, []byte{0x80, 0})
						return invocation.Call(source, 1)
					},
					want: uint64(math.MaxUint32),
				},
				{
					name: "mbtowc",
					call: func(t *testing.T, invocation *crtContractInvocation, mem *mmu.MMU) (uint64, error) {
						source := writeCRTLocaleTestData(t, mem, []byte{0x80, 0})
						destination := writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc})
						return invocation.Call(destination, source, 1)
					},
					want: uint64(math.MaxUint32),
				},
				{
					name: "wctomb",
					call: func(t *testing.T, invocation *crtContractInvocation, mem *mmu.MMU) (uint64, error) {
						destination := writeCRTLocaleTestData(t, mem, []byte{0xcc, 0xcc, 0xcc})
						return invocation.Call(destination, 0x20ac)
					},
					want: uint64(math.MaxUint32),
				},
				{
					name: "mbstowcs",
					call: func(t *testing.T, invocation *crtContractInvocation, mem *mmu.MMU) (uint64, error) {
						source := writeCRTLocaleTestData(t, mem, []byte{0x80, 0})
						return invocation.Call(0, source, 0)
					},
					want: wantFailure,
				},
				{
					name: "wcstombs",
					call: func(t *testing.T, invocation *crtContractInvocation, mem *mmu.MMU) (uint64, error) {
						source := writeCRTLocaleTestData(t, mem, crtWideBytes([]uint16{0x20ac}, true))
						return invocation.Call(0, source, 0)
					},
					want: wantFailure,
				},
			}
			for _, testCase := range cases {
				invocation, mem := newCRTLocaleInvocation(t, testCase.name, is32)
				crtWriteErrno(&ntapi.TrapContext{Mem: mem}, 0)
				result, err := testCase.call(t, invocation, mem)
				if err != nil || result != testCase.want || crtReadErrno(mem, 0) != 42 {
					t.Errorf("%s result=%#x want=%#x errno=%d err=%v", testCase.name, result, testCase.want, crtReadErrno(mem, 0), err)
				}
			}
		})
	}
}

func TestCRTLocaleCorpusRoutes(t *testing.T) {
	corpus := loadCRTCorpusData(t)
	routes := make(map[string]bool)
	for _, route := range corpus.Routes {
		routes[route.Module+"\x00"+strings.ToLower(route.Name)+"\x00"+route.Architecture] = true
	}
	for _, semantic := range crtLocaleSemantics {
		for _, module := range crtLocaleModules {
			for _, architecture := range []string{"i386", "win64"} {
				key := normalizeCRTModule(module) + "\x00" + strings.ToLower(semantic.name) + "\x00" + architecture
				if !routes[key] {
					t.Errorf("locale definition %s claims absent corpus route %s/%s", semantic.name, module, architecture)
				}
			}
		}
	}
	certificate := executeCRTCertificateSuite(t, corpus)
	valid := make(map[string]bool)
	for _, route := range certificate.ValidRoutes {
		valid[route.Module+"\x00"+strings.ToLower(route.Name)+"\x00"+route.Architecture] = true
	}
	reasons := make(map[string][]string)
	for _, exclusion := range certificate.Exclusions {
		key := exclusion.Module + "\x00" + strings.ToLower(exclusion.Name)
		reasons[key] = append(reasons[key], exclusion.Reason)
	}
	for _, semantic := range crtLocaleSemantics {
		for _, module := range crtLocaleModules {
			for _, architecture := range []string{"i386", "win64"} {
				key := normalizeCRTModule(module) + "\x00" + strings.ToLower(semantic.name) + "\x00" + architecture
				if !valid[key] {
					reasonKey := normalizeCRTModule(module) + "\x00" + strings.ToLower(semantic.name)
					t.Errorf("locale route lacks executable certificate %s/%s/%s: %v", semantic.name, module, architecture, reasons[reasonKey])
				}
			}
		}
	}
}
