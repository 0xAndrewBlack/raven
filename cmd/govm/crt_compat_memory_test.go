//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func TestCRTMemoryContracts(t *testing.T) {
	names := []string{"memcpy", "memmove", "memset", "memcmp", "memchr", "_memccpy", "_swab"}
	for _, is32 := range []bool{true, false} {
		for _, name := range names {
			t.Run(fmt.Sprintf("%s/PE%d", name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", name, is32)
				hctx := &HandlerCtx{
					Disp:        dispatcher,
					Mem:         mem,
					SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth},
				}
				registerCRTDefinitions(hctx, crtSemanticDefinitions())
				registration := dispatcher.SemanticHandlers()["msvcrt.dll"][name]
				if registration.Handler == nil {
					t.Fatalf("%s was not registered", name)
				}
				run := newCRTContractRun()
				run.Execute(hctx)
				var definition crtSemanticDefinition
				for _, candidate := range crtSemanticDefinitions() {
					if candidate.ExportName == name && crtAllowedModule(candidate, "msvcrt.dll") {
						definition = candidate
						break
					}
				}
				key := crtContractKey{
					Module:           "msvcrt.dll",
					Name:             name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: definition.ImplementationID,
					Signature:        definition.Signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed || evidence.callCount < 2 || evidence.distinctObservations < 2 {
					t.Fatalf("%s contract failed: %#v", name, evidence)
				}
			})
		}
	}
}

func TestCRTMemmoveMatchesBytesCopy(t *testing.T) {
	rng := rand.New(rand.NewSource(0x524156454e))
	mem := mmu.New()
	dispatcher, synth, _ := newCRTDispatcherWithMemory(t, mem, "msvcrt.dll", "memmove", false)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	invocation := &crtContractInvocation{
		Dispatcher: dispatcher,
		Synth:      synth,
		Mem:        mem,
		Module:     "msvcrt.dll",
		Name:       "memmove",
	}
	for iteration := 0; iteration < 500; iteration++ {
		size := 1 + rng.Intn(192)
		source := make([]byte, size)
		if _, err := rng.Read(source); err != nil {
			t.Fatal(err)
		}
		want := append([]byte(nil), source...)
		src := rng.Intn(size)
		dst := rng.Intn(size)
		count := rng.Intn(size - max(src, dst) + 1)
		copy(want[dst:dst+count], want[src:src+count])

		base := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if err := mem.WriteBytes(base, source); err != nil {
			t.Fatal(err)
		}
		if _, err := invocation.Call(base+uint64(dst), base+uint64(src), uint64(count)); err != nil {
			t.Fatal(err)
		}
		got, err := mem.ReadBytes(base, size)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("iteration %d mismatch", iteration)
		}
	}
}

func TestCRTMemoryFaultPreflightIsAtomic(t *testing.T) {
	mem := mmu.New()
	dispatcher, synth, _ := newCRTDispatcherWithMemory(t, mem, "msvcrt.dll", "memcpy", false)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	dst := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	base := mem.Mmap(0x500000000000, 2*mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.Munmap(base+mmu.PageSize, mmu.PageSize)
	before := bytes.Repeat([]byte{0x5a}, 32)
	if err := mem.WriteBytes(dst, before); err != nil {
		t.Fatal(err)
	}
	invocation := &crtContractInvocation{
		Dispatcher: dispatcher,
		Synth:      synth,
		Mem:        mem,
		Module:     "msvcrt.dll",
		Name:       "memcpy",
	}
	if _, err := invocation.Call(dst, base+mmu.PageSize-16, 32); err != nil {
		t.Fatal(err)
	}
	after, err := mem.ReadBytes(dst, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("faulting memcpy modified destination: dst=%#x source=%#x before=%x after=%x", dst, base+mmu.PageSize-16, before, after)
	}
}

func newCRTDispatcherWithMemory(
	t *testing.T,
	mem *mmu.MMU,
	module string,
	name string,
	is32 bool,
) (*ntapi.Dispatcher, *ntapi.SynthPE, *mmu.MMU) {
	t.Helper()
	mem.Mode32 = is32
	state := &ntapi.ProcessState{Is32: is32}
	dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
	synth := ntapi.GenerateSynthDLL(mem, module, []string{name}, ntapi.AutoSynthIDBase)
	return dispatcher, synth, mem
}
