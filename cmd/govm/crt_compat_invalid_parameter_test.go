//go:build guest_windows

package main

import (
	"fmt"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestCRTInvalidParameterContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtInvalidParameterSemantics {
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				mem := mmu.New()
				mem.Mode32 = is32
				state := &ntapi.ProcessState{Is32: is32}
				dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
				synth := ntapi.GenerateSynthDLL(mem, semantic.module, []string{semantic.name}, ntapi.AutoSynthIDBase)
				hctx := &HandlerCtx{
					Disp:        dispatcher,
					Mem:         mem,
					ProcState:   state,
					SynthByName: map[string]*ntapi.SynthPE{semantic.module: synth},
				}
				registerCRTDefinitions(hctx, crtSemanticDefinitions())
				run := newCRTContractRun()
				run.Execute(hctx)
				key := crtContractKey{
					Module:           semantic.module,
					Name:             semantic.name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: semantic.id,
					Signature:        semantic.signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed {
					t.Fatalf("invalid-parameter contract failed: %#v", evidence)
				}
			})
		}
	}
}

func TestCRTInvalidParameterWithoutHandlerAbortsGuest(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		mem := mmu.New()
		mem.Mode32 = is32
		cpu := x64.New(mem)
		cpu.Mode32 = is32
		cpu.Resume()
		ctx := &ntapi.TrapContext{
			CPU:   cpu,
			Mem:   mem,
			State: &ntapi.ProcessState{Is32: is32},
		}

		if !crtInvokeInvalidParameter(ctx, 0, 0, 0, 0, 0) {
			t.Fatalf("PE32=%t invalid parameter was not handled", is32)
		}
		err, ok := cpu.Run().(*arch.ExitError)
		if !ok || err.Code != int(crtInvalidRuntimeStatus) {
			t.Fatalf("PE32=%t abort = %#v", is32, err)
		}
	}
}
