//go:build guest_windows

package main

import (
	"fmt"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestCRTIntegerHelperContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtIntegerHelperSemantics {
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
				if !ok || !evidence.passed {
					t.Fatalf("%s contract failed: %#v", semantic.name, evidence)
				}
			})
		}
	}
}

func TestCRTRotateContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtRotateSemantics {
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", semantic.name, is32)
				hctx := &HandlerCtx{
					Disp:        dispatcher,
					Mem:         mem,
					SynthByName: map[string]*ntapi.SynthPE{"msvcrt.dll": synth},
				}
				registerCRTDefinitions(hctx, crtSemanticDefinitions())
				run := newCRTContractRun()
				run.Execute(hctx)
				key := crtContractKey{
					Module:           "msvcrt.dll",
					Name:             semantic.name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: semantic.id,
					Signature:        "cdecl(long long)",
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.passed {
					t.Fatalf("%s contract failed: %#v", semantic.name, evidence)
				}
			})
		}
	}
}
