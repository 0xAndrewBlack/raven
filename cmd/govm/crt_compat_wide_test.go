//go:build guest_windows

package main

import (
	"fmt"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestCRTWideContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtWideSemantics {
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
					Signature:        semantic.signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed {
					t.Fatalf("%s contract failed: %#v", semantic.name, evidence)
				}
			})
		}
	}
}
