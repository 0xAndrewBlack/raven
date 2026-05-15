//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func TestCRTStringContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtStringSemantics {
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

func TestCRTStringCompareMatchesByteOrdering(t *testing.T) {
	rng := rand.New(rand.NewSource(0x535452494e47))
	for _, is32 := range []bool{true, false} {
		dispatcher, synth, mem := newCRTDispatcher(t, "msvcrt.dll", "strcmp", is32)
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
			Is32:       is32,
			Module:     "msvcrt.dll",
			Name:       "strcmp",
		}
		for iteration := 0; iteration < 250; iteration++ {
			leftValue := make([]byte, rng.Intn(32))
			rightValue := make([]byte, rng.Intn(32))
			for index := range leftValue {
				leftValue[index] = byte(1 + rng.Intn(255))
			}
			for index := range rightValue {
				rightValue[index] = byte(1 + rng.Intn(255))
			}
			left := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			right := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(left, append(append([]byte(nil), leftValue...), 0)); err != nil {
				t.Fatal(err)
			}
			if err := mem.WriteBytes(right, append(append([]byte(nil), rightValue...), 0)); err != nil {
				t.Fatal(err)
			}
			got, err := invocation.Call(left, right)
			if err != nil {
				t.Fatal(err)
			}
			gotSign := compareSign(int32(got))
			wantSign := compareSign(int32(bytes.Compare(leftValue, rightValue)))
			if gotSign != wantSign {
				t.Fatalf("iteration %d: strcmp sign=%d, want %d", iteration, gotSign, wantSign)
			}
		}
	}
}

func compareSign(value int32) int {
	if value < 0 {
		return -1
	}
	if value > 0 {
		return 1
	}
	return 0
}
