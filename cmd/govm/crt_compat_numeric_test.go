//go:build guest_windows

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func newCRTNumericInvocation(t *testing.T, name string, is32 bool) (*crtContractInvocation, *mmu.MMU) {
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

func TestCRTNumericContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtNumericSemantics {
			semantic := semantic
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				invocation, _ := newCRTNumericInvocation(t, semantic.name, is32)
				run := newCRTContractRun()
				run.Execute(&HandlerCtx{
					Disp:        invocation.Dispatcher,
					Mem:         invocation.Mem,
					SynthByName: map[string]*ntapi.SynthPE{"ucrtbase.dll": invocation.Synth},
				})
				key := crtContractKey{
					Module:           "ucrtbase.dll",
					Name:             semantic.name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: semantic.id,
					Signature:        semantic.signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed || evidence.callCount < 2 || evidence.assertionCount < 3 {
					t.Fatalf("numeric contract failed: %#v", evidence)
				}
			})
		}
	}
}

func TestCRTNumericCorpusRoutes(t *testing.T) {
	corpus := loadCRTCorpusData(t)
	routes := make(map[string]bool)
	for _, route := range corpus.Routes {
		routes[route.Module+"\x00"+strings.ToLower(route.Name)+"\x00"+route.Architecture] = true
	}
	for _, semantic := range crtNumericSemantics {
		for _, module := range semantic.modules {
			for _, architecture := range []string{"i386", "win64"} {
				key := normalizeCRTModule(module) + "\x00" + strings.ToLower(semantic.name) + "\x00" + architecture
				if !routes[key] {
					t.Errorf("numeric definition %s claims absent corpus route %s/%s", semantic.name, module, architecture)
				}
			}
		}
	}
}

func TestCRTNumericParsingEdges(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocation, mem := newCRTNumericInvocation(t, "strtol", is32)
			input := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(input, []byte(" \t-0x2aZZ\x00")); err != nil {
				t.Fatal(err)
			}
			endptr := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(endptr, 0xA5A5A5A5); err != nil {
				t.Fatal(err)
			}
			crtNumericSetErrno(&ntapi.TrapContext{Mem: mem}, 0)
			negative := int32(-42)
			got, err := invocation.Call(input, endptr, 0)
			if err != nil || got != uint64(uint32(negative)) {
				t.Fatalf("strtol parse got %#x, err=%v", got, err)
			}
			end, err := crtNumericContractReadPointer(invocation, endptr)
			if err != nil || end != input+7 {
				t.Fatalf("strtol endptr %#x, err=%v", end, err)
			}

			crtNumericSetErrno(&ntapi.TrapContext{Mem: mem}, 0)
			got, err = invocation.Call(input, endptr, 1)
			end, endErr := crtNumericContractReadPointer(invocation, endptr)
			if err != nil || endErr != nil || got != 0 || end != input || crtNumericErrnoValue(mem) != crtNumericErrnoEINVAL {
				t.Fatalf("invalid base got=%#x end=%#x callErr=%v endErr=%v errno=%d", got, end, err, endErr, crtNumericErrnoValue(mem))
			}

			overflow := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(overflow, []byte("2147483648\x00")); err != nil {
				t.Fatal(err)
			}
			crtNumericSetErrno(&ntapi.TrapContext{Mem: mem}, 0)
			got, err = invocation.Call(overflow, endptr, 10)
			if err != nil || got != uint64(^uint32(0)>>1) || crtNumericErrnoValue(mem) != crtNumericErrnoERANGE {
				t.Fatalf("overflow got=%#x err=%v errno=%d", got, err, crtNumericErrnoValue(mem))
			}

			bad, err := invocation.Call(0x1234, 0, 10)
			if err != nil || bad != 0 {
				t.Fatalf("faulting source got=%#x err=%v", bad, err)
			}
			bad, err = invocation.Call(input, 0x2345, 10)
			if err != nil || bad != 0 {
				t.Fatalf("faulting endptr got=%#x err=%v", bad, err)
			}
		})
	}

	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("wide-PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocation, mem := newCRTNumericInvocation(t, "wcstoll", is32)
			input := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(input, crtWideASCII(" -9223372036854775808tail")); err != nil {
				t.Fatal(err)
			}
			endptr := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			got, err := invocation.CallReturn64(input, endptr, 10)
			end, endErr := crtNumericContractReadPointer(invocation, endptr)
			if err != nil || endErr != nil || got != uint64(1<<63) || end != input+uint64(21*2) {
				t.Fatalf("wcstoll got=%#x end=%#x callErr=%v endErr=%v", got, end, err, endErr)
			}

			invocation, mem = newCRTNumericInvocation(t, "strtoull", is32)
			input = mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.WriteBytes(input, []byte("-42\x00")); err != nil {
				t.Fatal(err)
			}
			got, err = invocation.CallReturn64(input, 0, 10)
			if err != nil || got != ^uint64(41) {
				t.Fatalf("strtoull negative got=%#x err=%v", got, err)
			}
		})
	}
}

func TestCRTNumericFormattingEdges(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtNumericSemantics {
			if semantic.mode != "itoa" {
				continue
			}
			semantic := semantic
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				invocation, mem := newCRTNumericInvocation(t, semantic.name, is32)
				buffer := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				negative := int32(-43)
				args := []uint64{uint64(uint32(negative)), buffer, 16}
				want := []byte("ffffffd5\x00")
				if !semantic.signed {
					args[0] = 0xfeedbeef
					want = []byte("feedbeef\x00")
				}
				if semantic.wide {
					units := make([]uint16, len(want))
					for index, value := range want {
						units[index] = uint16(value)
					}
					want = crtWideBytes(units[:len(units)-1], true)
				}
				if err := mem.WriteBytes(buffer, bytes.Repeat([]byte{0xCC}, len(want))); err != nil {
					t.Fatal(err)
				}
				got, err := invocation.Call(args...)
				if err != nil || got != buffer {
					t.Fatalf("formatter return=%#x err=%v", got, err)
				}
				actual, err := mem.ReadBytes(buffer, len(want))
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatalf("formatter output=%x want=%x err=%v", actual, want, err)
				}

				invalidBuffer := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
				if err := mem.WriteBytes(invalidBuffer, []byte("sentinel\x00")); err != nil {
					t.Fatal(err)
				}
				args[1], args[2] = invalidBuffer, 1
				got, err = invocation.Call(args...)
				if err != nil || got != 0 {
					t.Fatalf("invalid radix return=%#x err=%v", got, err)
				}
				if actual, readErr := mem.ReadBytes(invalidBuffer, 9); readErr != nil || !bytes.Equal(actual, []byte("sentinel\x00")) {
					t.Fatalf("invalid radix modified output=%x err=%v", actual, readErr)
				}

				got, err = invocation.Call(args[0], 0x3456, 16)
				if err != nil || got != 0 {
					t.Fatalf("faulting output return=%#x err=%v", got, err)
				}
			})
		}
	}
}
