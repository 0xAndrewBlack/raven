//go:build guest_windows

package main

import (
	"fmt"
	"math"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func newCRTMathInvocation(t *testing.T, name string, is32 bool) *crtContractInvocation {
	return newCRTMathInvocationForModule(t, "ucrtbase.dll", name, is32)
}

func newCRTMathInvocationForModule(t *testing.T, module, name string, is32 bool) *crtContractInvocation {
	t.Helper()
	dispatcher, synth, mem := newCRTDispatcher(t, module, name, is32)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		SynthByName: map[string]*ntapi.SynthPE{module: synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	return &crtContractInvocation{
		Dispatcher: dispatcher,
		Synth:      synth,
		Mem:        mem,
		Is32:       is32,
		Module:     module,
		Name:       name,
	}
}

func TestCRTMathRegistrationByArchitecture(t *testing.T) {
	for _, semantic := range crtMathSemantics {
		switch semantic.kind {
		case crtMathUnaryDouble, crtMathBinaryDouble, crtMathUnaryFloat, crtMathBinaryFloat:
		default:
			continue
		}
		for _, is32 := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				invocation := newCRTMathInvocation(t, semantic.name, is32)
				_, registered := invocation.Dispatcher.SemanticHandlers()["ucrtbase.dll"][semantic.name]
				if registered == is32 {
					t.Fatalf("registered=%v, want %v", registered, !is32)
				}
			})
		}
	}

	cases := []struct {
		name string
		pe32 bool
		pe64 bool
	}{
		{name: "_fpclass", pe32: true, pe64: true},
		{name: "_dclass", pe32: true, pe64: true},
		{name: "_ldclass", pe32: true, pe64: true},
		{name: "_fpclassf", pe64: true},
	}
	for _, tc := range cases {
		for _, is32 := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/PE%d", tc.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				invocation := newCRTMathInvocation(t, tc.name, is32)
				_, registered := invocation.Dispatcher.SemanticHandlers()["ucrtbase.dll"][tc.name]
				want := tc.pe64
				if is32 {
					want = tc.pe32
				}
				if registered != want {
					t.Fatalf("registered=%v, want %v", registered, want)
				}
			})
		}
	}
}

func TestCRTMathFPClassFloatModuleRegistration(t *testing.T) {
	modules := []string{
		"msvcrt.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll",
		"msvcr110.dll", "msvcr120.dll", "msvcr120_app.dll", "ucrtbase.dll",
	}
	for _, module := range modules {
		for _, is32 := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/PE%d", module, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				invocation := newCRTMathInvocationForModule(t, module, "_fpclassf", is32)
				_, registered := invocation.Dispatcher.SemanticHandlers()[module]["_fpclassf"]
				if registered == is32 {
					t.Fatalf("registered=%v, want %v", registered, !is32)
				}
			})
		}
	}
}

func TestCRTMathFPClassABI(t *testing.T) {
	cases := []struct {
		name string
		bits uint64
		want uint64
	}{
		{name: "positive zero", bits: 0x0000000000000000, want: 0x0040},
		{name: "negative zero", bits: 0x8000000000000000, want: 0x0020},
		{name: "positive subnormal", bits: 0x0000000000000001, want: 0x0080},
		{name: "negative subnormal", bits: 0x8000000000000001, want: 0x0010},
		{name: "positive normal", bits: 0x3ff0000000000000, want: 0x0100},
		{name: "negative normal", bits: 0xbff0000000000000, want: 0x0008},
		{name: "positive infinity", bits: 0x7ff0000000000000, want: 0x0200},
		{name: "negative infinity", bits: 0xfff0000000000000, want: 0x0004},
		{name: "quiet NaN", bits: 0x7ff8000000000001, want: 0x0002},
		{name: "signaling NaN", bits: 0x7ff0000000000001, want: 0x0001},
	}
	for _, is32 := range []bool{true, false} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("PE%d/%s", map[bool]int{true: 32, false: 64}[is32], tc.name), func(t *testing.T) {
				invocation := newCRTMathInvocation(t, "_fpclass", is32)
				result, err := crtMathCallDouble(invocation, []float64{math.Float64frombits(tc.bits)}, false)
				if err != nil || result.Return != tc.want {
					t.Fatalf("return=%#x, want %#x, err=%v", result.Return, tc.want, err)
				}
			})
		}
	}
}

func TestCRTMathDClassABI(t *testing.T) {
	cases := []struct {
		name string
		bits uint64
		want uint64
	}{
		{name: "positive zero", bits: 0x0000000000000000, want: 0},
		{name: "negative zero", bits: 0x8000000000000000, want: 0},
		{name: "positive subnormal", bits: 0x0000000000000001, want: 0xfffffffe},
		{name: "negative subnormal", bits: 0x8000000000000001, want: 0xfffffffe},
		{name: "normal", bits: 0x3ff0000000000000, want: 0xffffffff},
		{name: "infinity", bits: 0x7ff0000000000000, want: 1},
		{name: "quiet NaN", bits: 0x7ff8000000000001, want: 2},
		{name: "signaling NaN", bits: 0x7ff0000000000001, want: 2},
	}
	for _, name := range []string{"_dclass", "_ldclass"} {
		for _, is32 := range []bool{true, false} {
			for _, tc := range cases {
				t.Run(fmt.Sprintf("%s/PE%d/%s", name, map[bool]int{true: 32, false: 64}[is32], tc.name), func(t *testing.T) {
					invocation := newCRTMathInvocation(t, name, is32)
					result, err := crtMathCallDouble(invocation, []float64{math.Float64frombits(tc.bits)}, false)
					if err != nil || result.Return != tc.want {
						t.Fatalf("return=%#x, want %#x, err=%v", result.Return, tc.want, err)
					}
				})
			}
		}
	}
}

func TestCRTMathFPClassFloatABI(t *testing.T) {
	cases := []struct {
		name string
		bits uint32
		want uint64
	}{
		{name: "positive zero", bits: 0x00000000, want: 0x0040},
		{name: "negative zero", bits: 0x80000000, want: 0x0020},
		{name: "positive subnormal", bits: 0x00000001, want: 0x0080},
		{name: "negative subnormal", bits: 0x80000001, want: 0x0010},
		{name: "positive normal", bits: 0x3f800000, want: 0x0100},
		{name: "negative normal", bits: 0xbf800000, want: 0x0008},
		{name: "positive infinity", bits: 0x7f800000, want: 0x0200},
		{name: "negative infinity", bits: 0xff800000, want: 0x0004},
		{name: "quiet NaN", bits: 0x7fc00001, want: 0x0002},
		{name: "signaling NaN", bits: 0x7f800001, want: 0x0001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invocation := newCRTMathInvocation(t, "_fpclassf", false)
			result, err := crtMathCallFloat(invocation, []float32{math.Float32frombits(tc.bits)}, false)
			if err != nil || result.Return != tc.want {
				t.Fatalf("return=%#x, want %#x, err=%v", result.Return, tc.want, err)
			}
		})
	}
}

func TestCRTMathFixedOracleContracts(t *testing.T) {
	for _, semantic := range crtMathSemantics {
		for _, architecture := range semantic.arch {
			is32 := architecture == "i386"
			t.Run(semantic.name+"/"+architecture, func(t *testing.T) {
				invocation := newCRTMathInvocation(t, semantic.name, is32)
				crtExerciseMathContract(invocation, semantic)
				if len(invocation.errors) != 0 {
					t.Fatalf("contract errors: %v", invocation.errors)
				}
				if len(invocation.calls) != 2 {
					t.Fatalf("contract calls=%d, want 2", len(invocation.calls))
				}
				for index, call := range invocation.calls {
					if call.failed || call.assertions == 0 || !call.stackPreserved {
						t.Fatalf("call %d failed: %#v", index, call)
					}
				}
			})
		}
	}
}
