//go:build guest_windows

package main

import (
	"math"
	"reflect"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

// The x86 CRT returns scalar floating point values through x87. Raven's
// TrapContext exposes the Windows x64 XMM contract, but has no x87 return
// setter. Floating arithmetic is therefore registered only for win64. The
// integer predicates below are safe on both architectures because their
// result is returned in EAX/RAX and their double input is read from the
// documented PE32 stack layout when needed.
var crtMathModules = []string{
	"msvcrt20.dll", "msvcrt40.dll", "msvcrt.dll", "msvcr70.dll", "msvcr71.dll",
	"msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll",
	"msvcr120_app.dll", "msvcrtd.dll", "ucrtbase.dll", "vcruntime140.dll", "vcruntime140_1.dll",
}

var crtMathModernModules = []string{
	"msvcr120.dll", "msvcr120_app.dll", "ucrtbase.dll",
}

type crtMathKind uint8

const (
	crtMathUnaryDouble crtMathKind = iota
	crtMathBinaryDouble
	crtMathUnaryFloat
	crtMathBinaryFloat
	crtMathPredicateDouble
	crtMathPredicateFloat
	crtMathClassDouble
	crtMathClassFloat
)

type crtMathSemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	arch      []string
	kind      crtMathKind
	unaryD    func(float64) float64
	binaryD   func(float64, float64) float64
	unaryF    func(float32) float32
	binaryF   func(float32, float32) float32
	predicate func(float64) uint32
	classify  func(float64) uint32
	classifyF func(float32) uint32
}

func init() {
	registerCRTProvider(registerCRTMathDefinitions)
	for _, semantic := range crtMathSemantics {
		registerCRTMathContractCases(semantic)
	}
}

var crtMathSemantics = []crtMathSemantic{
	{name: "fabs", id: "crt.math.fabs64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Abs},
	{name: "floor", id: "crt.math.floor64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Floor},
	{name: "ceil", id: "crt.math.ceil64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Ceil},
	{name: "trunc", id: "crt.math.trunc64.v1", signature: "cdecl(double)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Trunc},
	{name: "round", id: "crt.math.round64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Round},
	{name: "fmod", id: "crt.math.fmod64.v1", signature: "cdecl(double double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathBinaryDouble, binaryD: math.Mod},
	{name: "copysign", id: "crt.math.copysign64.v1", signature: "cdecl(double double)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathBinaryDouble, binaryD: math.Copysign},
	{name: "sqrt", id: "crt.math.sqrt64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Sqrt},
	{name: "exp", id: "crt.math.exp64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Exp},
	{name: "log", id: "crt.math.log64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Log},
	{name: "log10", id: "crt.math.log10.64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Log10},
	{name: "sin", id: "crt.math.sin64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Sin},
	{name: "cos", id: "crt.math.cos64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Cos},
	{name: "tan", id: "crt.math.tan64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathUnaryDouble, unaryD: math.Tan},
	{name: "atan2", id: "crt.math.atan2.64.v1", signature: "cdecl(double double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathBinaryDouble, binaryD: math.Atan2},
	{name: "pow", id: "crt.math.pow64.v1", signature: "cdecl(double double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathBinaryDouble, binaryD: math.Pow},

	{name: "fabsf", id: "crt.math.fabs32.v1", signature: "cdecl(float)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathUnaryFloat, unaryF: func(v float32) float32 { return float32(math.Abs(float64(v))) }},
	{name: "roundf", id: "crt.math.round32.v1", signature: "cdecl(float)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathUnaryFloat, unaryF: func(v float32) float32 { return float32(math.Round(float64(v))) }},
	{name: "truncf", id: "crt.math.trunc32.v1", signature: "cdecl(float)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathUnaryFloat, unaryF: func(v float32) float32 { return float32(math.Trunc(float64(v))) }},
	{name: "copysignf", id: "crt.math.copysign32.v1", signature: "cdecl(float float)", modules: crtMathModernModules, arch: []string{"win64"}, kind: crtMathBinaryFloat, binaryF: func(a, b float32) float32 { return float32(math.Copysign(float64(a), float64(b))) }},
	{name: "powf", id: "crt.math.pow32.v1", signature: "cdecl(float float)", modules: []string{"ucrtbase.dll"}, arch: []string{"win64"}, kind: crtMathBinaryFloat, binaryF: func(a, b float32) float32 { return float32(math.Pow(float64(a), float64(b))) }},

	{name: "_finite", id: "crt.math.finite64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"i386", "win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return 0
		}
		return 1
	}},
	{name: "finite", id: "crt.math.finite64.public.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return 0
		}
		return 1
	}},
	{name: "_isnan", id: "crt.math.isnan64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"i386", "win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsNaN(v) {
			return 1
		}
		return 0
	}},
	{name: "isnan", id: "crt.math.isnan64.public.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsNaN(v) {
			return 1
		}
		return 0
	}},
	{name: "isinf", id: "crt.math.isinf64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsInf(v, 0) {
			return 1
		}
		return 0
	}},
	{name: "_isinf", id: "crt.math.isinf64.private.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"win64"}, kind: crtMathPredicateDouble, predicate: func(v float64) uint32 {
		if math.IsInf(v, 0) {
			return 1
		}
		return 0
	}},

	{name: "_fpclass", id: "crt.math.fpclass64.v1", signature: "cdecl(double)", modules: crtMathModules, arch: []string{"i386", "win64"}, kind: crtMathClassDouble, classify: crtMathFPClass},
	{name: "_dclass", id: "crt.math.dclass64.v1", signature: "cdecl(double)", modules: crtMathModernModules, arch: []string{"i386", "win64"}, kind: crtMathClassDouble, classify: crtMathDClass},
	{name: "_ldclass", id: "crt.math.ldclass64.v1", signature: "cdecl(double)", modules: crtMathModernModules, arch: []string{"i386", "win64"}, kind: crtMathClassDouble, classify: crtMathDClass},
	{name: "_fpclassf", id: "crt.math.fpclass32.v1", signature: "cdecl(float)", modules: []string{"msvcrt.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll", "msvcr120.dll", "msvcr120_app.dll", "ucrtbase.dll"}, arch: []string{"win64"}, kind: crtMathClassFloat, classifyF: crtMathFPClassFloat},
}

func registerCRTMathDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtMathSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   append([]string(nil), semantic.modules...),
			AllowedArch:      append([]string(nil), semantic.arch...),
			Handler:          crtMathHandler(semantic),
		})
	}
}

func crtMathHandler(semantic crtMathSemantic) ntapi.TrapHandler {
	switch semantic.kind {
	case crtMathUnaryDouble:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(semantic.unaryD(crtMathDoubleArg(ctx, 0)))
			return 0
		}
	case crtMathBinaryDouble:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetFloatReturn(semantic.binaryD(crtMathDoubleArg(ctx, 0), crtMathDoubleArg(ctx, 1)))
			return 0
		}
	case crtMathUnaryFloat:
		return func(ctx *ntapi.TrapContext) uint32 {
			crtMathSetFloatReturn(ctx, semantic.unaryF(crtMathFloatArg(ctx, 0)))
			return 0
		}
	case crtMathBinaryFloat:
		return func(ctx *ntapi.TrapContext) uint32 {
			crtMathSetFloatReturn(ctx, semantic.binaryF(crtMathFloatArg(ctx, 0), crtMathFloatArg(ctx, 1)))
			return 0
		}
	case crtMathPredicateDouble:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(semantic.predicate(crtMathDoubleArg(ctx, 0))))
			return 0
		}
	case crtMathClassDouble:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(semantic.classify(crtMathDoubleArg(ctx, 0))))
			return 0
		}
	case crtMathPredicateFloat:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(semantic.predicate(float64(crtMathFloatArg(ctx, 0)))))
			return 0
		}
	case crtMathClassFloat:
		return func(ctx *ntapi.TrapContext) uint32 {
			ctx.SetReturn(uint64(semantic.classifyF(crtMathFloatArg(ctx, 0))))
			return 0
		}
	default:
		return nil
	}
}

func crtMathDoubleArg(ctx *ntapi.TrapContext, index int) float64 {
	if ctx.CPU.GetArch() == arch.ArchI386 {
		lo := uint64(uint32(ctx.Arg(index * 2)))
		hi := uint64(uint32(ctx.Arg(index*2 + 1)))
		return math.Float64frombits(lo | hi<<32)
	}
	return ctx.FloatArg(index)
}

func crtMathFloatArg(ctx *ntapi.TrapContext, index int) float32 {
	if ctx.CPU.GetArch() == arch.ArchI386 {
		return math.Float32frombits(uint32(ctx.Arg(index)))
	}
	if xmm, ok := ctx.CPU.(ntapi.XMMAccess); ok {
		return math.Float32frombits(uint32(xmm.ReadXMM(index)))
	}
	return 0
}

func crtMathSetFloatReturn(ctx *ntapi.TrapContext, value float32) {
	if xmm, ok := ctx.CPU.(ntapi.XMMAccess); ok {
		xmm.WriteXMM(0, uint64(math.Float32bits(value)))
		ctx.ReturnOverridden = true
	}
}

const (
	crtFPClassSNAN = 0x0001
	crtFPClassQNAN = 0x0002
	crtFPClassNINF = 0x0004
	crtFPClassNN   = 0x0008
	crtFPClassND   = 0x0010
	crtFPClassNZ   = 0x0020
	crtFPClassPZ   = 0x0040
	crtFPClassPD   = 0x0080
	crtFPClassPN   = 0x0100
	crtFPClassPINF = 0x0200

	crtFPTypeInfinite  = 1
	crtFPTypeNaN       = 2
	crtFPTypeNormal    = ^uint32(0)
	crtFPTypeSubnormal = ^uint32(1)
	crtFPTypeZero      = 0
)

func crtMathFPClass(value float64) uint32 {
	bits := math.Float64bits(value)
	sign := bits>>63 != 0
	exponent := (bits >> 52) & 0x7ff
	fraction := bits & ((uint64(1) << 52) - 1)
	if exponent == 0x7ff {
		if fraction == 0 {
			if sign {
				return crtFPClassNINF
			}
			return crtFPClassPINF
		}
		if fraction&(uint64(1)<<51) == 0 {
			return crtFPClassSNAN
		}
		return crtFPClassQNAN
	}
	if exponent == 0 && fraction == 0 {
		if sign {
			return crtFPClassNZ
		}
		return crtFPClassPZ
	}
	if exponent == 0 {
		if sign {
			return crtFPClassND
		}
		return crtFPClassPD
	}
	if sign {
		return crtFPClassNN
	}
	return crtFPClassPN
}

func crtMathFPClassFloat(value float32) uint32 {
	bits := math.Float32bits(value)
	sign := bits>>31 != 0
	exponent := (bits >> 23) & 0xff
	fraction := bits & ((uint32(1) << 23) - 1)
	if exponent == 0xff {
		if fraction == 0 {
			if sign {
				return crtFPClassNINF
			}
			return crtFPClassPINF
		}
		if fraction&(uint32(1)<<22) == 0 {
			return crtFPClassSNAN
		}
		return crtFPClassQNAN
	}
	if exponent == 0 && fraction == 0 {
		if sign {
			return crtFPClassNZ
		}
		return crtFPClassPZ
	}
	if exponent == 0 {
		if sign {
			return crtFPClassND
		}
		return crtFPClassPD
	}
	if sign {
		return crtFPClassNN
	}
	return crtFPClassPN
}

func crtMathDClass(value float64) uint32 {
	bits := math.Float64bits(value)
	exponent := (bits >> 52) & 0x7ff
	fraction := bits & ((uint64(1) << 52) - 1)
	if exponent == 0x7ff {
		if fraction != 0 {
			return crtFPTypeNaN
		}
		return crtFPTypeInfinite
	}
	if exponent == 0 {
		if fraction == 0 {
			return crtFPTypeZero
		}
		return crtFPTypeSubnormal
	}
	return crtFPTypeNormal
}

func registerCRTMathContractCases(semantic crtMathSemantic) {
	for _, module := range semantic.modules {
		for _, architecture := range semantic.arch {
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					crtExerciseMathContract(invocation, semantic)
				},
			})
		}
	}
}

type crtMathDoubleOracle struct {
	args []uint64
	want uint64
}

type crtMathFloatOracle struct {
	args []uint32
	want uint64
}

var crtMathDoubleOracles = map[string][]crtMathDoubleOracle{
	"fabs":     {{args: []uint64{0xc00a000000000000}, want: 0x400a000000000000}, {args: []uint64{0x4006000000000000}, want: 0x4006000000000000}},
	"floor":    {{args: []uint64{0xc00a000000000000}, want: 0xc010000000000000}, {args: []uint64{0x4006000000000000}, want: 0x4000000000000000}},
	"ceil":     {{args: []uint64{0xc00a000000000000}, want: 0xc008000000000000}, {args: []uint64{0x4006000000000000}, want: 0x4008000000000000}},
	"trunc":    {{args: []uint64{0xc00a000000000000}, want: 0xc008000000000000}, {args: []uint64{0x4006000000000000}, want: 0x4000000000000000}},
	"round":    {{args: []uint64{0xc00a000000000000}, want: 0xc008000000000000}, {args: []uint64{0x4006000000000000}, want: 0x4008000000000000}},
	"fmod":     {{args: []uint64{0x401e000000000000, 0x4000000000000000}, want: 0x3ff8000000000000}, {args: []uint64{0xc00c000000000000, 0x4000000000000000}, want: 0xbff8000000000000}},
	"copysign": {{args: []uint64{0xc00c000000000000, 0x0000000000000000}, want: 0x400c000000000000}, {args: []uint64{0x400c000000000000, 0x8000000000000000}, want: 0xc00c000000000000}},
	"sqrt":     {{args: []uint64{0x4010000000000000}, want: 0x4000000000000000}, {args: []uint64{0x4022000000000000}, want: 0x4008000000000000}},
	"exp":      {{args: []uint64{0x0000000000000000}, want: 0x3ff0000000000000}, {args: []uint64{0x7ff0000000000000}, want: 0x7ff0000000000000}},
	"log":      {{args: []uint64{0x3ff0000000000000}, want: 0x0000000000000000}, {args: []uint64{0x7ff0000000000000}, want: 0x7ff0000000000000}},
	"log10":    {{args: []uint64{0x3ff0000000000000}, want: 0x0000000000000000}, {args: []uint64{0x4024000000000000}, want: 0x3ff0000000000000}},
	"sin":      {{args: []uint64{0x0000000000000000}, want: 0x0000000000000000}, {args: []uint64{0x8000000000000000}, want: 0x8000000000000000}},
	"cos":      {{args: []uint64{0x0000000000000000}, want: 0x3ff0000000000000}, {args: []uint64{0x400921fb54442d18}, want: 0xbff0000000000000}},
	"tan":      {{args: []uint64{0x0000000000000000}, want: 0x0000000000000000}, {args: []uint64{0x8000000000000000}, want: 0x8000000000000000}},
	"atan2":    {{args: []uint64{0x0000000000000000, 0x3ff0000000000000}, want: 0x0000000000000000}, {args: []uint64{0x8000000000000000, 0x3ff0000000000000}, want: 0x8000000000000000}},
	"pow":      {{args: []uint64{0x4000000000000000, 0x4008000000000000}, want: 0x4020000000000000}, {args: []uint64{0x4010000000000000, 0x3fe0000000000000}, want: 0x4000000000000000}},
	"_finite":  {{args: []uint64{0x400c000000000000}, want: 1}, {args: []uint64{0x7ff0000000000000}, want: 0}},
	"finite":   {{args: []uint64{0x400c000000000000}, want: 1}, {args: []uint64{0x7ff0000000000000}, want: 0}},
	"_isnan":   {{args: []uint64{0x7ff8000000000001}, want: 1}, {args: []uint64{0x400c000000000000}, want: 0}},
	"isnan":    {{args: []uint64{0x7ff8000000000001}, want: 1}, {args: []uint64{0x400c000000000000}, want: 0}},
	"isinf":    {{args: []uint64{0x7ff0000000000000}, want: 1}, {args: []uint64{0x400c000000000000}, want: 0}},
	"_isinf":   {{args: []uint64{0x7ff0000000000000}, want: 1}, {args: []uint64{0x400c000000000000}, want: 0}},
	"_fpclass": {{args: []uint64{0x0000000000000001}, want: 0x0080}, {args: []uint64{0x8000000000000001}, want: 0x0010}},
	"_dclass":  {{args: []uint64{0x7ff8000000000001}, want: 2}, {args: []uint64{0x0000000000000001}, want: 0xfffffffe}},
	"_ldclass": {{args: []uint64{0x7ff0000000000000}, want: 1}, {args: []uint64{0x0000000000000000}, want: 0}},
}

var crtMathFloatOracles = map[string][]crtMathFloatOracle{
	"fabsf":     {{args: []uint32{0xc0500000}, want: 0x40500000}, {args: []uint32{0x40300000}, want: 0x40300000}},
	"roundf":    {{args: []uint32{0xc0500000}, want: 0xc0400000}, {args: []uint32{0x40300000}, want: 0x40400000}},
	"truncf":    {{args: []uint32{0xc0500000}, want: 0xc0400000}, {args: []uint32{0x40300000}, want: 0x40000000}},
	"copysignf": {{args: []uint32{0xc0600000, 0x00000000}, want: 0x40600000}, {args: []uint32{0x40600000, 0x80000000}, want: 0xc0600000}},
	"powf":      {{args: []uint32{0x40000000, 0x40400000}, want: 0x41000000}, {args: []uint32{0x40800000, 0x3f000000}, want: 0x40000000}},
	"_fpclassf": {{args: []uint32{0x00000001}, want: 0x0080}, {args: []uint32{0x80000001}, want: 0x0010}},
}

func crtExerciseMathContract(invocation *crtContractInvocation, semantic crtMathSemantic) {
	switch semantic.kind {
	case crtMathUnaryDouble, crtMathBinaryDouble, crtMathPredicateDouble, crtMathClassDouble:
		oracles := crtMathDoubleOracles[semantic.name]
		for _, oracle := range oracles {
			values := make([]float64, len(oracle.args))
			for index, bits := range oracle.args {
				values[index] = math.Float64frombits(bits)
			}
			returnFloat := semantic.kind == crtMathUnaryDouble || semantic.kind == crtMathBinaryDouble
			result, err := crtMathCallDouble(invocation, values, returnFloat)
			if err != nil {
				invocation.Failf("dispatch %s contract: %v", semantic.name, err)
				return
			}
			result.ExpectReturn(oracle.want)
		}
		if len(oracles) == 0 {
			invocation.Failf("missing fixed oracle for %s", semantic.name)
		}
	case crtMathUnaryFloat, crtMathBinaryFloat, crtMathPredicateFloat, crtMathClassFloat:
		oracles := crtMathFloatOracles[semantic.name]
		for _, oracle := range oracles {
			values := make([]float32, len(oracle.args))
			for index, bits := range oracle.args {
				values[index] = math.Float32frombits(bits)
			}
			returnFloat := semantic.kind == crtMathUnaryFloat || semantic.kind == crtMathBinaryFloat
			result, err := crtMathCallFloat(invocation, values, returnFloat)
			if err != nil {
				invocation.Failf("dispatch %s contract: %v", semantic.name, err)
				return
			}
			result.ExpectReturn(oracle.want)
		}
		if len(oracles) == 0 {
			invocation.Failf("missing fixed oracle for %s", semantic.name)
		}
	}
}

func crtMathCallDouble(invocation *crtContractInvocation, values []float64, returnFloat bool) (crtContractResult, error) {
	result := crtContractResult{invocation: invocation, callIndex: -1}
	if invocation == nil || invocation.Dispatcher == nil || invocation.Synth == nil || invocation.Mem == nil {
		return result, &crtMathContractError{"invalid invocation"}
	}
	addr, ok := invocation.Synth.Exports[invocation.Name]
	if !ok {
		return result, &crtMathContractError{"missing export"}
	}
	id, ok := invocation.Synth.StubIDs[addr]
	if !ok {
		return result, &crtMathContractError{"export is not a trap route"}
	}
	registration, ok := invocation.Dispatcher.SemanticHandlers()[invocation.Module][invocation.Name]
	if !ok || registration.Handler == nil {
		return result, &crtMathContractError{"missing semantic handler"}
	}
	stack := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if stack == 0 {
		return result, &crtMathContractError{"unable to allocate stack"}
	}
	cpu := x64.New(invocation.Mem)
	cpu.Mode32 = invocation.Is32
	if invocation.Is32 {
		if err := invocation.Mem.Write32(stack, 0x7F000001); err != nil {
			return result, err
		}
		for index, value := range values {
			bits := math.Float64bits(value)
			base := stack + 4 + uint64(index*8)
			if err := invocation.Mem.Write32(base, uint32(bits)); err != nil {
				return result, err
			}
			if err := invocation.Mem.Write32(base+4, uint32(bits>>32)); err != nil {
				return result, err
			}
		}
	} else {
		if err := invocation.Mem.Write64(stack, 0x7F000001); err != nil {
			return result, err
		}
		for index, value := range values {
			cpu.WriteXMM(index, math.Float64bits(value))
		}
	}
	cpu.SetSP(stack)
	cpu.Regs[0] = uint64(id)
	call := crtContractCall{args: make([]uint64, len(values)), handlerPointer: reflect.ValueOf(registration.Handler).Pointer()}
	for index, value := range values {
		call.args[index] = math.Float64bits(value)
	}
	invocation.Dispatcher.Handle(cpu)
	if returnFloat && !invocation.Is32 {
		call.returnValue = cpu.ReadXMM(0)
	} else {
		call.returnValue = cpu.Regs[0]
	}
	call.stackPreserved = cpu.GetSP() == stack
	invocation.calls = append(invocation.calls, call)
	result.callIndex = len(invocation.calls) - 1
	result.Return = call.returnValue
	return result, nil
}

func crtMathCallFloat(invocation *crtContractInvocation, values []float32, returnFloat bool) (crtContractResult, error) {
	result := crtContractResult{invocation: invocation, callIndex: -1}
	if invocation == nil || invocation.Dispatcher == nil || invocation.Synth == nil || invocation.Mem == nil || invocation.Is32 {
		return result, &crtMathContractError{"float contract requires win64 XMM ABI"}
	}
	addr, ok := invocation.Synth.Exports[invocation.Name]
	if !ok {
		return result, &crtMathContractError{"missing export"}
	}
	id, ok := invocation.Synth.StubIDs[addr]
	if !ok {
		return result, &crtMathContractError{"export is not a trap route"}
	}
	registration, ok := invocation.Dispatcher.SemanticHandlers()[invocation.Module][invocation.Name]
	if !ok || registration.Handler == nil {
		return result, &crtMathContractError{"missing semantic handler"}
	}
	stack := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if stack == 0 {
		return result, &crtMathContractError{"unable to allocate stack"}
	}
	if err := invocation.Mem.Write64(stack, 0x7F000001); err != nil {
		return result, err
	}
	cpu := x64.New(invocation.Mem)
	for index, value := range values {
		cpu.WriteXMM(index, uint64(math.Float32bits(value)))
	}
	cpu.SetSP(stack)
	cpu.Regs[0] = uint64(id)
	call := crtContractCall{args: make([]uint64, len(values)), handlerPointer: reflect.ValueOf(registration.Handler).Pointer()}
	for index, value := range values {
		call.args[index] = uint64(math.Float32bits(value))
	}
	invocation.Dispatcher.Handle(cpu)
	if returnFloat {
		call.returnValue = cpu.ReadXMM(0) & 0xffffffff
	} else {
		call.returnValue = cpu.Regs[0]
	}
	call.stackPreserved = cpu.GetSP() == stack
	invocation.calls = append(invocation.calls, call)
	result.callIndex = len(invocation.calls) - 1
	result.Return = call.returnValue
	return result, nil
}

type crtMathContractError struct{ message string }

func (e *crtMathContractError) Error() string { return e.message }
