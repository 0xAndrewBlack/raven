//go:build guest_windows

package main

import (
	"math/bits"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var crtAbsModules = append([]string(nil), crtStringModules...)

var crtByteSwapModules = []string{
	"msvcr80.dll",
	"msvcr90.dll",
	"msvcr100.dll",
	"msvcr110.dll",
	"msvcr120.dll",
	"msvcr120_app.dll",
	"ucrtbase.dll",
}

type crtIntegerHelperSemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	handler   ntapi.TrapHandler
	inputs    [2]uint64
	outputs   [2]uint64
}

var crtIntegerHelperSemantics = []crtIntegerHelperSemantic{
	{
		name: "abs", id: "crt.integer.abs32.v1", signature: "cdecl(long)", modules: crtAbsModules,
		handler: crtAbs32, inputs: [2]uint64{0xFFFFFFEF, 29}, outputs: [2]uint64{17, 29},
	},
	{
		name: "labs", id: "crt.integer.labs32.v1", signature: "cdecl(long)", modules: crtAbsModules,
		handler: crtAbs32, inputs: [2]uint64{0xFFFFFFE1, 47}, outputs: [2]uint64{31, 47},
	},
	{
		name: "_byteswap_ushort", id: "crt.integer.byteswap16.v1", signature: "cdecl(long)", modules: crtByteSwapModules,
		handler: crtByteSwap16, inputs: [2]uint64{0x1234, 0xA1B2}, outputs: [2]uint64{0x3412, 0xB2A1},
	},
	{
		name: "_byteswap_ulong", id: "crt.integer.byteswap32.v1", signature: "cdecl(long)", modules: crtByteSwapModules,
		handler: crtByteSwap32, inputs: [2]uint64{0x12345678, 0xA1B2C3D4}, outputs: [2]uint64{0x78563412, 0xD4C3B2A1},
	},
}

func init() {
	registerCRTProvider(registerCRTIntegerHelperDefinitions)
	for _, semantic := range crtIntegerHelperSemantics {
		registerCRTIntegerHelperContractCases(semantic)
	}
}

func registerCRTIntegerHelperDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtIntegerHelperSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   append([]string(nil), semantic.modules...),
			AllowedArch:      []string{"i386", "win64"},
			Handler:          semantic.handler,
		})
	}
}

func crtAbs32(ctx *ntapi.TrapContext) uint32 {
	value := int32(ctx.Arg(0))
	if value < 0 {
		value = -value
	}
	ctx.SetReturn(uint64(uint32(value)))
	return 0
}

func crtByteSwap16(ctx *ntapi.TrapContext) uint32 {
	ctx.SetReturn(uint64(bits.ReverseBytes16(uint16(ctx.Arg(0)))))
	return 0
}

func crtByteSwap32(ctx *ntapi.TrapContext) uint32 {
	ctx.SetReturn(uint64(bits.ReverseBytes32(uint32(ctx.Arg(0)))))
	return 0
}

func registerCRTIntegerHelperContractCases(semantic crtIntegerHelperSemantic) {
	for _, module := range semantic.modules {
		for _, architecture := range []string{"i386", "win64"} {
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					for scenario := range semantic.inputs {
						value, err := invocation.Call(semantic.inputs[scenario])
						if err != nil {
							invocation.Failf("dispatch integer helper: %v", err)
							return
						}
						result := crtContractResult{
							invocation: invocation,
							callIndex:  len(invocation.calls) - 1,
							Return:     value,
						}
						result.ExpectReturn(semantic.outputs[scenario])
					}
				},
			})
		}
	}
}
