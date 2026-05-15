//go:build guest_windows

package main

import (
	"math/bits"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type crtRotateSemantic struct {
	name string
	id   string
	left bool
}

var crtRotateSemantics = []crtRotateSemantic{
	{name: "_rotl", id: "crt.integer.rotl32.v1", left: true},
	{name: "_rotr", id: "crt.integer.rotr32.v1", left: false},
	{name: "_lrotl", id: "crt.integer.lrotl32.v1", left: true},
	{name: "_lrotr", id: "crt.integer.lrotr32.v1", left: false},
}

func init() {
	registerCRTProvider(registerCRTRotateDefinitions)
	for _, semantic := range crtRotateSemantics {
		registerCRTRotateContractCases(semantic)
	}
}

func registerCRTRotateDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtRotateSemantics {
		handler := crtRotateRight32
		if semantic.left {
			handler = crtRotateLeft32
		}
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        "cdecl(long long)",
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   append([]string(nil), crtStringModules...),
			AllowedArch:      []string{"i386", "win64"},
			Handler:          handler,
		})
	}
}

func crtRotateLeft32(ctx *ntapi.TrapContext) uint32 {
	ctx.SetReturn(uint64(bits.RotateLeft32(uint32(ctx.Arg(0)), int(ctx.Arg(1)&31))))
	return 0
}

func crtRotateRight32(ctx *ntapi.TrapContext) uint32 {
	ctx.SetReturn(uint64(bits.RotateLeft32(uint32(ctx.Arg(0)), -int(ctx.Arg(1)&31))))
	return 0
}

func registerCRTRotateContractCases(semantic crtRotateSemantic) {
	for _, module := range crtStringModules {
		for _, architecture := range []string{"i386", "win64"} {
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        "cdecl(long long)",
				Exercise: func(invocation *crtContractInvocation) {
					inputs := [2][2]uint64{{0x12345678, 8}, {0x80000001, 1}}
					for _, input := range inputs {
						value, err := invocation.Call(input[0], input[1])
						if err != nil {
							invocation.Failf("dispatch rotate helper: %v", err)
							return
						}
						want := uint64(bits.RotateLeft32(uint32(input[0]), int(input[1])))
						if !semantic.left {
							want = uint64(bits.RotateLeft32(uint32(input[0]), -int(input[1])))
						}
						result := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: value}
						result.ExpectReturn(want)
					}
				},
			})
		}
	}
}
