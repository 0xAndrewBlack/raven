//go:build guest_windows

package main

import (
	"slices"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type crtStringMutationSemantic struct {
	name      string
	id        string
	signature string
	wide      bool
	mode      string
	handler   ntapi.TrapHandler
}

var crtStringMutationSemantics = []crtStringMutationSemantic{
	{name: "_strrev", id: "crt.string.reverse.v1", signature: "cdecl(str)", mode: "reverse", handler: crtStrrev},
	{name: "_strset", id: "crt.string.set.v1", signature: "cdecl(str long)", mode: "set", handler: crtStrset},
	{name: "_strnset", id: "crt.string.nset.v1", signature: "cdecl(str long long)", mode: "nset", handler: crtStrnset},
	{name: "_wcsrev", id: "crt.wide.reverse.v1", signature: "cdecl(wstr)", wide: true, mode: "reverse", handler: crtWcsrev},
	{name: "_wcsset", id: "crt.wide.set.v1", signature: "cdecl(wstr long)", wide: true, mode: "set", handler: crtWcsset},
	{name: "_wcsnset", id: "crt.wide.nset.v1", signature: "cdecl(wstr long long)", wide: true, mode: "nset", handler: crtWcsnset},
}

func init() {
	registerCRTProvider(registerCRTStringMutationDefinitions)
	for _, semantic := range crtStringMutationSemantics {
		registerCRTStringMutationContractCases(semantic)
	}
}

func registerCRTStringMutationDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtStringMutationSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   append([]string(nil), crtStringModules...),
			AllowedArch:      []string{"i386", "win64"},
			Handler:          semantic.handler,
		})
	}
}

func crtStrrev(ctx *ntapi.TrapContext) uint32 {
	address := ctx.Arg(0)
	value, ok := crtReadNarrowString(ctx.Mem, address)
	if !ok || !crtMemoryRange(ctx.Mem, address, uint64(len(value)), mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	slices.Reverse(value)
	if err := ctx.Mem.WriteBytes(address, value); err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(address)
	return 0
}

func crtStrset(ctx *ntapi.TrapContext) uint32 {
	return crtSetNarrow(ctx, false)
}

func crtStrnset(ctx *ntapi.TrapContext) uint32 {
	return crtSetNarrow(ctx, true)
}

func crtSetNarrow(ctx *ntapi.TrapContext, bounded bool) uint32 {
	address := ctx.Arg(0)
	value, ok := crtReadNarrowString(ctx.Mem, address)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	count := uint64(len(value))
	if bounded && count > ctx.Arg(2) {
		count = ctx.Arg(2)
	}
	if !crtMemoryRange(ctx.Mem, address, count, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	for index := uint64(0); index < count; index++ {
		if err := ctx.Mem.Write8(address+index, byte(ctx.Arg(1))); err != nil {
			return crtMemoryAccessFailure(ctx)
		}
	}
	ctx.SetReturn(address)
	return 0
}

func crtWcsrev(ctx *ntapi.TrapContext) uint32 {
	address := ctx.Arg(0)
	value, ok := crtReadWideString(ctx.Mem, address)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	slices.Reverse(value)
	if !crtWriteWide(ctx.Mem, address, value, false) {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(address)
	return 0
}

func crtWcsset(ctx *ntapi.TrapContext) uint32 {
	return crtSetWide(ctx, false)
}

func crtWcsnset(ctx *ntapi.TrapContext) uint32 {
	return crtSetWide(ctx, true)
}

func crtSetWide(ctx *ntapi.TrapContext, bounded bool) uint32 {
	address := ctx.Arg(0)
	value, ok := crtReadWideString(ctx.Mem, address)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	count := uint64(len(value))
	if bounded && count > ctx.Arg(2) {
		count = ctx.Arg(2)
	}
	for index := uint64(0); index < count; index++ {
		value[index] = uint16(ctx.Arg(1))
	}
	if !crtWriteWide(ctx.Mem, address, value[:count], false) {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(address)
	return 0
}

func registerCRTStringMutationContractCases(semantic crtStringMutationSemantic) {
	for _, module := range crtStringModules {
		for _, architecture := range []string{"i386", "win64"} {
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					exerciseCRTStringMutationContract(invocation, semantic)
				},
			})
		}
	}
}

func exerciseCRTStringMutationContract(invocation *crtContractInvocation, semantic crtStringMutationSemantic) {
	values := []string{"raven", "code"}
	for scenario, value := range values {
		data := append([]byte(value), 0)
		expected := append([]byte(nil), data...)
		unitSize := 1
		if semantic.wide {
			data = crtWideASCII(value)
			expected = append([]byte(nil), data...)
			unitSize = 2
		}
		address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if err := invocation.Mem.WriteBytes(address, data); err != nil {
			invocation.Failf("write mutation input: %v", err)
			return
		}
		args := []uint64{address}
		switch semantic.mode {
		case "reverse":
			if semantic.wide {
				units, _ := crtReadWideString(invocation.Mem, address)
				slices.Reverse(units)
				expected = crtWideBytes(units, true)
			} else {
				slices.Reverse(expected[:len(expected)-1])
			}
		case "set", "nset":
			replacement := []byte{'X', 'Q'}[scenario]
			count := len(value)
			args = append(args, uint64(replacement))
			if semantic.mode == "nset" {
				count = []int{2, 3}[scenario]
				args = append(args, uint64(count))
			}
			for index := 0; index < count; index++ {
				expected[index*unitSize] = replacement
				if unitSize == 2 {
					expected[index*unitSize+1] = 0
				}
			}
		}
		result, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: address, Size: len(data)}}, args...)
		if err != nil {
			invocation.Failf("dispatch mutation contract: %v", err)
			return
		}
		result.ExpectReturn(address)
		result.ExpectMemory(0, expected)
	}
}
