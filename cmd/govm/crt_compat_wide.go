//go:build guest_windows

package main

import (
	"encoding/binary"
	"math"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type crtWideSemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	handler   ntapi.TrapHandler
}

var crtWideSemantics = []crtWideSemantic{
	{name: "wcslen", id: "crt.wide.wcslen.v1", signature: "cdecl(wstr)", modules: crtStringModules, handler: crtWcslen},
	{name: "wcsnlen", id: "crt.wide.wcsnlen.v1", signature: "cdecl(wstr long)", modules: crtStrnlenModules, handler: crtWcsnlen},
	{name: "wcscpy", id: "crt.wide.wcscpy.v1", signature: "cdecl(ptr wstr)", modules: crtStringModules, handler: crtWcscpy},
	{name: "wcsncpy", id: "crt.wide.wcsncpy.v1", signature: "cdecl(ptr wstr long)", modules: crtStringModules, handler: crtWcsncpy},
	{name: "wcscat", id: "crt.wide.wcscat.v1", signature: "cdecl(wstr wstr)", modules: crtStringModules, handler: crtWcscat},
	{name: "wcsncat", id: "crt.wide.wcsncat.v1", signature: "cdecl(wstr wstr long)", modules: crtStringModules, handler: crtWcsncat},
	{name: "wcscmp", id: "crt.wide.wcscmp.v1", signature: "cdecl(wstr wstr)", modules: crtStringModules, handler: crtWcscmp},
	{name: "wcsncmp", id: "crt.wide.wcsncmp.v1", signature: "cdecl(wstr wstr long)", modules: crtStringModules, handler: crtWcsncmp},
	{name: "wcschr", id: "crt.wide.wcschr.v1", signature: "cdecl(wstr long)", modules: crtStringSearchModules, handler: crtWcschr},
	{name: "wcsrchr", id: "crt.wide.wcsrchr.v1", signature: "cdecl(wstr long)", modules: crtStringSearchModules, handler: crtWcsrchr},
	{name: "wcsstr", id: "crt.wide.wcsstr.v1", signature: "cdecl(wstr wstr)", modules: crtStringSearchModules, handler: crtWcsstr},
	{name: "wcspbrk", id: "crt.wide.wcspbrk.v1", signature: "cdecl(wstr wstr)", modules: crtStringModules, handler: crtWcspbrk},
	{name: "wcsspn", id: "crt.wide.wcsspn.v1", signature: "cdecl(wstr wstr)", modules: crtStringModules, handler: crtWcsspn},
	{name: "wcscspn", id: "crt.wide.wcscspn.v1", signature: "cdecl(wstr wstr)", modules: crtStringModules, handler: crtWcscspn},
}

func init() {
	registerCRTProvider(registerCRTWideDefinitions)
	for _, semantic := range crtWideSemantics {
		registerCRTWideContractCases(semantic)
	}
}

func registerCRTWideDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtWideSemantics {
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

func crtReadWideString(mem *mmu.MMU, address uint64) ([]uint16, bool) {
	var result []uint16
	for index := uint64(0); ; index++ {
		current := address + index*2
		if current < address {
			return nil, false
		}
		value, err := mem.Read16(current)
		if err != nil {
			return nil, false
		}
		if value == 0 {
			return result, true
		}
		result = append(result, value)
	}
}

func crtWideBytes(value []uint16, terminated bool) []byte {
	length := len(value)
	if terminated {
		length++
	}
	result := make([]byte, length*2)
	for index, unit := range value {
		binary.LittleEndian.PutUint16(result[index*2:], unit)
	}
	return result
}

func crtWriteWide(mem *mmu.MMU, address uint64, value []uint16, terminated bool) bool {
	data := crtWideBytes(value, terminated)
	if !crtMemoryRange(mem, address, uint64(len(data)), mmu.PermWrite) {
		return false
	}
	return mem.WriteBytes(address, data) == nil
}

func crtWcslen(ctx *ntapi.TrapContext) uint32 {
	value, ok := crtReadWideString(ctx.Mem, ctx.Arg(0))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(uint64(len(value)))
	return 0
}

func crtWcsnlen(ctx *ntapi.TrapContext) uint32 {
	address, limit := ctx.Arg(0), ctx.Arg(1)
	for index := uint64(0); index < limit; index++ {
		current := address + index*2
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == 0 {
			ctx.SetReturn(index)
			return 0
		}
	}
	ctx.SetReturn(limit)
	return 0
}

func crtWcscpy(ctx *ntapi.TrapContext) uint32 {
	destination := ctx.Arg(0)
	value, ok := crtReadWideString(ctx.Mem, ctx.Arg(1))
	if !ok || !crtWriteWide(ctx.Mem, destination, value, true) {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtWcsncpy(ctx *ntapi.TrapContext) uint32 {
	destination, source, limit := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if limit > math.MaxInt/2 || !crtMemoryRange(ctx.Mem, destination, limit*2, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	value := make([]uint16, 0, min(limit, 2048))
	terminated := false
	for index := uint64(0); index < limit; index++ {
		if terminated {
			value = append(value, 0)
			continue
		}
		current := source + index*2
		if current < source {
			return crtMemoryAccessFailure(ctx)
		}
		unit, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		value = append(value, unit)
		terminated = unit == 0
	}
	if !crtWriteWide(ctx.Mem, destination, value, false) {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtWcscat(ctx *ntapi.TrapContext) uint32 {
	return crtAppendWide(ctx, false)
}

func crtWcsncat(ctx *ntapi.TrapContext) uint32 {
	return crtAppendWide(ctx, true)
}

func crtAppendWide(ctx *ntapi.TrapContext, bounded bool) uint32 {
	destination := ctx.Arg(0)
	prefix, ok := crtReadWideString(ctx.Mem, destination)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	suffix, ok := crtReadWideString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	if bounded && uint64(len(suffix)) > ctx.Arg(2) {
		suffix = suffix[:ctx.Arg(2)]
	}
	appendAddress := destination + uint64(len(prefix))*2
	if appendAddress < destination || !crtWriteWide(ctx.Mem, appendAddress, suffix, true) {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtWcscmp(ctx *ntapi.TrapContext) uint32 {
	return crtCompareWide(ctx, false)
}

func crtWcsncmp(ctx *ntapi.TrapContext) uint32 {
	return crtCompareWide(ctx, true)
}

func crtCompareWide(ctx *ntapi.TrapContext, bounded bool) uint32 {
	left, right := ctx.Arg(0), ctx.Arg(1)
	limit := uint64(math.MaxUint64)
	if bounded {
		limit = ctx.Arg(2)
	}
	for index := uint64(0); index < limit; index++ {
		leftAddress, rightAddress := left+index*2, right+index*2
		if leftAddress < left || rightAddress < right {
			return crtMemoryAccessFailure(ctx)
		}
		a, errA := ctx.Mem.Read16(leftAddress)
		b, errB := ctx.Mem.Read16(rightAddress)
		if errA != nil || errB != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if a != b {
			crtSetSignedResult(ctx, int(a)-int(b))
			return 0
		}
		if a == 0 {
			ctx.SetReturn(0)
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtWcschr(ctx *ntapi.TrapContext) uint32 {
	return crtFindWideUnit(ctx, false)
}

func crtWcsrchr(ctx *ntapi.TrapContext) uint32 {
	return crtFindWideUnit(ctx, true)
}

func crtFindWideUnit(ctx *ntapi.TrapContext, lastMatch bool) uint32 {
	address, needle := ctx.Arg(0), uint16(ctx.Arg(1))
	last := uint64(0)
	for index := uint64(0); ; index++ {
		current := address + index*2
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == needle {
			if !lastMatch {
				ctx.SetReturn(current)
				return 0
			}
			last = current
		}
		if value == 0 {
			ctx.SetReturn(last)
			return 0
		}
	}
}

func crtWcsstr(ctx *ntapi.TrapContext) uint32 {
	haystackAddress := ctx.Arg(0)
	haystack, ok := crtReadWideString(ctx.Mem, haystackAddress)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	needle, ok := crtReadWideString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	if len(needle) == 0 {
		ctx.SetReturn(haystackAddress)
		return 0
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		matched := true
		for offset := range needle {
			if haystack[index+offset] != needle[offset] {
				matched = false
				break
			}
		}
		if matched {
			ctx.SetReturn(haystackAddress + uint64(index*2))
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtWcspbrk(ctx *ntapi.TrapContext) uint32 {
	address := ctx.Arg(0)
	set, ok := crtReadWideString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	table := make(map[uint16]struct{}, len(set))
	for _, unit := range set {
		table[unit] = struct{}{}
	}
	for index := uint64(0); ; index++ {
		current := address + index*2
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		unit, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if unit == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if _, exists := table[unit]; exists {
			ctx.SetReturn(current)
			return 0
		}
	}
}

func crtWcsspn(ctx *ntapi.TrapContext) uint32 {
	return crtWideSpan(ctx, true)
}

func crtWcscspn(ctx *ntapi.TrapContext) uint32 {
	return crtWideSpan(ctx, false)
}

func crtWideSpan(ctx *ntapi.TrapContext, accepted bool) uint32 {
	address := ctx.Arg(0)
	set, ok := crtReadWideString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	table := make(map[uint16]struct{}, len(set))
	for _, unit := range set {
		table[unit] = struct{}{}
	}
	for index := uint64(0); ; index++ {
		current := address + index*2
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		unit, err := ctx.Mem.Read16(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		_, exists := table[unit]
		if unit == 0 || exists != accepted {
			ctx.SetReturn(index)
			return 0
		}
	}
}
