//go:build guest_windows

package main

import (
	"math"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var crtMemoryModules = []string{
	"msvcrt20.dll",
	"msvcrt40.dll",
	"msvcrt.dll",
	"msvcr70.dll",
	"msvcr71.dll",
	"msvcr80.dll",
	"msvcr90.dll",
	"msvcr100.dll",
	"msvcr110.dll",
	"msvcr120.dll",
	"msvcr120_app.dll",
	"msvcrtd.dll",
	"ucrtbase.dll",
}

var crtMemoryForwarderModules = append(
	append([]string(nil), crtMemoryModules...),
	"vcruntime140.dll",
)

type crtMemorySemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	handler   ntapi.TrapHandler
}

var crtMemorySemantics = []crtMemorySemantic{
	{name: "memcpy", id: "crt.memory.memcpy.v1", signature: "cdecl(ptr ptr long)", modules: crtMemoryForwarderModules, handler: crtMemcpy},
	{name: "memmove", id: "crt.memory.memmove.v1", signature: "cdecl(ptr ptr long)", modules: crtMemoryForwarderModules, handler: crtMemmove},
	{name: "memset", id: "crt.memory.memset.v1", signature: "cdecl(ptr long long)", modules: crtMemoryForwarderModules, handler: crtMemset},
	{name: "memcmp", id: "crt.memory.memcmp.v1", signature: "cdecl(ptr ptr long)", modules: crtMemoryForwarderModules, handler: crtMemcmp},
	{name: "memchr", id: "crt.memory.memchr.v1", signature: "cdecl(ptr long long)", modules: crtMemoryForwarderModules, handler: crtMemchr},
	{name: "_memccpy", id: "crt.memory.memccpy.v1", signature: "cdecl(ptr ptr long long)", modules: crtMemoryModules, handler: crtMemccpy},
	{name: "_swab", id: "crt.memory.swab.v1", signature: "cdecl(str str long)", modules: crtMemoryModules, handler: crtSwab},
}

func init() {
	registerCRTProvider(registerCRTMemoryDefinitions)
	for _, semantic := range crtMemorySemantics {
		registerCRTMemoryContractCases(semantic)
	}
}

func registerCRTMemoryDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtMemorySemantics {
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

func crtMemoryRange(mem *mmu.MMU, addr, size uint64, perms uint8) bool {
	if size == 0 {
		return true
	}
	last := addr + size - 1
	if last < addr {
		return false
	}
	for page := addr & mmu.PageMask; ; page += mmu.PageSize {
		probe := page
		if probe < addr {
			probe = addr
		}
		if _, _, err := mem.LookupRead(probe, perms); err != nil {
			return false
		}
		if page >= last&mmu.PageMask {
			return true
		}
		if page > math.MaxUint64-mmu.PageSize {
			return false
		}
	}
}

func crtMemoryAccessFailure(ctx *ntapi.TrapContext) uint32 {
	ctx.SetReturn(0)
	ctx.CPU.Stop()
	return 0
}

func crtMemcpy(ctx *ntapi.TrapContext) uint32 {
	dst, src, size := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, src, size, mmu.PermRead) ||
		!crtMemoryRange(ctx.Mem, dst, size, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	const chunkSize = uint64(64 * 1024)
	for offset := uint64(0); offset < size; {
		chunk := size - offset
		if chunk > chunkSize {
			chunk = chunkSize
		}
		data, err := ctx.Mem.ReadBytes(src+offset, int(chunk))
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if err := ctx.Mem.WriteBytes(dst+offset, data); err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		offset += chunk
	}
	ctx.SetReturn(dst)
	return 0
}

func crtMemmove(ctx *ntapi.TrapContext) uint32 {
	dst, src, size := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, src, size, mmu.PermRead) ||
		!crtMemoryRange(ctx.Mem, dst, size, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	if size != 0 && dst > src && dst-src < size {
		for i := size; i > 0; i-- {
			value, err := ctx.Mem.Read8(src + i - 1)
			if err != nil || ctx.Mem.Write8(dst+i-1, value) != nil {
				return crtMemoryAccessFailure(ctx)
			}
		}
	} else {
		for i := uint64(0); i < size; i++ {
			value, err := ctx.Mem.Read8(src + i)
			if err != nil || ctx.Mem.Write8(dst+i, value) != nil {
				return crtMemoryAccessFailure(ctx)
			}
		}
	}
	ctx.SetReturn(dst)
	return 0
}

func crtMemset(ctx *ntapi.TrapContext) uint32 {
	dst, value, size := ctx.Arg(0), byte(ctx.Arg(1)), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, dst, size, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	for i := uint64(0); i < size; i++ {
		if err := ctx.Mem.Write8(dst+i, value); err != nil {
			return crtMemoryAccessFailure(ctx)
		}
	}
	ctx.SetReturn(dst)
	return 0
}

func crtMemcmp(ctx *ntapi.TrapContext) uint32 {
	left, right, size := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, left, size, mmu.PermRead) ||
		!crtMemoryRange(ctx.Mem, right, size, mmu.PermRead) {
		return crtMemoryAccessFailure(ctx)
	}
	for i := uint64(0); i < size; i++ {
		a, _ := ctx.Mem.Read8(left + i)
		b, _ := ctx.Mem.Read8(right + i)
		if a < b {
			ctx.SetReturn(uint64(uint32(math.MaxUint32)))
			return 0
		}
		if a > b {
			ctx.SetReturn(1)
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtMemchr(ctx *ntapi.TrapContext) uint32 {
	ptr, needle, size := ctx.Arg(0), byte(ctx.Arg(1)), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, ptr, size, mmu.PermRead) {
		return crtMemoryAccessFailure(ctx)
	}
	for i := uint64(0); i < size; i++ {
		value, _ := ctx.Mem.Read8(ptr + i)
		if value == needle {
			ctx.SetReturn(ptr + i)
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtMemicmp(ctx *ntapi.TrapContext) uint32 {
	left, right, size := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if !crtMemoryRange(ctx.Mem, left, size, mmu.PermRead) ||
		!crtMemoryRange(ctx.Mem, right, size, mmu.PermRead) {
		return crtMemoryAccessFailure(ctx)
	}
	for i := uint64(0); i < size; i++ {
		a, _ := ctx.Mem.Read8(left + i)
		b, _ := ctx.Mem.Read8(right + i)
		a = crtASCIILower(a)
		b = crtASCIILower(b)
		if a < b {
			ctx.SetReturn(uint64(uint32(math.MaxUint32)))
			return 0
		}
		if a > b {
			ctx.SetReturn(1)
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtMemccpy(ctx *ntapi.TrapContext) uint32 {
	destination, source, needle, limit := ctx.Arg(0), ctx.Arg(1), byte(ctx.Arg(2)), ctx.Arg(3)
	count := limit
	found := false
	for index := uint64(0); index < limit; index++ {
		current := source + index
		if current < source {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == needle {
			count = index + 1
			found = true
			break
		}
	}
	if !crtMemoryRange(ctx.Mem, destination, count, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	if count > math.MaxInt {
		return crtMemoryAccessFailure(ctx)
	}
	value, err := ctx.Mem.ReadBytes(source, int(count))
	if err != nil || ctx.Mem.WriteBytes(destination, value) != nil {
		return crtMemoryAccessFailure(ctx)
	}
	if found {
		ctx.SetReturn(destination + count)
	} else {
		ctx.SetReturn(0)
	}
	return 0
}

func crtSwab(ctx *ntapi.TrapContext) uint32 {
	source, destination := ctx.Arg(0), ctx.Arg(1)
	signedCount := int32(ctx.Arg(2))
	if signedCount <= 0 {
		ctx.SetReturn(0)
		return 0
	}
	count := uint64(uint32(signedCount)) &^ 1
	if count > math.MaxInt {
		return crtMemoryAccessFailure(ctx)
	}
	if !crtMemoryRange(ctx.Mem, source, count, mmu.PermRead) ||
		!crtMemoryRange(ctx.Mem, destination, count, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	value, err := ctx.Mem.ReadBytes(source, int(count))
	if err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	for index := 0; index < len(value); index += 2 {
		value[index], value[index+1] = value[index+1], value[index]
	}
	if err := ctx.Mem.WriteBytes(destination, value); err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(0)
	return 0
}

func crtASCIILower(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func registerCRTMemoryContractCases(semantic crtMemorySemantic) {
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
					exerciseCRTMemoryContract(invocation, semantic.name)
				},
			})
		}
	}
}

func exerciseCRTMemoryContract(invocation *crtContractInvocation, name string) {
	allocate := func(left, right []byte) (uint64, uint64, bool) {
		leftAddr := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		rightAddr := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if leftAddr == 0 || rightAddr == 0 {
			invocation.Failf("contract allocation failed")
			return 0, 0, false
		}
		if err := invocation.Mem.WriteBytes(leftAddr, left); err != nil {
			invocation.Failf("write left contract input: %v", err)
			return 0, 0, false
		}
		if err := invocation.Mem.WriteBytes(rightAddr, right); err != nil {
			invocation.Failf("write right contract input: %v", err)
			return 0, 0, false
		}
		return leftAddr, rightAddr, true
	}
	call := func(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, bool) {
		result, err := invocation.CallWatching(watches, args...)
		if err != nil {
			invocation.Failf("dispatch contract call: %v", err)
			return crtContractResult{}, false
		}
		return result, true
	}
	switch name {
	case "memcpy":
		left, right, ok := allocate([]byte("alpha"), []byte("....."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: right, Size: 5}}, right, left, 5)
		if !ok {
			return
		}
		first.ExpectReturn(right)
		first.ExpectMemory(0, []byte("alpha"))
		left, right, ok = allocate([]byte("BRAVO!"), []byte("......"))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: right, Size: 6}}, right, left, 6)
		if !ok {
			return
		}
		second.ExpectReturn(right)
		second.ExpectMemory(0, []byte("BRAVO!"))
	case "memmove":
		left, _, ok := allocate([]byte("abcdefgh"), []byte("."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: left, Size: 8}}, left+2, left, 6)
		if !ok {
			return
		}
		first.ExpectReturn(left + 2)
		first.ExpectMemory(0, []byte("ababcdef"))
		left, _, ok = allocate([]byte("abcdefgh"), []byte("."))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: left, Size: 8}}, left, left+2, 6)
		if !ok {
			return
		}
		second.ExpectReturn(left)
		second.ExpectMemory(0, []byte("cdefghgh"))
	case "memset":
		left, _, ok := allocate([]byte("....."), []byte("."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: left, Size: 5}}, left, 'x', 4)
		if !ok {
			return
		}
		first.ExpectReturn(left)
		first.ExpectMemory(0, []byte("xxxx."))
		left, _, ok = allocate([]byte("....."), []byte("."))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: left, Size: 5}}, left, 'Q', 3)
		if !ok {
			return
		}
		second.ExpectReturn(left)
		second.ExpectMemory(0, []byte("QQQ.."))
	case "memcmp":
		left, right, ok := allocate([]byte("abc"), []byte("abd"))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: left, Size: 3}, {Address: right, Size: 3}}, left, right, 3)
		if !ok {
			return
		}
		first.ExpectInt32Sign(-1)
		left, right, ok = allocate([]byte("abe"), []byte("abd"))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: left, Size: 3}, {Address: right, Size: 3}}, left, right, 3)
		if !ok {
			return
		}
		second.ExpectInt32Sign(1)
	case "memchr":
		left, _, ok := allocate([]byte("abcde"), []byte("."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: left, Size: 5}}, left, 'c', 5)
		if !ok {
			return
		}
		first.ExpectReturn(left + 2)
		left, _, ok = allocate([]byte("abcde"), []byte("."))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: left, Size: 5}}, left, 'z', 5)
		if !ok {
			return
		}
		second.ExpectReturn(0)
	case "_memicmp":
		left, right, ok := allocate([]byte("AbC"), []byte("aBc"))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: left, Size: 3}, {Address: right, Size: 3}}, left, right, 3)
		if !ok {
			return
		}
		first.ExpectInt32Sign(0)
		left, right, ok = allocate([]byte("AbD"), []byte("abc"))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: left, Size: 3}, {Address: right, Size: 3}}, left, right, 3)
		if !ok {
			return
		}
		second.ExpectInt32Sign(1)
	case "_memccpy":
		left, right, ok := allocate([]byte("ab-cd"), []byte("....."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: right, Size: 3}}, right, left, '-', 5)
		if !ok {
			return
		}
		first.ExpectReturn(right + 3)
		first.ExpectMemory(0, []byte("ab-"))
		left, right, ok = allocate([]byte("raven"), []byte("....."))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: right, Size: 5}}, right, left, 'x', 5)
		if !ok {
			return
		}
		second.ExpectReturn(0)
		second.ExpectMemory(0, []byte("raven"))
	case "_swab":
		left, right, ok := allocate([]byte("abcd"), []byte("...."))
		if !ok {
			return
		}
		first, ok := call([]crtContractMemoryWatch{{Address: right, Size: 4}}, left, right, 4)
		if !ok {
			return
		}
		first.ExpectReturn(0)
		first.ExpectMemory(0, []byte("badc"))
		left, right, ok = allocate([]byte("123456"), []byte("......"))
		if !ok {
			return
		}
		second, ok := call([]crtContractMemoryWatch{{Address: right, Size: 6}}, left, right, 6)
		if !ok {
			return
		}
		second.ExpectReturn(0)
		second.ExpectMemory(0, []byte("214365"))
	default:
		invocation.Failf("unknown memory contract %q", name)
	}
}
