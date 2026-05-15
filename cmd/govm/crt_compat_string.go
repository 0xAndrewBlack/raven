//go:build guest_windows

package main

import (
	"math"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

var crtStringModules = append([]string(nil), crtMemoryModules...)

var crtStrnlenModules = []string{
	"msvcrt.dll",
	"msvcr80.dll",
	"msvcr90.dll",
	"msvcr100.dll",
	"msvcr110.dll",
	"msvcr120.dll",
	"msvcr120_app.dll",
	"ucrtbase.dll",
}

var crtStringSearchModules = append(
	append([]string(nil), crtStringModules...),
	"vcruntime140.dll",
)

type crtStringSemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	handler   ntapi.TrapHandler
}

var crtStringSemantics = []crtStringSemantic{
	{name: "strlen", id: "crt.string.strlen.v1", signature: "cdecl(str)", modules: crtStringModules, handler: crtStrlen},
	{name: "strnlen", id: "crt.string.strnlen.v1", signature: "cdecl(str long)", modules: crtStrnlenModules, handler: crtStrnlen},
	{name: "strcpy", id: "crt.string.strcpy.v1", signature: "cdecl(ptr str)", modules: crtStringModules, handler: crtStrcpy},
	{name: "strncpy", id: "crt.string.strncpy.v1", signature: "cdecl(ptr str long)", modules: crtStringModules, handler: crtStrncpy},
	{name: "strcat", id: "crt.string.strcat.v1", signature: "cdecl(str str)", modules: crtStringModules, handler: crtStrcat},
	{name: "strncat", id: "crt.string.strncat.v1", signature: "cdecl(str str long)", modules: crtStringModules, handler: crtStrncat},
	{name: "strcmp", id: "crt.string.strcmp.v1", signature: "cdecl(str str)", modules: crtStringModules, handler: crtStrcmp},
	{name: "strncmp", id: "crt.string.strncmp.v1", signature: "cdecl(str str long)", modules: crtStringModules, handler: crtStrncmp},
	{name: "strchr", id: "crt.string.strchr.v1", signature: "cdecl(str long)", modules: crtStringSearchModules, handler: crtStrchr},
	{name: "strrchr", id: "crt.string.strrchr.v1", signature: "cdecl(str long)", modules: crtStringSearchModules, handler: crtStrrchr},
	{name: "strstr", id: "crt.string.strstr.v1", signature: "cdecl(str str)", modules: crtStringSearchModules, handler: crtStrstr},
	{name: "strpbrk", id: "crt.string.strpbrk.v1", signature: "cdecl(str str)", modules: crtStringModules, handler: crtStrpbrk},
	{name: "strspn", id: "crt.string.strspn.v1", signature: "cdecl(str str)", modules: crtStringModules, handler: crtStrspn},
	{name: "strcspn", id: "crt.string.strcspn.v1", signature: "cdecl(str str)", modules: crtStringModules, handler: crtStrcspn},
}

func init() {
	registerCRTProvider(registerCRTStringDefinitions)
	for _, semantic := range crtStringSemantics {
		registerCRTStringContractCases(semantic)
	}
}

func registerCRTStringDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtStringSemantics {
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

func crtReadNarrowString(mem *mmu.MMU, address uint64) ([]byte, bool) {
	var result []byte
	for current := address; ; current++ {
		value, err := mem.Read8(current)
		if err != nil {
			return nil, false
		}
		if value == 0 {
			return result, true
		}
		result = append(result, value)
		if current == math.MaxUint64 {
			return nil, false
		}
	}
}

func crtSetSignedResult(ctx *ntapi.TrapContext, value int) {
	ctx.SetReturn(uint64(uint32(int32(value))))
}

func crtStrlen(ctx *ntapi.TrapContext) uint32 {
	value, ok := crtReadNarrowString(ctx.Mem, ctx.Arg(0))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(uint64(len(value)))
	return 0
}

func crtStrnlen(ctx *ntapi.TrapContext) uint32 {
	address, limit := ctx.Arg(0), ctx.Arg(1)
	for index := uint64(0); index < limit; index++ {
		current := address + index
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
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

func crtStrcpy(ctx *ntapi.TrapContext) uint32 {
	destination, source := ctx.Arg(0), ctx.Arg(1)
	value, ok := crtReadNarrowString(ctx.Mem, source)
	if !ok || !crtMemoryRange(ctx.Mem, destination, uint64(len(value)+1), mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	value = append(value, 0)
	if err := ctx.Mem.WriteBytes(destination, value); err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtStrncpy(ctx *ntapi.TrapContext) uint32 {
	destination, source, limit := ctx.Arg(0), ctx.Arg(1), ctx.Arg(2)
	if limit > math.MaxInt || !crtMemoryRange(ctx.Mem, destination, limit, mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	value := make([]byte, 0, min(limit, 4096))
	terminated := false
	for index := uint64(0); index < limit; index++ {
		if terminated {
			value = append(value, 0)
			continue
		}
		currentAddress := source + index
		if currentAddress < source {
			return crtMemoryAccessFailure(ctx)
		}
		current, err := ctx.Mem.Read8(currentAddress)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		value = append(value, current)
		terminated = current == 0
	}
	if err := ctx.Mem.WriteBytes(destination, value); err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtStrcat(ctx *ntapi.TrapContext) uint32 {
	return crtAppendNarrow(ctx, false)
}

func crtStrncat(ctx *ntapi.TrapContext) uint32 {
	return crtAppendNarrow(ctx, true)
}

func crtAppendNarrow(ctx *ntapi.TrapContext, bounded bool) uint32 {
	destination, source := ctx.Arg(0), ctx.Arg(1)
	prefix, ok := crtReadNarrowString(ctx.Mem, destination)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	suffix, ok := crtReadNarrowString(ctx.Mem, source)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	if bounded && uint64(len(suffix)) > ctx.Arg(2) {
		suffix = suffix[:ctx.Arg(2)]
	}
	appendAddress := destination + uint64(len(prefix))
	if appendAddress < destination || !crtMemoryRange(ctx.Mem, appendAddress, uint64(len(suffix)+1), mmu.PermWrite) {
		return crtMemoryAccessFailure(ctx)
	}
	suffix = append(suffix, 0)
	if err := ctx.Mem.WriteBytes(appendAddress, suffix); err != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(destination)
	return 0
}

func crtStrcmp(ctx *ntapi.TrapContext) uint32 {
	return crtCompareNarrow(ctx, false)
}

func crtStrncmp(ctx *ntapi.TrapContext) uint32 {
	return crtCompareNarrow(ctx, true)
}

func crtCompareNarrow(ctx *ntapi.TrapContext, bounded bool) uint32 {
	left, right := ctx.Arg(0), ctx.Arg(1)
	limit := uint64(math.MaxUint64)
	if bounded {
		limit = ctx.Arg(2)
	}
	for index := uint64(0); index < limit; index++ {
		leftAddress, rightAddress := left+index, right+index
		if leftAddress < left || rightAddress < right {
			return crtMemoryAccessFailure(ctx)
		}
		a, errA := ctx.Mem.Read8(leftAddress)
		b, errB := ctx.Mem.Read8(rightAddress)
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

func crtStrchr(ctx *ntapi.TrapContext) uint32 {
	address, needle := ctx.Arg(0), byte(ctx.Arg(1))
	for index := uint64(0); ; index++ {
		current := address + index
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == needle {
			ctx.SetReturn(current)
			return 0
		}
		if value == 0 {
			ctx.SetReturn(0)
			return 0
		}
	}
}

func crtStrrchr(ctx *ntapi.TrapContext) uint32 {
	address, needle := ctx.Arg(0), byte(ctx.Arg(1))
	last := uint64(0)
	for index := uint64(0); ; index++ {
		current := address + index
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == needle {
			last = current
		}
		if value == 0 {
			ctx.SetReturn(last)
			return 0
		}
	}
}

func crtStrstr(ctx *ntapi.TrapContext) uint32 {
	haystackAddress, needleAddress := ctx.Arg(0), ctx.Arg(1)
	haystack, ok := crtReadNarrowString(ctx.Mem, haystackAddress)
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	needle, ok := crtReadNarrowString(ctx.Mem, needleAddress)
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
			ctx.SetReturn(haystackAddress + uint64(index))
			return 0
		}
	}
	ctx.SetReturn(0)
	return 0
}

func crtStrpbrk(ctx *ntapi.TrapContext) uint32 {
	address := ctx.Arg(0)
	accept, ok := crtReadNarrowString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	var table [256]bool
	for _, value := range accept {
		table[value] = true
	}
	for index := uint64(0); ; index++ {
		current := address + index
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == 0 {
			ctx.SetReturn(0)
			return 0
		}
		if table[value] {
			ctx.SetReturn(current)
			return 0
		}
	}
}

func crtStrspn(ctx *ntapi.TrapContext) uint32 {
	return crtStringSpan(ctx, true)
}

func crtStrcspn(ctx *ntapi.TrapContext) uint32 {
	return crtStringSpan(ctx, false)
}

func crtStringSpan(ctx *ntapi.TrapContext, accepted bool) uint32 {
	address := ctx.Arg(0)
	set, ok := crtReadNarrowString(ctx.Mem, ctx.Arg(1))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	var table [256]bool
	for _, value := range set {
		table[value] = true
	}
	for index := uint64(0); ; index++ {
		current := address + index
		if current < address {
			return crtMemoryAccessFailure(ctx)
		}
		value, err := ctx.Mem.Read8(current)
		if err != nil {
			return crtMemoryAccessFailure(ctx)
		}
		if value == 0 || table[value] != accepted {
			ctx.SetReturn(index)
			return 0
		}
	}
}

func registerCRTStringContractCases(semantic crtStringSemantic) {
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
					exerciseCRTStringContract(invocation, semantic.name)
				},
			})
		}
	}
}

func exerciseCRTStringContract(invocation *crtContractInvocation, name string) {
	allocate := func(value []byte) (uint64, bool) {
		address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if address == 0 {
			invocation.Failf("string contract allocation failed")
			return 0, false
		}
		if err := invocation.Mem.WriteBytes(address, value); err != nil {
			invocation.Failf("write string contract input: %v", err)
			return 0, false
		}
		return address, true
	}
	call := func(watches []crtContractMemoryWatch, args ...uint64) (crtContractResult, bool) {
		result, err := invocation.CallWatching(watches, args...)
		if err != nil {
			invocation.Failf("dispatch string contract: %v", err)
			return crtContractResult{}, false
		}
		return result, true
	}
	for scenario := 0; scenario < 2; scenario++ {
		switch name {
		case "strlen":
			value := [][]byte{[]byte("cat\x00"), []byte("raven\x00")}[scenario]
			source, ok := allocate(value)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}}, source)
			if !ok {
				return
			}
			result.ExpectReturn(uint64(len(value) - 1))
		case "strnlen":
			value := [][]byte{[]byte("abcdef\x00"), []byte("xy\x00")}[scenario]
			limit := []uint64{3, 8}[scenario]
			source, ok := allocate(value)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}}, source, limit)
			if !ok {
				return
			}
			result.ExpectReturn([]uint64{3, 2}[scenario])
		case "strcpy", "strncpy":
			sourceValue := [][]byte{[]byte("cat\x00"), []byte("ox\x00")}[scenario]
			source, ok := allocate(sourceValue)
			if !ok {
				return
			}
			destination, ok := allocate([]byte("........"))
			if !ok {
				return
			}
			size := len(sourceValue)
			args := []uint64{destination, source}
			expected := sourceValue
			if name == "strncpy" {
				size = []int{6, 4}[scenario]
				args = append(args, uint64(size))
				expected = append(append([]byte(nil), sourceValue...), make([]byte, size-len(sourceValue))...)
			}
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: size}}, args...)
			if !ok {
				return
			}
			result.ExpectReturn(destination)
			result.ExpectMemory(0, expected)
		case "strcat", "strncat":
			prefix := [][]byte{[]byte("red\x00....."), []byte("go\x00......")}[scenario]
			suffix := [][]byte{[]byte("wood\x00"), []byte("pher\x00")}[scenario]
			destination, ok := allocate(prefix)
			if !ok {
				return
			}
			source, ok := allocate(suffix)
			if !ok {
				return
			}
			args := []uint64{destination, source}
			expected := [][]byte{[]byte("redwood\x00"), []byte("gopher\x00")}[scenario]
			if name == "strncat" {
				limit := []uint64{2, 3}[scenario]
				args = append(args, limit)
				expected = [][]byte{[]byte("redwo\x00"), []byte("gophe\x00")}[scenario]
			}
			result, ok := call([]crtContractMemoryWatch{{Address: destination, Size: len(expected)}}, args...)
			if !ok {
				return
			}
			result.ExpectReturn(destination)
			result.ExpectMemory(0, expected)
		case "strcmp", "strncmp":
			leftValue := [][]byte{[]byte("abc\x00"), []byte("abe\x00")}[scenario]
			rightValue := [][]byte{[]byte("abd\x00"), []byte("abd\x00")}[scenario]
			left, ok := allocate(leftValue)
			if !ok {
				return
			}
			right, ok := allocate(rightValue)
			if !ok {
				return
			}
			args := []uint64{left, right}
			if name == "strncmp" {
				args = append(args, 3)
			}
			result, ok := call([]crtContractMemoryWatch{{Address: left, Size: 4}, {Address: right, Size: 4}}, args...)
			if !ok {
				return
			}
			result.ExpectInt32Sign([]int{-1, 1}[scenario])
		case "strchr", "strrchr":
			value := [][]byte{[]byte("abaca\x00"), []byte("xyz\x00")}[scenario]
			source, ok := allocate(value)
			if !ok {
				return
			}
			needle := []uint64{'a', 'q'}[scenario]
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}}, source, needle)
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = source
				if name == "strrchr" {
					want = source + 4
				}
			}
			result.ExpectReturn(want)
		case "strstr":
			haystackValue := [][]byte{[]byte("one-two-three\x00"), []byte("abcdef\x00")}[scenario]
			needleValue := [][]byte{[]byte("two\x00"), []byte("xyz\x00")}[scenario]
			haystack, ok := allocate(haystackValue)
			if !ok {
				return
			}
			needle, ok := allocate(needleValue)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: haystack, Size: len(haystackValue)}, {Address: needle, Size: len(needleValue)}}, haystack, needle)
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = haystack + 4
			}
			result.ExpectReturn(want)
		case "strpbrk":
			value := [][]byte{[]byte("raven\x00"), []byte("code\x00")}[scenario]
			setValue := [][]byte{[]byte("xyv\x00"), []byte("xyz\x00")}[scenario]
			source, ok := allocate(value)
			if !ok {
				return
			}
			set, ok := allocate(setValue)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}, {Address: set, Size: len(setValue)}}, source, set)
			if !ok {
				return
			}
			want := uint64(0)
			if scenario == 0 {
				want = source + 2
			}
			result.ExpectReturn(want)
		case "strspn", "strcspn":
			values := [][]byte{[]byte("aaabx\x00"), []byte("xyzab\x00")}
			sets := [][]byte{[]byte("ab\x00"), []byte("xyz\x00")}
			wants := []uint64{4, 3}
			if name == "strcspn" {
				values = [][]byte{[]byte("abcx\x00"), []byte("raven\x00")}
				sets = [][]byte{[]byte("x\x00"), []byte("v\x00")}
				wants = []uint64{3, 2}
			}
			value := values[scenario]
			setValue := sets[scenario]
			source, ok := allocate(value)
			if !ok {
				return
			}
			set, ok := allocate(setValue)
			if !ok {
				return
			}
			result, ok := call([]crtContractMemoryWatch{{Address: source, Size: len(value)}, {Address: set, Size: len(setValue)}}, source, set)
			if !ok {
				return
			}
			result.ExpectReturn(wants[scenario])
		default:
			invocation.Failf("unknown string contract %q", name)
			return
		}
	}
}
