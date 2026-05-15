//go:build guest_windows

package main

import (
	"strconv"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

const (
	crtNumericErrnoEINVAL = 22
	crtNumericErrnoERANGE = 34
)

var crtNumericModules = []string{
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

var crtNumericLongLongModules = []string{
	"msvcr120.dll",
	"msvcr120_app.dll",
	"ucrtbase.dll",
}

type crtNumericSemantic struct {
	name      string
	id        string
	signature string
	modules   []string
	wide      bool
	mode      string
	signed    bool
	bits      int
	handler   ntapi.TrapHandler
}

var crtNumericSemantics = []crtNumericSemantic{
	{name: "strtol", id: "crt.numeric.strtol.v1", signature: "cdecl(str ptr long)", modules: crtNumericModules, mode: "parse", signed: true, bits: 32, handler: crtStrtol},
	{name: "strtoul", id: "crt.numeric.strtoul.v1", signature: "cdecl(str ptr long)", modules: crtNumericModules, mode: "parse", bits: 32, handler: crtStrtoul},
	{name: "strtoll", id: "crt.numeric.strtoll.v1", signature: "cdecl(str ptr long)", modules: crtNumericLongLongModules, mode: "parse", signed: true, bits: 64, handler: crtStrtoll},
	{name: "strtoull", id: "crt.numeric.strtoull.v1", signature: "cdecl(str ptr long)", modules: crtNumericLongLongModules, mode: "parse", bits: 64, handler: crtStrtoull},
	{name: "wcstol", id: "crt.numeric.wcstol.v1", signature: "cdecl(wstr ptr long)", modules: crtNumericModules, wide: true, mode: "parse", signed: true, bits: 32, handler: crtWcstolNumeric},
	{name: "wcstoul", id: "crt.numeric.wcstoul.v1", signature: "cdecl(wstr ptr long)", modules: crtNumericModules, wide: true, mode: "parse", bits: 32, handler: crtWcstoulNumeric},
	{name: "wcstoll", id: "crt.numeric.wcstoll.v1", signature: "cdecl(wstr ptr long)", modules: crtNumericLongLongModules, wide: true, mode: "parse", signed: true, bits: 64, handler: crtWcstollNumeric},
	{name: "wcstoull", id: "crt.numeric.wcstoull.v1", signature: "cdecl(wstr ptr long)", modules: crtNumericLongLongModules, wide: true, mode: "parse", bits: 64, handler: crtWcstoullNumeric},
	{name: "atoi", id: "crt.numeric.atoi.v1", signature: "cdecl(str)", modules: crtNumericModules, mode: "atoi", signed: true, bits: 32, handler: crtAtoiNumeric},
	{name: "atol", id: "crt.numeric.atol.v1", signature: "cdecl(str)", modules: crtNumericModules, mode: "atoi", signed: true, bits: 32, handler: crtAtolNumeric},
	{name: "atoll", id: "crt.numeric.atoll.v1", signature: "cdecl(str)", modules: crtNumericLongLongModules, mode: "atoi", signed: true, bits: 64, handler: crtAtollNumeric},
	{name: "_itoa", id: "crt.numeric.itoa.v1", signature: "cdecl(long ptr long)", modules: crtNumericModules, mode: "itoa", signed: true, bits: 32, handler: crtItoaNumeric},
	{name: "_itow", id: "crt.numeric.itow.v1", signature: "cdecl(long ptr long)", modules: crtNumericModules, wide: true, mode: "itoa", signed: true, bits: 32, handler: crtItowNumeric},
	{name: "_ultoa", id: "crt.numeric.ultoa.v1", signature: "cdecl(long ptr long)", modules: crtNumericModules, mode: "itoa", bits: 32, handler: crtUltoaNumeric},
	{name: "_ultow", id: "crt.numeric.ultow.v1", signature: "cdecl(long ptr long)", modules: crtNumericModules, wide: true, mode: "itoa", bits: 32, handler: crtUltowNumeric},
}

func init() {
	registerCRTProvider(registerCRTNumericDefinitions)
	for _, semantic := range crtNumericSemantics {
		registerCRTNumericContractCases(semantic)
	}
}

func registerCRTNumericDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtNumericSemantics {
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

type crtNumericParsed struct {
	value uint64
	end   int
	errno uint32
}

func crtNumericDigit(value uint32) int {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0')
	case value >= 'a' && value <= 'z':
		return int(value-'a') + 10
	case value >= 'A' && value <= 'Z':
		return int(value-'A') + 10
	default:
		return -1
	}
}

func crtNumericSpace(value uint32) bool {
	switch value {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

func crtNumericParseInput(length int, read func(int) uint32, base int, signed bool, bits int) crtNumericParsed {
	if base != 0 && (base < 2 || base > 36) {
		return crtNumericParsed{errno: crtNumericErrnoEINVAL}
	}
	i := 0
	for i < length && crtNumericSpace(read(i)) {
		i++
	}
	negative := false
	if i < length {
		switch read(i) {
		case '+':
			i++
		case '-':
			negative = true
			i++
		}
	}
	actualBase := base
	if actualBase == 0 {
		actualBase = 10
		if i < length && read(i) == '0' {
			actualBase = 8
		}
	}
	if actualBase == 16 && i+2 <= length && read(i) == '0' && (read(i+1) == 'x' || read(i+1) == 'X') {
		if i+2 < length {
			if digit := crtNumericDigit(read(i + 2)); digit >= 0 && digit < actualBase {
				i += 2
			}
		}
	}
	if actualBase == 8 && i+2 <= length && read(i) == '0' && (read(i+1) == 'x' || read(i+1) == 'X') {
		if i+2 < length {
			if digit := crtNumericDigit(read(i + 2)); digit >= 0 && digit < 16 {
				actualBase = 16
				i += 2
			}
		}
	}
	digitsStart := i
	maxUnsigned := ^uint64(0)
	if bits < 64 {
		maxUnsigned = (uint64(1) << bits) - 1
	}
	limit := maxUnsigned
	if signed {
		limit = maxUnsigned >> 1
		if negative {
			limit++
		}
	}
	value := uint64(0)
	overflow := false
	for i < length {
		digit := crtNumericDigit(read(i))
		if digit < 0 || digit >= actualBase {
			break
		}
		if value > (limit-uint64(digit))/uint64(actualBase) {
			overflow = true
		} else if !overflow {
			value = value*uint64(actualBase) + uint64(digit)
		}
		i++
	}
	if i == digitsStart {
		return crtNumericParsed{}
	}
	if overflow {
		if signed {
			if negative {
				value = uint64(0) - limit
			} else {
				value = limit
			}
		} else {
			value = maxUnsigned
		}
		return crtNumericParsed{value: value, end: i, errno: crtNumericErrnoERANGE}
	}
	if negative {
		value = uint64(0) - value
		if bits < 64 {
			value &= maxUnsigned
		}
	}
	return crtNumericParsed{value: value, end: i}
}

func crtNumericSetErrno(ctx *ntapi.TrapContext, value uint32) {
	crtWriteErrno(ctx, value)
}

func crtNumericErrnoValue(mem *mmu.MMU) uint32 {
	return crtReadErrno(mem, 0)
}

func crtNumericSetReturn(ctx *ntapi.TrapContext, value uint64, bits int) {
	if bits == 32 {
		ctx.SetReturn(uint64(uint32(value)))
		return
	}
	if ctx.Mem != nil && ctx.Mem.Mode32 {
		if registers, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
			registers.WriteReg(x64.RDX, uint64(uint32(value>>32)))
		}
		ctx.SetReturn(uint64(uint32(value)))
		return
	}
	ctx.SetReturn(value)
}

func crtNumericWriteEnd(ctx *ntapi.TrapContext, address, value uint64) bool {
	if address == 0 {
		return true
	}
	width := uint64(8)
	if ctx.Mem.Mode32 {
		width = 4
	}
	if !crtMemoryRange(ctx.Mem, address, width, mmu.PermWrite) {
		return false
	}
	if width == 4 {
		return ctx.Mem.Write32(address, uint32(value)) == nil
	}
	return ctx.Mem.Write64(address, value) == nil
}

func crtNumericParseNarrow(ctx *ntapi.TrapContext, signed bool, bits int) uint32 {
	value, ok := crtReadNarrowString(ctx.Mem, ctx.Arg(0))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	parsed := crtNumericParseInput(len(value), func(index int) uint32 { return uint32(value[index]) }, int(int32(ctx.Arg(2))), signed, bits)
	if parsed.errno != 0 {
		crtNumericSetErrno(ctx, parsed.errno)
	}
	if !crtNumericWriteEnd(ctx, ctx.Arg(1), ctx.Arg(0)+uint64(parsed.end)) {
		return crtMemoryAccessFailure(ctx)
	}
	crtNumericSetReturn(ctx, parsed.value, bits)
	return 0
}

func crtNumericParseWide(ctx *ntapi.TrapContext, signed bool, bits int) uint32 {
	value, ok := crtReadWideString(ctx.Mem, ctx.Arg(0))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	parsed := crtNumericParseInput(len(value), func(index int) uint32 { return uint32(value[index]) }, int(int32(ctx.Arg(2))), signed, bits)
	if parsed.errno != 0 {
		crtNumericSetErrno(ctx, parsed.errno)
	}
	end := ctx.Arg(0) + uint64(parsed.end)*2
	if end < ctx.Arg(0) || !crtNumericWriteEnd(ctx, ctx.Arg(1), end) {
		return crtMemoryAccessFailure(ctx)
	}
	crtNumericSetReturn(ctx, parsed.value, bits)
	return 0
}

func crtNumericAtoi(ctx *ntapi.TrapContext, bits int) uint32 {
	value, ok := crtReadNarrowString(ctx.Mem, ctx.Arg(0))
	if !ok {
		return crtMemoryAccessFailure(ctx)
	}
	parsed := crtNumericParseInput(len(value), func(index int) uint32 { return uint32(value[index]) }, 10, true, bits)
	if parsed.errno != 0 {
		crtNumericSetErrno(ctx, parsed.errno)
	}
	crtNumericSetReturn(ctx, parsed.value, bits)
	return 0
}

func crtNumericFormatNarrow(ctx *ntapi.TrapContext, signed bool) uint32 {
	base := int(int32(ctx.Arg(2)))
	if base < 2 || base > 36 {
		crtNumericSetErrno(ctx, crtNumericErrnoEINVAL)
		ctx.SetReturn(0)
		return 0
	}
	var text string
	if signed && base == 10 {
		text = strconv.FormatInt(int64(int32(ctx.Arg(0))), base)
	} else {
		text = strconv.FormatUint(uint64(uint32(ctx.Arg(0))), base)
	}
	data := append([]byte(text), 0)
	buffer := ctx.Arg(1)
	if buffer == 0 || !crtMemoryRange(ctx.Mem, buffer, uint64(len(data)), mmu.PermWrite) || ctx.Mem.WriteBytes(buffer, data) != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(buffer)
	return 0
}

func crtNumericFormatWide(ctx *ntapi.TrapContext, signed bool) uint32 {
	base := int(int32(ctx.Arg(2)))
	if base < 2 || base > 36 {
		crtNumericSetErrno(ctx, crtNumericErrnoEINVAL)
		ctx.SetReturn(0)
		return 0
	}
	var text string
	if signed && base == 10 {
		text = strconv.FormatInt(int64(int32(ctx.Arg(0))), base)
	} else {
		text = strconv.FormatUint(uint64(uint32(ctx.Arg(0))), base)
	}
	units := make([]uint16, len(text)+1)
	for index := range text {
		units[index] = uint16(text[index])
	}
	data := crtWideBytes(units[:len(text)], true)
	buffer := ctx.Arg(1)
	if buffer == 0 || !crtMemoryRange(ctx.Mem, buffer, uint64(len(data)), mmu.PermWrite) || ctx.Mem.WriteBytes(buffer, data) != nil {
		return crtMemoryAccessFailure(ctx)
	}
	ctx.SetReturn(buffer)
	return 0
}

func crtStrtol(ctx *ntapi.TrapContext) uint32   { return crtNumericParseNarrow(ctx, true, 32) }
func crtStrtoul(ctx *ntapi.TrapContext) uint32  { return crtNumericParseNarrow(ctx, false, 32) }
func crtStrtoll(ctx *ntapi.TrapContext) uint32  { return crtNumericParseNarrow(ctx, true, 64) }
func crtStrtoull(ctx *ntapi.TrapContext) uint32 { return crtNumericParseNarrow(ctx, false, 64) }
func crtWcstolNumeric(ctx *ntapi.TrapContext) uint32 {
	return crtNumericParseWide(ctx, true, 32)
}
func crtWcstoulNumeric(ctx *ntapi.TrapContext) uint32 {
	return crtNumericParseWide(ctx, false, 32)
}
func crtWcstollNumeric(ctx *ntapi.TrapContext) uint32 {
	return crtNumericParseWide(ctx, true, 64)
}
func crtWcstoullNumeric(ctx *ntapi.TrapContext) uint32 {
	return crtNumericParseWide(ctx, false, 64)
}
func crtAtoiNumeric(ctx *ntapi.TrapContext) uint32  { return crtNumericAtoi(ctx, 32) }
func crtAtolNumeric(ctx *ntapi.TrapContext) uint32  { return crtNumericAtoi(ctx, 32) }
func crtAtollNumeric(ctx *ntapi.TrapContext) uint32 { return crtNumericAtoi(ctx, 64) }
func crtItoaNumeric(ctx *ntapi.TrapContext) uint32  { return crtNumericFormatNarrow(ctx, true) }
func crtUltoaNumeric(ctx *ntapi.TrapContext) uint32 { return crtNumericFormatNarrow(ctx, false) }
func crtItowNumeric(ctx *ntapi.TrapContext) uint32  { return crtNumericFormatWide(ctx, true) }
func crtUltowNumeric(ctx *ntapi.TrapContext) uint32 { return crtNumericFormatWide(ctx, false) }

func registerCRTNumericContractCases(semantic crtNumericSemantic) {
	for _, module := range semantic.modules {
		for _, architecture := range []string{"i386", "win64"} {
			semantic := semantic
			registerCRTContractCase(crtContractCase{
				CaseID:           semantic.id + ".contract",
				Module:           module,
				ExportName:       semantic.name,
				Architecture:     architecture,
				ImplementationID: semantic.id,
				Signature:        semantic.signature,
				Exercise: func(invocation *crtContractInvocation) {
					exerciseCRTNumericContract(invocation, semantic)
				},
			})
		}
	}
}

func crtNumericContractString(invocation *crtContractInvocation, value string, wide bool) (uint64, int, bool) {
	address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if wide {
		data := crtWideASCII(value)
		return address, len(data) / 2, invocation.Mem.WriteBytes(address, data) == nil
	}
	data := append([]byte(value), 0)
	return address, len(data), invocation.Mem.WriteBytes(address, data) == nil
}

func crtNumericContractPointer(invocation *crtContractInvocation, value uint64) (uint64, bool) {
	address := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if invocation.Is32 {
		return address, invocation.Mem.Write32(address, uint32(value)) == nil
	}
	return address, invocation.Mem.Write64(address, value) == nil
}

func crtNumericContractReadPointer(invocation *crtContractInvocation, address uint64) (uint64, error) {
	if invocation.Is32 {
		value, err := invocation.Mem.Read32(address)
		return uint64(value), err
	}
	return invocation.Mem.Read64(address)
}

func crtNumericContractReturn(value uint64, bits int) uint64 {
	if bits == 32 {
		return uint64(uint32(value))
	}
	return value
}

func exerciseCRTNumericContract(invocation *crtContractInvocation, semantic crtNumericSemantic) {
	switch semantic.mode {
	case "parse":
		input, _, ok := crtNumericContractString(invocation, " -0x2a tail", semantic.wide)
		if !ok {
			invocation.Failf("write numeric input")
			return
		}
		endptr, ok := crtNumericContractPointer(invocation, 0)
		if !ok {
			invocation.Failf("allocate numeric end pointer")
			return
		}
		call := invocation.CallWatching
		if semantic.bits == 64 {
			call = invocation.CallWatchingReturn64
		}
		result, err := call(nil, input, endptr, 0)
		if err != nil {
			invocation.Failf("dispatch numeric parser: %v", err)
			return
		}
		result.recordAssertion(result.Return == crtNumericContractReturn(^uint64(41), semantic.bits), "parser return %#x", result.Return)
		end, err := crtNumericContractReadPointer(invocation, endptr)
		endOffset := uint64(6)
		if semantic.wide {
			endOffset *= 2
		}
		result.recordAssertion(err == nil && end == input+endOffset, "parser end pointer %#x", end)

		overflowText := "999999999999999999999999999999999999"
		overflowInput, _, ok := crtNumericContractString(invocation, overflowText, semantic.wide)
		if !ok {
			invocation.Failf("write overflow input")
			return
		}
		overflowEnd, ok := crtNumericContractPointer(invocation, 0)
		if !ok {
			invocation.Failf("allocate overflow end pointer")
			return
		}
		result, err = call(nil, overflowInput, overflowEnd, 10)
		if err != nil {
			invocation.Failf("dispatch overflow parser: %v", err)
			return
		}
		want := uint64(^uint32(0))
		if semantic.signed {
			if semantic.bits == 32 {
				want = uint64(^uint32(0) >> 1)
			} else {
				want = uint64(^uint64(0) >> 1)
			}
		} else if semantic.bits == 64 {
			want = ^uint64(0)
		}
		result.recordAssertion(result.Return == crtNumericContractReturn(want, semantic.bits), "overflow return %#x", result.Return)
		result.recordAssertion(crtNumericErrnoValue(invocation.Mem) == crtNumericErrnoERANGE, "overflow errno %d", crtNumericErrnoValue(invocation.Mem))
	case "atoi":
		input, _, ok := crtNumericContractString(invocation, " -42xyz", false)
		if !ok {
			invocation.Failf("write atoi input")
			return
		}
		crtNumericSetErrno(&ntapi.TrapContext{Mem: invocation.Mem}, 0x1234)
		call := invocation.CallWatching
		if semantic.bits == 64 {
			call = invocation.CallWatchingReturn64
		}
		result, err := call(nil, input)
		if err != nil {
			invocation.Failf("dispatch atoi: %v", err)
			return
		}
		result.recordAssertion(result.Return == crtNumericContractReturn(^uint64(41), semantic.bits), "atoi return %#x", result.Return)
		result.recordAssertion(crtNumericErrnoValue(invocation.Mem) == 0x1234, "atoi changed errno to %d", crtNumericErrnoValue(invocation.Mem))
		secondInput, _, ok := crtNumericContractString(invocation, "17", false)
		if !ok {
			invocation.Failf("write second atoi input")
			return
		}
		result, err = call(nil, secondInput)
		if err != nil {
			invocation.Failf("dispatch second atoi: %v", err)
			return
		}
		result.recordAssertion(result.Return == 17, "second atoi return %#x", result.Return)
		result.recordAssertion(crtNumericErrnoValue(invocation.Mem) == 0x1234, "second atoi changed errno to %d", crtNumericErrnoValue(invocation.Mem))
	case "itoa":
		buffer := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		negative := int32(-42)
		args := []uint64{uint64(uint32(negative)), buffer, 16}
		if !semantic.signed {
			args[0] = 0xfeedbeef
		}
		data := []byte("ffffffd6\x00")
		if !semantic.signed {
			data = []byte("feedbeef\x00")
		}
		if semantic.wide {
			units := make([]uint16, len(data))
			for index, value := range data {
				units[index] = uint16(value)
			}
			data = crtWideBytes(units[:len(units)-1], true)
		}
		result, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: buffer, Size: len(data)}}, args...)
		if err != nil {
			invocation.Failf("dispatch numeric formatter: %v", err)
			return
		}
		result.recordAssertion(result.Return == buffer, "formatter buffer %#x", result.Return)
		result.ExpectMemory(0, data)

		secondBuffer := invocation.Mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		secondData := []byte("37\x00")
		if semantic.wide {
			secondData = crtWideASCII("37")
		}
		result, err = invocation.CallWatching(
			[]crtContractMemoryWatch{{Address: secondBuffer, Size: len(secondData)}},
			37, secondBuffer, 10,
		)
		if err != nil {
			invocation.Failf("dispatch second numeric formatter: %v", err)
			return
		}
		result.recordAssertion(result.Return == secondBuffer, "second formatter buffer %#x", result.Return)
		result.ExpectMemory(0, secondData)
	}
}
