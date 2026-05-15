//go:build guest_windows

package main

import (
	"encoding/binary"
	gotime "time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	crtTimeEINVAL    = 22
	crtTimeTMSize    = 9 * 4
	crtTimeMin64     = int64(0)
	crtTimeMax32     = int64(2147471999)
	crtTimeMax64     = int64(32535215999)
	crtTimeGMTModule = "ucrtbase.dll"
)

type crtTimeSemantic struct {
	name      string
	id        string
	signature string
	bits      int
	secure    bool
	handler   ntapi.TrapHandler
}

var (
	crtTimeGMT32  = crtTimeGMTHandler(32)
	crtTimeGMT32S = crtTimeGMTSHandler(32)
	crtTimeGMT64  = crtTimeGMTHandler(64)
	crtTimeGMT64S = crtTimeGMTSHandler(64)
)

var crtTimeSemantics = []crtTimeSemantic{
	{name: "_gmtime32", id: "crt.time.gmtime32.v1", signature: "cdecl(ptr)", bits: 32, handler: crtTimeGMT32},
	{name: "_gmtime32_s", id: "crt.time.gmtime32.s.v1", signature: "cdecl(ptr ptr)", bits: 32, secure: true, handler: crtTimeGMT32S},
	{name: "_gmtime64", id: "crt.time.gmtime64.v1", signature: "cdecl(ptr)", bits: 64, handler: crtTimeGMT64},
	{name: "_gmtime64_s", id: "crt.time.gmtime64.s.v1", signature: "cdecl(ptr ptr)", bits: 64, secure: true, handler: crtTimeGMT64S},
	{name: "_o__gmtime32", id: "crt.time.gmtime32.v1", signature: "cdecl(ptr)", bits: 32, handler: crtTimeGMT32},
	{name: "_o__gmtime32_s", id: "crt.time.gmtime32.s.v1", signature: "cdecl(ptr ptr)", bits: 32, secure: true, handler: crtTimeGMT32S},
	{name: "_o__gmtime64", id: "crt.time.gmtime64.v1", signature: "cdecl(ptr)", bits: 64, handler: crtTimeGMT64},
	{name: "_o__gmtime64_s", id: "crt.time.gmtime64.s.v1", signature: "cdecl(ptr ptr)", bits: 64, secure: true, handler: crtTimeGMT64S},
}

func init() {
	registerCRTProvider(registerCRTTimeDefinitions)
	for _, semantic := range crtTimeSemantics {
		registerCRTTimeContractCases(semantic)
	}
}

func registerCRTTimeDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtTimeSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   []string{crtTimeGMTModule},
			AllowedArch:      []string{"i386", "win64"},
			Handler:          semantic.handler,
		})
	}
}

func crtTimeGMTHandler(bits int) ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		if ctx.Arg(0) == 0 {
			crtTimeWriteErrno(ctx, crtTimeEINVAL)
			crtInvokeInvalidParameter(ctx, 0, 0, 0, 0, 0)
			ctx.SetReturn(0)
			return 0
		}
		buffer := crtTimeBuffer(ctx)
		if buffer == 0 || crtTimeGMT(ctx, buffer, ctx.Arg(0), bits, true) != 0 {
			ctx.SetReturn(0)
			return 0
		}
		ctx.SetReturn(buffer)
		return 0
	}
}

func crtTimeGMTSHandler(bits int) ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		result := crtTimeGMT(ctx, ctx.Arg(0), ctx.Arg(1), bits, false)
		ctx.SetReturn(uint64(result))
		return 0
	}
}

func crtTimeBuffer(ctx *ntapi.TrapContext) uint64 {
	if ctx == nil || ctx.Mem == nil || ctx.State == nil {
		return 0
	}
	teb := crtTimeCurrentTEB(ctx)
	return ctx.State.GetOrCreateRuntimePointer("ucrt.gmtime", teb, func() uint64 {
		return ctx.Mem.Mmap(0, crtTimeTMSize, mmu.PermRead|mmu.PermWrite)
	})
}

func crtTimeCurrentTEB(ctx *ntapi.TrapContext) uint64 {
	if ctx == nil {
		return 0
	}
	if ctx.CPU != nil {
		if ctx.Mem != nil && ctx.Mem.Mode32 {
			if teb := ctx.CPU.GetTLS(); teb != 0 {
				return teb
			}
		} else if cpu, ok := ctx.CPU.(interface{ GetGSBase() uint64 }); ok {
			if teb := cpu.GetGSBase(); teb != 0 {
				return teb
			}
		}
	}
	if ctx.State != nil {
		return ctx.State.TEBAddr
	}
	return 0
}

func crtTimeWriteErrno(ctx *ntapi.TrapContext, value uint32) bool {
	if ctx == nil {
		return false
	}
	return crtWriteErrnoAtTEB(ctx, crtTimeCurrentTEB(ctx), value)
}

func crtTimeGMT(ctx *ntapi.TrapContext, resultAddress, secondsAddress uint64, bits int, invokeRangeHandler bool) uint32 {
	seconds, ok := crtTimeReadSeconds(ctx, secondsAddress, bits)
	maxSeconds := crtTimeMax64
	if bits == 32 {
		maxSeconds = crtTimeMax32
	}
	rangeInvalid := seconds < crtTimeMin64 || seconds > maxSeconds
	if resultAddress == 0 || !ok || rangeInvalid {
		if resultAddress != 0 {
			crtTimeWriteInvalidTM(ctx.Mem, resultAddress)
		}
		crtTimeWriteErrno(ctx, crtTimeEINVAL)
		if resultAddress == 0 || !ok || (invokeRangeHandler && rangeInvalid) {
			crtInvokeInvalidParameter(ctx, 0, 0, 0, 0, 0)
		}
		return crtTimeEINVAL
	}
	if !crtTimeWriteTM(ctx.Mem, resultAddress, gotime.Unix(seconds, 0).UTC()) {
		crtTimeWriteErrno(ctx, crtTimeEINVAL)
		return crtTimeEINVAL
	}
	return 0
}

func crtTimeReadSeconds(ctx *ntapi.TrapContext, address uint64, bits int) (int64, bool) {
	if ctx == nil || ctx.Mem == nil || address == 0 {
		return 0, false
	}
	if bits == 32 {
		value, err := ctx.Mem.Read32(address)
		return int64(int32(value)), err == nil
	}
	value, err := ctx.Mem.Read64(address)
	return int64(value), err == nil
}

func crtTimeWriteTM(mem *mmu.MMU, address uint64, value gotime.Time) bool {
	fields := [...]int32{
		int32(value.Second()),
		int32(value.Minute()),
		int32(value.Hour()),
		int32(value.Day()),
		int32(value.Month()) - 1,
		int32(value.Year()) - 1900,
		int32(value.Weekday()),
		int32(value.YearDay()) - 1,
		0,
	}
	data := make([]byte, crtTimeTMSize)
	for index, field := range fields {
		binary.LittleEndian.PutUint32(data[index*4:], uint32(field))
	}
	return crtMemoryRange(mem, address, crtTimeTMSize, mmu.PermWrite) && mem.WriteBytes(address, data) == nil
}

func crtTimeWriteInvalidTM(mem *mmu.MMU, address uint64) {
	data := make([]byte, crtTimeTMSize)
	for index := 0; index < len(data); index += 4 {
		binary.LittleEndian.PutUint32(data[index:], ^uint32(0))
	}
	if crtMemoryRange(mem, address, crtTimeTMSize, mmu.PermWrite) {
		_ = mem.WriteBytes(address, data)
	}
}

func registerCRTTimeContractCases(semantic crtTimeSemantic) {
	for _, architecture := range []string{"i386", "win64"} {
		registerCRTContractCase(crtContractCase{
			CaseID:           semantic.id + ".contract",
			Module:           crtTimeGMTModule,
			ExportName:       semantic.name,
			Architecture:     architecture,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			Exercise: func(invocation *crtContractInvocation) {
				crtExerciseTimeContract(invocation, semantic)
			},
		})
	}
}

func crtExerciseTimeContract(invocation *crtContractInvocation, semantic crtTimeSemantic) {
	epoch := crtTimeContractSeconds(invocation.Mem, semantic.bits, 0)
	boundaryValue := crtTimeMax32
	boundaryTM := crtTimeLiteralTM(59, 59, 23, 18, 0, 138, 1, 17, 0)
	invalidValue := crtTimeMin64 - 1
	if semantic.bits == 64 {
		boundaryValue = crtTimeMax64
		boundaryTM = crtTimeLiteralTM(59, 59, 23, 31, 11, 1100, 3, 364, 0)
		invalidValue = crtTimeMax64 + 1
	}
	boundary := crtTimeContractSeconds(invocation.Mem, semantic.bits, boundaryValue)
	invalid := crtTimeContractSeconds(invocation.Mem, semantic.bits, invalidValue)
	if epoch == 0 || boundary == 0 || invalid == 0 {
		invocation.Failf("allocate time contract input")
		return
	}
	epochTM := crtTimeLiteralTM(0, 0, 0, 1, 0, 70, 4, 0, 0)
	if semantic.secure {
		output := invocation.Mem.Mmap(0, crtTimeTMSize, mmu.PermRead|mmu.PermWrite)
		for _, scenario := range []struct {
			input uint64
			want  []byte
		}{{epoch, epochTM}, {boundary, boundaryTM}} {
			result, err := invocation.CallWatching(
				[]crtContractMemoryWatch{{Address: output, Size: crtTimeTMSize}},
				output,
				scenario.input,
			)
			if err != nil {
				invocation.Failf("dispatch secure gmtime contract: %v", err)
				return
			}
			result.ExpectReturn(0)
			result.ExpectMemory(0, scenario.want)
		}
		errnoContext := &ntapi.TrapContext{Mem: invocation.Mem}
		if !crtTimeWriteErrno(errnoContext, 0x1234) {
			invocation.Failf("initialize time contract errno")
			return
		}
		errnoAddress := crtErrnoAddress(errnoContext)
		result, err := invocation.CallWatching(
			[]crtContractMemoryWatch{
				{Address: output, Size: crtTimeTMSize},
				{Address: errnoAddress, Size: 4},
			},
			output,
			invalid,
		)
		if err != nil {
			invocation.Failf("dispatch secure gmtime error contract: %v", err)
			return
		}
		result.ExpectReturn(crtTimeEINVAL)
		result.ExpectMemory(0, crtTimeInvalidTM())
		result.recordAssertion(crtReadErrno(invocation.Mem, 0) == crtTimeEINVAL, "secure gmtime errno %d", crtReadErrno(invocation.Mem, 0))
		return
	}
	first, err := invocation.Call(epoch)
	if err != nil {
		invocation.Failf("dispatch gmtime epoch contract: %v", err)
		return
	}
	firstResult := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: first}
	firstData, readErr := invocation.Mem.ReadBytes(first, crtTimeTMSize)
	firstResult.recordAssertion(first != 0 && readErr == nil && string(firstData) == string(epochTM), "gmtime epoch output %x", firstData)
	second, err := invocation.CallWatching(
		[]crtContractMemoryWatch{{Address: first, Size: crtTimeTMSize}},
		boundary,
	)
	if err != nil {
		invocation.Failf("dispatch gmtime leap contract: %v", err)
		return
	}
	second.recordAssertion(second.Return == first, "gmtime buffer changed from %#x to %#x", first, second.Return)
	second.ExpectMemory(0, boundaryTM)
	errnoContext := &ntapi.TrapContext{Mem: invocation.Mem}
	if !crtTimeWriteErrno(errnoContext, 0x1234) {
		invocation.Failf("initialize time contract errno")
		return
	}
	errnoAddress := crtErrnoAddress(errnoContext)
	third, err := invocation.CallWatching(
		[]crtContractMemoryWatch{
			{Address: first, Size: crtTimeTMSize},
			{Address: errnoAddress, Size: 4},
		},
		invalid,
	)
	if err != nil {
		invocation.Failf("dispatch gmtime error contract: %v", err)
		return
	}
	third.ExpectReturn(0)
	third.ExpectMemory(0, crtTimeInvalidTM())
	third.recordAssertion(crtReadErrno(invocation.Mem, 0) == crtTimeEINVAL, "gmtime errno %d", crtReadErrno(invocation.Mem, 0))
}

func crtTimeContractSeconds(mem *mmu.MMU, bits int, value int64) uint64 {
	address := mem.Mmap(0, 8, mmu.PermRead|mmu.PermWrite)
	if bits == 32 {
		if mem.Write32(address, uint32(value)) != nil {
			return 0
		}
		return address
	}
	if mem.Write64(address, uint64(value)) != nil {
		return 0
	}
	return address
}

func crtTimeLiteralTM(fields ...int32) []byte {
	data := make([]byte, crtTimeTMSize)
	for index, field := range fields {
		binary.LittleEndian.PutUint32(data[index*4:], uint32(field))
	}
	return data
}

func crtTimeInvalidTM() []byte {
	data := make([]byte, crtTimeTMSize)
	for index := range data {
		data[index] = 0xff
	}
	return data
}
