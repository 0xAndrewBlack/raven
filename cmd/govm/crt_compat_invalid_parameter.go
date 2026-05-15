//go:build guest_windows

package main

import (
	"encoding/binary"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	crtInvalidGlobalNamespace = "crt.invalid_parameter.global"
	crtInvalidThreadNamespace = "crt.invalid_parameter.thread"
	crtInvalidRuntimeStatus   = 0xC0000417
)

type crtInvalidParameterKind uint8

const (
	crtInvalidGetGlobal crtInvalidParameterKind = iota
	crtInvalidSetGlobal
	crtInvalidGetThread
	crtInvalidSetThread
	crtInvalidInvoke
	crtInvalidInvokeNoReturn
	crtInvalidInvokeWatson
)

type crtInvalidParameterSemantic struct {
	name      string
	module    string
	id        string
	signature string
	kind      crtInvalidParameterKind
	handler   ntapi.TrapHandler
}

var (
	crtInvalidGetGlobalHandler      = crtInvalidParameterGetHandler(false)
	crtInvalidSetGlobalHandler      = crtInvalidParameterSetHandler(false)
	crtInvalidGetThreadHandler      = crtInvalidParameterGetHandler(true)
	crtInvalidSetThreadHandler      = crtInvalidParameterSetHandler(true)
	crtInvalidInvokeHandler         = crtInvalidParameterInvokeHandler(false, false)
	crtInvalidInvokeNoReturnHandler = crtInvalidParameterInvokeHandler(false, true)
	crtInvalidInvokeFull            = crtInvalidParameterInvokeHandler(true, false)
	crtInvalidInvokeWatsonHandler   = crtInvalidParameterWatsonHandler()
)

var crtInvalidParameterSemantics = []crtInvalidParameterSemantic{
	{name: "_get_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.get.global.v1", signature: "cdecl()", kind: crtInvalidGetGlobal, handler: crtInvalidGetGlobalHandler},
	{name: "_set_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.set.global.v1", signature: "cdecl(ptr)", kind: crtInvalidSetGlobal, handler: crtInvalidSetGlobalHandler},
	{name: "_get_thread_local_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.get.thread.v1", signature: "cdecl()", kind: crtInvalidGetThread, handler: crtInvalidGetThreadHandler},
	{name: "_set_thread_local_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.set.thread.v1", signature: "cdecl(ptr)", kind: crtInvalidSetThread, handler: crtInvalidSetThreadHandler},
	{name: "_invalid_parameter_noinfo", module: "ucrtbase.dll", id: "crt.invalid.invoke.v1", signature: "cdecl()", kind: crtInvalidInvoke, handler: crtInvalidInvokeHandler},
	{name: "_invalid_parameter_noinfo_noreturn", module: "ucrtbase.dll", id: "crt.invalid.invoke.noreturn.v1", signature: "cdecl()", kind: crtInvalidInvokeNoReturn, handler: crtInvalidInvokeNoReturnHandler},
	{name: "_invoke_watson", module: "ucrtbase.dll", id: "crt.invalid.watson.v1", signature: "cdecl(ptr ptr ptr long long)", kind: crtInvalidInvokeWatson, handler: crtInvalidInvokeWatsonHandler},
	{name: "_o__get_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.get.global.v1", signature: "cdecl()", kind: crtInvalidGetGlobal, handler: crtInvalidGetGlobalHandler},
	{name: "_o__set_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.set.global.v1", signature: "cdecl(ptr)", kind: crtInvalidSetGlobal, handler: crtInvalidSetGlobalHandler},
	{name: "_o__get_thread_local_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.get.thread.v1", signature: "cdecl()", kind: crtInvalidGetThread, handler: crtInvalidGetThreadHandler},
	{name: "_o__set_thread_local_invalid_parameter_handler", module: "ucrtbase.dll", id: "crt.invalid.set.thread.v1", signature: "cdecl(ptr)", kind: crtInvalidSetThread, handler: crtInvalidSetThreadHandler},
	{name: "_o__invalid_parameter_noinfo", module: "ucrtbase.dll", id: "crt.invalid.invoke.v1", signature: "cdecl()", kind: crtInvalidInvoke, handler: crtInvalidInvokeHandler},
	{name: "_o__invalid_parameter_noinfo_noreturn", module: "ucrtbase.dll", id: "crt.invalid.invoke.noreturn.v1", signature: "cdecl()", kind: crtInvalidInvokeNoReturn, handler: crtInvalidInvokeNoReturnHandler},
	{name: "_o__invoke_watson", module: "ucrtbase.dll", id: "crt.invalid.watson.v1", signature: "cdecl(ptr ptr ptr long long)", kind: crtInvalidInvokeWatson, handler: crtInvalidInvokeWatsonHandler},
	{name: "_invalid_parameter", module: "msvcrt.dll", id: "crt.invalid.invoke.full.v1", signature: "cdecl(ptr ptr ptr long long)", kind: crtInvalidInvoke, handler: crtInvalidInvokeFull},
}

func init() {
	registerCRTProvider(registerCRTInvalidParameterDefinitions)
	for _, semantic := range crtInvalidParameterSemantics {
		registerCRTInvalidParameterContractCases(semantic)
	}
}

func registerCRTInvalidParameterDefinitions(registry *crtSemanticRegistry) {
	for _, semantic := range crtInvalidParameterSemantics {
		registry.Define(crtSemanticDefinition{
			ExportName:       semantic.name,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			ContractCaseID:   semantic.id + ".contract",
			AllowedModules:   []string{semantic.module},
			AllowedArch:      []string{"i386", "win64"},
			Handler:          semantic.handler,
		})
	}
}

func crtInvalidParameterTEB(ctx *ntapi.TrapContext) uint64 {
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

func crtInvalidParameterGetHandler(threadLocal bool) ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		namespace, key := crtInvalidGlobalNamespace, uint64(0)
		if threadLocal {
			namespace, key = crtInvalidThreadNamespace, crtInvalidParameterTEB(ctx)
		}
		value := uint64(0)
		if ctx.State != nil {
			value = ctx.State.RuntimePointer(namespace, key)
		}
		ctx.SetReturn(value)
		return 0
	}
}

func crtInvalidParameterSetHandler(threadLocal bool) ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		namespace, key := crtInvalidGlobalNamespace, uint64(0)
		if threadLocal {
			namespace, key = crtInvalidThreadNamespace, crtInvalidParameterTEB(ctx)
		}
		previous := uint64(0)
		if ctx.State != nil {
			previous = ctx.State.SwapRuntimePointer(namespace, key, ctx.Arg(0))
		}
		ctx.SetReturn(previous)
		return 0
	}
}

func crtAbortInvalidParameter(ctx *ntapi.TrapContext) {
	if ctx == nil || ctx.CPU == nil {
		return
	}
	if aborter, ok := ctx.CPU.(interface{ Abort(error) }); ok {
		aborter.Abort(&arch.ExitError{Code: int(crtInvalidRuntimeStatus)})
	} else {
		ctx.CPU.Stop()
	}
}

func crtInvokeInvalidParameter(ctx *ntapi.TrapContext, args ...uint64) bool {
	if ctx == nil || ctx.CPU == nil || ctx.Mem == nil || ctx.State == nil {
		return false
	}
	handler := ctx.State.RuntimePointer(crtInvalidThreadNamespace, crtInvalidParameterTEB(ctx))
	if handler == 0 {
		handler = ctx.State.RuntimePointer(crtInvalidGlobalNamespace, 0)
	}
	if handler == 0 {
		crtAbortInvalidParameter(ctx)
		return true
	}
	trampoline := ctx.State.GetOrCreateGuestCallTrampoline(func() *ntapi.DllMainTrampoline {
		return ntapi.AllocTrampoline(ctx.Mem)
	})
	_, err := ntapi.CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, handler, args, ctx.Trace)
	if err != nil {
		crtAbortInvalidParameter(ctx)
		return false
	}
	return true
}

func crtInvalidParameterInvokeHandler(full, noReturn bool) ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		args := []uint64{0, 0, 0, 0, 0}
		if full {
			for index := range args {
				args[index] = ctx.Arg(index)
			}
		}
		crtInvokeInvalidParameter(ctx, args...)
		if noReturn {
			crtAbortInvalidParameter(ctx)
		}
		ctx.SetReturn(0)
		return 0
	}
}

func crtInvalidParameterWatsonHandler() ntapi.TrapHandler {
	return func(ctx *ntapi.TrapContext) uint32 {
		crtAbortInvalidParameter(ctx)
		ctx.SetReturn(0)
		return 0
	}
}

func registerCRTInvalidParameterContractCases(semantic crtInvalidParameterSemantic) {
	for _, architecture := range []string{"i386", "win64"} {
		registerCRTContractCase(crtContractCase{
			CaseID:           semantic.id + ".contract",
			Module:           semantic.module,
			ExportName:       semantic.name,
			Architecture:     architecture,
			ImplementationID: semantic.id,
			Signature:        semantic.signature,
			Exercise: func(invocation *crtContractInvocation) {
				crtExerciseInvalidParameterContract(invocation, semantic)
			},
		})
	}
}

func crtExerciseInvalidParameterContract(invocation *crtContractInvocation, semantic crtInvalidParameterSemantic) {
	state := invocation.Dispatcher.ProcessState()
	if state == nil {
		invocation.Failf("invalid-parameter contract has no process state")
		return
	}
	threadLocal := semantic.kind == crtInvalidGetThread || semantic.kind == crtInvalidSetThread
	namespace, key := crtInvalidGlobalNamespace, uint64(0)
	if threadLocal {
		namespace, key = crtInvalidThreadNamespace, state.TEBAddr
	}
	switch semantic.kind {
	case crtInvalidSetGlobal, crtInvalidSetThread:
		first, err := invocation.Call(0x11110000)
		if err != nil {
			invocation.Failf("set invalid-parameter handler: %v", err)
			return
		}
		firstResult := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: first}
		firstResult.ExpectReturn(0)
		second, err := invocation.Call(0x22220000)
		if err != nil {
			invocation.Failf("replace invalid-parameter handler: %v", err)
			return
		}
		secondResult := crtContractResult{invocation: invocation, callIndex: len(invocation.calls) - 1, Return: second}
		secondResult.ExpectReturn(0x11110000)
	case crtInvalidGetGlobal, crtInvalidGetThread:
		marker := invocation.Mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		state.SwapRuntimePointer(namespace, key, 0x11110000)
		invocation.Mem.Write32(marker, 1)
		first, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: marker, Size: 4}})
		if err != nil {
			invocation.Failf("get invalid-parameter handler: %v", err)
			return
		}
		first.ExpectReturn(0x11110000)
		state.SwapRuntimePointer(namespace, key, 0x22220000)
		invocation.Mem.Write32(marker, 2)
		second, err := invocation.CallWatching([]crtContractMemoryWatch{{Address: marker, Size: 4}})
		if err != nil {
			invocation.Failf("get replaced invalid-parameter handler: %v", err)
			return
		}
		second.ExpectReturn(0x22220000)
	case crtInvalidInvoke, crtInvalidInvokeNoReturn:
		crtExerciseInvalidParameterInvokeContract(invocation, semantic)
	case crtInvalidInvokeWatson:
		crtExerciseInvalidParameterWatsonContract(invocation)
	}
	state.SwapRuntimePointer(namespace, key, 0)
}

func crtExerciseInvalidParameterInvokeContract(invocation *crtContractInvocation, semantic crtInvalidParameterSemantic) {
	state := invocation.Dispatcher.ProcessState()
	const markerSize = 48
	marker := invocation.Mem.Mmap(0, markerSize, mmu.PermRead|mmu.PermWrite)
	inputMarker := invocation.Mem.Mmap(0, 1, mmu.PermRead|mmu.PermWrite)
	firstCallback := crtInvalidParameterContractCallback(invocation, marker, 1)
	secondCallback := crtInvalidParameterContractCallback(invocation, marker, 2)
	if marker == 0 || inputMarker == 0 || firstCallback == 0 || secondCallback == 0 {
		invocation.Failf("allocate invalid-parameter callback contract")
		return
	}
	state.SetGuestCallTrampoline(ntapi.AllocTrampoline(invocation.Mem))
	state.SwapRuntimePointer(crtInvalidGlobalNamespace, 0, firstCallback)
	invocation.Mem.Write32(marker, 0)
	args := []uint64(nil)
	if semantic.name == "_invalid_parameter" {
		args = []uint64{1, 2, 3, 4, 5}
	}
	callbackArgs := make([]uint64, 5)
	copy(callbackArgs, args)
	wantAbort := 0
	if semantic.kind == crtInvalidInvokeNoReturn {
		wantAbort = int(crtInvalidRuntimeStatus)
	}
	_ = invocation.Mem.Write8(inputMarker, 1)
	watches := []crtContractMemoryWatch{
		{Address: marker, Size: markerSize},
		{Address: inputMarker, Size: 1},
	}
	first, err := invocation.CallWatching(watches, args...)
	if err != nil {
		invocation.Failf("invoke global invalid-parameter handler: %v", err)
		return
	}
	first.ExpectReturn(0)
	first.ExpectMemory(0, crtInvalidParameterContractResult(invocation.Is32, 1, callbackArgs))
	first.ExpectAbort(wantAbort)
	state.SwapRuntimePointer(crtInvalidThreadNamespace, state.TEBAddr, secondCallback)
	_ = invocation.Mem.WriteBytes(marker, make([]byte, markerSize))
	_ = invocation.Mem.Write8(inputMarker, 2)
	second, err := invocation.CallWatching(watches, args...)
	if err != nil {
		invocation.Failf("invoke thread invalid-parameter handler: %v", err)
		return
	}
	second.ExpectReturn(0)
	second.ExpectMemory(0, crtInvalidParameterContractResult(invocation.Is32, 2, callbackArgs))
	second.ExpectAbort(wantAbort)
	state.SwapRuntimePointer(crtInvalidGlobalNamespace, 0, 0)
	state.SwapRuntimePointer(crtInvalidThreadNamespace, state.TEBAddr, 0)
}

func crtExerciseInvalidParameterWatsonContract(invocation *crtContractInvocation) {
	for _, args := range [][]uint64{
		{1, 2, 3, 4, 5},
		{6, 7, 8, 9, 10},
	} {
		result, err := invocation.CallWatching(nil, args...)
		if err != nil {
			invocation.Failf("invoke watson contract: %v", err)
			return
		}
		result.ExpectReturn(0)
		result.ExpectAbort(int(crtInvalidRuntimeStatus))
	}
}

func crtInvalidParameterContractCallback(invocation *crtContractInvocation, marker uint64, value uint32) uint64 {
	code := invocation.Mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	if code == 0 {
		return 0
	}
	if invocation.Is32 {
		body := make([]byte, 0, 56)
		body = append(body, 0xB9)
		address := make([]byte, 4)
		binary.LittleEndian.PutUint32(address, uint32(marker))
		body = append(body, address...)
		body = append(body, 0xC7, 0x01)
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, value)
		body = append(body, data...)
		for index := 0; index < 5; index++ {
			body = append(body, 0x8B, 0x44, 0x24, byte(4+index*4))
			body = append(body, 0x89, 0x41, byte(8+index*8))
		}
		body = append(body, 0xC3)
		if invocation.Mem.WriteBytes(code, body) != nil {
			return 0
		}
		return code
	}
	body := make([]byte, 0, 15)
	body = append(body, 0x48, 0xB8)
	address := make([]byte, 8)
	binary.LittleEndian.PutUint64(address, marker)
	body = append(body, address...)
	body = append(body, 0xC7, 0x00)
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	body = append(body, data...)
	body = append(body,
		0x48, 0x89, 0x48, 0x08,
		0x48, 0x89, 0x50, 0x10,
		0x4C, 0x89, 0x40, 0x18,
		0x4C, 0x89, 0x48, 0x20,
		0x48, 0x8B, 0x54, 0x24, 0x28,
		0x48, 0x89, 0x50, 0x28,
	)
	body = append(body, 0xC3)
	if invocation.Mem.WriteBytes(code, body) != nil {
		return 0
	}
	return code
}

func crtInvalidParameterContractResult(is32 bool, value uint32, args []uint64) []byte {
	result := make([]byte, 48)
	binary.LittleEndian.PutUint32(result, value)
	for index := 0; index < 5 && index < len(args); index++ {
		offset := 8 + index*8
		if is32 {
			binary.LittleEndian.PutUint32(result[offset:], uint32(args[index]))
		} else {
			binary.LittleEndian.PutUint64(result[offset:], args[index])
		}
	}
	return result
}
