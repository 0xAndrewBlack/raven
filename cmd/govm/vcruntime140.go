//go:build guest_windows

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

type cxxActiveException struct {
	record           uint64
	context          uint64
	object           uint64
	handler          *ntapi.CxxCatchHandler
	rethrow          bool
	rethrowCompleted bool
}

type cxxThreadExceptions struct {
	active      []cxxActiveException
	recordSlot  uint64
	contextSlot uint64
}

type cxxExceptionRegistry struct {
	mu      sync.Mutex
	mem     *mmu.MMU
	threads map[int]*cxxThreadExceptions
}

const (
	cxxExceptionRecordSize = uint64(0x100)
	cxxContextRecordSize   = uint64(1232)
)

type cxxThrowMappings struct {
	record  uint64
	context uint64
}

func captureCxxThrowMappings(ctx *ntapi.TrapContext) (cxxThrowMappings, error) {
	var mappings cxxThrowMappings
	if ctx == nil || ctx.Mem == nil {
		return mappings, fmt.Errorf("invalid C++ throw context")
	}
	mappings.record = ctx.Mem.Mmap(0, cxxExceptionRecordSize, mmu.PermRead|mmu.PermWrite)
	if mappings.record == 0 {
		return mappings, fmt.Errorf("allocate C++ exception record")
	}
	mappings.context = ctx.Mem.Mmap(0, cxxContextRecordSize, mmu.PermRead|mmu.PermWrite)
	if mappings.context == 0 {
		mappings.release(ctx.Mem)
		return mappings, fmt.Errorf("allocate C++ exception context")
	}
	contextMarshaler, ok := ctx.CPU.(ntapi.ContextMarshaler)
	if !ok {
		mappings.release(ctx.Mem)
		return mappings, fmt.Errorf("CPU does not support C++ exception context capture")
	}
	if err := contextMarshaler.SaveContext(ctx.Mem, mappings.context); err != nil {
		mappings.release(ctx.Mem)
		return mappings, fmt.Errorf("capture C++ exception context: %w", err)
	}
	return mappings, nil
}

func (m *cxxThrowMappings) release(mem *mmu.MMU) {
	if m == nil || mem == nil {
		return
	}
	if m.context != 0 {
		mem.Munmap(m.context, cxxContextRecordSize)
		m.context = 0
	}
	if m.record != 0 {
		mem.Munmap(m.record, cxxExceptionRecordSize)
		m.record = 0
	}
}

func newCxxExceptionRegistry(mem *mmu.MMU) *cxxExceptionRegistry {
	return &cxxExceptionRegistry{mem: mem, threads: make(map[int]*cxxThreadExceptions)}
}

func (r *cxxExceptionRegistry) syncSlotsLocked(thread *cxxThreadExceptions) {
	if r.mem == nil || thread == nil || thread.recordSlot == 0 {
		return
	}
	record := uint64(0)
	context := uint64(0)
	if count := len(thread.active); count != 0 {
		record = thread.active[count-1].record
		context = thread.active[count-1].context
	}
	r.mem.Write64(thread.recordSlot, record)
	r.mem.Write64(thread.contextSlot, context)
}

func (r *cxxExceptionRegistry) begin(tid int, record, context, object uint64, handler *ntapi.CxxCatchHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil {
		thread = &cxxThreadExceptions{}
		r.threads[tid] = thread
	}
	thread.active = append(thread.active, cxxActiveException{
		record: record, context: context, object: object, handler: handler,
	})
	r.syncSlotsLocked(thread)
}

func (r *cxxExceptionRegistry) markRethrow(tid int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil || len(thread.active) == 0 {
		return false
	}
	thread.active[len(thread.active)-1].rethrow = true
	return true
}

func (r *cxxExceptionRegistry) completeRethrow(tid int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil || len(thread.active) == 0 {
		return false
	}
	active := &thread.active[len(thread.active)-1]
	if !active.rethrow {
		return false
	}
	active.rethrowCompleted = true
	return true
}

func (r *cxxExceptionRegistry) current(tid int) (cxxActiveException, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil || len(thread.active) == 0 {
		return cxxActiveException{}, false
	}
	return thread.active[len(thread.active)-1], true
}

func (r *cxxExceptionRegistry) end(tid int) (cxxActiveException, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil || len(thread.active) == 0 {
		return cxxActiveException{}, false
	}
	index := len(thread.active) - 1
	active := thread.active[index]
	thread.active = thread.active[:index]
	destroy := !active.rethrow || active.rethrowCompleted
	if destroy {
		for _, outer := range thread.active {
			if outer.object == active.object {
				destroy = false
				break
			}
		}
	}
	r.syncSlotsLocked(thread)
	return active, destroy
}

func (r *cxxExceptionRegistry) slots(tid int, allocate func() uint64) (uint64, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	thread := r.threads[tid]
	if thread == nil {
		thread = &cxxThreadExceptions{}
		r.threads[tid] = thread
	}
	if thread.recordSlot == 0 {
		thread.recordSlot = allocate()
		if thread.recordSlot != 0 {
			thread.contextSlot = thread.recordSlot + 8
		}
	}
	r.syncSlotsLocked(thread)
	return thread.recordSlot, thread.contextSlot
}

func allocCxxCatchTrampoline(mem *mmu.MMU) (*ntapi.DllMainTrampoline, error) {
	return allocRtlConsolidateTrampoline(mem)
}

func cxxCatchCallStack(mem *mmu.MMU, stackBase, stackSize, returnAddress,
	targetRip, targetRsp, rflags uint64) (uint64, error) {

	return rtlConsolidateCallStack(
		mem, stackBase, stackSize, returnAddress, targetRip, targetRsp, rflags,
	)
}

func writeCxxConsolidateRecord(mem *mmu.MMU, address, callback,
	originalRecord, contextRecord uint64, handler *ntapi.CxxCatchHandler,
	unwindStartState *int32) error {

	if address == 0 || callback == 0 || originalRecord == 0 || contextRecord == 0 || handler == nil {
		return fmt.Errorf("invalid C++ consolidation record")
	}
	if err := mem.WriteBytes(address, make([]byte, 0x100)); err != nil {
		return err
	}
	mem.Write32(address, ntapi.StatusUnwindConsolidate)
	mem.Write32(address+4, 1)
	mem.Write32(address+0x18, ntapi.CxxConsolidateParameterCount)
	mem.Write64(address+0x20, callback)
	mem.Write64(address+0x28, handler.EstablisherRBP)
	mem.Write64(address+0x30, uint64(int64(handler.CatchState)))
	mem.Write64(address+0x38, uint64(int64(handler.UnwindTargetState)))
	if unwindStartState != nil {
		mem.Write64(address+0x40, uint64(int64(*unwindStartState)))
		mem.Write64(address+0x68, 1)
	}
	mem.Write64(address+0x48, handler.ImageBase+uint64(handler.FuncletRVA))
	mem.Write64(address+0x50, originalRecord)
	mem.Write64(address+0x58, contextRecord)
	for index := uint8(0); index < handler.ContinuationCount && index < 2; index++ {
		mem.Write64(address+0x60+uint64(index)*8,
			handler.ImageBase+uint64(handler.ContinuationRVAs[index]))
	}
	return nil
}

func readCxxExceptionInfo(mem *mmu.MMU, exceptionRecord, defaultImageBase uint64) *ntapi.CxxExceptionInfo {
	if exceptionRecord == 0 {
		return nil
	}
	count, err := mem.Read32(exceptionRecord + 0x18)
	if err != nil || count < 3 {
		return nil
	}
	object, err := mem.Read64(exceptionRecord + 0x28)
	if err != nil {
		return nil
	}
	throwInfo, err := mem.Read64(exceptionRecord + 0x30)
	if err != nil {
		return nil
	}
	imageBase := defaultImageBase
	if count >= 4 {
		if value, readErr := mem.Read64(exceptionRecord + 0x38); readErr == nil && value != 0 {
			imageBase = value
		}
	}
	return &ntapi.CxxExceptionInfo{
		Object:    object,
		ThrowInfo: throwInfo,
		ImageBase: imageBase,
	}
}

func executeCxxUnwindActions(mem *mmu.MMU, imageBase uint64, handler *ntapi.CxxCatchHandler, guestCall ntapi.GuestCallFunc) error {
	if handler == nil || len(handler.UnwindActions) == 0 {
		return nil
	}
	if guestCall == nil {
		return fmt.Errorf("nil guest caller for C++ unwind")
	}
	for index, action := range handler.UnwindActions {
		if action.HandlerRVA == 0 {
			return fmt.Errorf("C++ unwind action %d has no handler", index)
		}
		actionImageBase := action.ImageBase
		if actionImageBase == 0 {
			actionImageBase = imageBase
		}
		object, frame, err := action.Arguments(mem)
		if err != nil {
			return fmt.Errorf("resolve C++ unwind action %d: %w", index, err)
		}
		if _, err := guestCall(actionImageBase+uint64(action.HandlerRVA), []uint64{object, frame}); err != nil {
			return fmt.Errorf("execute C++ unwind action %d at RVA 0x%x: %w", index, action.HandlerRVA, err)
		}
	}
	return nil
}

func cxxContinuationAddress(imageBase uint64, handler *ntapi.CxxCatchHandler, result uint64) (uint64, error) {
	if handler == nil {
		return 0, fmt.Errorf("nil C++ catch handler")
	}
	switch handler.ContinuationCount {
	case 0:
		if result != 0 {
			return result, nil
		}
		if handler.ContinuationRVA != 0 {
			return imageBase + uint64(handler.ContinuationRVA), nil
		}
	case 1:
		if handler.ContinuationRVAs[0] != 0 {
			return imageBase + uint64(handler.ContinuationRVAs[0]), nil
		}
	case 2:
		if result >= 2 {
			return 0, fmt.Errorf("invalid C++ continuation selector %d", result)
		}
		if handler.ContinuationRVAs[result] != 0 {
			return imageBase + uint64(handler.ContinuationRVAs[result]), nil
		}
	default:
		return 0, fmt.Errorf("invalid C++ continuation count %d", handler.ContinuationCount)
	}
	return 0, fmt.Errorf("C++ catch funclet returned no continuation")
}

func registerCxxFrameHandlers(
	d *ntapi.Dispatcher,
	synthByName map[string]*ntapi.SynthPE,
	handler ntapi.TrapHandler,
) {
	if vcrt := synthByName["vcruntime140.dll"]; vcrt != nil {
		d.RegisterAutoStubHandler(vcrt, "__CxxFrameHandler3", handler)
		d.RegisterAutoStubHandler(vcrt, "__CxxFrameHandler4", handler)
	}
	if vcrtFH4 := synthByName["vcruntime140_1.dll"]; vcrtFH4 != nil {
		d.RegisterAutoStubHandler(vcrtFH4, "__CxxFrameHandler4", handler)
	}
}

// registerVcruntime140Handlers registers handlers for vcruntime140.dll.
// This DLL provides C++ exception handling, memory intrinsics, and CRT
// startup/shutdown helpers that MSVC-compiled binaries depend on.
func registerVcruntime140Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree
	exceptionTable := hctx.ExTable
	handles := hctx.Handles
	procState := hctx.ProcState
	tmPtr := hctx.TMPtr
	guestCallTrampoline := hctx.GuestCallTrampoline
	if guestCallTrampoline == nil {
		guestCallTrampoline = ntapi.AllocTrampoline(mem)
	}
	catchReturnTrampoline, err := allocCxxCatchTrampoline(mem)
	if err != nil {
		panic(err)
	}
	callCxxGuest := func(ctx *ntapi.TrapContext, address uint64, args []uint64) (uint64, error) {
		return ntapi.CallGuestFunction(ctx.CPU, mem, guestCallTrampoline, address, args, ctx.Trace)
	}
	callCxxCatchFunclet := func(ctx *ntapi.TrapContext, handler *ntapi.CxxCatchHandler,
		address, unwindContext uint64) (result uint64, err error) {

		if handler == nil || address == 0 || handler.EstablisherRBP < 8 {
			return 0, fmt.Errorf("invalid C++ catch funclet call")
		}
		contextMarshaler, ok := ctx.CPU.(ntapi.ContextMarshaler)
		if !ok {
			return 0, fmt.Errorf("CPU does not support C++ catch context marshaling")
		}
		registerReader, ok := ctx.CPU.(ntapi.RegisterReader)
		if !ok {
			return 0, fmt.Errorf("CPU does not support C++ catch register reads")
		}
		registerWriter, ok := ctx.CPU.(ntapi.RegisterWriter)
		if !ok {
			return 0, fmt.Errorf("CPU does not support C++ catch register writes")
		}
		const contextSize = uint64(1232)
		savedContext := mem.Mmap(0, contextSize, mmu.PermRead|mmu.PermWrite)
		if savedContext == 0 {
			return 0, fmt.Errorf("allocate C++ catch context")
		}
		defer mem.Munmap(savedContext, contextSize)
		if err := contextMarshaler.SaveContext(mem, savedContext); err != nil {
			return 0, err
		}
		defer func() {
			restoreErr := contextMarshaler.RestoreContext(mem, savedContext)
			if err == nil && restoreErr != nil {
				err = restoreErr
			}
		}()

		if unwindContext != 0 {
			if err := contextMarshaler.RestoreContext(mem, unwindContext); err != nil {
				return 0, err
			}
		}
		for register, value := range handler.SavedRegs {
			registerWriter.WriteReg(register, value)
		}
		const catchStackSize = uint64(64 * 1024)
		catchStack := mem.Mmap(0, catchStackSize, mmu.PermRead|mmu.PermWrite)
		if catchStack == 0 {
			return 0, fmt.Errorf("allocate C++ catch call stack")
		}
		defer mem.Munmap(catchStack, catchStackSize)
		targetContext, err := ntapi.ReadAMD64Context(mem, unwindContext)
		if err != nil {
			return 0, err
		}
		stackPointer, err := cxxCatchCallStack(
			mem,
			catchStack,
			catchStackSize,
			catchReturnTrampoline.Addr,
			handler.ControlPC,
			handler.BodyRSP,
			targetContext.Rflags,
		)
		if err != nil {
			return 0, err
		}
		registerWriter.WriteReg(1, address)
		registerWriter.WriteReg(2, handler.EstablisherRBP)
		registerWriter.WriteReg(8, 0x100)
		ctx.CPU.SetSP(stackPointer)
		ctx.CPU.SetPC(address)
		runErr := ctx.CPU.Run()
		ctx.CPU.Resume()
		result = registerReader.ReadReg(11)
		if runErr != nil {
			return result, runErr
		}
		return result, nil
	}
	runFrameUnwind := func(ctx *ntapi.TrapContext, exceptionRecord uint64, dispatcherContext *ntapi.DispatcherContext) error {
		flags, err := mem.Read32(exceptionRecord + 4)
		if err != nil || flags&(ntapi.ExceptionFlagUnwinding|ntapi.ExceptionFlagExitUnwind) == 0 {
			return err
		}
		targetState := int32(-1)
		var currentState *int32
		code, _ := mem.Read32(exceptionRecord)
		parameters, _ := mem.Read32(exceptionRecord + 0x18)
		if flags&ntapi.ExceptionFlagTargetUnwind != 0 && code == 0x80000029 && parameters >= 4 {
			value, readErr := mem.Read64(exceptionRecord + 0x38)
			if readErr != nil {
				return readErr
			}
			targetState = int32(value)
			if parameters >= ntapi.CxxConsolidateParameterCount {
				targetFrame, targetErr := mem.Read64(exceptionRecord + 0x28)
				hasState, stateErr := mem.Read64(exceptionRecord + 0x68)
				if targetErr != nil {
					return targetErr
				}
				if stateErr != nil {
					return stateErr
				}
				if hasState != 0 && targetFrame == dispatcherContext.EstablisherFrame {
					value, readErr = mem.Read64(exceptionRecord + 0x40)
					if readErr != nil {
						return readErr
					}
					state := int32(value)
					currentState = &state
				}
			}
		}
		actions, err := ntapi.CxxPlanFrameUnwindAtState(
			mem,
			exceptionTable,
			dispatcherContext.EstablisherFrame,
			dispatcherContext.ControlPc,
			targetState,
			currentState,
			ctx.Trace,
		)
		if err != nil {
			return err
		}
		handler := &ntapi.CxxCatchHandler{UnwindActions: actions}
		return executeCxxUnwindActions(mem, dispatcherContext.ImageBase, handler, func(address uint64, args []uint64) (uint64, error) {
			return callCxxGuest(ctx, address, args)
		})
	}

	vcrt, ok := hctx.SynthByName["vcruntime140.dll"]
	if !ok {
		return
	}

	currentThreadID := func(ctx *ntapi.TrapContext) int {
		if tmPtr != nil && *tmPtr != nil {
			return (*tmPtr).GetTID(ctx.CPU)
		}
		return 1
	}
	exceptions := newCxxExceptionRegistry(mem)
	captureContextRecord := func(ctx *ntapi.TrapContext) uint64 {
		const amd64ContextSize = 1232
		ctxAddr := mem.Mmap(0, amd64ContextSize, mmu.PermRead|mmu.PermWrite)
		if ctxAddr == 0 {
			return 0
		}
		contextMarshaler, ok := ctx.CPU.(ntapi.ContextMarshaler)
		if !ok {
			mem.Munmap(ctxAddr, amd64ContextSize)
			return 0
		}
		if err := contextMarshaler.SaveContext(mem, ctxAddr); err != nil {
			mem.Munmap(ctxAddr, amd64ContextSize)
			return 0
		}
		return ctxAddr
	}
	normalizeModuleName := func(name string) string {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return name
		}
		if !strings.HasSuffix(name, ".dll") {
			name += ".dll"
		}
		return name
	}

	// -- Onexit table support --
	// Each onexit table is tracked by its guest address.
	var onexitMu sync.Mutex
	onexitTables := make(map[uint64][]uint64) // table addr -> list of function pointers

	// -- Type info destroy list --
	// MSVC keeps a singly-linked list of RTTI type_info nodes for cleanup.
	// Each node: { next *node; data *void } - 16 bytes on x64.

	// ====================================================================
	// C++ Exception Handling
	// ====================================================================

	var dispatchCxxException func(
		*ntapi.TrapContext,
		uint64,
		uint64,
		uint64,
		*int32,
		*int32,
	) (bool, error)
	dispatchCxxException = func(ctx *ntapi.TrapContext, exceptionRecord, searchContextRecord,
		unwindContextRecord uint64, searchStateOverride, unwindStateOverride *int32) (bool, error) {

		context, err := ntapi.ReadAMD64Context(mem, searchContextRecord)
		if err != nil {
			return false, err
		}
		imageBase := uint64(0)
		if exceptionTable != nil {
			imageBase = exceptionTable.ImageBase
		}
		exception := readCxxExceptionInfo(mem, exceptionRecord, imageBase)
		var handler *ntapi.CxxCatchHandler
		if searchStateOverride == nil {
			handler = ntapi.CxxDispatchException(
				mem, exceptionTable, context.Regs[4], context.Rip, exception, ctx.Trace,
			)
		} else {
			handler = ntapi.CxxDispatchExceptionAtState(
				mem,
				exceptionTable,
				context.Regs[4],
				context.Rip,
				exception,
				*searchStateOverride,
				ctx.Trace,
			)
		}
		if handler == nil {
			return false, nil
		}
		if handler.ImageBase == 0 {
			handler.ImageBase = imageBase
		}

		consolidateRecord := mem.Mmap(0, 0x100, mmu.PermRead|mmu.PermWrite)
		if consolidateRecord == 0 {
			return false, fmt.Errorf("allocate C++ consolidation record")
		}
		defer mem.Munmap(consolidateRecord, 0x100)
		callbackToken := consolidateRecord + 0x80
		if err := writeCxxConsolidateRecord(
			mem,
			consolidateRecord,
			callbackToken,
			exceptionRecord,
			unwindContextRecord,
			handler,
			unwindStateOverride,
		); err != nil {
			return false, err
		}

		tid := currentThreadID(ctx)
		guestCall := func(address uint64, args []uint64) (uint64, error) {
			if address != callbackToken {
				return callCxxGuest(ctx, address, args)
			}
			if len(args) != 1 || args[0] != consolidateRecord {
				return 0, fmt.Errorf("invalid C++ consolidation callback arguments")
			}
			if err := ntapi.MaterializeCxxCatchObject(mem, handler, exception, func(address uint64, args []uint64) (uint64, error) {
				return callCxxGuest(ctx, address, args)
			}); err != nil {
				return 0, err
			}

			exceptions.begin(tid, exceptionRecord, unwindContextRecord, exception.Object, handler)
			funcletResult := uint64(0)
			if handler.FuncletRVA != 0 {
				funcletResult, err = callCxxCatchFunclet(
					ctx,
					handler,
					handler.ImageBase+uint64(handler.FuncletRVA),
					unwindContextRecord,
				)
				if err != nil {
					exceptions.end(tid)
					return 0, err
				}
			}

			active, activeOK := exceptions.current(tid)
			rethrow := activeOK && active.rethrow
			continuation := uint64(0)
			if rethrow {
				refreshed, readErr := ntapi.ReadAMD64Context(mem, unwindContextRecord)
				if readErr != nil {
					exceptions.end(tid)
					return 0, readErr
				}
				continuation = refreshed.Rip
			} else {
				continuation, err = cxxContinuationAddress(handler.ImageBase, handler, funcletResult)
				if err != nil {
					exceptions.end(tid)
					return 0, err
				}
				refreshed, readErr := ntapi.ReadAMD64Context(mem, unwindContextRecord)
				if readErr != nil {
					exceptions.end(tid)
					return 0, readErr
				}
				refreshed.Rip = continuation
				refreshed.Regs[4] = handler.BodyRSP
				for register, value := range handler.SavedRegs {
					if register >= 0 && register < len(refreshed.Regs) {
						refreshed.Regs[register] = value
					}
				}
				if writeErr := ntapi.WriteAMD64Context(mem, unwindContextRecord, refreshed); writeErr != nil {
					exceptions.end(tid)
					return 0, writeErr
				}
			}

			ended, destroy := exceptions.end(tid)
			if destroy && exception != nil {
				destructor, destructorErr := exception.DestructorAddress(mem)
				if destructorErr != nil {
					return 0, destructorErr
				}
				if destructor != 0 {
					if _, callErr := callCxxGuest(ctx, destructor, []uint64{ended.object}); callErr != nil {
						return 0, callErr
					}
				}
			}
			return continuation, nil
		}

		err = ntapi.UnwindStack(
			mem,
			consolidateRecord,
			unwindContextRecord,
			handler.EstablisherRBP,
			handler.ControlPC,
			0,
			0,
			guestCall,
			ctx.Trace,
		)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	runCxxFrameHandler := func(ctx *ntapi.TrapContext) uint32 {
		exceptionRecord := ctx.Arg(0)
		dispatcherContext, err := ntapi.ReadDispatcherContext(mem, ctx.Arg(3))
		if err != nil || dispatcherContext == nil {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		exceptionFlags, err := mem.Read32(exceptionRecord + 4)
		if err != nil {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		if exceptionFlags&(ntapi.ExceptionFlagUnwinding|ntapi.ExceptionFlagExitUnwind) != 0 {
			if err := runFrameUnwind(ctx, exceptionRecord, dispatcherContext); err != nil {
				ravelog.Logf("[vcrt] C++ frame unwind failed: %v\n", err)
				ctx.SetReturn(^uint64(0))
				return 0
			}
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		handled, err := dispatchCxxException(
			ctx,
			exceptionRecord,
			dispatcherContext.ContextRecord,
			dispatcherContext.ContextRecord,
			nil,
			nil,
		)
		if err != nil {
			ravelog.Logf("[vcrt] C++ phase-two dispatch failed: %v\n", err)
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		if handled {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
		} else {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		}
		return 0
	}

	registerCxxFrameHandlers(d, hctx.SynthByName, runCxxFrameHandler)

	d.RegisterAutoStubHandler(vcrt, "_CxxThrowException", func(ctx *ntapi.TrapContext) uint32 {
		tid := currentThreadID(ctx)
		pExceptionObject := ctx.Arg(0)
		pThrowInfo := ctx.Arg(1)
		if pExceptionObject == 0 && pThrowInfo == 0 {
			active, ok := exceptions.current(tid)
			if !ok || active.handler == nil || !exceptions.markRethrow(tid) {
				fmt.Fprintln(os.Stderr, "govm: C++ rethrow without an active exception")
				os.Exit(3)
				return 0
			}
			rethrowContext := captureContextRecord(ctx)
			if rethrowContext == 0 {
				fmt.Fprintln(os.Stderr, "govm: cannot capture C++ rethrow context")
				os.Exit(3)
				return 0
			}
			defer mem.Munmap(rethrowContext, 1232)
			context, contextErr := ntapi.ReadAMD64Context(mem, rethrowContext)
			if contextErr != nil {
				fmt.Fprintf(os.Stderr, "govm: cannot read C++ rethrow context: %v\n", contextErr)
				os.Exit(3)
				return 0
			}
			returnAddress, returnErr := mem.Read64(context.Regs[4])
			if returnErr != nil || returnAddress == 0 {
				fmt.Fprintf(os.Stderr, "govm: cannot find C++ rethrow call site: %v\n", returnErr)
				os.Exit(3)
				return 0
			}
			context.Rip = returnAddress
			context.Regs[4] += 8
			if contextErr = ntapi.WriteAMD64Context(mem, rethrowContext, context); contextErr != nil {
				fmt.Fprintf(os.Stderr, "govm: cannot write C++ rethrow context: %v\n", contextErr)
				os.Exit(3)
				return 0
			}
			searchState := active.handler.CatchState
			unwindState := active.handler.UnwindTargetState
			handled, err := dispatchCxxException(
				ctx,
				active.record,
				active.context,
				rethrowContext,
				&searchState,
				&unwindState,
			)
			if err != nil || !handled || !exceptions.completeRethrow(tid) {
				fmt.Fprintf(os.Stderr, "govm: unhandled C++ rethrow: %v\n", err)
				os.Exit(3)
				return 0
			}
			completedContext, readErr := ntapi.ReadAMD64Context(mem, rethrowContext)
			if readErr != nil {
				fmt.Fprintf(os.Stderr, "govm: cannot read C++ rethrow continuation: %v\n", readErr)
				os.Exit(3)
				return 0
			}
			if writeErr := ntapi.WriteAMD64Context(mem, active.context, completedContext); writeErr != nil {
				fmt.Fprintf(os.Stderr, "govm: cannot transfer C++ rethrow continuation: %v\n", writeErr)
				os.Exit(3)
				return 0
			}
			ctx.CPU.SetPC(catchReturnTrampoline.Addr)
			return 0
		}

		mappings, captureErr := captureCxxThrowMappings(ctx)
		if captureErr != nil {
			fmt.Fprintf(os.Stderr, "govm: cannot prepare C++ exception: %v\n", captureErr)
			os.Exit(3)
			return 0
		}
		defer mappings.release(mem)
		exceptionRecord := mappings.record
		contextRecord := mappings.context
		context, err := ntapi.ReadAMD64Context(mem, contextRecord)
		if err != nil {
			mappings.release(mem)
			fmt.Fprintf(os.Stderr, "govm: cannot read C++ exception context: %v\n", err)
			os.Exit(3)
			return 0
		}
		returnAddress, err := mem.Read64(context.Regs[4])
		if err == nil && returnAddress != 0 {
			context.Rip = returnAddress
			context.Regs[4] += 8
			_ = ntapi.WriteAMD64Context(mem, contextRecord, context)
		}

		imageBase := uint64(0)
		if _, throwImageBase, _ := ntapi.LookupFunctionEntry(mem, context.Rip, nil); throwImageBase != 0 {
			imageBase = throwImageBase
		} else if exceptionTable != nil {
			imageBase = exceptionTable.ImageBase
		}
		mem.Write32(exceptionRecord, 0xE06D7363)
		mem.Write32(exceptionRecord+4, 1)
		mem.Write64(exceptionRecord+0x10, context.Rip)
		mem.Write32(exceptionRecord+0x18, 4)
		mem.Write64(exceptionRecord+0x20, 0x19930520)
		mem.Write64(exceptionRecord+0x28, pExceptionObject)
		mem.Write64(exceptionRecord+0x30, pThrowInfo)
		mem.Write64(exceptionRecord+0x38, imageBase)

		handled, dispatchErr := dispatchCxxException(
			ctx, exceptionRecord, contextRecord, contextRecord, nil, nil,
		)
		if dispatchErr != nil || !handled {
			mappings.release(mem)
			fmt.Fprintf(os.Stderr, "govm: unhandled C++ exception at RIP=0x%x: %v\n", context.Rip, dispatchErr)
			os.Exit(3)
			return 0
		}
		contextMarshaler, ok := ctx.CPU.(ntapi.ContextMarshaler)
		if !ok || contextMarshaler.RestoreContext(mem, contextRecord) != nil {
			mappings.release(mem)
			fmt.Fprintln(os.Stderr, "govm: cannot restore C++ continuation context")
			os.Exit(3)
		}
		return 0
	})

	// ====================================================================
	// __C_specific_handler / _except_handler4_common: C SEH dispatch.
	// ====================================================================

	runCSpecificHandler := func(ctx *ntapi.TrapContext, exceptionRecordAddr, dispatcherContextAddr uint64) uint32 {
		dispatcherContext, err := ntapi.ReadDispatcherContext(ctx.Mem, dispatcherContextAddr)
		if err != nil || dispatcherContext == nil || dispatcherContext.HandlerData == 0 {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}
		controlRVA := uint32(0)
		if dispatcherContext.ControlPc >= dispatcherContext.ImageBase {
			controlRVA = uint32(dispatcherContext.ControlPc - dispatcherContext.ImageBase)
		}
		scopeCount, _ := ctx.Mem.Read32(dispatcherContext.HandlerData)
		for i := uint32(0); i < scopeCount; i++ {
			recordAddr := dispatcherContext.HandlerData + 4 + uint64(i)*16
			beginRVA, _ := ctx.Mem.Read32(recordAddr)
			endRVA, _ := ctx.Mem.Read32(recordAddr + 4)
			handlerRVA, _ := ctx.Mem.Read32(recordAddr + 8)
			jumpTarget, _ := ctx.Mem.Read32(recordAddr + 12)
			if controlRVA < beginRVA || controlRVA >= endRVA || jumpTarget == 0 {
				continue
			}
			filterResult := uint32(ntapi.ExceptionContinueSearch)
			switch handlerRVA {
			case 0:
				filterResult = ntapi.ExceptionContinueSearch
			case 1:
				filterResult = ntapi.ExceptionExecuteHandler
			default:
				exceptionPointersAddr := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
				mem.Write64(exceptionPointersAddr+0, exceptionRecordAddr)
				mem.Write64(exceptionPointersAddr+8, dispatcherContext.ContextRecord)
				filterAddr := dispatcherContext.ImageBase + uint64(handlerRVA)
				ret, callErr := ntapi.CallGuestFunction(ctx.CPU, mem, ntapi.AllocTrampoline(mem), filterAddr, []uint64{exceptionPointersAddr}, ctx.Trace)
				if callErr == nil {
					filterResult = uint32(ret)
				}
			}
			if filterResult == ntapi.ExceptionContinueExecution {
				ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
				return 0
			}
			if filterResult != ntapi.ExceptionExecuteHandler {
				continue
			}
			contextRecord, readErr := ntapi.ReadAMD64Context(ctx.Mem, dispatcherContext.ContextRecord)
			if readErr != nil {
				break
			}
			dispatcherContext.TargetIp = dispatcherContext.ImageBase + uint64(jumpTarget)
			_ = ntapi.WriteDispatcherContext(ctx.Mem, dispatcherContextAddr, dispatcherContext)
			contextRecord.Rip = dispatcherContext.TargetIp
			contextRecord.Regs[4] = dispatcherContext.EstablisherFrame
			_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
			return 0
		}
		ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		return 0
	}

	d.RegisterAutoStubHandler(vcrt, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
		return runCSpecificHandler(ctx, ctx.Arg(0), ctx.Arg(3))
	})

	d.RegisterAutoStubHandler(vcrt, "_except_handler4_common", func(ctx *ntapi.TrapContext) uint32 {
		return runCSpecificHandler(ctx, ctx.Arg(2), ctx.Arg(5))
	})

	// ====================================================================
	// Memory intrinsics (same logic as ucrtbase)
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "memset", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		val := byte(ctx.Arg(1))
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf := make([]byte, count)
		for i := range buf {
			buf[i] = val
		}
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "memcpy", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf, _ := ctx.Mem.ReadBytes(src, int(count))
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "memmove", func(ctx *ntapi.TrapContext) uint32 {
		dst := ctx.Arg(0)
		src := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		buf, _ := ctx.Mem.ReadBytes(src, int(count))
		ctx.Mem.WriteBytes(dst, buf)
		ctx.SetReturn(dst)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "memcmp", func(ctx *ntapi.TrapContext) uint32 {
		buf1 := ctx.Arg(0)
		buf2 := ctx.Arg(1)
		count := ctx.Arg(2)
		if count > 0x1000000 {
			count = 0x1000000
		}
		b1, _ := ctx.Mem.ReadBytes(buf1, int(count))
		b2, _ := ctx.Mem.ReadBytes(buf2, int(count))
		for i := 0; i < int(count); i++ {
			if b1[i] < b2[i] {
				ctx.SetReturn(^uint64(0)) // -1
				return 0
			}
			if b1[i] > b2[i] {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "strlen", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		n := uint64(0)
		for {
			b, _ := ctx.Mem.Read8(addr + n)
			if b == 0 {
				break
			}
			n++
			if n > 0x1000000 {
				break
			}
		}
		ctx.SetReturn(n)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "wcslen", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		n := uint64(0)
		for {
			ch, _ := ctx.Mem.Read16(addr + n*2)
			if ch == 0 {
				break
			}
			n++
			if n > 0x800000 {
				break
			}
		}
		ctx.SetReturn(n)
		return 0
	})

	// ====================================================================
	// _purecall: Called when a pure virtual function is invoked.
	// This is always a fatal programming error.
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "_purecall", func(ctx *ntapi.TrapContext) uint32 {
		rip := ctx.CPU.GetPC()
		ravelog.Logf("[vcrt] _purecall invoked from RIP=0x%x - pure virtual function call\n", rip)
		fmt.Fprintf(os.Stderr, "govm: pure virtual function call at RIP=0x%x\n", rip)
		os.Exit(3)
		return 0
	})

	// ====================================================================
	// __std_type_info_destroy_list: cleanup hook.
	// For now we simply clear the head pointer and leave the allocations intact.
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "__std_type_info_destroy_list", func(ctx *ntapi.TrapContext) uint32 {
		if headPtr := ctx.Arg(0); headPtr != 0 {
			mem.Write64(headPtr, 0)
		}
		return 0
	})

	// ====================================================================
	// __std_exception_copy / __std_exception_destroy
	// MSVC std::exception internal structure:
	//   struct __std_exception_data { char* _What; bool _DoFree; };
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "__std_exception_copy", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0) // const __std_exception_data*
		dst := ctx.Arg(1) // __std_exception_data*
		if src == 0 || dst == 0 {
			return 0
		}
		srcWhat, _ := mem.Read64(src)    // char* _What
		srcFree, _ := mem.Read8(src + 8) // bool _DoFree
		if srcWhat == 0 {
			mem.Write64(dst, 0)
			mem.Write8(dst+8, 0)
			return 0
		}
		// Measure the source string
		n := uint64(0)
		for {
			b, _ := mem.Read8(srcWhat + n)
			if b == 0 {
				break
			}
			n++
			if n > 0x10000 {
				break
			}
		}
		_ = srcFree
		// Allocate a copy on the guest heap
		newBuf := sharedHeapAlloc(n+1, false)
		if newBuf != 0 {
			data, _ := mem.ReadBytes(srcWhat, int(n))
			mem.WriteBytes(newBuf, append(data, 0))
		}
		mem.Write64(dst, newBuf)
		mem.Write8(dst+8, 1) // _DoFree = true (we allocated it)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "__std_exception_destroy", func(ctx *ntapi.TrapContext) uint32 {
		dataPtr := ctx.Arg(0) // __std_exception_data*
		if dataPtr == 0 {
			return 0
		}
		what, _ := mem.Read64(dataPtr)
		doFree, _ := mem.Read8(dataPtr + 8)
		if what != 0 && doFree != 0 {
			sharedHeapFree(what)
		}
		mem.Write64(dataPtr, 0)
		mem.Write8(dataPtr+8, 0)
		return 0
	})

	// ====================================================================
	// CRT startup/shutdown helpers
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "_initialize_narrow_environment", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[vcrt] _initialize_narrow_environment\n")
		ctx.SetReturn(0) // success
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_initialize_onexit_table", func(ctx *ntapi.TrapContext) uint32 {
		table := ctx.Arg(0)
		ravelog.Logf("[vcrt] _initialize_onexit_table table=0x%x\n", table)
		if table != 0 {
			// _onexit_table_t { _PVFV* _first; _PVFV* _last; _PVFV* _end; }
			mem.Write64(table, 0)    // _first
			mem.Write64(table+8, 0)  // _last
			mem.Write64(table+16, 0) // _end
		}
		onexitMu.Lock()
		onexitTables[table] = nil
		onexitMu.Unlock()
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_register_onexit_function", func(ctx *ntapi.TrapContext) uint32 {
		table := ctx.Arg(0)
		fn := ctx.Arg(1)
		ravelog.Logf("[vcrt] _register_onexit_function table=0x%x fn=0x%x\n", table, fn)
		if fn != 0 {
			onexitMu.Lock()
			onexitTables[table] = append(onexitTables[table], fn)
			onexitMu.Unlock()
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_execute_onexit_table", func(ctx *ntapi.TrapContext) uint32 {
		table := ctx.Arg(0)
		ravelog.Logf("[vcrt] _execute_onexit_table table=0x%x\n", table)
		onexitMu.Lock()
		funcs := onexitTables[table]
		delete(onexitTables, table)
		onexitMu.Unlock()
		// Execute in LIFO order (last registered first)
		for i := len(funcs) - 1; i >= 0; i-- {
			fn := funcs[i]
			if fn == 0 {
				continue
			}
			ravelog.Logf("[vcrt] _execute_onexit_table calling fn=0x%x\n", fn)
			trampoline := ntapi.AllocTrampoline(mem)
			_, _ = ntapi.CallGuestFunction(ctx.CPU, mem, trampoline, fn, nil, ctx.Trace)
		}
		ctx.SetReturn(0)
		return 0
	})

	// ====================================================================
	// __vcrt forwarded kernel32 functions
	// ====================================================================

	// __vcrt_GetModuleFileNameW: forward to GetModuleFileNameW logic
	d.RegisterAutoStubHandler(vcrt, "__vcrt_GetModuleFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		hModule := ctx.Arg(0)
		buf := ctx.Arg(1)
		nSize := ctx.Arg(2)
		path := hctx.ImagePath
		if hModule != 0 {
			hctx.SynthMu.RLock()
			for _, synth := range hctx.SynthByName {
				if synth != nil && synth.BaseAddr == hModule {
					path = `C:\` + synth.Name
					break
				}
			}
			hctx.SynthMu.RUnlock()
		}
		if buf != 0 && nSize > 0 {
			chars := []rune(path)
			n := len(chars)
			if uint64(n) >= nSize {
				n = int(nSize) - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(chars[i]))
			}
			ctx.Mem.Write16(buf+uint64(n*2), 0)
			ctx.SetReturn(uint64(n))
		} else {
			ctx.SetReturn(0)
		}
		return 0
	})

	// __vcrt_GetModuleHandleW: forward to GetModuleHandleW logic
	d.RegisterAutoStubHandler(vcrt, "__vcrt_GetModuleHandleW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			if hctx.MainModule != nil {
				ctx.SetReturn(hctx.MainModule.BaseAddr)
			} else {
				ctx.SetReturn(0x00400000)
			}
			return 0
		}
		name := normalizeModuleName(hctx.ReadGuestUTF16(namePtr))
		hctx.SynthMu.RLock()
		for dllName, synth := range hctx.SynthByName {
			if normalizeModuleName(dllName) == name {
				hctx.SynthMu.RUnlock()
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		hctx.SynthMu.RUnlock()
		ctx.SetReturn(0)
		return 0
	})

	// __vcrt_LoadLibraryExW: forward to LoadLibraryExW logic
	d.RegisterAutoStubHandler(vcrt, "__vcrt_LoadLibraryExW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := normalizeModuleName(hctx.ReadGuestUTF16(namePtr))
		ravelog.Logf("[vcrt] __vcrt_LoadLibraryExW %q\n", name)
		hctx.SynthMu.RLock()
		for dllName, synth := range hctx.SynthByName {
			if normalizeModuleName(dllName) == name {
				hctx.SynthMu.RUnlock()
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		hctx.SynthMu.RUnlock()
		ctx.SetReturn(0xDEAD0000)
		return 0
	})

	// ====================================================================
	// __current_exception / __current_exception_context
	// Return pointers to thread-local exception state.
	// ====================================================================

	d.RegisterAutoStubHandler(vcrt, "__current_exception", func(ctx *ntapi.TrapContext) uint32 {
		tid := currentThreadID(ctx)
		recordSlot, _ := exceptions.slots(tid, func() uint64 {
			return mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		})
		ctx.SetReturn(recordSlot)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "__current_exception_context", func(ctx *ntapi.TrapContext) uint32 {
		tid := currentThreadID(ctx)
		_, contextSlot := exceptions.slots(tid, func() uint64 {
			return mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		})
		ctx.SetReturn(contextSlot)
		return 0
	})

	// ====================================================================
	createGuestThread := func(ctx *ntapi.TrapContext, startAddr, param, stackSize, threadIDPtr uint64) uint64 {
		if startAddr == 0 || tmPtr == nil || *tmPtr == nil || procState == nil || handles == nil {
			return 0
		}
		if stackSize == 0 {
			stackSize = 1 << 20
		}
		stackBase := mem.Mmap(0, stackSize, mmu.PermRead|mmu.PermWrite)
		threadTEB := mem.Mmap(0, uint64(ntapi.TebSize), mmu.PermRead|mmu.PermWrite)
		if threadTEB != 0 {
			tlsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebThreadLocalStorage)
			mem.Write64(threadTEB+ntapi.TebThreadLocalStorage, tlsPtr)
			flsPtr, _ := mem.Read64(procState.TEBAddr + ntapi.TebFlsData)
			mem.Write64(threadTEB+ntapi.TebFlsData, flsPtr)
			heapBase, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapBase)
			mem.Write64(threadTEB+ntapi.TebHeapBase, heapBase)
			heapOff, _ := mem.Read64(procState.TEBAddr + ntapi.TebHeapOffset)
			mem.Write64(threadTEB+ntapi.TebHeapOffset, heapOff)
			mem.Write64(threadTEB+ntapi.TebSelf, threadTEB)
			mem.Write64(threadTEB+ntapi.TebPEB, procState.PEBAddr)
			mem.Write64(threadTEB+ntapi.TebStackBase, stackBase+stackSize)
			mem.Write64(threadTEB+ntapi.TebStackLimit, stackBase)
			mem.Write32(threadTEB+ntapi.TebProcessId, uint32(procState.PEBAddr>>12))
			mem.Write64(threadTEB+ntapi.TebExceptionList, 0xFFFFFFFFFFFFFFFF)
		}
		tid, done, err := (*tmPtr).CloneWin32Thread(ctx.CPU, startAddr, param, stackBase, stackSize, threadTEB)
		if err != nil {
			return 0
		}
		if threadTEB != 0 {
			mem.Write32(threadTEB+ntapi.TebThreadId, uint32(tid))
		}
		if threadIDPtr != 0 {
			mem.Write32(threadIDPtr, uint32(tid))
		}
		h := handles.Alloc(&ntapi.ThreadHandle{TID: tid, Done: done})
		return uint64(h)
	}

	d.RegisterAutoStubHandler(vcrt, "_beginthread", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(createGuestThread(ctx, ctx.Arg(0), ctx.Arg(2), ctx.Arg(1), 0))
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_beginthreadex", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(createGuestThread(ctx, ctx.Arg(2), ctx.Arg(3), ctx.Arg(1), ctx.Arg(5)))
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_endthread", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "_endthreadex", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// Additional vcruntime140 exports
	// ====================================================================

	// __std_type_info_hash: hash a type_info name for unordered containers.
	d.RegisterAutoStubHandler(vcrt, "__std_type_info_hash", func(ctx *ntapi.TrapContext) uint32 {
		// _TypeInfo_data* - contains the mangled name at offset 8
		dataPtr := ctx.Arg(0)
		if dataPtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		namePtr, _ := mem.Read64(dataPtr + 8)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// FNV-1a hash of the name string
		hash := uint64(14695981039346656037)
		for i := uint64(0); i < 256; i++ {
			b, _ := mem.Read8(namePtr + i)
			if b == 0 {
				break
			}
			hash ^= uint64(b)
			hash *= 1099511628211
		}
		ctx.SetReturn(hash)
		return 0
	})

	// __std_type_info_compare: compare two type_info names.
	d.RegisterAutoStubHandler(vcrt, "__std_type_info_compare", func(ctx *ntapi.TrapContext) uint32 {
		lhs := ctx.Arg(0)
		rhs := ctx.Arg(1)
		if lhs == rhs {
			ctx.SetReturn(0)
			return 0
		}
		if lhs == 0 || rhs == 0 {
			if lhs == 0 {
				ctx.SetReturn(^uint64(0)) // -1
			} else {
				ctx.SetReturn(1)
			}
			return 0
		}
		lhsName, _ := mem.Read64(lhs + 8)
		rhsName, _ := mem.Read64(rhs + 8)
		if lhsName == rhsName {
			ctx.SetReturn(0)
			return 0
		}
		// Compare the mangled name strings byte by byte
		for i := uint64(0); i < 1024; i++ {
			a, _ := mem.Read8(lhsName + i)
			b, _ := mem.Read8(rhsName + i)
			if a != b {
				if a < b {
					ctx.SetReturn(^uint64(0))
				} else {
					ctx.SetReturn(1)
				}
				return 0
			}
			if a == 0 {
				break
			}
		}
		ctx.SetReturn(0)
		return 0
	})

	// __std_type_info_name: return the human-readable name from type_info.
	// In MSVC, type_info at offset 0 is the vtable, offset 8 is the spare/hash,
	// offset 16 is the mangled name. __std_type_info_name demangling is complex;
	// we return the raw mangled name which is sufficient for most uses.
	d.RegisterAutoStubHandler(vcrt, "__std_type_info_name", func(ctx *ntapi.TrapContext) uint32 {
		ti := ctx.Arg(0)     // type_info*
		result := ctx.Arg(1) // __std_type_info_data*
		if ti == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// The mangled name is at type_info + 16 in MSVC x64
		nameAddr := ti + 16
		_ = result
		ctx.SetReturn(nameAddr)
		return 0
	})

	// _onexit: register an atexit-like function (legacy CRT)
	d.RegisterAutoStubHandler(vcrt, "_onexit", func(ctx *ntapi.TrapContext) uint32 {
		fn := ctx.Arg(0)
		ravelog.Logf("[vcrt] _onexit fn=0x%x\n", fn)
		onexitMu.Lock()
		onexitTables[0] = append(onexitTables[0], fn)
		onexitMu.Unlock()
		ctx.SetReturn(fn) // returns the function pointer on success
		return 0
	})

	// atexit: register a function to call at exit
	d.RegisterAutoStubHandler(vcrt, "atexit", func(ctx *ntapi.TrapContext) uint32 {
		fn := ctx.Arg(0)
		ravelog.Logf("[vcrt] atexit fn=0x%x\n", fn)
		onexitMu.Lock()
		onexitTables[0] = append(onexitTables[0], fn)
		onexitMu.Unlock()
		ctx.SetReturn(0) // success
		return 0
	})

	// __telemetry_main_invoke_trigger / __telemetry_main_return_trigger: MSVC telemetry stubs
	d.RegisterAutoStubHandler(vcrt, "__telemetry_main_invoke_trigger", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	d.RegisterAutoStubHandler(vcrt, "__telemetry_main_return_trigger", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// _guard_check_icall / _guard_dispatch_icall: Control Flow Guard
	d.RegisterAutoStubHandler(vcrt, "_guard_check_icall", func(ctx *ntapi.TrapContext) uint32 {
		// CFG check: in emulation, all indirect calls are valid
		return 0
	})
	d.RegisterAutoStubHandler(vcrt, "_guard_dispatch_icall", func(ctx *ntapi.TrapContext) uint32 {
		// CFG dispatch: jump to the target in RAX
		if rr, ok := ctx.CPU.(ntapi.RegisterReader); ok {
			target := rr.ReadReg(0) // RAX
			if target != 0 {
				ctx.CPU.SetPC(target)
			}
		}
		return 0
	})

	// __vcrt_InitializeCriticalSectionEx: forward to InitializeCriticalSectionEx
	d.RegisterAutoStubHandler(vcrt, "__vcrt_InitializeCriticalSectionEx", func(ctx *ntapi.TrapContext) uint32 {
		cs := ctx.Arg(0)
		if cs != 0 {
			// Initialize the critical section fields to a valid state
			mem.Write64(cs, 0)    // DebugInfo
			mem.Write32(cs+8, 0)  // LockCount = -1 (unlocked)
			mem.Write32(cs+12, 0) // RecursionCount
			mem.Write64(cs+16, 0) // OwningThread
			mem.Write64(cs+24, 0) // LockSemaphore
			mem.Write64(cs+32, 0) // SpinCount
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	// __std_terminate: calls std::terminate() -> abort
	d.RegisterAutoStubHandler(vcrt, "__std_terminate", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[vcrt] __std_terminate called\n")
		fmt.Fprintf(os.Stderr, "govm: std::terminate() called\n")
		os.Exit(3)
		return 0
	})

	// _seh_filter_dll / _seh_filter_exe: default SEH filter
	d.RegisterAutoStubHandler(vcrt, "_seh_filter_dll", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(ntapi.ExceptionExecuteHandler))
		return 0
	})
	d.RegisterAutoStubHandler(vcrt, "_seh_filter_exe", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(ntapi.ExceptionExecuteHandler))
		return 0
	})

	// __report_rangecheckfailure: range check failure handler
	d.RegisterAutoStubHandler(vcrt, "__report_rangecheckfailure", func(ctx *ntapi.TrapContext) uint32 {
		rip := ctx.CPU.GetPC()
		ravelog.Logf("[vcrt] __report_rangecheckfailure at RIP=0x%x\n", rip)
		fmt.Fprintf(os.Stderr, "govm: range check failure at RIP=0x%x\n", rip)
		os.Exit(3)
		return 0
	})

	// __report_gsfailure: stack buffer overrun detected (GS cookie check)
	d.RegisterAutoStubHandler(vcrt, "__report_gsfailure", func(ctx *ntapi.TrapContext) uint32 {
		rip := ctx.CPU.GetPC()
		ravelog.Logf("[vcrt] __report_gsfailure (stack corruption) at RIP=0x%x\n", rip)
		fmt.Fprintf(os.Stderr, "govm: buffer overrun detected at RIP=0x%x\n", rip)
		os.Exit(3)
		return 0
	})

	// __security_check_cookie / __security_init_cookie: GS buffer security
	var gsCookie uint64 = 0x00002B992DDFA232 // fixed cookie for deterministic emulation
	d.RegisterAutoStubHandler(vcrt, "__security_init_cookie", func(ctx *ntapi.TrapContext) uint32 {
		// The cookie is stored in __security_cookie global; just log
		ravelog.Logf("[vcrt] __security_init_cookie\n")
		return 0
	})
	d.RegisterAutoStubHandler(vcrt, "__security_check_cookie", func(ctx *ntapi.TrapContext) uint32 {
		cookie := ctx.Arg(0)
		if cookie != gsCookie {
			ravelog.Logf("[vcrt] __security_check_cookie MISMATCH: got 0x%x expected 0x%x\n", cookie, gsCookie)
			// In real MSVC this would __fastfail, but we allow it to continue
		}
		return 0
	})

	// __vcrt_thread_attach / __vcrt_thread_detach: per-thread init/cleanup
	d.RegisterAutoStubHandler(vcrt, "__vcrt_thread_attach", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(vcrt, "__vcrt_thread_detach", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(1)
		return 0
	})

	// __vcrt_GetCurrentThreadId: forward to GetCurrentThreadId
	d.RegisterAutoStubHandler(vcrt, "__vcrt_GetCurrentThreadId", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(uint64(currentThreadID(ctx)))
		return 0
	})

	ravelog.Logf("[vcrt] registered vcruntime140 handlers\n")
}
