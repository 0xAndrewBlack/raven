//go:build guest_windows

package main

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestCxxCatchCallStackUsesIsolatedWindowsABIFrame(t *testing.T) {
	mem := mmu.New()
	stackBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	establisher := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	if err := mem.WriteBytes(establisher, make([]byte, mmu.PageSize)); err != nil {
		t.Fatal(err)
	}
	const (
		returnAddress = uint64(0x140001000)
		targetRIP     = uint64(0x140002000)
		targetRSP     = uint64(0x7fff12345000)
		rflags        = uint64(0x202)
	)
	entryRSP, err := cxxCatchCallStack(
		mem, stackBase, 0x10000, returnAddress, targetRIP, targetRSP, rflags,
	)
	if err != nil {
		t.Fatal(err)
	}
	if entryRSP&0xf != 8 || entryRSP < stackBase || entryRSP+0x50 > stackBase+0x10000 {
		t.Fatalf("catch entry RSP = %#x", entryRSP)
	}
	if entryRSP >= establisher && entryRSP < establisher+mmu.PageSize {
		t.Fatalf("catch frame overlaps establisher at %#x", establisher)
	}
	if got, _ := mem.Read64(entryRSP); got != returnAddress {
		t.Fatalf("return address = %#x", got)
	}
	shadow, err := mem.ReadBytes(entryRSP+8, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(shadow, make([]byte, 32)) {
		t.Fatalf("shadow space = %#v", shadow)
	}
	for offset, want := range map[uint64]uint64{
		0x28: targetRIP,
		0x30: 0x33,
		0x38: rflags,
		0x40: targetRSP,
		0x48: 0x2b,
	} {
		if got, _ := mem.Read64(entryRSP + offset); got != want {
			t.Fatalf("machine frame +%#x = %#x, want %#x", offset, got, want)
		}
	}
}

func TestRegisterCxxFrameHandlersIncludesVCRuntime140_1(t *testing.T) {
	mem := mmu.New()
	dispatcher := ntapi.NewDispatcher(mem, nil, nil, nil, nil, nil, nil)
	makeSynth := func(name string, id uint32) *ntapi.SynthPE {
		const address = uint64(0x1000)
		return &ntapi.SynthPE{
			Name:       name,
			Exports:    map[string]uint64{"__CxxFrameHandler4": address},
			StubIDs:    map[uint64]uint32{address: id},
			ExportOrds: make(map[uint16]uint64),
		}
	}
	vcrt := makeSynth("vcruntime140.dll", 0x8000)
	vcrtFH4 := makeSynth("vcruntime140_1.dll", 0x8001)
	registerCxxFrameHandlers(
		dispatcher,
		map[string]*ntapi.SynthPE{
			"vcruntime140.dll":   vcrt,
			"vcruntime140_1.dll": vcrtFH4,
		},
		func(*ntapi.TrapContext) uint32 { return 0 },
	)
	if address, _ := dispatcher.MaterializeNamedHandler(
		mem, vcrtFH4, "__CxxFrameHandler4", ntapi.DynExportIDBase,
	); address == 0 {
		t.Fatal("vcruntime140_1.dll __CxxFrameHandler4 was not registered")
	}
}

func TestCxxCatchTrampolineUnwindsToEstablisherContext(t *testing.T) {
	mem := mmu.New()
	trampoline, err := allocCxxCatchTrampoline(mem)
	if err != nil {
		t.Fatal(err)
	}
	stackBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		targetRIP = uint64(0x140004000)
		targetRSP = uint64(0x7fff56789000)
	)
	entryRSP, err := cxxCatchCallStack(
		mem, stackBase, 0x10000, trampoline.Addr, targetRIP, targetRSP, 0x246,
	)
	if err != nil {
		t.Fatal(err)
	}
	function, imageBase, _ := ntapi.LookupFunctionEntry(mem, trampoline.Addr, nil)
	if function == nil {
		t.Fatal("catch trampoline has no runtime function")
	}
	context := &ntapi.AMD64Context{Rip: trampoline.Addr}
	context.Regs[4] = entryRSP + 8
	if _, _, _, err := ntapi.VirtualUnwind(
		mem, 0, imageBase, trampoline.Addr, function, context,
	); err != nil {
		t.Fatal(err)
	}
	if context.Rip != targetRIP || context.Regs[4] != targetRSP {
		t.Fatalf("trampoline unwind context = %#v", context)
	}
}

func TestCxxRethrowPhaseTwoCrossesCatchTrampoline(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	trampoline, err := allocCxxCatchTrampoline(mem)
	if err != nil {
		t.Fatal(err)
	}
	const (
		catchBegin    = uint32(0x1000)
		targetBegin   = uint32(0x1100)
		catchUnwind   = uint32(0x3000)
		targetUnwind  = uint32(0x3040)
		catchHandler  = uint32(0x5000)
		targetHandler = uint32(0x5010)
		callback      = uint32(0x6000)
		continuation  = uint32(0x7000)
	)
	writeUnwindInfo := func(address uint64, handler uint32) {
		mem.Write8(address, 1|(ntapi.UnwFlagUHandler<<3))
		mem.Write8(address+1, 0)
		mem.Write8(address+2, 0)
		mem.Write8(address+3, 0)
		mem.Write32(address+4, handler)
	}
	writeUnwindInfo(imageBase+uint64(catchUnwind), catchHandler)
	writeUnwindInfo(imageBase+uint64(targetUnwind), targetHandler)
	table := &ntapi.ExceptionTable{
		ImageBase: imageBase,
		Entries: []ntapi.RuntimeFunction{
			{
				BeginAddress: catchBegin,
				EndAddress:   catchBegin + 0x100,
				UnwindData:   catchUnwind,
				EntryAddr:    imageBase + 0x200,
			},
			{
				BeginAddress: targetBegin,
				EndAddress:   targetBegin + 0x100,
				UnwindData:   targetUnwind,
				EntryAddr:    imageBase + 0x20c,
			},
		},
	}
	for index, function := range table.Entries {
		address := imageBase + 0x200 + uint64(index)*12
		mem.Write32(address, function.BeginAddress)
		mem.Write32(address+4, function.EndAddress)
		mem.Write32(address+8, function.UnwindData)
	}
	ntapi.RegisterExceptionTable(imageBase, 0x10000, table)

	catchStack := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	targetStack := imageBase + 0x8000
	mem.Write64(targetStack, 0)
	entryRSP, err := cxxCatchCallStack(
		mem,
		catchStack,
		0x10000,
		trampoline.Addr,
		imageBase+uint64(targetBegin)+0x10,
		targetStack,
		0x202,
	)
	if err != nil {
		t.Fatal(err)
	}
	contextAddress := imageBase + 0x7400
	exceptionAddress := imageBase + 0x7800
	context := &ntapi.AMD64Context{Rip: imageBase + uint64(catchBegin) + 0x10}
	context.Regs[4] = entryRSP
	if err := ntapi.WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	mem.Write32(exceptionAddress, ntapi.StatusUnwindConsolidate)
	mem.Write32(exceptionAddress+0x18, 1)
	mem.Write64(exceptionAddress+0x20, imageBase+uint64(callback))

	var calls []uint64
	err = ntapi.UnwindStack(
		mem,
		exceptionAddress,
		contextAddress,
		targetStack,
		imageBase+0xdead,
		0,
		0,
		func(address uint64, args []uint64) (uint64, error) {
			calls = append(calls, address)
			if address == imageBase+uint64(callback) {
				return imageBase + uint64(continuation), nil
			}
			return ntapi.ExceptionDispositionContinueSearch, nil
		},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []uint64{
		imageBase + uint64(catchHandler),
		imageBase + uint64(targetHandler),
		imageBase + uint64(callback),
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("rethrow phase-two calls = %#v, want %#v", calls, wantCalls)
	}
	result, err := ntapi.ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rip != imageBase+uint64(continuation) || result.Regs[4] != targetStack {
		t.Fatalf("rethrow continuation context = %#v", result)
	}
}

func TestCxxExceptionRegistryIsThreadAndExceptionScoped(t *testing.T) {
	registry := newCxxExceptionRegistry(nil)
	const threadCount = 32
	var nextSlot atomic.Uint64
	nextSlot.Store(0x100000)
	slots := make(chan uint64, threadCount)
	failures := make(chan string, threadCount)
	var wait sync.WaitGroup
	for tid := 1; tid <= threadCount; tid++ {
		tid := tid
		wait.Add(1)
		go func() {
			defer wait.Done()
			record := uint64(0x200000 + tid*0x100)
			context := uint64(0x300000 + tid*0x100)
			object := uint64(0x400000 + tid*0x100)
			handler := &ntapi.CxxCatchHandler{CatchState: int32(tid)}
			registry.begin(tid, record, context, object, handler)
			active, ok := registry.current(tid)
			if !ok || active.record != record || active.context != context ||
				active.object != object || active.handler != handler {
				failures <- "active exception crossed thread boundary"
				return
			}
			recordSlot, contextSlot := registry.slots(tid, func() uint64 {
				return nextSlot.Add(0x10) - 0x10
			})
			if contextSlot != recordSlot+8 {
				failures <- "thread slots are not adjacent"
				return
			}
			slots <- recordSlot
			if !registry.markRethrow(tid) || !registry.completeRethrow(tid) {
				failures <- "rethrow state was not retained"
				return
			}
			ended, destroy := registry.end(tid)
			if !destroy || !ended.rethrow || !ended.rethrowCompleted || ended.object != object {
				failures <- "completed rethrow did not transfer destruction ownership"
			}
		}()
	}
	wait.Wait()
	close(slots)
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	seen := make(map[uint64]bool)
	for slot := range slots {
		if seen[slot] {
			t.Fatalf("shared current-exception slot %#x", slot)
		}
		seen[slot] = true
	}
	if len(seen) != threadCount {
		t.Fatalf("thread slot count = %d, want %d", len(seen), threadCount)
	}
}

func TestCxxThrowMappingsAreReusedAfterHandledThrows(t *testing.T) {
	mem := mmu.New()
	cpu := x64.New(mem)
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}
	registry := newCxxExceptionRegistry(mem)
	recordSlot, contextSlot := registry.slots(1, func() uint64 {
		return mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	})
	var firstRecord, firstContext uint64
	for iteration := 0; iteration < 128; iteration++ {
		mappings, err := captureCxxThrowMappings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		record := mappings.record
		context := mappings.context
		if iteration == 0 {
			firstRecord = record
			firstContext = context
		} else if record != firstRecord || context != firstContext {
			t.Fatalf("throw %d mappings = (%#x, %#x), want (%#x, %#x)",
				iteration, record, context, firstRecord, firstContext)
		}

		registry.begin(1, record, context, 0x500000, &ntapi.CxxCatchHandler{})
		if _, ok := registry.current(1); !ok {
			t.Fatal("handled throw was not active")
		}
		if _, destroy := registry.end(1); !destroy {
			t.Fatal("handled throw did not close its exception lifetime")
		}
		if record, _ := mem.Read64(recordSlot); record != 0 {
			t.Fatalf("throw %d left current exception %#x", iteration, record)
		}
		if context, _ := mem.Read64(contextSlot); context != 0 {
			t.Fatalf("throw %d left current exception context %#x", iteration, context)
		}
		mappings.release(mem)
		if _, _, mapped, _ := mem.QueryRegion(record); mapped {
			t.Fatalf("throw %d exception record remained mapped", iteration)
		}
		if _, _, mapped, _ := mem.QueryRegion(context); mapped {
			t.Fatalf("throw %d context remained mapped", iteration)
		}
	}
}

func TestCxxThrowMappingsAreReleasedWhenContextCaptureFails(t *testing.T) {
	mem := mmu.New()
	probe := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.Munmap(probe, mmu.PageSize)
	ctx := &ntapi.TrapContext{Mem: mem}
	for iteration := 0; iteration < 128; iteration++ {
		if _, err := captureCxxThrowMappings(ctx); err == nil {
			t.Fatal("context capture without a CPU succeeded")
		}
		reused := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
		if reused != probe {
			t.Fatalf("capture failure %d allocated at %#x, want reused %#x",
				iteration, reused, probe)
		}
		mem.Munmap(reused, mmu.PageSize)
	}
}

func TestCxxThrowMappingsSurviveNestedThrowAndRethrow(t *testing.T) {
	mem := mmu.New()
	cpu := x64.New(mem)
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem}
	registry := newCxxExceptionRegistry(mem)
	recordSlot, contextSlot := registry.slots(1, func() uint64 {
		return mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	})

	outer, err := captureCxxThrowMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	outerRecord := outer.record
	outerContext := outer.context
	registry.begin(1, outerRecord, outerContext, 0x500000, &ntapi.CxxCatchHandler{})
	if record, _ := mem.Read64(recordSlot); record != outerRecord {
		t.Fatalf("outer current exception = %#x, want %#x", record, outerRecord)
	}
	if context, _ := mem.Read64(contextSlot); context != outerContext {
		t.Fatalf("outer current context = %#x, want %#x", context, outerContext)
	}

	inner, err := captureCxxThrowMappings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	registry.begin(1, inner.record, inner.context, 0x600000, &ntapi.CxxCatchHandler{})
	if record, _ := mem.Read64(recordSlot); record != inner.record {
		t.Fatalf("nested current exception = %#x, want %#x", record, inner.record)
	}
	if context, _ := mem.Read64(contextSlot); context != inner.context {
		t.Fatalf("nested current context = %#x, want %#x", context, inner.context)
	}
	if _, destroy := registry.end(1); !destroy {
		t.Fatal("nested throw did not own its exception object")
	}
	inner.release(mem)
	if record, _ := mem.Read64(recordSlot); record != outerRecord {
		t.Fatalf("current exception after nested throw = %#x, want %#x", record, outerRecord)
	}
	if context, _ := mem.Read64(contextSlot); context != outerContext {
		t.Fatalf("current context after nested throw = %#x, want %#x", context, outerContext)
	}

	active, ok := registry.current(1)
	if !ok || active.record != outerRecord || active.context != outerContext {
		t.Fatalf("outer throw was not restored after nested throw: %#v", active)
	}
	if err := mem.ValidateRange(outerRecord, cxxExceptionRecordSize, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatalf("outer exception record was released during nested throw: %v", err)
	}
	if err := mem.ValidateRange(outerContext, cxxContextRecordSize, mmu.PermRead|mmu.PermWrite); err != nil {
		t.Fatalf("outer context was released during nested throw: %v", err)
	}
	if !registry.markRethrow(1) || !registry.completeRethrow(1) {
		t.Fatal("outer rethrow state was not retained")
	}
	if ended, destroy := registry.end(1); !destroy || ended.record != outerRecord {
		t.Fatalf("completed rethrow lifetime = (%#v, %t)", ended, destroy)
	}
	if record, _ := mem.Read64(recordSlot); record != 0 {
		t.Fatalf("completed rethrow left current exception %#x", record)
	}
	if context, _ := mem.Read64(contextSlot); context != 0 {
		t.Fatalf("completed rethrow left current context %#x", context)
	}
	if err := mem.ValidateRange(outerContext, cxxContextRecordSize, mmu.PermRead); err != nil {
		t.Fatalf("rethrow released context before continuation restore: %v", err)
	}
	outer.release(mem)
	if _, _, mapped, _ := mem.QueryRegion(outerRecord); mapped {
		t.Fatal("outer exception record remained mapped after rethrow")
	}
	if _, _, mapped, _ := mem.QueryRegion(outerContext); mapped {
		t.Fatal("outer context remained mapped after rethrow")
	}
}

func TestWriteCxxConsolidateRecordUsesFH4PhaseTwoParameters(t *testing.T) {
	mem := mmu.New()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	handler := &ntapi.CxxCatchHandler{
		ImageBase:         0x140000000,
		FuncletRVA:        0x1200,
		EstablisherRBP:    0x7fff00100000,
		CatchState:        7,
		UnwindTargetState: 3,
		ContinuationCount: 2,
		ContinuationRVAs:  [2]uint32{0x2000, 0x3000},
	}
	if err := writeCxxConsolidateRecord(
		mem, address, 0x140004000, 0x500000, 0x600000, handler, nil,
	); err != nil {
		t.Fatal(err)
	}
	if status, _ := mem.Read32(address); status != ntapi.StatusUnwindConsolidate {
		t.Fatalf("consolidation status = %#x", status)
	}
	if count, _ := mem.Read32(address + 0x18); count != ntapi.CxxConsolidateParameterCount {
		t.Fatalf("consolidation parameter count = %d", count)
	}
	want := []uint64{
		0x140004000,
		handler.EstablisherRBP,
		7,
		3,
		0,
		handler.ImageBase + uint64(handler.FuncletRVA),
		0x500000,
		0x600000,
		handler.ImageBase + 0x2000,
		handler.ImageBase + 0x3000,
	}
	for index, expected := range want {
		got, _ := mem.Read64(address + 0x20 + uint64(index)*8)
		if got != expected {
			t.Fatalf("consolidation parameter %d = %#x, want %#x", index, got, expected)
		}
	}
}

func TestWriteCxxConsolidateRecordCarriesRethrowState(t *testing.T) {
	mem := mmu.New()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	handler := &ntapi.CxxCatchHandler{
		ImageBase:         0x140000000,
		FuncletRVA:        0x1200,
		EstablisherRBP:    0x7fff00100000,
		CatchState:        13,
		UnwindTargetState: 8,
	}
	state := int32(12)
	if err := writeCxxConsolidateRecord(
		mem, address, 0x140004000, 0x500000, 0x600000, handler, &state,
	); err != nil {
		t.Fatal(err)
	}
	if got, _ := mem.Read64(address + 0x40); int32(got) != state {
		t.Fatalf("rethrow state = %d, want %d", int32(got), state)
	}
	if marker, _ := mem.Read64(address + 0x68); marker != 1 {
		t.Fatalf("rethrow state marker = %d", marker)
	}
}

func TestExecuteCxxUnwindActionsPreservesOrderAndArguments(t *testing.T) {
	mem := mmu.New()
	frame := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	imageBase := uint64(0x140000000)
	pointedObject := frame + 0x300
	mem.Write64(frame+0x40, pointedObject)
	handler := &ntapi.CxxCatchHandler{
		UnwindActions: []ntapi.CxxUnwindAction{
			{
				Kind:          ntapi.CxxUnwindFrame,
				HandlerRVA:    0x1000,
				Frame:         frame,
				ObjectAddress: frame,
			},
			{
				Kind:          ntapi.CxxUnwindDestructorPointer,
				HandlerRVA:    0x2000,
				Frame:         frame,
				ObjectAddress: frame + 0x40,
			},
			{
				Kind:          ntapi.CxxUnwindDestructorObject,
				HandlerRVA:    0x3000,
				Frame:         frame,
				ObjectAddress: frame + 0x80,
			},
		},
	}

	var addresses []uint64
	var arguments [][]uint64
	err := executeCxxUnwindActions(mem, imageBase, handler, func(address uint64, args []uint64) (uint64, error) {
		addresses = append(addresses, address)
		arguments = append(arguments, append([]uint64(nil), args...))
		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(addresses, []uint64{
		imageBase + 0x1000,
		imageBase + 0x2000,
		imageBase + 0x3000,
	}) {
		t.Fatalf("action addresses = %#v", addresses)
	}
	if !reflect.DeepEqual(arguments, [][]uint64{
		{frame, frame},
		{pointedObject, frame},
		{frame + 0x80, frame},
	}) {
		t.Fatalf("action arguments = %#v", arguments)
	}
}

func TestCxxContinuationAddress(t *testing.T) {
	const imageBase = uint64(0x140000000)
	tests := []struct {
		name    string
		handler *ntapi.CxxCatchHandler
		result  uint64
		want    uint64
		wantErr bool
	}{
		{
			name:    "funclet returns absolute continuation",
			handler: &ntapi.CxxCatchHandler{},
			result:  imageBase + 0x1000,
			want:    imageBase + 0x1000,
		},
		{
			name:    "one encoded continuation",
			handler: &ntapi.CxxCatchHandler{ContinuationCount: 1, ContinuationRVAs: [2]uint32{0x2000}},
			want:    imageBase + 0x2000,
		},
		{
			name:    "second encoded continuation",
			handler: &ntapi.CxxCatchHandler{ContinuationCount: 2, ContinuationRVAs: [2]uint32{0x3000, 0x4000}},
			result:  1,
			want:    imageBase + 0x4000,
		},
		{
			name:    "invalid selector",
			handler: &ntapi.CxxCatchHandler{ContinuationCount: 2, ContinuationRVAs: [2]uint32{0x3000, 0x4000}},
			result:  2,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cxxContinuationAddress(imageBase, tt.handler, tt.result)
			if (err != nil) != tt.wantErr {
				t.Fatalf("cxxContinuationAddress() error = %v, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("cxxContinuationAddress() = %#x, want %#x", got, tt.want)
			}
		})
	}
}
