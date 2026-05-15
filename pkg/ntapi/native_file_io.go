//go:build guest_windows

package ntapi

import (
	"sync"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

type nativeIOOperation struct {
	id           uint64
	registry     *nativeIORegistry
	fileHandle   Handle
	file         *FileHandle
	ioStatus     uint64
	event        *EventHandle
	apcRoutine   uint64
	apcContext   uint64
	threadID     uint64
	cpu          arch.CPU
	mem          *mmu.MMU
	trampoline   *DllMainTrampoline
	trace        bool
	cancel       chan struct{}
	cancelOnce   sync.Once
	completeOnce sync.Once
	done         chan struct{}
}

type nativeIORegistry struct {
	mu     sync.Mutex
	nextID uint64
	byID   map[uint64]*nativeIOOperation
}

var nativeIORegistries sync.Map

func nativeIOFor(handles *HandleTable) *nativeIORegistry {
	registry := &nativeIORegistry{byID: make(map[uint64]*nativeIOOperation)}
	actual, _ := nativeIORegistries.LoadOrStore(handles, registry)
	return actual.(*nativeIORegistry)
}

func nativeCurrentThreadID(ctx *TrapContext) uint64 {
	if ctx == nil {
		return 1
	}
	var teb uint64
	var threadOffset uint64
	if ctx.CPU != nil {
		if ctx.CPU.GetArch() == arch.ArchI386 {
			teb = ctx.CPU.GetTLS()
			threadOffset = Teb32ThreadId
		} else if cpu, ok := ctx.CPU.(interface{ GetGSBase() uint64 }); ok {
			teb = cpu.GetGSBase()
			threadOffset = TebThreadId
		}
	}
	if teb != 0 && ctx.Mem != nil {
		if threadID, err := ctx.Mem.Read32(teb + threadOffset); err == nil && threadID != 0 {
			return uint64(threadID)
		}
	}
	if ctx.State != nil && ctx.State.ThreadId != 0 {
		return uint64(ctx.State.ThreadId)
	}
	return 1
}

func beginNativeIO(
	ctx *TrapContext,
	fileHandle Handle,
	file *FileHandle,
	ioStatus uint64,
	event *EventHandle,
	apcRoutine, apcContext uint64,
) *nativeIOOperation {
	registry := nativeIOFor(ctx.Handles)
	operation := &nativeIOOperation{
		registry:   registry,
		fileHandle: fileHandle,
		file:       file,
		ioStatus:   ioStatus,
		event:      event,
		apcRoutine: apcRoutine,
		apcContext: apcContext,
		threadID:   nativeCurrentThreadID(ctx),
		cpu:        ctx.CPU,
		mem:        ctx.Mem,
		trampoline: nativeIOTrampoline(ctx, apcRoutine),
		trace:      ctx.Trace,
		cancel:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	registry.mu.Lock()
	registry.nextID++
	operation.id = registry.nextID
	registry.byID[operation.id] = operation
	registry.mu.Unlock()
	writeIOStatus(ctx.Mem, ioStatus, StatusPending, 0)
	if event != nil {
		event.Reset()
	}
	return operation
}

func nativeIOTrampoline(ctx *TrapContext, apcRoutine uint64) *DllMainTrampoline {
	if apcRoutine == 0 || ctx == nil || ctx.State == nil {
		return nil
	}
	return ctx.State.GetOrCreateGuestCallTrampoline(func() *DllMainTrampoline {
		return AllocTrampoline(ctx.Mem)
	})
}

func notifyNativeIOCompletion(
	fileHandle Handle,
	file *FileHandle,
	ioStatus uint64,
	event *EventHandle,
	apcRoutine, apcContext, threadID uint64,
	cpu arch.CPU,
	mem *mmu.MMU,
	trampoline *DllMainTrampoline,
	trace bool,
	operationID uint64,
	status uint32,
	information uint64,
) {
	writeIOStatus(mem, ioStatus, status, information)
	if event != nil {
		event.Set()
	}
	if file != nil {
		if port, key, ok := file.CompletionAssociation(); ok {
			port.PostForFileOperation(
				fileHandle,
				key,
				apcContext,
				uint32(information),
				status,
				operationID,
			)
		}
	}
	if apcRoutine == 0 || trampoline == nil {
		return
	}
	ObjMgr.QueueAPC(threadID, func() {
		if _, err := CallGuestFunction(
			cpu,
			mem,
			trampoline,
			apcRoutine,
			[]uint64{apcContext, ioStatus, 0},
			trace,
		); err != nil {
			ravelog.Logf(
				"[ntapi] file I/O APC callback 0x%x failed: %v\n",
				apcRoutine,
				err,
			)
		}
	})
}

func completeNativeIOInline(
	ctx *TrapContext,
	fileHandle Handle,
	file *FileHandle,
	ioStatus uint64,
	event *EventHandle,
	apcRoutine, apcContext uint64,
	status uint32,
	information uint64,
) {
	notifyNativeIOCompletion(
		fileHandle,
		file,
		ioStatus,
		event,
		apcRoutine,
		apcContext,
		nativeCurrentThreadID(ctx),
		ctx.CPU,
		ctx.Mem,
		nativeIOTrampoline(ctx, apcRoutine),
		ctx.Trace,
		0,
		status,
		information,
	)
}

func (operation *nativeIOOperation) remove() {
	operation.registry.mu.Lock()
	delete(operation.registry.byID, operation.id)
	operation.registry.mu.Unlock()
}

func (operation *nativeIOOperation) complete(status uint32, information uint64) bool {
	completed := false
	operation.completeOnce.Do(func() {
		completed = true
		notifyNativeIOCompletion(
			operation.fileHandle,
			operation.file,
			operation.ioStatus,
			operation.event,
			operation.apcRoutine,
			operation.apcContext,
			operation.threadID,
			operation.cpu,
			operation.mem,
			operation.trampoline,
			operation.trace,
			operation.id,
			status,
			information,
		)
		operation.remove()
		close(operation.done)
	})
	return completed
}

func (operation *nativeIOOperation) requestCancel() bool {
	requested := false
	operation.cancelOnce.Do(func() {
		requested = true
		close(operation.cancel)
	})
	return requested
}

func (registry *nativeIORegistry) matching(
	fileHandle Handle,
	threadID uint64,
	onlyThread bool,
	ioStatus uint64,
) []*nativeIOOperation {
	registry.mu.Lock()
	operations := make([]*nativeIOOperation, 0, len(registry.byID))
	for _, operation := range registry.byID {
		if operation.fileHandle != fileHandle {
			continue
		}
		if onlyThread && operation.threadID != threadID {
			continue
		}
		if ioStatus != 0 && operation.ioStatus != ioStatus {
			continue
		}
		operations = append(operations, operation)
	}
	registry.mu.Unlock()
	return operations
}

func (registry *nativeIORegistry) cancelMatching(
	fileHandle Handle,
	threadID uint64,
	onlyThread bool,
	ioStatus uint64,
) int {
	operations := registry.matching(
		fileHandle,
		threadID,
		onlyThread,
		ioStatus,
	)
	cancelled := 0
	for _, operation := range operations {
		if operation.requestCancel() {
			cancelled++
		}
	}
	return cancelled
}

// CancelNativeIOForHandle completes every pending NT file operation on a
// closing handle with STATUS_CANCELLED.
func CancelNativeIOForHandle(handles *HandleTable, fileHandle Handle) int {
	if handles == nil {
		return 0
	}
	registry := nativeIOFor(handles)
	operations := registry.matching(fileHandle, 0, false, 0)
	cancelled := 0
	for _, operation := range operations {
		if operation.requestCancel() {
			cancelled++
		}
	}
	for _, operation := range operations {
		<-operation.done
	}
	return cancelled
}
