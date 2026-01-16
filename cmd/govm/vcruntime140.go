package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

// registerVcruntime140Handlers registers handlers for vcruntime140.dll.
// This DLL provides C++ exception handling, memory intrinsics, and CRT
// startup/shutdown helpers that MSVC-compiled binaries depend on.
func registerVcruntime140Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	sharedHeapAlloc := hctx.HeapAlloc
	sharedHeapFree := hctx.HeapFree
	exceptionTable := hctx.ExTable

	vcrt, ok := hctx.SynthByName["vcruntime140.dll"]
	if !ok {
		return
	}

	// ── Thread-local exception state ──
	// Per-thread current exception pointer and context.
	var currentExMu sync.Mutex
	var currentExceptionPtr uint64
	var currentExceptionContextPtr uint64

	// ── Onexit table support ──
	// Each onexit table is tracked by its guest address.
	var onexitMu sync.Mutex
	onexitTables := make(map[uint64][]uint64) // table addr → list of function pointers

	// ── Type info destroy list ──
	// MSVC keeps a singly-linked list of RTTI type_info nodes for cleanup.
	// Each node: { next *node; data *void } - 16 bytes on x64.

	// ════════════════════════════════════════════════════════════════════
	// C++ Exception Handling
	// ════════════════════════════════════════════════════════════════════

	// __CxxFrameHandler3: C++ frame-based exception handler (FH3 format).
	// Called by the OS exception dispatcher. Walks the function's try/catch
	// map, evaluates type-match filters, and dispatches to catch funclets.
	//
	// Signature: EXCEPTION_DISPOSITION __CxxFrameHandler3(
	//   EXCEPTION_RECORD *pExcept, void *EstablisherFrame,
	//   CONTEXT *pContext, DISPATCHER_CONTEXT *pDispatcherContext)
	d.RegisterAutoStubHandler(vcrt, "__CxxFrameHandler3", func(ctx *ntapi.TrapContext) uint32 {
		exceptionRecord := ctx.Arg(0)
		dispatcherContext, err := ntapi.ReadDispatcherContext(ctx.Mem, ctx.Arg(3))
		if err != nil || dispatcherContext == nil {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}

		// Use the emulator's built-in C++ exception dispatch engine which
		// parses FH3 FuncInfo, walks tryBlockMap, and matches catch types.
		rsp := dispatcherContext.EstablisherFrame
		rip := dispatcherContext.ControlPc
		handler := ntapi.CxxDispatchException(ctx.Mem, exceptionTable, rsp, rip, ctx.Trace)
		if handler != nil {
			imageBase := uint64(0)
			if exceptionTable != nil {
				imageBase = exceptionTable.ImageBase
			}
			if handler.IsFallback {
				ravelog.Logf("[vcrt] __CxxFrameHandler3 FH4 fallback unwind RIP=0x%x RSP=0x%x\n",
					handler.FallbackRIP, handler.FallbackRSP)
				contextRecord, err := ntapi.ReadAMD64Context(ctx.Mem, dispatcherContext.ContextRecord)
				if err == nil {
					contextRecord.Rip = handler.FallbackRIP
					contextRecord.Regs[7] = handler.FallbackRSP // RSP
					for reg, val := range handler.SavedRegs {
						if reg < len(contextRecord.Regs) {
							contextRecord.Regs[reg] = val
						}
					}
					_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
				}
				ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
				return 0
			}
			catchAddr := imageBase + uint64(handler.FuncletRVA)
			ravelog.Logf("[vcrt] __CxxFrameHandler3 → catch at 0x%x establisher=0x%x\n",
				catchAddr, handler.EstablisherRBP)

			// Place the thrown object at [EstablisherRBP + CatchObjOffset]
			if handler.CatchObjOffset != 0 {
				// Read thrown object pointer from the exception parameters
				nParams, _ := ctx.Mem.Read32(exceptionRecord + 0x18)
				if nParams >= 2 {
					thrownObjPtr, _ := ctx.Mem.Read64(exceptionRecord + 0x20 + 8) // args[1]
					dest := handler.EstablisherRBP + uint64(int64(handler.CatchObjOffset))
					ctx.Mem.Write64(dest, thrownObjPtr)
				}
			}

			// Update context to resume at the catch funclet
			contextRecord, err := ntapi.ReadAMD64Context(ctx.Mem, dispatcherContext.ContextRecord)
			if err == nil {
				if handler.FuncletRVA != 0 {
					contextRecord.Rip = catchAddr
				} else if handler.ContinuationRVA != 0 {
					contextRecord.Rip = imageBase + uint64(handler.ContinuationRVA)
				}
				contextRecord.Regs[4] = handler.EstablisherRBP // RBP
				for reg, val := range handler.SavedRegs {
					if reg < len(contextRecord.Regs) {
						contextRecord.Regs[reg] = val
					}
				}
				_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
			}

			// Save current exception for __current_exception()
			currentExMu.Lock()
			currentExceptionPtr = exceptionRecord
			currentExceptionContextPtr = dispatcherContext.ContextRecord
			currentExMu.Unlock()

			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
			return 0
		}

		ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		return 0
	})

	// __CxxFrameHandler4: FH4 compressed format - same dispatch logic.
	d.RegisterAutoStubHandler(vcrt, "__CxxFrameHandler4", func(ctx *ntapi.TrapContext) uint32 {
		dispatcherContext, err := ntapi.ReadDispatcherContext(ctx.Mem, ctx.Arg(3))
		if err != nil || dispatcherContext == nil {
			ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
			return 0
		}

		rsp := dispatcherContext.EstablisherFrame
		rip := dispatcherContext.ControlPc
		handler := ntapi.CxxDispatchException(ctx.Mem, exceptionTable, rsp, rip, ctx.Trace)
		if handler != nil {
			imageBase := uint64(0)
			if exceptionTable != nil {
				imageBase = exceptionTable.ImageBase
			}
			contextRecord, err := ntapi.ReadAMD64Context(ctx.Mem, dispatcherContext.ContextRecord)
			if err == nil {
				if handler.IsFallback {
					contextRecord.Rip = handler.FallbackRIP
					contextRecord.Regs[7] = handler.FallbackRSP
				} else if handler.FuncletRVA != 0 {
					contextRecord.Rip = imageBase + uint64(handler.FuncletRVA)
				} else if handler.ContinuationRVA != 0 {
					contextRecord.Rip = imageBase + uint64(handler.ContinuationRVA)
				}
				contextRecord.Regs[4] = handler.EstablisherRBP
				for reg, val := range handler.SavedRegs {
					if reg < len(contextRecord.Regs) {
						contextRecord.Regs[reg] = val
					}
				}
				_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
			}
			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
			return 0
		}
		ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		return 0
	})

	// _CxxThrowException: raise a C++ exception.
	// Builds an EXCEPTION_RECORD with code 0xE06D7363 and dispatches it
	// through RaiseException, which the emulator's kernel32 handler processes.
	d.RegisterAutoStubHandler(vcrt, "_CxxThrowException", func(ctx *ntapi.TrapContext) uint32 {
		pExceptionObject := ctx.Arg(0) // pointer to thrown object
		pThrowInfo := ctx.Arg(1)       // pointer to _ThrowInfo
		ravelog.Logf("[vcrt] _CxxThrowException obj=0x%x throwInfo=0x%x\n", pExceptionObject, pThrowInfo)

		// Build an EXCEPTION_RECORD on the guest heap:
		// ExceptionCode = 0xE06D7363 ('msc' | 0xE0000000)
		// ExceptionFlags = EXCEPTION_NONCONTINUABLE (1)
		// NumberParameters = 4
		// ExceptionInformation[0] = EH magic (0x19930520)
		// ExceptionInformation[1] = pointer to thrown object
		// ExceptionInformation[2] = pointer to _ThrowInfo
		// ExceptionInformation[3] = image base (for RVA-based pThrowInfo)
		const excRecordSize = 0x100
		excRecord := mem.Mmap(0, excRecordSize, mmu.PermRead|mmu.PermWrite)
		mem.Write32(excRecord+0x00, 0xE06D7363) // ExceptionCode
		mem.Write32(excRecord+0x04, 1)           // ExceptionFlags = NONCONTINUABLE
		mem.Write64(excRecord+0x08, 0)           // ExceptionRecord chain
		mem.Write64(excRecord+0x10, ctx.CPU.GetPC()) // ExceptionAddress
		mem.Write32(excRecord+0x18, 4)           // NumberParameters

		imageBase := uint64(0)
		if exceptionTable != nil {
			imageBase = exceptionTable.ImageBase
		}
		mem.Write64(excRecord+0x20, 0x19930520)      // EH magic number
		mem.Write64(excRecord+0x28, pExceptionObject) // thrown object
		mem.Write64(excRecord+0x30, pThrowInfo)       // _ThrowInfo
		mem.Write64(excRecord+0x38, imageBase)        // module base for RVA resolution

		// Save as current exception
		currentExMu.Lock()
		currentExceptionPtr = excRecord
		currentExMu.Unlock()

		// Dispatch through the emulator's SEH machinery
		rsp := ctx.CPU.GetSP()
		rip := ctx.CPU.GetPC()
		handler := ntapi.CxxDispatchException(ctx.Mem, exceptionTable, rsp, rip, ctx.Trace)
		if handler != nil {
			if handler.IsFallback {
				ravelog.Logf("[vcrt] _CxxThrowException → FH4 fallback RIP=0x%x RSP=0x%x\n",
					handler.FallbackRIP, handler.FallbackRSP)
				if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
					rw.WriteReg(0, 0) // RAX = 0
					for reg, val := range handler.SavedRegs {
						rw.WriteReg(reg, val)
					}
				}
				ctx.CPU.SetSP(handler.FallbackRSP)
				ctx.CPU.SetPC(handler.FallbackRIP)
				return 0
			}
			catchAddr := imageBase + uint64(handler.FuncletRVA)
			// Place thrown object for the catch block
			if handler.CatchObjOffset != 0 && pExceptionObject != 0 {
				dest := handler.EstablisherRBP + uint64(int64(handler.CatchObjOffset))
				mem.Write64(dest, pExceptionObject)
			}
			if handler.FuncletRVA == 0 && handler.ContinuationRVA != 0 {
				contAddr := imageBase + uint64(handler.ContinuationRVA)
				if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
					for reg, val := range handler.SavedRegs {
						rw.WriteReg(reg, val)
					}
				}
				ctx.CPU.SetPC(contAddr)
				ctx.CPU.SetSP(handler.BodyRSP)
				return 0
			}
			if rw, ok := ctx.CPU.(ntapi.RegisterWriter); ok {
				for reg, val := range handler.SavedRegs {
					rw.WriteReg(reg, val)
				}
				rw.WriteReg(2, handler.EstablisherRBP) // RDX = establisher frame
			}
			sp := handler.EstablisherRBP - 8
			ctx.CPU.SetSP(sp)
			ctx.CPU.SetPC(catchAddr)
			return 0
		}

		// No handler found - this is a fatal unhandled C++ exception
		ravelog.Logf("[vcrt] _CxxThrowException: no handler found - calling terminate\n")
		fmt.Fprintf(os.Stderr, "govm: unhandled C++ exception at RIP=0x%x\n", rip)
		os.Exit(3)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// __C_specific_handler: C SEH dispatch (same as kernel32's implementation)
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(vcrt, "__C_specific_handler", func(ctx *ntapi.TrapContext) uint32 {
		exceptionRecord := ctx.Arg(0)
		dispatcherContext, err := ntapi.ReadDispatcherContext(ctx.Mem, ctx.Arg(3))
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
				// Call the filter expression
				exceptionPointersAddr := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
				mem.Write64(exceptionPointersAddr+0, exceptionRecord)
				mem.Write64(exceptionPointersAddr+8, dispatcherContext.ContextRecord)
				filterAddr := dispatcherContext.ImageBase + uint64(handlerRVA)
				ret, callErr := ntapi.CallGuestFunction(ctx.CPU, mem,
					ntapi.AllocTrampoline(mem), filterAddr,
					[]uint64{exceptionPointersAddr}, ctx.Trace)
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
			_ = ntapi.WriteDispatcherContext(ctx.Mem, ctx.Arg(3), dispatcherContext)
			contextRecord.Rip = dispatcherContext.TargetIp
			contextRecord.Regs[4] = dispatcherContext.EstablisherFrame // RBP
			_ = ntapi.WriteAMD64Context(ctx.Mem, dispatcherContext.ContextRecord, contextRecord)
			ctx.SetReturn(ntapi.ExceptionDispositionContinueExecution)
			return 0
		}
		ctx.SetReturn(ntapi.ExceptionDispositionContinueSearch)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// Memory intrinsics (same logic as ucrtbase)
	// ════════════════════════════════════════════════════════════════════

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

	// ════════════════════════════════════════════════════════════════════
	// _purecall: Called when a pure virtual function is invoked.
	// This is always a fatal programming error.
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(vcrt, "_purecall", func(ctx *ntapi.TrapContext) uint32 {
		rip := ctx.CPU.GetPC()
		ravelog.Logf("[vcrt] _purecall invoked from RIP=0x%x - pure virtual function call\n", rip)
		fmt.Fprintf(os.Stderr, "govm: pure virtual function call at RIP=0x%x\n", rip)
		os.Exit(3)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// __std_type_info_destroy_list: Walk and free RTTI type_info nodes.
	// The list is a singly-linked list of {next, data} pairs.
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(vcrt, "__std_type_info_destroy_list", func(ctx *ntapi.TrapContext) uint32 {
		headPtr := ctx.Arg(0)
		if headPtr == 0 {
			return 0
		}
		// Read the head pointer (first node address)
		node, _ := mem.Read64(headPtr)
		freed := 0
		for node != 0 && freed < 10000 {
			next, _ := mem.Read64(node)      // node->next
			dataPtr, _ := mem.Read64(node + 8) // node->data
			if dataPtr != 0 {
				sharedHeapFree(dataPtr)
			}
			sharedHeapFree(node)
			node = next
			freed++
		}
		// Clear the head pointer
		mem.Write64(headPtr, 0)
		ravelog.Logf("[vcrt] __std_type_info_destroy_list freed %d nodes\n", freed)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// __std_exception_copy / __std_exception_destroy
	// MSVC std::exception internal structure:
	//   struct __std_exception_data { char* _What; bool _DoFree; };
	// ════════════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(vcrt, "__std_exception_copy", func(ctx *ntapi.TrapContext) uint32 {
		src := ctx.Arg(0) // const __std_exception_data*
		dst := ctx.Arg(1) // __std_exception_data*
		if src == 0 || dst == 0 {
			return 0
		}
		srcWhat, _ := mem.Read64(src)     // char* _What
		srcFree, _ := mem.Read8(src + 8)  // bool _DoFree
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

	// ════════════════════════════════════════════════════════════════════
	// CRT startup/shutdown helpers
	// ════════════════════════════════════════════════════════════════════

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

	// ════════════════════════════════════════════════════════════════════
	// __vcrt forwarded kernel32 functions
	// ════════════════════════════════════════════════════════════════════

	// __vcrt_GetModuleFileNameW: forward to GetModuleFileNameW logic
	d.RegisterAutoStubHandler(vcrt, "__vcrt_GetModuleFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		// hModule(arg0), lpFilename(arg1), nSize(arg2)
		buf := ctx.Arg(1)
		nSize := ctx.Arg(2)
		path := hctx.ImagePath
		if buf != 0 && nSize > 0 {
			n := len(path)
			if uint64(n) >= nSize {
				n = int(nSize) - 1
			}
			for i := 0; i < n; i++ {
				ctx.Mem.Write16(buf+uint64(i*2), uint16(path[i]))
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
			// NULL → return main module base
			if hctx.MainModule != nil {
				ctx.SetReturn(hctx.MainModule.BaseAddr)
			} else {
				ctx.SetReturn(0x00400000)
			}
		} else {
			// Look up by DLL name
			name := hctx.ReadGuestUTF16(namePtr)
			found := false
			for dllName, synth := range hctx.SynthByName {
				if len(dllName) > 0 && len(name) > 0 &&
					(dllName == name || dllName == name+".dll") {
					ctx.SetReturn(synth.BaseAddr)
					found = true
					break
				}
			}
			if !found {
				ctx.SetReturn(0)
			}
		}
		return 0
	})

	// __vcrt_LoadLibraryExW: forward to LoadLibraryExW logic
	d.RegisterAutoStubHandler(vcrt, "__vcrt_LoadLibraryExW", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := hctx.ReadGuestUTF16(namePtr)
		ravelog.Logf("[vcrt] __vcrt_LoadLibraryExW %q\n", name)
		// Check if it's one of our synthetic DLLs
		for dllName, synth := range hctx.SynthByName {
			if dllName == name || dllName == name+".dll" {
				ctx.SetReturn(synth.BaseAddr)
				return 0
			}
		}
		// Return a fake non-zero handle to avoid NULL failure
		ctx.SetReturn(0xDEAD0000)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// __current_exception / __current_exception_context
	// Return pointers to thread-local exception state.
	// ════════════════════════════════════════════════════════════════════

	// Allocate guest slots for the pointers
	currentExSlot := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	currentExCtxSlot := currentExSlot + 8

	d.RegisterAutoStubHandler(vcrt, "__current_exception", func(ctx *ntapi.TrapContext) uint32 {
		currentExMu.Lock()
		mem.Write64(currentExSlot, currentExceptionPtr)
		currentExMu.Unlock()
		ctx.SetReturn(currentExSlot)
		return 0
	})

	d.RegisterAutoStubHandler(vcrt, "__current_exception_context", func(ctx *ntapi.TrapContext) uint32 {
		currentExMu.Lock()
		mem.Write64(currentExCtxSlot, currentExceptionContextPtr)
		currentExMu.Unlock()
		ctx.SetReturn(currentExCtxSlot)
		return 0
	})

	// ════════════════════════════════════════════════════════════════════
	// Additional vcruntime140 exports
	// ════════════════════════════════════════════════════════════════════

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
		ti := ctx.Arg(0)         // type_info*
		result := ctx.Arg(1)     // __std_type_info_data*
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
			mem.Write64(cs, 0)     // DebugInfo
			mem.Write32(cs+8, 0)   // LockCount = -1 (unlocked)
			mem.Write32(cs+12, 0)  // RecursionCount
			mem.Write64(cs+16, 0)  // OwningThread
			mem.Write64(cs+24, 0)  // LockSemaphore
			mem.Write64(cs+32, 0)  // SpinCount
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})

	// __std_terminate: calls std::terminate() → abort
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
		ctx.SetReturn(uint64(runtime.NumCPU())) // return a stable thread ID
		return 0
	})

	ravelog.Logf("[vcrt] registered vcruntime140 handlers\n")
}
