//go:build guest_windows

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

const crtTimeTestTEB = 0x71000000

func crtTimeTestTM(fields ...int32) []byte {
	data := make([]byte, 36)
	for index, field := range fields {
		binary.LittleEndian.PutUint32(data[index*4:], uint32(field))
	}
	return data
}

func newCRTTimeInvocations(t *testing.T, names []string, is32 bool) (map[string]*crtContractInvocation, *mmu.MMU) {
	t.Helper()
	mem := mmu.New()
	mem.Mode32 = is32
	state := &ntapi.ProcessState{Is32: is32, TEBAddr: crtTimeTestTEB}
	dispatcher := ntapi.NewDispatcher(mem, vfs.New(), ntapi.NewHandleTable(), nil, state, nil, nil)
	synth := ntapi.GenerateSynthDLL(mem, crtTimeGMTModule, names, ntapi.AutoSynthIDBase)
	hctx := &HandlerCtx{
		Disp:        dispatcher,
		Mem:         mem,
		ProcState:   state,
		SynthByName: map[string]*ntapi.SynthPE{crtTimeGMTModule: synth},
	}
	registerCRTDefinitions(hctx, crtSemanticDefinitions())
	invocations := make(map[string]*crtContractInvocation, len(names))
	for _, name := range names {
		invocations[name] = &crtContractInvocation{
			Dispatcher: dispatcher,
			Synth:      synth,
			Mem:        mem,
			Is32:       is32,
			Module:     crtTimeGMTModule,
			Name:       name,
		}
	}
	return invocations, mem
}

func TestCRTTimeContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		for _, semantic := range crtTimeSemantics {
			t.Run(fmt.Sprintf("%s/PE%d", semantic.name, map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
				dispatcher, synth, mem := newCRTDispatcher(t, crtTimeGMTModule, semantic.name, is32)
				hctx := &HandlerCtx{
					Disp:        dispatcher,
					Mem:         mem,
					ProcState:   &ntapi.ProcessState{Is32: is32},
					SynthByName: map[string]*ntapi.SynthPE{crtTimeGMTModule: synth},
				}
				registerCRTDefinitions(hctx, crtSemanticDefinitions())
				run := newCRTContractRun()
				run.Execute(hctx)
				key := crtContractKey{
					Module:           crtTimeGMTModule,
					Name:             semantic.name,
					Architecture:     map[bool]string{true: "i386", false: "win64"}[is32],
					ImplementationID: semantic.id,
					Signature:        semantic.signature,
				}
				evidence, ok := run.evidence[key]
				if !ok || !evidence.executed || !evidence.passed {
					t.Fatalf("time contract failed: %#v", evidence)
				}
				if evidence.callCount != 3 || evidence.distinctInputs != 3 || evidence.distinctObservations != 3 || !evidence.memoryChanged {
					t.Fatalf("time contract evidence is incomplete: %#v", evidence)
				}
			})
		}
	}
}

func TestCRTTimeSecureLimitsAndErrors(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocations, mem := newCRTTimeInvocations(t, []string{"_gmtime32_s", "_gmtime64_s"}, is32)
			output := mem.Mmap(0, crtTimeTMSize, mmu.PermRead|mmu.PermWrite)
			seconds32 := crtTimeContractSeconds(mem, 32, 0)
			crtWriteErrno(&ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{TEBAddr: crtTimeTestTEB}}, 0x1234)
			result, err := invocations["_gmtime32_s"].Call(output, seconds32)
			wantLower := crtTimeTestTM(0, 0, 0, 1, 0, 70, 4, 0, 0)
			got, readErr := mem.ReadBytes(output, crtTimeTMSize)
			if err != nil || readErr != nil || result != 0 || !bytes.Equal(got, wantLower) || crtReadErrno(mem, crtTimeTestTEB) != 0x1234 {
				t.Fatalf("_gmtime32_s lower limit result=%d output=%x errno=%d callErr=%v readErr=%v", result, got, crtReadErrno(mem, crtTimeTestTEB), err, readErr)
			}

			seconds32 = crtTimeContractSeconds(mem, 32, crtTimeMax32)
			result, err = invocations["_gmtime32_s"].Call(output, seconds32)
			wantUpper32 := crtTimeTestTM(59, 59, 23, 18, 0, 138, 1, 17, 0)
			got, readErr = mem.ReadBytes(output, crtTimeTMSize)
			if err != nil || readErr != nil || result != 0 || !bytes.Equal(got, wantUpper32) {
				t.Fatalf("_gmtime32_s upper limit result=%d output=%x callErr=%v readErr=%v", result, got, err, readErr)
			}

			tooHigh32 := crtTimeContractSeconds(mem, 32, crtTimeMax32+1)
			result, err = invocations["_gmtime32_s"].Call(output, tooHigh32)
			if err != nil || result != crtTimeEINVAL ||
				invocations["_gmtime32_s"].calls[len(invocations["_gmtime32_s"].calls)-1].abortCode != 0 {
				t.Fatalf("_gmtime32_s above range result=%d err=%v", result, err)
			}

			seconds64 := crtTimeContractSeconds(mem, 64, 32535215999)
			result, err = invocations["_gmtime64_s"].Call(output, seconds64)
			wantUpper := crtTimeTestTM(59, 59, 23, 31, 11, 1100, 3, 364, 0)
			got, readErr = mem.ReadBytes(output, crtTimeTMSize)
			if err != nil || readErr != nil || result != 0 || !bytes.Equal(got, wantUpper) {
				t.Fatalf("_gmtime64_s upper limit result=%d output=%x callErr=%v readErr=%v", result, got, err, readErr)
			}

			result, err = invocations["_gmtime32_s"].Call(0, seconds32)
			if err != nil || result != crtTimeEINVAL || crtReadErrno(mem, crtTimeTestTEB) != crtTimeEINVAL ||
				invocations["_gmtime32_s"].calls[len(invocations["_gmtime32_s"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime32_s null result buffer result=%d errno=%d err=%v", result, crtReadErrno(mem, crtTimeTestTEB), err)
			}

			crtWriteErrno(&ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{TEBAddr: crtTimeTestTEB}}, 0x1234)
			result, err = invocations["_gmtime64_s"].Call(output, 0)
			got, readErr = mem.ReadBytes(output, crtTimeTMSize)
			if err != nil || readErr != nil || result != crtTimeEINVAL || !bytes.Equal(got, bytes.Repeat([]byte{0xff}, crtTimeTMSize)) ||
				crtReadErrno(mem, crtTimeTestTEB) != crtTimeEINVAL ||
				invocations["_gmtime64_s"].calls[len(invocations["_gmtime64_s"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime64_s null result=%d output=%x errno=%d callErr=%v readErr=%v", result, got, crtReadErrno(mem, crtTimeTestTEB), err, readErr)
			}

			tooLow := crtTimeContractSeconds(mem, 64, -1)
			result, err = invocations["_gmtime64_s"].Call(output, tooLow)
			if err != nil || result != crtTimeEINVAL ||
				invocations["_gmtime64_s"].calls[len(invocations["_gmtime64_s"].calls)-1].abortCode != 0 {
				t.Fatalf("_gmtime64_s below range result=%d err=%v", result, err)
			}

			tooHigh := crtTimeContractSeconds(mem, 64, 32535216000)
			result, err = invocations["_gmtime64_s"].Call(output, tooHigh)
			if err != nil || result != crtTimeEINVAL ||
				invocations["_gmtime64_s"].calls[len(invocations["_gmtime64_s"].calls)-1].abortCode != 0 {
				t.Fatalf("_gmtime64_s above range result=%d err=%v", result, err)
			}
		})
	}
}

func TestCRTTimeBuffersFollowCurrentGuestTEB(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			mem := mmu.New()
			mem.Mode32 = is32
			cpu := x64.New(mem)
			cpu.Mode32 = is32
			state := &ntapi.ProcessState{Is32: is32, TEBAddr: 0x71000000}
			ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem, State: state}
			setTEB := func(address uint64) {
				if is32 {
					cpu.SetTLS(address)
				} else {
					cpu.SetGSBase(address)
				}
			}

			setTEB(0x72000000)
			first := crtTimeBuffer(ctx)
			if first == 0 || crtTimeCurrentTEB(ctx) != 0x72000000 {
				t.Fatalf("first TEB=%#x buffer=%#x", crtTimeCurrentTEB(ctx), first)
			}
			setTEB(0x73000000)
			second := crtTimeBuffer(ctx)
			if second == 0 || second == first || crtTimeCurrentTEB(ctx) != 0x73000000 {
				t.Fatalf("second TEB=%#x first=%#x second=%#x", crtTimeCurrentTEB(ctx), first, second)
			}
			setTEB(0x72000000)
			if repeated := crtTimeBuffer(ctx); repeated != first {
				t.Fatalf("first TEB buffer changed from %#x to %#x", first, repeated)
			}

			if !crtTimeWriteErrno(ctx, 31) || crtReadErrno(mem, 0x72000000) != 31 {
				t.Fatalf("first TEB errno=%d", crtReadErrno(mem, 0x72000000))
			}
			setTEB(0x73000000)
			if !crtTimeWriteErrno(ctx, 47) || crtReadErrno(mem, 0x73000000) != 47 || crtReadErrno(mem, 0x72000000) != 31 {
				t.Fatalf("errno first=%d second=%d", crtReadErrno(mem, 0x72000000), crtReadErrno(mem, 0x73000000))
			}
		})
	}
}

func TestCRTTimeBuffersSupportConcurrentGuestTEBs(t *testing.T) {
	mem := mmu.New()
	state := &ntapi.ProcessState{TEBAddr: 0x71000000}
	contexts := make([]*ntapi.TrapContext, 2)
	for index, teb := range []uint64{0x72000000, 0x73000000} {
		cpu := x64.New(mem)
		cpu.SetGSBase(teb)
		contexts[index] = &ntapi.TrapContext{CPU: cpu, Mem: mem, State: state}
	}

	results := make([]uint64, len(contexts))
	var group sync.WaitGroup
	for index, context := range contexts {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				address := crtTimeBuffer(context)
				if results[index] == 0 {
					results[index] = address
				} else if results[index] != address {
					t.Errorf("TEB buffer changed from %#x to %#x", results[index], address)
				}
			}
		}()
	}
	group.Wait()

	if results[0] == 0 || results[1] == 0 || results[0] == results[1] {
		t.Fatalf("concurrent TEB buffers = %#x and %#x", results[0], results[1])
	}
}

func TestCRTTimeErrnoUsesProcessOwnedStorage(t *testing.T) {
	mem := mmu.New()
	state := &ntapi.ProcessState{PEBAddr: 0x70000000, TEBAddr: 0x71000000}
	ctx := &ntapi.TrapContext{Mem: mem, State: state}

	if !crtTimeWriteErrno(ctx, 22) {
		t.Fatal("write process-owned errno")
	}
	address := state.RuntimePointer("crt.errno", state.TEBAddr)
	value, err := mem.Read32(address)
	if address == 0 || err != nil || value != 22 {
		t.Fatalf("process errno address=%#x value=%d err=%v", address, value, err)
	}

	crtErrnoSlots.Lock()
	globalAddress := crtErrnoSlots.values[crtErrnoKey{mem: mem, teb: state.TEBAddr}]
	crtErrnoSlots.Unlock()
	if globalAddress != 0 {
		t.Fatalf("process errno leaked into global fallback at %#x", globalAddress)
	}
}

func TestCRTThreadRuntimeIsReleasedWithTEB(t *testing.T) {
	mem := mmu.New()
	state := &ntapi.ProcessState{PEBAddr: 0x70000000, TEBAddr: crtTimeTestTEB}
	cpu := x64.New(mem)
	cpu.SetGSBase(crtTimeTestTEB)
	ctx := &ntapi.TrapContext{CPU: cpu, Mem: mem, State: state}

	timeBuffer := crtTimeBuffer(ctx)
	if timeBuffer == 0 || !crtTimeWriteErrno(ctx, 22) {
		t.Fatal("initialize thread CRT runtime")
	}
	errnoAddress := state.RuntimePointer("crt.errno", crtTimeTestTEB)
	state.SwapRuntimePointer(crtInvalidThreadNamespace, crtTimeTestTEB, 0x12340000)

	crtReleaseThreadRuntime(mem, state, crtTimeTestTEB)

	if state.RuntimePointer("ucrt.gmtime", crtTimeTestTEB) != 0 ||
		state.RuntimePointer("crt.errno", crtTimeTestTEB) != 0 ||
		state.RuntimePointer(crtInvalidThreadNamespace, crtTimeTestTEB) != 0 {
		t.Fatal("thread CRT slots survived TEB cleanup")
	}
	if _, err := mem.Read8(timeBuffer); err == nil {
		t.Fatal("gmtime buffer remained mapped after TEB cleanup")
	}
	if _, err := mem.Read8(errnoAddress); err == nil {
		t.Fatal("errno buffer remained mapped after TEB cleanup")
	}
}

func TestCRTTimeThreadBufferAndNullContracts(t *testing.T) {
	for _, is32 := range []bool{true, false} {
		t.Run(fmt.Sprintf("PE%d", map[bool]int{true: 32, false: 64}[is32]), func(t *testing.T) {
			invocations, mem := newCRTTimeInvocations(t, []string{"_gmtime32", "_gmtime64"}, is32)
			epoch32 := crtTimeContractSeconds(mem, 32, 0)
			first, err := invocations["_gmtime32"].Call(epoch32)
			if err != nil || first == 0 {
				t.Fatalf("_gmtime32 result=%#x err=%v", first, err)
			}
			leap64 := crtTimeContractSeconds(mem, 64, 951827696)
			second, err := invocations["_gmtime64"].Call(leap64)
			got, readErr := mem.ReadBytes(second, crtTimeTMSize)
			want := crtTimeTestTM(56, 34, 12, 29, 1, 100, 2, 59, 0)
			if err != nil || readErr != nil || second != first || !bytes.Equal(got, want) {
				t.Fatalf("shared gmtime buffer first=%#x second=%#x output=%x callErr=%v readErr=%v", first, second, got, err, readErr)
			}

			crtWriteErrno(&ntapi.TrapContext{Mem: mem, State: &ntapi.ProcessState{TEBAddr: crtTimeTestTEB}}, 0x1234)
			result, err := invocations["_gmtime32"].Call(0)
			if err != nil || result != 0 || crtReadErrno(mem, crtTimeTestTEB) != crtTimeEINVAL ||
				invocations["_gmtime32"].calls[len(invocations["_gmtime32"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime32 null result=%#x errno=%d err=%v", result, crtReadErrno(mem, crtTimeTestTEB), err)
			}
			result, err = invocations["_gmtime64"].Call(0)
			if err != nil || result != 0 || crtReadErrno(mem, crtTimeTestTEB) != crtTimeEINVAL ||
				invocations["_gmtime64"].calls[len(invocations["_gmtime64"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime64 null result=%#x errno=%d err=%v", result, crtReadErrno(mem, crtTimeTestTEB), err)
			}

			negative32 := crtTimeContractSeconds(mem, 32, -1)
			result, err = invocations["_gmtime32"].Call(negative32)
			if err != nil || result != 0 ||
				invocations["_gmtime32"].calls[len(invocations["_gmtime32"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime32 negative result=%#x err=%v", result, err)
			}
			negative64 := crtTimeContractSeconds(mem, 64, -1)
			result, err = invocations["_gmtime64"].Call(negative64)
			if err != nil || result != 0 ||
				invocations["_gmtime64"].calls[len(invocations["_gmtime64"].calls)-1].abortCode != int(crtInvalidRuntimeStatus) {
				t.Fatalf("_gmtime64 negative result=%#x err=%v", result, err)
			}
		})
	}
}
