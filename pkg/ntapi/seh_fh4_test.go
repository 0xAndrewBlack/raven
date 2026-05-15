//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func encodeFH4Uint(value uint32) []byte {
	switch {
	case value < 1<<7:
		return []byte{byte(value << 1)}
	case value < 1<<14:
		return []byte{byte(value<<2) | 1, byte(value >> 6)}
	case value < 1<<21:
		return []byte{byte(value<<3) | 3, byte(value >> 5), byte(value >> 13)}
	default:
		return []byte{byte(value<<4) | 7, byte(value >> 4), byte(value >> 12), byte(value >> 20)}
	}
}

func appendFH4RVA(data []byte, value uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return append(data, raw[:]...)
}

func writeFH4Bytes(t *testing.T, mem *mmu.MMU, address uint64, data []byte) {
	t.Helper()
	if err := mem.WriteBytes(address, data); err != nil {
		t.Fatal(err)
	}
}

func TestFH4StateUsesDecodeUintMinusOne(t *testing.T) {
	mem := mmu.New()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	values := []uint32{0, 1, 12, 0x123, 0x12345}
	cursor := address
	for _, value := range values {
		encoded := encodeFH4Uint(value)
		writeFH4Bytes(t, mem, cursor, encoded)
		got, size := readFH4Int(mem, cursor)
		if got != int32(value)-1 {
			t.Fatalf("decode %d = %d, want %d", value, got, int32(value)-1)
		}
		if size != uint64(len(encoded)) {
			t.Fatalf("decode %d consumed %d bytes, want %d", value, size, len(encoded))
		}
		cursor += uint64(len(encoded))
	}
}

func TestFH4CatchEntryHeaders(t *testing.T) {
	mem := mmu.New()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)

	oneReturn := []byte{fh4CatchHasFlags | fh4CatchHasType | fh4CatchHasObject | fh4CatchOneReturn}
	oneReturn = append(oneReturn, encodeFH4Uint(cxxTypeFlagReference)...)
	oneReturn = appendFH4RVA(oneReturn, 0x2200)
	oneReturn = append(oneReturn, encodeFH4Uint(0x20)...)
	oneReturn = appendFH4RVA(oneReturn, 0x3300)
	oneReturn = append(oneReturn, encodeFH4Uint(0x40)...)
	oneReturn = append(oneReturn, 0)
	oneReturn = appendFH4RVA(oneReturn, 0x4400)
	writeFH4Bytes(t, mem, address, oneReturn)

	entries, err := parseFH4CatchEntries(mem, address, 2, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[0]; got.flags != cxxTypeFlagReference ||
		got.typeRVA != 0x2200 ||
		got.objectOffset != 0x20 ||
		got.handlerRVA != 0x3300 ||
		got.returnCount != 1 ||
		got.returnRVAs[0] != 0x1040 {
		t.Fatalf("one-return catch parsed as %#v", got)
	}
	if got := entries[1]; got.handlerRVA != 0x4400 || got.returnCount != 0 {
		t.Fatalf("following catch parsed as %#v", got)
	}

	twoReturns := []byte{fh4CatchSeparated | fh4CatchTwoReturns}
	twoReturns = appendFH4RVA(twoReturns, 0x5500)
	twoReturns = appendFH4RVA(twoReturns, 0x6600)
	twoReturns = appendFH4RVA(twoReturns, 0x7700)
	writeFH4Bytes(t, mem, address+0x100, twoReturns)
	entries, err = parseFH4CatchEntries(mem, address+0x100, 1, 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if got := entries[0]; got.handlerRVA != 0x5500 ||
		got.returnCount != 2 ||
		got.returnRVAs != [2]uint32{0x6600, 0x7700} {
		t.Fatalf("two-return catch parsed as %#v", got)
	}
}

func TestFH4TypedReferenceCatchUsesCatchableTypes(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		baseTypeRVA        = 0x1000
		derivedTypeRVA     = 0x1100
		throwInfoRVA       = 0x2000
		typeArrayRVA       = 0x2100
		derivedCatchRVA    = 0x2200
		baseCatchableRVA   = 0x2240
		exceptionObjectRVA = 0x5000
	)
	writeFH4Bytes(t, mem, imageBase+baseTypeRVA+16, append([]byte(".?AVBase@@"), 0))
	writeFH4Bytes(t, mem, imageBase+derivedTypeRVA+16, append([]byte(".?AVDerived@@"), 0))

	mem.Write32(imageBase+throwInfoRVA+12, typeArrayRVA)
	mem.Write32(imageBase+typeArrayRVA, 2)
	mem.Write32(imageBase+typeArrayRVA+4, derivedCatchRVA)
	mem.Write32(imageBase+typeArrayRVA+8, baseCatchableRVA)

	mem.Write32(imageBase+derivedCatchRVA+4, derivedTypeRVA)
	mem.Write32(imageBase+derivedCatchRVA+12, ^uint32(0))
	mem.Write32(imageBase+baseCatchableRVA+4, baseTypeRVA)
	mem.Write32(imageBase+baseCatchableRVA+8, 8)
	mem.Write32(imageBase+baseCatchableRVA+12, ^uint32(0))

	entry := fh4CatchEntry{
		flags:        cxxTypeFlagReference,
		typeRVA:      baseTypeRVA,
		objectOffset: 0x30,
	}
	exception := &CxxExceptionInfo{
		Object:    imageBase + exceptionObjectRVA,
		ThrowInfo: imageBase + throwInfoRVA,
		ImageBase: imageBase,
	}
	object, byReference, matched, err := fh4MatchTypedCatch(mem, imageBase, entry, exception)
	if err != nil {
		t.Fatal(err)
	}
	if !matched || !byReference || object != exception.Object+8 {
		t.Fatalf("typed catch object=%#x reference=%t matched=%t", object, byReference, matched)
	}

	frame := imageBase + 0x6000
	handler := &CxxCatchHandler{
		EstablisherRBP:   frame,
		CatchObjOffset:   entry.objectOffset,
		CatchObject:      object,
		CatchByReference: true,
	}
	if err := WriteCxxCatchObject(mem, handler, exception); err != nil {
		t.Fatal(err)
	}
	if got, _ := mem.Read64(frame + uint64(entry.objectOffset)); got != exception.Object+8 {
		t.Fatalf("reference catch slot = %#x", got)
	}

	handler.CatchObjOffset = 0
	handler.HasCatchObject = true
	if err := WriteCxxCatchObject(mem, handler, exception); err != nil {
		t.Fatal(err)
	}
	if got, _ := mem.Read64(frame); got != exception.Object+8 {
		t.Fatalf("zero-offset reference catch slot = %#x", got)
	}

	catchAll := fh4CatchEntry{}
	if _, _, matched, err := fh4MatchTypedCatch(mem, imageBase, catchAll, nil); err != nil || !matched {
		t.Fatalf("catch-all matched=%t err=%v", matched, err)
	}
}

func TestFH4ReferenceOnlyCatchableRequiresReferenceCatch(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		typeRVA       = 0x1000
		throwInfoRVA  = 0x2000
		typeArrayRVA  = 0x2100
		catchableRVA  = 0x2200
		objectRVA     = 0x5000
		referenceOnly = 0x02
	)
	writeFH4Bytes(t, mem, imageBase+typeRVA+16, append([]byte(".?AVReferenceOnly@@"), 0))
	mem.Write32(imageBase+throwInfoRVA+12, typeArrayRVA)
	mem.Write32(imageBase+typeArrayRVA, 1)
	mem.Write32(imageBase+typeArrayRVA+4, catchableRVA)
	mem.Write32(imageBase+catchableRVA, referenceOnly)
	mem.Write32(imageBase+catchableRVA+4, typeRVA)
	mem.Write32(imageBase+catchableRVA+12, ^uint32(0))
	mem.Write32(imageBase+catchableRVA+20, 16)

	exception := &CxxExceptionInfo{
		Object:    imageBase + objectRVA,
		ThrowInfo: imageBase + throwInfoRVA,
		ImageBase: imageBase,
	}
	byValue, err := fh4MatchTypedCatchInfo(mem, imageBase, fh4CatchEntry{typeRVA: typeRVA}, exception)
	if err != nil {
		t.Fatal(err)
	}
	if byValue.matched {
		t.Fatalf("reference-only catchable matched by-value catch: %#v", byValue)
	}

	byReference, err := fh4MatchTypedCatchInfo(mem, imageBase, fh4CatchEntry{
		flags:   cxxTypeFlagReference,
		typeRVA: typeRVA,
	}, exception)
	if err != nil {
		t.Fatal(err)
	}
	if !byReference.matched || !byReference.byReference || byReference.object != exception.Object {
		t.Fatalf("reference catch match = %#v", byReference)
	}
}

func TestFH4TypedByValueCatchUsesMetadata(t *testing.T) {
	tests := []struct {
		name       string
		properties uint32
		size       uint32
		copyRVA    uint32
	}{
		{name: "raw copy", size: 12},
		{name: "virtual-base copy constructor", properties: CxxCatchableVirtualBase, size: 16, copyRVA: 0x3400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := mmu.New()
			imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
			const (
				typeRVA      = 0x1000
				throwInfoRVA = 0x2000
				typeArrayRVA = 0x2100
				catchableRVA = 0x2200
				objectRVA    = 0x5000
				frameRVA     = 0x6000
			)
			writeFH4Bytes(t, mem, imageBase+typeRVA+16, append([]byte(".?AVValue@@"), 0))
			mem.Write32(imageBase+throwInfoRVA+12, typeArrayRVA)
			mem.Write32(imageBase+typeArrayRVA, 1)
			mem.Write32(imageBase+typeArrayRVA+4, catchableRVA)
			mem.Write32(imageBase+catchableRVA, tt.properties)
			mem.Write32(imageBase+catchableRVA+4, typeRVA)
			mem.Write32(imageBase+catchableRVA+8, 4)
			mem.Write32(imageBase+catchableRVA+12, ^uint32(0))
			mem.Write32(imageBase+catchableRVA+16, 0)
			mem.Write32(imageBase+catchableRVA+20, tt.size)
			mem.Write32(imageBase+catchableRVA+24, tt.copyRVA)

			object := imageBase + objectRVA
			source := object + 4
			writeFH4Bytes(t, mem, source, []byte("abcdefghijklmnop"))
			exception := &CxxExceptionInfo{
				Object:    object,
				ThrowInfo: imageBase + throwInfoRVA,
				ImageBase: imageBase,
			}
			match, err := fh4MatchTypedCatchInfo(mem, imageBase, fh4CatchEntry{
				typeRVA: typeRVA,
			}, exception)
			if err != nil {
				t.Fatal(err)
			}
			if !match.matched || match.byReference || match.size != tt.size ||
				match.copyRVA != tt.copyRVA || match.object != source {
				t.Fatalf("by-value metadata = %#v", match)
			}

			handler := &CxxCatchHandler{
				EstablisherRBP:  imageBase + frameRVA,
				CatchObjOffset:  0x40,
				HasCatchObject:  true,
				CatchObject:     match.object,
				CatchObjectSize: match.size,
				CatchCopyRVA:    match.copyRVA,
				CatchProperties: match.properties,
				ThrowImageBase:  match.throwBase,
			}
			copyCalls := 0
			err = MaterializeCxxCatchObject(mem, handler, exception, func(address uint64, args []uint64) (uint64, error) {
				copyCalls++
				if address != imageBase+uint64(tt.copyRVA) ||
					!reflect.DeepEqual(args, []uint64{handler.EstablisherRBP + 0x40, source, 1}) {
					t.Fatalf("copy constructor call address=%#x args=%#v", address, args)
				}
				return 0, mem.WriteBytes(args[0], []byte("constructed-value"))
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := mem.ReadBytes(handler.EstablisherRBP+0x40, int(tt.size))
			if err != nil {
				t.Fatal(err)
			}
			if tt.copyRVA == 0 {
				if copyCalls != 0 || string(got) != "abcdefghijkl" {
					t.Fatalf("raw catch copy calls=%d data=%q", copyCalls, got)
				}
			} else if copyCalls != 1 || string(got) != "constructed-valu" {
				t.Fatalf("constructed catch calls=%d data=%q", copyCalls, got)
			}
		})
	}
}

func TestFH4UnwindActionsFollowPredecessors(t *testing.T) {
	mem := mmu.New()
	address := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	data := make([]byte, 0, 17)
	data = append(data, encodeFH4Uint((1<<2)|uint32(CxxUnwindDestructorObject))...)
	data = appendFH4RVA(data, 0x1010)
	data = append(data, encodeFH4Uint(0x20)...)
	data = append(data, encodeFH4Uint((6<<2)|uint32(CxxUnwindDestructorPointer))...)
	data = appendFH4RVA(data, 0x2020)
	data = append(data, encodeFH4Uint(0x30)...)
	data = append(data, encodeFH4Uint((6<<2)|uint32(CxxUnwindFrame))...)
	data = appendFH4RVA(data, 0x3030)
	writeFH4Bytes(t, mem, address, data)

	frame := address + 0x400
	pointedObject := address + 0x700
	mem.Write64(frame+0x30, pointedObject)
	info := &fh4FunctionInfo{unwindCount: 3, unwindData: address}
	actions, err := fh4PlanUnwindActions(mem, info, 2, -1, frame, false)
	if err != nil {
		t.Fatal(err)
	}
	var handlers []uint32
	var objects []uint64
	for _, action := range actions {
		handlers = append(handlers, action.HandlerRVA)
		object, gotFrame, err := action.Arguments(mem)
		if err != nil {
			t.Fatal(err)
		}
		if gotFrame != frame {
			t.Fatalf("action frame = %#x, want %#x", gotFrame, frame)
		}
		objects = append(objects, object)
	}
	if !reflect.DeepEqual(handlers, []uint32{0x3030, 0x2020, 0x1010}) {
		t.Fatalf("handler order = %#v", handlers)
	}
	if !reflect.DeepEqual(objects, []uint64{frame, pointedObject, frame + 0x20}) {
		t.Fatalf("action objects = %#v", objects)
	}
}

func writeFH4FunctionFixture(t *testing.T, mem *mmu.MMU, imageBase uint64,
	functionInfoRVA, unwindMapRVA, tryMapRVA, catchMapRVA, ipMapRVA uint32,
	typeRVA, handlerRVA uint32) {

	t.Helper()
	header := byte(fh4FuncHasTry)
	functionInfo := []byte{header}
	if unwindMapRVA != 0 {
		functionInfo[0] |= fh4FuncHasUnwind
		functionInfo = appendFH4RVA(functionInfo, unwindMapRVA)
	}
	functionInfo = appendFH4RVA(functionInfo, tryMapRVA)
	functionInfo = appendFH4RVA(functionInfo, ipMapRVA)
	writeFH4Bytes(t, mem, imageBase+uint64(functionInfoRVA), functionInfo)

	tryMap := encodeFH4Uint(1)
	tryMap = append(tryMap, encodeFH4Uint(0)...)
	tryMap = append(tryMap, encodeFH4Uint(0)...)
	tryMap = append(tryMap, encodeFH4Uint(0)...)
	tryMap = appendFH4RVA(tryMap, catchMapRVA)
	writeFH4Bytes(t, mem, imageBase+uint64(tryMapRVA), tryMap)

	catchMap := encodeFH4Uint(1)
	if typeRVA != 0 {
		catchMap = append(catchMap, fh4CatchHasType)
		catchMap = appendFH4RVA(catchMap, typeRVA)
	} else {
		catchMap = append(catchMap, 0)
	}
	catchMap = appendFH4RVA(catchMap, handlerRVA)
	writeFH4Bytes(t, mem, imageBase+uint64(catchMapRVA), catchMap)

	ipMap := encodeFH4Uint(1)
	ipMap = append(ipMap, encodeFH4Uint(0)...)
	ipMap = append(ipMap, encodeFH4Uint(1)...)
	writeFH4Bytes(t, mem, imageBase+uint64(ipMapRVA), ipMap)
}

func writeEHUnwindInfo(t *testing.T, mem *mmu.MMU, imageBase uint64,
	unwindRVA, languageHandlerRVA, functionInfoRVA uint32, flags uint8) {

	t.Helper()
	address := imageBase + uint64(unwindRVA)
	mem.Write8(address, 1|(flags<<3))
	mem.Write8(address+1, 0)
	mem.Write8(address+2, 0)
	mem.Write8(address+3, 0)
	mem.Write32(address+4, languageHandlerRVA)
	mem.Write32(address+8, functionInfoRVA)
}

func writePushEHUnwindInfo(mem *mmu.MMU, imageBase uint64,
	unwindRVA, languageHandlerRVA, functionInfoRVA uint32, register uint8) {

	address := imageBase + uint64(unwindRVA)
	writeUnwindCodeHeader(mem, address, UnwFlagEHandler, 1, 1, 0)
	mem.Write8(address+4, 1)
	mem.Write8(address+5, register<<4)
	mem.Write32(address+8, languageHandlerRVA)
	mem.Write32(address+12, functionInfoRVA)
}

func writeSetFPEHUnwindInfo(mem *mmu.MMU, imageBase uint64,
	unwindRVA, languageHandlerRVA, functionInfoRVA uint32, frameOffset uint8) {

	address := imageBase + uint64(unwindRVA)
	writeUnwindCodeHeader(mem, address, UnwFlagEHandler, 6, 3, (frameOffset<<4)|regRBP)
	mem.Write8(address+4, 6)
	mem.Write8(address+5, 3)
	mem.Write8(address+6, 3)
	mem.Write8(address+7, (3<<4)|2)
	mem.Write8(address+8, 1)
	mem.Write8(address+9, regRBP<<4)
	mem.Write16(address+10, 0)
	mem.Write32(address+12, languageHandlerRVA)
	mem.Write32(address+16, functionInfoRVA)
}

func TestFH4DispatchContinuesToOuterFrame(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x20000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin      = 0x1000
		outerBegin      = 0x1100
		innerUnwind     = 0x3000
		outerUnwind     = 0x3040
		innerFunction   = 0x4000
		outerFunction   = 0x4040
		innerUnwindMap  = 0x4100
		innerTryMap     = 0x4200
		innerCatchMap   = 0x4300
		innerIPMap      = 0x4400
		outerTryMap     = 0x4500
		outerCatchMap   = 0x4600
		outerIPMap      = 0x4700
		missingType     = 0x4800
		innerDestructor = 0x5100
		outerCatch      = 0x5200
		languageHandler = 0x6000
	)
	writeEHUnwindInfo(t, mem, imageBase, innerUnwind, languageHandler, innerFunction, UnwFlagEHandler)
	writeEHUnwindInfo(t, mem, imageBase, outerUnwind, languageHandler, outerFunction, UnwFlagEHandler)
	writeFH4FunctionFixture(t, mem, imageBase, innerFunction, innerUnwindMap, innerTryMap, innerCatchMap, innerIPMap, missingType, 0x5000)
	writeFH4FunctionFixture(t, mem, imageBase, outerFunction, 0, outerTryMap, outerCatchMap, outerIPMap, 0, outerCatch)

	unwindMap := encodeFH4Uint(1)
	unwindMap = append(unwindMap, encodeFH4Uint((1<<2)|uint32(CxxUnwindFrame))...)
	unwindMap = appendFH4RVA(unwindMap, innerDestructor)
	writeFH4Bytes(t, mem, imageBase+innerUnwindMap, unwindMap)

	stack := imageBase + 0x18000
	mem.Write64(stack, imageBase+outerBegin+0x10)
	mem.Write64(stack+8, 0)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind},
			{BeginAddress: outerBegin, EndAddress: outerBegin + 0x100, UnwindData: outerUnwind},
		},
	}
	handler := CxxDispatchException(mem, table, stack, imageBase+innerBegin+0x10, nil, false)
	if handler == nil {
		t.Fatal("outer catch was not found")
	}
	if handler.FuncletRVA != outerCatch || handler.EstablisherRBP != stack+8 || handler.BodyRSP != stack+8 {
		t.Fatalf("outer handler = %#v", handler)
	}
	if len(handler.UnwindActions) != 1 || handler.UnwindActions[0].HandlerRVA != innerDestructor {
		t.Fatalf("outer unwind actions = %#v", handler.UnwindActions)
	}
}

func TestFH4SetFPRegUsesEstablisherForCatchObject(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x20000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin      = 0x1000
		targetBegin     = 0x1100
		innerUnwind     = 0x3000
		targetUnwind    = 0x3040
		innerFunction   = 0x4000
		targetFunction  = 0x4040
		innerTryMap     = 0x4200
		innerCatchMap   = 0x4300
		innerIPMap      = 0x4400
		targetTryMap    = 0x4500
		targetCatchMap  = 0x4600
		targetIPMap     = 0x4700
		missingType     = 0x4800
		targetCatch     = 0x5200
		languageHandler = 0x6000
	)
	writePushEHUnwindInfo(mem, imageBase, innerUnwind, languageHandler, innerFunction, regRBP)
	writeSetFPEHUnwindInfo(mem, imageBase, targetUnwind, languageHandler, targetFunction, 2)
	writeFH4FunctionFixture(t, mem, imageBase, innerFunction, 0, innerTryMap, innerCatchMap, innerIPMap, missingType, 0x5100)
	writeFH4FunctionFixture(t, mem, imageBase, targetFunction, 0, targetTryMap, targetCatchMap, targetIPMap, 0, targetCatch)

	stack := imageBase + 0x18000
	dynamicRSP := stack + 16
	establisher := dynamicRSP + 0x80
	framePointer := establisher + 0x20
	mem.Write64(stack, framePointer)
	mem.Write64(stack+8, imageBase+targetBegin+0x10)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind},
			{BeginAddress: targetBegin, EndAddress: targetBegin + 0x100, UnwindData: targetUnwind},
		},
	}
	handler := CxxDispatchException(mem, table, stack, imageBase+innerBegin+0x10, nil, false)
	if handler == nil {
		t.Fatal("frame-pointer catch was not found")
	}
	if handler.FuncletRVA != targetCatch ||
		handler.EstablisherRBP != establisher ||
		handler.BodyRSP != dynamicRSP {
		t.Fatalf("frame-pointer handler = %#v", handler)
	}

	object := imageBase + 0x17000
	handler.HasCatchObject = true
	handler.CatchByReference = true
	handler.CatchObject = object
	handler.CatchObjOffset = 0x30
	if err := WriteCxxCatchObject(mem, handler, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := mem.Read64(establisher + 0x30); got != object {
		t.Fatalf("catch object = %#x at establisher, want %#x", got, object)
	}
	if got, _ := mem.Read64(dynamicRSP + 0x30); got != 0 {
		t.Fatalf("catch object written relative to dynamic RSP: %#x", got)
	}
}

func TestFH4SetFPRegUnwindsToOuterFrame(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x20000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin      = 0x1000
		allocaBegin     = 0x1100
		outerBegin      = 0x1200
		innerUnwind     = 0x3000
		allocaUnwind    = 0x3040
		outerUnwind     = 0x3080
		innerFunction   = 0x4000
		allocaFunction  = 0x4040
		outerFunction   = 0x4080
		innerTryMap     = 0x4200
		innerCatchMap   = 0x4300
		innerIPMap      = 0x4400
		allocaTryMap    = 0x4500
		allocaCatchMap  = 0x4600
		allocaIPMap     = 0x4700
		outerTryMap     = 0x4800
		outerCatchMap   = 0x4900
		outerIPMap      = 0x4a00
		missingType     = 0x4b00
		outerCatch      = 0x5200
		languageHandler = 0x6000
	)
	writePushEHUnwindInfo(mem, imageBase, innerUnwind, languageHandler, innerFunction, regRBP)
	writeSetFPEHUnwindInfo(mem, imageBase, allocaUnwind, languageHandler, allocaFunction, 2)
	writeEHUnwindInfo(t, mem, imageBase, outerUnwind, languageHandler, outerFunction, UnwFlagEHandler)
	writeFH4FunctionFixture(t, mem, imageBase, innerFunction, 0, innerTryMap, innerCatchMap, innerIPMap, missingType, 0x5000)
	writeFH4FunctionFixture(t, mem, imageBase, allocaFunction, 0, allocaTryMap, allocaCatchMap, allocaIPMap, missingType, 0x5100)
	writeFH4FunctionFixture(t, mem, imageBase, outerFunction, 0, outerTryMap, outerCatchMap, outerIPMap, 0, outerCatch)

	stack := imageBase + 0x18000
	dynamicRSP := stack + 16
	establisher := dynamicRSP + 0x80
	framePointer := establisher + 0x20
	outerRSP := establisher + 0x30
	mem.Write64(stack, framePointer)
	mem.Write64(stack+8, imageBase+allocaBegin+0x10)
	mem.Write64(establisher+0x20, 0x1111222233334444)
	mem.Write64(establisher+0x28, imageBase+outerBegin+0x10)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind},
			{BeginAddress: allocaBegin, EndAddress: allocaBegin + 0x100, UnwindData: allocaUnwind},
			{BeginAddress: outerBegin, EndAddress: outerBegin + 0x100, UnwindData: outerUnwind},
		},
	}
	handler := CxxDispatchException(mem, table, stack, imageBase+innerBegin+0x10, nil, false)
	if handler == nil {
		t.Fatal("outer catch after alloca frame was not found")
	}
	if handler.FuncletRVA != outerCatch ||
		handler.EstablisherRBP != outerRSP ||
		handler.BodyRSP != outerRSP {
		t.Fatalf("outer handler = %#v", handler)
	}
}

func TestFH4TargetFrameDoesNotRestoreParentRegisters(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x20000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin     = 0x1000
		outerBegin     = 0x1100
		innerUnwind    = 0x3000
		outerUnwind    = 0x3040
		innerFunction  = 0x4000
		outerFunction  = 0x4040
		innerTryMap    = 0x4200
		innerCatchMap  = 0x4300
		innerIPMap     = 0x4400
		outerTryMap    = 0x4500
		outerCatchMap  = 0x4600
		outerIPMap     = 0x4700
		missingType    = 0x4800
		outerCatch     = 0x5200
		languageHandle = 0x6000
	)
	writePushEHUnwindInfo(mem, imageBase, innerUnwind, languageHandle, innerFunction, regRBP)
	writePushEHUnwindInfo(mem, imageBase, outerUnwind, languageHandle, outerFunction, regRBX)
	writeFH4FunctionFixture(t, mem, imageBase, innerFunction, 0, innerTryMap, innerCatchMap, innerIPMap, missingType, 0x5100)
	writeFH4FunctionFixture(t, mem, imageBase, outerFunction, 0, outerTryMap, outerCatchMap, outerIPMap, 0, outerCatch)

	stack := imageBase + 0x18000
	mem.Write64(stack, 0x1111222233334444)
	mem.Write64(stack+8, imageBase+outerBegin+0x10)
	mem.Write64(stack+16, 0xAAAABBBBCCCCDDDD)
	mem.Write64(stack+24, 0)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind},
			{BeginAddress: outerBegin, EndAddress: outerBegin + 0x100, UnwindData: outerUnwind},
		},
	}
	handler := CxxDispatchException(mem, table, stack, imageBase+innerBegin+0x10, nil, false)
	if handler == nil {
		t.Fatal("outer catch was not found")
	}
	if got := handler.SavedRegs[regRBP]; got != 0x1111222233334444 {
		t.Fatalf("inner frame RBP restore = %#x", got)
	}
	if got, exists := handler.SavedRegs[regRBX]; exists {
		t.Fatalf("target frame parent RBX leaked into catch context: %#x", got)
	}
	if handler.BodyRSP != stack+16 {
		t.Fatalf("target body RSP = %#x, want %#x", handler.BodyRSP, stack+16)
	}
}

func TestFH4DispatchCrossesModuleExceptionTables(t *testing.T) {
	mem := mmu.New()
	innerBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	outerBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin      = 0x1000
		outerBegin      = 0x1200
		innerUnwind     = 0x3000
		outerUnwind     = 0x3040
		innerFunction   = 0x4000
		outerFunction   = 0x4040
		innerUnwindMap  = 0x4100
		innerTryMap     = 0x4200
		innerCatchMap   = 0x4300
		innerIPMap      = 0x4400
		outerTryMap     = 0x4500
		outerCatchMap   = 0x4600
		outerIPMap      = 0x4700
		missingType     = 0x4800
		innerDestructor = 0x5100
		outerCatch      = 0x5200
		languageHandler = 0x6000
	)
	writeEHUnwindInfo(t, mem, innerBase, innerUnwind, languageHandler, innerFunction, UnwFlagEHandler)
	writeEHUnwindInfo(t, mem, outerBase, outerUnwind, languageHandler, outerFunction, UnwFlagEHandler)
	writeFH4FunctionFixture(t, mem, innerBase, innerFunction, innerUnwindMap, innerTryMap, innerCatchMap, innerIPMap, missingType, 0x5000)
	writeFH4FunctionFixture(t, mem, outerBase, outerFunction, 0, outerTryMap, outerCatchMap, outerIPMap, 0, outerCatch)
	unwindMap := encodeFH4Uint(1)
	unwindMap = append(unwindMap, encodeFH4Uint((1<<2)|uint32(CxxUnwindFrame))...)
	unwindMap = appendFH4RVA(unwindMap, innerDestructor)
	writeFH4Bytes(t, mem, innerBase+innerUnwindMap, unwindMap)

	innerTable := &ExceptionTable{
		ImageBase: innerBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind},
		},
	}
	outerTable := &ExceptionTable{
		ImageBase: outerBase,
		Entries: []RuntimeFunction{
			{BeginAddress: outerBegin, EndAddress: outerBegin + 0x100, UnwindData: outerUnwind},
		},
	}
	sehFunctionTableMu.Lock()
	oldStatic := staticFunctionTables
	oldDynamic := dynamicFunctionTables
	staticFunctionTables = nil
	dynamicFunctionTables = nil
	sehFunctionTableMu.Unlock()
	t.Cleanup(func() {
		sehFunctionTableMu.Lock()
		staticFunctionTables = oldStatic
		dynamicFunctionTables = oldDynamic
		sehFunctionTableMu.Unlock()
	})
	RegisterExceptionTable(outerBase, 0x10000, outerTable)

	stack := innerBase + 0x8000
	mem.Write64(stack, outerBase+outerBegin+0x10)
	mem.Write64(stack+8, 0)
	handler := CxxDispatchException(mem, innerTable, stack, innerBase+innerBegin+0x10, nil, false)
	if handler == nil {
		t.Fatal("cross-module outer catch was not found")
	}
	if handler.ImageBase != outerBase || handler.FuncletRVA != outerCatch {
		t.Fatalf("cross-module handler = %#v", handler)
	}
	if len(handler.UnwindActions) != 1 ||
		handler.UnwindActions[0].ImageBase != innerBase ||
		handler.UnwindActions[0].HandlerRVA != innerDestructor {
		t.Fatalf("cross-module unwind actions = %#v", handler.UnwindActions)
	}
}

func TestUnwindStackCallsHandlersThroughTargetFrame(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin   = 0x1000
		outerBegin   = 0x1100
		innerUnwind  = 0x3000
		outerUnwind  = 0x3040
		innerHandler = 0x5000
		outerHandler = 0x5010
	)
	writeEHUnwindInfo(t, mem, imageBase, innerUnwind, innerHandler, 0, UnwFlagUHandler)
	writeEHUnwindInfo(t, mem, imageBase, outerUnwind, outerHandler, 0, UnwFlagUHandler)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind, EntryAddr: imageBase + 0x200},
			{BeginAddress: outerBegin, EndAddress: outerBegin + 0x100, UnwindData: outerUnwind, EntryAddr: imageBase + 0x20c},
		},
	}

	sehFunctionTableMu.Lock()
	oldStatic := staticFunctionTables
	oldDynamic := dynamicFunctionTables
	staticFunctionTables = nil
	dynamicFunctionTables = nil
	sehFunctionTableMu.Unlock()
	t.Cleanup(func() {
		sehFunctionTableMu.Lock()
		staticFunctionTables = oldStatic
		dynamicFunctionTables = oldDynamic
		sehFunctionTableMu.Unlock()
	})
	RegisterExceptionTable(imageBase, 0x10000, table)

	stack := imageBase + 0x8000
	mem.Write64(stack, imageBase+outerBegin+0x10)
	mem.Write64(stack+8, 0)
	contextAddress := imageBase + 0x7000
	exceptionAddress := imageBase + 0x7400
	context := &AMD64Context{Rip: imageBase + innerBegin + 0x10}
	context.Regs[regRSP] = stack
	if err := WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	mem.Write32(exceptionAddress, 0xc0000027)

	var calls []uint64
	var callFlags []uint32
	guestCall := func(address uint64, args []uint64) (uint64, error) {
		calls = append(calls, address)
		flags, _ := mem.Read32(args[0] + 4)
		callFlags = append(callFlags, flags)
		dispatch, err := ReadDispatcherContext(mem, args[3])
		if err != nil {
			return 0, err
		}
		if dispatch.EstablisherFrame != args[1] || dispatch.TargetIp != imageBase+0x9000 {
			t.Fatalf("dispatcher context = %#v", dispatch)
		}
		handlerContext, err := ReadAMD64Context(mem, args[2])
		if err != nil {
			return 0, err
		}
		if address == imageBase+innerHandler {
			if handlerContext.Rip != imageBase+outerBegin+0x10 || handlerContext.Regs[regRSP] != stack+8 {
				t.Fatalf("inner unwind handler context = %#v", handlerContext)
			}
		} else if handlerContext.Rip != 0 || handlerContext.Regs[regRSP] != stack+16 {
			t.Fatalf("target unwind handler context = %#v", handlerContext)
		}
		return ExceptionDispositionContinueSearch, nil
	}
	if err := UnwindStack(
		mem,
		exceptionAddress,
		contextAddress,
		stack+8,
		imageBase+0x9000,
		0x1234,
		0,
		guestCall,
		false,
	); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []uint64{imageBase + innerHandler, imageBase + outerHandler}) {
		t.Fatalf("unwind handler calls = %#v", calls)
	}
	if callFlags[0]&ExceptionFlagTargetUnwind != 0 || callFlags[1]&ExceptionFlagTargetUnwind == 0 {
		t.Fatalf("unwind flags = %#v", callFlags)
	}
	result, err := ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rip != imageBase+0x9000 || result.Regs[regRSP] != stack+8 || result.Regs[regRAX] != 0x1234 {
		t.Fatalf("target context = %#v", result)
	}
}

func TestUnwindStackConsolidatesAfterIntermediateHandlers(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		innerBegin    = 0x1000
		targetBegin   = 0x1100
		innerUnwind   = 0x3000
		targetUnwind  = 0x3040
		innerHandler  = 0x5000
		targetHandler = 0x5010
		callback      = 0x6000
		continuation  = 0x7000
	)
	writeEHUnwindInfo(t, mem, imageBase, innerUnwind, innerHandler, 0, UnwFlagUHandler)
	writeEHUnwindInfo(t, mem, imageBase, targetUnwind, targetHandler, 0, UnwFlagUHandler)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{BeginAddress: innerBegin, EndAddress: innerBegin + 0x100, UnwindData: innerUnwind, EntryAddr: imageBase + 0x200},
			{BeginAddress: targetBegin, EndAddress: targetBegin + 0x100, UnwindData: targetUnwind, EntryAddr: imageBase + 0x20c},
		},
	}
	sehFunctionTableMu.Lock()
	oldStatic := staticFunctionTables
	oldDynamic := dynamicFunctionTables
	staticFunctionTables = nil
	dynamicFunctionTables = nil
	sehFunctionTableMu.Unlock()
	t.Cleanup(func() {
		sehFunctionTableMu.Lock()
		staticFunctionTables = oldStatic
		dynamicFunctionTables = oldDynamic
		sehFunctionTableMu.Unlock()
	})
	RegisterExceptionTable(imageBase, 0x10000, table)

	stack := imageBase + 0x8000
	mem.Write64(stack, imageBase+targetBegin+0x10)
	mem.Write64(stack+8, 0)
	contextAddress := imageBase + 0x7400
	exceptionAddress := imageBase + 0x7800
	context := &AMD64Context{Rip: imageBase + innerBegin + 0x10}
	context.Regs[regRSP] = stack
	context.XMM[6] = [2]uint64{1, 2}
	if err := WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	mem.Write32(exceptionAddress, StatusUnwindConsolidate)
	mem.Write32(exceptionAddress+0x18, 1)
	mem.Write64(exceptionAddress+0x20, imageBase+callback)

	var calls []uint64
	guestCall := func(address uint64, args []uint64) (uint64, error) {
		calls = append(calls, address)
		if address == imageBase+callback {
			if !reflect.DeepEqual(calls, []uint64{
				imageBase + innerHandler,
				imageBase + targetHandler,
				imageBase + callback,
			}) {
				t.Fatalf("phase-two order = %#v", calls)
			}
			if len(args) != 1 || args[0] != exceptionAddress {
				t.Fatalf("consolidation arguments = %#v", args)
			}
			refreshed, err := ReadAMD64Context(mem, contextAddress)
			if err != nil {
				return 0, err
			}
			refreshed.XMM[6] = [2]uint64{3, 4}
			if err := WriteAMD64Context(mem, contextAddress, refreshed); err != nil {
				return 0, err
			}
			return imageBase + continuation, nil
		}
		return ExceptionDispositionContinueSearch, nil
	}
	if err := UnwindStack(
		mem,
		exceptionAddress,
		contextAddress,
		stack+8,
		imageBase+0xdead,
		0x1234,
		0,
		guestCall,
		false,
	); err != nil {
		t.Fatal(err)
	}
	result, err := ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rip != imageBase+continuation || result.Rip == imageBase+0xdead ||
		result.XMM[6] != [2]uint64{3, 4} {
		t.Fatalf("consolidated context = %#v", result)
	}
}

func TestUnwindStackRejectsMissingTarget(t *testing.T) {
	mem := mmu.New()
	stack := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	contextAddress := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	exceptionAddress := mem.Mmap(0, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	mem.Write64(stack, 0)
	context := &AMD64Context{Rip: 0x7fff00001000}
	context.Regs[regRSP] = stack
	if err := WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	mem.Write32(exceptionAddress, 0xc0000027)

	err := UnwindStack(
		mem,
		exceptionAddress,
		contextAddress,
		stack+0x80,
		0x7fff00002000,
		0,
		0,
		nil,
		false,
	)
	if err == nil {
		t.Fatal("missing target frame was accepted")
	}
	var unwindErr *UnwindError
	if !errors.As(err, &unwindErr) || unwindErr.Status != StatusInvalidUnwindTarget {
		t.Fatalf("missing target error = %v", err)
	}
}

func TestUnwindStackContinuesAfterCollidedUnwind(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		functionBegin = 0x1000
		unwindRVA     = 0x3000
		handlerRVA    = 0x5000
	)
	writeEHUnwindInfo(t, mem, imageBase, unwindRVA, handlerRVA, 0, UnwFlagUHandler)
	table := &ExceptionTable{
		ImageBase: imageBase,
		Entries: []RuntimeFunction{
			{
				BeginAddress: functionBegin,
				EndAddress:   functionBegin + 0x100,
				UnwindData:   unwindRVA,
				EntryAddr:    imageBase + 0x200,
			},
		},
	}
	mem.Write32(imageBase+0x200, functionBegin)
	mem.Write32(imageBase+0x204, functionBegin+0x100)
	mem.Write32(imageBase+0x208, unwindRVA)

	sehFunctionTableMu.Lock()
	oldStatic := staticFunctionTables
	oldDynamic := dynamicFunctionTables
	staticFunctionTables = nil
	dynamicFunctionTables = nil
	sehFunctionTableMu.Unlock()
	t.Cleanup(func() {
		sehFunctionTableMu.Lock()
		staticFunctionTables = oldStatic
		dynamicFunctionTables = oldDynamic
		sehFunctionTableMu.Unlock()
	})
	RegisterExceptionTable(imageBase, 0x10000, table)

	stack := imageBase + 0x8000
	mem.Write64(stack, imageBase+functionBegin+0x20)
	mem.Write64(stack+8, 0)
	contextAddress := imageBase + 0x7000
	exceptionAddress := imageBase + 0x7400
	context := &AMD64Context{Rip: imageBase + functionBegin + 0x10}
	context.Regs[regRSP] = stack
	if err := WriteAMD64Context(mem, contextAddress, context); err != nil {
		t.Fatal(err)
	}
	mem.Write32(exceptionAddress, 0xc0000027)

	calls := 0
	guestCall := func(address uint64, args []uint64) (uint64, error) {
		calls++
		if address != imageBase+handlerRVA {
			t.Fatalf("collided handler address = %#x", address)
		}
		return ExceptionDispositionCollidedUnwind, nil
	}
	err := UnwindStack(
		mem,
		exceptionAddress,
		contextAddress,
		0,
		imageBase+0x6000,
		0x55,
		0,
		guestCall,
		false,
	)
	var unwindErr *UnwindError
	if !errors.As(err, &unwindErr) || unwindErr.Status != StatusBadStack {
		t.Fatalf("exit unwind error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("collided handler calls = %d, want 1", calls)
	}
	flags, _ := mem.Read32(exceptionAddress + 4)
	if flags&ExceptionFlagCollidedUnwind == 0 {
		t.Fatalf("collided unwind flag was not retained: %#x", flags)
	}
	result, err := ReadAMD64Context(mem, contextAddress)
	if err != nil {
		t.Fatal(err)
	}
	if result.Rip == imageBase+0x6000 || result.Regs[regRAX] == 0x55 {
		t.Fatalf("collided unwind result = %#v", result)
	}
}

func TestVirtualUnwindRestoresNonvolatileXMM(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		functionRVA = 0x1000
		unwindRVA   = 0x3000
	)
	writeUnwindCodeHeader(mem, imageBase+unwindRVA, 0, 1, 5, 0)
	mem.Write8(imageBase+unwindRVA+4, 1)
	mem.Write8(imageBase+unwindRVA+5, (6<<4)|8)
	mem.Write16(imageBase+unwindRVA+6, 2)
	mem.Write8(imageBase+unwindRVA+8, 1)
	mem.Write8(imageBase+unwindRVA+9, (15<<4)|9)
	mem.Write16(imageBase+unwindRVA+10, 0x80)
	mem.Write16(imageBase+unwindRVA+12, 0)
	function := &RuntimeFunction{
		BeginAddress: functionRVA,
		EndAddress:   functionRVA + 0x100,
		UnwindData:   unwindRVA,
	}

	stack := imageBase + 0x8000
	mem.Write64(stack, imageBase+0x5000)
	want6 := [2]uint64{0x1111222233334444, 0x5555666677778888}
	want15 := [2]uint64{0x9999aaaabbbbcccc, 0xddddeeeeffff0000}
	mem.Write64(stack+0x20, want6[0])
	mem.Write64(stack+0x28, want6[1])
	mem.Write64(stack+0x80, want15[0])
	mem.Write64(stack+0x88, want15[1])
	context := &AMD64Context{Rip: imageBase + functionRVA + 0x10}
	context.Regs[regRSP] = stack
	if _, _, _, err := VirtualUnwind(mem, 0, imageBase, context.Rip, function, context); err != nil {
		t.Fatal(err)
	}
	if context.XMM[6] != want6 || context.XMM[15] != want15 {
		t.Fatalf("restored XMM6=%#v XMM15=%#v", context.XMM[6], context.XMM[15])
	}
}

func writeUnwindCodeHeader(mem *mmu.MMU, address uint64, flags, prologSize, count, frame uint8) {
	mem.Write8(address, 1|(flags<<3))
	mem.Write8(address+1, prologSize)
	mem.Write8(address+2, count)
	mem.Write8(address+3, frame)
}

func TestVirtualUnwindHonorsPartialProlog(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	const (
		functionRVA = 0x1000
		unwindRVA   = 0x3000
	)
	writeUnwindCodeHeader(mem, imageBase+unwindRVA, 0, 8, 2, 0)
	mem.Write8(imageBase+unwindRVA+4, 8)
	mem.Write8(imageBase+unwindRVA+5, (3<<4)|2) // sub rsp, 32
	mem.Write8(imageBase+unwindRVA+6, 1)
	mem.Write8(imageBase+unwindRVA+7, (regRBX<<4)|0)
	function := &RuntimeFunction{BeginAddress: functionRVA, EndAddress: functionRVA + 0x100, UnwindData: unwindRVA}

	stack := imageBase + 0x8000
	mem.Write64(stack, 0x1122334455667788)
	mem.Write64(stack+8, imageBase+0x5000)
	context := &AMD64Context{Rip: imageBase + functionRVA + 4}
	context.Regs[regRSP] = stack
	if _, _, _, err := VirtualUnwind(mem, 0, imageBase, context.Rip, function, context); err != nil {
		t.Fatal(err)
	}
	if context.Regs[regRBX] != 0x1122334455667788 ||
		context.Regs[regRSP] != stack+16 ||
		context.Rip != imageBase+0x5000 {
		t.Fatalf("partial prolog context = %#v", context)
	}
}

func TestVirtualUnwindFollowsChainInfo(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite)
	const (
		functionRVA   = 0x1000
		chainedUnwind = 0x3000
		parentUnwind  = 0x3040
		handlerRVA    = 0x5000
	)
	writeUnwindCodeHeader(mem, imageBase+chainedUnwind, UnwFlagChainInfo, 4, 1, 0)
	mem.Write8(imageBase+chainedUnwind+4, 4)
	mem.Write8(imageBase+chainedUnwind+5, (1<<4)|2) // sub rsp, 16
	mem.Write32(imageBase+chainedUnwind+8, functionRVA)
	mem.Write32(imageBase+chainedUnwind+12, functionRVA+0x100)
	mem.Write32(imageBase+chainedUnwind+16, parentUnwind)

	writeUnwindCodeHeader(mem, imageBase+parentUnwind, UnwFlagUHandler, 1, 1, 0)
	mem.Write8(imageBase+parentUnwind+4, 1)
	mem.Write8(imageBase+parentUnwind+5, (regRBX<<4)|0)
	mem.Write32(imageBase+parentUnwind+8, handlerRVA)
	function := &RuntimeFunction{BeginAddress: functionRVA, EndAddress: functionRVA + 0x100, UnwindData: chainedUnwind}

	stack := imageBase + 0x8000
	mem.Write64(stack+16, 0x8877665544332211)
	mem.Write64(stack+24, imageBase+0x6000)
	context := &AMD64Context{Rip: imageBase + functionRVA + 0x20}
	context.Regs[regRSP] = stack
	handler, _, _, err := VirtualUnwind(mem, UnwFlagUHandler, imageBase, context.Rip, function, context)
	if err != nil {
		t.Fatal(err)
	}
	if handler != imageBase+handlerRVA ||
		context.Regs[regRBX] != 0x8877665544332211 ||
		context.Regs[regRSP] != stack+32 ||
		context.Rip != imageBase+0x6000 {
		t.Fatalf("chained unwind handler=%#x context=%#v", handler, context)
	}
}

func TestVirtualUnwindExecutesEpilog(t *testing.T) {
	mem := mmu.New()
	imageBase := mem.Mmap(0, 0x10000, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	const (
		functionRVA = 0x1000
		unwindRVA   = 0x3000
		epilogRVA   = functionRVA + 0x80
	)
	writeUnwindCodeHeader(mem, imageBase+unwindRVA, 0, 5, 2, 0)
	mem.Write8(imageBase+unwindRVA+4, 5)
	mem.Write8(imageBase+unwindRVA+5, (3<<4)|2)
	mem.Write8(imageBase+unwindRVA+6, 1)
	mem.Write8(imageBase+unwindRVA+7, (regRBX<<4)|0)
	writeFH4Bytes(t, mem, imageBase+epilogRVA, []byte{0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3})
	function := &RuntimeFunction{BeginAddress: functionRVA, EndAddress: functionRVA + 0x100, UnwindData: unwindRVA}

	stack := imageBase + 0x8000
	mem.Write64(stack+32, 0x1020304050607080)
	mem.Write64(stack+40, imageBase+0x7000)
	context := &AMD64Context{Rip: imageBase + epilogRVA}
	context.Regs[regRSP] = stack
	if _, _, _, err := VirtualUnwind(mem, 0, imageBase, context.Rip, function, context); err != nil {
		t.Fatal(err)
	}
	if context.Regs[regRBX] != 0x1020304050607080 ||
		context.Regs[regRSP] != stack+48 ||
		context.Rip != imageBase+0x7000 {
		t.Fatalf("epilog context = %#v", context)
	}
}
