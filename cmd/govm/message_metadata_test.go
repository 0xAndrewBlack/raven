//go:build guest_windows

package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

func TestWriteMessageMetadataLayouts(t *testing.T) {
	for _, test := range []struct {
		name       string
		is32       bool
		timeOffset uint64
	}{
		{name: "PE32", is32: true, timeOffset: 16},
		{name: "PE64", timeOffset: 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			const addr = uint64(0x4000)
			mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if !writeMessageMetadata(mem, addr, test.is32, 1234, -12, 34) {
				t.Fatal("writeMessageMetadata returned false")
			}
			messageTime, err := mem.Read32(addr + test.timeOffset)
			if err != nil || messageTime != 1234 {
				t.Fatalf("time = %d, err %v", messageTime, err)
			}
			x, err := mem.Read32(addr + test.timeOffset + 4)
			if err != nil || int32(x) != -12 {
				t.Fatalf("x = %d, err %v", int32(x), err)
			}
			y, err := mem.Read32(addr + test.timeOffset + 8)
			if err != nil || int32(y) != 34 {
				t.Fatalf("y = %d, err %v", int32(y), err)
			}
		})
	}
}

func TestWriteMessageMetadataRejectsUnmappedMemory(t *testing.T) {
	if writeMessageMetadata(mmu.New(), 0x4000, true, 1, 2, 3) {
		t.Fatal("writeMessageMetadata accepted unmapped memory")
	}
}

func TestPackMessagePos(t *testing.T) {
	if got, want := packMessagePos(-2, 300), uint32(0x012c_fffe); got != want {
		t.Fatalf("packed position = %#x, want %#x", got, want)
	}
}

func TestNewQueuedMsgCapturesPostingMetadata(t *testing.T) {
	hctx := &HandlerCtx{
		BootTime:   time.Now().Add(-time.Second),
		CursorPosX: -5,
		CursorPosY: 9,
	}
	msg := newQueuedMsg(hctx, 1, 2, 3, 4)
	if msg.time < 900 || msg.x != -5 || msg.y != 9 || msg.extraInfo != 0 {
		t.Fatalf("metadata = time %d, pos (%d,%d), extra %#x", msg.time, msg.x, msg.y, msg.extraInfo)
	}
	hctx.CursorPosX = 100
	if msg.x != -5 || msg.extraInfo != 0 {
		t.Fatalf("queued metadata changed to x %d, extra %#x", msg.x, msg.extraInfo)
	}
}

func TestWriteQueuedMessageLayouts(t *testing.T) {
	for _, test := range []struct {
		name       string
		is32       bool
		structSize uint64
		privateOff uint64
	}{
		{name: "PE32", is32: true, structSize: 32, privateOff: 28},
		{name: "PE64", structSize: 48, privateOff: 44},
	} {
		t.Run(test.name, func(t *testing.T) {
			mem := mmu.New()
			const addr = uint64(0x4000)
			mem.MapRange(addr, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
			if err := mem.Write32(addr+test.privateOff, 0xdeadbeef); err != nil {
				t.Fatal(err)
			}
			if err := mem.Write32(addr+test.structSize, 0xa5a5a5a5); err != nil {
				t.Fatal(err)
			}
			msg := queuedMsg{hwnd: 7, message: 8, wParam: 9, lParam: 10, time: 11, x: -12, y: 13, extraInfo: 14}
			if !writeQueuedMessage(mem, addr, test.is32, msg) {
				t.Fatal("writeQueuedMessage returned false")
			}
			private, err := mem.Read32(addr + test.privateOff)
			if err != nil || private != 0 {
				t.Fatalf("lPrivate = %#x, err %v", private, err)
			}
			sentinel, err := mem.Read32(addr + test.structSize)
			if err != nil || sentinel != 0xa5a5a5a5 {
				t.Fatalf("adjacent memory = %#x, err %v", sentinel, err)
			}
		})
	}
}

func TestWriteQueuedMessageRejectsPartiallyMappedBuffer(t *testing.T) {
	mem := mmu.New()
	const page = uint64(0x4000)
	mem.MapRange(page, mmu.PageSize, mmu.PermRead|mmu.PermWrite)
	addr := page + mmu.PageSize - 16
	want := bytes.Repeat([]byte{0xa5}, 16)
	if err := mem.WriteBytes(addr, want); err != nil {
		t.Fatal(err)
	}
	if writeQueuedMessage(mem, addr, true, queuedMsg{message: 1}) {
		t.Fatal("writeQueuedMessage accepted a partially mapped buffer")
	}
	got, err := mem.ReadBytes(addr, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("mapped bytes = %x, err %v", got, err)
	}
}

func TestDeliverQueuedMessagePreservesEntryOnWriteFailure(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	queue.enqueue(cpu, queuedMsg{message: 1}, queuedMsg{message: 2})
	if _, ok := queue.deliver(cpu, nil, func(queuedMsg) bool { return true }, func(queuedMsg) bool { return false }); ok {
		t.Fatal("failed message write was reported as delivered")
	}
	if count := queue.count(cpu); count != 2 {
		t.Fatalf("queue count after failed write = %d, want 2", count)
	}
}

func TestDeliverQueuedMessageRemovalModes(t *testing.T) {
	cpu := x64.New(mmu.New())
	var queue messageQueue
	queue.enqueue(cpu, queuedMsg{message: 1}, queuedMsg{message: 2})
	msg, ok := queue.deliver(cpu, nil, func(queuedMsg) bool { return false }, func(queuedMsg) bool { return true })
	if !ok || msg.message != 1 || queue.count(cpu) != 2 {
		t.Fatalf("peek result = %+v, %v, count = %d", msg, ok, queue.count(cpu))
	}
	msg, ok = queue.deliver(cpu, nil, func(queuedMsg) bool { return true }, func(queuedMsg) bool { return true })
	next, nextOK := queue.take(cpu, nil)
	if !ok || msg.message != 1 || queue.count(cpu) != 0 || !nextOK || next.message != 2 {
		t.Fatalf("remove result = %+v, %v, next = %+v, %v", msg, ok, next, nextOK)
	}
}

func TestMessageMetadataStoreIsolatesGuestCPUs(t *testing.T) {
	first := x64.New(mmu.New())
	second := x64.New(mmu.New())
	var store messageMetadataStore

	store.delivered(first, queuedMsg{time: 10, x: 11, y: 12, extraInfo: 13})
	store.delivered(second, queuedMsg{time: 20, x: 21, y: 22, extraInfo: 23})

	firstState := store.get(first)
	secondState := store.get(second)
	if firstState.messageTime != 10 || firstState.x != 11 || firstState.y != 12 || firstState.extraInfo != 13 {
		t.Fatalf("first CPU metadata = %+v", firstState)
	}
	if secondState.messageTime != 20 || secondState.x != 21 || secondState.y != 22 || secondState.extraInfo != 23 {
		t.Fatalf("second CPU metadata = %+v", secondState)
	}
	if previous := store.setExtraInfo(first, 14); previous != 13 {
		t.Fatalf("first CPU previous extra info = %d, want 13", previous)
	}
	if got := store.get(second).extraInfo; got != 23 {
		t.Fatalf("second CPU extra info = %d, want 23", got)
	}
}
