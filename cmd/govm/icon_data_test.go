//go:build guest_windows

package main

import (
	"encoding/binary"
	"sync"
	"testing"
)

func TestDecodeIconResourceDIB(t *testing.T) {
	data := make([]byte, 40+16+8)
	binary.LittleEndian.PutUint32(data[0:4], 40)
	binary.LittleEndian.PutUint32(data[4:8], 2)
	binary.LittleEndian.PutUint32(data[8:12], 4)
	binary.LittleEndian.PutUint16(data[12:14], 1)
	binary.LittleEndian.PutUint16(data[14:16], 32)
	copy(data[40:56], []byte{
		0x00, 0x00, 0xff, 0xff,
		0x00, 0xff, 0x00, 0xff,
		0xff, 0x00, 0x00, 0xff,
		0xff, 0xff, 0xff, 0xff,
	})

	icon, ok := decodeIconResource(data)
	if !ok {
		t.Fatal("DIB icon did not decode")
	}
	if icon.width != 2 || icon.height != 2 || len(icon.pixels) != 16 {
		t.Fatalf("decoded icon = %dx%d, %d bytes", icon.width, icon.height, len(icon.pixels))
	}
	if icon.pixels[0] != 0xff || icon.pixels[1] != 0 || icon.pixels[2] != 0 {
		t.Fatalf("top-left BGRA = %#v, want blue", icon.pixels[:4])
	}
}

func TestScaleIconPixels(t *testing.T) {
	icon := &iconHandleData{
		width:  2,
		height: 1,
		pixels: []byte{
			1, 2, 3, 4,
			5, 6, 7, 8,
		},
	}
	scaled := scaleIconPixels(icon, 4, 1)
	want := []byte{
		1, 2, 3, 4,
		1, 2, 3, 4,
		5, 6, 7, 8,
		5, 6, 7, 8,
	}
	if len(scaled) != len(want) {
		t.Fatalf("scaled length = %d, want %d", len(scaled), len(want))
	}
	for i := range want {
		if scaled[i] != want[i] {
			t.Fatalf("scaled[%d] = %d, want %d", i, scaled[i], want[i])
		}
	}
}

func TestSelectGroupIconResource(t *testing.T) {
	data := make([]byte, 6+2*14)
	binary.LittleEndian.PutUint16(data[2:4], 1)
	binary.LittleEndian.PutUint16(data[4:6], 2)
	data[6], data[7] = 16, 16
	binary.LittleEndian.PutUint16(data[12:14], 32)
	binary.LittleEndian.PutUint16(data[18:20], 7)
	second := 20
	data[second], data[second+1] = 32, 32
	binary.LittleEndian.PutUint16(data[second+6:second+8], 32)
	binary.LittleEndian.PutUint16(data[second+12:second+14], 9)

	if got := selectGroupIconResource(data, 16, 16); got != 7 {
		t.Fatalf("16px icon resource = %d, want 7", got)
	}
	if got := selectGroupIconResource(data, 32, 32); got != 9 {
		t.Fatalf("32px icon resource = %d, want 9", got)
	}
}

func TestDynamicIconHandlesAreConcurrentAndDisjointFromResources(t *testing.T) {
	hctx := &HandlerCtx{}
	const count = 64
	handles := make(chan uint64, count)
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		workers.Add(1)
		go func(width int32) {
			defer workers.Done()
			pixels := make([]byte, int(width)*16*4)
			handles <- hctx.allocIcon(&iconHandleData{width: width, height: 16, pixels: pixels})
		}(int32(index + 1))
	}
	workers.Wait()
	close(handles)

	seen := make(map[uint64]struct{}, count)
	for handle := range handles {
		if handle <= 0x40000000 {
			t.Fatalf("dynamic handle = %#x", handle)
		}
		if handle == 0x00020011 {
			t.Fatalf("dynamic handle collided with module resource handle %#x", handle)
		}
		if _, duplicate := seen[handle]; duplicate {
			t.Fatalf("duplicate dynamic handle %#x", handle)
		}
		seen[handle] = struct{}{}
		if pixels := hctx.iconPixels(handle, 16, 16); pixels == nil {
			t.Fatalf("dynamic handle %#x has no icon data", handle)
		}
	}
	if len(seen) != count {
		t.Fatalf("unique handles = %d, want %d", len(seen), count)
	}
}
