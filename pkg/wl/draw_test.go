package wl

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDrawTextAbsClippedDoesNotTouchPixelsOutsideBounds(t *testing.T) {
	win := NewHeadlessWindow("clip", 32, 20, 0)
	before := append([]byte(nil), win.Pix...)

	win.DrawTextAbsClipped(0, 0, 8, 16, "AB", 0x000000, 0xFFFFFF, true)

	for y := 0; y < 16; y++ {
		for x := 8; x < 16; x++ {
			off := y*int(win.Stride) + x*4
			for channel := 0; channel < 4; channel++ {
				if win.Pix[off+channel] != before[off+channel] {
					t.Fatalf("pixel (%d,%d) changed outside clip", x, y)
				}
			}
		}
	}
}

func TestScreenshotWaitsForCompleteFrame(t *testing.T) {
	win := NewHeadlessWindow("frame", 32, 20, 0)
	updateStarted := make(chan struct{})
	releaseUpdate := make(chan struct{})
	updateDone := make(chan struct{})
	go func() {
		win.UpdateFrame(func() {
			close(updateStarted)
			<-releaseUpdate
			win.DrawRectAbs(0, 0, win.Width, win.Height, 0x123456)
		})
		close(updateDone)
	}()
	<-updateStarted

	screenshotDone := make(chan error, 1)
	go func() {
		screenshotDone <- win.Screenshot(filepath.Join(t.TempDir(), "frame.png"))
	}()
	select {
	case err := <-screenshotDone:
		t.Fatalf("Screenshot completed during an active frame: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseUpdate)
	select {
	case <-updateDone:
	case <-time.After(time.Second):
		t.Fatal("frame update did not finish")
	}
	select {
	case err := <-screenshotDone:
		if err != nil {
			t.Fatalf("Screenshot failed after frame completion: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Screenshot remained blocked after frame completion")
	}
}
