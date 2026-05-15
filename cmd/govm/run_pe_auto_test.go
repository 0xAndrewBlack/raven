//go:build guest_windows

package main

import (
	"testing"
	"time"

	"github.com/mirkobrombin/Raven/pkg/wl"
)

func TestWaitForAutoWindowRetriesUntilTitleAppears(t *testing.T) {
	target := wl.NewHeadlessWindow("Other", 100, 40, 0)
	go func() {
		time.Sleep(10 * time.Millisecond)
		target.SetTitleText("Find")
	}()
	got := waitForAutoWindow(func() []*wl.Window {
		return []*wl.Window{target}
	}, " find ", time.Second)
	if got != target {
		t.Fatalf("window = %p, want %p", got, target)
	}
}

func TestWaitForAutoWindowTimesOut(t *testing.T) {
	start := time.Now()
	if got := waitForAutoWindow(func() []*wl.Window { return nil }, "Missing", 30*time.Millisecond); got != nil {
		t.Fatalf("window = %p, want nil", got)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout took %s", elapsed)
	}
}
