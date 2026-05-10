//go:build guest_windows

package main

import "testing"

func TestOutlineTextMetricSize(t *testing.T) {
	if got := outlineTextMetricSize(true); got != 216 {
		t.Fatalf("PE32 OUTLINETEXTMETRICW size = %d", got)
	}
	if got := outlineTextMetricSize(false); got != 232 {
		t.Fatalf("PE32+ OUTLINETEXTMETRICW size = %d", got)
	}
}
