//go:build guest_windows

package win32

import "testing"

func TestScaleForDPI(t *testing.T) {
	tests := []struct {
		value int32
		dpi   uint32
		want  int32
	}{
		{value: 32, dpi: 96, want: 32},
		{value: 32, dpi: 144, want: 48},
		{value: 17, dpi: 120, want: 21},
		{value: -12, dpi: 144, want: -18},
	}
	for _, test := range tests {
		if got := ScaleForDPI(test.value, test.dpi); got != test.want {
			t.Errorf("ScaleForDPI(%d, %d) = %d, want %d", test.value, test.dpi, got, test.want)
		}
	}
}

func TestGetSystemMetricsForDPIScalesLogicalDimensions(t *testing.T) {
	if got := GetSystemMetricsForDPI(SM_CXICON, 144); got != 48 {
		t.Fatalf("SM_CXICON at 144 DPI = %d, want 48", got)
	}
	if got := GetSystemMetricsForDPI(SM_MOUSEPRESENT, 144); got != 1 {
		t.Fatalf("SM_MOUSEPRESENT at 144 DPI = %d, want 1", got)
	}
	if got := GetSystemMetricsForDPI(SM_CXSCREEN, 144); got != ScreenWidth {
		t.Fatalf("SM_CXSCREEN at 144 DPI = %d, want %d", got, ScreenWidth)
	}
	if got := GetSystemMetricsForDPI(SM_CXICON, 0); got != 0 {
		t.Fatalf("SM_CXICON at 0 DPI = %d, want 0", got)
	}
}
