//go:build guest_windows

package ntapi

import "testing"

func TestDecodeMemIoLength(t *testing.T) {
	tests := []struct {
		name         string
		resourceType byte
		flags        uint16
		encoded      uint32
		want         uint64
		valid        bool
	}{
		{name: "port", resourceType: cmResourceTypePort, encoded: 0x1234, want: 0x1234, valid: true},
		{name: "memory", resourceType: cmResourceTypeMemory, encoded: 0x5678, want: 0x5678, valid: true},
		{name: "memory40", resourceType: cmResourceTypeMemoryLarge, flags: cmResourceMemoryLarge40, encoded: 2, want: 2 << 8, valid: true},
		{name: "memory48", resourceType: cmResourceTypeMemoryLarge, flags: cmResourceMemoryLarge48, encoded: 3, want: 3 << 16, valid: true},
		{name: "memory64", resourceType: cmResourceTypeMemoryLarge, flags: cmResourceMemoryLarge64, encoded: 4, want: 4 << 32, valid: true},
		{name: "invalid large flags", resourceType: cmResourceTypeMemoryLarge, encoded: 1},
		{name: "invalid type", resourceType: 2, encoded: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, valid := decodeMemIoLength(tt.resourceType, tt.flags, tt.encoded)
			if valid != tt.valid {
				t.Fatalf("valid = %v, want %v", valid, tt.valid)
			}
			if got != tt.want {
				t.Fatalf("length = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestNtdllExportsResourceDecoders(t *testing.T) {
	for _, name := range []string{"RtlCmDecodeMemIoResource", "RtlIoDecodeMemIoResource"} {
		if id := idOf(name); id >= AutoSynthIDBase {
			t.Fatalf("%s syscall ID %#x is outside ntdll range", name, id)
		}
	}
}
