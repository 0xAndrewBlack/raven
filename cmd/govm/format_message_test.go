//go:build guest_windows

package main

import "testing"

func TestFormatMessageFromTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     string
	}{
		{name: "plain", template: "Registry Editor", want: "Registry Editor"},
		{name: "percent", template: "100%% complete", want: "100% complete"},
		{name: "controls", template: "first%nsecond%tvalue%r%bnext", want: "first\r\nsecond\tvalue\r next"},
		{name: "terminate", template: "visible%0hidden", want: "visible"},
		{name: "numbered insert", template: "value %1!s!", want: "value %1!s!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatMessageFromTemplate(tt.template, true, nil); got != tt.want {
				t.Fatalf("formatMessageFromTemplate(%q) = %q, want %q", tt.template, got, tt.want)
			}
		})
	}
}

func TestFormatMessageFromTemplateExpandsInserts(t *testing.T) {
	values := map[int]string{1: "alpha", 2: "42"}
	resolve := func(index int, format string) (string, bool) {
		value, ok := values[index]
		return value, ok
	}

	got := formatMessageFromTemplate("%1!s! = %2!u!, %3", false, resolve)
	if got != "alpha = 42, %3" {
		t.Fatalf("expanded template = %q", got)
	}
}

func TestFormatMessageInsertValue(t *testing.T) {
	readANSI := func(uint64) string { return "ansi" }
	readWide := func(uint64) string { return "wide" }
	tests := []struct {
		name   string
		value  uint64
		format string
		wide   bool
		want   string
	}{
		{name: "wide string", value: 1, format: "s", wide: true, want: "wide"},
		{name: "wide opposite string", value: 1, format: "S", wide: true, want: "ansi"},
		{name: "signed", value: uint64(uint32(0xFFFFFFFF)), format: "d", want: "-1"},
		{name: "unsigned", value: 42, format: "u", want: "42"},
		{name: "hex", value: 0xBEEF, format: "X", want: "BEEF"},
		{name: "character", value: 'A', format: "c", want: "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatMessageInsertValue(tt.value, tt.format, tt.wide, readANSI, readWide)
			if !ok || got != tt.want {
				t.Fatalf("insert value = %q, %v, want %q, true", got, ok, tt.want)
			}
		})
	}
}

func TestFormatMessageArgumentSlot(t *testing.T) {
	template := "%1!I64x! %2!s! %3!u!"
	if got := formatMessageArgumentSlot(template, 2, true); got != 2 {
		t.Fatalf("PE32 second argument slot = %d, want 2", got)
	}
	if got := formatMessageArgumentSlot(template, 3, true); got != 3 {
		t.Fatalf("PE32 third argument slot = %d, want 3", got)
	}
	if got := formatMessageArgumentSlot(template, 3, false); got != 2 {
		t.Fatalf("PE64 third argument slot = %d, want 2", got)
	}
}
