package main

import "testing"

func TestDialogHelpers(t *testing.T) {
filters := parseDialogFilters([]string{"Text Files (*.txt)", "*.txt", "All Files (*.*)", "*.*"})
if len(filters) != 2 || filters[0].name != "Text Files (*.txt)" || filters[1].patterns[0] != "*" {
t.Fatalf("unexpected filters: %#v", filters)
}
if got := normalizeDialogGuestPath("/home/test/file.txt"); got == "/home/test/file.txt" {
t.Fatalf("expected guest path conversion, got %q", got)
}
color, ok := parseColorOutput("rgb(17,34,51)")
if !ok || color != 0x00332211 {
t.Fatalf("unexpected color %#x ok=%v", color, ok)
}
font, size, ok := parseFontOutput("Sans Bold 12")
if !ok || font != "Sans Bold" || size != 12 {
t.Fatalf("unexpected font %q %d %v", font, size, ok)
}
}
