package gdi

// Palette implements Win32 logical palette management.
// ReactOS: win32ss/gdi/ntgdi/palette.c - PALETTE / HPALETTE
//
// On true-color displays (24/32-bit), palette operations are largely
// pass-through - RealizePalette doesn't actually remap colors. But we
// maintain the full PALETTEENTRY array so that GetPaletteEntries and
// friends return correct results.

// PaletteEntry is a Win32 PALETTEENTRY: R, G, B, Flags.
type PaletteEntry struct {
	R, G, B, Flags uint8
}

// Palette holds a Win32 logical palette (HPALETTE).
type Palette struct {
	Version uint16 // always 0x0300
	Entries []PaletteEntry
}

// NewPalette creates a palette from the given entries.
func NewPalette(entries []PaletteEntry) *Palette {
	dup := make([]PaletteEntry, len(entries))
	copy(dup, entries)
	return &Palette{Version: 0x0300, Entries: dup}
}

// GetEntries copies up to len(dst) entries starting at startIndex.
// Returns the number of entries written.
// ReactOS: NtGdiGetPaletteEntries
func (p *Palette) GetEntries(startIndex int, dst []PaletteEntry) int {
	if startIndex < 0 || startIndex >= len(p.Entries) {
		return 0
	}
	n := copy(dst, p.Entries[startIndex:])
	return n
}

// SetEntries writes entries starting at startIndex.
// Returns the number of entries written.
// ReactOS: NtGdiSetPaletteEntries
func (p *Palette) SetEntries(startIndex int, src []PaletteEntry) int {
	if startIndex < 0 || startIndex >= len(p.Entries) {
		return 0
	}
	n := copy(p.Entries[startIndex:], src)
	return n
}

// AnimateEntries replaces palette entries without requiring RealizePalette.
// ReactOS: NtGdiDoPalette with GdiPalAnimate.
func (p *Palette) AnimateEntries(startIndex int, src []PaletteEntry) bool {
	if startIndex < 0 || startIndex+len(src) > len(p.Entries) {
		return false
	}
	copy(p.Entries[startIndex:], src)
	return true
}

// NearestIndex returns the index of the entry closest to the given COLORREF.
// ReactOS: NtGdiGetNearestPaletteIndex → PALETTE_ulGetNearestPaletteIndex
func (p *Palette) NearestIndex(colorRef uint32) int {
	r := uint8(colorRef & 0xFF)
	g := uint8((colorRef >> 8) & 0xFF)
	b := uint8((colorRef >> 16) & 0xFF)
	bestIdx := 0
	bestDist := int(^uint(0) >> 1) // max int
	for i, e := range p.Entries {
		dr := int(r) - int(e.R)
		dg := int(g) - int(e.G)
		db := int(b) - int(e.B)
		d := dr*dr + dg*dg + db*db
		if d < bestDist {
			bestDist = d
			bestIdx = i
			if d == 0 {
				break
			}
		}
	}
	return bestIdx
}

// NearestColor returns the COLORREF of the palette entry closest to colorRef.
func (p *Palette) NearestColor(colorRef uint32) uint32 {
	idx := p.NearestIndex(colorRef)
	if idx >= len(p.Entries) {
		return colorRef
	}
	e := p.Entries[idx]
	return uint32(e.R) | uint32(e.G)<<8 | uint32(e.B)<<16
}

// DefaultSystemPalette returns the 20-entry default system palette.
// ReactOS: PALETTE_Init in win32ss/gdi/eng/palette.c
// The system palette has 256 entries but only the first 10 and last 10 are
// fixed. We provide all 256 with the standard VGA colors.
func DefaultSystemPalette() *Palette {
	entries := make([]PaletteEntry, 256)
	// First 10 static colors (standard Windows VGA)
	static := [10]PaletteEntry{
		{0x00, 0x00, 0x00, 0}, // Black
		{0x80, 0x00, 0x00, 0}, // Dark Red
		{0x00, 0x80, 0x00, 0}, // Dark Green
		{0x80, 0x80, 0x00, 0}, // Dark Yellow
		{0x00, 0x00, 0x80, 0}, // Dark Blue
		{0x80, 0x00, 0x80, 0}, // Dark Magenta
		{0x00, 0x80, 0x80, 0}, // Dark Cyan
		{0xC0, 0xC0, 0xC0, 0}, // Light Gray
		{0xC0, 0xDC, 0xC0, 0}, // Money Green
		{0xA6, 0xCA, 0xF0, 0}, // Sky Blue
	}
	copy(entries[:10], static[:])
	// Last 10 static colors
	staticEnd := [10]PaletteEntry{
		{0xFF, 0xFB, 0xF0, 0}, // Cream
		{0xA0, 0xA0, 0xA4, 0}, // Medium Gray
		{0x80, 0x80, 0x80, 0}, // Dark Gray
		{0xFF, 0x00, 0x00, 0}, // Red
		{0x00, 0xFF, 0x00, 0}, // Green
		{0xFF, 0xFF, 0x00, 0}, // Yellow
		{0x00, 0x00, 0xFF, 0}, // Blue
		{0xFF, 0x00, 0xFF, 0}, // Magenta
		{0x00, 0xFF, 0xFF, 0}, // Cyan
		{0xFF, 0xFF, 0xFF, 0}, // White
	}
	copy(entries[246:], staticEnd[:])
	// Middle entries: 6-6-6 color cube (216 colors), indices 10..225
	idx := 10
	for r := 0; r < 6 && idx < 246; r++ {
		for g := 0; g < 6 && idx < 246; g++ {
			for b := 0; b < 6 && idx < 246; b++ {
				entries[idx] = PaletteEntry{
					R: uint8(r * 51), G: uint8(g * 51), B: uint8(b * 51),
				}
				idx++
			}
		}
	}
	return &Palette{Version: 0x0300, Entries: entries}
}
