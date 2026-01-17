package ddraw

type PaletteEntry struct {
	Red   byte
	Green byte
	Blue  byte
	Flags byte
}

type Palette struct {
	Entries [256]PaletteEntry
}

func (p *Palette) SetEntries(flags, start, count uint32, entries []PaletteEntry) {
	_ = flags
	if start >= uint32(len(p.Entries)) {
		return
	}
	limit := start + count
	if limit > uint32(len(p.Entries)) {
		limit = uint32(len(p.Entries))
	}
	for i := start; i < limit && int(i-start) < len(entries); i++ {
		p.Entries[i] = entries[i-start]
	}
}

func (p *Palette) GetEntries(flags, start, count uint32) []PaletteEntry {
	_ = flags
	if start >= uint32(len(p.Entries)) {
		return nil
	}
	limit := start + count
	if limit > uint32(len(p.Entries)) {
		limit = uint32(len(p.Entries))
	}
	out := make([]PaletteEntry, 0, limit-start)
	for i := start; i < limit; i++ {
		out = append(out, p.Entries[i])
	}
	return out
}
