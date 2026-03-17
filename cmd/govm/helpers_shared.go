package main

import "strings"

func utf16Decode(s []uint16) []byte {
	var out []byte
	for i := 0; i < len(s); i++ {
		w := s[i]
		// Handle surrogate pairs (U+10000..U+10FFFF)
		if w >= 0xD800 && w <= 0xDBFF && i+1 < len(s) {
			w2 := s[i+1]
			if w2 >= 0xDC00 && w2 <= 0xDFFF {
				r := 0x10000 + uint32(w&0x3FF)<<10 | uint32(w2&0x3FF)
				out = append(out,
					byte(0xF0|(r>>18)),
					byte(0x80|((r>>12)&0x3F)),
					byte(0x80|((r>>6)&0x3F)),
					byte(0x80|(r&0x3F)))
				i++ // skip low surrogate
				continue
			}
		}
		if w < 0x80 {
			out = append(out, byte(w))
		} else if w < 0x800 {
			out = append(out, byte(0xC0|(w>>6)), byte(0x80|(w&0x3F)))
		} else {
			out = append(out, byte(0xE0|(w>>12)), byte(0x80|((w>>6)&0x3F)), byte(0x80|(w&0x3F)))
		}
	}
	return out
}

func utf16Encode(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		}
	}
	return out
}

// shellescape wraps a string in single quotes for safe use in shell commands.
func shellescape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// clipFormatName returns the standard Windows name for a predefined clipboard format,
// or empty string for unknown formats. Custom format names are tracked separately.
func clipFormatName(format uint32) string {
	switch format {
	case 1:
		return "CF_TEXT"
	case 2:
		return "CF_BITMAP"
	case 3:
		return "CF_METAFILEPICT"
	case 4:
		return "CF_SYLK"
	case 5:
		return "CF_DIF"
	case 6:
		return "CF_TIFF"
	case 7:
		return "CF_OEMTEXT"
	case 8:
		return "CF_DIB"
	case 9:
		return "CF_PALETTE"
	case 10:
		return "CF_PENDATA"
	case 11:
		return "CF_RIFF"
	case 12:
		return "CF_WAVE"
	case 13:
		return "CF_UNICODETEXT"
	case 14:
		return "CF_ENHMETAFILE"
	case 15:
		return "CF_HDROP"
	case 16:
		return "CF_LOCALE"
	case 17:
		return "CF_DIBV5"
	}
	return ""
}
