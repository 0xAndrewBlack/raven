package main

import (
	"encoding/binary"
	"fmt"
)

const dsSetFont = 0x0040 // DS_SETFONT style bit

// dlgItem represents a single control inside a dialog template.
type dlgItem struct {
	style    uint32
	extStyle uint32
	x, y     int16
	cx, cy   int16
	id       uint32
	class    string // "Button", "Edit", "Static", etc.
	title    string // control text or "#n" for resource icon
}

// dlgInfo holds the parsed result of a DLGTEMPLATE or DLGTEMPLATEEX.
type dlgInfo struct {
	style      uint32
	extStyle   uint32
	x, y       int16
	cx, cy     int16
	title      string
	fontName   string
	fontSize   uint16
	items      []dlgItem
	isExtended bool
}

// sysClassAtoms maps the Win32 system-class atom values in DLGITEMTEMPLATE
// to their string class names.
var sysClassAtoms = map[uint16]string{
	0x0080: "Button",
	0x0081: "Edit",
	0x0082: "Static",
	0x0083: "ListBox",
	0x0084: "ScrollBar",
	0x0085: "ComboBox",
}

// parseDLGTEMPLATE parses a binary DLGTEMPLATE or DLGTEMPLATEEX blob from the
// PE resource section.  data must be the complete raw resource bytes.
func parseDLGTEMPLATE(data []byte) (*dlgInfo, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("dlgtemplate: data too short (%d bytes)", len(data))
	}

	le := binary.LittleEndian
	off := 0

	// ── low-level read helpers ────────────────────────────────────────────────

	readU16 := func() (uint16, bool) {
		if off+2 > len(data) {
			return 0, false
		}
		v := le.Uint16(data[off:])
		off += 2
		return v, true
	}

	readU32 := func() (uint32, bool) {
		if off+4 > len(data) {
			return 0, false
		}
		v := le.Uint32(data[off:])
		off += 4
		return v, true
	}

	skip := func(n int) {
		if off+n <= len(data) {
			off += n
		}
	}

	alignDWORD := func() {
		if off%4 != 0 {
			off += 4 - (off % 4)
		}
	}

	// readUTF16NullTerm reads a null-terminated UTF-16LE string from data[off:]
	// and advances off past the terminating NUL word.
	readUTF16NullTerm := func() string {
		start := off
		for off+2 <= len(data) {
			w := le.Uint16(data[off:])
			off += 2
			if w == 0 {
				break
			}
		}
		// string occupies [start, off-2); off now points past the NUL word
		nChars := (off - start - 2) / 2
		if nChars <= 0 {
			return ""
		}
		ws := make([]uint16, nChars)
		for i := range ws {
			ws[i] = le.Uint16(data[start+i*2:])
		}
		return string(utf16Decode(ws))
	}

	// readMenuField: 0 → "", 0xFFFF+WORD → "#n", else null-term UTF-16 string
	readMenuField := func() {
		if off+2 > len(data) {
			return
		}
		flag := le.Uint16(data[off:])
		if flag == 0 {
			off += 2
			return
		}
		if flag == 0xFFFF {
			off += 4 // WORD 0xFFFF + WORD id
			return
		}
		readUTF16NullTerm()
	}

	// readClassDialogField: 0 → "Dialog", 0xFFFF+WORD → atom, else string
	readClassDialogField := func() {
		if off+2 > len(data) {
			return
		}
		flag := le.Uint16(data[off:])
		if flag == 0 {
			off += 2
			return
		}
		if flag == 0xFFFF {
			off += 4
			return
		}
		readUTF16NullTerm()
	}

	// readItemClassField: 0xFFFF+WORD → system atom class name, else null-term string
	readItemClassField := func() string {
		if off+2 > len(data) {
			return ""
		}
		flag := le.Uint16(data[off:])
		if flag == 0xFFFF {
			off += 2
			if off+2 > len(data) {
				return ""
			}
			atom := le.Uint16(data[off:])
			off += 2
			if name, ok := sysClassAtoms[atom]; ok {
				return name
			}
			return fmt.Sprintf("atom:0x%04x", atom)
		}
		return readUTF16NullTerm()
	}

	// readItemTitleField: 0xFFFF+WORD → "#n" (icon resource), else null-term string
	readItemTitleField := func() string {
		if off+2 > len(data) {
			return ""
		}
		flag := le.Uint16(data[off:])
		if flag == 0xFFFF {
			off += 2
			if off+2 > len(data) {
				return ""
			}
			id := le.Uint16(data[off:])
			off += 2
			return fmt.Sprintf("#%d", id)
		}
		return readUTF16NullTerm()
	}

	// ── detect DLGTEMPLATEEX vs. classic DLGTEMPLATE ──────────────────────────

	info := &dlgInfo{}
	var cdit uint16

	w0 := le.Uint16(data[0:])
	w1 := le.Uint16(data[2:])

	if w0 == 1 && w1 == 0xFFFF {
		// ── DLGTEMPLATEEX ─────────────────────────────────────────────────────
		info.isExtended = true
		off = 0
		readU16() // dlgVer = 1
		readU16() // signature = 0xFFFF
		readU32() // helpID
		exStyle, _ := readU32()
		style, _ := readU32()
		info.style = style
		info.extStyle = exStyle
		cnt, _ := readU16()
		cdit = cnt
		x, _ := readU16()
		info.x = int16(x)
		y, _ := readU16()
		info.y = int16(y)
		cx, _ := readU16()
		info.cx = int16(cx)
		cy, _ := readU16()
		info.cy = int16(cy)
	} else {
		// ── Classic DLGTEMPLATE (18 bytes header) ─────────────────────────────
		off = 0
		style, _ := readU32()
		exStyle, _ := readU32()
		info.style = style
		info.extStyle = exStyle
		cnt, _ := readU16()
		cdit = cnt
		x, _ := readU16()
		info.x = int16(x)
		y, _ := readU16()
		info.y = int16(y)
		cx, _ := readU16()
		info.cx = int16(cx)
		cy, _ := readU16()
		info.cy = int16(cy)
	}

	// ── variable-length dialog header fields ──────────────────────────────────

	readMenuField()
	readClassDialogField()
	info.title = readUTF16NullTerm()

	// Optional font info (DS_SETFONT)
	if info.style&dsSetFont != 0 {
		fontSize, _ := readU16()
		info.fontSize = fontSize
		if info.isExtended {
			readU16() // weight
			skip(1)   // italic
			skip(1)   // charset
		}
		info.fontName = readUTF16NullTerm()
	}

	// ── per-control items ─────────────────────────────────────────────────────

	info.items = make([]dlgItem, 0, cdit)

	for i := uint16(0); i < cdit; i++ {
		alignDWORD()
		if off >= len(data) {
			break
		}

		var item dlgItem

		if info.isExtended {
			// DLGITEMTEMPLATEEX
			if off+24 > len(data) {
				break
			}
			readU32() // helpID
			exStyle, _ := readU32()
			style, _ := readU32()
			item.extStyle = exStyle
			item.style = style
			x, _ := readU16()
			item.x = int16(x)
			y, _ := readU16()
			item.y = int16(y)
			cx, _ := readU16()
			item.cx = int16(cx)
			cy, _ := readU16()
			item.cy = int16(cy)
			id, _ := readU32() // 32-bit ID in extended template
			item.id = id
		} else {
			// Classic DLGITEMTEMPLATE (18 bytes)
			if off+18 > len(data) {
				break
			}
			style, _ := readU32()
			exStyle, _ := readU32()
			item.style = style
			item.extStyle = exStyle
			x, _ := readU16()
			item.x = int16(x)
			y, _ := readU16()
			item.y = int16(y)
			cx, _ := readU16()
			item.cx = int16(cx)
			cy, _ := readU16()
			item.cy = int16(cy)
			id, _ := readU16()
			item.id = uint32(id)
		}

		item.class = readItemClassField()
		item.title = readItemTitleField()

		extraCount, ok := readU16()
		if ok && extraCount > 0 {
			skip(int(extraCount))
		}

		info.items = append(info.items, item)
	}

	return info, nil
}

// dlgUnitsToPixels converts dialog units to approximate pixels using the
// standard base-unit calculation for 8-point system font at 96 DPI.
// Horizontal: 1 DU = charWidth/4 px; Vertical: 1 DU = charHeight/8 px.
// Using charWidth=8, charHeight=16 (standard screen font) → both = 2 px.
func dlgUnitsToPixels(x, y, cx, cy int16) (px, py, pcx, pcy int32) {
	const duX = 8  // base char width  (pixels per 4 DU)
	const duY = 16 // base char height (pixels per 8 DU)
	px = int32(x) * duX / 4
	py = int32(y) * duY / 8
	pcx = int32(cx) * duX / 4
	pcy = int32(cy) * duY / 8
	return
}
