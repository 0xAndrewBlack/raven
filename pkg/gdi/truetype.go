package gdi

// truetype.go - TrueType/OpenType font loader and rasterizer.
//
// When a host sysroot is available, we load real TTF/OTF files from
// <sysroot>/Windows/Fonts/ and use golang.org/x/image/font/opentype to
// rasterize glyphs.  This replaces the hard-coded 8×16 bitmap font for
// all fonts that can be resolved by family name.
//
// ReactOS reference: win32ss/gdi/ntgdi/freetype.c (FreeType integration)

import (
	"fmt"
	"image"
	"image/color"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
)

// GlyphKey identifies a rasterized glyph.
type GlyphKey struct {
	FaceID int
	Size   int32 // em height in pixels (absolute value of LOGFONT.lfHeight)
	Rune   rune
}

// GlyphImage is a cached pre-rendered glyph.
type GlyphImage struct {
	Pix    []byte // BGRA pixels
	W, H   int32
	BearingX, BearingY int32 // offset from pen origin to glyph top-left
	Advance int32            // pen advance after this glyph
}

// FontCache holds loaded font faces and glyph bitmaps.
// FaceInfo holds the resolved metadata for a loaded font face.
type FaceInfo struct {
	ID         int
	FamilyName string // canonical family name (as stored in the font or filename stem)
}

type FontCache struct {
	mu         sync.Mutex
	searchDirs []string                 // host directories to scan for TTF files
	faceByName map[string]int           // family name (lower) → face ID
	faceNames  []string                 // canonical family name indexed by face ID
	faces      []*opentype.Font         // indexed by face ID
	glyphs     map[GlyphKey]*GlyphImage // rasterized glyph cache
}

var globalFontCache = &FontCache{
	faceByName: make(map[string]int),
	glyphs:     make(map[GlyphKey]*GlyphImage),
}

// AddSearchDir registers a host directory where TTF files can be found.
func AddFontSearchDir(dir string) {
	globalFontCache.mu.Lock()
	globalFontCache.searchDirs = append(globalFontCache.searchDirs, dir)
	globalFontCache.mu.Unlock()
	globalFontCache.scanDir(dir)
}

// scanDir loads all .ttf/.otf files in dir into the cache.
func (fc *FontCache) scanDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".ttf" && ext != ".otf" {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		fc.addFaceData(data, stem)
	}
}

// addFaceData parses font bytes and registers the face. stem is used as fallback name.
// Returns the new face ID, or -1 on parse error. Caller must not hold fc.mu.
func (fc *FontCache) addFaceData(data []byte, stem string) int {
	f, err := opentype.Parse(data)
	if err != nil {
		return -1
	}
	// Try to extract the real family name from the name table.
	canonical := stem
	if sf, err2 := sfnt.Parse(data); err2 == nil {
		var nameBuf sfnt.Buffer
		if n, err3 := sf.Name(&nameBuf, sfnt.NameIDFamily); err3 == nil && n != "" {
			canonical = n
		}
	}
	key := strings.ToLower(strings.TrimSpace(canonical))
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if id, exists := fc.faceByName[key]; exists {
		return id
	}
	id := len(fc.faces)
	fc.faces = append(fc.faces, f)
	fc.faceNames = append(fc.faceNames, canonical)
	fc.faceByName[key] = id
	// Also register the filename stem as an alias if different.
	stemKey := strings.ToLower(strings.TrimSpace(stem))
	if stemKey != key {
		if _, exists := fc.faceByName[stemKey]; !exists {
			fc.faceByName[stemKey] = id
		}
	}
	return id
}

// findFace returns the face ID for a given logical font family name, or -1.
func (fc *FontCache) findFace(familyName string) int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(familyName))
	if id, ok := fc.faceByName[key]; ok {
		return id
	}
	// Fuzzy: try prefix match
	for k, id := range fc.faceByName {
		if strings.HasPrefix(k, key) || strings.HasPrefix(key, k) {
			return id
		}
	}
	return -1
}

// getFace returns the opentype.Font for faceID, or nil.
func (fc *FontCache) getFace(id int) *opentype.Font {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if id < 0 || id >= len(fc.faces) {
		return nil
	}
	return fc.faces[id]
}

// GetGlyph returns the rasterized glyph for (faceID, size, r), creating it on demand.
func (fc *FontCache) GetGlyph(faceID int, size int32, r rune) *GlyphImage {
	key := GlyphKey{faceID, size, r}
	fc.mu.Lock()
	if g, ok := fc.glyphs[key]; ok {
		fc.mu.Unlock()
		return g
	}
	fc.mu.Unlock()

	face := fc.getFace(faceID)
	if face == nil {
		return nil
	}
	if size <= 0 {
		size = 12
	}
	opts := &opentype.FaceOptions{
		Size:    float64(size),
		DPI:     96,
		Hinting: font.HintingFull,
	}
	fr, err := opentype.NewFace(face, opts)
	if err != nil {
		return nil
	}
	defer fr.Close()

	// Measure bounds
	advance, ok := fr.GlyphAdvance(r)
	if !ok {
		advance, _ = fr.GlyphAdvance('?')
	}
	bounds, adv2, _ := fr.GlyphBounds(r)
	_ = adv2

	// Convert fixed-point to integer
	x0 := int(bounds.Min.X.Floor())
	y0 := int(bounds.Min.Y.Floor())
	x1 := int(bounds.Max.X.Ceil())
	y1 := int(bounds.Max.Y.Ceil())
	w := x1 - x0
	h := y1 - y0
	if w <= 0 || h <= 0 {
		// Space or zero-size glyph
		g := &GlyphImage{
			W: 0, H: 0,
			BearingX: 0, BearingY: 0,
			Advance: int32(math.Round(float64(advance) / 64.0)),
		}
		fc.mu.Lock()
		fc.glyphs[key] = g
		fc.mu.Unlock()
		return g
	}

	// Rasterize into alpha image
	img := image.NewAlpha(image.Rect(0, 0, w, h))
	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color.Alpha{255}),
		Face: fr,
		Dot:  fixed.P(-x0, -y0),
	}
	d.DrawString(string(r))

	// Convert to pre-multiplied BGRA with foreground=white (0xFFFFFFFF).
	// Actual colorization happens in DC.TextOutUTF16 by blending.
	pix := make([]byte, w*h*4)
	for py := 0; py < h; py++ {
		for px := 0; px < w; px++ {
			a := img.AlphaAt(px, py).A
			off := (py*w + px) * 4
			pix[off+0] = a // B (will be replaced with actual fg color)
			pix[off+1] = a // G
			pix[off+2] = a // R
			pix[off+3] = a // A
		}
	}

	g := &GlyphImage{
		Pix:      pix,
		W:        int32(w),
		H:        int32(h),
		BearingX: int32(x0),
		BearingY: int32(-y0),
		Advance:  int32(math.Round(float64(advance) / 64.0)),
	}
	fc.mu.Lock()
	fc.glyphs[key] = g
	fc.mu.Unlock()
	return g
}

// HasFonts returns true if at least one TTF/OTF was loaded.
func HasTTFFonts() bool {
	globalFontCache.mu.Lock()
	defer globalFontCache.mu.Unlock()
	return len(globalFontCache.faces) > 0
}

// ResolveFontFace returns the face ID for a LOGFONT family name, or -1.
func ResolveFontFace(name string) int {
	return globalFontCache.findFace(name)
}

// GlyphFor returns the rasterized glyph for a given face/size/rune.
func GlyphFor(faceID int, size int32, r rune) *GlyphImage {
	return globalFontCache.GetGlyph(faceID, size, r)
}

// FaceMetrics returns (cellHeight, ascent, descent, aveCharWidth) for the face at size.
func FaceMetrics(faceID int, size int32) (cellH, asc, desc, aveW int32) {
	face := globalFontCache.getFace(faceID)
	if face == nil {
		return fontCharH, 13, 3, fontCharW
	}
	if size <= 0 {
		size = 12
	}
	opts := &opentype.FaceOptions{Size: float64(size), DPI: 96, Hinting: font.HintingFull}
	fr, err := opentype.NewFace(face, opts)
	if err != nil {
		return fontCharH, 13, 3, fontCharW
	}
	defer fr.Close()
	m := fr.Metrics()
	asc32 := int32(m.Ascent.Ceil())
	desc32 := int32(m.Descent.Ceil())
	cellH32 := asc32 + desc32
	// Average char width: measure 'x'
	adv, _ := fr.GlyphAdvance('x')
	aveW32 := int32(math.Round(float64(adv) / 64.0))
	return cellH32, asc32, desc32, aveW32
}

// ListFaces returns metadata for all loaded font faces.
func ListFaces() []FaceInfo {
	globalFontCache.mu.Lock()
	defer globalFontCache.mu.Unlock()
	seen := make(map[int]bool)
	result := make([]FaceInfo, 0, len(globalFontCache.faces))
	for _, id := range globalFontCache.faceByName {
		if seen[id] {
			continue
		}
		seen[id] = true
		name := fmt.Sprintf("font-%d", id)
		if id < len(globalFontCache.faceNames) {
			name = globalFontCache.faceNames[id]
		}
		result = append(result, FaceInfo{ID: id, FamilyName: name})
	}
	return result
}

// AddFontFromBytes parses raw TTF/OTF bytes, registers the face, and returns its ID (-1 on error).
// stem is a fallback name used only when the font's name table cannot be read.
func AddFontFromBytes(stem string, data []byte) int {
	return globalFontCache.addFaceData(data, stem)
}
