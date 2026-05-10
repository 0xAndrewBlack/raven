//go:build guest_windows

package gdi

// truetype.go - TrueType/OpenType font loader and rasterizer.
//
// We load real TTF/OTF files and use golang.org/x/image/font/opentype to
// rasterize glyphs. Fonts may come from explicit host directories or be
// resolved on demand through fontconfig.
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
	"unicode"

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

type glyphFallbackKey struct {
	FaceID int
	Rune   rune
}

// GlyphImage is a cached pre-rendered glyph.
type GlyphImage struct {
	Pix                []byte // BGRA pixels
	W, H               int32
	BearingX, BearingY int32 // offset from pen origin to glyph top-left
	Advance            int32 // pen advance after this glyph
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
	faceBySpec map[string]int           // logical family + style → face ID
	pathToFace map[string]int           // absolute font path → face ID
	faceNames  []string                 // canonical family name indexed by face ID
	faces      []*opentype.Font         // indexed by face ID
	glyphs     map[GlyphKey]*GlyphImage // rasterized glyph cache
	fallbacks  map[glyphFallbackKey]int
}

var globalFontCache = &FontCache{
	faceByName: make(map[string]int),
	faceBySpec: make(map[string]int),
	pathToFace: make(map[string]int),
	glyphs:     make(map[GlyphKey]*GlyphImage),
	fallbacks:  make(map[glyphFallbackKey]int),
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
		if ext != ".ttf" && ext != ".otf" && ext != ".ttc" && ext != ".otc" {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		stem := strings.TrimSuffix(name, filepath.Ext(name))
		if ext == ".ttc" || ext == ".otc" {
			collection, parseErr := opentype.ParseCollection(data)
			if parseErr != nil {
				continue
			}
			for index := 0; index < collection.NumFonts(); index++ {
				fc.addFaceData(data, stem, index)
			}
			continue
		}
		fc.addFaceData(data, stem)
	}
}

// addFaceData parses font bytes and registers the face. stem is used as fallback name.
// Returns the new face ID, or -1 on parse error. Caller must not hold fc.mu.
func (fc *FontCache) addFaceData(data []byte, stem string, faceIndex ...int) int {
	f, err := parseOpenTypeFont(data, faceIndex...)
	if err != nil {
		return -1
	}
	// Try to extract the real family name from the name table.
	canonical := stem
	var nameBuf sfnt.Buffer
	if n, nameErr := f.Name(&nameBuf, sfnt.NameIDFamily); nameErr == nil && n != "" {
		canonical = n
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

func (fc *FontCache) addFaceFile(path string, faceIndex int, alias string) int {
	if path == "" {
		return -1
	}
	cleanPath := filepath.Clean(path)
	cacheKey := fmt.Sprintf("%s#%d", cleanPath, faceIndex)
	fc.mu.Lock()
	if id, ok := fc.pathToFace[cacheKey]; ok {
		if alias != "" {
			fc.faceBySpec[fontSpecKey(alias, false, false)] = id
		}
		fc.mu.Unlock()
		return id
	}
	fc.mu.Unlock()

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return -1
	}
	f, err := parseOpenTypeFont(data, faceIndex)
	if err != nil {
		return -1
	}
	canonical := strings.TrimSuffix(filepath.Base(cleanPath), filepath.Ext(cleanPath))
	var nameBuf sfnt.Buffer
	if n, nameErr := f.Name(&nameBuf, sfnt.NameIDFamily); nameErr == nil && n != "" {
		canonical = n
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()
	if id, ok := fc.pathToFace[cacheKey]; ok {
		if alias != "" {
			fc.faceBySpec[fontSpecKey(alias, false, false)] = id
		}
		return id
	}
	id := len(fc.faces)
	fc.faces = append(fc.faces, f)
	fc.faceNames = append(fc.faceNames, canonical)
	fc.pathToFace[cacheKey] = id

	canonicalKey := strings.ToLower(strings.TrimSpace(canonical))
	if canonicalKey != "" {
		if _, exists := fc.faceByName[canonicalKey]; !exists {
			fc.faceByName[canonicalKey] = id
		}
	}
	stemKey := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(filepath.Base(cleanPath), filepath.Ext(cleanPath))))
	if stemKey != "" {
		if _, exists := fc.faceByName[stemKey]; !exists {
			fc.faceByName[stemKey] = id
		}
	}
	if alias != "" {
		fc.faceBySpec[fontSpecKey(alias, false, false)] = id
	}
	return id
}

func parseOpenTypeFont(data []byte, faceIndex ...int) (*opentype.Font, error) {
	index := 0
	if len(faceIndex) > 0 {
		index = faceIndex[0]
	}
	if index == 0 {
		if face, err := opentype.Parse(data); err == nil {
			return face, nil
		}
	}
	collection, err := opentype.ParseCollection(data)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= collection.NumFonts() {
		return nil, fmt.Errorf("font collection index %d out of range", index)
	}
	return collection.Font(index)
}

func glyphHasInk(glyph *GlyphImage, r rune) bool {
	if glyph == nil {
		return false
	}
	if unicode.IsSpace(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return true
	}
	if glyph.W <= 0 || glyph.H <= 0 {
		return false
	}
	for i := 3; i < len(glyph.Pix); i += 4 {
		if glyph.Pix[i] != 0 {
			return true
		}
	}
	return false
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

func (fc *FontCache) findFaceSpec(familyName string, bold, italic bool) int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if id, ok := fc.faceBySpec[fontSpecKey(familyName, bold, italic)]; ok {
		return id
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
	var glyphBuf sfnt.Buffer
	index, err := face.GlyphIndex(&glyphBuf, r)
	if err != nil || index == 0 {
		return nil
	}
	if size <= 0 {
		size = 12
	}
	opts := &opentype.FaceOptions{
		Size:    float64(size),
		DPI:     72, // Size is already in pixels: pixels = pts * DPI/72 = size * 72/72 = size
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

func (fc *FontCache) fallbackFace(faceID int, r rune) int {
	key := glyphFallbackKey{FaceID: faceID, Rune: r}
	fc.mu.Lock()
	if fallback, ok := fc.fallbacks[key]; ok {
		fc.mu.Unlock()
		return fallback
	}
	family := ""
	if faceID >= 0 && faceID < len(fc.faceNames) {
		family = fc.faceNames[faceID]
	}
	fc.mu.Unlock()

	fallback := -1
	for _, match := range findSystemFallbackFonts(family, r) {
		candidate := fc.addFaceFile(match.path, match.index, "")
		if candidate < 0 || !glyphHasInk(fc.GetGlyph(candidate, 16, r), r) {
			continue
		}
		fallback = candidate
		break
	}

	fc.mu.Lock()
	if cached, ok := fc.fallbacks[key]; ok {
		fc.mu.Unlock()
		return cached
	}
	fc.fallbacks[key] = fallback
	fc.mu.Unlock()
	return fallback
}

// HasFonts returns true if at least one TTF/OTF was loaded.
func HasTTFFonts() bool {
	globalFontCache.mu.Lock()
	defer globalFontCache.mu.Unlock()
	return len(globalFontCache.faces) > 0
}

// ResolveFontFace returns the face ID for a LOGFONT family name, or -1.
func ResolveFontFace(name string) int {
	return ResolveFontFaceStyle(name, false, false)
}

// ResolveFontFaceStyle returns the face ID for a logical family/style tuple, or -1.
func ResolveFontFaceStyle(name string, bold, italic bool) int {
	if id := globalFontCache.findFaceSpec(name, bold, italic); id >= 0 {
		return id
	}
	if id := globalFontCache.findFace(name); id >= 0 && !bold && !italic {
		globalFontCache.mu.Lock()
		globalFontCache.faceBySpec[fontSpecKey(name, bold, italic)] = id
		globalFontCache.mu.Unlock()
		return id
	}
	match := findSystemFont(name, bold, italic)
	if match.path == "" {
		return -1
	}
	id := globalFontCache.addFaceFile(match.path, match.index, name)
	if id < 0 {
		return -1
	}
	globalFontCache.mu.Lock()
	globalFontCache.faceBySpec[fontSpecKey(name, bold, italic)] = id
	globalFontCache.mu.Unlock()
	return id
}

// GlyphFor returns the rasterized glyph for a given face/size/rune.
func GlyphFor(faceID int, size int32, r rune) *GlyphImage {
	if glyph := globalFontCache.GetGlyph(faceID, size, r); glyphHasInk(glyph, r) {
		return glyph
	}
	fallback := globalFontCache.fallbackFace(faceID, r)
	if fallback < 0 || fallback == faceID {
		return nil
	}
	return globalFontCache.GetGlyph(fallback, size, r)
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
	opts := &opentype.FaceOptions{Size: float64(size), DPI: 72, Hinting: font.HintingFull}
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
