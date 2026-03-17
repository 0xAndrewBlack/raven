package gfx

import (
	"image"
	"image/color"
	"os"
	"sync"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

// TrueType is the ONLY text path - there is no bitmap-font fallback (the old
// font8x16 path is the root cause of the "testi sgranati" the project had). Faces
// are loaded from real TTF/OTF files and glyphs are rasterized anti-aliased
// straight into a Surface via font.Drawer (which composites through our
// draw.Image adapter).

// FontCache loads and caches TrueType faces and per-size font.Faces.
type FontCache struct {
	mu    sync.Mutex
	fonts []*opentype.Font // by face id
	faces map[faceKey]font.Face
}

type faceKey struct {
	id     int
	sizePx int
}

// NewFontCache creates an empty font cache.
func NewFontCache() *FontCache { return &FontCache{faces: make(map[faceKey]font.Face)} }

// LoadFile parses a TTF/OTF file and returns its face id (>=0) or an error.
func (c *FontCache) LoadFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1, err
	}
	return c.LoadBytes(data)
}

// LoadBytes parses font bytes and returns its face id.
func (c *FontCache) LoadBytes(data []byte) (int, error) {
	f, err := opentype.Parse(data)
	if err != nil {
		return -1, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fonts = append(c.fonts, f)
	return len(c.fonts) - 1, nil
}

// face returns a cached font.Face for (id, sizePx).
func (c *FontCache) face(id, sizePx int) (font.Face, error) {
	if sizePx <= 0 {
		sizePx = 16
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id < 0 || id >= len(c.fonts) {
		return nil, os.ErrInvalid
	}
	k := faceKey{id, sizePx}
	if fc, ok := c.faces[k]; ok {
		return fc, nil
	}
	fc, err := opentype.NewFace(c.fonts[id], &opentype.FaceOptions{
		Size: float64(sizePx), DPI: 72, Hinting: font.HintingFull,
	})
	if err != nil {
		return nil, err
	}
	c.faces[k] = fc
	return fc, nil
}

// drawImage adapts a Surface to draw.Image so font.Drawer can render into it.
type drawImage struct{ s *Surface }

func (d drawImage) ColorModel() color.Model { return color.RGBAModel }
func (d drawImage) Bounds() image.Rectangle { return image.Rect(0, 0, d.s.W, d.s.H) }
func (d drawImage) At(x, y int) color.Color {
	p := d.s.GetPixel(x, y)
	return color.RGBA{uint8(p >> 16), uint8(p >> 8), uint8(p), uint8(p >> 24)}
}
func (d drawImage) Set(x, y int, c color.Color) {
	r, g, b, a := c.RGBA()
	argb := (a>>8)<<24 | (r>>8)<<16 | (g>>8)<<8 | (b >> 8)
	d.s.SetPixel(x, y, uint32(argb))
}

// DrawText renders text at baseline (x,y) in the given ARGB color using face id
// at sizePx. Returns the advance width in pixels. Anti-aliased.
func (c *FontCache) DrawText(s *Surface, text string, x, y, faceID, sizePx int, argb uint32) (int, error) {
	fc, err := c.face(faceID, sizePx)
	if err != nil {
		return 0, err
	}
	col := color.RGBA{uint8(argb >> 16), uint8(argb >> 8), uint8(argb), uint8(argb >> 24)}
	d := &font.Drawer{
		Dst:  drawImage{s},
		Src:  image.NewUniform(col),
		Face: fc,
		Dot:  fixed.P(x, y),
	}
	start := d.Dot.X
	d.DrawString(text)
	return (d.Dot.X - start).Round(), nil
}

// MeasureText returns the advance width and the face metrics (ascent, descent)
// in pixels for text at face id / sizePx.
func (c *FontCache) MeasureText(text string, faceID, sizePx int) (width, ascent, descent int, err error) {
	fc, err := c.face(faceID, sizePx)
	if err != nil {
		return 0, 0, 0, err
	}
	adv := font.MeasureString(fc, text)
	m := fc.Metrics()
	return adv.Round(), m.Ascent.Round(), m.Descent.Round(), nil
}

// faceCount reports how many faces are loaded (diagnostics/tests).
func (c *FontCache) faceCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.fonts)
}
