package gfx

import "sync"

// DisplayBackend abstracts the presentation target. win32k renders top-level
// windows into per-window Surfaces and presents them; the Wayland backend in
// pkg/wl implements this over wl_shm / dmabuf with a direct fd write, while
// MemoryBackend is a headless implementation for tests and -wayland=false.
type DisplayBackend interface {
	// Size reports the output dimensions in pixels.
	Size() (w, h int)
	// Present pushes a surface to the output, limited to the damaged rectangles
	// (nil/empty damage means the whole surface).
	Present(s *Surface, damage []Rect)
}

// MemoryBackend is a headless DisplayBackend that keeps the last presented frame
// and counts presents - used by tests and headless runs.
type MemoryBackend struct {
	mu       sync.Mutex
	w, h     int
	frame    *Surface
	presents int
	damaged  []Rect
}

// NewMemoryBackend creates a headless backend of the given size.
func NewMemoryBackend(w, h int) *MemoryBackend {
	return &MemoryBackend{w: w, h: h, frame: NewSurface(w, h)}
}

// Size reports the output dimensions.
func (b *MemoryBackend) Size() (int, int) { return b.w, b.h }

// Present composites the damaged regions of s into the kept frame.
func (b *MemoryBackend) Present(s *Surface, damage []Rect) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.presents++
	if len(damage) == 0 {
		damage = []Rect{s.Bounds()}
	}
	b.damaged = append(b.damaged[:0], damage...)
	for _, d := range damage {
		d = d.Intersect(b.frame.Bounds()).Intersect(s.Bounds())
		for y := d.Top; y < d.Bottom; y++ {
			copy(b.frame.Pix[y*b.frame.W+d.Left:y*b.frame.W+d.Right],
				s.Pix[y*s.W+d.Left:y*s.W+d.Right])
		}
	}
}

// Frame returns the last presented frame surface (tests).
func (b *MemoryBackend) Frame() *Surface {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.frame
}

// Presents returns how many times Present was called (tests).
func (b *MemoryBackend) Presents() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.presents
}

// Compositor blits a set of window surfaces onto an output frame in z-order
// (back-to-front) and presents it. It is the bridge from winmgr's z-order to a
// DisplayBackend; the Wayland backend can instead present each window as its own
// wl_surface, but this single-frame compositor is enough for headless rendering
// and tests.
type Compositor struct {
	backend DisplayBackend
	frame   *Surface
}

// NewCompositor creates a compositor for a backend.
func NewCompositor(b DisplayBackend) *Compositor {
	w, h := b.Size()
	return &Compositor{backend: b, frame: NewSurface(w, h)}
}

// Layer is one window's contribution: its surface and screen position.
type Layer struct {
	Surface *Surface
	X, Y    int
}

// Composite blits layers back-to-front (layers[0] is bottom-most) and presents.
func (c *Compositor) Composite(layers []Layer) {
	c.frame.ResetClip()
	c.frame.FillRect(c.frame.Bounds(), 0xFF000000) // clear to black
	for _, l := range layers {
		if l.Surface == nil {
			continue
		}
		c.frame.BitBlt(l.X, l.Y, l.Surface.W, l.Surface.H, l.Surface, 0, 0, SRCCOPY)
	}
	c.backend.Present(c.frame, nil)
}

// Frame returns the compositor's output frame (tests).
func (c *Compositor) Frame() *Surface { return c.frame }
