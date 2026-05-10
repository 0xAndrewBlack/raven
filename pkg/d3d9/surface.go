//go:build guest_windows

package d3d9

type Surface struct {
	Width     uint32
	Height    uint32
	Format    uint32
	Pool      uint32
	Data      []byte
	GuestAddr uint64
	Locked    bool
}

type Texture struct {
	Levels []*Surface
	Format uint32
	Pool   uint32
	Usage  uint32
}

func NewTexture(width, height, levels uint32, format, pool uint32) *Texture {
	if levels == 0 {
		levels = 1
		for w, h := width, height; w > 1 || h > 1; {
			levels++
			if w > 1 {
				w >>= 1
			}
			if h > 1 {
				h >>= 1
			}
		}
	}

	tex := &Texture{
		Levels: make([]*Surface, 0, levels),
		Format: format,
		Pool:   pool,
	}
	w, h := width, height
	for i := uint32(0); i < levels; i++ {
		if w == 0 {
			w = 1
		}
		if h == 0 {
			h = 1
		}
		tex.Levels = append(tex.Levels, &Surface{
			Width:  w,
			Height: h,
			Format: format,
			Pool:   pool,
			Data:   make([]byte, surfaceDataSize(w, h, format)),
		})
		if w > 1 {
			w >>= 1
		}
		if h > 1 {
			h >>= 1
		}
	}
	return tex
}

func (s *Surface) Lock(rect *Rect) (pitch int, data []byte) {
	s.Locked = true
	return surfacePitch(s.Width, s.Format), s.Data
}

func (s *Surface) Unlock() {
	s.Locked = false
}

func surfacePitch(width, format uint32) int {
	switch format {
	case D3DFMT_DXT1:
		return int(((width + 3) / 4) * 8)
	case D3DFMT_DXT2, D3DFMT_DXT3, D3DFMT_DXT4, D3DFMT_DXT5:
		return int(((width + 3) / 4) * 16)
	default:
		return int(width) * bytesPerPixel(format)
	}
}

func surfaceDataSize(width, height, format uint32) int {
	switch format {
	case D3DFMT_DXT1:
		return int(((width + 3) / 4) * ((height + 3) / 4) * 8)
	case D3DFMT_DXT2, D3DFMT_DXT3, D3DFMT_DXT4, D3DFMT_DXT5:
		return int(((width + 3) / 4) * ((height + 3) / 4) * 16)
	default:
		return int(width) * int(height) * bytesPerPixel(format)
	}
}

func bytesPerPixel(format uint32) int {
	switch format {
	case D3DFMT_R8G8B8:
		return 3
	case D3DFMT_R5G6B5, D3DFMT_X1R5G5B5, D3DFMT_A1R5G5B5, D3DFMT_A4R4G4B4, D3DFMT_A8L8, D3DFMT_G16R16, D3DFMT_V16U16, D3DFMT_L16, D3DFMT_R16F:
		return 2
	case D3DFMT_A16B16G16R16, D3DFMT_A16B16G16R16F, D3DFMT_G32R32F:
		return 8
	case D3DFMT_A32B32G32R32F:
		return 16
	default:
		return 4
	}
}
