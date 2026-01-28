package d3d9

type VertexBuffer struct {
	Size      uint32
	Usage     uint32
	FVF       uint32
	Pool      uint32
	Data      []byte
	GuestAddr uint64 // guest memory address mapped to Data (set on first Lock)
}

type IndexBuffer struct {
	Size      uint32
	Format    uint32
	Pool      uint32
	Data      []byte
	GuestAddr uint64 // guest memory address mapped to Data (set on first Lock)
}

func (vb *VertexBuffer) Lock(offset, size uint32) []byte {
	if offset >= uint32(len(vb.Data)) {
		return nil
	}
	end := uint32(len(vb.Data))
	if size != 0 && offset+size < end {
		end = offset + size
	}
	return vb.Data[offset:end]
}

func (vb *VertexBuffer) Unlock() {}
