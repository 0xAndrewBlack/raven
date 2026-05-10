//go:build guest_windows

package d3d9

import "sync"

type bufferSync struct {
	stateMu sync.Mutex
	dataMu  sync.RWMutex
	locked  bool
}

func (s *bufferSync) beginWrite() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.locked {
		return false
	}
	s.locked = true
	return true
}

func (s *bufferSync) commit(dst, src []byte) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !s.locked {
		return false
	}
	s.dataMu.Lock()
	copy(dst, src)
	s.dataMu.Unlock()
	s.locked = false
	return true
}

type VertexBuffer struct {
	sync      bufferSync
	Size      uint32
	Usage     uint32
	FVF       uint32
	Pool      uint32
	Data      []byte
	Staging   []byte
	GuestAddr uint64
}

type IndexBuffer struct {
	sync      bufferSync
	Size      uint32
	Format    uint32
	Pool      uint32
	Data      []byte
	Staging   []byte
	GuestAddr uint64
}

func (vb *VertexBuffer) BeginGuestWrite() bool { return vb.sync.beginWrite() }
func (vb *VertexBuffer) EndGuestWrite() bool   { return vb.sync.commit(vb.Data, vb.Staging) }
func (vb *VertexBuffer) BeginRead()            { vb.sync.dataMu.RLock() }
func (vb *VertexBuffer) EndRead()              { vb.sync.dataMu.RUnlock() }

func (ib *IndexBuffer) BeginGuestWrite() bool { return ib.sync.beginWrite() }
func (ib *IndexBuffer) EndGuestWrite() bool   { return ib.sync.commit(ib.Data, ib.Staging) }
func (ib *IndexBuffer) BeginRead()            { ib.sync.dataMu.RLock() }
func (ib *IndexBuffer) EndRead()              { ib.sync.dataMu.RUnlock() }

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
