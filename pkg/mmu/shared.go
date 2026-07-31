package mmu

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

type SharedMapping struct {
	Address uint64
	Size    uint64
	Offset  int64
	Perms   uint8
}

type sharedPage struct {
	data   []byte
	offset int64
}

type sharedBacking struct {
	fd     int
	chunks [][]byte
	pages  map[uint64]sharedPage
	next   int64
	err    error
}

// EnableSharedBacking must run before mapping pages. The file offsets describe
// backing storage, not guest addresses; sparse PE64 addresses need no huge file.
func (m *MMU) EnableSharedBacking() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shared != nil {
		return nil
	}
	if m.flat != nil || m.MappingGeneration() != 0 {
		return fmt.Errorf("shared backing requires an unmapped MMU")
	}
	fd, err := newSharedFile()
	if err != nil {
		return err
	}
	m.shared = &sharedBacking{fd: fd, pages: make(map[uint64]sharedPage)}
	return nil
}

func (b *sharedBacking) page(addr uint64) ([]byte, error) {
	if p, ok := b.pages[addr]; ok {
		return p.data, nil
	}
	const chunkSize = 1 << 20
	if b.next%chunkSize == 0 {
		if err := unix.Ftruncate(b.fd, b.next+chunkSize); err != nil {
			b.err = err
			return nil, err
		}
		chunk, err := unix.Mmap(b.fd, b.next, chunkSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			b.err = err
			return nil, err
		}
		b.chunks = append(b.chunks, chunk)
	}
	start := int(b.next % chunkSize)
	data := b.chunks[len(b.chunks)-1][start : start+PageSize : start+PageSize]
	b.pages[addr] = sharedPage{data: data, offset: b.next}
	b.next += PageSize
	return data, nil
}

func (m *MMU) SharedFD() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shared == nil {
		return -1, fmt.Errorf("shared backing is disabled")
	}
	return m.shared.fd, nil
}

// SharedMappings coalesces pages only when both guest addresses and file
// offsets are adjacent. External host slices cannot be mapped from this file.
func (m *MMU) SharedMappings() ([]SharedMapping, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shared == nil {
		return nil, fmt.Errorf("shared backing is disabled")
	}
	for addr := range m.pages {
		if _, ok := m.shared.pages[addr]; !ok {
			return nil, fmt.Errorf("external host mapping at 0x%x is unavailable in direct mode", addr)
		}
	}
	var mappings []SharedMapping
	for addr, backing := range m.shared.pages {
		pe := m.getPage(addr)
		if pe == nil {
			continue
		}
		if &pe.Data[0] != &backing.data[0] {
			return nil, fmt.Errorf("page at 0x%x has different backing", addr)
		}
		mappings = append(mappings, SharedMapping{Address: addr, Size: PageSize, Offset: backing.offset, Perms: pe.Perms})
	}
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].Address < mappings[j].Address })
	result := mappings[:0]
	for _, mapping := range mappings {
		if len(result) != 0 {
			last := &result[len(result)-1]
			if last.Address+last.Size == mapping.Address && last.Offset+int64(last.Size) == mapping.Offset && last.Perms == mapping.Perms {
				last.Size += mapping.Size
				continue
			}
		}
		result = append(result, mapping)
	}
	return result, nil
}

// CloseSharedBacking unmaps owned pages after every guest CPU has stopped.
// Borrowed PageEntry slices must not be accessed after this call.
func (m *MMU) CloseSharedBacking() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shared == nil {
		return nil
	}
	m.beginMappingMutation()
	defer m.endMappingMutation()
	for addr, backing := range m.shared.pages {
		if pe := m.getPage(addr); pe != nil && &pe.Data[0] == &backing.data[0] {
			m.removePage(addr)
		}
	}
	clear(m.pages)
	var first error
	for _, chunk := range m.shared.chunks {
		if err := unix.Munmap(chunk); err != nil && first == nil {
			first = err
		}
	}
	if err := unix.Close(m.shared.fd); err != nil && first == nil {
		first = err
	}
	m.shared = nil
	return first
}
