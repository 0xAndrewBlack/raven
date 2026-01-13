package gdi

import "sync"

// Metafile provides basic Win32 metafile (WMF/EMF) handle management.
// ReactOS: win32ss/gdi/ntgdi/metafile.c
//
// We don't record or play back GDI commands, but we track the metafile
// handles so that Create/Close/Delete/Play follow correct lifecycle
// semantics and return proper values.

// MetafileType distinguishes WMF from EMF.
type MetafileType int

const (
	MetafileWMF MetafileType = iota
	MetafileEMF
)

// MetafileRecord represents a created metafile.
type MetafileRecord struct {
	Type   MetafileType
	File   string // output file path ("" = memory metafile)
	DC     uint64 // associated DC handle during recording (0 after close)
	Closed bool   // true after CloseMetaFile/CloseEnhMetaFile
}

// MetafileManager tracks metafile handles.
type MetafileManager struct {
	mu    sync.Mutex
	files map[uint64]*MetafileRecord
	next  uint64
}

// NewMetafileManager creates a new metafile manager.
func NewMetafileManager() *MetafileManager {
	return &MetafileManager{
		files: make(map[uint64]*MetafileRecord),
		next:  0xEE000001,
	}
}

// Create registers a new metafile being recorded into the given DC.
// Returns a metafile handle.
func (m *MetafileManager) Create(mfType MetafileType, dcHandle uint64, file string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.next
	m.next++
	m.files[h] = &MetafileRecord{
		Type: mfType,
		File: file,
		DC:   dcHandle,
	}
	return h
}

// Close marks a metafile as closed (no longer recording).
// Returns the metafile handle (like the real API).
// ReactOS: CloseMetaFile returns HMETAFILE, CloseEnhMetaFile returns HENHMETAFILE.
func (m *MetafileManager) Close(dcHandle uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, rec := range m.files {
		if rec.DC == dcHandle && !rec.Closed {
			rec.Closed = true
			rec.DC = 0
			return h
		}
	}
	return 0
}

// Delete removes a metafile handle.
// ReactOS: DeleteMetaFile / DeleteEnhMetaFile
func (m *MetafileManager) Delete(handle uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.files[handle]; ok {
		delete(m.files, handle)
		return true
	}
	return false
}

// Get returns the metafile record, or nil if not found.
func (m *MetafileManager) Get(handle uint64) *MetafileRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.files[handle]
}

// Play "plays" a metafile into a DC.
// Since we don't actually record GDI commands, this is a successful no-op.
// ReactOS: PlayMetaFile / PlayEnhMetaFile iterate stored records.
func (m *MetafileManager) Play(handle uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.files[handle]
	if !ok || !rec.Closed {
		return false
	}
	return true
}
