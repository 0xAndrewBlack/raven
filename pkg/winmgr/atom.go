package winmgr

import "sync"

// AtomTable implements the string-interning used by RegisterWindowMessage and
// the global/local atom tables: a name maps to a stable unique id, and the same
// name always returns the same id. Class atoms live in Manager (0xC000+ range);
// this table serves RegisterWindowMessageW (0xC000+ message ids) and
// GlobalAddAtom (0xC000+ atoms).
type AtomTable struct {
	mu     sync.Mutex
	next   uint32
	byName map[string]uint32
	byID   map[uint32]string
	refs   map[uint32]int32
}

// NewAtomTable creates an atom table starting at the given base id.
func NewAtomTable(base uint32) *AtomTable {
	if base == 0 {
		base = 0xC000
	}
	return &AtomTable{
		next:   base,
		byName: make(map[string]uint32),
		byID:   make(map[uint32]string),
		refs:   make(map[uint32]int32),
	}
}

// Add interns name and returns its id, incrementing its reference count
// (GlobalAddAtom). The same name always yields the same id.
func (t *AtomTable) Add(name string) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.byName[name]; ok {
		t.refs[id]++
		return id
	}
	id := t.next
	t.next++
	t.byName[name] = id
	t.byID[id] = name
	t.refs[id] = 1
	return id
}

// Find returns the id for name without adding it (FindAtom); 0 if absent.
func (t *AtomTable) Find(name string) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byName[name]
}

// Name returns the name for an id (GlobalGetAtomName); "" if absent.
func (t *AtomTable) Name(id uint32) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byID[id]
}

// Delete drops one reference (GlobalDeleteAtom); the atom is removed at zero.
// RegisterWindowMessage atoms are never ref-counted away in practice, so callers
// for those should not Delete.
func (t *AtomTable) Delete(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.refs[id] <= 0 {
		return
	}
	t.refs[id]--
	if t.refs[id] == 0 {
		name := t.byID[id]
		delete(t.byName, name)
		delete(t.byID, id)
		delete(t.refs, id)
	}
}
