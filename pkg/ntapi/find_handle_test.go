//go:build guest_windows

package ntapi

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFindHandleNextIsConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	const entryCount = 100
	for i := 0; i < entryCount; i++ {
		path := filepath.Join(dir, fmt.Sprintf("entry-%03d", i))
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	handle := &FindHandle{Entries: entries}

	names := make(chan string, entryCount)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				entry, _, _, ok := handle.Next()
				if !ok {
					return
				}
				names <- entry.Name()
			}
		}()
	}
	wg.Wait()
	close(names)

	seen := make(map[string]bool)
	for name := range names {
		if seen[name] {
			t.Fatalf("duplicate entry %q", name)
		}
		seen[name] = true
	}
	if len(seen) != entryCount {
		t.Fatalf("got %d entries, want %d", len(seen), entryCount)
	}
}
