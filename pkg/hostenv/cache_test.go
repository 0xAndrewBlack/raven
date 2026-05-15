package hostenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTempDirDefaultsToUserCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("RAVEN_CACHE_ROOT", "")
	t.Setenv("RAVEN_TMPDIR", "")

	dir, err := TempDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "cache", "raven", "tmp")
	if dir != want {
		t.Fatalf("TempDir() = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("%q is not a directory", dir)
	}
}

func TestTempDirHonorsExplicitRavenDirectory(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "cache", "raven")
	dir := filepath.Join(root, "raven-work")
	t.Setenv("HOME", home)
	t.Setenv("RAVEN_CACHE_ROOT", root)
	t.Setenv("RAVEN_TMPDIR", dir)

	got, err := TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Fatalf("TempDir() = %q, want %q", got, dir)
	}
}

func TestTempDirRejectsPathOutsideCacheRoot(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, "cache", "raven")
	t.Setenv("HOME", home)
	t.Setenv("RAVEN_CACHE_ROOT", root)
	t.Setenv("RAVEN_TMPDIR", filepath.Join(home, "outside"))

	if _, err := TempDir(); err == nil {
		t.Fatal("TempDir accepted a path outside the Raven cache root")
	}
}

func TestCacheRootRejectsSymlinkOutsideHome(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "home")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "cache-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("RAVEN_CACHE_ROOT", filepath.Join(link, "raven"))

	if _, err := CacheRoot(); err == nil {
		t.Fatal("CacheRoot accepted a symlink outside HOME")
	}
}
