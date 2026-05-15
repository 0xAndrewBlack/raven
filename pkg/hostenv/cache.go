package hostenv

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func CacheRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	home, err = resolvePath(home)
	if err != nil {
		return "", fmt.Errorf("resolve user home path: %w", err)
	}
	root := os.Getenv("RAVEN_CACHE_ROOT")
	if root == "" {
		cacheDir, cacheErr := os.UserCacheDir()
		if cacheErr != nil {
			return "", fmt.Errorf("resolve user cache directory: %w", cacheErr)
		}
		root = filepath.Join(cacheDir, "raven")
	}
	root, err = resolvePath(root)
	if err != nil {
		return "", fmt.Errorf("resolve Raven cache root: %w", err)
	}
	if root == home || !pathWithin(home, root) {
		return "", fmt.Errorf("Raven cache root %q is outside user home %q", root, home)
	}
	return root, nil
}

func TempDir() (string, error) {
	root, err := CacheRoot()
	if err != nil {
		return "", err
	}
	dir := os.Getenv("RAVEN_TMPDIR")
	if dir == "" {
		dir = filepath.Join(root, "tmp")
	}
	dir, err = resolvePath(dir)
	if err != nil {
		return "", fmt.Errorf("resolve Raven temporary directory: %w", err)
	}
	if !pathWithin(root, dir) {
		return "", fmt.Errorf("Raven temporary directory %q is outside cache root %q", dir, root)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create Raven temporary directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("secure Raven temporary directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("verify Raven temporary directory: %w", err)
	}
	if !pathWithin(root, resolved) {
		return "", fmt.Errorf("Raven temporary directory %q escapes cache root %q", resolved, root)
	}
	return resolved, nil
}

func resolvePath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolute)
	var missing []string
	for {
		resolved, evalErr := filepath.EvalSymlinks(current)
		if evalErr == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(evalErr, fs.ErrNotExist) {
			return "", evalErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", evalErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func pathWithin(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
