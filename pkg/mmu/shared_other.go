//go:build !linux

package mmu

import "fmt"

func newSharedFile() (int, error) {
	return -1, fmt.Errorf("shared guest backing requires Linux")
}
