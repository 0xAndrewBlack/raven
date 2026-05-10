//go:build guest_windows

package gdi

import (
	"sync"
	"testing"
)

func TestManagerConcurrentHandleAccess(t *testing.T) {
	m := NewManager()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				dcHandle, _ := m.AllocMemDC()
				brush := m.CreateSolidBrush(0x123456)
				m.SelectObject(dcHandle, brush)
				_ = m.GetDC(dcHandle)
				_ = m.GetObject(brush)
				m.DeleteObject(brush)
				m.DeleteDC(dcHandle)
			}
		}()
	}
	wg.Wait()
}
