//go:build guest_windows

package d3d9

import (
	"os"
	"sync"
	"testing"
)

func TestConcurrentRendererLifecycle(t *testing.T) {
	if os.Getenv("RAVEN_VK_INTEGRATION") != "1" {
		t.Skip("set RAVEN_VK_INTEGRATION=1 to run Vulkan integration tests")
	}

	const count = 4
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			renderer, err := NewRenderer(64, 64)
			if err == nil {
				renderer.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
