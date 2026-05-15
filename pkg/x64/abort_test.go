package x64

import (
	"testing"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

func TestAbortPersistsAcrossResume(t *testing.T) {
	cpu := New(mmu.New())
	want := &arch.ExitError{Code: int(0xC0000417)}

	cpu.Resume()
	cpu.Abort(want)
	cpu.Resume()

	if got := cpu.Run(); got != want {
		t.Fatalf("Run() error = %v, want abort error", got)
	}
}
