package win32k

import (
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

// TrapDispatcher routes Win32k (Shadow SSDT) syscalls to the appropriate handler.
// In the NT kernel, Win32k has its own syscall table separate from ntoskrnl.
// We intercept these via the synthetic win32u.dll.
type TrapDispatcher struct {
	win32k *Win32kSubsystem
	gdi    *GDISubsystem
}

// NewTrapDispatcher creates a Win32k trap dispatcher and registers all handlers.
func NewTrapDispatcher(w *Win32kSubsystem, g *GDISubsystem) *TrapDispatcher {
	return &TrapDispatcher{
		win32k: w,
		gdi:    g,
	}
}

// RegisterAll registers all Win32k handlers with the NTAPI dispatcher.
func (td *TrapDispatcher) RegisterAll(d *ntapi.Dispatcher) {
	td.win32k.RegisterHandlers(d)
	td.gdi.RegisterHandlers(d)
}
