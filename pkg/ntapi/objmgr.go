//go:build guest_windows

package ntapi

import "github.com/mirkobrombin/Raven/pkg/ntobj"

// ObjMgr is the process-wide in-process NT object manager (the wineserver
// replacement, pkg/ntobj). It backs the waitable handle types - events,
// mutants, semaphores - so they share one locking discipline and one wait
// engine (correct atomic WaitAll, no lost wakeups). One per emulated machine.
var ObjMgr = ntobj.New()

// WaitableFor returns the ntobj.Waitable behind a handle, or nil if the handle
// is not one of the unified waitable types (event/mutant/semaphore). Used by
// WaitForMultipleObjects to run an atomic multi-object wait through the engine.
func (ht *HandleTable) WaitableFor(h Handle) ntobj.Waitable {
	switch o := ht.Get(h).(type) {
	case *EventHandle:
		return o.Waitable()
	case *MutantHandle:
		return o.Waitable()
	case *SemaphoreHandle:
		return o.Waitable()
	case *WaitableTimerHandle:
		return o.Waitable()
	default:
		return nil
	}
}
