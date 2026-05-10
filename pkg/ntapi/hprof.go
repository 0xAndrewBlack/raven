//go:build guest_windows

package ntapi

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

// handlerProfiler counts trap-handler dispatches per trapID and periodically
// reports the busiest handlers. It exists to pinpoint hot API-call loops (for
// example a game that hammers one D3D9 method every frame) without attaching a
// debugger. Gated by RAVEN_PROFILE_HANDLERS; zero cost when disabled.
type handlerProfiler struct {
	total  atomic.Uint64
	lastPC atomic.Uint64
	lastID atomic.Uint32
	counts sync.Map // uint32 trapID -> *atomic.Uint64
	names  func(uint32) string
}

func (p *handlerProfiler) record(id uint32, pc uint64) {
	p.total.Add(1)
	p.lastID.Store(id)
	p.lastPC.Store(pc)
	if v, ok := p.counts.Load(id); ok {
		v.(*atomic.Uint64).Add(1)
		return
	}
	c := new(atomic.Uint64)
	c.Add(1)
	actual, _ := p.counts.LoadOrStore(id, c)
	if actual != c {
		actual.(*atomic.Uint64).Add(1)
	}
}

// report logs the call rate and the top handlers seen since the last interval.
func (p *handlerProfiler) report(prevTotal uint64, dt time.Duration) uint64 {
	total := p.total.Load()
	rate := float64(total-prevTotal) / dt.Seconds()

	type kv struct {
		id    uint32
		count uint64
	}
	// Per-interval top: read-and-reset each counter so the report reflects what
	// is hot *now*, not cumulative totals dominated by the init allocation burst.
	var top []kv
	p.counts.Range(func(k, v any) bool {
		c := v.(*atomic.Uint64).Swap(0)
		if c > 0 {
			top = append(top, kv{k.(uint32), c})
		}
		return true
	})
	sort.Slice(top, func(i, j int) bool { return top[i].count > top[j].count })

	line := ""
	for i := 0; i < len(top) && i < 5; i++ {
		name := p.names(top[i].id)
		if name == "" {
			name = "unknown"
		}
		if i > 0 {
			line += " "
		}
		line += name + "=" + itoa(top[i].count)
	}
	ravelog.Logf("[hprof] %.0f calls/s total=%d lastPC=0x%x top: %s\n",
		rate, total, p.lastPC.Load(), line)
	return total
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// EnableHandlerProfile turns on periodic hot-handler reporting on this
// dispatcher and starts the reporter goroutine.
func (d *Dispatcher) EnableHandlerProfile() {
	p := &handlerProfiler{names: func(id uint32) string { return d.names[id] }}
	d.hprof = p
	go func() {
		const interval = 2 * time.Second
		var prev uint64
		for {
			time.Sleep(interval)
			prev = p.report(prev, interval)
		}
	}()
}

// EnableStdcallTrace logs stdcall cleanups whose return address is in the
// guest's own code range, to locate a call that misaligns the stack.
func (d *Dispatcher) EnableStdcallTrace() { d.traceStdcall = true }
