package signal

import "sync"

// Linux signal constants
const (
	SIGHUP    = 1
	SIGINT    = 2
	SIGQUIT   = 3
	SIGILL    = 4
	SIGTRAP   = 5
	SIGABRT   = 6
	SIGBUS    = 7
	SIGFPE    = 8
	SIGKILL   = 9
	SIGSEGV   = 11
	SIGPIPE   = 13
	SIGALRM   = 14
	SIGTERM   = 15
	SIGCHLD   = 17
	SIGCONT   = 18
	SIGSTOP   = 19
	SIGTSTP   = 20
	SIGTTIN   = 21
	SIGTTOU   = 22
	SIGURG    = 23
	SIGXCPU   = 24
	SIGXFSZ   = 25
	SIGVTALRM = 26
	SIGPROF   = 27
	SIGWINCH  = 28
	SIGIO     = 29
	SIGPWR    = 30
	SIGSYS    = 31
	SIGRTMIN  = 32
	NSIG      = 64
)

// SA flags
const (
	SA_NOCLDSTOP = 0x00000001
	SA_NOCLDWAIT = 0x00000002
	SA_SIGINFO   = 0x00000004
	SA_RESTORER  = 0x04000000
	SA_ONSTACK   = 0x08000000
	SA_RESTART   = 0x10000000
	SA_NODEFER   = 0x40000000
)

// SigAction stores a signal handler configuration.
type SigAction struct {
	Handler  uint64 // sa_handler/sa_sigaction address (SIG_DFL=0, SIG_IGN=1)
	Flags    uint64
	Restorer uint64
	Mask     uint64 // sa_mask (simplified: single 64-bit mask)
}

// SignalState manages per-thread signal state.
type SignalState struct {
	mu         sync.Mutex
	Actions    [NSIG + 1]SigAction
	Blocked    uint64 // blocked signal mask
	Pending    uint64 // pending signal bitmap
	AltStack   [3]uint64 // ss_sp, ss_flags, ss_size
}

// New creates a new SignalState with default handlers.
func New() *SignalState {
	return &SignalState{}
}

// SetAction registers a signal handler (rt_sigaction).
func (s *SignalState) SetAction(signum int, act *SigAction) *SigAction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if signum < 1 || signum > NSIG {
		return nil
	}
	// SIGKILL and SIGSTOP cannot be caught
	if signum == SIGKILL || signum == SIGSTOP {
		return nil
	}
	old := s.Actions[signum]
	if act != nil {
		s.Actions[signum] = *act
	}
	return &old
}

// GetAction returns the current handler for a signal.
func (s *SignalState) GetAction(signum int) *SigAction {
	s.mu.Lock()
	defer s.mu.Unlock()
	if signum < 1 || signum > NSIG {
		return nil
	}
	a := s.Actions[signum]
	return &a
}

// SetMask sets the blocked signal mask (rt_sigprocmask).
func (s *SignalState) SetMask(how int, newmask uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.Blocked
	switch how {
	case 0: // SIG_BLOCK
		s.Blocked |= newmask
	case 1: // SIG_UNBLOCK
		s.Blocked &^= newmask
	case 2: // SIG_SETMASK
		s.Blocked = newmask
	}
	// SIGKILL and SIGSTOP can never be blocked
	s.Blocked &^= (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1))
	return old
}

// SetAltStack sets the alternate signal stack (sigaltstack).
func (s *SignalState) SetAltStack(sp, flags, size uint64) (uint64, uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	oldSP, oldFlags, oldSize := s.AltStack[0], s.AltStack[1], s.AltStack[2]
	s.AltStack[0] = sp
	s.AltStack[1] = flags
	s.AltStack[2] = size
	return oldSP, oldFlags, oldSize
}

// Raise marks a signal as pending.
func (s *SignalState) Raise(signum int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if signum >= 1 && signum <= NSIG {
		s.Pending |= 1 << (signum - 1)
	}
}

// DequeueSignal returns the next deliverable (pending & ~blocked) signal, or 0.
func (s *SignalState) DequeueSignal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deliverable := s.Pending & ^s.Blocked
	if deliverable == 0 {
		return 0
	}
	for i := 1; i <= NSIG; i++ {
		bit := uint64(1) << (i - 1)
		if deliverable&bit != 0 {
			s.Pending &^= bit
			return i
		}
	}
	return 0
}

// IsDefault returns true if the handler is SIG_DFL (0).
func (a *SigAction) IsDefault() bool {
	return a.Handler == 0
}

// IsIgnored returns true if the handler is SIG_IGN (1).
func (a *SigAction) IsIgnored() bool {
	return a.Handler == 1
}
