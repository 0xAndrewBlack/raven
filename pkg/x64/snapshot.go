package x64

// Snapshot is a host-side copy of architectural and callback-control CPU state.
type Snapshot struct {
	regs             [16]uint64
	rip              uint64
	rflags           uint64
	fsBase           uint64
	gsBase           uint64
	mode32           bool
	expectedReturnPC uint64
	expectedReturnSP uint64
	xmm              [16][2]uint64
	ymmHi            [16][2]uint64
	fpuST            [8]float64
	fpuTop           int
	fpuCW            uint16
	fpuSW            uint16
	fpuTW            uint16
	mxcsr            uint32
}

// Snapshot returns an independent value copy of architectural and callback-control state.
func (c *CPU) Snapshot() Snapshot {
	return Snapshot{
		regs:             c.Regs,
		rip:              c.RIP,
		rflags:           c.Rflags,
		fsBase:           c.fsBase,
		gsBase:           c.gsBase,
		mode32:           c.Mode32,
		expectedReturnPC: c.ExpectedReturnPC,
		expectedReturnSP: c.ExpectedReturnSP,
		xmm:              c.XMM,
		ymmHi:            c.YMM_hi,
		fpuST:            c.fpuST,
		fpuTop:           c.fpuTop,
		fpuCW:            c.fpuCW,
		fpuSW:            c.fpuSW,
		fpuTW:            c.fpuTW,
		mxcsr:            c.MXCSR,
	}
}

// Restore restores architectural state without rewinding executor state.
func (c *CPU) Restore(snapshot Snapshot) {
	c.Regs = snapshot.regs
	c.RIP = snapshot.rip
	c.Rflags = snapshot.rflags
	c.fsBase = snapshot.fsBase
	c.gsBase = snapshot.gsBase
	c.Mode32 = snapshot.mode32
	c.ExpectedReturnPC = snapshot.expectedReturnPC
	c.ExpectedReturnSP = snapshot.expectedReturnSP
	c.XMM = snapshot.xmm
	c.YMM_hi = snapshot.ymmHi
	c.fpuST = snapshot.fpuST
	c.fpuTop = snapshot.fpuTop
	c.fpuCW = snapshot.fpuCW
	c.fpuSW = snapshot.fpuSW
	c.fpuTW = snapshot.fpuTW
	c.MXCSR = snapshot.mxcsr
	c.InvalidateFetchCache()
}
