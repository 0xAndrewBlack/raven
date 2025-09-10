package syscall

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mirkobrombin/go-vm/pkg/arch"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
	"github.com/mirkobrombin/go-vm/pkg/signal"
	"github.com/mirkobrombin/go-vm/pkg/thread"
	"github.com/mirkobrombin/go-vm/pkg/vfs"
)

// Linux RISC-V syscall numbers (from asm-generic/unistd.h)
const (
	SysGetcwd         = 17
	SysDup            = 23
	SysDup3           = 24
	SysFcntl          = 25
	SysIoctl          = 29
	SysMkdirat        = 34
	SysUnlinkat       = 35
	SysSymlinkat      = 36
	SysLinkat         = 37
	SysFaccessat      = 48
	SysChdir          = 49
	SysFchmod         = 52
	SysFchmodat       = 53
	SysFchownat       = 54
	SysFchown         = 55
	SysOpenat         = 56
	SysClose          = 57
	SysPipe2          = 59
	SysGetdents64     = 61
	SysLseek          = 62
	SysRead           = 63
	SysWrite          = 64
	SysReadv          = 65
	SysWritev         = 66
	SysPread64        = 67
	SysPwrite64       = 68
	SysPselect6       = 72
	SysPpoll          = 73
	sysPoll           = 10025 // internal: x64 poll(fds, nfds, timeout_ms)
	SysReadlinkat     = 78
	SysFstatat        = 79
	SysFstat          = 80
	SysFsync          = 82
	SysFdatasync      = 83
	SysFtruncate      = 46
	SysFallocate      = 47
	SysUtimensat      = 88
	SysExit           = 93
	SysExitGroup      = 94
	SysSetTidAddress  = 96
	SysFutex          = 98
	SysSetRobustList  = 99
	SysNanosleep      = 101
	SysGetitimer      = 102
	SysSetitimer      = 103
	SysClockGettime   = 113
	SysClockGetres    = 114
	SysClockNanosleep = 115
	SysSyslog         = 116
	SysSchedSetaffinity = 122
	SysSchedGetaffinity = 123
	SysSchedYield     = 124
	SysKill           = 129
	SysTkill          = 130
	SysTgkill         = 131
	SysSigaltstack    = 132
	SysRtSigaction    = 134
	SysRtSigprocmask  = 135
	SysRtSigreturn    = 139
	SysTimes          = 153
	SysUname          = 160
	SysSync           = 162
	SysUmask          = 166
	SysPrctl          = 167
	SysGetrusage      = 165
	SysGetpid         = 172
	SysGetppid        = 173
	SysGetuid         = 174
	SysGeteuid        = 175
	SysGetgid         = 176
	SysGetegid        = 177
	SysGetresuid      = 10095
	SysGetresgid      = 10096
	SysMincore        = 10097
	SysGettid         = 178
	SysSysinfo        = 179
	SysSocket         = 198
	SysBind           = 200
	SysListen         = 201
	SysAccept         = 202
	SysConnect        = 203
	SysSendto         = 206
	SysRecvfrom       = 207
	SysSetsockopt     = 208
	SysGetsockopt     = 209
	SysShutdown       = 210
	SysSendmsg        = 211
	SysRecvmsg        = 212
	SysBrk            = 214
	SysMunmap         = 215
	SysMremap         = 216
	SysClone          = 220
	SysExecve         = 221
	SysMmap           = 222
	SysFadvise64      = 223
	SysSwapon         = 224
	SysMprotect       = 226
	SysMsync          = 227
	SysMlock          = 228
	SysMunlock        = 229
	SysMadvise        = 233
	SysAccept4        = 242
	SysWait4          = 260
	SysPrlimit64      = 261
	SysRenameat2      = 276
	SysGetrandom      = 278
	SysMembarrier     = 283
	SysStatx          = 291
	SysRseq           = 293
	SysEpollCreate1   = 20
	SysEpollCtl       = 21
	SysEpollPwait     = 22
	SysEventfd2       = 19
	SysTimerfdCreate  = 85
	SysTimerfdSettime = 86
	SysTimerfdGettime = 87
	SysSocketpair     = 199
	SysGetsockname    = 204
	SysGetpeername    = 205
	SysMemfdCreate    = 279
	SysKcmp           = 10091 // internal, mapped from x86-64 kcmp (SYS 253)
	SysRiscvHwprobe   = 258
	SysArchPrctl      = 259 // internal, mapped from x86-64 arch_prctl
	SysSendfile       = 262 // internal, mapped from x86-64 sendfile

	SysClone3 = 10090 // internal, mapped from x86-64 clone3 (SYS 435)

	// Legacy x64 syscalls that need arg remapping to their *at variants.
	// These use high numbers to avoid collisions with RISC-V generic numbers.
	sysX64Open     = 10002
	sysX64Stat     = 10004
	sysX64Lstat    = 10006
	sysX64Access   = 10021
	sysX64Rename   = 10082
	sysX64Mkdir    = 10083
	sysX64Unlink   = 10087
	sysX64Symlink  = 10088
	sysX64Readlink = 10089
)

// Handler holds the synthetic kernel state.
type Handler struct {
	Mem     *mmu.MMU
	FS      *vfs.VFS
	ThreadM *thread.Manager
	Signals *signal.SignalState
	Umask   uint32    // current umask
	Trace   bool      // trace syscalls to stderr
	Arch    arch.Arch // guest architecture
	debugX11 bool     // trace all syscalls (for X11 debugging)

	clearChildTidMu sync.Mutex
	clearChildTid   map[int]uint64 // TID → clear_child_tid address

	// temporary debug: count syscalls by number
	// vfork / posix_spawn subprocess support.
	// When the guest calls clone(CLONE_VFORK) or clone3(CLONE_VFORK),
	// we record a pending vfork state. The child goroutine runs until it
	// calls execve (which launches a real host process) or exit, then
	// unblocks the parent via vforkDone.
	vforkMu       sync.Mutex
	vforkPending  bool            // true while a vfork child is running
	vforkDone     chan int         // child sends guest PID after execve/exit
	vforkSnapshot vfs.FDSnapshot  // parent FD table saved before vfork child runs

	// host child processes spawned via execve-in-vfork-child, keyed by guest PID.
	childMu    sync.Mutex
	childProcs map[int]*os.Process // guest pid → host *os.Process
	nextGPID   int                 // monotonic guest PID counter (starts at 2)
}

// NewHandler creates a syscall handler wired to the given MMU and VFS.
func NewHandler(mem *mmu.MMU, fs *vfs.VFS) *Handler {
	h := &Handler{
		Mem:        mem,
		FS:         fs,
		Signals:    signal.New(),
		Umask:      0022,
		childProcs: make(map[int]*os.Process),
		nextGPID:   2,
	}
	return h
}

// Handle is the SyscallHandler callback for the CPU.
func (h *Handler) Handle(c arch.CPU) {
	num := c.SyscallNum()
	if c.GetArch() == arch.ArchAMD64 {
		num = x64SyscallToRV(num)
	}
	args := c.SyscallArgs()
	a0, a1, a2, a3, a4, a5 := args[0], args[1], args[2], args[3], args[4], args[5]

	if h.debugX11 {
		fmt.Fprintf(os.Stderr, "[x11-trace] syscall %d (a0=0x%x a1=0x%x a2=0x%x)\n", num, a0, a1, a2)
	}

	if h.Trace {
		fmt.Fprintf(os.Stderr, "[trace] syscall %d (a0=0x%x a1=0x%x a2=0x%x a3=0x%x) instret=%d\n", num, a0, a1, a2, a3, c.GetInstret())
	}

	// DEBUG: heap integrity check before/after each syscall
	var heapSigBefore uint64
	if h.Trace {
		heapSigBefore = h.heapSignature()
		if heapSigBefore != 0 {
			fmt.Fprintf(os.Stderr, "[heap-sig] before syscall %d: 0x%x\n", num, heapSigBefore)
		}
	}
	defer func() {
		if h.Trace {
			after := h.heapSignature()
			if after != 0 {
				fmt.Fprintf(os.Stderr, "[heap-sig] after syscall %d: 0x%x\n", num, after)
			}
			if heapSigBefore != 0 && after != 0 && heapSigBefore != after {
				fmt.Fprintf(os.Stderr, "[HEAP-CORRUPT] syscall %d (a0=0x%x a1=0x%x a2=0x%x) changed heap sig 0x%x→0x%x instret=%d\n",
					num, a0, a1, a2, heapSigBefore, after, c.GetInstret())
			}
		}
	}()

	switch num {
	// --- I/O ---
	case SysWrite:
		h.sysWrite(c, a0, a1, a2)
	case SysWritev:
		h.sysWritev(c, a0, a1, a2)
	case SysReadv:
		h.sysReadv(c, a0, a1, a2)
	case SysRead:
		h.sysRead(c, a0, a1, a2)
	case SysPread64:
		h.sysPread64(c, a0, a1, a2, a3)
	case SysPwrite64:
		h.sysPwrite64(c, a0, a1, a2, a3)

	// --- Process lifecycle ---
	case SysExit, SysExitGroup:
		c.Stop()
		c.SetSyscallReturn(a0)

	// --- Memory management ---
	case SysBrk:
		result := h.Mem.Brk(a0)
		if h.Trace {
			fmt.Fprintf(os.Stderr, "[brk] req=0x%x → 0x%x\n", a0, result)
			if a0 != 0 && result == a0 {
				// Dump first 128 bytes of the heap region
				heapBase := h.Mem.GetBrkBase()
				if data, err := h.Mem.ReadBytes(heapBase, 128); err == nil {
					fmt.Fprintf(os.Stderr, "[brk] heap@0x%x: %x\n", heapBase, data)
				}
			}
		}
		c.SetSyscallReturn(result)
	case SysMmap:
		h.sysMmap(c)
	case SysMunmap:
		if h.ThreadM != nil && h.ThreadM.IsThreadStack(a0, a1) {
			// The parent is trying to munmap a live thread's stack (common in
			// Rust/glibc clone3 patterns where the parent frees the stack
			// allocation immediately after clone3). Skip the unmap so the child
			// goroutine can execute; the stack is unregistered when the thread exits.
			c.SetSyscallReturn(0)
			break
		}
		h.Mem.Munmap(a0, a1)
		c.SetSyscallReturn(0)
	case SysMprotect:
		h.sysMprotect(c, a0, a1, a2)
	case SysMremap:
		h.sysMremap(c, a0, a1, a2, a3, a4)
	case SysMadvise:
		h.sysMadvise(c, a0, a1, a2)
	case SysMsync, SysMlock, SysMunlock:
		c.SetSyscallReturn(0)

	// --- Filesystem ---
	case SysOpenat:
		h.sysOpenat(c, a0, a1, a2, a3)
	case sysX64Open: // x64 open(pathname, flags, mode) → openat(AT_FDCWD, ...)
		h.sysOpenat(c, atFDCWD, a0, a1, a2)
	case SysClose:
		if err := h.FS.Close(int(a0)); err != nil {
			c.SetSyscallReturn(negErrno(EBADF))
		} else {
			c.SetSyscallReturn(0)
		}
	case SysFstat:
		h.sysFstat(c, a0, a1)
	case SysFstatat:
		h.sysFstatat(c, a0, a1, a2)
	case sysX64Stat: // x64 stat(pathname, statbuf) → fstatat(AT_FDCWD, ...)
		h.sysFstatat(c, atFDCWD, a0, a1)
	case sysX64Lstat: // x64 lstat(pathname, statbuf) → fstatat(AT_FDCWD, ...)
		h.sysFstatat(c, atFDCWD, a0, a1)
	case SysStatx:
		h.sysStatx(c, a0, a1, a2, a3, a4)
	case SysLseek:
		h.sysLseek(c, a0, a1, a2)
	case SysDup:
		h.sysDup(c, a0)
	case SysDup3:
		h.sysDup3(c, a0, a1)
	case SysPipe2:
		h.sysPipe2(c, a0, a1)
	case SysFcntl:
		h.sysFcntl(c, a0, a1, a2)
	case SysIoctl:
		h.sysIoctl(c, a0, a1)
	case SysGetdents64:
		h.sysGetdents64(c, a0, a1, a2)
	case SysReadlinkat:
		h.sysReadlinkat(c, a0, a1, a2, a3)
	case sysX64Readlink: // x64 readlink(pathname, buf, bufsiz) → readlinkat(AT_FDCWD, ...)
		h.sysReadlinkat(c, atFDCWD, a0, a1, a2)
	case SysFaccessat:
		h.sysFaccessat(c, a0, a1)
	case sysX64Access: // x64 access(pathname, mode) → faccessat(AT_FDCWD, ...)
		h.sysFaccessat(c, atFDCWD, a0)
	case SysGetcwd:
		h.sysGetcwd(c, a0, a1)
	case SysMkdirat:
		h.sysMkdirat(c, a0, a1, a2)
	case sysX64Mkdir: // x64 mkdir(pathname, mode) → mkdirat(AT_FDCWD, ...)
		h.sysMkdirat(c, atFDCWD, a0, a1)
	case SysUnlinkat:
		h.sysUnlinkat(c, a0, a1, a2)
	case sysX64Unlink: // x64 unlink(pathname) → unlinkat(AT_FDCWD, pathname, 0)
		h.sysUnlinkat(c, atFDCWD, a0, 0)
	case SysChdir:
		h.sysChdir(c, a0)
	case SysFchmod, SysFchmodat, SysFchownat, SysFchown:
		c.SetSyscallReturn(0)
	case SysFsync, SysFdatasync, SysFadvise64:
		c.SetSyscallReturn(0)
	case SysSync:
		c.SetSyscallReturn(0)
	case SysFtruncate:
		h.sysFtruncate(c, a0, a1)
	case SysFallocate:
		h.sysFallocate(c, a0, a1, a2, a3)
	case SysUtimensat:
		c.SetSyscallReturn(0)
	case SysSymlinkat:
		h.sysSymlinkat(c, a0, a1, a2)
	case sysX64Symlink: // x64 symlink(target, linkpath) → symlinkat(target, AT_FDCWD, linkpath)
		h.sysSymlinkat(c, a0, atFDCWD, a1)
	case SysLinkat:
		c.SetSyscallReturn(negErrno(ENOSYS))
	case SysRenameat2:
		h.sysRenameat(c, a0, a1, a2, a3)
	case sysX64Rename: // x64 rename(oldpath, newpath) → renameat(AT_FDCWD, old, AT_FDCWD, new)
		h.sysRenameat(c, atFDCWD, a0, atFDCWD, a1)

	// --- Process/Thread info ---
	case SysGetuid, SysGeteuid, SysGetgid, SysGetegid:
		c.SetSyscallReturn(1000)
	case SysGetresuid:
		// getresuid(ruid, euid, suid) - stub: all UIDs = 1000
		if a0 != 0 {
			h.Mem.Write32(a0, 1000)
		}
		if a1 != 0 {
			h.Mem.Write32(a1, 1000)
		}
		if a2 != 0 {
			h.Mem.Write32(a2, 1000)
		}
		c.SetSyscallReturn(0)
	case SysGetresgid:
		// getresgid(rgid, egid, sgid) - stub: all GIDs = 1000
		if a0 != 0 {
			h.Mem.Write32(a0, 1000)
		}
		if a1 != 0 {
			h.Mem.Write32(a1, 1000)
		}
		if a2 != 0 {
			h.Mem.Write32(a2, 1000)
		}
		c.SetSyscallReturn(0)
	case SysGetpid, SysGetppid:
		c.SetSyscallReturn(1)
	case SysGettid:
		tid := h.getTID(c)
		c.SetSyscallReturn(uint64(tid))
	case SysSetTidAddress:
		tid := h.getTID(c)
		h.clearChildTidMu.Lock()
		if h.clearChildTid == nil {
			h.clearChildTid = make(map[int]uint64)
		}
		h.clearChildTid[tid] = a0
		h.clearChildTidMu.Unlock()
		c.SetSyscallReturn(uint64(tid))
	case SysUmask:
		old := h.Umask
		h.Umask = uint32(a0) & 0777
		c.SetSyscallReturn(uint64(old))

	// --- Signals ---
	case SysRtSigaction:
		h.sysRtSigaction(c, a0, a1, a2, a3)
	case SysRtSigprocmask:
		h.sysRtSigprocmask(c, a0, a1, a2)
	case SysSigaltstack:
		h.sysSigaltstack(c, a0, a1)
	case SysRtSigreturn:
		c.SetSyscallReturn(0) // TODO: restore saved signal frame
	case SysKill, SysTkill:
		h.Signals.Raise(int(a1))
		c.SetSyscallReturn(0)
	case SysTgkill:
		h.Signals.Raise(int(a2))
		c.SetSyscallReturn(0)

	// --- Time ---
	case SysClockGettime:
		h.sysClockGettime(c, a0, a1)
	case SysClockGetres:
		h.sysClockGetres(c, a0, a1)
	case SysClockNanosleep:
		h.sysClockNanosleep(c, a0, a1, a2, a3)
	case SysNanosleep:
		h.sysNanosleep(c, a1)

	// --- Resource limits ---
	case SysPrlimit64:
		h.sysPrlimit64(c, a0, a1, a2, a3)
	case SysGetrusage:
		h.sysGetrusage(c, a0, a1)

	// --- Random ---
	case SysGetrandom:
		h.sysGetrandom(c, a0, a1)

	// --- System info ---
	case SysUname:
		h.sysUname(c, a0)
	case SysSysinfo:
		h.sysSysinfo(c, a0)

	// --- Threading ---
	case SysFutex:
		h.sysFutex(c, a0, a1, a2, a3)
	case SysSetRobustList:
		c.SetSyscallReturn(0)
	case SysClone:
		h.sysClone(c, a0, a1, a2, a3, a4)
	case SysClone3:
		h.sysClone3(c, a0, a1)

	// --- Scheduling ---
	case SysSchedYield:
		c.SetSyscallReturn(0)
	case SysSchedGetaffinity:
		if a2 >= 8 {
			h.Mem.Write64(a1, 1)
			c.SetSyscallReturn(0)
		} else {
			c.SetSyscallReturn(negErrno(EINVAL))
		}
	case SysSchedSetaffinity:
		c.SetSyscallReturn(0)

	// --- Misc ---
	case SysPrctl:
		h.sysPrctl(c, a0, a1)
	case SysArchPrctl:
		h.sysArchPrctl(c, a0, a1)
	case SysSyslog:
		c.SetSyscallReturn(negErrno(EPERM))
	case SysMembarrier:
		c.SetSyscallReturn(0)
	case SysKcmp:
		c.SetSyscallReturn(negErrno(ENOSYS))
	case SysMincore:
		// mincore(addr, length, vec) - report pages in memory.
		// Linux returns -ENOMEM if any page in [addr, addr+length) is not mapped.
		pageSize := uint64(4096)
		nPages := (a1 + pageSize - 1) / pageSize
		for i := uint64(0); i < nPages; i++ {
			pageAddr := a0 + i*pageSize
			if _, _, err := h.Mem.LookupRead(pageAddr, mmu.PermRead); err != nil {
				c.SetSyscallReturn(negErrno(ENOMEM))
				return
			}
			h.Mem.Write8(a2+i, 1) // bit 0 set = page in RAM
		}
		c.SetSyscallReturn(0)
	case SysRseq:
		c.SetSyscallReturn(negErrno(ENOSYS))
	case SysPpoll:
		h.sysPpoll(c, a0, a1, a2, a3)
	case sysPoll:
		h.sysPollInt(c, a0, a1, int32(a2))
	case SysPselect6:
		c.SetSyscallReturn(0)
	case SysTimes:
		c.SetSyscallReturn(0)
	case SysSendfile:
		h.sysSendfile(c, a0, a1, a2, a3)

	// --- Networking ---
	case SysSocket:
		h.sysSocket(c, a0, a1, a2)
	case SysBind:
		h.sysBind(c, a0, a1, a2)
	case SysListen:
		h.sysListen(c, a0, a1)
	case SysAccept, SysAccept4:
		h.sysAccept4(c, a0, a1, a2, a3)
	case SysConnect:
		h.sysConnect(c, a0, a1, a2)
	case SysSendto:
		h.sysSendto(c, a0, a1, a2, a3, a4, a5)
	case SysRecvfrom:
		h.sysRecvfrom(c, a0, a1, a2, a3, a4, a5)
	case SysSendmsg:
		h.sysSendmsg(c, a0, a1, a2)
	case SysRecvmsg:
		h.sysRecvmsg(c, a0, a1, a2)
	case SysSetsockopt:
		h.sysSetsockopt(c, a0, a1, a2, a3, a4)
	case SysGetsockopt:
		h.sysGetsockopt(c, a0, a1, a2, a3, a4)
	case SysShutdown:
		h.sysShutdown(c, a0, a1)
	case SysSocketpair:
		h.sysSocketpair(c, a0, a1, a2, a3)
	case SysGetsockname:
		h.sysGetsockname(c, a0, a1, a2)
	case SysGetpeername:
		h.sysGetpeername(c, a0, a1, a2)

	// --- Epoll ---
	case SysEpollCreate1:
		h.sysEpollCreate1(c, a0)
	case SysEpollCtl:
		h.sysEpollCtl(c, a0, a1, a2, a3)
	case SysEpollPwait:
		h.sysEpollPwait(c, a0, a1, a2, a3)
	case SysEventfd2:
		h.sysEventfd2(c, a0, a1)
	case SysTimerfdCreate:
		h.sysTimerfdCreate(c, a0, a1)
	case SysTimerfdSettime:
		h.sysTimerfdSettime(c, a0, a1, a2, a3)
	case SysTimerfdGettime:
		h.sysTimerfdGettime(c, a0, a1)

	// --- memfd ---
	case SysMemfdCreate:
		h.sysMemfdCreate(c, a0, a1)

	// --- Wait ---
	case SysWait4:
		h.sysWait4(c, a0, a1, a2, a3)

	// --- Exec ---
	case SysExecve:
		h.sysExecve(c, a0, a1, a2)

	// --- Timers ---
	case SysGetitimer:
		h.sysGetitimer(c, a0, a1)
	case SysSetitimer:
		h.sysSetitimer(c, a0, a1, a2)

	// --- RISC-V specific ---
	case SysRiscvHwprobe:
		// Return success; guest memory already zeroed → reports no extensions.
		c.SetSyscallReturn(0)

	default:
		fmt.Fprintf(os.Stderr, "[govm] unhandled syscall %d (a0=0x%x a1=0x%x a2=0x%x)\n", num, a0, a1, a2)
		c.SetSyscallReturn(negErrno(ENOSYS))
	}
}

// allocGuestPID returns a monotonically increasing guest PID for a new child process.
func (h *Handler) allocGuestPID() int {
	h.childMu.Lock()
	defer h.childMu.Unlock()
	pid := h.nextGPID
	h.nextGPID++
	return pid
}

// sysExecve: if we're inside a vfork-child goroutine, launch the real host
// binary and unblock the parent.  Otherwise return ENOSYS (we don't support
// exec-as-replace-image for the main guest process).
func (h *Handler) sysExecve(c arch.CPU, pathPtr, argvPtr, envpPtr uint64) {
	path, err := h.readGuestString(pathPtr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}

	// Build argv
	argv := h.readGuestStringArray(argvPtr)
	// Build envp
	envp := h.readGuestStringArray(envpPtr)

	fmt.Fprintf(os.Stderr, "[govm] execve(%q, %v)\n", path, argv)

	h.vforkMu.Lock()
	pending := h.vforkPending
	ch := h.vforkDone
	snap := h.vforkSnapshot
	if pending {
		h.vforkPending = false
	}
	h.vforkMu.Unlock()

	if !pending {
		// Not inside a vfork child - can't replace main guest image.
		fmt.Fprintf(os.Stderr, "[govm] execve outside vfork → ENOSYS\n")
		c.SetSyscallReturn(negErrno(ENOSYS))
		return
	}

	// Capture the child's current host FDs for 0/1/2 BEFORE restoring the
	// parent's FD table.  The child may have dup2'd a pipe write-end onto fd 1.
	childHFD := [3]int{-1, -1, -1}
	for i := 0; i < 3; i++ {
		childHFD[i] = h.FS.GetHostFDNum(i)
	}

	// Restore the parent's FD table immediately - this undoes any dup2/close
	// file actions the child performed on the shared FD table.
	h.FS.RestoreFDs(snap)

	// Launch the real host process using dup'd copies of the child's stdio fds.
	dupOrFallback := func(hfd int, fallback *os.File) (*os.File, bool) {
		if hfd >= 0 {
			dupFD, err := syscall.Dup(hfd)
			if err == nil {
				return os.NewFile(uintptr(dupFD), fmt.Sprintf("hfd%d-dup", hfd)), true
			}
		}
		return fallback, false
	}
	stdinF,  stdinDup  := dupOrFallback(childHFD[0], os.Stdin)
	stdoutF, stdoutDup := dupOrFallback(childHFD[1], os.Stdout)
	stderrF, stderrDup := dupOrFallback(childHFD[2], os.Stderr)
	cmd := exec.Command(path, argv[1:]...)
	cmd.Env = envp
	cmd.Stdin  = stdinF
	cmd.Stdout = stdoutF
	cmd.Stderr = stderrF
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[govm] execve host start error: %v\n", err)
		ch <- -1
		c.Stop()
		return
	}
	// Close our dup'd copies now that the child process owns them.
	// This is critical for any pipe write-end: once we close our copy,
	// the reader sees EOF when the child process exits.
	if stdinDup  { stdinF.Close()  }
	if stdoutDup { stdoutF.Close() }
	if stderrDup { stderrF.Close() }
	// Also close the original child host fds that are now owned by the subprocess.
	// These were in the child's FD table (e.g. dup2'd pipe write-end on fd 1)
	// and must not stay open in our process.
	for i := 0; i < 3; i++ {
		hfd := childHFD[i]
		if hfd < 0 {
			continue
		}
		// Don't close if it's the same as the parent's restored fd for that slot
		// (i.e. child didn't change it) - GetHostFDNum after RestoreFDs reflects parent.
		parentHFD := h.FS.GetHostFDNum(i)
		if hfd != parentHFD {
			syscall.Close(hfd)
		}
	}

	gpid := h.allocGuestPID()
	h.childMu.Lock()
	h.childProcs[gpid] = cmd.Process
	h.childMu.Unlock()

	fmt.Fprintf(os.Stderr, "[govm] execve launched pid=%d (guest=%d)\n", cmd.Process.Pid, gpid)
	ch <- gpid
	// Stop this child CPU - it has been replaced by the host process.
	c.Stop()
}

// sysWait4 waits for a child host process, populating the wstatus word.
func (h *Handler) sysWait4(c arch.CPU, gpidArg, wstatusPtr, options, rusagePtr uint64) {
	gpid := int(int32(gpidArg)) // signed: -1 = any child
	h.childMu.Lock()
	if len(h.childProcs) == 0 {
		h.childMu.Unlock()
		fmt.Fprintf(os.Stderr, "[govm] wait4(pid=%d) → ECHILD (no children)\n", gpid)
		c.SetSyscallReturn(negErrno(ECHILD))
		return
	}
	// Find matching pid
	var proc *os.Process
	var foundPID int
	for pid, p := range h.childProcs {
		if gpid == -1 || gpid == pid {
			proc = p
			foundPID = pid
			break
		}
	}
	if proc == nil {
		h.childMu.Unlock()
		fmt.Fprintf(os.Stderr, "[govm] wait4(pid=%d) → ECHILD (not found)\n", gpid)
		c.SetSyscallReturn(negErrno(ECHILD))
		return
	}
	h.childMu.Unlock()

	const WNOHANG = 1
	fmt.Fprintf(os.Stderr, "[govm] wait4(guest=%d host=%d options=0x%x)\n", gpid, proc.Pid, options)

	if options&WNOHANG != 0 {
		// Non-blocking: use unix.Wait4 with WNOHANG.
		var wstatus unix.WaitStatus
		wpid, err := unix.Wait4(proc.Pid, &wstatus, unix.WNOHANG, nil)
		if err != nil || wpid == 0 {
			// Child not yet done.
			c.SetSyscallReturn(0)
			return
		}
		h.childMu.Lock()
		delete(h.childProcs, foundPID)
		h.childMu.Unlock()
		ws := uint32(wstatus)
		if wstatusPtr != 0 {
			h.Mem.Write32(wstatusPtr, ws)
		}
		fmt.Fprintf(os.Stderr, "[govm] wait4 WNOHANG → pid=%d wstatus=0x%x\n", foundPID, ws)
		c.SetSyscallReturn(uint64(foundPID))
		return
	}

	// Blocking wait.
	var wstatus unix.WaitStatus
	_, err := unix.Wait4(proc.Pid, &wstatus, 0, nil)
	h.childMu.Lock()
	delete(h.childProcs, foundPID)
	h.childMu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[govm] wait4 error: %v\n", err)
		c.SetSyscallReturn(negErrno(ECHILD))
		return
	}
	ws := uint32(wstatus)
	if wstatusPtr != 0 {
		h.Mem.Write32(wstatusPtr, ws)
	}
	fmt.Fprintf(os.Stderr, "[govm] wait4 → pid=%d wstatus=0x%x exitCode=%d\n", foundPID, ws, wstatus.ExitStatus())
	c.SetSyscallReturn(uint64(foundPID))
}

// readGuestStringArray reads a NULL-terminated array of guest string pointers.
func (h *Handler) readGuestStringArray(ptr uint64) []string {
	if ptr == 0 {
		return nil
	}
	var result []string
	for i := uint64(0); ; i++ {
		addrBytes, err := h.Mem.ReadBytes(ptr+i*8, 8)
		if err != nil {
			break
		}
		strPtr := binary.LittleEndian.Uint64(addrBytes)
		if strPtr == 0 {
			break
		}
		s, err := h.readGuestString(strPtr)
		if err != nil {
			break
		}
		result = append(result, s)
	}
	return result
}

// --- Errno constants ---

const (
	EPERM   = 1
	ENOENT  = 2
	ESRCH   = 3
	EINTR   = 4
	EIO     = 5
	ENXIO   = 6
	EBADF   = 9
	ECHILD  = 10
	EAGAIN  = 11
	ENOMEM  = 12
	EACCES  = 13
	EFAULT  = 14
	EEXIST  = 17
	ENODEV  = 19
	ENOTDIR = 20
	EISDIR  = 21
	EINVAL  = 22
	ENFILE  = 23
	EMFILE  = 24
	ENOTTY  = 25
	ENOSPC  = 28
	ESPIPE  = 29
	EPIPE   = 32
	ERANGE  = 34
	ENOSYS  = 38
	ENOTEMPTY    = 39
	ENOTSOCK     = 88
	EMSGSIZE     = 90
	EPROTOTYPE   = 91
	ENOPROTOOPT  = 92
	EPROTONOSUPPORT = 93
	EOPNOTSUPP   = 95
	EAFNOSUPPORT = 97
	EADDRINUSE   = 98
	EADDRNOTAVAIL = 99
	ENETUNREACH  = 101
	ECONNABORTED = 103
	ECONNRESET   = 104
	ENOBUFS      = 105
	EISCONN      = 106
	ENOTCONN     = 107
	ETIMEDOUT    = 110
	ECONNREFUSED = 111
	EINPROGRESS  = 115
)

// AT_FDCWD is the "current working directory" sentinel for *at() syscalls.
const atFDCWD = uint64(0xFFFFFFFFFFFFFF9C) // -100 as uint64

func negErrno(e uint64) uint64 {
	return ^(e - 1) // -e in two's complement
}

// getTID returns the guest thread ID for the calling CPU.
func (h *Handler) getTID(c arch.CPU) int {
	if h.ThreadM != nil {
		return h.ThreadM.GetTID(c)
	}
	return 1
}

// --- Helpers ---

// readBytes is a convenience wrapper for Mem.ReadBytes that discards the error.
func (h *Handler) readBytes(addr, n uint64) []byte {
	data, _ := h.Mem.ReadBytes(addr, int(n))
	return data
}

func (h *Handler) readGuestString(addr uint64) (string, error) {
	if addr == 0 {
		return "", syscall.EFAULT
	}
	var buf []byte
	for {
		b, err := h.Mem.Read8(addr)
		if err != nil || b == 0 {
			break
		}
		buf = append(buf, b)
		addr++
	}
	return string(buf), nil
}

// --- Syscall implementations ---

// heapSignature computes a fast hash of the glibc heap chunk headers.
// We walk the chunk chain from aligned heap base and hash the size fields.
func (h *Handler) heapSignature() uint64 {
	heapBase := h.Mem.GetBrkBase()
	if heapBase == 0 {
		return 0
	}
	// Aligned heap start (glibc aligns to 16)
	aligned := (heapBase + 15) &^ 15
	var sig uint64
	addr := aligned
	brkCur := h.Mem.Brk(0)
	for i := 0; i < 64 && addr < brkCur; i++ {
		// Read size field at addr+8
		sz, err := h.Mem.Read64(addr + 8)
		if err != nil {
			break
		}
		chunkSz := sz &^ 7 // mask out flags
		if chunkSz == 0 || chunkSz > (brkCur-heapBase) {
			break // top chunk or invalid
		}
		sig = sig*31 + sz // include flags in sig
		addr += chunkSz
	}
	return sig
}

func (h *Handler) sysOpenat(c arch.CPU, dirfd, pathAddr, flags, mode uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	if path == "" {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	fd, err := h.FS.OpenAt(int(int32(dirfd)), path, int(flags), uint32(mode))
	if err != nil {
		if h.Trace {
			fmt.Fprintf(os.Stderr, "[govm] openat(%q) → ENOENT\n", path)
		}
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[govm] openat(%q) → fd=%d\n", path, fd)
	}
	c.SetSyscallReturn(uint64(fd))
}

func (h *Handler) sysMprotect(c arch.CPU, addr, length, prot uint64) {
	var perms uint8
	if prot&0x1 != 0 {
		perms |= mmu.PermRead
	}
	if prot&0x2 != 0 {
		perms |= mmu.PermWrite
	}
	if prot&0x4 != 0 {
		perms |= mmu.PermExecute
	}

	length = (length + mmu.PageSize - 1) & mmu.PageMask
	addr = addr & mmu.PageMask

	// Verify all pages are already mapped
	for pg := addr; pg < addr+length; pg += mmu.PageSize {
		if !h.Mem.IsMapped(pg) {
			if h.Trace {
				fmt.Fprintf(os.Stderr, "[mprotect] ENOMEM: addr=0x%x len=0x%x prot=%d unmapped_page=0x%x\n", addr, length, prot, pg)
			}
			c.SetSyscallReturn(negErrno(ENOMEM))
			return
		}
	}

	// Change permissions
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[mprotect] OK: addr=0x%x len=0x%x end=0x%x prot=%d perms=0x%x pages=%d\n", addr, length, addr+length, prot, perms, length/mmu.PageSize)
		brkBase := h.Mem.GetBrkBase()
		brkCur := h.Mem.Brk(0)
		if brkBase != 0 && addr+length > brkBase {
			fmt.Fprintf(os.Stderr, "[mprotect] WARNING: overlaps heap! heap=0x%x-0x%x mprotect=0x%x-0x%x prot=%d\n",
				brkBase, brkCur, addr, addr+length, prot)
		}
	}
	for pg := addr; pg < addr+length; pg += mmu.PageSize {
		h.Mem.MapPage(pg, perms)
	}

	c.SetSyscallReturn(0)
}

func (h *Handler) sysIoctl(c arch.CPU, fd, cmd uint64) {
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[govm] ioctl(fd=%d, cmd=0x%x)\n", fd, cmd)
	}
	const FIONREAD = 0x541B
	const FIONBIO = 0x5421
	switch cmd {
	case 0x5401: // TCGETS
		if fd <= 2 {
			h.dumpGuestEnviron()
		}
		c.SetSyscallReturn(negErrno(ENOTTY))
		return
	case 0x5413: // TIOCGWINSZ
		c.SetSyscallReturn(negErrno(ENOTTY))
		return
	case FIONREAD:
		arg := c.SyscallArgs()[2]
		hostFD := h.FS.GetHostFDNum(int(fd))
		if hostFD >= 0 {
			avail, err := unix.IoctlRetInt(hostFD, FIONREAD)
			if err == nil {
				h.Mem.Write32(arg, uint32(avail))
				if h.Trace {
					fmt.Fprintf(os.Stderr, "[govm] ioctl FIONREAD fd=%d→hfd=%d avail=%d\n", fd, hostFD, avail)
				}
				c.SetSyscallReturn(0)
				return
			}
		}
		h.Mem.Write32(arg, 0)
		c.SetSyscallReturn(0)
		return
	case FIONBIO:
		hostFD := h.FS.GetHostFDNum(int(fd))
		if hostFD >= 0 {
			arg := c.SyscallArgs()[2]
			val, _ := h.Mem.Read32(arg)
			if val != 0 {
				unix.SetNonblock(hostFD, true)
			} else {
				unix.SetNonblock(hostFD, false)
			}
		}
		c.SetSyscallReturn(0)
		return
	}
	if fd <= 2 {
		c.SetSyscallReturn(negErrno(ENOTTY))
	} else {
		c.SetSyscallReturn(negErrno(ENOTTY))
	}
}

// dumpGuestEnviron reads the guest's environ pointer and dumps each entry.
// This is a temporary debug helper.
func (h *Handler) dumpGuestEnviron() {
	// Scan memory for the environ pointer pattern.
	// The environ global is typically near the BSS of libc.
	// As an approximation, we search for a sequence of guest pointers
	// that form consecutive nul-terminated KEY=VALUE strings.
	// More reliably: the env strings are at strArea = 0x6ffffffff000
	// and the environ array is pointed to by glibc's __environ.
	// We can compute the environ array address from the stack layout:
	//   - argc at sp
	//   - argv[0..n] at sp+8 .. sp+8*(argc+1)
	//   - env[0..m] at sp+8*(argc+2) ..
	// Read sp from the initial stack pointer minus a bit.
	// For now, use a known layout: stackTop=0x700000000000, strArea=stackTop-4096.
	const stackTop = uint64(0x700000000000)
	const strArea = stackTop - 4096
	// Read argc first - it's at sp which we approximate from strArea.
	// The actual sp is below strArea by nWords*8. We can scan from strArea upward
	// to find the argc, but that's complex. Instead, just dump the strings
	// in strArea directly.
	if data, err := h.Mem.ReadBytes(strArea, 512); err == nil {
		fmt.Fprintf(os.Stderr, "[ENVIRON DUMP] strArea=0x%x:\n", strArea)
		// Print as individual nul-terminated strings
		start := 0
		for i, b := range data {
			if b == 0 {
				if i > start {
					fmt.Fprintf(os.Stderr, "  [%d..%d] %q\n", start, i, data[start:i])
				}
				start = i + 1
			}
		}
	}
}

func (h *Handler) sysFstat(c arch.CPU, fd, statAddr uint64) {
	node := h.FS.Stat(int(fd))
	if node == nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	h.writeStatBuf(statAddr, node)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysFstatat(c arch.CPU, dirfd, pathAddr, statAddr uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	if path == "" {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	node, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	h.writeStatBuf(statAddr, node)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysStatx(c arch.CPU, dirfd, pathAddr, flags, mask, statxAddr uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	if path == "" && flags&0x1000 == 0 { // AT_EMPTY_PATH = 0x1000
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	node, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	// struct statx = 256 bytes
	buf := make([]byte, 256)
	binary.LittleEndian.PutUint32(buf[0:], 0x7FF)            // stx_mask
	binary.LittleEndian.PutUint32(buf[4:], 4096)             // stx_blksize
	binary.LittleEndian.PutUint64(buf[8:], 0)                // stx_attributes
	binary.LittleEndian.PutUint32(buf[16:], node.Nlink)       // stx_nlink
	binary.LittleEndian.PutUint32(buf[20:], node.Uid)         // stx_uid
	binary.LittleEndian.PutUint32(buf[24:], node.Gid)         // stx_gid
	binary.LittleEndian.PutUint16(buf[28:], uint16(node.FileMode)) // stx_mode
	binary.LittleEndian.PutUint64(buf[32:], node.Ino)         // stx_ino
	binary.LittleEndian.PutUint64(buf[40:], uint64(node.Size)) // stx_size
	h.Mem.WriteBytes(statxAddr, buf)
	c.SetSyscallReturn(0)
}

// writeStatBuf writes a struct stat for the current guest architecture.
func (h *Handler) writeStatBuf(addr uint64, node *vfs.VNode) {
	h.writeStatBufArch(addr, node, h.Arch)
}

func (h *Handler) writeStatBufArch(addr uint64, node *vfs.VNode, a arch.Arch) {
	if a == arch.ArchAMD64 {
		// x86_64 struct stat: 144 bytes
		buf := make([]byte, 144)
		binary.LittleEndian.PutUint64(buf[0:], 1)                  // st_dev
		binary.LittleEndian.PutUint64(buf[8:], node.Ino)            // st_ino
		binary.LittleEndian.PutUint64(buf[16:], uint64(node.Nlink)) // st_nlink (8 bytes)
		binary.LittleEndian.PutUint32(buf[24:], node.FileMode)      // st_mode
		binary.LittleEndian.PutUint32(buf[28:], node.Uid)           // st_uid
		binary.LittleEndian.PutUint32(buf[32:], node.Gid)           // st_gid
		binary.LittleEndian.PutUint64(buf[48:], uint64(node.Size))  // st_size
		binary.LittleEndian.PutUint64(buf[56:], 4096)               // st_blksize (8 bytes)
		binary.LittleEndian.PutUint64(buf[72:], uint64(node.Atime.Unix()))
		binary.LittleEndian.PutUint64(buf[88:], uint64(node.Mtime.Unix()))
		binary.LittleEndian.PutUint64(buf[104:], uint64(node.Ctime.Unix()))
		h.Mem.WriteBytes(addr, buf)
	} else {
		// RISC-V struct stat: 128 bytes
		buf := make([]byte, 128)
		binary.LittleEndian.PutUint64(buf[0:], 1)                  // st_dev
		binary.LittleEndian.PutUint64(buf[8:], node.Ino)            // st_ino
		binary.LittleEndian.PutUint32(buf[16:], node.FileMode)      // st_mode
		binary.LittleEndian.PutUint32(buf[20:], node.Nlink)         // st_nlink
		binary.LittleEndian.PutUint32(buf[24:], node.Uid)           // st_uid
		binary.LittleEndian.PutUint32(buf[28:], node.Gid)           // st_gid
		binary.LittleEndian.PutUint64(buf[48:], uint64(node.Size))  // st_size
		binary.LittleEndian.PutUint32(buf[56:], 4096)               // st_blksize
		binary.LittleEndian.PutUint64(buf[72:], uint64(node.Atime.Unix()))
		binary.LittleEndian.PutUint64(buf[88:], uint64(node.Mtime.Unix()))
		binary.LittleEndian.PutUint64(buf[104:], uint64(node.Ctime.Unix()))
		h.Mem.WriteBytes(addr, buf)
	}
}

func (h *Handler) sysLseek(c arch.CPU, fd uint64, offset uint64, whence uint64) {
	pos, err := h.FS.Lseek(int(fd), int64(offset), int(whence))
	if err != nil {
		c.SetSyscallReturn(negErrno(ESPIPE))
		return
	}
	c.SetSyscallReturn(uint64(pos))
}

func (h *Handler) sysDup(c arch.CPU, oldfd uint64) {
	newfd, err := h.FS.Dup(int(oldfd))
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(uint64(newfd))
}

func (h *Handler) sysDup3(c arch.CPU, oldfd, newfd uint64) {
	err := h.FS.Dup3(int(oldfd), int(newfd))
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(newfd)
}

func (h *Handler) sysPipe2(c arch.CPU, pipefdAddr, flags uint64) {
	// Strip O_NONBLOCK from the host pipe: Go's os.File doesn't use the
	// network poller for pipes, so a non-blocking pipe causes EAGAIN on read
	// instead of blocking.  The guest's O_NONBLOCK semantics are honoured at
	// the syscall level (our sysRead returns EAGAIN when appropriate).
	hostFlags := int(flags) &^ unix.O_NONBLOCK
	hostFDs := make([]int, 2)
	if err := unix.Pipe2(hostFDs, hostFlags); err != nil {
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	rf := os.NewFile(uintptr(hostFDs[0]), "pipe:r")
	wf := os.NewFile(uintptr(hostFDs[1]), "pipe:w")
	rfd := h.FS.AllocHostFile(rf)
	wfd := h.FS.AllocHostFile(wf)
	h.Mem.Write32(pipefdAddr, uint32(rfd))
	h.Mem.Write32(pipefdAddr+4, uint32(wfd))
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[govm] pipe2 → rfd=%d wfd=%d\n", rfd, wfd)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetdents64(c arch.CPU, fd, buf, count uint64) {
	// For host-backed fds (real directories on the host filesystem) call the
	// kernel directly and copy the result into guest memory.
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		hostBuf := make([]byte, count)
		n, err := unix.Getdents(hostFD, hostBuf)
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		if n > 0 {
			h.Mem.WriteBytes(buf, hostBuf[:n])
		}
		c.SetSyscallReturn(uint64(n))
		return
	}

	entries := h.FS.Getdents64(int(fd))
	if entries == nil {
		c.SetSyscallReturn(0) // EOF
		return
	}
	// Each dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name + padding
	offset := uint64(0)
	for _, e := range entries {
		nameLen := len(e.Name) + 1 // +1 for null terminator
		recLen := uint16(((8 + 8 + 2 + 1 + nameLen) + 7) & ^7) // 8-byte aligned
		if offset+uint64(recLen) > count {
			break
		}
		h.Mem.Write64(buf+offset, e.Ino)
		h.Mem.Write64(buf+offset+8, offset+uint64(recLen))
		h.Mem.Write16(buf+offset+16, recLen)
		dtype := uint8(8) // DT_REG
		if e.IsDir {
			dtype = 4 // DT_DIR
		}
		h.Mem.Write8(buf+offset+18, dtype)
		h.Mem.WriteBytes(buf+offset+19, append([]byte(e.Name), 0))
		offset += uint64(recLen)
	}
	c.SetSyscallReturn(offset)
}

func (h *Handler) sysReadlinkat(c arch.CPU, dirfd, pathAddr, buf, bufsiz uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	target, err := h.FS.Readlinkat(int(int32(dirfd)), path)
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	data := []byte(target)
	if uint64(len(data)) > bufsiz {
		data = data[:bufsiz]
	}
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[govm] readlinkat(%q) → %q (len=%d)\n", path, data, len(data))
	}
	h.Mem.WriteBytes(buf, data)
	c.SetSyscallReturn(uint64(len(data)))
}

func (h *Handler) sysFaccessat(c arch.CPU, dirfd, pathAddr uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	_, err = h.FS.StatPath(int(int32(dirfd)), path)
	if strings.Contains(path, "Xauth") || strings.Contains(path, "xauth") || strings.Contains(path, ".X") || strings.Contains(path, "mutter") {
		if h.Trace {
			fmt.Fprintf(os.Stderr, "[govm] access(%q) → err=%v\n", path, err)
		}
	}
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetcwd(c arch.CPU, buf, size uint64) {
	cwd := h.FS.Getcwd()
	data := append([]byte(cwd), 0)
	if uint64(len(data)) > size {
		c.SetSyscallReturn(negErrno(ERANGE))
		return
	}
	h.Mem.WriteBytes(buf, data)
	c.SetSyscallReturn(uint64(len(data)))
}

func (h *Handler) sysMkdirat(c arch.CPU, dirfd, pathAddr, mode uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	if path == "" {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	absPath := h.FS.ResolvePath(int(int32(dirfd)), path)
	// Check if already exists
	if _, err := h.FS.Resolve(absPath); err == nil {
		c.SetSyscallReturn(negErrno(EEXIST))
		return
	}
	// Check if parent exists
	dir, _ := vfs.SplitPath(absPath)
	if _, err := h.FS.Resolve(dir); err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	h.FS.MkdirAll(absPath)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysClockGettime(c arch.CPU, clockID, tsAddr uint64) {
	if tsAddr != 0 {
		now := time.Now()
		h.Mem.Write64(tsAddr, uint64(now.Unix()))
		h.Mem.Write64(tsAddr+8, uint64(now.Nanosecond()))
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysClockGetres(c arch.CPU, clockID, resAddr uint64) {
	if resAddr != 0 {
		h.Mem.Write64(resAddr, 0)   // seconds
		h.Mem.Write64(resAddr+8, 1) // nanoseconds (1ns resolution)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysNanosleep(c arch.CPU, reqAddr uint64) {
	if reqAddr != 0 {
		sec, _ := h.Mem.Read64(reqAddr)
		nsec, _ := h.Mem.Read64(reqAddr + 8)
		d := time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond
		if d > 0 && d < 10*time.Second {
			time.Sleep(d)
		}
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysFcntl(c arch.CPU, fd, cmd, arg uint64) {
	switch cmd {
	case 0: // F_DUPFD
		newfd, err := h.FS.Dup(int(fd))
		if err != nil {
			c.SetSyscallReturn(negErrno(EBADF))
		} else {
			c.SetSyscallReturn(uint64(newfd))
		}
	case 1: // F_GETFD
		c.SetSyscallReturn(0)
	case 2: // F_SETFD
		c.SetSyscallReturn(0)
	case 3: // F_GETFL
		hostFD := h.FS.GetHostFDNum(int(fd))
		if hostFD >= 0 {
			flags, err := unix.FcntlInt(uintptr(hostFD), 3, 0)
			if err != nil {
				c.SetSyscallReturn(negErrno(errnoFromErr(err)))
				return
			}
			c.SetSyscallReturn(uint64(flags))
			return
		}
		f := h.FS.GetFD(int(fd))
		if f == nil {
			c.SetSyscallReturn(negErrno(EBADF))
		} else {
			c.SetSyscallReturn(uint64(f.Flags))
		}
	case 4: // F_SETFL
		hostFD := h.FS.GetHostFDNum(int(fd))
		if hostFD >= 0 {
			_, err := unix.FcntlInt(uintptr(hostFD), 4, int(arg))
			if err != nil {
				c.SetSyscallReturn(negErrno(errnoFromErr(err)))
				return
			}
			c.SetSyscallReturn(0)
			return
		}
		c.SetSyscallReturn(0)
	case 1024: // F_DUPFD_CLOEXEC
		newfd, err := h.FS.Dup(int(fd))
		if err != nil {
			c.SetSyscallReturn(negErrno(EBADF))
		} else {
			c.SetSyscallReturn(uint64(newfd))
		}
	default:
		c.SetSyscallReturn(negErrno(EINVAL))
	}
}

func (h *Handler) sysPrlimit64(c arch.CPU, pid, resource, newLimit, oldLimit uint64) {
	if oldLimit != 0 {
		h.Mem.Write64(oldLimit, 0x7FFFFFFFFFFFFFFF)
		h.Mem.Write64(oldLimit+8, 0x7FFFFFFFFFFFFFFF)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetrandom(c arch.CPU, buf, count uint64) {
	data := make([]byte, count)
	rand.Read(data)
	h.Mem.WriteBytes(buf, data)
	c.SetSyscallReturn(count)
}

func (h *Handler) sysUname(c arch.CPU, buf uint64) {
	const fieldLen = 65
	machine := "riscv64"
	if c.GetArch() == arch.ArchAMD64 {
		machine = "x86_64"
	}
	fields := []string{
		"Linux",         // sysname
		"govm",          // nodename
		"6.1.0",         // release
		"#1 SMP",        // version
		machine,         // machine
	}
	for i, s := range fields {
		offset := uint64(i) * fieldLen
		b := make([]byte, fieldLen)
		copy(b, s)
		h.Mem.WriteBytes(buf+offset, b)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSysinfo(c arch.CPU, buf uint64) {
	// struct sysinfo is 112 bytes on RISC-V
	data := make([]byte, 112)
	binary.LittleEndian.PutUint64(data[0:], uint64(time.Now().Unix())) // uptime
	binary.LittleEndian.PutUint64(data[32:], 1024*1024*1024)           // totalram (1GB)
	binary.LittleEndian.PutUint64(data[40:], 512*1024*1024)            // freeram
	binary.LittleEndian.PutUint64(data[48:], 0)                        // sharedram
	binary.LittleEndian.PutUint64(data[56:], 0)                        // bufferram
	binary.LittleEndian.PutUint64(data[64:], 0)                        // totalswap
	binary.LittleEndian.PutUint64(data[72:], 0)                        // freeswap
	binary.LittleEndian.PutUint16(data[80:], 1)                        // procs
	binary.LittleEndian.PutUint32(data[104:], 1)                       // mem_unit
	h.Mem.WriteBytes(buf, data)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetrusage(c arch.CPU, who, usage uint64) {
	// struct rusage = 144 bytes, zero-fill
	data := make([]byte, 144)
	h.Mem.WriteBytes(usage, data)
	c.SetSyscallReturn(0)
}

// --- Signal syscalls ---

func (h *Handler) sysRtSigaction(c arch.CPU, signum, actAddr, oldAddr, sigsetsize uint64) {
	sig := int(signum)
	if sig < 1 || sig > signal.NSIG {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	// Write old action if requested
	if oldAddr != 0 {
		old := h.Signals.GetAction(sig)
		if old != nil {
			h.Mem.Write64(oldAddr, old.Handler)
			h.Mem.Write64(oldAddr+8, old.Flags)
			h.Mem.Write64(oldAddr+16, old.Restorer)
			h.Mem.Write64(oldAddr+24, old.Mask)
		}
	}
	// Set new action if provided
	if actAddr != 0 {
		handler, _ := h.Mem.Read64(actAddr)
		flags, _ := h.Mem.Read64(actAddr + 8)
		restorer, _ := h.Mem.Read64(actAddr + 16)
		mask, _ := h.Mem.Read64(actAddr + 24)
		act := &signal.SigAction{
			Handler:  handler,
			Flags:    flags,
			Restorer: restorer,
			Mask:     mask,
		}
		h.Signals.SetAction(sig, act)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysRtSigprocmask(c arch.CPU, how, setAddr, oldsetAddr uint64) {
	var newmask uint64
	if setAddr != 0 {
		newmask, _ = h.Mem.Read64(setAddr)
	}
	old := h.Signals.SetMask(int(how), newmask)
	if oldsetAddr != 0 {
		h.Mem.Write64(oldsetAddr, old)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSigaltstack(c arch.CPU, ssAddr, oldssAddr uint64) {
	if oldssAddr != 0 {
		oldSP, oldFlags, oldSize := h.Signals.SetAltStack(0, 0, 0)
		h.Mem.Write64(oldssAddr, oldSP)
		h.Mem.Write32(oldssAddr+8, uint32(oldFlags))
		h.Mem.Write64(oldssAddr+16, oldSize)
		// Restore since we just read
		h.Signals.SetAltStack(oldSP, oldFlags, oldSize)
	}
	if ssAddr != 0 {
		sp, _ := h.Mem.Read64(ssAddr)
		flags, _ := h.Mem.Read32(ssAddr + 8)
		size, _ := h.Mem.Read64(ssAddr + 16)
		h.Signals.SetAltStack(sp, uint64(flags), size)
	}
	c.SetSyscallReturn(0)
}

// --- Filesystem operations ---

func (h *Handler) sysUnlinkat(c arch.CPU, dirfd, pathAddr, flags uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	err = h.FS.Unlinkat(int(int32(dirfd)), path, int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysChdir(c arch.CPU, pathAddr uint64) {
	path, err := h.readGuestString(pathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	err = h.FS.Chdir(path)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysFtruncate(c arch.CPU, fd, length uint64) {
	// If backed by a host file (memfd), truncate the real file
	if hf := h.FS.GetHostFile(int(fd)); hf != nil {
		if err := hf.Truncate(int64(length)); err != nil {
			c.SetSyscallReturn(negErrno(EINVAL))
			return
		}
		c.SetSyscallReturn(0)
		return
	}
	err := h.FS.Ftruncate(int(fd), int64(length))
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysFallocate(c arch.CPU, fd, mode, offset, length uint64) {
	// Simplified: just extend the file if needed
	total := int64(offset + length)
	err := h.FS.Ftruncate(int(fd), total)
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSymlinkat(c arch.CPU, targetAddr, dirfd, linkpathAddr uint64) {
	target, err := h.readGuestString(targetAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	linkpath, err := h.readGuestString(linkpathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	err = h.FS.Symlinkat(target, int(int32(dirfd)), linkpath)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysRenameat(c arch.CPU, olddirfd, oldpathAddr, newdirfd, newpathAddr uint64) {
	oldpath, err := h.readGuestString(oldpathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	newpath, err := h.readGuestString(newpathAddr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	err = h.FS.Renameat(int(int32(olddirfd)), oldpath, int(int32(newdirfd)), newpath)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

// --- Time syscalls ---

func (h *Handler) sysClockNanosleep(c arch.CPU, clockID, flags, reqAddr, remAddr uint64) {
	if reqAddr == 0 {
		c.SetSyscallReturn(0)
		return
	}
	sec, _ := h.Mem.Read64(reqAddr)
	nsec, _ := h.Mem.Read64(reqAddr + 8)

	if flags&1 != 0 { // TIMER_ABSTIME
		target := time.Unix(int64(sec), int64(nsec))
		d := time.Until(target)
		if d > 0 && d < 60*time.Second {
			time.Sleep(d)
		}
	} else {
		d := time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond
		if d > 0 && d < 60*time.Second {
			time.Sleep(d)
		}
	}
	// Write zero to remaining time
	if remAddr != 0 {
		h.Mem.Write64(remAddr, 0)
		h.Mem.Write64(remAddr+8, 0)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetitimer(c arch.CPU, which, currValue uint64) {
	if currValue != 0 {
		// struct itimerval = 2 × struct timeval = 2 × (8+8) = 32 bytes
		data := make([]byte, 32)
		h.Mem.WriteBytes(currValue, data) // zero-filled = timer disabled
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSetitimer(c arch.CPU, which, newValue, oldValue uint64) {
	if oldValue != 0 {
		data := make([]byte, 32)
		h.Mem.WriteBytes(oldValue, data) // return old as zero
	}
	c.SetSyscallReturn(0)
}

// --- ppoll ---

func (h *Handler) sysPpoll(c arch.CPU, fdsAddr, nfds, timeoutAddr, sigmask uint64) {
	if nfds == 0 {
		c.SetSyscallReturn(0)
		return
	}
	// Build host pollfd array by translating guest fds → host fds.
	// struct pollfd: fd(4) + events(2) + revents(2) = 8 bytes
	const pollfdSize = 8
	hostFDs := make([]unix.PollFd, 0, nfds)
	guestFDIdx := make([]int, 0, nfds) // guest fd number for each hostFD entry
	for i := uint64(0); i < nfds; i++ {
		off := fdsAddr + i*pollfdSize
		gfd32, _ := h.Mem.Read32(off)
		events, _ := h.Mem.Read16(off + 4)
		gfd := int(int32(gfd32))
		hfd := h.FS.GetHostFDNum(gfd)
		if hfd < 0 {
			// Non-host fd (VFS file) - skip from real poll, mark no events
			continue
		}
		hostFDs = append(hostFDs, unix.PollFd{Fd: int32(hfd), Events: int16(events)})
		guestFDIdx = append(guestFDIdx, int(i))
	}

	// Build timeout
	var timeoutMs int
	if timeoutAddr == 0 {
		timeoutMs = -1 // block indefinitely
	} else {
		sec, _ := h.Mem.Read64(timeoutAddr)
		nsec, _ := h.Mem.Read64(timeoutAddr + 8)
		ms := int64(sec)*1000 + int64(nsec)/1_000_000
		if ms < 0 {
			ms = 0
		}
		timeoutMs = int(ms)
	}

	var n int
	var err error
	if len(hostFDs) > 0 {
		n, err = unix.Poll(hostFDs, timeoutMs)
	} else {
		// No host fds to poll - sleep for timeout and return 0
		if timeoutMs > 0 {
			time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		}
		c.SetSyscallReturn(0)
		return
	}
	if err != nil {
		if err == syscall.EINTR {
			c.SetSyscallReturn(negErrno(EINTR))
		} else {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		}
		return
	}

	// Write revents back into guest pollfd structs
	for j, idx := range guestFDIdx {
		off := fdsAddr + uint64(idx)*pollfdSize
		h.Mem.Write16(off+6, uint16(hostFDs[j].Revents))
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysPrctl(c arch.CPU, option, arg uint64) {
	switch option {
	case 15: // PR_SET_NAME
		c.SetSyscallReturn(0)
	case 16: // PR_GET_NAME
		h.Mem.WriteBytes(arg, append([]byte("govm"), 0))
		c.SetSyscallReturn(0)
	default:
		c.SetSyscallReturn(0)
	}
}

func (h *Handler) sysArchPrctl(c arch.CPU, code, addr uint64) {
	switch code {
	case 0x1001: // ARCH_SET_GS
		c.SetSyscallReturn(0)
	case 0x1002: // ARCH_SET_FS
		c.SetTLS(addr)
		c.SetSyscallReturn(0)
	case 0x1003: // ARCH_GET_FS
		h.Mem.Write64(addr, c.GetTLS())
		c.SetSyscallReturn(0)
	case 0x1004: // ARCH_GET_GS
		h.Mem.Write64(addr, 0)
		c.SetSyscallReturn(0)
	default:
		c.SetSyscallReturn(negErrno(EINVAL))
	}
}

func (h *Handler) sysFutex(c arch.CPU, uaddr, op, val, timeout uint64) {
	futexOp := op & 0x7F // mask out FUTEX_PRIVATE_FLAG

	switch futexOp {
	case 0, 9: // FUTEX_WAIT / FUTEX_WAIT_BITSET
		// Read current value at uaddr
		cur, err := h.Mem.Read32(uaddr)
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		if cur != uint32(val) {
			c.SetSyscallReturn(negErrno(EAGAIN))
			return
		}
		// For single-threaded, we'd block forever. Use thread manager if available.
		if h.ThreadM != nil {
			h.ThreadM.FutexWait(uaddr, uint32(val))
		}
		c.SetSyscallReturn(0)

	case 1, 10: // FUTEX_WAKE / FUTEX_WAKE_BITSET
		woken := 0
		if h.ThreadM != nil {
			woken = h.ThreadM.FutexWake(uaddr, int(val))
		}
		c.SetSyscallReturn(uint64(woken))

	default:
		c.SetSyscallReturn(0)
	}
}

// sysPollInt handles x64's poll(2) where timeout is int milliseconds (not *timespec).
func (h *Handler) sysPollInt(c arch.CPU, fdsAddr, nfds uint64, timeoutMs int32) {
	if nfds == 0 {
		if timeoutMs > 0 {
			time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		}
		c.SetSyscallReturn(0)
		return
	}
	const pollfdSize = 8
	hostFDs := make([]unix.PollFd, 0, nfds)
	guestFDIdx := make([]int, 0, nfds)
	for i := uint64(0); i < nfds; i++ {
		off := fdsAddr + i*pollfdSize
		gfd32, _ := h.Mem.Read32(off)
		events, _ := h.Mem.Read16(off + 4)
		gfd := int(int32(gfd32))
		hfd := h.FS.GetHostFDNum(gfd)
		if hfd < 0 {
			continue
		}
		hostFDs = append(hostFDs, unix.PollFd{Fd: int32(hfd), Events: int16(events)})
		guestFDIdx = append(guestFDIdx, int(i))
	}
	var n int
	var err error
	if len(hostFDs) > 0 {
		n, err = unix.Poll(hostFDs, int(timeoutMs))
	} else {
		// All polled FDs are emulated (no host backing). Sleep to avoid spinning.
		switch {
		case timeoutMs == 0:
			// non-blocking poll: just return 0
		case timeoutMs > 0:
			time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		default: // -1 (infinite)
			time.Sleep(10 * time.Millisecond)
		}
		c.SetSyscallReturn(0)
		return
	}
	if err != nil {
		if err == syscall.EINTR {
			c.SetSyscallReturn(negErrno(EINTR))
			return
		}
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	// Write revents back
	for j, idx := range guestFDIdx {
		off := fdsAddr + uint64(idx)*pollfdSize
		h.Mem.Write16(off+6, uint16(hostFDs[j].Revents))
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysClone(c arch.CPU, flags, childStack, parentTid, a3, a4 uint64) {
	tls := uint64(0)
	childTid := a4
	if c.GetArch() == arch.ArchAMD64 {
		// x86_64: flags, stack, parent_tid, child_tid, tls
		childTid = a3
		tls = a4
	}

	// If this is a thread creation (CLONE_THREAD is the definitive flag for pthreads).
	// posix_spawn and vfork use CLONE_VM|CLONE_VFORK but NOT CLONE_THREAD; those
	// should fall through to the fork-like path and fail gracefully.
	if h.ThreadM != nil && flags&0x10000 != 0 { // CLONE_THREAD
		childPC := c.SyscallReturnPC()
		if childStack == 0 {
			childStack = c.GetSP()
		}
		childTLS := uint64(0)
		if flags&0x00080000 != 0 { // CLONE_SETTLS
			childTLS = tls
		}
		tid, err := h.ThreadM.Clone(c, childPC, childStack, childTLS, 0, 0)
		if err != nil {
			c.SetSyscallReturn(negErrno(ENOMEM))
			return
		}
		// Write TID to child_tidptr if CLONE_CHILD_SETTID (0x01000000)
		if flags&0x01000000 != 0 && childTid != 0 {
			h.Mem.Write32(childTid, uint32(tid))
		}
		// Write TID to parent_tidptr if CLONE_PARENT_SETTID (0x00100000)
		if flags&0x00100000 != 0 && parentTid != 0 {
			h.Mem.Write32(parentTid, uint32(tid))
		}
		c.SetSyscallReturn(uint64(tid))
	} else {
		// fork-like (posix_spawn, vfork): if CLONE_VFORK, run the child as a
		// goroutine that can call execve to launch a real host process, then
		// unblocks the parent.  Without CLONE_VFORK just fail immediately.
		const CLONE_VFORK = 0x4000
		if flags&CLONE_VFORK != 0 {
			gpid := h.allocGuestPID()
			ch := make(chan int, 1)
			snap := h.FS.SnapshotFDs() // save parent FD table before child modifies it
			h.vforkMu.Lock()
			h.vforkPending = true
			h.vforkDone = ch
			h.vforkSnapshot = snap
			h.vforkMu.Unlock()
			// Child goroutine: clone the CPU state and run until execve/exit.
			childCPU := c.CloneForThread()
			childCPU.SetSyscallReturn(0) // child sees pid 0
			if childStack != 0 {
				childCPU.SetSP(childStack)
			}
			childCPU.SetSyscallHandler(h.Handle)
			go func() {
				if err2 := childCPU.Run(); err2 != nil {
					fmt.Fprintf(os.Stderr, "[govm] vfork-child exited: %v\n", err2)
				}
				// If child exited without execve, restore FD table and unblock parent.
				h.vforkMu.Lock()
				pending := h.vforkPending
				h.vforkPending = false
				savedSnap := h.vforkSnapshot
				h.vforkMu.Unlock()
				if pending {
					h.FS.RestoreFDs(savedSnap)
					ch <- gpid
				}
			}()
			// Parent blocks until child calls execve (or exits).
			guestPID := <-ch
			c.SetSyscallReturn(uint64(guestPID))
		} else {
			fmt.Fprintf(os.Stderr, "[govm] clone fork-like flags=0x%x → ENOSYS\n", flags)
			c.SetSyscallReturn(negErrno(ENOSYS))
		}
	}
}

// sysClone3 handles the clone3(2) syscall (x86-64 SYS 435).
// Unlike clone(2), clone3 passes a pointer to struct clone_args rather than
// individual register arguments.
//
// struct clone_args layout (CLONE_ARGS_SIZE_VER0 = 64 bytes):
//
//	u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls
func (h *Handler) sysClone3(c arch.CPU, uargsPtr, size uint64) {
	if size < 64 {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	// Read struct clone_args from guest memory.
	buf, err := h.Mem.ReadBytes(uargsPtr, 64)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	flags := binary.LittleEndian.Uint64(buf[0:8])
	pidfdPtr := binary.LittleEndian.Uint64(buf[8:16])
	childTid := binary.LittleEndian.Uint64(buf[16:24])
	parentTid := binary.LittleEndian.Uint64(buf[24:32])
	// exit_signal at buf[32:40] - not used beyond SIGCHLD detection
	stack := binary.LittleEndian.Uint64(buf[40:48])
	stackSize := binary.LittleEndian.Uint64(buf[48:56])
	tls := binary.LittleEndian.Uint64(buf[56:64])

	if h.ThreadM != nil && flags&0x10000 != 0 { // CLONE_THREAD → pthread creation
		childPC := c.SyscallReturnPC()
		childStack := stack + stackSize // stack grows down: top = base + size
		if childStack == 0 {
			childStack = c.GetSP()
		}
		childTLS := uint64(0)
		if flags&0x00080000 != 0 { // CLONE_SETTLS
			childTLS = tls
		}

		tid, err := h.ThreadM.Clone(c, childPC, childStack, childTLS, stack, stackSize)
		if err != nil {
			c.SetSyscallReturn(negErrno(ENOMEM))
			return
		}
		if flags&0x01000000 != 0 && childTid != 0 { // CLONE_CHILD_SETTID
			h.Mem.Write32(childTid, uint32(tid))
		}
		if flags&0x00100000 != 0 && parentTid != 0 { // CLONE_PARENT_SETTID
			h.Mem.Write32(parentTid, uint32(tid))
		}
		if flags&0x1000 != 0 && pidfdPtr != 0 { // CLONE_PIDFD
			// Write a fake pidfd (-1) so callers that require a valid fd get
			// a safe sentinel.  The real pidfd model isn't implemented.
			h.Mem.Write32(pidfdPtr, ^uint32(0))
		}
		c.SetSyscallReturn(uint64(tid))
	} else {
		// Process-creation (fork-like, posix_spawn, vfork).
		const CLONE_VFORK = 0x4000
		if flags&CLONE_VFORK != 0 {
			gpid := h.allocGuestPID()
			ch := make(chan int, 1)
			snap := h.FS.SnapshotFDs()
			h.vforkMu.Lock()
			h.vforkPending = true
			h.vforkDone = ch
			h.vforkSnapshot = snap
			h.vforkMu.Unlock()
			childCPU := c.CloneForThread()
			childCPU.SetSyscallReturn(0)
			if stack != 0 {
				childCPU.SetSP(stack + stackSize)
			}
			childCPU.SetSyscallHandler(h.Handle)
			if flags&0x00080000 != 0 && tls != 0 { // CLONE_SETTLS
				childCPU.SetTLS(tls)
			}
			go func() {
				if err2 := childCPU.Run(); err2 != nil {
					fmt.Fprintf(os.Stderr, "[govm] vfork-child exited: %v\n", err2)
				}
				h.vforkMu.Lock()
				pending := h.vforkPending
				h.vforkPending = false
				savedSnap := h.vforkSnapshot
				h.vforkMu.Unlock()
				if pending {
					h.FS.RestoreFDs(savedSnap)
					ch <- gpid
				}
			}()
			guestPID := <-ch
			if flags&0x1000 != 0 && pidfdPtr != 0 { // CLONE_PIDFD
				h.Mem.Write32(pidfdPtr, ^uint32(0))
			}
			c.SetSyscallReturn(uint64(guestPID))
		} else {
			fmt.Fprintf(os.Stderr, "[govm] clone3 fork-like flags=0x%x → ENOSYS\n", flags)
			c.SetSyscallReturn(negErrno(ENOSYS))
		}
	}
}

func (h *Handler) sysWrite(c arch.CPU, fdNum, bufAddr, count uint64) {
	data, err := h.Mem.ReadBytes(bufAddr, int(count))
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	n, err := h.FS.Write(int(fdNum), data)
	if err != nil {
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysWritev(c arch.CPU, fdNum, iovAddr, iovcnt uint64) {
	// Debug: dump heap before error output
	if h.Trace && fdNum == 2 {
		heapBase := h.Mem.GetBrkBase()
		if heapBase != 0 {
			// Dump first 2048 bytes for better visibility
			if data, err := h.Mem.ReadBytes(heapBase, 2048); err == nil {
				fmt.Fprintf(os.Stderr, "[heap-dump] base=0x%x\n", heapBase)
				// Print as 8-byte words for easier reading
				for off := 0; off+8 <= len(data); off += 8 {
					val := binary.LittleEndian.Uint64(data[off:])
					if val != 0 || off < 64 || off > len(data)-64 {
						fmt.Fprintf(os.Stderr, "  +0x%04x: 0x%016x\n", off, val)
					}
				}
			}
		}
	}
	var total uint64
	for i := uint64(0); i < iovcnt; i++ {
		base, err := h.Mem.Read64(iovAddr + i*16)
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		length, err := h.Mem.Read64(iovAddr + i*16 + 8)
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		data, err := h.Mem.ReadBytes(base, int(length))
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		if h.Trace {
			if hfd := h.FS.GetHostFDNum(int(fdNum)); hfd >= 0 {
				disp := data
				if len(disp) > 24 {
					disp = disp[:24]
				}
				fmt.Fprintf(os.Stderr, "[govm] writev(fd=%d→hfd=%d, buf=%d, base=0x%x): %02x\n", fdNum, hfd, length, base, disp)
			}
		}
		n, err := h.FS.Write(int(fdNum), data)
		if err != nil {
			c.SetSyscallReturn(negErrno(EBADF))
			return
		}
		total += uint64(n)
	}
	c.SetSyscallReturn(total)
}

func (h *Handler) sysRead(c arch.CPU, fdNum, bufAddr, count uint64) {
	buf := make([]byte, count)
	n, err := h.FS.Read(int(fdNum), buf)
	if err != nil && err != io.EOF {
		hfd := h.FS.GetHostFDNum(int(fdNum))
		fmt.Fprintf(os.Stderr, "[govm] read(fd=%d→hfd=%d) err=%v\n", fdNum, hfd, err)
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	if n > 0 {
		if h.Trace {
			if hfd := h.FS.GetHostFDNum(int(fdNum)); hfd >= 0 {
				fmt.Fprintf(os.Stderr, "[govm] read(fd=%d→hfd=%d, n=%d): %02x\n", fdNum, hfd, n, buf[:min(8, n)])
			}
		}
		if err := h.Mem.WriteBytes(bufAddr, buf[:n]); err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysPread64(c arch.CPU, fdNum, bufAddr, count, offset uint64) {
	buf := make([]byte, count)
	n, err := h.FS.Pread(int(fdNum), buf, int64(offset))
	if err != nil && err != io.EOF {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	if n > 0 {
		if err := h.Mem.WriteBytes(bufAddr, buf[:n]); err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysPwrite64(c arch.CPU, fdNum, bufAddr, count, offset uint64) {
	data, err := h.Mem.ReadBytes(bufAddr, int(count))
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	n, err := h.FS.Pwrite(int(fdNum), data, int64(offset))
	if err != nil {
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysSendfile(c arch.CPU, outFd, inFd, offsetAddr, count uint64) {
	buf := make([]byte, count)
	n, err := h.FS.Read(int(inFd), buf)
	if err != nil || n == 0 {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	wn, err := h.FS.Write(int(outFd), buf[:n])
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	if offsetAddr != 0 {
		off, _ := h.Mem.Read64(offsetAddr)
		off += uint64(n)
		h.Mem.Write64(offsetAddr, off)
	}
	c.SetSyscallReturn(uint64(wn))
}

func (h *Handler) sysReadv(c arch.CPU, fdNum, iovAddr, iovcnt uint64) {
	var total uint64
	for i := uint64(0); i < iovcnt; i++ {
		base, err := h.Mem.Read64(iovAddr + i*16)
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		length, err := h.Mem.Read64(iovAddr + i*16 + 8)
		if err != nil {
			c.SetSyscallReturn(negErrno(EFAULT))
			return
		}
		buf := make([]byte, length)
		n, err := h.FS.Read(int(fdNum), buf)
		if err != nil && err != io.EOF {
			if total > 0 {
				break
			}
			c.SetSyscallReturn(negErrno(EBADF))
			return
		}
		if n > 0 {
			if err := h.Mem.WriteBytes(base, buf[:n]); err != nil {
				c.SetSyscallReturn(negErrno(EFAULT))
				return
			}
		}
		total += uint64(n)
		if n < int(length) || err == io.EOF {
			break
		}
	}
	c.SetSyscallReturn(total)
}

// ===================================================================
// Socket syscalls - AF_UNIX uses in-memory VFS sockets; AF_INET and
// AF_INET6 pass through to real host sockets.
// ===================================================================

const (
	AF_INET  = 2
	AF_INET6 = 10
)

func (h *Handler) sysSocket(c arch.CPU, domain, sockType, protocol uint64) {
	stype := int(sockType & 0xff) // strip SOCK_CLOEXEC/SOCK_NONBLOCK
	if h.Trace {
		fmt.Fprintf(os.Stderr, "[govm] socket(domain=%d, type=%d)\n", domain, stype)
	}

	if domain == vfs.AF_UNIX {
		// Use a real host socket so the guest can connect to host AF_UNIX sockets
		// (Wayland, D-Bus, X11, etc.). Preserve SOCK_CLOEXEC/SOCK_NONBLOCK flags.
		hostFlags := int(sockType) | syscall.SOCK_CLOEXEC
		hostFD, err := syscall.Socket(syscall.AF_UNIX, hostFlags, 0)
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		gfd := h.FS.WrapHostFD(hostFD, fmt.Sprintf("socket(AF_UNIX,%d)", stype))
		c.SetSyscallReturn(uint64(gfd))
		return
	}

	// AF_INET / AF_INET6 - create real host socket
	if domain != AF_INET && domain != AF_INET6 {
		c.SetSyscallReturn(negErrno(EAFNOSUPPORT))
		return
	}
	hostFD, err := syscall.Socket(int(domain), stype, int(protocol))
	if err != nil {
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	gfd := h.FS.WrapHostFD(hostFD, fmt.Sprintf("socket(%d,%d)", domain, stype))
	c.SetSyscallReturn(uint64(gfd))
}

func (h *Handler) sysConnect(c arch.CPU, fd, addrPtr, addrLen uint64) {
	// Host socket?
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		sa := h.parseSockaddr(addrPtr, addrLen)
		if sa == nil {
			c.SetSyscallReturn(negErrno(EINVAL))
			return
		}
		err := syscall.Connect(hostFD, sa)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[govm] connect ERROR: %v\n", err)
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		c.SetSyscallReturn(0)
		return
	}
	// AF_UNIX in-memory socket
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	addrBuf := h.readBytes(addrPtr, addrLen)
	if len(addrBuf) < 3 {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	path := extractUnixPath(addrBuf)
	if err := sock.Connect(path); err != nil {
		c.SetSyscallReturn(negErrno(ECONNREFUSED))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysBind(c arch.CPU, fd, addrPtr, addrLen uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		sa := h.parseSockaddr(addrPtr, addrLen)
		if sa == nil {
			c.SetSyscallReturn(negErrno(EINVAL))
			return
		}
		err := syscall.Bind(hostFD, sa)
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		c.SetSyscallReturn(0)
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	addrBuf := h.readBytes(addrPtr, addrLen)
	if len(addrBuf) < 3 {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	path := extractUnixPath(addrBuf)
	if err := sock.Bind(path); err != nil {
		c.SetSyscallReturn(negErrno(EADDRINUSE))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysListen(c arch.CPU, fd, backlog uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		err := syscall.Listen(hostFD, int(backlog))
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		c.SetSyscallReturn(0)
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	if err := sock.Listen(int(backlog)); err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysAccept4(c arch.CPU, fd, addrPtr, addrLenPtr, flags uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		nfd, sa, err := syscall.Accept(hostFD)
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		// Write peer address back if requested
		if addrPtr != 0 && addrLenPtr != 0 {
			h.writeSockaddr(addrPtr, addrLenPtr, sa)
		}
		gfd := h.FS.WrapHostFD(nfd, "accepted")
		c.SetSyscallReturn(uint64(gfd))
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	newSock, err := sock.Accept()
	if err != nil {
		c.SetSyscallReturn(negErrno(EAGAIN))
		return
	}
	h.FS.Lock()
	gfd := h.FS.AllocSocketUnlocked(newSock)
	h.FS.Unlock()
	c.SetSyscallReturn(uint64(gfd))
}

func (h *Handler) sysSendto(c arch.CPU, fd, bufAddr, bufLen, flags, destAddr, destLen uint64) {
	// Try host FD first (covers both host-backed sockets and HostFile FDs)
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		buf := h.readBytes(bufAddr, bufLen)
		n, err := syscall.Write(hostFD, buf)
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		c.SetSyscallReturn(uint64(n))
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock != nil {
		buf := h.readBytes(bufAddr, bufLen)
		n, err := sock.Write(buf)
		if err != nil {
			c.SetSyscallReturn(negErrno(ECONNRESET))
			return
		}
		c.SetSyscallReturn(uint64(n))
		return
	}
	// Fallback to VFS write
	buf := h.readBytes(bufAddr, bufLen)
	n, err := h.FS.Write(int(fd), buf)
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysRecvfrom(c arch.CPU, fd, bufAddr, bufLen, flags, srcAddr, srcLenPtr uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		buf := make([]byte, bufLen)
		n, err := syscall.Read(hostFD, buf)
		if err != nil {
			if h.Trace {
				fmt.Fprintf(os.Stderr, "[govm] recvfrom(fd=%d→hfd=%d, len=%d) err=%v\n", fd, hostFD, bufLen, err)
			}
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		if n > 0 {
			if h.Trace {
				fmt.Fprintf(os.Stderr, "[govm] recvfrom(fd=%d→hfd=%d, n=%d): %02x\n", fd, hostFD, n, buf[:min(64, n)])
			}
			h.Mem.WriteBytes(bufAddr, buf[:n])
		}
		c.SetSyscallReturn(uint64(n))
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock != nil {
		buf := make([]byte, bufLen)
		n, err := sock.Read(buf)
		if err != nil {
			c.SetSyscallReturn(negErrno(ECONNRESET))
			return
		}
		if n > 0 {
			h.Mem.WriteBytes(bufAddr, buf[:n])
		}
		c.SetSyscallReturn(uint64(n))
		return
	}
	// Fallback to VFS read
	buf := make([]byte, bufLen)
	n, err := h.FS.Read(int(fd), buf)
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	if n > 0 {
		h.Mem.WriteBytes(bufAddr, buf[:n])
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysShutdown(c arch.CPU, fd, how uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		err := syscall.Shutdown(hostFD, int(how))
		if err != nil {
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		c.SetSyscallReturn(0)
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	sock.Close()
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSocketpair(c arch.CPU, domain, sockType, protocol, sv uint64) {
	fds, err := syscall.Socketpair(int(domain), int(sockType), int(protocol))
	if err != nil {
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	gfd0 := h.FS.WrapHostFD(fds[0], "socketpair")
	gfd1 := h.FS.WrapHostFD(fds[1], "socketpair")
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(gfd0))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(gfd1))
	h.Mem.WriteBytes(sv, buf[:])
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetsockopt(c arch.CPU, fd, level, optname, optval, optlen uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		if optval != 0 && optlen != 0 {
			lenBuf := h.readBytes(optlen, 4)
			if len(lenBuf) >= 4 {
				olen := int(binary.LittleEndian.Uint32(lenBuf))
				val, err := syscall.GetsockoptInt(hostFD, int(level), int(optname))
				if err != nil {
					// fallback: return 0
					var buf [4]byte
					h.Mem.WriteBytes(optval, buf[:])
				} else if olen >= 4 {
					var buf [4]byte
					binary.LittleEndian.PutUint32(buf[:], uint32(val))
					h.Mem.WriteBytes(optval, buf[:])
				}
				_ = val
			}
		}
		c.SetSyscallReturn(0)
		return
	}
	// Stub for VFS sockets
	if optval != 0 && optlen != 0 {
		lenBuf := h.readBytes(optlen, 4)
		if len(lenBuf) >= 4 {
			olen := binary.LittleEndian.Uint32(lenBuf)
			if olen >= 4 {
				var buf [4]byte
				h.Mem.WriteBytes(optval, buf[:])
			}
		}
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysSetsockopt(c arch.CPU, fd, level, optname, optval, optlen uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 && optval != 0 && optlen >= 4 {
		valBuf := h.readBytes(optval, 4)
		val := int(binary.LittleEndian.Uint32(valBuf))
		syscall.SetsockoptInt(hostFD, int(level), int(optname), val)
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetsockname(c arch.CPU, fd, addrPtr, addrLenPtr uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		sa, err := syscall.Getsockname(hostFD)
		if err == nil && addrPtr != 0 && addrLenPtr != 0 {
			h.writeSockaddr(addrPtr, addrLenPtr, sa)
		}
		c.SetSyscallReturn(0)
		return
	}
	// Minimal stub: return AF_UNIX + empty path
	if addrPtr != 0 && addrLenPtr != 0 {
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(vfs.AF_UNIX))
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 2)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetpeername(c arch.CPU, fd, addrPtr, addrLenPtr uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD >= 0 {
		sa, err := syscall.Getpeername(hostFD)
		if err == nil && addrPtr != 0 && addrLenPtr != 0 {
			h.writeSockaddr(addrPtr, addrLenPtr, sa)
		}
		c.SetSyscallReturn(0)
		return
	}
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.SetSyscallReturn(negErrno(ENOTSOCK))
		return
	}
	if addrPtr != 0 && addrLenPtr != 0 {
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(vfs.AF_UNIX))
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 2)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	}
	c.SetSyscallReturn(0)
}

// parseSockaddr reads a Linux sockaddr from guest memory and returns a Go Sockaddr.
func (h *Handler) parseSockaddr(addrPtr, addrLen uint64) syscall.Sockaddr {
	buf := h.readBytes(addrPtr, addrLen)
	if len(buf) < 2 {
		return nil
	}
	family := binary.LittleEndian.Uint16(buf)
	switch family {
	case AF_INET:
		if len(buf) < 8 {
			return nil
		}
		port := int(buf[2])<<8 | int(buf[3])
		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], buf[4:8])
		return sa
	case AF_INET6:
		if len(buf) < 28 {
			return nil
		}
		port := int(buf[2])<<8 | int(buf[3])
		sa := &syscall.SockaddrInet6{Port: port}
		// flowinfo at [4:8], skip
		copy(sa.Addr[:], buf[8:24])
		// scope_id at [24:28]
		sa.ZoneId = binary.LittleEndian.Uint32(buf[24:28])
		return sa
	case vfs.AF_UNIX:
		path := extractUnixPath(buf)
		return &syscall.SockaddrUnix{Name: path}
	}
	return nil
}

// writeSockaddr writes a Go Sockaddr back to guest memory.
func (h *Handler) writeSockaddr(addrPtr, addrLenPtr uint64, sa syscall.Sockaddr) {
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		var buf [16]byte
		binary.LittleEndian.PutUint16(buf[0:], AF_INET)
		buf[2] = byte(a.Port >> 8)
		buf[3] = byte(a.Port)
		copy(buf[4:8], a.Addr[:])
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 16)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	case *syscall.SockaddrInet6:
		var buf [28]byte
		binary.LittleEndian.PutUint16(buf[0:], AF_INET6)
		buf[2] = byte(a.Port >> 8)
		buf[3] = byte(a.Port)
		copy(buf[8:24], a.Addr[:])
		binary.LittleEndian.PutUint32(buf[24:], a.ZoneId)
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 28)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	case *syscall.SockaddrUnix:
		var buf [110]byte
		binary.LittleEndian.PutUint16(buf[0:], uint16(vfs.AF_UNIX))
		copy(buf[2:], a.Name)
		sz := uint32(2 + len(a.Name) + 1)
		h.Mem.WriteBytes(addrPtr, buf[:sz])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], sz)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	}
}

// extractUnixPath extracts the path from a sockaddr_un buffer.
// Format: family(2 bytes LE) + path (up to 108 bytes).
// Handles both concrete paths (null-terminated) and Linux abstract sockets
// (first path byte is \0; the rest is the abstract name up to end of buf).
func extractUnixPath(buf []byte) string {
	if len(buf) <= 2 {
		return ""
	}
	pathBytes := buf[2:]
	if len(pathBytes) == 0 {
		return ""
	}
	if pathBytes[0] == 0 {
		// Abstract socket: leading null is NOT a terminator.
		// The name spans from buf[2] to end of the trimmed buffer.
		return string(pathBytes)
	}
	for i, b := range pathBytes {
		if b == 0 {
			return string(pathBytes[:i])
		}
	}
	return string(pathBytes)
}

// ===================================================================
// sendmsg / recvmsg with SCM_RIGHTS FD translation
// ===================================================================

// RISC-V 64-bit struct msghdr layout:
//   msg_name       8 bytes (ptr)
//   msg_namelen    4 bytes (uint32) + 4 pad
//   msg_iov        8 bytes (ptr)
//   msg_iovlen     8 bytes (size_t)
//   msg_control    8 bytes (ptr)
//   msg_controllen 8 bytes (size_t)
//   msg_flags      4 bytes (int) + 4 pad
// Total: 56 bytes

func (h *Handler) sysSendmsg(c arch.CPU, fd, msgPtr, flags uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD < 0 {
		// Try socket
		sock := h.FS.GetSocket(int(fd))
		if sock == nil {
			c.SetSyscallReturn(negErrno(ENOTSOCK))
			return
		}
		hostFD = sock.HostFD()
		if hostFD < 0 {
			c.SetSyscallReturn(negErrno(ENOTCONN))
			return
		}
	}

	// Parse msghdr from guest memory
	hdr := h.readBytes(msgPtr, 56)
	if len(hdr) < 56 {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}

	iovPtr := binary.LittleEndian.Uint64(hdr[16:])
	iovLen := binary.LittleEndian.Uint64(hdr[24:])
	controlPtr := binary.LittleEndian.Uint64(hdr[32:])
	controlLen := binary.LittleEndian.Uint64(hdr[40:])

	// Gather iov data
	var payload []byte
	for i := uint64(0); i < iovLen; i++ {
		iovEntry := h.readBytes(iovPtr+i*16, 16)
		base := binary.LittleEndian.Uint64(iovEntry[0:])
		blen := binary.LittleEndian.Uint64(iovEntry[8:])
		if blen > 0 {
			payload = append(payload, h.readBytes(base, blen)...)
		}
	}

	// Process control messages - translate guest FDs to host FDs
	var oob []byte
	if controlLen > 0 && controlPtr != 0 {
		guestCtrl := h.readBytes(controlPtr, controlLen)
		cmsgs := ParseCmsgs(guestCtrl)
		for _, cm := range cmsgs {
			if cm.Level == 1 && cm.Type == vfs.SCM_RIGHTS { // SOL_SOCKET=1
				// Translate guest FDs → host FDs
				guestFDs := ExtractSCMRightsFDs(cm.Data)
				hostFDs := make([]int, len(guestFDs))
				for j, gfd := range guestFDs {
					hfd := h.FS.GetHostFDNum(int(gfd))
					if hfd < 0 {
						c.SetSyscallReturn(negErrno(EBADF))
						return
					}
					hostFDs[j] = hfd
				}
				oob = syscall.UnixRights(hostFDs...)
			} else {
				// Pass through non-SCM_RIGHTS control messages
				oob = append(oob, BuildCmsg(cm.Level, cm.Type, cm.Data)...)
			}
		}
	}

	err := syscall.Sendmsg(hostFD, payload, oob, nil, int(flags))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[govm] sendmsg(fd=%d→hfd=%d, len=%d) err=%v\n", fd, hostFD, len(payload), err)
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	fmt.Fprintf(os.Stderr, "[govm] sendmsg(fd=%d→hfd=%d, len=%d): %02x\n", fd, hostFD, len(payload), payload[:min(8, len(payload))])
	c.SetSyscallReturn(uint64(len(payload)))
}

func (h *Handler) sysRecvmsg(c arch.CPU, fd, msgPtr, flags uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD < 0 {
		sock := h.FS.GetSocket(int(fd))
		if sock == nil {
			c.SetSyscallReturn(negErrno(ENOTSOCK))
			return
		}
		hostFD = sock.HostFD()
		if hostFD < 0 {
			c.SetSyscallReturn(negErrno(ENOTCONN))
			return
		}
	}

	// Parse msghdr from guest memory
	hdr := h.readBytes(msgPtr, 56)
	if len(hdr) < 56 {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}

	iovPtr := binary.LittleEndian.Uint64(hdr[16:])
	iovLen := binary.LittleEndian.Uint64(hdr[24:])
	controlPtr := binary.LittleEndian.Uint64(hdr[32:])
	controlLen := binary.LittleEndian.Uint64(hdr[40:])

	// Calculate total iov capacity
	var totalCap uint64
	iovEntries := make([]struct{ base, blen uint64 }, iovLen)
	for i := uint64(0); i < iovLen; i++ {
		iovEntry := h.readBytes(iovPtr+i*16, 16)
		iovEntries[i].base = binary.LittleEndian.Uint64(iovEntry[0:])
		iovEntries[i].blen = binary.LittleEndian.Uint64(iovEntry[8:])
		totalCap += iovEntries[i].blen
	}

	buf := make([]byte, totalCap)
	oob := make([]byte, controlLen+256) // extra space for FDs

	n, oobn, _, _, err := syscall.Recvmsg(hostFD, buf, oob, int(flags))
	if err != nil {
		if h.debugX11 {
			fmt.Fprintf(os.Stderr, "[govm] recvmsg(fd=%d→hfd=%d, len=%d) err=%v\n", fd, hostFD, totalCap, err)
		}
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
	if h.debugX11 && n > 0 {
		disp := buf[:n]
		if len(disp) > 64 {
			disp = disp[:64]
		}
		fmt.Fprintf(os.Stderr, "[govm] recvmsg(fd=%d→hfd=%d, n=%d, iovs=%d): %x\n", fd, hostFD, n, iovLen, disp)
		for i, iov := range iovEntries {
			fmt.Fprintf(os.Stderr, "[govm]   iov[%d]: base=0x%x len=%d\n", i, iov.base, iov.blen)
		}
	}

	// Scatter received data into guest iov
	off := 0
	for _, iov := range iovEntries {
		if off >= n {
			break
		}
		chunk := n - off
		if uint64(chunk) > iov.blen {
			chunk = int(iov.blen)
		}
		if h.debugX11 {
			fmt.Fprintf(os.Stderr, "[govm]   scatter %d bytes at 0x%x: %x\n", chunk, iov.base, buf[off:off+chunk])
		}
		h.Mem.WriteBytes(iov.base, buf[off:off+chunk])
		off += chunk
	}

	// Process received control messages - reverse-translate host FDs to guest FDs
	if oobn > 0 && controlPtr != 0 && controlLen > 0 {
		cmsgs := ParseCmsgs(oob[:oobn])
		var guestCtrl []byte
		for _, cm := range cmsgs {
			if cm.Level == 1 && cm.Type == vfs.SCM_RIGHTS { // SOL_SOCKET=1
				hostFDs := ExtractSCMRightsFDs(cm.Data)
				guestFDs := make([]int32, len(hostFDs))
				for j, hfd := range hostFDs {
					// Wrap each received host FD as a VFS FD
					gfd := h.FS.WrapHostFD(int(hfd), fmt.Sprintf("scm_fd_%d", hfd))
					guestFDs[j] = int32(gfd)
				}
				guestCtrl = append(guestCtrl, BuildCmsg(cm.Level, cm.Type, PackSCMRightsFDs(guestFDs))...)
			} else {
				guestCtrl = append(guestCtrl, BuildCmsg(cm.Level, cm.Type, cm.Data)...)
			}
		}
		if len(guestCtrl) > int(controlLen) {
			guestCtrl = guestCtrl[:controlLen]
		}
		h.Mem.WriteBytes(controlPtr, guestCtrl)
		// Update msg_controllen
		binary.LittleEndian.PutUint64(hdr[40:], uint64(len(guestCtrl)))
		h.Mem.WriteBytes(msgPtr+40, hdr[40:48])
	}

	c.SetSyscallReturn(uint64(n))
}

// errnoFromErr extracts a numeric errno from a Go error.
func errnoFromErr(err error) uint64 {
	if err == nil {
		return 0
	}
	if errno, ok := err.(syscall.Errno); ok {
		return uint64(errno)
	}
	// os.File wraps syscall errors in *os.PathError or *os.LinkError
	if pe, ok := err.(*os.PathError); ok {
		return errnoFromErr(pe.Err)
	}
	if le, ok := err.(*os.LinkError); ok {
		return errnoFromErr(le.Err)
	}
	return EINVAL
}

// ===================================================================
// Epoll syscalls
// ===================================================================

func (h *Handler) sysEpollCreate1(c arch.CPU, flags uint64) {
	epfd := h.FS.AllocEpoll()
	c.SetSyscallReturn(uint64(epfd))
}

func (h *Handler) sysEpollCtl(c arch.CPU, epfd, op, fd, eventPtr uint64) {
	ep := h.FS.GetEpoll(int(epfd))
	if ep == nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	var events uint32
	var data uint64
	if op != uint64(vfs.EPOLL_CTL_DEL) && eventPtr != 0 {
		if c.GetArch() == arch.ArchAMD64 {
			// On x86_64, struct epoll_event is packed (12 bytes)
			evBuf := h.readBytes(eventPtr, 12)
			if len(evBuf) >= 12 {
				events = binary.LittleEndian.Uint32(evBuf[0:])
				data = binary.LittleEndian.Uint64(evBuf[4:])
			}
		} else {
			// On others (like riscv64), it's 16 bytes
			evBuf := h.readBytes(eventPtr, 16)
			if len(evBuf) >= 16 {
				events = binary.LittleEndian.Uint32(evBuf[0:])
				data = binary.LittleEndian.Uint64(evBuf[8:])
			}
		}
	}
	if err := ep.Ctl(int(op), int(fd), events, data); err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysEpollPwait(c arch.CPU, epfd, eventsPtr, maxevents, timeout uint64) {
	ep := h.FS.GetEpoll(int(epfd))
	if ep == nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}

	entries := ep.Entries()
	if len(entries) == 0 {
		// No FDs monitored - respect timeout
		if timeout > 0 && timeout != ^uint64(0) {
			time.Sleep(time.Duration(timeout) * time.Millisecond)
		}
		c.SetSyscallReturn(0)
		return
	}

	// Check eventfds and pipes first (VFS-only FDs without host backing)
	nReady := uint64(0)
	for _, e := range entries {
		if nReady >= maxevents {
			break
		}
		efd := h.FS.GetEventFD(e.GuestFD)
		if efd != nil && efd.Ready() {
			var events uint32
			if e.Events&vfs.EPOLLIN != 0 {
				events |= vfs.EPOLLIN
			}
			// eventfd is always writable
			if e.Events&vfs.EPOLLOUT != 0 {
				events |= vfs.EPOLLOUT
			}
			if events != 0 {
				if c.GetArch() == arch.ArchAMD64 {
					var evBuf [12]byte
					binary.LittleEndian.PutUint32(evBuf[0:], events)
					binary.LittleEndian.PutUint64(evBuf[4:], e.Data)
					h.Mem.WriteBytes(eventsPtr+nReady*12, evBuf[:])
				} else {
					var evBuf [16]byte
					binary.LittleEndian.PutUint32(evBuf[0:], events)
					binary.LittleEndian.PutUint64(evBuf[8:], e.Data)
					h.Mem.WriteBytes(eventsPtr+nReady*16, evBuf[:])
				}
				nReady++
			}
		}
	}
	if nReady > 0 {
		c.SetSyscallReturn(nReady)
		return
	}

	// Build poll set from monitored entries that have host FDs
	type pollEntry struct {
		entry  *vfs.EpollEntry
		hostFD int
	}
	var polls []pollEntry
	var pollFDs []unix.PollFd
	for _, e := range entries {
		hfd := h.FS.GetHostFDNum(e.GuestFD)
		if hfd >= 0 {
			var pEvents int16
			if e.Events&vfs.EPOLLIN != 0 {
				pEvents |= unix.POLLIN
			}
			if e.Events&vfs.EPOLLOUT != 0 {
				pEvents |= unix.POLLOUT
			}
			if e.Events&vfs.EPOLLRDHUP != 0 {
				pEvents |= unix.POLLRDHUP
			}
			pollFDs = append(pollFDs, unix.PollFd{
				Fd:     int32(hfd),
				Events: pEvents,
			})
			polls = append(polls, pollEntry{entry: e, hostFD: hfd})
		}
	}

	if len(pollFDs) == 0 {
		if timeout > 0 && timeout != ^uint64(0) {
			time.Sleep(time.Duration(timeout) * time.Millisecond)
		}
		c.SetSyscallReturn(0)
		return
	}

	// Call host poll
	timeoutMs := int(timeout)
	if timeout == ^uint64(0) {
		timeoutMs = -1
	}
	_, _ = unix.Poll(pollFDs, timeoutMs)

	// Translate results back into guest epoll_event structs
	for i, pfd := range pollFDs {
		if pfd.Revents == 0 || nReady >= maxevents {
			continue
		}
		var events uint32
		if pfd.Revents&unix.POLLIN != 0 {
			events |= vfs.EPOLLIN
		}
		if pfd.Revents&unix.POLLOUT != 0 {
			events |= vfs.EPOLLOUT
		}
		if pfd.Revents&unix.POLLERR != 0 {
			events |= vfs.EPOLLERR
		}
		if pfd.Revents&unix.POLLHUP != 0 {
			events |= vfs.EPOLLHUP
		}
		if pfd.Revents&unix.POLLRDHUP != 0 {
			events |= vfs.EPOLLRDHUP
		}

		// struct epoll_event layout is arch-dependent:
		//   x86-64: packed { uint32 events; uint64 data } = 12 bytes, no padding
		//   others: { uint32 events; pad[4]; uint64 data } = 16 bytes
		if c.GetArch() == arch.ArchAMD64 {
			var evBuf [12]byte
			binary.LittleEndian.PutUint32(evBuf[0:], events)
			binary.LittleEndian.PutUint64(evBuf[4:], polls[i].entry.Data)
			h.Mem.WriteBytes(eventsPtr+nReady*12, evBuf[:])
		} else {
			var evBuf [16]byte
			binary.LittleEndian.PutUint32(evBuf[0:], events)
			binary.LittleEndian.PutUint64(evBuf[8:], polls[i].entry.Data)
			h.Mem.WriteBytes(eventsPtr+nReady*16, evBuf[:])
		}
		nReady++
	}

	c.SetSyscallReturn(nReady)
}

// ===================================================================
// eventfd2
// ===================================================================

func (h *Handler) sysEventfd2(c arch.CPU, initval, flags uint64) {
	hostFD, err := unix.Eventfd(uint(initval), int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	f := os.NewFile(uintptr(hostFD), "eventfd")
	gfd := h.FS.AllocHostFile(f)
	c.SetSyscallReturn(uint64(gfd))
}

// ===================================================================
// timerfd
// ===================================================================

func (h *Handler) sysTimerfdCreate(c arch.CPU, clockid, flags uint64) {
	hostFD, err := unix.TimerfdCreate(int(clockid), int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	f := os.NewFile(uintptr(hostFD), "timerfd")
	gfd := h.FS.AllocHostFile(f)
	c.SetSyscallReturn(uint64(gfd))
}

func (h *Handler) sysTimerfdSettime(c arch.CPU, fdNum, flags, newValue, oldValue uint64) {
	hostFD := h.FS.GetHostFDNum(int(fdNum))
	if hostFD < 0 {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	// Read itimerspec from guest (two timespec = 32 bytes)
	buf := h.readBytes(newValue, 32)
	if len(buf) < 32 {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	var newSpec unix.ItimerSpec
	newSpec.Interval.Sec = int64(binary.LittleEndian.Uint64(buf[0:]))
	newSpec.Interval.Nsec = int64(binary.LittleEndian.Uint64(buf[8:]))
	newSpec.Value.Sec = int64(binary.LittleEndian.Uint64(buf[16:]))
	newSpec.Value.Nsec = int64(binary.LittleEndian.Uint64(buf[24:]))

	var oldSpec unix.ItimerSpec
	err := unix.TimerfdSettime(hostFD, int(flags), &newSpec, &oldSpec)
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	if oldValue != 0 {
		var out [32]byte
		binary.LittleEndian.PutUint64(out[0:], uint64(oldSpec.Interval.Sec))
		binary.LittleEndian.PutUint64(out[8:], uint64(oldSpec.Interval.Nsec))
		binary.LittleEndian.PutUint64(out[16:], uint64(oldSpec.Value.Sec))
		binary.LittleEndian.PutUint64(out[24:], uint64(oldSpec.Value.Nsec))
		h.Mem.WriteBytes(oldValue, out[:])
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysTimerfdGettime(c arch.CPU, fdNum, currValue uint64) {
	hostFD := h.FS.GetHostFDNum(int(fdNum))
	if hostFD < 0 {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	var spec unix.ItimerSpec
	err := unix.TimerfdGettime(hostFD, &spec)
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:], uint64(spec.Interval.Sec))
	binary.LittleEndian.PutUint64(out[8:], uint64(spec.Interval.Nsec))
	binary.LittleEndian.PutUint64(out[16:], uint64(spec.Value.Sec))
	binary.LittleEndian.PutUint64(out[24:], uint64(spec.Value.Nsec))
	h.Mem.WriteBytes(currValue, out[:])
	c.SetSyscallReturn(0)
}

// ===================================================================
// memfd_create + fd-backed mmap
// ===================================================================

func (h *Handler) sysMemfdCreate(c arch.CPU, namePtr, flags uint64) {
	name, err := h.readGuestString(namePtr)
	if err != nil {
		c.SetSyscallReturn(negErrno(EFAULT))
		return
	}
	if name == "" {
		name = "memfd"
	}

	hostFD, err := unix.MemfdCreate(name, int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOMEM))
		return
	}

	f := os.NewFile(uintptr(hostFD), name)
	gfd := h.FS.AllocHostFile(f)
	c.SetSyscallReturn(uint64(gfd))
}

// Ensure unused imports are silenced
var _ = unsafe.Sizeof(0)

// sysMmap handles mmap with support for fd-backed mappings.
func (h *Handler) sysMmap(c arch.CPU) {
	args := c.SyscallArgs()
	addr := args[0]
	length := args[1]
	prot := args[2]
	flags := args[3]
	fd := args[4]
	offset := args[5]

	if length == 0 {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}

	// Reject unreasonably large mappings that would cause integer overflow.
	// Real Linux imposes a per-process memory limit; we conservatively cap at 1TB.
	// The value 0x8000000000001000 is a known bad size from ld.so reservation arithmetic.
	if length > 0x10000000000 { // > 1TB
		c.SetSyscallReturn(negErrno(ENOMEM))
		return
	}

	origAddr := addr
	logMmap := func(result uint64) {
		if h.Trace {
			fmt.Fprintf(os.Stderr, "[mmap] req=0x%x len=0x%x prot=%d flags=0x%x fd=%d off=0x%x → 0x%x\n",
				origAddr, length, prot, flags, int64(fd), offset, result)
		}
	}

	var perms uint8
	if prot&0x1 != 0 {
		perms |= mmu.PermRead
	}
	if prot&0x2 != 0 {
		perms |= mmu.PermWrite
	}
	if prot&0x4 != 0 {
		perms |= mmu.PermExecute
	}

	mapShared := flags&0x01 != 0 // MAP_SHARED
	mapAnon := flags&0x20 != 0   // MAP_ANONYMOUS
	mapFixed := flags&0x10 != 0   // MAP_FIXED

	if mapFixed && addr&mmu.PageMask != addr {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}

	// If MAP_ANONYMOUS or fd == -1, use normal anonymous mmap
	if mapAnon || fd == ^uint64(0) || int64(fd) == -1 {
		if mapFixed && addr != 0 {
			h.Mem.MapRangeZero(addr, length, perms)
			logMmap(addr)
			c.SetSyscallReturn(addr)
		} else {
			result := h.Mem.Mmap(addr, length, perms)
			logMmap(result)
			c.SetSyscallReturn(result)
		}
		return
	}

	// fd-backed mmap: check if the FD has a real host file
	hostFile := h.FS.GetHostFile(int(fd))
	if hostFile == nil {
		// VFS-only file - allocate anonymous pages and copy data
		if mapFixed && addr != 0 {
			h.Mem.MapRangeZero(addr, length, perms)
		} else {
			addr = h.Mem.Mmap(addr, length, perms)
		}
		// Read file data into the mapped region without advancing offset
		buf := make([]byte, length)
		n, _ := h.FS.Pread(int(fd), buf, int64(offset))
		if n > 0 {
			h.Mem.WriteBytesRaw(addr, buf[:n])
		}
		logMmap(addr)
		c.SetSyscallReturn(addr)
		return
	}

	// Real host file (memfd or host passthrough)
	_ = offset
	if !mapShared {
		// MAP_PRIVATE: just allocate memory and read the file. This avoids SIGBUS
		// if the requested length exceeds the file size (common in ELF loaders).
		if mapFixed && addr != 0 {
			h.Mem.MapRangeZero(addr, length, perms)
		} else {
			addr = h.Mem.Mmap(addr, length, perms)
			// Mmap for anonymous already creates fresh (zeroed) pages if they are new,
			// but just to be absolutely sure for file-backed we could zero it.
			// Actually, Mmap on an unmapped region creates zeroed pages, so it's fine.
		}
		// Read data at offset
		buf := make([]byte, length)
		n, _ := hostFile.ReadAt(buf, int64(offset))
		if n > 0 {
			// Bypass permission checks because the requested perms might be PROT_READ
			h.Mem.WriteBytesRaw(addr, buf[:n])
		}
		logMmap(addr)
		c.SetSyscallReturn(addr)
		return
	}

	// MAP_SHARED (like Wayland shm or memfd): mmap for zero-copy
	hostFDnum := int(hostFile.Fd())
	mmapProt := 0
	if prot&0x1 != 0 {
		mmapProt |= syscall.PROT_READ
	}
	if prot&0x2 != 0 {
		mmapProt |= syscall.PROT_WRITE
	}

	mmapFlags := syscall.MAP_SHARED

	if addr != 0 && !mapFixed {
		// Check if hint address is available
		conflict := false
		for pg := addr & mmu.PageMask; pg < addr+length; pg += mmu.PageSize {
			if h.Mem.IsMapped(pg) {
				conflict = true
				break
			}
		}
		if conflict {
			addr = 0
		}
	}

	hostSlice, err := syscall.Mmap(hostFDnum, int64(offset), int(length), mmapProt, mmapFlags)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOMEM))
		return
	}

	// Alias the host mmap'd region into the guest MMU
	guestAddr := h.Mem.MapHostSlice(addr, hostSlice, perms)
	logMmap(guestAddr)
	c.SetSyscallReturn(guestAddr)
}

func (h *Handler) sysMadvise(c arch.CPU, addr, length, advice uint64) {
	// MADV_DONTNEED = 4
	if advice == 4 {
		h.Mem.MapRangeZero(addr, length, mmu.PermRead|mmu.PermWrite) // should keep current perms, but this is a stub
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysMremap(c arch.CPU, oldAddr, oldLen, newLen, flags, newAddr uint64) {
	// flags: 1 = MREMAP_MAYMOVE, 2 = MREMAP_FIXED, 3 = both
	mayMove := flags&1 != 0
	isFixed := flags&2 != 0

	oldLen = (oldLen + mmu.PageSize - 1) & mmu.PageMask
	newLen = (newLen + mmu.PageSize - 1) & mmu.PageMask

	if newLen <= oldLen {
		if oldLen > newLen {
			h.Mem.Munmap(oldAddr+newLen, oldLen-newLen)
		}
		if isFixed {
			// Move to newAddr
			data, _ := h.Mem.ReadBytesRaw(oldAddr, int(newLen))
			h.Mem.MapRangeZero(newAddr, newLen, mmu.PermRead|mmu.PermWrite|mmu.PermExecute) // simplified perms
			h.Mem.WriteBytesRaw(newAddr, data)
			if oldAddr != newAddr {
				h.Mem.Munmap(oldAddr, oldLen)
			}
			c.SetSyscallReturn(newAddr)
			return
		}
		c.SetSyscallReturn(oldAddr)
		return
	}

	if isFixed {
		// MREMAP_FIXED requires MREMAP_MAYMOVE
		if !mayMove {
			c.SetSyscallReturn(negErrno(EINVAL))
			return
		}
		data, _ := h.Mem.ReadBytesRaw(oldAddr, int(oldLen))
		h.Mem.MapRangeZero(newAddr, newLen, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		h.Mem.WriteBytesRaw(newAddr, data)
		if oldAddr != newAddr {
			h.Mem.Munmap(oldAddr, oldLen)
		}
		c.SetSyscallReturn(newAddr)
		return
	}

	// Try expanding in place if the following pages are unmapped
	canExpand := true
	for pg := oldAddr + oldLen; pg < oldAddr+newLen; pg += mmu.PageSize {
		if h.Mem.IsMapped(pg) {
			canExpand = false
			break
		}
	}

	if canExpand {
		h.Mem.MapRangeZero(oldAddr+oldLen, newLen-oldLen, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
		c.SetSyscallReturn(oldAddr)
		return
	}

	if !mayMove {
		c.SetSyscallReturn(negErrno(ENOMEM))
		return
	}

	// Move the allocation
	targetAddr := h.Mem.Mmap(0, newLen, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	data, _ := h.Mem.ReadBytesRaw(oldAddr, int(oldLen))
	h.Mem.WriteBytesRaw(targetAddr, data)
	h.Mem.Munmap(oldAddr, oldLen)
	c.SetSyscallReturn(targetAddr)
}

// x64SyscallToRV translates an x86_64 Linux syscall number to the RISC-V
// (asm-generic) number used by the handler's switch statement.
func x64SyscallToRV(num uint64) uint64 {
	if n, ok := x64Map[num]; ok {
		return n
	}
	return num | 0x80000000 // will hit default/ENOSYS
}

var x64Map = map[uint64]uint64{
	0:   SysRead,
	1:   SysWrite,
	2:   sysX64Open,     // open → openat (needs AT_FDCWD)
	3:   SysClose,
	4:   sysX64Stat,    // stat → fstatat (needs AT_FDCWD)
	5:   SysFstat,
	6:   sysX64Lstat,   // lstat → fstatat (needs AT_FDCWD)
	7:   sysPoll,        // poll(fds, nfds, timeout_ms) - timeout is int, not *timespec
	8:   SysLseek,
	9:   SysMmap,
	10:  SysMprotect,
	11:  SysMunmap,
	12:  SysBrk,
	13:  SysRtSigaction,
	14:  SysRtSigprocmask,
	15:  SysRtSigreturn,
	16:  SysIoctl,
	17:  SysPread64,     // pread64
	18:  SysPwrite64,    // pwrite64
	19:  SysReadv,
	20:  SysWritev,
	21:  sysX64Access,  // access → faccessat (needs AT_FDCWD)
	22:  SysPipe2,      // pipe → pipe2
	23:  SysPselect6,   // select → pselect6
	24:  SysSchedYield,
	25:  SysMremap,
	26:  SysMsync,
	27:  SysMincore,
	28:  SysMadvise,
	32:  SysDup,
	33:  SysDup3,       // dup2 → dup3
	35:  SysNanosleep,
	36:  SysGetitimer,
	38:  SysSetitimer,
	39:  SysGetpid,
	40:  SysSendfile,
	41:  SysSocket,
	42:  SysConnect,
	43:  SysAccept,
	44:  SysSendto,
	45:  SysRecvfrom,
	46:  SysSendmsg,
	47:  SysRecvmsg,
	48:  SysShutdown,
	49:  SysBind,
	50:  SysListen,
	51:  SysGetsockname,
	52:  SysGetpeername,
	53:  SysSocketpair,
	54:  SysSetsockopt,
	55:  SysGetsockopt,
	56:  SysClone,
	59:  SysExecve,
	60:  SysExit,
	61:  SysWait4,
	62:  SysKill,
	63:  SysUname,
	72:  SysFcntl,
	73:  SysFlock,      // flock → stub
	74:  SysFsync,
	75:  SysFdatasync,
	76:  SysFtruncate,  // truncate → stub
	77:  SysFtruncate,
	78:  SysGetdents64,
	79:  SysGetcwd,
	80:  SysChdir,
	82:  sysX64Rename,  // rename → renameat2 (needs 2x AT_FDCWD)
	83:  sysX64Mkdir,   // mkdir → mkdirat (needs AT_FDCWD)
	87:  sysX64Unlink,  // unlink → unlinkat (needs AT_FDCWD)
	88:  sysX64Symlink, // symlink → symlinkat (needs AT_FDCWD)
	89:  sysX64Readlink, // readlink → readlinkat (needs AT_FDCWD)
	90:  SysFchmod,     // chmod → fchmod
	91:  SysFchown,     // fchown
	95:  SysUmask,
	96:  SysTimes,
	97:  SysGetrusage,  // getrlimit → stub
	98:  SysGetrusage,
	99:  SysSysinfo,
	100: SysTimes,
	102: SysGetuid,
	103: SysSyslog,
	104: SysGetgid,
	105: SysSetTidAddress, // setuid → stub
	106: sysX64Stat,       // stat → fstatat (needs AT_FDCWD)
	107: SysGeteuid,
	108: SysGetegid,
	118: SysGetresuid,
	120: SysGetresgid,
	110: SysGetppid,
	131: SysSigaltstack,
	137: SysStatx,      // statfs → stub
	155: SysPrctl,      // pivot_root → stub
	157: SysPrctl,
	158: SysArchPrctl,
	160: SysSchedSetaffinity,  // setrlimit → stub
	186: SysGettid,
	201: SysClockGettime, // time → clock_gettime stub
	202: SysFutex,
	203: SysSchedSetaffinity,
	204: SysSchedGetaffinity,
	206: SysStatx,      // io_setup → stub
	217: SysGetdents64,
	218: SysSetTidAddress,
	228: SysClockGettime,
	229: SysClockGetres,
	230: SysClockNanosleep,
	231: SysExitGroup,
	232: SysEpollPwait,
	233: SysEpollCtl,
	234: SysTgkill,
	257: SysOpenat,
	258: SysMkdirat,    // mkdirat
	260: SysFchownat,
	262: SysFstatat,    // newfstatat
	263: SysUnlinkat,
	264: SysRenameat2,
	265: SysLinkat,
	266: SysSymlinkat,
	267: SysReadlinkat,
	268: SysFchmodat,
	269: SysFaccessat,
	270: SysPselect6,
	271: SysPpoll,
	276: SysSplice,     // splice → will hit default
	279: SysStatx,      // move_pages → stub
	281: SysEpollPwait, // epoll_pwait
	282: SysEpollCreate1, // via 291
	283: SysTimerfdCreate,  // timerfd_create (obsolete, see 322)
	284: SysEventfd2,      // eventfd (old), treat as eventfd2
	285: SysFallocate,
	286: SysTimerfdSettime,
	287: SysTimerfdGettime,
	288: SysAccept4,
	289: SysPipe2,         // signalfd4 → pipe2 stub
	290: SysEventfd2,
	291: SysEpollCreate1,
	273: SysSetRobustList,
	292: SysDup3,
	293: SysPipe2,         // pipe2
	302: SysPrlimit64,
	303: SysMemfdCreate,
	310: SysSetRobustList, // process_vm_readv → stub
	318: SysGetrandom,
	316: SysRenameat2,
	253: SysKcmp,          // kcmp - compare kernel resources of two processes
	319: SysMemfdCreate,
	320: SysMembarrier,   // kexec_file_load → stub
	334: SysRseq,
	322: SysTimerfdCreate, // timerfd_create (new number)
	332: SysStatx,         // statx
	435: SysClone3,      // clone3
}

// SysFlock/SysSplice: handled as unknown → ENOSYS
const SysFlock = 0xDEAD0001
const SysSplice = 0xDEAD0002
