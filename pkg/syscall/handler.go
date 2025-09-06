package syscall

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
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
	SysRiscvHwprobe   = 258
	SysArchPrctl      = 259 // internal, mapped from x86-64 arch_prctl
	SysSendfile       = 262 // internal, mapped from x86-64 sendfile
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

	clearChildTidMu sync.Mutex
	clearChildTid   map[int]uint64 // TID → clear_child_tid address
}

// NewHandler creates a syscall handler wired to the given MMU and VFS.
func NewHandler(mem *mmu.MMU, fs *vfs.VFS) *Handler {
	return &Handler{Mem: mem, FS: fs, Signals: signal.New(), Umask: 0022}
}

// Handle is the SyscallHandler callback for the CPU.
func (h *Handler) Handle(c arch.CPU) {
	num := c.SyscallNum()
	if c.GetArch() == arch.ArchAMD64 {
		num = x64SyscallToRV(num)
	}
	args := c.SyscallArgs()
	a0, a1, a2, a3, a4, a5 := args[0], args[1], args[2], args[3], args[4], args[5]

	if h.Trace {
		fmt.Fprintf(os.Stderr, "[trace] syscall %d (a0=0x%x a1=0x%x a2=0x%x a3=0x%x)\n", num, a0, a1, a2, a3)
	}

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
		c.SetSyscallReturn(result)
	case SysMmap:
		h.sysMmap(c)
	case SysMunmap:
		h.Mem.Munmap(a0, a1)
		c.SetSyscallReturn(0)
	case SysMprotect:
		h.sysMprotect(c, a0, a1, a2)
	case SysMremap:
		c.SetSyscallReturn(negErrno(ENOMEM))
	case SysMadvise:
		c.SetSyscallReturn(0)
	case SysMsync, SysMlock, SysMunlock:
		c.SetSyscallReturn(0)

	// --- Filesystem ---
	case SysOpenat:
		h.sysOpenat(c, a0, a1, a2, a3)
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
	case SysFaccessat:
		h.sysFaccessat(c, a0, a1)
	case SysGetcwd:
		h.sysGetcwd(c, a0, a1)
	case SysMkdirat:
		h.sysMkdirat(c, a0, a1, a2)
	case SysUnlinkat:
		h.sysUnlinkat(c, a0, a1, a2)
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
	case SysLinkat:
		c.SetSyscallReturn(negErrno(ENOSYS))
	case SysRenameat2:
		h.sysRenameat(c, a0, a1, a2, a3)

	// --- Process/Thread info ---
	case SysGetuid, SysGeteuid, SysGetgid, SysGetegid:
		c.SetSyscallReturn(1000)
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
	case SysKill, SysTkill, SysTgkill:
		// For self-signals, just record as pending
		h.Signals.Raise(int(a1))
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
	case SysRseq:
		c.SetSyscallReturn(negErrno(ENOSYS))
	case SysPpoll:
		h.sysPpoll(c, a0, a1, a2, a3)
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
		c.SetSyscallReturn(negErrno(ECHILD))

	// --- Exec ---
	case SysExecve:
		c.SetSyscallReturn(negErrno(ENOSYS))

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

func (h *Handler) readGuestString(addr uint64) string {
	var buf []byte
	for {
		b, err := h.Mem.Read8(addr)
		if err != nil || b == 0 {
			break
		}
		buf = append(buf, b)
		addr++
	}
	return string(buf)
}

// --- Syscall implementations ---

func (h *Handler) sysOpenat(c arch.CPU, dirfd, pathAddr, flags, mode uint64) {
	path := h.readGuestString(pathAddr)
	fd, err := h.FS.OpenAt(int(int32(dirfd)), path, int(flags), uint32(mode))
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
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
	h.Mem.Mprotect(addr, length, perms)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysIoctl(c arch.CPU, fd, cmd uint64) {
	if fd <= 2 {
		switch cmd {
		case 0x5401: // TCGETS
			c.SetSyscallReturn(negErrno(ENOTTY))
		case 0x5413: // TIOCGWINSZ
			c.SetSyscallReturn(negErrno(ENOTTY))
		default:
			c.SetSyscallReturn(negErrno(ENOTTY))
		}
	} else {
		c.SetSyscallReturn(negErrno(ENOTTY))
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
	path := h.readGuestString(pathAddr)
	node, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	h.writeStatBuf(statAddr, node)
	c.SetSyscallReturn(0)
}

func (h *Handler) sysStatx(c arch.CPU, dirfd, pathAddr, flags, mask, statxAddr uint64) {
	path := h.readGuestString(pathAddr)
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
	rfd, wfd, err := h.FS.Pipe2(int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(ENFILE))
		return
	}
	h.Mem.Write32(pipefdAddr, uint32(rfd))
	h.Mem.Write32(pipefdAddr+4, uint32(wfd))
	c.SetSyscallReturn(0)
}

func (h *Handler) sysGetdents64(c arch.CPU, fd, buf, count uint64) {
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
	path := h.readGuestString(pathAddr)
	target, err := h.FS.Readlinkat(int(int32(dirfd)), path)
	if err != nil {
		c.SetSyscallReturn(negErrno(EINVAL))
		return
	}
	data := []byte(target)
	if uint64(len(data)) > bufsiz {
		data = data[:bufsiz]
	}
	h.Mem.WriteBytes(buf, data)
	c.SetSyscallReturn(uint64(len(data)))
}

func (h *Handler) sysFaccessat(c arch.CPU, dirfd, pathAddr uint64) {
	path := h.readGuestString(pathAddr)
	_, err := h.FS.StatPath(int(int32(dirfd)), path)
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
	c.SetSyscallReturn(buf)
}

func (h *Handler) sysMkdirat(c arch.CPU, dirfd, pathAddr, mode uint64) {
	path := h.readGuestString(pathAddr)
	if path == "" {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	// Simple: resolve and create
	if path[0] != '/' {
		path = h.FS.Getcwd() + "/" + path
	}
	h.FS.MkdirAll(path)
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
		f := h.FS.GetFD(int(fd))
		if f == nil {
			c.SetSyscallReturn(negErrno(EBADF))
		} else {
			c.SetSyscallReturn(uint64(f.Flags))
		}
	case 4: // F_SETFL
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
	binary.LittleEndian.PutUint32(data[108:], 1)                       // mem_unit
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
	path := h.readGuestString(pathAddr)
	err := h.FS.Unlinkat(int(int32(dirfd)), path, int(flags))
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysChdir(c arch.CPU, pathAddr uint64) {
	path := h.readGuestString(pathAddr)
	err := h.FS.Chdir(path)
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
	target := h.readGuestString(targetAddr)
	linkpath := h.readGuestString(linkpathAddr)
	err := h.FS.Symlinkat(target, int(int32(dirfd)), linkpath)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOENT))
		return
	}
	c.SetSyscallReturn(0)
}

func (h *Handler) sysRenameat(c arch.CPU, olddirfd, oldpathAddr, newdirfd, newpathAddr uint64) {
	oldpath := h.readGuestString(oldpathAddr)
	newpath := h.readGuestString(newpathAddr)
	err := h.FS.Renameat(int(int32(olddirfd)), oldpath, int(int32(newdirfd)), newpath)
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
	// Simplified ppoll: if timeout is provided, sleep; otherwise return immediately
	if timeoutAddr != 0 {
		sec, _ := h.Mem.Read64(timeoutAddr)
		nsec, _ := h.Mem.Read64(timeoutAddr + 8)
		d := time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond
		if d > 0 && d < 10*time.Second {
			time.Sleep(d)
		}
	}
	c.SetSyscallReturn(0) // no fds ready
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
	case 0: // FUTEX_WAIT
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

	case 1: // FUTEX_WAKE
		woken := 0
		if h.ThreadM != nil {
			woken = h.ThreadM.FutexWake(uaddr, int(val))
		}
		c.SetSyscallReturn(uint64(woken))

	default:
		c.SetSyscallReturn(0)
	}
}

func (h *Handler) sysClone(c arch.CPU, flags, childStack, parentTid, tls, childTid uint64) {
	// If this is a thread creation (CLONE_VM|CLONE_FS|CLONE_THREAD)
	if h.ThreadM != nil && flags&0x100 != 0 { // CLONE_VM
		childPC := c.SyscallReturnPC()
		if childStack == 0 {
			childStack = c.GetSP()
		}
		tid, err := h.ThreadM.Clone(c, childPC, childStack)
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
		// Set TLS if CLONE_SETTLS (0x00080000)
		if flags&0x00080000 != 0 {
			h.ThreadM.SetChildTLS(tid, tls)
		}
		c.SetSyscallReturn(uint64(tid))
	} else {
		// fork-like: return 0 (pretend we're child)
		c.SetSyscallReturn(0)
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
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysWritev(c arch.CPU, fdNum, iovAddr, iovcnt uint64) {
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
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	if n > 0 {
		h.Mem.WriteBytes(bufAddr, buf[:n])
	}
	c.SetSyscallReturn(uint64(n))
}

func (h *Handler) sysPread64(c arch.CPU, fdNum, bufAddr, count, offset uint64) {
	buf := make([]byte, count)
	n, err := h.FS.Pread(int(fdNum), buf, int64(offset))
	if err != nil {
		c.SetSyscallReturn(negErrno(EBADF))
		return
	}
	if n > 0 {
		h.Mem.WriteBytes(bufAddr, buf[:n])
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
		c.SetSyscallReturn(negErrno(EBADF))
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
		if err != nil {
			c.SetSyscallReturn(negErrno(EBADF))
			return
		}
		if n > 0 {
			h.Mem.WriteBytes(base, buf[:n])
		}
		total += uint64(n)
		if uint64(n) < length {
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

	if domain == vfs.AF_UNIX {
		if stype != vfs.SOCK_STREAM && stype != vfs.SOCK_DGRAM && stype != vfs.SOCK_SEQPACKET {
			c.SetSyscallReturn(negErrno(EPROTONOSUPPORT))
			return
		}
		fd, err := h.FS.AllocSocket(int(domain), stype)
		if err != nil {
			c.SetSyscallReturn(negErrno(ENOMEM))
			return
		}
		c.SetSyscallReturn(uint64(fd))
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
			c.SetSyscallReturn(negErrno(errnoFromErr(err)))
			return
		}
		if n > 0 {
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

// extractUnixPath extracts the null-terminated path from a sockaddr_un buffer.
// Format: family(2 bytes LE) + path (up to 108 bytes, null-terminated)
func extractUnixPath(buf []byte) string {
	if len(buf) <= 2 {
		return ""
	}
	pathBytes := buf[2:]
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
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
	}
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
		c.SetSyscallReturn(negErrno(errnoFromErr(err)))
		return
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
		evBuf := h.readBytes(eventPtr, 12)
		if len(evBuf) >= 12 {
			events = binary.LittleEndian.Uint32(evBuf[0:])
			data = binary.LittleEndian.Uint64(evBuf[4:])
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
				var evBuf [12]byte
				binary.LittleEndian.PutUint32(evBuf[0:], events)
				binary.LittleEndian.PutUint64(evBuf[4:], e.Data)
				h.Mem.WriteBytes(eventsPtr+nReady*12, evBuf[:])
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

		// Write epoll_event: events(4) + data(8) = 12 bytes
		var evBuf [12]byte
		binary.LittleEndian.PutUint32(evBuf[0:], events)
		binary.LittleEndian.PutUint64(evBuf[4:], polls[i].entry.Data)
		h.Mem.WriteBytes(eventsPtr+nReady*12, evBuf[:])
		nReady++
	}
	c.SetSyscallReturn(nReady)
}

// ===================================================================
// eventfd2
// ===================================================================

func (h *Handler) sysEventfd2(c arch.CPU, initval, flags uint64) {
	fd := h.FS.AllocEventFD(initval, int(flags))
	c.SetSyscallReturn(uint64(fd))
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
	name := h.readGuestString(namePtr)
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

	// If MAP_ANONYMOUS or fd == -1, use normal anonymous mmap
	if mapAnon || fd == ^uint64(0) || int64(fd) == -1 {
		if mapFixed && addr != 0 {
			h.Mem.MapRange(addr, length, perms)
			c.SetSyscallReturn(addr)
		} else {
			result := h.Mem.Mmap(addr, length, perms)
			c.SetSyscallReturn(result)
		}
		return
	}

	// fd-backed mmap: check if the FD has a real host file
	hostFile := h.FS.GetHostFile(int(fd))
	if hostFile == nil {
		// VFS-only file - allocate anonymous pages and copy data
		if mapFixed && addr != 0 {
			h.Mem.MapRange(addr, length, perms)
		} else {
			addr = h.Mem.Mmap(addr, length, perms)
		}
		// Read file data into the mapped region
		buf := make([]byte, length)
		n, _ := h.FS.Read(int(fd), buf)
		if n > 0 {
			h.Mem.WriteBytes(addr, buf[:n])
		}
		c.SetSyscallReturn(addr)
		return
	}

	// Real host file (memfd) - mmap for zero-copy
	_ = offset
	hostFDnum := int(hostFile.Fd())
	mmapProt := 0
	if prot&0x1 != 0 {
		mmapProt |= syscall.PROT_READ
	}
	if prot&0x2 != 0 {
		mmapProt |= syscall.PROT_WRITE
	}

	mmapFlags := syscall.MAP_SHARED
	if !mapShared {
		mmapFlags = syscall.MAP_PRIVATE
	}

	hostSlice, err := syscall.Mmap(hostFDnum, int64(offset), int(length), mmapProt, mmapFlags)
	if err != nil {
		c.SetSyscallReturn(negErrno(ENOMEM))
		return
	}

	// Alias the host mmap'd region into the guest MMU
	guestAddr := h.Mem.MapHostSlice(addr, hostSlice, perms)
	c.SetSyscallReturn(guestAddr)
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
	2:   SysOpenat,     // open → openat
	3:   SysClose,
	4:   SysFstatat,    // stat → fstatat
	5:   SysFstat,
	6:   SysFstatat,    // lstat → fstatat
	7:   SysPpoll,      // poll → ppoll
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
	21:  SysFaccessat,  // access → faccessat
	22:  SysPipe2,      // pipe → pipe2
	23:  SysPselect6,   // select → pselect6
	24:  SysSchedYield,
	25:  SysMremap,
	26:  SysMsync,
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
	82:  SysRenameat2,  // rename → renameat2
	83:  SysMkdirat,    // mkdir → mkdirat
	87:  SysUnlinkat,   // unlink → unlinkat
	88:  SysSymlinkat,  // symlink → symlinkat
	89:  SysReadlinkat, // readlink → readlinkat
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
	106: SysFstatat,       // stat → fstatat
	107: SysGeteuid,
	108: SysGetegid,
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
	319: SysMemfdCreate,
	320: SysMembarrier,   // kexec_file_load → stub
	334: SysRseq,
	322: SysTimerfdCreate, // timerfd_create (new number)
	332: SysStatx,         // statx
	435: SysClone,       // clone3
}

// SysFlock/SysSplice: handled as unknown → ENOSYS
const SysFlock = 0xDEAD0001
const SysSplice = 0xDEAD0002
