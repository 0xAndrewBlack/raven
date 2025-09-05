package syscall

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/mirkobrombin/go-vm/pkg/cpu"
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
)

// Handler holds the synthetic kernel state.
type Handler struct {
	Mem     *mmu.MMU
	FS      *vfs.VFS
	ThreadM *thread.Manager
	Signals *signal.SignalState
	Umask   uint32 // current umask
	Trace   bool   // trace syscalls to stderr
}

// NewHandler creates a syscall handler wired to the given MMU and VFS.
func NewHandler(mem *mmu.MMU, fs *vfs.VFS) *Handler {
	return &Handler{Mem: mem, FS: fs, Signals: signal.New(), Umask: 0022}
}

// Handle is the SyscallHandler callback for the CPU.
func (h *Handler) Handle(c *cpu.CPU) {
	num := c.X[17] // a7
	a0 := c.X[10]
	a1 := c.X[11]
	a2 := c.X[12]
	a3 := c.X[13]
	a4 := c.X[14]
	a5 := c.X[15]

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

	// --- Process lifecycle ---
	case SysExit, SysExitGroup:
		c.Stop()
		c.X[10] = a0

	// --- Memory management ---
	case SysBrk:
		result := h.Mem.Brk(a0)
		c.X[10] = result
	case SysMmap:
		h.sysMmap(c)
	case SysMunmap:
		h.Mem.Munmap(a0, a1)
		c.X[10] = 0
	case SysMprotect:
		h.sysMprotect(c, a0, a1, a2)
	case SysMremap:
		c.X[10] = negErrno(ENOMEM)
	case SysMadvise:
		c.X[10] = 0
	case SysMsync, SysMlock, SysMunlock:
		c.X[10] = 0

	// --- Filesystem ---
	case SysOpenat:
		h.sysOpenat(c, a0, a1, a2, a3)
	case SysClose:
		if err := h.FS.Close(int(a0)); err != nil {
			c.X[10] = negErrno(EBADF)
		} else {
			c.X[10] = 0
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
		c.X[10] = 0
	case SysFsync, SysFdatasync, SysFadvise64:
		c.X[10] = 0
	case SysSync:
		c.X[10] = 0
	case SysFtruncate:
		h.sysFtruncate(c, a0, a1)
	case SysFallocate:
		h.sysFallocate(c, a0, a1, a2, a3)
	case SysUtimensat:
		c.X[10] = 0
	case SysSymlinkat:
		h.sysSymlinkat(c, a0, a1, a2)
	case SysLinkat:
		c.X[10] = negErrno(ENOSYS)
	case SysRenameat2:
		h.sysRenameat(c, a0, a1, a2, a3)

	// --- Process/Thread info ---
	case SysGetuid, SysGeteuid, SysGetgid, SysGetegid:
		c.X[10] = 1000
	case SysGetpid, SysGetppid:
		c.X[10] = 1
	case SysGettid:
		c.X[10] = 1
	case SysSetTidAddress:
		c.X[10] = 1
	case SysUmask:
		old := h.Umask
		h.Umask = uint32(a0) & 0777
		c.X[10] = uint64(old)

	// --- Signals ---
	case SysRtSigaction:
		h.sysRtSigaction(c, a0, a1, a2, a3)
	case SysRtSigprocmask:
		h.sysRtSigprocmask(c, a0, a1, a2)
	case SysSigaltstack:
		h.sysSigaltstack(c, a0, a1)
	case SysRtSigreturn:
		c.X[10] = 0 // TODO: restore saved signal frame
	case SysKill, SysTkill, SysTgkill:
		// For self-signals, just record as pending
		h.Signals.Raise(int(a1))
		c.X[10] = 0

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
		c.X[10] = 0
	case SysClone:
		h.sysClone(c, a0, a1, a2, a3, a4)

	// --- Scheduling ---
	case SysSchedYield:
		c.X[10] = 0
	case SysSchedGetaffinity:
		if a2 >= 8 {
			h.Mem.Write64(a1, 1)
			c.X[10] = 0
		} else {
			c.X[10] = negErrno(EINVAL)
		}
	case SysSchedSetaffinity:
		c.X[10] = 0

	// --- Misc ---
	case SysPrctl:
		h.sysPrctl(c, a0, a1)
	case SysSyslog:
		c.X[10] = negErrno(EPERM)
	case SysMembarrier:
		c.X[10] = 0
	case SysRseq:
		c.X[10] = negErrno(ENOSYS)
	case SysPpoll:
		h.sysPpoll(c, a0, a1, a2, a3)
	case SysPselect6:
		c.X[10] = 0
	case SysTimes:
		c.X[10] = 0

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
		c.X[10] = 0 // stub OK for most opts
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
		c.X[10] = negErrno(ENOSYS)
	case SysTimerfdCreate, SysTimerfdSettime, SysTimerfdGettime:
		c.X[10] = negErrno(ENOSYS)

	// --- memfd ---
	case SysMemfdCreate:
		h.sysMemfdCreate(c, a0, a1)

	// --- Wait ---
	case SysWait4:
		c.X[10] = negErrno(ECHILD)

	// --- Exec ---
	case SysExecve:
		c.X[10] = negErrno(ENOSYS)

	// --- Timers ---
	case SysGetitimer:
		h.sysGetitimer(c, a0, a1)
	case SysSetitimer:
		h.sysSetitimer(c, a0, a1, a2)

	default:
		fmt.Fprintf(os.Stderr, "[techvm] unhandled syscall %d (a0=0x%x a1=0x%x a2=0x%x)\n", num, a0, a1, a2)
		c.X[10] = negErrno(ENOSYS)
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

func (h *Handler) sysOpenat(c *cpu.CPU, dirfd, pathAddr, flags, mode uint64) {
	path := h.readGuestString(pathAddr)
	fd, err := h.FS.OpenAt(int(int32(dirfd)), path, int(flags), uint32(mode))
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = uint64(fd)
}

func (h *Handler) sysMprotect(c *cpu.CPU, addr, length, prot uint64) {
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
	c.X[10] = 0
}

func (h *Handler) sysIoctl(c *cpu.CPU, fd, cmd uint64) {
	if fd <= 2 {
		switch cmd {
		case 0x5401: // TCGETS
			c.X[10] = negErrno(ENOTTY)
		case 0x5413: // TIOCGWINSZ
			c.X[10] = negErrno(ENOTTY)
		default:
			c.X[10] = negErrno(ENOTTY)
		}
	} else {
		c.X[10] = negErrno(ENOTTY)
	}
}

func (h *Handler) sysFstat(c *cpu.CPU, fd, statAddr uint64) {
	node := h.FS.Stat(int(fd))
	if node == nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	h.writeStatBuf(statAddr, node)
	c.X[10] = 0
}

func (h *Handler) sysFstatat(c *cpu.CPU, dirfd, pathAddr, statAddr uint64) {
	path := h.readGuestString(pathAddr)
	node, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	h.writeStatBuf(statAddr, node)
	c.X[10] = 0
}

func (h *Handler) sysStatx(c *cpu.CPU, dirfd, pathAddr, flags, mask, statxAddr uint64) {
	path := h.readGuestString(pathAddr)
	node, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
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
	c.X[10] = 0
}

// writeStatBuf writes a struct stat (128 bytes) for RISC-V Linux.
func (h *Handler) writeStatBuf(addr uint64, node *vfs.VNode) {
	buf := make([]byte, 128)
	// st_dev[0:8], st_ino[8:16], st_mode[16:20], st_nlink[20:24]
	// st_uid[24:28], st_gid[28:32], st_rdev[32:40], __pad1[40:48]
	// st_size[48:56], st_blksize[56:60], __pad2[60:64]
	// st_blocks[64:72], st_atime[72:80], st_atime_nsec[80:88]
	// st_mtime[88:96], st_mtime_nsec[96:104]
	// st_ctime[104:112], st_ctime_nsec[112:120]
	binary.LittleEndian.PutUint64(buf[0:], 1)                  // st_dev
	binary.LittleEndian.PutUint64(buf[8:], node.Ino)            // st_ino
	binary.LittleEndian.PutUint32(buf[16:], node.FileMode)      // st_mode
	binary.LittleEndian.PutUint32(buf[20:], node.Nlink)         // st_nlink
	binary.LittleEndian.PutUint32(buf[24:], node.Uid)           // st_uid
	binary.LittleEndian.PutUint32(buf[28:], node.Gid)           // st_gid
	binary.LittleEndian.PutUint64(buf[48:], uint64(node.Size))  // st_size
	binary.LittleEndian.PutUint32(buf[56:], 4096)               // st_blksize
	binary.LittleEndian.PutUint64(buf[72:], uint64(node.Atime.Unix())) // st_atime
	binary.LittleEndian.PutUint64(buf[88:], uint64(node.Mtime.Unix())) // st_mtime
	binary.LittleEndian.PutUint64(buf[104:], uint64(node.Ctime.Unix())) // st_ctime
	h.Mem.WriteBytes(addr, buf)
}

func (h *Handler) sysLseek(c *cpu.CPU, fd uint64, offset uint64, whence uint64) {
	pos, err := h.FS.Lseek(int(fd), int64(offset), int(whence))
	if err != nil {
		c.X[10] = negErrno(ESPIPE)
		return
	}
	c.X[10] = uint64(pos)
}

func (h *Handler) sysDup(c *cpu.CPU, oldfd uint64) {
	newfd, err := h.FS.Dup(int(oldfd))
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	c.X[10] = uint64(newfd)
}

func (h *Handler) sysDup3(c *cpu.CPU, oldfd, newfd uint64) {
	err := h.FS.Dup3(int(oldfd), int(newfd))
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	c.X[10] = newfd
}

func (h *Handler) sysPipe2(c *cpu.CPU, pipefdAddr, flags uint64) {
	rfd, wfd, err := h.FS.Pipe2(int(flags))
	if err != nil {
		c.X[10] = negErrno(ENFILE)
		return
	}
	h.Mem.Write32(pipefdAddr, uint32(rfd))
	h.Mem.Write32(pipefdAddr+4, uint32(wfd))
	c.X[10] = 0
}

func (h *Handler) sysGetdents64(c *cpu.CPU, fd, buf, count uint64) {
	entries := h.FS.Getdents64(int(fd))
	if entries == nil {
		c.X[10] = 0 // EOF
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
	c.X[10] = offset
}

func (h *Handler) sysReadlinkat(c *cpu.CPU, dirfd, pathAddr, buf, bufsiz uint64) {
	path := h.readGuestString(pathAddr)
	target, err := h.FS.Readlinkat(int(int32(dirfd)), path)
	if err != nil {
		c.X[10] = negErrno(EINVAL)
		return
	}
	data := []byte(target)
	if uint64(len(data)) > bufsiz {
		data = data[:bufsiz]
	}
	h.Mem.WriteBytes(buf, data)
	c.X[10] = uint64(len(data))
}

func (h *Handler) sysFaccessat(c *cpu.CPU, dirfd, pathAddr uint64) {
	path := h.readGuestString(pathAddr)
	_, err := h.FS.StatPath(int(int32(dirfd)), path)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysGetcwd(c *cpu.CPU, buf, size uint64) {
	cwd := h.FS.Getcwd()
	data := append([]byte(cwd), 0)
	if uint64(len(data)) > size {
		c.X[10] = negErrno(ERANGE)
		return
	}
	h.Mem.WriteBytes(buf, data)
	c.X[10] = buf
}

func (h *Handler) sysMkdirat(c *cpu.CPU, dirfd, pathAddr, mode uint64) {
	path := h.readGuestString(pathAddr)
	if path == "" {
		c.X[10] = negErrno(ENOENT)
		return
	}
	// Simple: resolve and create
	if path[0] != '/' {
		path = h.FS.Getcwd() + "/" + path
	}
	h.FS.MkdirAll(path)
	c.X[10] = 0
}

func (h *Handler) sysClockGettime(c *cpu.CPU, clockID, tsAddr uint64) {
	if tsAddr != 0 {
		now := time.Now()
		h.Mem.Write64(tsAddr, uint64(now.Unix()))
		h.Mem.Write64(tsAddr+8, uint64(now.Nanosecond()))
	}
	c.X[10] = 0
}

func (h *Handler) sysClockGetres(c *cpu.CPU, clockID, resAddr uint64) {
	if resAddr != 0 {
		h.Mem.Write64(resAddr, 0)   // seconds
		h.Mem.Write64(resAddr+8, 1) // nanoseconds (1ns resolution)
	}
	c.X[10] = 0
}

func (h *Handler) sysNanosleep(c *cpu.CPU, reqAddr uint64) {
	if reqAddr != 0 {
		sec, _ := h.Mem.Read64(reqAddr)
		nsec, _ := h.Mem.Read64(reqAddr + 8)
		d := time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond
		if d > 0 && d < 10*time.Second {
			time.Sleep(d)
		}
	}
	c.X[10] = 0
}

func (h *Handler) sysFcntl(c *cpu.CPU, fd, cmd, arg uint64) {
	switch cmd {
	case 0: // F_DUPFD
		newfd, err := h.FS.Dup(int(fd))
		if err != nil {
			c.X[10] = negErrno(EBADF)
		} else {
			c.X[10] = uint64(newfd)
		}
	case 1: // F_GETFD
		c.X[10] = 0
	case 2: // F_SETFD
		c.X[10] = 0
	case 3: // F_GETFL
		f := h.FS.GetFD(int(fd))
		if f == nil {
			c.X[10] = negErrno(EBADF)
		} else {
			c.X[10] = uint64(f.Flags)
		}
	case 4: // F_SETFL
		c.X[10] = 0
	case 1024: // F_DUPFD_CLOEXEC
		newfd, err := h.FS.Dup(int(fd))
		if err != nil {
			c.X[10] = negErrno(EBADF)
		} else {
			c.X[10] = uint64(newfd)
		}
	default:
		c.X[10] = negErrno(EINVAL)
	}
}

func (h *Handler) sysPrlimit64(c *cpu.CPU, pid, resource, newLimit, oldLimit uint64) {
	if oldLimit != 0 {
		h.Mem.Write64(oldLimit, 0x7FFFFFFFFFFFFFFF)
		h.Mem.Write64(oldLimit+8, 0x7FFFFFFFFFFFFFFF)
	}
	c.X[10] = 0
}

func (h *Handler) sysGetrandom(c *cpu.CPU, buf, count uint64) {
	data := make([]byte, count)
	rand.Read(data)
	h.Mem.WriteBytes(buf, data)
	c.X[10] = count
}

func (h *Handler) sysUname(c *cpu.CPU, buf uint64) {
	const fieldLen = 65
	fields := []string{
		"Linux",         // sysname
		"techvm",        // nodename
		"6.1.0",         // release
		"#1 SMP",        // version
		"riscv64",       // machine
	}
	for i, s := range fields {
		offset := uint64(i) * fieldLen
		b := make([]byte, fieldLen)
		copy(b, s)
		h.Mem.WriteBytes(buf+offset, b)
	}
	c.X[10] = 0
}

func (h *Handler) sysSysinfo(c *cpu.CPU, buf uint64) {
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
	c.X[10] = 0
}

func (h *Handler) sysGetrusage(c *cpu.CPU, who, usage uint64) {
	// struct rusage = 144 bytes, zero-fill
	data := make([]byte, 144)
	h.Mem.WriteBytes(usage, data)
	c.X[10] = 0
}

// --- Signal syscalls ---

func (h *Handler) sysRtSigaction(c *cpu.CPU, signum, actAddr, oldAddr, sigsetsize uint64) {
	sig := int(signum)
	if sig < 1 || sig > signal.NSIG {
		c.X[10] = negErrno(EINVAL)
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
	c.X[10] = 0
}

func (h *Handler) sysRtSigprocmask(c *cpu.CPU, how, setAddr, oldsetAddr uint64) {
	var newmask uint64
	if setAddr != 0 {
		newmask, _ = h.Mem.Read64(setAddr)
	}
	old := h.Signals.SetMask(int(how), newmask)
	if oldsetAddr != 0 {
		h.Mem.Write64(oldsetAddr, old)
	}
	c.X[10] = 0
}

func (h *Handler) sysSigaltstack(c *cpu.CPU, ssAddr, oldssAddr uint64) {
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
	c.X[10] = 0
}

// --- Filesystem operations ---

func (h *Handler) sysUnlinkat(c *cpu.CPU, dirfd, pathAddr, flags uint64) {
	path := h.readGuestString(pathAddr)
	err := h.FS.Unlinkat(int(int32(dirfd)), path, int(flags))
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysChdir(c *cpu.CPU, pathAddr uint64) {
	path := h.readGuestString(pathAddr)
	err := h.FS.Chdir(path)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysFtruncate(c *cpu.CPU, fd, length uint64) {
	// If backed by a host file (memfd), truncate the real file
	if hf := h.FS.GetHostFile(int(fd)); hf != nil {
		if err := hf.Truncate(int64(length)); err != nil {
			c.X[10] = negErrno(EINVAL)
			return
		}
		c.X[10] = 0
		return
	}
	err := h.FS.Ftruncate(int(fd), int64(length))
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysFallocate(c *cpu.CPU, fd, mode, offset, length uint64) {
	// Simplified: just extend the file if needed
	total := int64(offset + length)
	err := h.FS.Ftruncate(int(fd), total)
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysSymlinkat(c *cpu.CPU, targetAddr, dirfd, linkpathAddr uint64) {
	target := h.readGuestString(targetAddr)
	linkpath := h.readGuestString(linkpathAddr)
	err := h.FS.Symlinkat(target, int(int32(dirfd)), linkpath)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysRenameat(c *cpu.CPU, olddirfd, oldpathAddr, newdirfd, newpathAddr uint64) {
	oldpath := h.readGuestString(oldpathAddr)
	newpath := h.readGuestString(newpathAddr)
	err := h.FS.Renameat(int(int32(olddirfd)), oldpath, int(int32(newdirfd)), newpath)
	if err != nil {
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

// --- Time syscalls ---

func (h *Handler) sysClockNanosleep(c *cpu.CPU, clockID, flags, reqAddr, remAddr uint64) {
	if reqAddr == 0 {
		c.X[10] = 0
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
	c.X[10] = 0
}

func (h *Handler) sysGetitimer(c *cpu.CPU, which, currValue uint64) {
	if currValue != 0 {
		// struct itimerval = 2 × struct timeval = 2 × (8+8) = 32 bytes
		data := make([]byte, 32)
		h.Mem.WriteBytes(currValue, data) // zero-filled = timer disabled
	}
	c.X[10] = 0
}

func (h *Handler) sysSetitimer(c *cpu.CPU, which, newValue, oldValue uint64) {
	if oldValue != 0 {
		data := make([]byte, 32)
		h.Mem.WriteBytes(oldValue, data) // return old as zero
	}
	c.X[10] = 0
}

// --- ppoll ---

func (h *Handler) sysPpoll(c *cpu.CPU, fdsAddr, nfds, timeoutAddr, sigmask uint64) {
	// Simplified ppoll: if timeout is provided, sleep; otherwise return immediately
	if timeoutAddr != 0 {
		sec, _ := h.Mem.Read64(timeoutAddr)
		nsec, _ := h.Mem.Read64(timeoutAddr + 8)
		d := time.Duration(sec)*time.Second + time.Duration(nsec)*time.Nanosecond
		if d > 0 && d < 10*time.Second {
			time.Sleep(d)
		}
	}
	c.X[10] = 0 // no fds ready
}

func (h *Handler) sysPrctl(c *cpu.CPU, option, arg uint64) {
	switch option {
	case 15: // PR_SET_NAME
		c.X[10] = 0
	case 16: // PR_GET_NAME
		h.Mem.WriteBytes(arg, append([]byte("techvm"), 0))
		c.X[10] = 0
	default:
		c.X[10] = 0
	}
}

func (h *Handler) sysFutex(c *cpu.CPU, uaddr, op, val, timeout uint64) {
	futexOp := op & 0x7F // mask out FUTEX_PRIVATE_FLAG

	switch futexOp {
	case 0: // FUTEX_WAIT
		// Read current value at uaddr
		cur, err := h.Mem.Read32(uaddr)
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		if cur != uint32(val) {
			c.X[10] = negErrno(EAGAIN)
			return
		}
		// For single-threaded, we'd block forever. Use thread manager if available.
		if h.ThreadM != nil {
			h.ThreadM.FutexWait(uaddr, uint32(val))
		}
		c.X[10] = 0

	case 1: // FUTEX_WAKE
		woken := 0
		if h.ThreadM != nil {
			woken = h.ThreadM.FutexWake(uaddr, int(val))
		}
		c.X[10] = uint64(woken)

	default:
		c.X[10] = 0
	}
}

func (h *Handler) sysClone(c *cpu.CPU, flags, childStack, parentTid, tls, childTid uint64) {
	// If this is a thread creation (CLONE_VM|CLONE_FS|CLONE_THREAD)
	if h.ThreadM != nil && flags&0x100 != 0 { // CLONE_VM
		childPC := c.PC + 4 // child returns after the syscall
		if childStack == 0 {
			childStack = c.X[2]
		}
		tid, err := h.ThreadM.Clone(c, childPC, childStack)
		if err != nil {
			c.X[10] = negErrno(ENOMEM)
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
		// Set TLS if CLONE_SETTLS (0x00080000) - set tp in child CPU
		if flags&0x00080000 != 0 {
			h.ThreadM.SetChildTLS(tid, tls)
		}
		c.X[10] = uint64(tid) // parent gets child TID
	} else {
		// fork-like: return 0 (pretend we're child)
		c.X[10] = 0
	}
}

func (h *Handler) sysWrite(c *cpu.CPU, fdNum, bufAddr, count uint64) {
	data, err := h.Mem.ReadBytes(bufAddr, int(count))
	if err != nil {
		c.X[10] = negErrno(EFAULT)
		return
	}
	n, err := h.FS.Write(int(fdNum), data)
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	c.X[10] = uint64(n)
}

func (h *Handler) sysWritev(c *cpu.CPU, fdNum, iovAddr, iovcnt uint64) {
	var total uint64
	for i := uint64(0); i < iovcnt; i++ {
		base, err := h.Mem.Read64(iovAddr + i*16)
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		length, err := h.Mem.Read64(iovAddr + i*16 + 8)
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		data, err := h.Mem.ReadBytes(base, int(length))
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		n, err := h.FS.Write(int(fdNum), data)
		if err != nil {
			c.X[10] = negErrno(EBADF)
			return
		}
		total += uint64(n)
	}
	c.X[10] = total
}

func (h *Handler) sysRead(c *cpu.CPU, fdNum, bufAddr, count uint64) {
	buf := make([]byte, count)
	n, err := h.FS.Read(int(fdNum), buf)
	if err != nil {
		c.X[10] = negErrno(EBADF)
		return
	}
	if n > 0 {
		h.Mem.WriteBytes(bufAddr, buf[:n])
	}
	c.X[10] = uint64(n)
}

func (h *Handler) sysReadv(c *cpu.CPU, fdNum, iovAddr, iovcnt uint64) {
	var total uint64
	for i := uint64(0); i < iovcnt; i++ {
		base, err := h.Mem.Read64(iovAddr + i*16)
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		length, err := h.Mem.Read64(iovAddr + i*16 + 8)
		if err != nil {
			c.X[10] = negErrno(EFAULT)
			return
		}
		buf := make([]byte, length)
		n, err := h.FS.Read(int(fdNum), buf)
		if err != nil {
			c.X[10] = negErrno(EBADF)
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
	c.X[10] = total
}

// ===================================================================
// Socket syscalls
// ===================================================================

func (h *Handler) sysSocket(c *cpu.CPU, domain, sockType, protocol uint64) {
	if domain != vfs.AF_UNIX {
		c.X[10] = negErrno(EAFNOSUPPORT)
		return
	}
	stype := int(sockType & 0xff) // strip SOCK_CLOEXEC/SOCK_NONBLOCK
	if stype != vfs.SOCK_STREAM && stype != vfs.SOCK_DGRAM && stype != vfs.SOCK_SEQPACKET {
		c.X[10] = negErrno(EPROTONOSUPPORT)
		return
	}
	fd, err := h.FS.AllocSocket(int(domain), stype)
	if err != nil {
		c.X[10] = negErrno(ENOMEM)
		return
	}
	c.X[10] = uint64(fd)
}

func (h *Handler) sysConnect(c *cpu.CPU, fd, addrPtr, addrLen uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	// Parse sockaddr_un: family(2) + path
	addrBuf := h.readBytes(addrPtr, addrLen)
	if len(addrBuf) < 3 {
		c.X[10] = negErrno(EINVAL)
		return
	}
	path := extractUnixPath(addrBuf)
	if err := sock.Connect(path); err != nil {
		c.X[10] = negErrno(ECONNREFUSED)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysBind(c *cpu.CPU, fd, addrPtr, addrLen uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	addrBuf := h.readBytes(addrPtr, addrLen)
	if len(addrBuf) < 3 {
		c.X[10] = negErrno(EINVAL)
		return
	}
	path := extractUnixPath(addrBuf)
	if err := sock.Bind(path); err != nil {
		c.X[10] = negErrno(EADDRINUSE)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysListen(c *cpu.CPU, fd, backlog uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	if err := sock.Listen(int(backlog)); err != nil {
		c.X[10] = negErrno(EINVAL)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysAccept4(c *cpu.CPU, fd, addrPtr, addrLenPtr, flags uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	newSock, err := sock.Accept()
	if err != nil {
		c.X[10] = negErrno(EAGAIN)
		return
	}
	// Allocate a new VFS FD for the accepted socket
	h.FS.Lock()
	gfd := h.FS.AllocSocketUnlocked(newSock)
	h.FS.Unlock()
	c.X[10] = uint64(gfd)
}

func (h *Handler) sysSendto(c *cpu.CPU, fd, bufAddr, bufLen, flags, destAddr, destLen uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		// Fall through: non-socket sendto - just do write
		buf := h.readBytes(bufAddr, bufLen)
		n, err := h.FS.Write(int(fd), buf)
		if err != nil {
			c.X[10] = negErrno(EBADF)
			return
		}
		c.X[10] = uint64(n)
		return
	}
	buf := h.readBytes(bufAddr, bufLen)
	n, err := sock.Write(buf)
	if err != nil {
		c.X[10] = negErrno(ECONNRESET)
		return
	}
	c.X[10] = uint64(n)
}

func (h *Handler) sysRecvfrom(c *cpu.CPU, fd, bufAddr, bufLen, flags, srcAddr, srcLenPtr uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		// Fall through: non-socket recvfrom - just do read
		buf := make([]byte, bufLen)
		n, err := h.FS.Read(int(fd), buf)
		if err != nil {
			c.X[10] = negErrno(EBADF)
			return
		}
		if n > 0 {
			h.Mem.WriteBytes(bufAddr, buf[:n])
		}
		c.X[10] = uint64(n)
		return
	}
	buf := make([]byte, bufLen)
	n, err := sock.Read(buf)
	if err != nil {
		c.X[10] = negErrno(ECONNRESET)
		return
	}
	if n > 0 {
		h.Mem.WriteBytes(bufAddr, buf[:n])
	}
	c.X[10] = uint64(n)
}

func (h *Handler) sysShutdown(c *cpu.CPU, fd, how uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	sock.Close()
	c.X[10] = 0
}

func (h *Handler) sysGetsockopt(c *cpu.CPU, fd, level, optname, optval, optlen uint64) {
	// Common stub: return 0 for SO_ERROR, generic ok for others
	if optval != 0 && optlen != 0 {
		lenBuf := h.readBytes(optlen, 4)
		if len(lenBuf) >= 4 {
			olen := binary.LittleEndian.Uint32(lenBuf)
			if olen >= 4 {
				var buf [4]byte
				// SO_ERROR returns 0
				h.Mem.WriteBytes(optval, buf[:])
			}
		}
	}
	c.X[10] = 0
}

func (h *Handler) sysSocketpair(c *cpu.CPU, domain, sockType, protocol, svPtr uint64) {
	if domain != vfs.AF_UNIX {
		c.X[10] = negErrno(EAFNOSUPPORT)
		return
	}
	// Create a real host socketpair, wrap in VFS
	stype := int(sockType & 0xff)
	hostType := syscall.SOCK_STREAM
	if stype == vfs.SOCK_DGRAM {
		hostType = syscall.SOCK_DGRAM
	}
	var fds [2]int
	var err error
	fds, err = syscall.Socketpair(syscall.AF_UNIX, hostType, 0)
	if err != nil {
		c.X[10] = negErrno(ENOMEM)
		return
	}
	// Wrap each host FD as a VFS FD with HostFile
	gfd0 := h.FS.WrapHostFD(fds[0], "socketpair[0]")
	gfd1 := h.FS.WrapHostFD(fds[1], "socketpair[1]")
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[0:], uint32(gfd0))
	binary.LittleEndian.PutUint32(buf[4:], uint32(gfd1))
	h.Mem.WriteBytes(svPtr, buf[:])
	c.X[10] = 0
}

func (h *Handler) sysGetsockname(c *cpu.CPU, fd, addrPtr, addrLenPtr uint64) {
	// Minimal stub: return AF_UNIX + empty path
	if addrPtr != 0 && addrLenPtr != 0 {
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(vfs.AF_UNIX))
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 2)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	}
	c.X[10] = 0
}

func (h *Handler) sysGetpeername(c *cpu.CPU, fd, addrPtr, addrLenPtr uint64) {
	sock := h.FS.GetSocket(int(fd))
	if sock == nil {
		c.X[10] = negErrno(ENOTSOCK)
		return
	}
	// Return AF_UNIX stub
	if addrPtr != 0 && addrLenPtr != 0 {
		var buf [2]byte
		binary.LittleEndian.PutUint16(buf[:], uint16(vfs.AF_UNIX))
		h.Mem.WriteBytes(addrPtr, buf[:])
		var lenBuf [4]byte
		binary.LittleEndian.PutUint32(lenBuf[:], 2)
		h.Mem.WriteBytes(addrLenPtr, lenBuf[:])
	}
	c.X[10] = 0
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

func (h *Handler) sysSendmsg(c *cpu.CPU, fd, msgPtr, flags uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD < 0 {
		// Try socket
		sock := h.FS.GetSocket(int(fd))
		if sock == nil {
			c.X[10] = negErrno(ENOTSOCK)
			return
		}
		hostFD = sock.HostFD()
		if hostFD < 0 {
			c.X[10] = negErrno(ENOTCONN)
			return
		}
	}

	// Parse msghdr from guest memory
	hdr := h.readBytes(msgPtr, 56)
	if len(hdr) < 56 {
		c.X[10] = negErrno(EFAULT)
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
						c.X[10] = negErrno(EBADF)
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
		c.X[10] = negErrno(errnoFromErr(err))
		return
	}
	c.X[10] = uint64(len(payload))
}

func (h *Handler) sysRecvmsg(c *cpu.CPU, fd, msgPtr, flags uint64) {
	hostFD := h.FS.GetHostFDNum(int(fd))
	if hostFD < 0 {
		sock := h.FS.GetSocket(int(fd))
		if sock == nil {
			c.X[10] = negErrno(ENOTSOCK)
			return
		}
		hostFD = sock.HostFD()
		if hostFD < 0 {
			c.X[10] = negErrno(ENOTCONN)
			return
		}
	}

	// Parse msghdr from guest memory
	hdr := h.readBytes(msgPtr, 56)
	if len(hdr) < 56 {
		c.X[10] = negErrno(EFAULT)
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
		c.X[10] = negErrno(errnoFromErr(err))
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

	c.X[10] = uint64(n)
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

func (h *Handler) sysEpollCreate1(c *cpu.CPU, flags uint64) {
	epfd := h.FS.AllocEpoll()
	c.X[10] = uint64(epfd)
}

func (h *Handler) sysEpollCtl(c *cpu.CPU, epfd, op, fd, eventPtr uint64) {
	ep := h.FS.GetEpoll(int(epfd))
	if ep == nil {
		c.X[10] = negErrno(EBADF)
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
		c.X[10] = negErrno(ENOENT)
		return
	}
	c.X[10] = 0
}

func (h *Handler) sysEpollPwait(c *cpu.CPU, epfd, eventsPtr, maxevents, timeout uint64) {
	ep := h.FS.GetEpoll(int(epfd))
	if ep == nil {
		c.X[10] = negErrno(EBADF)
		return
	}

	entries := ep.Entries()
	if len(entries) == 0 {
		// No FDs monitored - respect timeout
		if timeout > 0 && timeout != ^uint64(0) {
			time.Sleep(time.Duration(timeout) * time.Millisecond)
		}
		c.X[10] = 0
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
		c.X[10] = 0
		return
	}

	// Call host poll
	timeoutMs := int(timeout)
	if timeout == ^uint64(0) {
		timeoutMs = -1
	}
	_, _ = unix.Poll(pollFDs, timeoutMs)

	// Translate results back into guest epoll_event structs
	nReady := uint64(0)
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
	c.X[10] = nReady
}

// ===================================================================
// memfd_create + fd-backed mmap
// ===================================================================

func (h *Handler) sysMemfdCreate(c *cpu.CPU, namePtr, flags uint64) {
	name := h.readGuestString(namePtr)
	if name == "" {
		name = "memfd"
	}

	hostFD, err := unix.MemfdCreate(name, int(flags))
	if err != nil {
		c.X[10] = negErrno(ENOMEM)
		return
	}

	f := os.NewFile(uintptr(hostFD), name)
	gfd := h.FS.AllocHostFile(f)
	c.X[10] = uint64(gfd)
}

// Ensure unused imports are silenced
var _ = unsafe.Sizeof(0)

// sysMmap handles mmap with support for fd-backed mappings.
func (h *Handler) sysMmap(c *cpu.CPU) {
	addr := c.X[10]
	length := c.X[11]
	prot := c.X[12]
	flags := c.X[13]
	fd := c.X[14]
	offset := c.X[15]

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
			c.X[10] = addr
		} else {
			result := h.Mem.Mmap(addr, length, perms)
			c.X[10] = result
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
		c.X[10] = addr
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
		c.X[10] = negErrno(ENOMEM)
		return
	}

	// Alias the host mmap'd region into the guest MMU
	guestAddr := h.Mem.MapHostSlice(addr, hostSlice, perms)
	c.X[10] = guestAddr
}
