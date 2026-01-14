package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerWs2Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	sharedHeapAlloc := hctx.HeapAlloc

	ws2, ok := hctx.SynthByName["ws2_32.dll"]
	if !ok {
		return
	}
	_ = ws2
	// WSAStartup: initialize Winsock 2.2
	// WSADATA layout (x64): wVersion(2) + wHighVersion(2) + iMaxSockets(2) + iMaxUdpDg(2) +
	//   lpVendorInfo(8) + szDescription(257) + szSystemStatus(129) = 400+ bytes
	d.RegisterAutoStubHandler(ws2, "WSAStartup", func(ctx *ntapi.TrapContext) uint32 {
		lpWSAData := ctx.Arg(1)
		if lpWSAData != 0 {
			ctx.Mem.Write16(lpWSAData+0, 0x0202) // wVersion 2.2
			ctx.Mem.Write16(lpWSAData+2, 0x0202) // wHighVersion 2.2
			// iMaxSockets and iMaxUdpDg (legacy, ignored post-2.0)
			ctx.Mem.Write16(lpWSAData+4, 0)
			ctx.Mem.Write16(lpWSAData+6, 0)
			ctx.Mem.Write64(lpWSAData+8, 0) // lpVendorInfo = NULL
			// szDescription at offset 16 (257 bytes)
			desc := []byte("WinSock 2.0")
			for i, b := range desc {
				ctx.Mem.Write8(lpWSAData+16+uint64(i), b)
			}
			ctx.Mem.Write8(lpWSAData+16+uint64(len(desc)), 0)
			// szSystemStatus at offset 16+257 = 273 (129 bytes)
			status := []byte("Running")
			for i, b := range status {
				ctx.Mem.Write8(lpWSAData+273+uint64(i), b)
			}
			ctx.Mem.Write8(lpWSAData+273+uint64(len(status)), 0)
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACleanup", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ws2_32] WSACleanup called\n")
		ctx.SetReturn(0)
		return 0
	})

	// Winsock socket creation / management
	const (
		winAFUnix        = 1
		winAFInet        = 2
		winAFInet6       = 23
		winSOLSocket     = 0xFFFF
		winSOReuseAddr   = 4
		winSOKeepAlive   = 8
		winSOSendBuf     = 0x1001
		winSORecvBuf     = 0x1002
		winTCPNodeDelay  = 1
		winFIONBIO       = 0x8004667e
		winFIONREAD      = 0x4004667f
		winPollIn        = 0x0300
		winPollRdNorm    = 0x0100
		winPollRdBand    = 0x0200
		winPollPri       = 0x0002
		winPollOut       = 0x0010
		winPollWrNorm    = 0x0010
		winPollErr       = 0x0001
		winPollHup       = 0x0004
		winPollNVal      = 0x1000
		wsaeWouldBlock   = 10035
		wsaeInProgress   = 10036
		wsaeAlready      = 10037
		wsaeFault        = 10014
		wsaeInval        = 10022
		wsaeMFile        = 10024
		wsaeNotSock      = 10038
		wsaeAddrInUse    = 10048
		wsaeAddrNotAvail = 10049
		wsaeConnReset    = 10054
		wsaeIsConn       = 10056
		wsaeNotConn      = 10057
		wsaeTimedOut     = 10060
		wsaeConnRefused  = 10061
		wsaeAfNoSupport  = 10047
		wsaHostNotFound  = 11001
		invalidSocketRet = ^uint64(0)
		socketErrorRet   = ^uint64(0)
		addrInfoSize     = 48
		wsabufSize       = 16
		wsapollfdSize    = 16
	)

	hostToNet16 := func(v uint16) uint16 {
		return (v>>8)&0xFF | (v<<8)&0xFF00
	}
	hostToNet32 := func(v uint32) uint32 {
		return (v>>24)&0xFF | (v>>8)&0xFF00 | (v<<8)&0xFF0000 | (v<<24)&0xFF000000
	}
	netToHost16 := hostToNet16
	netToHost32 := hostToNet32

	winAfToLinux := func(af uint16) int {
		switch af {
		case winAFInet:
			return syscall.AF_INET // AF_INET
		case winAFInet6:
			return syscall.AF_INET6 // AF_INET6 (Win=23, Linux=10)
		case winAFUnix:
			return syscall.AF_UNIX // AF_UNIX
		default:
			return int(af)
		}
	}
	wsaSetErr := func(ctx *ntapi.TrapContext, e uint32) {
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			ctx.Mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, e)
		}
	}
	wsaErrno := func(err error) uint32 {
		if err == nil {
			return 0
		}
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return wsaeInval
		}
		switch errno {
		case syscall.EAGAIN:
			return wsaeWouldBlock
		case syscall.EINPROGRESS:
			return wsaeInProgress
		case syscall.EALREADY:
			return wsaeAlready
		case syscall.EAFNOSUPPORT:
			return wsaeAfNoSupport
		case syscall.EADDRINUSE:
			return wsaeAddrInUse
		case syscall.EADDRNOTAVAIL:
			return wsaeAddrNotAvail
		case syscall.EBADF, syscall.ENOTSOCK:
			return wsaeNotSock
		case syscall.ECONNRESET:
			return wsaeConnReset
		case syscall.EISCONN:
			return wsaeIsConn
		case syscall.ENOTCONN:
			return wsaeNotConn
		case syscall.ETIMEDOUT:
			return wsaeTimedOut
		case syscall.ECONNREFUSED:
			return wsaeConnRefused
		case syscall.EMFILE:
			return wsaeMFile
		case syscall.EFAULT:
			return wsaeFault
		case syscall.EINVAL:
			return wsaeInval
		default:
			return wsaeInval
		}
	}
	resolveSocket := func(ctx *ntapi.TrapContext, h ntapi.Handle) *ntapi.SocketHandle {
		s := handles.GetSocket(h)
		if s == nil {
			wsaSetErr(ctx, wsaeNotSock)
			ctx.SetReturn(socketErrorRet)
			return nil
		}
		return s
	}
	failSocket := func(ctx *ntapi.TrapContext, err error) uint32 {
		wsaSetErr(ctx, wsaErrno(err))
		ctx.SetReturn(socketErrorRet)
		return 0
	}
	failInvalidSocket := func(ctx *ntapi.TrapContext, errCode uint32) uint32 {
		wsaSetErr(ctx, errCode)
		ctx.SetReturn(invalidSocketRet)
		return 0
	}
	readWSABufs := func(lpBuffers, count uint64) ([]struct {
		Len uint32
		Ptr uint64
	}, error) {
		if lpBuffers == 0 || count == 0 {
			return nil, nil
		}
		bufs := make([]struct {
			Len uint32
			Ptr uint64
		}, 0, count)
		for i := uint64(0); i < count; i++ {
			off := lpBuffers + i*wsabufSize
			bufLen, err := mem.Read32(off)
			if err != nil {
				return nil, err
			}
			bufPtr, err := mem.Read64(off + 8)
			if err != nil {
				return nil, err
			}
			bufs = append(bufs, struct {
				Len uint32
				Ptr uint64
			}{Len: bufLen, Ptr: bufPtr})
		}
		return bufs, nil
	}
	gatherWSABufs := func(lpBuffers, count uint64) ([]byte, error) {
		bufs, err := readWSABufs(lpBuffers, count)
		if err != nil {
			return nil, err
		}
		total := 0
		for _, buf := range bufs {
			total += int(buf.Len)
		}
		data := make([]byte, 0, total)
		for _, buf := range bufs {
			if buf.Len == 0 {
				continue
			}
			part, err := mem.ReadBytes(buf.Ptr, int(buf.Len))
			if err != nil {
				return nil, err
			}
			data = append(data, part...)
		}
		return data, nil
	}
	scatterWSABufs := func(lpBuffers, count uint64, data []byte) (int, error) {
		bufs, err := readWSABufs(lpBuffers, count)
		if err != nil {
			return 0, err
		}
		written := 0
		for _, buf := range bufs {
			if buf.Len == 0 || written >= len(data) {
				continue
			}
			n := int(buf.Len)
			if n > len(data)-written {
				n = len(data) - written
			}
			if err := mem.WriteBytes(buf.Ptr, data[written:written+n]); err != nil {
				return written, err
			}
			written += n
		}
		return written, nil
	}

	d.RegisterAutoStubHandler(ws2, "socket", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASocketW", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASocketA", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "closesocket", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		s := handles.GetSocket(h)
		if s == nil {
			return failSocket(ctx, syscall.ENOTSOCK)
		}
		if err := syscall.Close(s.FD); err != nil && err != syscall.EBADF {
			return failSocket(ctx, err)
		}
		handles.Close(h)
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})

	// Build a Linux sockaddr from Win32 sockaddr_in/in6 at guestAddr
	makeSockaddr := func(guestAddr, guestLen uint64) (syscall.Sockaddr, error) {
		if guestAddr == 0 {
			return nil, syscall.EFAULT
		}
		family, _ := mem.Read16(guestAddr)
		switch family {
		case winAFInet: // AF_INET
			if guestLen != 0 && guestLen < 16 {
				return nil, syscall.EINVAL
			}
			port, _ := mem.Read16(guestAddr + 2)
			a0, _ := mem.Read8(guestAddr + 4)
			a1, _ := mem.Read8(guestAddr + 5)
			a2, _ := mem.Read8(guestAddr + 6)
			a3, _ := mem.Read8(guestAddr + 7)
			return &syscall.SockaddrInet4{
				Port: int(netToHost16(port)),
				Addr: [4]byte{a0, a1, a2, a3},
			}, nil
		case winAFInet6, syscall.AF_INET6: // AF_INET6
			if guestLen != 0 && guestLen < 28 {
				return nil, syscall.EINVAL
			}
			port, _ := mem.Read16(guestAddr + 2)
			var addr [16]byte
			for i := 0; i < 16; i++ {
				b, _ := mem.Read8(guestAddr + 8 + uint64(i))
				addr[i] = b
			}
			scopeId, _ := mem.Read32(guestAddr + 24)
			return &syscall.SockaddrInet6{
				Port:   int(netToHost16(port)),
				Addr:   addr,
				ZoneId: scopeId,
			}, nil
		}
		return nil, syscall.EAFNOSUPPORT
	}

	// Write sockaddr back to guest memory
	writeSockaddr := func(guestAddr uint64, guestLenPtr uint64, sa syscall.Sockaddr) error {
		if guestAddr == 0 {
			return nil
		}
		maxLen := ^uint64(0)
		if guestLenPtr != 0 {
			n, err := mem.Read32(guestLenPtr)
			if err == nil {
				maxLen = uint64(n)
			}
		}
		switch s := sa.(type) {
		case *syscall.SockaddrInet4:
			if maxLen < 16 {
				return syscall.EFAULT
			}
			port := hostToNet16(uint16(s.Port))
			mem.Write16(guestAddr, winAFInet)
			mem.Write16(guestAddr+2, port)
			mem.Write8(guestAddr+4, s.Addr[0])
			mem.Write8(guestAddr+5, s.Addr[1])
			mem.Write8(guestAddr+6, s.Addr[2])
			mem.Write8(guestAddr+7, s.Addr[3])
			for i := uint64(8); i < 16; i++ {
				mem.Write8(guestAddr+i, 0)
			}
			if guestLenPtr != 0 {
				mem.Write32(guestLenPtr, 16)
			}
			return nil
		case *syscall.SockaddrInet6:
			if maxLen < 28 {
				return syscall.EFAULT
			}
			port := hostToNet16(uint16(s.Port))
			mem.Write16(guestAddr, winAFInet6)
			mem.Write16(guestAddr+2, port)
			mem.Write32(guestAddr+4, 0)
			for i, b := range s.Addr {
				mem.Write8(guestAddr+8+uint64(i), b)
			}
			mem.Write32(guestAddr+24, s.ZoneId)
			if guestLenPtr != 0 {
				mem.Write32(guestLenPtr, 28)
			}
			return nil
		default:
			return syscall.EAFNOSUPPORT
		}
	}
	readFDSet := func(setAddr uint64) ([]ntapi.Handle, error) {
		if setAddr == 0 {
			return nil, nil
		}
		count, err := mem.Read32(setAddr)
		if err != nil {
			return nil, err
		}
		out := make([]ntapi.Handle, 0, count)
		for i := uint32(0); i < count; i++ {
			h, err := mem.Read64(setAddr + 4 + uint64(i)*8)
			if err != nil {
				return nil, err
			}
			out = append(out, ntapi.Handle(h))
		}
		return out, nil
	}
	writeFDSet := func(setAddr uint64, fds []ntapi.Handle) error {
		if setAddr == 0 {
			return nil
		}
		if err := mem.Write32(setAddr, uint32(len(fds))); err != nil {
			return err
		}
		for i, h := range fds {
			if err := mem.Write64(setAddr+4+uint64(i)*8, uint64(h)); err != nil {
				return err
			}
		}
		return nil
	}
	translateSockopt := func(level, opt int) (int, int) {
		switch level {
		case winSOLSocket:
			level = syscall.SOL_SOCKET
			switch opt {
			case winSOReuseAddr:
				opt = syscall.SO_REUSEADDR
			case winSOKeepAlive:
				opt = syscall.SO_KEEPALIVE
			case winSOSendBuf:
				opt = syscall.SO_SNDBUF
			case winSORecvBuf:
				opt = syscall.SO_RCVBUF
			}
		case syscall.IPPROTO_TCP:
			switch opt {
			case winTCPNodeDelay:
				opt = syscall.TCP_NODELAY
			}
		}
		return level, opt
	}
	timeoutFromTimeval := func(timeoutPtr uint64) int {
		if timeoutPtr == 0 {
			return -1
		}
		sec, _ := mem.Read32(timeoutPtr)
		usec, _ := mem.Read32(timeoutPtr + 4)
		ms := int(int64(int32(sec))*1000 + int64(int32(usec))/1000)
		if ms < 0 {
			return 0
		}
		return ms
	}
	translateWinPollEvents := func(events int16) int16 {
		var out int16
		if events&(winPollIn|winPollRdNorm|winPollRdBand) != 0 {
			out |= unix.POLLIN
		}
		if events&(winPollOut|winPollWrNorm) != 0 {
			out |= unix.POLLOUT
		}
		if events&winPollPri != 0 {
			out |= unix.POLLPRI
		}
		return out
	}
	translateLinuxPollRevents := func(revents int16) int16 {
		var out int16
		if revents&unix.POLLIN != 0 {
			out |= winPollRdNorm
		}
		if revents&unix.POLLOUT != 0 {
			out |= winPollWrNorm
		}
		if revents&unix.POLLPRI != 0 {
			out |= winPollPri
		}
		if revents&unix.POLLERR != 0 {
			out |= winPollErr
		}
		if revents&(unix.POLLHUP|unix.POLLRDHUP) != 0 {
			out |= winPollHup
		}
		if revents&unix.POLLNVAL != 0 {
			out |= winPollNVal
		}
		return out
	}

	d.RegisterAutoStubHandler(ws2, "bind", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		sa, err := makeSockaddr(addrPtr, addrLen)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := syscall.Bind(s.FD, sa); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "connect", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		sa, err := makeSockaddr(addrPtr, addrLen)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := syscall.Connect(s.FD, sa); err != nil {
			if err == syscall.EINPROGRESS {
				wsaSetErr(ctx, wsaeInProgress)
				ctx.SetReturn(0)
				return 0
			}
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "listen", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		backlog := int(ctx.Arg(1))
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		if err := syscall.Listen(s.FD, backlog); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "accept", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		fd, sa, err := syscall.Accept(s.FD)
		if err != nil {
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		if err := writeSockaddr(addrPtr, addrLen, sa); err != nil {
			syscall.Close(fd)
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		family := s.Family
		switch sa.(type) {
		case *syscall.SockaddrInet4:
			family = syscall.AF_INET
		case *syscall.SockaddrInet6:
			family = syscall.AF_INET6
		}
		newH := handles.Alloc(ntapi.NewSocketHandle(fd, family, s.SockType, s.Proto))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(newH))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "send", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		flags := int(ctx.Arg(3))
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		data, err := mem.ReadBytes(lpBuf, nLen)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		n, err := unix.SendmsgN(s.FD, data, nil, nil, flags)
		if err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "recv", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		flags := int(ctx.Arg(3))
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		data := make([]byte, nLen)
		n, _, err := unix.Recvfrom(s.FD, data, flags)
		if err != nil || n < 0 {
			if err == nil {
				err = syscall.EINVAL
			}
			return failSocket(ctx, err)
		}
		mem.WriteBytes(lpBuf, data[:n])
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "sendto", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		flags := int(ctx.Arg(3))
		addrPtr := ctx.Arg(4)
		addrLen := ctx.Arg(5)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		data, err := mem.ReadBytes(lpBuf, nLen)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		var sa syscall.Sockaddr
		if addrPtr != 0 {
			sa, err = makeSockaddr(addrPtr, addrLen)
			if err != nil {
				return failSocket(ctx, err)
			}
		}
		n, err := syscall.SendmsgN(s.FD, data, nil, sa, flags)
		if err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "recvfrom", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		flags := int(ctx.Arg(3))
		fromPtr := ctx.Arg(4)
		fromLen := ctx.Arg(5)
		s := handles.GetSocket(h)
		if s == nil {
			wsaSetErr(ctx, wsaeNotSock)
			ctx.SetReturn(socketErrorRet)
			return 0
		}
		data := make([]byte, nLen)
		n, sa, err := syscall.Recvfrom(s.FD, data, flags)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := mem.WriteBytes(lpBuf, data[:n]); err != nil {
			return failSocket(ctx, err)
		}
		if err := writeSockaddr(fromPtr, fromLen, sa); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "shutdown", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		how := int(ctx.Arg(1)) // SD_RECEIVE=0, SD_SEND=1, SD_BOTH=2
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		if err := syscall.Shutdown(s.FD, how); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "setsockopt", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		level := int(ctx.Arg(1))
		optName := int(ctx.Arg(2))
		optVal := ctx.Arg(3)
		optLen := int(ctx.Arg(4))
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		level, optName = translateSockopt(level, optName)
		if optVal == 0 || optLen <= 0 {
			return failSocket(ctx, syscall.EFAULT)
		}
		var val int
		switch {
		case optLen >= 4:
			v, err := mem.Read32(optVal)
			if err != nil {
				return failSocket(ctx, syscall.EFAULT)
			}
			val = int(int32(v))
		default:
			v, err := mem.Read8(optVal)
			if err != nil {
				return failSocket(ctx, syscall.EFAULT)
			}
			val = int(v)
		}
		if err := syscall.SetsockoptInt(s.FD, level, optName, val); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getsockopt", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		level := int(ctx.Arg(1))
		optName := int(ctx.Arg(2))
		optVal := ctx.Arg(3)
		optLen := ctx.Arg(4)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		if optVal == 0 || optLen == 0 {
			return failSocket(ctx, syscall.EFAULT)
		}
		level, optName = translateSockopt(level, optName)
		wantLen, err := mem.Read32(optLen)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		val, err := syscall.GetsockoptInt(s.FD, level, optName)
		if err != nil {
			return failSocket(ctx, err)
		}
		if wantLen >= 4 {
			mem.Write32(optVal, uint32(val))
			mem.Write32(optLen, 4)
		} else if wantLen >= 1 {
			mem.Write8(optVal, byte(val))
			mem.Write32(optLen, 1)
		} else {
			return failSocket(ctx, syscall.EINVAL)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getsockname", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		sa, err := syscall.Getsockname(s.FD)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := writeSockaddr(addrPtr, addrLen, sa); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getpeername", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		sa, err := syscall.Getpeername(s.FD)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := writeSockaddr(addrPtr, addrLen, sa); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "ioctlsocket", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		cmd := uint32(ctx.Arg(1))
		argPtr := ctx.Arg(2)
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		if argPtr == 0 {
			return failSocket(ctx, syscall.EFAULT)
		}
		switch cmd {
		case winFIONBIO:
			v, _ := mem.Read32(argPtr)
			if err := syscall.SetNonblock(s.FD, v != 0); err != nil {
				return failSocket(ctx, err)
			}
		case winFIONREAD:
			n, err := unix.IoctlGetInt(s.FD, unix.TIOCINQ)
			if err != nil {
				return failSocket(ctx, err)
			}
			mem.Write32(argPtr, uint32(n))
		default:
			return failSocket(ctx, syscall.EINVAL)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})

	// WSASend / WSARecv - simplified (single buffer, no overlapped)
	d.RegisterAutoStubHandler(ws2, "WSASend", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1)
		dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesSent := ctx.Arg(3)
		dwFlags := int(ctx.Arg(4))
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		data, err := gatherWSABufs(lpBuffers, dwBufferCount)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		n, err := unix.SendmsgN(s.FD, data, nil, nil, dwFlags)
		if err != nil {
			return failSocket(ctx, err)
		}
		if lpNumberOfBytesSent != 0 {
			mem.Write32(lpNumberOfBytesSent, uint32(n))
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSARecv", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1)
		dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesRecvd := ctx.Arg(3)
		lpFlags := ctx.Arg(4)
		flags := 0
		if lpFlags != 0 {
			v, _ := mem.Read32(lpFlags)
			flags = int(v)
		}
		s := resolveSocket(ctx, h)
		if s == nil {
			return 0
		}
		bufs, err := readWSABufs(lpBuffers, dwBufferCount)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		total := 0
		for _, buf := range bufs {
			total += int(buf.Len)
		}
		data := make([]byte, total)
		n, _, err := unix.Recvfrom(s.FD, data, flags)
		if err != nil || n < 0 {
			if err == nil {
				err = syscall.EINVAL
			}
			return failSocket(ctx, err)
		}
		if _, err := scatterWSABufs(lpBuffers, dwBufferCount, data[:n]); err != nil {
			return failSocket(ctx, err)
		}
		if lpNumberOfBytesRecvd != 0 {
			mem.Write32(lpNumberOfBytesRecvd, uint32(n))
		}
		if lpFlags != 0 {
			mem.Write32(lpFlags, 0)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})

	// WSAGetLastError - reads from TEB LastErrorValue (same as GetLastError per MSDN)
	d.RegisterAutoStubHandler(ws2, "WSAGetLastError", func(ctx *ntapi.TrapContext) uint32 {
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			val, err := ctx.Mem.Read32(ctx.State.TEBAddr + ntapi.TebLastErrorValue)
			if err == nil {
				ctx.SetReturn(uint64(val))
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetLastError", func(ctx *ntapi.TrapContext) uint32 {
		errCode := uint32(ctx.Arg(0))
		if ctx.State != nil && ctx.State.TEBAddr != 0 {
			ctx.Mem.Write32(ctx.State.TEBAddr+ntapi.TebLastErrorValue, errCode)
		}
		return 0
	})

	// gethostname - return "raven" as the hostname
	d.RegisterAutoStubHandler(ws2, "gethostname", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		n := int(ctx.Arg(1))
		if n == 0 || buf == 0 {
			return failSocket(ctx, syscall.EFAULT)
		}
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "localhost"
		}
		b := []byte(hostname)
		if len(b)+1 > n {
			wsaSetErr(ctx, wsaeFault)
			ctx.SetReturn(socketErrorRet)
			return 0
		}
		mem.WriteBytes(buf, append(b, 0))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})

	buildAddrInfo := func(node, service string, hintsPtr uint64, wide bool) (uint64, uint32) {
		var (
			aiFlags    uint32
			aiFamily   uint32
			aiSockType uint32 = syscall.SOCK_STREAM
			aiProto    uint32 = syscall.IPPROTO_TCP
		)
		if hintsPtr != 0 {
			aiFlags, _ = mem.Read32(hintsPtr)
			aiFamily, _ = mem.Read32(hintsPtr + 4)
			aiSockType, _ = mem.Read32(hintsPtr + 8)
			aiProto, _ = mem.Read32(hintsPtr + 12)
		}
		if aiSockType == 0 && aiProto == syscall.IPPROTO_UDP {
			aiSockType = syscall.SOCK_DGRAM
		}
		if aiProto == 0 {
			switch aiSockType {
			case syscall.SOCK_DGRAM:
				aiProto = syscall.IPPROTO_UDP
			default:
				aiProto = syscall.IPPROTO_TCP
			}
		}
		port := 0
		if service != "" {
			if n, err := strconv.Atoi(service); err == nil && n >= 0 && n <= 65535 {
				port = n
			} else {
				network := "tcp"
				if aiSockType == syscall.SOCK_DGRAM || aiProto == syscall.IPPROTO_UDP {
					network = "udp"
				}
				n, err := net.LookupPort(network, service)
				if err != nil {
					return 0, wsaHostNotFound
				}
				port = n
			}
		}
		var ips []net.IP
		if parsed := net.ParseIP(node); parsed != nil {
			ips = []net.IP{parsed}
		} else if node != "" {
			lookedUp, err := net.LookupIP(node)
			if err != nil || len(lookedUp) == 0 {
				return 0, wsaHostNotFound
			}
			ips = lookedUp
		} else {
			switch aiFamily {
			case winAFInet:
				if aiFlags&1 != 0 {
					ips = []net.IP{net.IPv4zero}
				} else {
					ips = []net.IP{net.IPv4(127, 0, 0, 1)}
				}
			case winAFInet6:
				if aiFlags&1 != 0 {
					ips = []net.IP{net.IPv6zero}
				} else {
					ips = []net.IP{net.IPv6loopback}
				}
			default:
				if aiFlags&1 != 0 {
					ips = []net.IP{net.IPv4zero, net.IPv6zero}
				} else {
					ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
				}
			}
		}
		var firstAddr uint64
		var prevNext uint64
		for i := len(ips) - 1; i >= 0; i-- {
			ip := ips[i]
			var (
				addrBlock uint64
				addrSize  uint64
				family    uint32
			)
			if ip4 := ip.To4(); ip4 != nil {
				if aiFamily != 0 && aiFamily != winAFInet {
					continue
				}
				family = winAFInet
				addrSize = 16
				addrBlock = mem.Mmap(0, addrSize, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, winAFInet)
				mem.Write16(addrBlock+2, hostToNet16(uint16(port)))
				mem.WriteBytes(addrBlock+4, ip4)
			} else if ip6 := ip.To16(); ip6 != nil {
				if aiFamily != 0 && aiFamily != winAFInet6 {
					continue
				}
				family = winAFInet6
				addrSize = 28
				addrBlock = mem.Mmap(0, addrSize, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, winAFInet6)
				mem.Write16(addrBlock+2, hostToNet16(uint16(port)))
				mem.WriteBytes(addrBlock+8, ip6)
			} else {
				continue
			}
			aiBlock := mem.Mmap(0, addrInfoSize, mmu.PermRead|mmu.PermWrite)
			canonName := uint64(0)
			if node != "" && (aiFlags&0x2) != 0 {
				if wide {
					encoded := make([]byte, 0, len(node)*2+2)
					for _, r := range node {
						encoded = append(encoded, byte(r), byte(r>>8))
					}
					encoded = append(encoded, 0, 0)
					canonName = mem.Mmap(0, uint64(len(encoded)), mmu.PermRead|mmu.PermWrite)
					mem.WriteBytes(canonName, encoded)
				} else {
					canonName = mem.Mmap(0, uint64(len(node)+1), mmu.PermRead|mmu.PermWrite)
					mem.WriteBytes(canonName, append([]byte(node), 0))
				}
			}
			mem.Write32(aiBlock, aiFlags)
			mem.Write32(aiBlock+4, family)
			mem.Write32(aiBlock+8, aiSockType)
			mem.Write32(aiBlock+12, aiProto)
			mem.Write64(aiBlock+16, addrSize)
			mem.Write64(aiBlock+24, canonName)
			mem.Write64(aiBlock+32, addrBlock)
			mem.Write64(aiBlock+40, prevNext)
			prevNext = aiBlock
			firstAddr = aiBlock
		}
		if firstAddr == 0 {
			return 0, wsaHostNotFound
		}
		return firstAddr, 0
	}
	d.RegisterAutoStubHandler(ws2, "getaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
		nodePtr := ctx.Arg(0)
		servicePtr := ctx.Arg(1)
		hintsPtr := ctx.Arg(2)
		ppResult := ctx.Arg(3)
		if ppResult == 0 {
			ctx.SetReturn(wsaeFault)
			return 0
		}
		mem.Write64(ppResult, 0)
		node := ""
		if nodePtr != 0 {
			node = strings.TrimSpace(readGuestString(nodePtr))
		}
		service := ""
		if servicePtr != 0 {
			service = strings.TrimSpace(readGuestString(servicePtr))
		}
		firstAddr, rc := buildAddrInfo(node, service, hintsPtr, false)
		mem.Write64(ppResult, firstAddr)
		ctx.SetReturn(uint64(rc))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "GetAddrInfoW", func(ctx *ntapi.TrapContext) uint32 {
		nodePtr := ctx.Arg(0)
		servicePtr := ctx.Arg(1)
		hintsPtr := ctx.Arg(2)
		ppResult := ctx.Arg(3)
		if ppResult == 0 {
			ctx.SetReturn(wsaeFault)
			return 0
		}
		mem.Write64(ppResult, 0)
		node := ""
		if nodePtr != 0 {
			node = strings.TrimSpace(readGuestUTF16(nodePtr))
		}
		service := ""
		if servicePtr != 0 {
			service = strings.TrimSpace(readGuestUTF16(servicePtr))
		}
		firstAddr, rc := buildAddrInfo(node, service, hintsPtr, true)
		mem.Write64(ppResult, firstAddr)
		ctx.SetReturn(uint64(rc))
		return 0
	})
	for _, fn := range []string{"freeaddrinfo", "FreeAddrInfoW", "FreeAddrInfoEx"} {
		d.RegisterAutoStubHandler(ws2, fn, func(ctx *ntapi.TrapContext) uint32 { return 0 })
	}
	d.RegisterAutoStubHandler(ws2, "gethostbyname", func(ctx *ntapi.TrapContext) uint32 {
		namePtr := ctx.Arg(0)
		if namePtr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		name := readGuestString(namePtr)
		addrs, err := net.LookupHost(name)
		if err != nil || len(addrs) == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ip := net.ParseIP(addrs[0]).To4()
		if ip == nil {
			ctx.SetReturn(0)
			return 0
		}
		// Build hostent in guest memory
		hostent := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
		// h_name pointer
		nameBuf := mem.Mmap(0, uint64(len(name)+1), mmu.PermRead|mmu.PermWrite)
		mem.WriteBytes(nameBuf, append([]byte(name), 0))
		addrBuf := mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		mem.Write8(addrBuf, ip[0])
		mem.Write8(addrBuf+1, ip[1])
		mem.Write8(addrBuf+2, ip[2])
		mem.Write8(addrBuf+3, ip[3])
		addrList := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		mem.Write64(addrList, addrBuf)
		mem.Write64(addrList+8, 0)
		mem.Write64(hostent, nameBuf)     // h_name
		mem.Write64(hostent+8, 0)         // h_aliases
		mem.Write16(hostent+16, 2)        // h_addrtype = AF_INET
		mem.Write16(hostent+18, 4)        // h_length = 4
		mem.Write64(hostent+20, addrList) // h_addr_list
		ctx.SetReturn(hostent)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAIoctl", func(ctx *ntapi.TrapContext) uint32 {
		// Most IOCTLs not supported
		ctx.SetReturn(^uint64(0)) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEnumNetworkEvents", func(ctx *ntapi.TrapContext) uint32 {
		// int WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
		//   LPWSANETWORKEVENTS lpNetworkEvents)
		// Return SOCKET_ERROR with WSAEINVAL - no real event tracking
		wsaSetErr(ctx, 10022)     // WSAEINVAL
		ctx.SetReturn(^uint64(0)) // SOCKET_ERROR (-1)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEventSelect", func(ctx *ntapi.TrapContext) uint32 {
		sock := ctx.Arg(0)
		hEvent := ctx.Arg(1)
		lNetworkEvents := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAEventSelect sock=0x%x event=0x%x networkEvents=0x%x\n", sock, hEvent, lNetworkEvents)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACreateEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := handles.Alloc(ntapi.NewEvent(true, false))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACloseEvent", func(ctx *ntapi.TrapContext) uint32 {
		handles.Close(ntapi.Handle(ctx.Arg(0)))
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAWaitForMultipleEvents", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0) // WSA_WAIT_EVENT_0
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAResetEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if ev := handles.GetEvent(h); ev != nil {
			ev.Reset()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetEvent", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if ev := handles.GetEvent(h); ev != nil {
			ev.Signal()
		}
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSADuplicateSocketW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(^uint64(0))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "select", func(ctx *ntapi.TrapContext) uint32 {
		_ = ctx.Arg(0) // nfds is ignored by Winsock.
		readfds := ctx.Arg(1)
		writefds := ctx.Arg(2)
		exceptfds := ctx.Arg(3)
		timeoutPtr := ctx.Arg(4)
		readHandles, err := readFDSet(readfds)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		writeHandles, err := readFDSet(writefds)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		exceptHandles, err := readFDSet(exceptfds)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		type pollSpec struct {
			handle ntapi.Handle
			events int16
		}
		merged := map[ntapi.Handle]int16{}
		addHandles := func(items []ntapi.Handle, events int16) error {
			for _, h := range items {
				s := handles.GetSocket(h)
				if s == nil {
					return syscall.ENOTSOCK
				}
				merged[h] |= events
			}
			return nil
		}
		if err := addHandles(readHandles, unix.POLLIN); err != nil {
			return failSocket(ctx, err)
		}
		if err := addHandles(writeHandles, unix.POLLOUT); err != nil {
			return failSocket(ctx, err)
		}
		if err := addHandles(exceptHandles, unix.POLLPRI|unix.POLLERR); err != nil {
			return failSocket(ctx, err)
		}
		pollFDs := make([]unix.PollFd, 0, len(merged))
		specs := make([]pollSpec, 0, len(merged))
		for h, events := range merged {
			s := handles.GetSocket(h)
			pollFDs = append(pollFDs, unix.PollFd{Fd: int32(s.FD), Events: events})
			specs = append(specs, pollSpec{handle: h, events: events})
		}
		timeoutMs := timeoutFromTimeval(timeoutPtr)
		readyCount := 0
		readReady := make([]ntapi.Handle, 0, len(readHandles))
		writeReady := make([]ntapi.Handle, 0, len(writeHandles))
		exceptReady := make([]ntapi.Handle, 0, len(exceptHandles))
		if len(pollFDs) == 0 {
			if timeoutMs > 0 {
				time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
			}
		} else {
			n, err := unix.Poll(pollFDs, timeoutMs)
			if err != nil {
				return failSocket(ctx, err)
			}
			if n > 0 {
				reventsByHandle := make(map[ntapi.Handle]int16, len(specs))
				for i, spec := range specs {
					reventsByHandle[spec.handle] = pollFDs[i].Revents
				}
				for _, h := range readHandles {
					if reventsByHandle[h]&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
						readReady = append(readReady, h)
					}
				}
				for _, h := range writeHandles {
					if reventsByHandle[h]&(unix.POLLOUT|unix.POLLERR) != 0 {
						writeReady = append(writeReady, h)
					}
				}
				for _, h := range exceptHandles {
					if reventsByHandle[h]&(unix.POLLPRI|unix.POLLERR|unix.POLLNVAL) != 0 {
						exceptReady = append(exceptReady, h)
					}
				}
				readyCount = len(readReady) + len(writeReady) + len(exceptReady)
			}
		}
		if err := writeFDSet(readfds, readReady); err != nil {
			return failSocket(ctx, err)
		}
		if err := writeFDSet(writefds, writeReady); err != nil {
			return failSocket(ctx, err)
		}
		if err := writeFDSet(exceptfds, exceptReady); err != nil {
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(readyCount))
		return 0
	})

	// ═══════════════════════════════════════════════════════════════
	// AUTO-GENERATED: Missing ws2_32 handlers from ReactOS spec
	// ═══════════════════════════════════════════════════════════════

	d.RegisterAutoStubHandler(ws2, "GetNameInfoW", func(ctx *ntapi.TrapContext) uint32 {
		pSockaddr := ctx.Arg(0)
		SockaddrLength := ctx.Arg(1)
		pNodeBuffer := ctx.Arg(2)
		NodeBufferSize := ctx.Arg(3)
		pServiceBuffer := ctx.Arg(4)
		ServiceBufferSize := ctx.Arg(5)
		ravelog.Logf("[ws2_32] GetNameInfoW addr=0x%x\n", pSockaddr)
		_ = SockaddrLength
		_ = NodeBufferSize
		_ = ServiceBufferSize
		if pNodeBuffer != 0 {
			ctx.Mem.Write16(pNodeBuffer, 0)
		} // empty host
		if pServiceBuffer != 0 {
			ctx.Mem.Write16(pServiceBuffer, 0)
		} // empty service
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WEP", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ws2_32] WEP()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WPUCompleteOverlappedRequest", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		lpOverlapped := ctx.Arg(1)
		dwError := ctx.Arg(2)
		cbTransferred := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WPUCompleteOverlappedRequest sock=0x%x err=%d bytes=%d\n", s, dwError, cbTransferred)
		_ = lpOverlapped
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAccept", func(ctx *ntapi.TrapContext) uint32 {
		s := ntapi.Handle(ctx.Arg(0))
		addr := ctx.Arg(1)
		addrlen := ctx.Arg(2)
		lpfnCondition := ctx.Arg(3)
		dwCallbackData := ctx.Arg(4)
		ravelog.Logf("[ws2_32] WSAAccept sock=0x%x\n", s)
		_ = lpfnCondition
		_ = dwCallbackData
		sock := resolveSocket(ctx, s)
		if sock == nil {
			ctx.SetReturn(invalidSocketRet)
			return 0
		}
		fd, sa, err := syscall.Accept(sock.FD)
		if err != nil {
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		if err := writeSockaddr(addr, addrlen, sa); err != nil {
			syscall.Close(fd)
			return failInvalidSocket(ctx, wsaErrno(err))
		}
		family := sock.Family
		switch sa.(type) {
		case *syscall.SockaddrInet4:
			family = syscall.AF_INET
		case *syscall.SockaddrInet6:
			family = syscall.AF_INET6
		}
		newH := handles.Alloc(ntapi.NewSocketHandle(fd, family, sock.SockType, sock.Proto))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(uint64(newH))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAddressToStringA", func(ctx *ntapi.TrapContext) uint32 {
		lpsaAddress := ctx.Arg(0)
		dwAddressLength := ctx.Arg(1)
		lpProtocolInfo := ctx.Arg(2)
		lpszAddressString := ctx.Arg(3)
		lpdwAddressStringLength := ctx.Arg(4)
		_ = lpProtocolInfo
		ravelog.Logf("[ws2_32] WSAAddressToStringA addr=0x%x len=%d\n", lpsaAddress, dwAddressLength)
		// Read sin_family, sin_port, sin_addr from sockaddr_in
		if lpsaAddress != 0 {
			af, _ := ctx.Mem.Read16(lpsaAddress)
			if af == 2 { // AF_INET
				port, _ := ctx.Mem.Read16(lpsaAddress + 2)
				port = (port>>8)&0xFF | (port<<8)&0xFF00 // ntohs
				ipRaw, _ := ctx.Mem.Read32(lpsaAddress + 4)
				ips := fmt.Sprintf("%d.%d.%d.%d:%d", ipRaw&0xFF, (ipRaw>>8)&0xFF, (ipRaw>>16)&0xFF, (ipRaw>>24)&0xFF, port)
				if lpdwAddressStringLength != 0 {
					ctx.Mem.Write32(lpdwAddressStringLength, uint32(len(ips)+1))
				}
				if lpszAddressString != 0 {
					for i, ch := range ips {
						ctx.Mem.Write8(lpszAddressString+uint64(i), byte(ch))
					}
					ctx.Mem.Write8(lpszAddressString+uint64(len(ips)), 0)
				}
			}
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAddressToStringW", func(ctx *ntapi.TrapContext) uint32 {
		lpsaAddress := ctx.Arg(0)
		dwAddressLength := ctx.Arg(1)
		lpProtocolInfo := ctx.Arg(2)
		lpszAddressString := ctx.Arg(3)
		lpdwAddressStringLength := ctx.Arg(4)
		_ = lpProtocolInfo
		ravelog.Logf("[ws2_32] WSAAddressToStringW addr=0x%x len=%d\n", lpsaAddress, dwAddressLength)
		// Read sin_family, sin_port, sin_addr from sockaddr_in
		if lpsaAddress != 0 {
			af, _ := ctx.Mem.Read16(lpsaAddress)
			if af == 2 { // AF_INET
				port, _ := ctx.Mem.Read16(lpsaAddress + 2)
				port = (port>>8)&0xFF | (port<<8)&0xFF00 // ntohs
				ipRaw, _ := ctx.Mem.Read32(lpsaAddress + 4)
				ips := fmt.Sprintf("%d.%d.%d.%d:%d", ipRaw&0xFF, (ipRaw>>8)&0xFF, (ipRaw>>16)&0xFF, (ipRaw>>24)&0xFF, port)
				if lpdwAddressStringLength != 0 {
					ctx.Mem.Write32(lpdwAddressStringLength, uint32(len(ips)+1))
				}
				if lpszAddressString != 0 {
					for i, ch := range ips {
						ctx.Mem.Write8(lpszAddressString+uint64(i), byte(ch))
					}
					ctx.Mem.Write8(lpszAddressString+uint64(len(ips)), 0)
				}
			}
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetHostByAddr", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetHostByAddr hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetHostByName", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetHostByName hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetProtoByName", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetProtoByName hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetProtoByNumber", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetProtoByNumber hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetServByName", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetServByName hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncGetServByPort", func(ctx *ntapi.TrapContext) uint32 {
		hWnd := ctx.Arg(0)
		wMsg := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAAsyncGetServByPort hwnd=0x%x msg=0x%x\n", hWnd, wMsg)
		ctx.SetReturn(0) // NULL handle = error
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAAsyncSelect", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		hWnd := ctx.Arg(1)
		wMsg := ctx.Arg(2)
		lEvent := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSAAsyncSelect sock=0x%x hwnd=0x%x msg=0x%x event=0x%x\n", s, hWnd, wMsg, lEvent)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACancelAsyncRequest", func(ctx *ntapi.TrapContext) uint32 {
		hAsyncTaskHandle := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSACancelAsyncRequest handle=0x%x\n", hAsyncTaskHandle)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACancelBlockingCall", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ws2_32] WSACancelBlockingCall()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAConnect", func(ctx *ntapi.TrapContext) uint32 {
		s := ntapi.Handle(ctx.Arg(0))
		name := ctx.Arg(1)
		namelen := ctx.Arg(2)
		lpCallerData := ctx.Arg(3)
		lpCalleeData := ctx.Arg(4)
		lpSQOS := ctx.Arg(5)
		lpGQOS := ctx.Arg(6)
		ravelog.Logf("[ws2_32] WSAConnect sock=0x%x addr=0x%x len=%d\n", s, name, namelen)
		_ = lpCallerData
		_ = lpCalleeData
		_ = lpSQOS
		_ = lpGQOS
		sock := resolveSocket(ctx, s)
		if sock == nil {
			return 0
		}
		sa, err := makeSockaddr(name, namelen)
		if err != nil {
			return failSocket(ctx, err)
		}
		if err := syscall.Connect(sock.FD, sa); err != nil {
			if err == syscall.EINPROGRESS {
				wsaSetErr(ctx, wsaeInProgress)
				ctx.SetReturn(0)
				return 0
			}
			return failSocket(ctx, err)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSADuplicateSocketA", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		dwProcessId := ctx.Arg(1)
		lpProtocolInfo := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSADuplicateSocketA sock=0x%x pid=%d\n", s, dwProcessId)
		_ = lpProtocolInfo
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEnumNameSpaceProvidersA", func(ctx *ntapi.TrapContext) uint32 {
		lpdwBufferLength := ctx.Arg(0)
		lpnspBuffer := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAEnumNameSpaceProvidersA buflen=0x%x buf=0x%x\n", lpdwBufferLength, lpnspBuffer)
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0) // 0 providers
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEnumNameSpaceProvidersW", func(ctx *ntapi.TrapContext) uint32 {
		lpdwBufferLength := ctx.Arg(0)
		lpnspBuffer := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSAEnumNameSpaceProvidersW buflen=0x%x buf=0x%x\n", lpdwBufferLength, lpnspBuffer)
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0) // 0 providers
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEnumProtocolsA", func(ctx *ntapi.TrapContext) uint32 {
		lpiProtocols := ctx.Arg(0)
		lpProtocolBuffer := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAEnumProtocolsA protos=0x%x buf=0x%x\n", lpiProtocols, lpProtocolBuffer)
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0) // 0 protocols
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEnumProtocolsW", func(ctx *ntapi.TrapContext) uint32 {
		lpiProtocols := ctx.Arg(0)
		lpProtocolBuffer := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAEnumProtocolsW protos=0x%x buf=0x%x\n", lpiProtocols, lpProtocolBuffer)
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0) // 0 protocols
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetOverlappedResult", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		lpOverlapped := ctx.Arg(1)
		lpcbTransfer := ctx.Arg(2)
		fWait := ctx.Arg(3)
		lpdwFlags := ctx.Arg(4)
		ravelog.Logf("[ws2_32] WSAGetOverlappedResult sock=0x%x ovl=0x%x wait=%d\n", s, lpOverlapped, fWait)
		if lpcbTransfer != 0 {
			ctx.Mem.Write32(lpcbTransfer, 0)
		}
		if lpdwFlags != 0 {
			ctx.Mem.Write32(lpdwFlags, 0)
		}
		ctx.SetReturn(1) // TRUE
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetQOSByName", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		lpQOSName := ctx.Arg(1)
		lpQOS := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAGetQOSByName sock=0x%x\n", s)
		_ = lpQOSName
		_ = lpQOS
		ctx.SetReturn(0) // FALSE = not found
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetServiceClassInfoA", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpServiceClassId := ctx.Arg(1)
		lpdwBufSize := ctx.Arg(2)
		lpServiceClassInfo := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSAGetServiceClassInfoA\n")
		_ = lpProviderId
		_ = lpServiceClassId
		_ = lpServiceClassInfo
		if lpdwBufSize != 0 {
			ctx.Mem.Write32(lpdwBufSize, 0)
		}
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetServiceClassInfoW", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpServiceClassId := ctx.Arg(1)
		lpdwBufSize := ctx.Arg(2)
		lpServiceClassInfo := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSAGetServiceClassInfoW\n")
		_ = lpProviderId
		_ = lpServiceClassId
		_ = lpServiceClassInfo
		if lpdwBufSize != 0 {
			ctx.Mem.Write32(lpdwBufSize, 0)
		}
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetServiceClassNameByClassIdA", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceClassId := ctx.Arg(0)
		lpszServiceClassName := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAGetServiceClassNameByClassIdA\n")
		_ = lpServiceClassId
		_ = lpszServiceClassName
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAGetServiceClassNameByClassIdW", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceClassId := ctx.Arg(0)
		lpszServiceClassName := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAGetServiceClassNameByClassIdW\n")
		_ = lpServiceClassId
		_ = lpszServiceClassName
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAHtonl", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		hostlong := uint32(ctx.Arg(1))
		lpnetlong := ctx.Arg(2)
		_ = s
		result := (hostlong>>24)&0xFF | (hostlong>>8)&0xFF00 | (hostlong<<8)&0xFF0000 | (hostlong<<24)&0xFF000000
		if lpnetlong != 0 {
			ctx.Mem.Write32(lpnetlong, result)
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAHtons", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		hostshort := uint16(ctx.Arg(1))
		lpnetshort := ctx.Arg(2)
		_ = s
		result := (hostshort>>8)&0xFF | (hostshort<<8)&0xFF00
		if lpnetshort != 0 {
			ctx.Mem.Write16(lpnetshort, result)
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAInstallServiceClassA", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceClassInfo := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSAInstallServiceClassA info=0x%x\n", lpServiceClassInfo)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAInstallServiceClassW", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceClassInfo := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSAInstallServiceClassW info=0x%x\n", lpServiceClassInfo)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAIsBlocking", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ws2_32] WSAIsBlocking()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAJoinLeaf", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		name := ctx.Arg(1)
		namelen := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAJoinLeaf sock=0x%x addr=0x%x\n", s, name)
		_ = namelen
		ctx.SetReturn(0xFFFFFFFF) // INVALID_SOCKET
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSALookupServiceBeginA", func(ctx *ntapi.TrapContext) uint32 {
		lpqsRestrictions := ctx.Arg(0)
		dwControlFlags := ctx.Arg(1)
		lphLookup := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSALookupServiceBeginA restr=0x%x flags=0x%x\n", lpqsRestrictions, dwControlFlags)
		if lphLookup != 0 {
			ctx.Mem.Write64(lphLookup, 0xDEAD0001)
		} // fake handle
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSALookupServiceBeginW", func(ctx *ntapi.TrapContext) uint32 {
		lpqsRestrictions := ctx.Arg(0)
		dwControlFlags := ctx.Arg(1)
		lphLookup := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSALookupServiceBeginW restr=0x%x flags=0x%x\n", lpqsRestrictions, dwControlFlags)
		if lphLookup != 0 {
			ctx.Mem.Write64(lphLookup, 0xDEAD0001)
		} // fake handle
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSALookupServiceEnd", func(ctx *ntapi.TrapContext) uint32 {
		hLookup := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSALookupServiceEnd handle=0x%x\n", hLookup)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSALookupServiceNextA", func(ctx *ntapi.TrapContext) uint32 {
		hLookup := ctx.Arg(0)
		dwControlFlags := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		lpqsResults := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSALookupServiceNextA handle=0x%x flags=0x%x\n", hLookup, dwControlFlags)
		_ = lpqsResults
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		// WSASERVICE_NOT_FOUND = 10108
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSALookupServiceNextW", func(ctx *ntapi.TrapContext) uint32 {
		hLookup := ctx.Arg(0)
		dwControlFlags := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		lpqsResults := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSALookupServiceNextW handle=0x%x flags=0x%x\n", hLookup, dwControlFlags)
		_ = lpqsResults
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		// WSASERVICE_NOT_FOUND = 10108
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSANSPIoctl", func(ctx *ntapi.TrapContext) uint32 {
		hLookup := ctx.Arg(0)
		dwControlCode := ctx.Arg(1)
		lpvInBuffer := ctx.Arg(2)
		cbInBuffer := ctx.Arg(3)
		lpvOutBuffer := ctx.Arg(4)
		cbOutBuffer := ctx.Arg(5)
		ravelog.Logf("[ws2_32] WSANSPIoctl handle=0x%x code=0x%x\n", hLookup, dwControlCode)
		_ = lpvInBuffer
		_ = cbInBuffer
		_ = lpvOutBuffer
		_ = cbOutBuffer
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSANtohl", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		netlong := uint32(ctx.Arg(1))
		lphostlong := ctx.Arg(2)
		_ = s
		result := (netlong>>24)&0xFF | (netlong>>8)&0xFF00 | (netlong<<8)&0xFF0000 | (netlong<<24)&0xFF000000
		if lphostlong != 0 {
			ctx.Mem.Write32(lphostlong, result)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSANtohs", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		netshort := uint16(ctx.Arg(1))
		lphostshort := ctx.Arg(2)
		_ = s
		result := (netshort>>8)&0xFF | (netshort<<8)&0xFF00
		if lphostshort != 0 {
			ctx.Mem.Write16(lphostshort, result)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAProviderConfigChange", func(ctx *ntapi.TrapContext) uint32 {
		lpNotificationHandle := ctx.Arg(0)
		lpOverlapped := ctx.Arg(1)
		lpCompletionRoutine := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSAProviderConfigChange\n")
		_ = lpNotificationHandle
		_ = lpOverlapped
		_ = lpCompletionRoutine
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR (no provider changes)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSARecvDisconnect", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		lpInboundDisconnectData := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSARecvDisconnect sock=0x%x\n", s)
		_ = lpInboundDisconnectData
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSARecvFrom", func(ctx *ntapi.TrapContext) uint32 {
		s := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1)
		dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesRecvd := ctx.Arg(3)
		lpFlags := ctx.Arg(4)
		lpFrom := ctx.Arg(5)
		lpFromLen := ctx.Arg(6)
		lpOverlapped := ctx.Arg(7)
		lpCompletionRoutine := ctx.Arg(8)
		ravelog.Logf("[ws2_32] WSARecvFrom sock=0x%x bufs=%d\n", s, dwBufferCount)
		_ = lpOverlapped
		_ = lpCompletionRoutine
		sock := resolveSocket(ctx, s)
		if sock == nil {
			return 0
		}
		flags := 0
		if lpFlags != 0 {
			v, _ := mem.Read32(lpFlags)
			flags = int(v)
		}
		bufs, err := readWSABufs(lpBuffers, dwBufferCount)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		total := 0
		for _, buf := range bufs {
			total += int(buf.Len)
		}
		data := make([]byte, total)
		n, sa, err := syscall.Recvfrom(sock.FD, data, flags)
		if err != nil {
			return failSocket(ctx, err)
		}
		if _, err := scatterWSABufs(lpBuffers, dwBufferCount, data[:n]); err != nil {
			return failSocket(ctx, err)
		}
		if err := writeSockaddr(lpFrom, lpFromLen, sa); err != nil {
			return failSocket(ctx, err)
		}
		if lpNumberOfBytesRecvd != 0 {
			ctx.Mem.Write32(lpNumberOfBytesRecvd, uint32(n))
		}
		if lpFlags != 0 {
			ctx.Mem.Write32(lpFlags, 0)
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSARemoveServiceClass", func(ctx *ntapi.TrapContext) uint32 {
		lpServiceClassId := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSARemoveServiceClass id=0x%x\n", lpServiceClassId)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASendDisconnect", func(ctx *ntapi.TrapContext) uint32 {
		s := ctx.Arg(0)
		lpOutboundDisconnectData := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSASendDisconnect sock=0x%x\n", s)
		_ = lpOutboundDisconnectData
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASendTo", func(ctx *ntapi.TrapContext) uint32 {
		s := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1)
		dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesSent := ctx.Arg(3)
		dwFlags := ctx.Arg(4)
		lpTo := ctx.Arg(5)
		iToLen := ctx.Arg(6)
		lpOverlapped := ctx.Arg(7)
		lpCompletionRoutine := ctx.Arg(8)
		ravelog.Logf("[ws2_32] WSASendTo sock=0x%x bufs=%d flags=0x%x\n", s, dwBufferCount, dwFlags)
		_ = lpOverlapped
		_ = lpCompletionRoutine
		sock := resolveSocket(ctx, s)
		if sock == nil {
			return 0
		}
		data, err := gatherWSABufs(lpBuffers, dwBufferCount)
		if err != nil {
			return failSocket(ctx, syscall.EFAULT)
		}
		var sa syscall.Sockaddr
		if lpTo != 0 {
			sa, err = makeSockaddr(lpTo, iToLen)
			if err != nil {
				return failSocket(ctx, err)
			}
		}
		n, err := syscall.SendmsgN(sock.FD, data, nil, sa, int(dwFlags))
		if err != nil {
			return failSocket(ctx, err)
		}
		if lpNumberOfBytesSent != 0 {
			ctx.Mem.Write32(lpNumberOfBytesSent, uint32(n))
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetBlockingHook", func(ctx *ntapi.TrapContext) uint32 {
		lpBlockFunc := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSASetBlockingHook func=0x%x\n", lpBlockFunc)
		ctx.SetReturn(lpBlockFunc) // return previous hook (same function)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetServiceA", func(ctx *ntapi.TrapContext) uint32 {
		lpqsRegInfo := ctx.Arg(0)
		essOperation := ctx.Arg(1)
		dwControlFlags := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSASetServiceA op=%d flags=0x%x\n", essOperation, dwControlFlags)
		_ = lpqsRegInfo
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetServiceW", func(ctx *ntapi.TrapContext) uint32 {
		lpqsRegInfo := ctx.Arg(0)
		essOperation := ctx.Arg(1)
		dwControlFlags := ctx.Arg(2)
		ravelog.Logf("[ws2_32] WSASetServiceW op=%d flags=0x%x\n", essOperation, dwControlFlags)
		_ = lpqsRegInfo
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAStringToAddressA", func(ctx *ntapi.TrapContext) uint32 {
		AddressString := ctx.Arg(0)
		AddressFamily := ctx.Arg(1)
		lpProtocolInfo := ctx.Arg(2)
		lpAddress := ctx.Arg(3)
		lpAddressLength := ctx.Arg(4)
		_ = lpProtocolInfo
		var addrStr string
		if AddressString != 0 {
			addrStr = readGuestString(AddressString)
		}
		ravelog.Logf("[ws2_32] WSAStringToAddressA str=%q af=%d\n", addrStr, AddressFamily)
		_ = lpAddress
		if lpAddressLength != 0 {
			ctx.Mem.Write32(lpAddressLength, 16)
		} // sizeof(sockaddr_in)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAStringToAddressW", func(ctx *ntapi.TrapContext) uint32 {
		AddressString := ctx.Arg(0)
		AddressFamily := ctx.Arg(1)
		lpProtocolInfo := ctx.Arg(2)
		lpAddress := ctx.Arg(3)
		lpAddressLength := ctx.Arg(4)
		_ = lpProtocolInfo
		var addrStr string
		if AddressString != 0 {
			addrStr = readGuestString(AddressString)
		}
		ravelog.Logf("[ws2_32] WSAStringToAddressW str=%q af=%d\n", addrStr, AddressFamily)
		_ = lpAddress
		if lpAddressLength != 0 {
			ctx.Mem.Write32(lpAddressLength, 16)
		} // sizeof(sockaddr_in)
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAUnhookBlockingHook", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[ws2_32] WSAUnhookBlockingHook()\n")
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSApSetPostRoutine", func(ctx *ntapi.TrapContext) uint32 {
		lpPostRoutine := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSApSetPostRoutine routine=0x%x\n", lpPostRoutine)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCDeinstallProvider", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpErrno := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSCDeinstallProvider id=0x%x\n", lpProviderId)
		if lpErrno != 0 {
			ctx.Mem.Write32(lpErrno, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCEnableNSProvider", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		fEnable := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSCEnableNSProvider id=0x%x enable=%d\n", lpProviderId, fEnable)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCEnumProtocols", func(ctx *ntapi.TrapContext) uint32 {
		lpiProtocols := ctx.Arg(0)
		lpProtocolBuffer := ctx.Arg(1)
		lpdwBufferLength := ctx.Arg(2)
		lpErrno := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSCEnumProtocols protos=0x%x buf=0x%x\n", lpiProtocols, lpProtocolBuffer)
		if lpdwBufferLength != 0 {
			ctx.Mem.Write32(lpdwBufferLength, 0)
		}
		if lpErrno != 0 {
			ctx.Mem.Write32(lpErrno, 0)
		}
		ctx.SetReturn(0) // 0 protocols
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCGetProviderPath", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpszProviderDllPath := ctx.Arg(1)
		lpProviderDllPathLen := ctx.Arg(2)
		lpErrno := ctx.Arg(3)
		ravelog.Logf("[ws2_32] WSCGetProviderPath id=0x%x\n", lpProviderId)
		_ = lpszProviderDllPath
		if lpProviderDllPathLen != 0 {
			ctx.Mem.Write32(lpProviderDllPathLen, 0)
		}
		if lpErrno != 0 {
			ctx.Mem.Write32(lpErrno, 0)
		}
		ctx.SetReturn(0xFFFFFFFF) // SOCKET_ERROR
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCInstallNameSpace", func(ctx *ntapi.TrapContext) uint32 {
		lpszIdentifier := ctx.Arg(0)
		lpszPathName := ctx.Arg(1)
		dwNameSpace := ctx.Arg(2)
		dwVersion := ctx.Arg(3)
		lpProviderId := ctx.Arg(4)
		ravelog.Logf("[ws2_32] WSCInstallNameSpace ns=%d ver=%d\n", dwNameSpace, dwVersion)
		_ = lpszIdentifier
		_ = lpszPathName
		_ = lpProviderId
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCInstallProvider", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpszProviderDllPath := ctx.Arg(1)
		lpProtocolInfoList := ctx.Arg(2)
		dwNumberOfEntries := ctx.Arg(3)
		lpErrno := ctx.Arg(4)
		ravelog.Logf("[ws2_32] WSCInstallProvider entries=%d\n", dwNumberOfEntries)
		_ = lpProviderId
		_ = lpszProviderDllPath
		_ = lpProtocolInfoList
		if lpErrno != 0 {
			ctx.Mem.Write32(lpErrno, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCUnInstallNameSpace", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		ravelog.Logf("[ws2_32] WSCUnInstallNameSpace id=0x%x\n", lpProviderId)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCUpdateProvider", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		lpszProviderDllPath := ctx.Arg(1)
		lpProtocolInfoList := ctx.Arg(2)
		dwNumberOfEntries := ctx.Arg(3)
		lpErrno := ctx.Arg(4)
		ravelog.Logf("[ws2_32] WSCUpdateProvider entries=%d\n", dwNumberOfEntries)
		_ = lpProviderId
		_ = lpszProviderDllPath
		_ = lpProtocolInfoList
		if lpErrno != 0 {
			ctx.Mem.Write32(lpErrno, 0)
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCWriteNameSpaceOrder", func(ctx *ntapi.TrapContext) uint32 {
		lpProviderId := ctx.Arg(0)
		dwNumberOfEntries := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSCWriteNameSpaceOrder entries=%d\n", dwNumberOfEntries)
		_ = lpProviderId
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSCWriteProviderOrder", func(ctx *ntapi.TrapContext) uint32 {
		lpwdCatalogEntryId := ctx.Arg(0)
		dwNumberOfEntries := ctx.Arg(1)
		ravelog.Logf("[ws2_32] WSCWriteProviderOrder entries=%d\n", dwNumberOfEntries)
		_ = lpwdCatalogEntryId
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "__WSAFDIsSet", func(ctx *ntapi.TrapContext) uint32 {
		fd := ctx.Arg(0)
		set := ctx.Arg(1)
		ravelog.Logf("[ws2_32] __WSAFDIsSet fd=0x%x set=0x%x\n", fd, set)
		if set == 0 {
			ctx.SetReturn(0)
			return 0
		}
		// fd_set: fd_count(4) + fd_array[FD_SETSIZE](8 each)
		count, _ := ctx.Mem.Read32(set)
		for i := uint32(0); i < count && i < 64; i++ {
			sock, _ := ctx.Mem.Read64(set + 4 + uint64(i*8))
			if sock == fd {
				ctx.SetReturn(1)
				return 0
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "gethostbyaddr", func(ctx *ntapi.TrapContext) uint32 {
		addr := ctx.Arg(0)
		len_ := ctx.Arg(1)
		type_ := ctx.Arg(2)
		ravelog.Logf("[ws2_32] gethostbyaddr addr=0x%x len=%d type=%d\n", addr, len_, type_)
		ctx.SetReturn(0) // NULL = not found
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getnameinfo", func(ctx *ntapi.TrapContext) uint32 {
		pSockaddr := ctx.Arg(0)
		SockaddrLength := ctx.Arg(1)
		pNodeBuffer := ctx.Arg(2)
		NodeBufferSize := ctx.Arg(3)
		pServiceBuffer := ctx.Arg(4)
		ServiceBufferSize := ctx.Arg(5)
		ravelog.Logf("[ws2_32] getnameinfo addr=0x%x\n", pSockaddr)
		_ = SockaddrLength
		_ = NodeBufferSize
		_ = ServiceBufferSize
		if pNodeBuffer != 0 {
			ctx.Mem.Write8(pNodeBuffer, 0)
		}
		if pServiceBuffer != 0 {
			ctx.Mem.Write8(pServiceBuffer, 0)
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getprotobyname", func(ctx *ntapi.TrapContext) uint32 {
		name := ctx.Arg(0)
		var protoName string
		if name != 0 {
			protoName = readGuestString(name)
		}
		ravelog.Logf("[ws2_32] getprotobyname name=%q\n", protoName)
		// Return a static protoent in guest memory
		buf := sharedHeapAlloc(32, true)
		var protoNum uint32
		switch protoName {
		case "tcp":
			protoNum = 6
		case "udp":
			protoNum = 17
		case "icmp":
			protoNum = 1
		default:
			protoNum = 0
		}
		// protoent: p_name(8), p_aliases(8), p_proto(4)
		ctx.Mem.Write64(buf, 0)   // p_name = NULL for now
		ctx.Mem.Write64(buf+8, 0) // p_aliases = NULL
		ctx.Mem.Write32(buf+16, protoNum)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getprotobynumber", func(ctx *ntapi.TrapContext) uint32 {
		proto := ctx.Arg(0)
		ravelog.Logf("[ws2_32] getprotobynumber proto=%d\n", proto)
		buf := sharedHeapAlloc(32, true)
		ctx.Mem.Write64(buf, 0)
		ctx.Mem.Write64(buf+8, 0)
		ctx.Mem.Write32(buf+16, uint32(proto))
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getservbyname", func(ctx *ntapi.TrapContext) uint32 {
		name := ctx.Arg(0)
		proto := ctx.Arg(1)
		var svcName, protoName string
		if name != 0 {
			svcName = readGuestString(name)
		}
		if proto != 0 {
			protoName = readGuestString(proto)
		}
		ravelog.Logf("[ws2_32] getservbyname name=%q proto=%q\n", svcName, protoName)
		// servent: s_name(8), s_aliases(8), s_port(4), s_proto(8)
		buf := sharedHeapAlloc(32, true)
		var port uint16
		switch svcName {
		case "http":
			port = 80
		case "https":
			port = 443
		case "ftp":
			port = 21
		case "ssh":
			port = 22
		case "smtp":
			port = 25
		default:
			ctx.SetReturn(0)
			return 0 // not found
		}
		port = (port>>8)&0xFF | (port<<8)&0xFF00 // htons
		ctx.Mem.Write16(buf+16, port)            // s_port (network byte order)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getservbyport", func(ctx *ntapi.TrapContext) uint32 {
		port := ctx.Arg(0)
		proto := ctx.Arg(1)
		ravelog.Logf("[ws2_32] getservbyport port=%d proto=0x%x\n", port, proto)
		ctx.SetReturn(0) // not found
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAPoll", func(ctx *ntapi.TrapContext) uint32 {
		fdArray := ctx.Arg(0)
		fds := ctx.Arg(1)
		timeout := int(ctx.Arg(2))
		if fds == 0 {
			ctx.SetReturn(0)
			return 0
		}
		pollFDs := make([]unix.PollFd, 0, fds)
		handleIdx := make([]int, 0, fds)
		for i := uint64(0); i < fds; i++ {
			off := fdArray + i*wsapollfdSize
			h, _ := mem.Read64(off)
			events, _ := mem.Read16(off + 8)
			mem.Write16(off+10, 0)
			s := handles.GetSocket(ntapi.Handle(h))
			if s == nil {
				mem.Write16(off+10, uint16(winPollNVal))
				continue
			}
			pollFDs = append(pollFDs, unix.PollFd{
				Fd:     int32(s.FD),
				Events: translateWinPollEvents(int16(events)),
			})
			handleIdx = append(handleIdx, int(i))
		}
		if len(pollFDs) == 0 {
			if timeout > 0 {
				time.Sleep(time.Duration(timeout) * time.Millisecond)
			}
			ctx.SetReturn(0)
			return 0
		}
		n, err := unix.Poll(pollFDs, timeout)
		if err != nil {
			return failSocket(ctx, err)
		}
		ready := 0
		for i, pfd := range pollFDs {
			off := fdArray + uint64(handleIdx[i])*wsapollfdSize
			revents := translateLinuxPollRevents(pfd.Revents)
			mem.Write16(off+10, uint16(revents))
			if revents != 0 {
				ready++
			}
		}
		wsaSetErr(ctx, 0)
		if n > ready {
			ready = n
		}
		ctx.SetReturn(uint64(ready))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "htonl", func(ctx *ntapi.TrapContext) uint32 {
		val := uint32(ctx.Arg(0))
		result := uint64(hostToNet32(val))
		ctx.SetReturn(result)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "htons", func(ctx *ntapi.TrapContext) uint32 {
		val := uint16(ctx.Arg(0))
		result := uint64(hostToNet16(val))
		ctx.SetReturn(result)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "inet_ntop", func(ctx *ntapi.TrapContext) uint32 {
		family := uint16(ctx.Arg(0))
		src := ctx.Arg(1)
		dst := ctx.Arg(2)
		size := int(ctx.Arg(3))
		if src == 0 || dst == 0 || size <= 0 {
			wsaSetErr(ctx, wsaeFault)
			ctx.SetReturn(0)
			return 0
		}
		var text string
		switch family {
		case winAFInet:
			data, err := mem.ReadBytes(src, 4)
			if err != nil {
				wsaSetErr(ctx, wsaeFault)
				ctx.SetReturn(0)
				return 0
			}
			text = net.IP(data).String()
		case winAFInet6:
			data, err := mem.ReadBytes(src, 16)
			if err != nil {
				wsaSetErr(ctx, wsaeFault)
				ctx.SetReturn(0)
				return 0
			}
			text = net.IP(data).String()
		default:
			wsaSetErr(ctx, wsaeAfNoSupport)
			ctx.SetReturn(0)
			return 0
		}
		if len(text)+1 > size {
			wsaSetErr(ctx, wsaeFault)
			ctx.SetReturn(0)
			return 0
		}
		mem.WriteBytes(dst, append([]byte(text), 0))
		wsaSetErr(ctx, 0)
		ctx.SetReturn(dst)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "inet_pton", func(ctx *ntapi.TrapContext) uint32 {
		family := uint16(ctx.Arg(0))
		src := ctx.Arg(1)
		dst := ctx.Arg(2)
		if src == 0 || dst == 0 {
			wsaSetErr(ctx, wsaeFault)
			ctx.SetReturn(0)
			return 0
		}
		ip := net.ParseIP(strings.TrimSpace(readGuestString(src)))
		if ip == nil {
			wsaSetErr(ctx, 0)
			ctx.SetReturn(0)
			return 0
		}
		switch family {
		case winAFInet:
			ip4 := ip.To4()
			if ip4 == nil {
				wsaSetErr(ctx, 0)
				ctx.SetReturn(0)
				return 0
			}
			mem.WriteBytes(dst, ip4)
		case winAFInet6:
			ip6 := ip.To16()
			if ip6 == nil {
				wsaSetErr(ctx, 0)
				ctx.SetReturn(0)
				return 0
			}
			mem.WriteBytes(dst, ip6)
		default:
			wsaSetErr(ctx, wsaeAfNoSupport)
			ctx.SetReturn(^uint64(0))
			return 0
		}
		wsaSetErr(ctx, 0)
		ctx.SetReturn(1)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "inet_addr", func(ctx *ntapi.TrapContext) uint32 {
		cp := ctx.Arg(0)
		if cp == 0 {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		} // INADDR_NONE
		ip4 := net.ParseIP(strings.TrimSpace(readGuestString(cp))).To4()
		if ip4 == nil {
			ctx.SetReturn(0xFFFFFFFF)
			return 0
		}
		ctx.SetReturn(uint64(uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "inet_ntoa", func(ctx *ntapi.TrapContext) uint32 {
		inAddr := uint32(ctx.Arg(0))
		a := inAddr & 0xFF
		b := (inAddr >> 8) & 0xFF
		c := (inAddr >> 16) & 0xFF
		d := (inAddr >> 24) & 0xFF
		ips := fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
		buf := sharedHeapAlloc(uint64(len(ips)+1), true)
		for i := 0; i < len(ips); i++ {
			ctx.Mem.Write8(buf+uint64(i), ips[i])
		}
		ctx.Mem.Write8(buf+uint64(len(ips)), 0)
		ctx.SetReturn(buf)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "ntohl", func(ctx *ntapi.TrapContext) uint32 {
		val := uint32(ctx.Arg(0))
		result := uint64(netToHost32(val))
		ctx.SetReturn(result)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "ntohs", func(ctx *ntapi.TrapContext) uint32 {
		val := uint16(ctx.Arg(0))
		result := uint64(netToHost16(val))
		ctx.SetReturn(result)
		return 0
	})
}
