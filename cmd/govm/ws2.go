package main

import (
	"net"
	"os"
	"syscall"

	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func registerWs2Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	handles := hctx.Handles
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16

	ws2, ok := hctx.SynthByName["ws2_32.dll"]
	if !ok {
		return
	}
	_ = ws2

	// getaddrinfo: return EAI_NONAME (no DNS resolution in emulator)
	d.RegisterAutoStubHandler(ws2, "getaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
		ppResult := ctx.Arg(3)
		if ppResult != 0 {
			ctx.Mem.Write64(ppResult, 0)
		}
		ctx.SetReturn(11) // EAI_NONAME (WSAHOST_NOT_FOUND)
		return 0
	})
	// freeaddrinfo: no-op (we never allocate addrinfo structs)
	d.RegisterAutoStubHandler(ws2, "freeaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})
	// WSAStartup: pretend Winsock 2.2 is available
	d.RegisterAutoStubHandler(ws2, "WSAStartup", func(ctx *ntapi.TrapContext) uint32 {
		lpWSAData := ctx.Arg(1)
		if lpWSAData != 0 {
			// WSADATA: first two WORDs are wVersion and wHighVersion
			ctx.Mem.Write16(lpWSAData+0, 0x0202) // version 2.2
			ctx.Mem.Write16(lpWSAData+2, 0x0202) // high version 2.2
		}
		ctx.SetReturn(0) // success
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSACleanup", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	// Winsock socket creation / management
	// Windows AF constants that differ from Linux:
	winAfToLinux := func(af uint16) int {
		switch af {
		case 2:
			return syscall.AF_INET // AF_INET
		case 23:
			return syscall.AF_INET6 // AF_INET6 (Win=23, Linux=10)
		case 1:
			return syscall.AF_UNIX // AF_UNIX
		default:
			return int(af)
		}
	}
	wsaSetErr := func(e int32) {
		// Store WSALASTERROR in the fake TLS
		_ = e
	}
	_ = wsaSetErr

	d.RegisterAutoStubHandler(ws2, "socket", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			ctx.SetReturn(^uint64(0)) // INVALID_SOCKET
			return 0
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASocketW", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASocketA", func(ctx *ntapi.TrapContext) uint32 {
		af := winAfToLinux(uint16(ctx.Arg(0)))
		sockType := int(ctx.Arg(1))
		proto := int(ctx.Arg(2))
		fd, err := syscall.Socket(af, sockType, proto)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		h := handles.Alloc(ntapi.NewSocketHandle(fd, af, sockType, proto))
		ctx.SetReturn(uint64(h))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "closesocket", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		if s := handles.GetSocket(h); s != nil {
			syscall.Close(s.FD)
			handles.Close(h)
		}
		ctx.SetReturn(0)
		return 0
	})

	// Build a Linux sockaddr from Win32 sockaddr_in/in6 at guestAddr
	makeSockaddr := func(guestAddr uint64) (syscall.Sockaddr, bool) {
		if guestAddr == 0 {
			return nil, false
		}
		family, _ := mem.Read16(guestAddr)
		switch family {
		case 2: // AF_INET
			port, _ := mem.Read16(guestAddr + 2)
			a0, _ := mem.Read8(guestAddr + 4)
			a1, _ := mem.Read8(guestAddr + 5)
			a2, _ := mem.Read8(guestAddr + 6)
			a3, _ := mem.Read8(guestAddr + 7)
			return &syscall.SockaddrInet4{
				Port: int(port>>8 | port<<8), // big-endian port
				Addr: [4]byte{a0, a1, a2, a3},
			}, true
		case 23, 10: // AF_INET6
			port, _ := mem.Read16(guestAddr + 2)
			var addr [16]byte
			for i := 0; i < 16; i++ {
				b, _ := mem.Read8(guestAddr + 8 + uint64(i))
				addr[i] = b
			}
			scopeId, _ := mem.Read32(guestAddr + 24)
			return &syscall.SockaddrInet6{
				Port:   int(port>>8 | port<<8),
				Addr:   addr,
				ZoneId: scopeId,
			}, true
		}
		return nil, false
	}

	// Write sockaddr back to guest memory
	writeSockaddr := func(guestAddr uint64, guestLen *uint64, sa syscall.Sockaddr) {
		if guestAddr == 0 {
			return
		}
		switch s := sa.(type) {
		case *syscall.SockaddrInet4:
			port := uint16(s.Port>>8 | s.Port<<8)
			mem.Write16(guestAddr, 2) // AF_INET
			mem.Write16(guestAddr+2, port)
			mem.Write8(guestAddr+4, s.Addr[0])
			mem.Write8(guestAddr+5, s.Addr[1])
			mem.Write8(guestAddr+6, s.Addr[2])
			mem.Write8(guestAddr+7, s.Addr[3])
			if guestLen != nil {
				*guestLen = 16
			}
		case *syscall.SockaddrInet6:
			port := uint16(s.Port>>8 | s.Port<<8)
			mem.Write16(guestAddr, 23) // AF_INET6 (Windows)
			mem.Write16(guestAddr+2, port)
			for i, b := range s.Addr {
				mem.Write8(guestAddr+8+uint64(i), b)
			}
			if guestLen != nil {
				*guestLen = 28
			}
		}
	}

	d.RegisterAutoStubHandler(ws2, "bind", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		sa, ok := makeSockaddr(addrPtr)
		if !ok {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		err := syscall.Bind(s.FD, sa)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "connect", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		sa, ok := makeSockaddr(addrPtr)
		if !ok {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		err := syscall.Connect(s.FD, sa)
		if err != nil && err != syscall.EINPROGRESS {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "listen", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		backlog := int(ctx.Arg(1))
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if err := syscall.Listen(s.FD, backlog); err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "accept", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		fd, sa, err := syscall.Accept(s.FD)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if addrPtr != 0 {
			var l uint64
			writeSockaddr(addrPtr, &l, sa)
			if addrLen != 0 {
				mem.Write32(addrLen, uint32(l))
			}
		}
		newH := handles.Alloc(ntapi.NewSocketHandle(fd, s.Family, s.SockType, s.Proto))
		ctx.SetReturn(uint64(newH))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "send", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		// flags := ctx.Arg(3)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		data, _ := mem.ReadBytes(lpBuf, nLen)
		n, err := syscall.Write(s.FD, data)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "recv", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		// flags := ctx.Arg(3)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		data := make([]byte, nLen)
		n, err := syscall.Read(s.FD, data)
		if err != nil || n < 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		mem.WriteBytes(lpBuf, data[:n])
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "sendto", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		// flags := ctx.Arg(3)
		addrPtr := ctx.Arg(4)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		data, _ := mem.ReadBytes(lpBuf, nLen)
		if sa, ok := makeSockaddr(addrPtr); ok {
			err := syscall.Sendto(s.FD, data, 0, sa)
			if err != nil {
				ctx.SetReturn(^uint64(0))
				return 0
			}
		}
		ctx.SetReturn(uint64(nLen))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "recvfrom", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuf := ctx.Arg(1)
		nLen := int(ctx.Arg(2))
		// flags := ctx.Arg(3)
		fromPtr := ctx.Arg(4)
		fromLen := ctx.Arg(5)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		data := make([]byte, nLen)
		n, sa, err := syscall.Recvfrom(s.FD, data, 0)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		mem.WriteBytes(lpBuf, data[:n])
		if fromPtr != 0 {
			var l uint64
			writeSockaddr(fromPtr, &l, sa)
			if fromLen != 0 {
				mem.Write32(fromLen, uint32(l))
			}
		}
		ctx.SetReturn(uint64(n))
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "shutdown", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		how := int(ctx.Arg(1)) // SD_RECEIVE=0, SD_SEND=1, SD_BOTH=2
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		syscall.Shutdown(s.FD, how)
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "setsockopt", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		level := int(ctx.Arg(1))
		optName := int(ctx.Arg(2))
		optVal := ctx.Arg(3)
		optLen := int(ctx.Arg(4))
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		data, _ := mem.ReadBytes(optVal, optLen)
		// Map Win32 SOL_SOCKET=0xFFFF → Linux SOL_SOCKET=1
		if level == 0xFFFF {
			level = syscall.SOL_SOCKET
		}
		syscall.SetsockoptByte(s.FD, level, optName, data[0])
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getsockopt", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		level := int(ctx.Arg(1))
		optName := int(ctx.Arg(2))
		optVal := ctx.Arg(3)
		optLen := ctx.Arg(4)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if level == 0xFFFF {
			level = syscall.SOL_SOCKET
		}
		_ = optName
		_ = level
		if optVal != 0 && optLen != 0 {
			n, _ := mem.Read32(optLen)
			for i := uint64(0); i < uint64(n); i++ {
				mem.Write8(optVal+i, 0)
			}
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getsockname", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		sa, err := syscall.Getsockname(s.FD)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		var l uint64
		writeSockaddr(addrPtr, &l, sa)
		if addrLen != 0 {
			mem.Write32(addrLen, uint32(l))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "getpeername", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		addrPtr := ctx.Arg(1)
		addrLen := ctx.Arg(2)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		sa, err := syscall.Getpeername(s.FD)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		var l uint64
		writeSockaddr(addrPtr, &l, sa)
		if addrLen != 0 {
			mem.Write32(addrLen, uint32(l))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "ioctlsocket", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		cmd := uint32(ctx.Arg(1))
		argPtr := ctx.Arg(2)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		const FIONBIO = 0x8004667e // FIONBIO Win32
		if cmd == FIONBIO && argPtr != 0 {
			v, _ := mem.Read32(argPtr)
			mode := 0
			if v != 0 {
				mode = 1
			}
			syscall.SetNonblock(s.FD, mode != 0)
		}
		ctx.SetReturn(0)
		return 0
	})

	// WSASend / WSARecv - simplified (single buffer, no overlapped)
	d.RegisterAutoStubHandler(ws2, "WSASend", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1) // LPWSABUF: {len ULONG, buf CHAR*}
		// dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesSent := ctx.Arg(3)
		// dwFlags := ctx.Arg(4)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		bufLen, _ := mem.Read32(lpBuffers)
		bufPtr, _ := mem.Read64(lpBuffers + 4)
		data, _ := mem.ReadBytes(bufPtr, int(bufLen))
		n, err := syscall.Write(s.FD, data)
		if err != nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		if lpNumberOfBytesSent != 0 {
			mem.Write32(lpNumberOfBytesSent, uint32(n))
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSARecv", func(ctx *ntapi.TrapContext) uint32 {
		h := ntapi.Handle(ctx.Arg(0))
		lpBuffers := ctx.Arg(1)
		// dwBufferCount := ctx.Arg(2)
		lpNumberOfBytesRecvd := ctx.Arg(3)
		// lpFlags := ctx.Arg(4)
		s := handles.GetSocket(h)
		if s == nil {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		bufLen, _ := mem.Read32(lpBuffers)
		bufPtr, _ := mem.Read64(lpBuffers + 4)
		data := make([]byte, bufLen)
		n, err := syscall.Read(s.FD, data)
		if err != nil || n < 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		mem.WriteBytes(bufPtr, data[:n])
		if lpNumberOfBytesRecvd != 0 {
			mem.Write32(lpNumberOfBytesRecvd, uint32(n))
		}
		ctx.SetReturn(0)
		return 0
	})

	// WSAGetLastError
	d.RegisterAutoStubHandler(ws2, "WSAGetLastError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSASetLastError", func(ctx *ntapi.TrapContext) uint32 {
		return 0
	})

	// gethostname
	d.RegisterAutoStubHandler(ws2, "gethostname", func(ctx *ntapi.TrapContext) uint32 {
		buf := ctx.Arg(0)
		n := int(ctx.Arg(1))
		name, err := os.Hostname()
		if err != nil || n == 0 {
			ctx.SetReturn(^uint64(0))
			return 0
		}
		b := []byte(name)
		if len(b)+1 > n {
			b = b[:n-1]
		}
		mem.WriteBytes(buf, append(b, 0))
		ctx.SetReturn(0)
		return 0
	})

	// Real getaddrinfo using net.DefaultResolver
	d.RegisterAutoStubHandler(ws2, "getaddrinfo", func(ctx *ntapi.TrapContext) uint32 {
		nodePtr := ctx.Arg(0)
		// servicePtr := ctx.Arg(1)
		// hintsPtr := ctx.Arg(2)
		ppResult := ctx.Arg(3)
		if ppResult == 0 {
			ctx.SetReturn(11)
			return 0
		}
		node := ""
		if nodePtr != 0 {
			node = readGuestString(nodePtr)
		}
		if node == "" {
			ctx.SetReturn(11)
			return 0
		}
		addrs, err := net.LookupHost(node)
		if err != nil || len(addrs) == 0 {
			mem.Write64(ppResult, 0)
			ctx.SetReturn(11) // WSAHOST_NOT_FOUND
			return 0
		}
		// Build addrinfo chain in guest memory
		// addrinfo: ai_flags(4)+ai_family(4)+ai_socktype(4)+ai_protocol(4)+ai_addrlen(8)+ai_canonname(8)+ai_addr(8)+ai_next(8) = 48 bytes
		var prevNext uint64
		var firstAddr uint64
		for i := len(addrs) - 1; i >= 0; i-- {
			ip := net.ParseIP(addrs[i])
			if ip == nil {
				continue
			}
			var addrSize uint64
			var addrBlock uint64
			ip4 := ip.To4()
			family := uint32(2) // AF_INET
			if ip4 != nil {
				addrSize = 16
				addrBlock = mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, 2) // AF_INET
				port := uint16(0)
				mem.Write16(addrBlock+2, port)
				mem.Write8(addrBlock+4, ip4[0])
				mem.Write8(addrBlock+5, ip4[1])
				mem.Write8(addrBlock+6, ip4[2])
				mem.Write8(addrBlock+7, ip4[3])
			} else {
				ip6 := ip.To16()
				if ip6 == nil {
					continue
				}
				family = 23 // AF_INET6 (Windows)
				addrSize = 28
				addrBlock = mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, 23)
				mem.Write16(addrBlock+2, 0)
				for j := 0; j < 16; j++ {
					mem.Write8(addrBlock+8+uint64(j), ip6[j])
				}
			}
			aiBlock := mem.Mmap(0, 48, mmu.PermRead|mmu.PermWrite)
			mem.Write32(aiBlock, 0)            // ai_flags
			mem.Write32(aiBlock+4, family)     // ai_family
			mem.Write32(aiBlock+8, 1)          // ai_socktype = SOCK_STREAM
			mem.Write32(aiBlock+12, 6)         // ai_protocol = IPPROTO_TCP
			mem.Write64(aiBlock+16, addrSize)  // ai_addrlen
			mem.Write64(aiBlock+24, 0)         // ai_canonname
			mem.Write64(aiBlock+32, addrBlock) // ai_addr
			mem.Write64(aiBlock+40, prevNext)  // ai_next
			prevNext = aiBlock
			if firstAddr == 0 {
				firstAddr = aiBlock
			}
			firstAddr = aiBlock
		}
		mem.Write64(ppResult, firstAddr)
		if firstAddr == 0 {
			ctx.SetReturn(11)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "GetAddrInfoW", func(ctx *ntapi.TrapContext) uint32 {
		nodePtr := ctx.Arg(0)
		ppResult := ctx.Arg(3)
		if ppResult == 0 {
			ctx.SetReturn(11)
			return 0
		}
		node := ""
		if nodePtr != 0 {
			node = readGuestUTF16(nodePtr)
		}
		if node == "" {
			ctx.SetReturn(11)
			return 0
		}
		addrs, err := net.LookupHost(node)
		if err != nil || len(addrs) == 0 {
			mem.Write64(ppResult, 0)
			ctx.SetReturn(11)
			return 0
		}
		var firstAddr uint64
		var prevNext uint64
		for i := len(addrs) - 1; i >= 0; i-- {
			ip := net.ParseIP(addrs[i])
			if ip == nil {
				continue
			}
			var addrBlock uint64
			var addrSize uint64
			family := uint32(2)
			if ip4 := ip.To4(); ip4 != nil {
				addrSize = 16
				addrBlock = mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, 2)
				mem.Write8(addrBlock+4, ip4[0])
				mem.Write8(addrBlock+5, ip4[1])
				mem.Write8(addrBlock+6, ip4[2])
				mem.Write8(addrBlock+7, ip4[3])
			} else if ip6 := ip.To16(); ip6 != nil {
				family = 23
				addrSize = 28
				addrBlock = mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
				mem.Write16(addrBlock, 23)
				for j := 0; j < 16; j++ {
					mem.Write8(addrBlock+8+uint64(j), ip6[j])
				}
			} else {
				continue
			}
			aiBlock := mem.Mmap(0, 48, mmu.PermRead|mmu.PermWrite)
			mem.Write32(aiBlock, 0)
			mem.Write32(aiBlock+4, family)
			mem.Write32(aiBlock+8, 1)
			mem.Write32(aiBlock+12, 6)
			mem.Write64(aiBlock+16, addrSize)
			mem.Write64(aiBlock+24, 0)
			mem.Write64(aiBlock+32, addrBlock)
			mem.Write64(aiBlock+40, prevNext)
			prevNext = aiBlock
			firstAddr = aiBlock
		}
		mem.Write64(ppResult, firstAddr)
		if firstAddr == 0 {
			ctx.SetReturn(11)
			return 0
		}
		ctx.SetReturn(0)
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
		ctx.SetReturn(0)
		return 0
	})
	d.RegisterAutoStubHandler(ws2, "WSAEventSelect", func(ctx *ntapi.TrapContext) uint32 {
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
		// Basic select: just check if fds have data (non-blocking scan)
		// nfds ignored for Winsock
		// readfds := ctx.Arg(1)
		// writefds := ctx.Arg(2)
		// exceptfds := ctx.Arg(3)
		// timeout := ctx.Arg(4)
		ctx.SetReturn(0) // 0 = timeout (no sockets ready)
		return 0
	})
}
