package vfs

import (
	"fmt"
	"net"
	"os"
	"sync"
)

// SocketFD wraps a real host AF_UNIX connection behind a guest FD.
type SocketFD struct {
	mu       sync.Mutex
	Domain   int // AF_UNIX = 1
	SockType int // SOCK_STREAM = 1, SOCK_DGRAM = 2
	Conn     *net.UnixConn
	Listener *net.UnixListener
	Bound    bool
	// Raw host-side file for sendmsg/recvmsg with cmsg
	RawConn  *os.File
}

// Socket constants matching Linux
const (
	AF_UNIX      = 1
	AF_LOCAL     = 1
	SOCK_STREAM  = 1
	SOCK_DGRAM   = 2
	SOCK_SEQPACKET = 5
	SOCK_CLOEXEC = 0x80000
	SOCK_NONBLOCK = 0x800

	SOL_SOCKET   = 1
	SO_ERROR     = 4
	SO_RCVBUF    = 8
	SO_SNDBUF    = 7
	SO_REUSEADDR = 2
	SO_KEEPALIVE = 9
	SO_PASSCRED  = 16

	SCM_RIGHTS   = 1
	SCM_CREDENTIALS = 2
)

// NewSocketFD creates a new unconnected socket.
func NewSocketFD(domain, sockType int) *SocketFD {
	return &SocketFD{
		Domain:   domain,
		SockType: sockType & ^(SOCK_CLOEXEC | SOCK_NONBLOCK),
	}
}

// Connect connects an AF_UNIX socket to the given path on the host.
func (s *SocketFD) Connect(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	netType := "unix"
	if s.SockType == SOCK_DGRAM {
		netType = "unixgram"
	}

	addr := &net.UnixAddr{Name: path, Net: netType}
	conn, err := net.DialUnix(netType, nil, addr)
	if err != nil {
		return err
	}
	s.Conn = conn

	// Get the underlying os.File for sendmsg/recvmsg with ancillary data
	f, err := conn.File()
	if err == nil {
		s.RawConn = f
	}

	return nil
}

// Read reads data from the socket.
func (s *SocketFD) Read(buf []byte) (int, error) {
	s.mu.Lock()
	conn := s.Conn
	s.mu.Unlock()
	if conn == nil {
		return -1, fmt.Errorf("socket not connected")
	}
	return conn.Read(buf)
}

// Write writes data to the socket.
func (s *SocketFD) Write(data []byte) (int, error) {
	s.mu.Lock()
	conn := s.Conn
	s.mu.Unlock()
	if conn == nil {
		return -1, fmt.Errorf("socket not connected")
	}
	return conn.Write(data)
}

// Close closes the socket and any underlying resources.
func (s *SocketFD) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RawConn != nil {
		s.RawConn.Close()
		s.RawConn = nil
	}
	if s.Conn != nil {
		err := s.Conn.Close()
		s.Conn = nil
		return err
	}
	if s.Listener != nil {
		err := s.Listener.Close()
		s.Listener = nil
		return err
	}
	return nil
}

// HostFD returns the raw host file descriptor number, or -1 if unavailable.
func (s *SocketFD) HostFD() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RawConn != nil {
		return int(s.RawConn.Fd())
	}
	return -1
}

// Bind binds the socket to a path (for server sockets).
func (s *SocketFD) Bind(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Bound = true
	// For listen, we'll create the listener in Listen()
	return nil
}

// Listen starts listening (AF_UNIX SOCK_STREAM only).
func (s *SocketFD) Listen(backlog int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Not implemented for now - guest as server is rare for Wayland
	return fmt.Errorf("listen not implemented")
}

// Accept accepts a connection (AF_UNIX SOCK_STREAM only).
func (s *SocketFD) Accept() (*SocketFD, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Listener == nil {
		return nil, fmt.Errorf("socket not listening")
	}
	conn, err := s.Listener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	child := &SocketFD{
		Domain:   s.Domain,
		SockType: s.SockType,
		Conn:     conn,
	}
	f, err := conn.File()
	if err == nil {
		child.RawConn = f
	}
	return child, nil
}
