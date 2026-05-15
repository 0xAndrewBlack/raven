package vfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestOpenAtCreateAndRead(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/tmp/test.txt", O_CREAT|O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello world")
	n, err := fs.Write(fd, data)
	if err != nil || n != len(data) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	// Seek back to beginning
	pos, err := fs.Lseek(fd, 0, SEEK_SET)
	if err != nil || pos != 0 {
		t.Fatalf("Lseek: pos=%d err=%v", pos, err)
	}
	// Read back
	buf := make([]byte, 64)
	rn, err := fs.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:rn]) != "hello world" {
		t.Fatalf("Read: got %q", string(buf[:rn]))
	}
}

func TestFileBytesSnapshotsConcurrentWrites(t *testing.T) {
	fs := New()
	const (
		path       = "/tmp/snapshot.txt"
		size       = 4096
		iterations = 1000
	)
	first := make([]byte, size)
	second := make([]byte, size)
	for i := range first {
		first[i] = 'a'
		second[i] = 'b'
	}
	if err := fs.CreateFile(path, first, ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}
	fd, err := fs.Open(path, O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	writerDone := make(chan error, 1)
	go func() {
		for i := 0; i < iterations; i++ {
			data := first
			if i&1 != 0 {
				data = second
			}
			if _, err := fs.Pwrite(fd, data, 0); err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	for i := 0; i < iterations; i++ {
		data, err := fs.FileBytes(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != size {
			t.Fatalf("snapshot length = %d, want %d", len(data), size)
		}
		for _, value := range data[1:] {
			if value != data[0] {
				t.Fatal("snapshot contains bytes from concurrent writes")
			}
		}
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
}

func TestOpenAccessModesAreEnforced(t *testing.T) {
	fs := New()
	const path = "/tmp/access.txt"
	if err := fs.CreateFile(path, []byte("original"), ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}

	readOnly, err := fs.Open(path, O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(readOnly)
	if _, err := fs.Write(readOnly, []byte("changed")); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Write(read-only) error = %v, want EBADF", err)
	}
	if _, err := fs.Pwrite(readOnly, []byte("changed"), 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Pwrite(read-only) error = %v, want EBADF", err)
	}
	data, err := fs.FileBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("read-only write changed data to %q", data)
	}
	if _, err := fs.Open(path, O_RDONLY|O_TRUNC); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("Open(read-only truncate) error = %v, want EACCES", err)
	}
	data, err = fs.FileBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original" {
		t.Fatalf("read-only truncate changed data to %q", data)
	}

	writeOnly, err := fs.Open(path, O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(writeOnly)
	buf := make([]byte, 8)
	if _, err := fs.Read(writeOnly, buf); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Read(write-only) error = %v, want EBADF", err)
	}
	if _, err := fs.Pread(writeOnly, buf, 0); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Pread(write-only) error = %v, want EBADF", err)
	}

	appendRead, err := fs.Open(path, O_RDWR|O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(appendRead)
	if _, err := fs.Pwrite(appendRead, []byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	data, err = fs.FileBytes(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original!" {
		t.Fatalf("Pwrite(append) data = %q, want original!", data)
	}
}

func TestHostPassthroughOpenFlags(t *testing.T) {
	fs := New()
	path := filepath.Join(t.TempDir(), "passthrough.txt")

	fd, err := fs.OpenAt(-100, path, O_CREAT|O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}

	fd, err = fs.OpenAt(-100, path, O_WRONLY|O_APPEND, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("-second")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}
	appended, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(appended) != "first-second" {
		t.Fatalf("appended host file = %q, want %q", appended, "first-second")
	}

	fd, err = fs.OpenAt(-100, path, O_WRONLY|O_TRUNC, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Write(fd, []byte("final")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(fd); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "final" {
		t.Fatalf("host file = %q, want %q", got, "final")
	}
}

func TestReadDirMergesVirtualAndHostEntries(t *testing.T) {
	fs := New()
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "host.txt"), []byte("host"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "COLLIDE.TXT"), []byte("host collision"), 0644); err != nil {
		t.Fatal(err)
	}
	fs.MkdirAll(hostDir)
	if err := fs.CreateFile(filepath.Join(hostDir, "virtual.txt"), []byte("virtual"), ModeRead); err != nil {
		t.Fatal(err)
	}
	if err := fs.CreateFile(filepath.Join(hostDir, "collide.txt"), []byte("virtual collision"), ModeRead); err != nil {
		t.Fatal(err)
	}

	entries, err := fs.ReadDir(strings.ToUpper(hostDir))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name()
	}
	if len(entries) != 3 ||
		entries[0].Name() != "collide.txt" ||
		entries[1].Name() != "host.txt" ||
		entries[2].Name() != "virtual.txt" {
		t.Fatalf("entries = %v", names)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() || info.Size() != int64(len("virtual collision")) {
		t.Fatalf("virtual info = size %d, dir %t", info.Size(), info.IsDir())
	}
}

func TestReadDirReportsVirtualFileTypes(t *testing.T) {
	fs := New()
	entries, err := fs.ReadDir("/dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "null" {
			continue
		}
		if entry.Type()&(os.ModeDevice|os.ModeCharDevice) != os.ModeDevice|os.ModeCharDevice {
			t.Fatalf("null type = %v", entry.Type())
		}
		return
	}
	t.Fatal("/dev/null missing")
}

func TestReadDirConcurrentMutation(t *testing.T) {
	fs := New()
	fs.MkdirAll("/work")
	fd, err := fs.Open("/work/data.txt", O_CREAT|O_RDWR|O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := fs.Write(fd, []byte("x")); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			fs.MkdirAll(fmt.Sprintf("/work/dir-%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if _, err := fs.ReadDir("/work"); err != nil {
				t.Errorf("ReadDir: %v", err)
				return
			}
		}
	}()
	wg.Wait()
}

func TestDup(t *testing.T) {
	fs := New()
	if err := fs.CreateFile("/dup.txt", []byte("abcdef"), ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}
	fd, err := fs.Open("/dup.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	buf := make([]byte, 2)
	if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "ab" {
		t.Fatalf("Read(original): n=%d data=%q err=%v", n, buf, err)
	}

	fd2, err := fs.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd2)
	if fd2 == fd {
		t.Fatal("Dup returned same fd")
	}
	node1 := fs.Stat(fd)
	node2 := fs.Stat(fd2)
	if node1.Ino != node2.Ino {
		t.Fatal("Dup'd fds don't share inode")
	}
	if n, err := fs.Read(fd2, buf); err != nil || n != len(buf) || string(buf) != "cd" {
		t.Fatalf("Read(duplicate): n=%d data=%q err=%v", n, buf, err)
	}
	if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "ef" {
		t.Fatalf("Read(original after duplicate): n=%d data=%q err=%v", n, buf, err)
	}
}

func TestDup3(t *testing.T) {
	fs := New()
	if err := fs.CreateFile("/dup3.txt", []byte("abcdef"), ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}
	fd, err := fs.Open("/dup3.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	buf := make([]byte, 2)
	if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "ab" {
		t.Fatalf("Read(original): n=%d data=%q err=%v", n, buf, err)
	}

	const duplicateFD = 10
	if err := fs.Dup3(fd, duplicateFD); err != nil {
		t.Fatal(err)
	}
	defer fs.Close(duplicateFD)
	if n, err := fs.Read(duplicateFD, buf); err != nil || n != len(buf) || string(buf) != "cd" {
		t.Fatalf("Read(duplicate): n=%d data=%q err=%v", n, buf, err)
	}
	if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "ef" {
		t.Fatalf("Read(original after duplicate): n=%d data=%q err=%v", n, buf, err)
	}
}

func TestOpenFilePositionsAreIndependent(t *testing.T) {
	fs := New()
	if err := fs.CreateFile("/independent.txt", []byte("abcdef"), ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}
	first, err := fs.Open("/independent.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(first)
	second, err := fs.Open("/independent.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(second)

	buf := make([]byte, 2)
	for _, fd := range []int{first, second} {
		if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "ab" {
			t.Fatalf("Read(fd %d): n=%d data=%q err=%v", fd, n, buf, err)
		}
	}
	for _, fd := range []int{first, second} {
		if n, err := fs.Read(fd, buf); err != nil || n != len(buf) || string(buf) != "cd" {
			t.Fatalf("Read(fd %d): n=%d data=%q err=%v", fd, n, buf, err)
		}
	}
}

func TestPositionalIORejectsInvalidRanges(t *testing.T) {
	fs := New()
	if err := fs.CreateFile("/positional-io.txt", []byte("data"), ModeRead|ModeWrite); err != nil {
		t.Fatal(err)
	}
	fd, err := fs.Open("/positional-io.txt", O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	const maxInt64 = int64(1<<63 - 1)
	tests := []struct {
		name string
		call func() (int, error)
	}{
		{
			name: "pread negative offset",
			call: func() (int, error) {
				return fs.Pread(fd, make([]byte, 1), -1)
			},
		},
		{
			name: "pread range overflow",
			call: func() (int, error) {
				return fs.Pread(fd, make([]byte, 2), maxInt64)
			},
		},
		{
			name: "pwrite negative offset",
			call: func() (int, error) {
				return fs.Pwrite(fd, []byte("x"), -1)
			},
		},
		{
			name: "pwrite range overflow",
			call: func() (int, error) {
				return fs.Pwrite(fd, []byte("xy"), maxInt64)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			n, err := test.call()
			if n != -1 || !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("result = %d, %v; want -1, EINVAL", n, err)
			}
		})
	}
}

func TestPipe2(t *testing.T) {
	fs := New()
	rfd, wfd, err := fs.Pipe2(0)
	if err != nil {
		t.Fatal(err)
	}
	// Write into pipe
	fs.Write(wfd, []byte("pipe data"))
	// Read from pipe
	buf := make([]byte, 64)
	n, err := fs.Read(rfd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pipe data" {
		t.Fatalf("Pipe: got %q", string(buf[:n]))
	}
	if _, err := fs.Write(rfd, []byte("wrong end")); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Write(read end) error = %v, want EBADF", err)
	}
	if _, err := fs.Read(wfd, buf); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("Read(write end) error = %v, want EBADF", err)
	}
}

func TestLseek(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/seek.txt", O_CREAT|O_RDWR, 0644)
	fs.Write(fd, []byte("0123456789"))

	// SEEK_SET to 5
	pos, _ := fs.Lseek(fd, 5, SEEK_SET)
	if pos != 5 {
		t.Fatalf("SEEK_SET: expected 5, got %d", pos)
	}
	// SEEK_CUR +2
	pos, _ = fs.Lseek(fd, 2, SEEK_CUR)
	if pos != 7 {
		t.Fatalf("SEEK_CUR: expected 7, got %d", pos)
	}
	// SEEK_END -3
	pos, _ = fs.Lseek(fd, -3, SEEK_END)
	if pos != 7 {
		t.Fatalf("SEEK_END: expected 7, got %d", pos)
	}
}

func TestLseekCharDevice(t *testing.T) {
	fs := New()
	// stdout is a char device - lseek should fail
	_, err := fs.Lseek(1, 0, SEEK_SET)
	if err == nil {
		t.Fatal("Lseek on char device should fail")
	}
}

func TestReadlinkatProcSelfExe(t *testing.T) {
	fs := New()
	fs.ElfPath = "/usr/bin/test"
	target, err := fs.Readlinkat(-100, "/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/usr/bin/test" {
		t.Fatalf("Expected /usr/bin/test, got %s", target)
	}
}

func TestStatInode(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/stat.txt", O_CREAT|O_RDWR, 0644)
	node := fs.Stat(fd)
	if node == nil {
		t.Fatal("Stat returned nil")
	}
	if node.Ino == 0 {
		t.Fatal("Inode should be non-zero")
	}
	if node.FileMode&S_IFREG == 0 {
		t.Fatalf("Expected regular file, got mode 0x%x", node.FileMode)
	}
}

func TestFileIdentityVirtualAliases(t *testing.T) {
	fs := New()
	firstFD, err := fs.Open("/tmp/identity.txt", O_CREAT|O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(firstFD)
	secondFD, err := fs.Open("/tmp/identity.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(secondFD)
	dupFD, err := fs.Dup(firstFD)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dupFD)

	first, ok := fs.FileIdentity(firstFD)
	if !ok {
		t.Fatal("FileIdentity rejected virtual regular file")
	}
	if first.Host || first.Device != 0 || first.Inode == 0 {
		t.Fatalf("virtual identity = %#v", first)
	}
	for _, fd := range []int{secondFD, dupFD} {
		identity, ok := fs.FileIdentity(fd)
		if !ok || identity != first {
			t.Fatalf("fd %d identity = %#v, %v; want %#v, true", fd, identity, ok, first)
		}
	}

	if err := fs.Renameat(-100, "/tmp/identity.txt", -100, "/tmp/renamed.txt"); err != nil {
		t.Fatal(err)
	}
	renamedFD, err := fs.Open("/tmp/renamed.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(renamedFD)
	node := fs.Stat(renamedFD)
	fs.mu.Lock()
	parent, resolveErr := fs.Resolve("/tmp")
	if resolveErr == nil {
		parent.Children["hardlink.txt"] = node
		node.Nlink++
	}
	fs.mu.Unlock()
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	hardlinkFD, err := fs.Open("/tmp/hardlink.txt", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(hardlinkFD)

	for _, fd := range []int{firstFD, renamedFD, hardlinkFD} {
		identity, ok := fs.FileIdentity(fd)
		if !ok || identity != first {
			t.Fatalf("fd %d identity = %#v, %v after alias change; want %#v, true", fd, identity, ok, first)
		}
	}
}

func TestFileIdentityHostRegularFile(t *testing.T) {
	const cacheRoot = "/home/user/.cache/raven"
	if err := os.MkdirAll(cacheRoot, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(cacheRoot, "vfs-file-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("RemoveAll: %v", err)
		}
	})
	path := filepath.Join(dir, "host.txt")
	alias := filepath.Join(dir, "host-link.txt")
	if err := os.WriteFile(path, []byte("host"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}

	fs := New()
	firstFD, err := fs.Open(path, O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(firstFD)
	aliasFD, err := fs.Open(alias, O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(aliasFD)
	dupFD, err := fs.Dup(firstFD)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dupFD)
	hostFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	allocatedFD := fs.AllocHostFile(hostFile)
	defer fs.Close(allocatedFD)

	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	want := FileIdentity{
		Host:   true,
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
	}
	for _, fd := range []int{firstFD, aliasFD, dupFD, allocatedFD} {
		identity, ok := fs.FileIdentity(fd)
		if !ok || identity != want {
			t.Fatalf("fd %d identity = %#v, %v; want %#v, true", fd, identity, ok, want)
		}
	}
}

func TestFileIdentityRejectsNonRegularDescriptors(t *testing.T) {
	fs := New()
	if identity, ok := fs.FileIdentity(9999); ok {
		t.Fatalf("invalid fd identity = %#v, true", identity)
	}

	dirFD, err := fs.Open("/tmp", O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dirFD)
	deviceFD, err := fs.Open("/dev/null", O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(deviceFD)
	pipeReadFD, pipeWriteFD, err := fs.Pipe2(0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(pipeReadFD)
	defer fs.Close(pipeWriteFD)
	socketFD, err := fs.AllocSocket(AF_UNIX, SOCK_STREAM)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(socketFD)
	eventFD := fs.AllocEventFD(0, 0)
	defer fs.Close(eventFD)
	dupEventFD, err := fs.Dup(eventFD)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dupEventFD)
	const dup3EventFD = 100
	if err := fs.Dup3(eventFD, dup3EventFD); err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dup3EventFD)
	epollFD := fs.AllocEpoll()
	defer fs.Close(epollFD)
	dupEpollFD, err := fs.Dup(epollFD)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dupEpollFD)
	const dup3EpollFD = 200
	if err := fs.Dup3(epollFD, dup3EpollFD); err != nil {
		t.Fatal(err)
	}
	defer fs.Close(dup3EpollFD)

	hostPipeRead, hostPipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	hostPipeReadFD := fs.AllocHostFile(hostPipeRead)
	defer fs.Close(hostPipeReadFD)
	hostPipeWriteFD := fs.AllocHostFile(hostPipeWrite)
	defer fs.Close(hostPipeWriteFD)
	hostDevice, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	hostDeviceFD := fs.AllocHostFile(hostDevice)
	defer fs.Close(hostDeviceFD)
	hostSocket, err := syscall.Socket(AF_UNIX, SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostSocketFD := fs.WrapHostFD(hostSocket, "file-identity-socket")
	defer fs.Close(hostSocketFD)

	for _, fd := range []int{
		dirFD,
		deviceFD,
		pipeReadFD,
		pipeWriteFD,
		socketFD,
		eventFD,
		dupEventFD,
		dup3EventFD,
		epollFD,
		dupEpollFD,
		dup3EpollFD,
		hostPipeReadFD,
		hostPipeWriteFD,
		hostDeviceFD,
		hostSocketFD,
	} {
		if identity, ok := fs.FileIdentity(fd); ok {
			t.Fatalf("fd %d identity = %#v, true", fd, identity)
		}
	}
}

func TestDevNull(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/dev/null", O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Write should succeed
	n, err := fs.Write(fd, []byte("garbage"))
	if err != nil || n != 7 {
		t.Fatalf("Write to /dev/null: n=%d err=%v", n, err)
	}
	// Read should return EOF
	buf := make([]byte, 10)
	rn, _ := fs.Read(fd, buf)
	if rn != 0 {
		t.Fatalf("Read from /dev/null: expected 0, got %d", rn)
	}
}

func TestGetdents64(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/a.txt", []byte("a"), ModeRead)
	fs.CreateFile("/tmp/b.txt", []byte("b"), ModeRead)
	fd, _ := fs.OpenAt(-100, "/tmp", 0, 0)
	entries := fs.Getdents64(fd)
	if len(entries) < 2 {
		t.Fatalf("Expected at least 2 entries, got %d", len(entries))
	}
}

func TestUnlinkat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/todelete.txt", []byte("gone"), ModeRead)
	// Verify exists
	_, err := fs.StatPath(-100, "/tmp/todelete.txt")
	if err != nil {
		t.Fatal("file should exist before unlink")
	}
	// Unlink it
	if err := fs.Unlinkat(-100, "/tmp/todelete.txt", 0); err != nil {
		t.Fatal(err)
	}
	// Verify gone
	_, err = fs.StatPath(-100, "/tmp/todelete.txt")
	if err == nil {
		t.Fatal("file should not exist after unlink")
	}
}

func TestRemoveAll(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/tree/nested")
	fs.CreateFile("/tmp/tree/nested/file.txt", []byte("gone"), ModeRead)
	if err := fs.RemoveAll(-100, "/TMP/TREE"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.StatPath(-100, "/tmp/tree"); err == nil {
		t.Fatal("directory tree still exists")
	}
	if err := fs.RemoveAll(-100, "/tmp/missing"); err != nil {
		t.Fatalf("missing path: %v", err)
	}
	if err := fs.RemoveAll(-100, "/"); err == nil {
		t.Fatal("VFS root removal succeeded")
	}
}

func TestFtruncate(t *testing.T) {
	fs := New()
	fd, _ := fs.OpenAt(-100, "/tmp/trunc.txt", O_CREAT|O_RDWR, 0644)
	fs.Write(fd, []byte("hello world"))
	// Truncate to 5
	if err := fs.Ftruncate(fd, 5); err != nil {
		t.Fatal(err)
	}
	node := fs.Stat(fd)
	if node.Size != 5 {
		t.Fatalf("expected size 5, got %d", node.Size)
	}
	// Extend to 20
	if err := fs.Ftruncate(fd, 20); err != nil {
		t.Fatal(err)
	}
	node = fs.Stat(fd)
	if node.Size != 20 {
		t.Fatalf("expected size 20, got %d", node.Size)
	}
}

func TestChdir(t *testing.T) {
	fs := New()
	fs.MkdirAll("/home/user")
	if err := fs.Chdir("/home/user"); err != nil {
		t.Fatal(err)
	}
	if fs.Getcwd() != "/home/user" {
		t.Fatalf("expected /home/user, got %s", fs.Getcwd())
	}
}

func TestRenameat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("data"), ModeRead)
	if err := fs.Renameat(-100, "/tmp/old.txt", -100, "/tmp/new.txt"); err != nil {
		t.Fatal(err)
	}
	_, err := fs.StatPath(-100, "/tmp/old.txt")
	if err == nil {
		t.Fatal("old path should not exist after rename")
	}
	_, err = fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatal("new path should exist after rename")
	}
}

func TestRenameatWithCommitLeavesEntriesUnchangedOnFailure(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/new.txt", []byte("destination"), ModeRead)
	commitErr := errors.New("commit failed")
	var committedData []byte

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{ReplaceExisting: true}, func(source RenameCommitSource) (RenameCommitResult, error) {
		committedData = source.Data
		return RenameCommitResult{}, commitErr
	})
	if !errors.Is(err, commitErr) {
		t.Fatalf("RenameatWithCommit error = %v, want %v", err, commitErr)
	}
	if string(committedData) != "source" {
		t.Fatalf("commit data = %q, want source", committedData)
	}
	oldNode, err := fs.StatPath(-100, "/tmp/old.txt")
	if err != nil {
		t.Fatalf("old entry is missing: %v", err)
	}
	if string(oldNode.Data) != "source" {
		t.Fatalf("old entry data = %q, want source", oldNode.Data)
	}
	newNode, err := fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatalf("new entry is missing: %v", err)
	}
	if string(newNode.Data) != "destination" {
		t.Fatalf("new entry data = %q, want destination", newNode.Data)
	}
}

func TestRenameatWithCommitRejectsExistingDestinationBeforeCommit(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/new.txt", []byte("destination"), ModeRead)
	commitCalled := false

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{}, func(RenameCommitSource) (RenameCommitResult, error) {
		commitCalled = true
		return RenameCommitResult{}, nil
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("RenameatWithCommit error = %v, want destination-exists error", err)
	}
	if commitCalled {
		t.Fatal("external commit ran after destination conflict")
	}
	oldNode, _ := fs.StatPath(-100, "/tmp/old.txt")
	newNode, _ := fs.StatPath(-100, "/tmp/new.txt")
	if string(oldNode.Data) != "source" || string(newNode.Data) != "destination" {
		t.Fatalf("entries changed: old=%q new=%q", oldNode.Data, newNode.Data)
	}
}

func TestRenameatWithCommitRejectsNonDirectoryParent(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/not-a-directory", []byte("file"), ModeRead)

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/not-a-directory/new.txt", RenameOptions{}, nil)
	if !errors.Is(err, ErrRenameParentNotFound) {
		t.Fatalf("RenameatWithCommit error = %v, want parent error", err)
	}
	if _, err := fs.StatPath(-100, "/tmp/old.txt"); err != nil {
		t.Fatalf("source entry was removed: %v", err)
	}
}

func TestRenameatRejectsDirectoryMovedIntoDescendant(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/tree/sub")

	err := fs.Renameat(-100, "/tmp/tree", -100, "/tmp/tree/sub/moved")
	if !errors.Is(err, ErrInvalidPathAlias) {
		t.Fatalf("Renameat error = %v, want invalid alias", err)
	}
	if _, err := fs.StatPath(-100, "/tmp/tree/sub"); err != nil {
		t.Fatalf("source tree changed after failed rename: %v", err)
	}
}

func TestRenameatWithCommitRejectsExistingDirectoryForWindowsMove(t *testing.T) {
	fs := New()
	fs.MkdirAll("/tmp/source")
	fs.MkdirAll("/tmp/destination")
	commitCalled := false

	err := fs.RenameatWithCommit(-100, "/tmp/source", -100, "/tmp/destination", RenameOptions{
		ReplaceExisting:         true,
		RejectExistingDirectory: true,
	}, func(RenameCommitSource) (RenameCommitResult, error) {
		commitCalled = true
		return RenameCommitResult{}, nil
	})
	if err == nil {
		t.Fatal("existing destination directory was replaced")
	}
	if commitCalled {
		t.Fatal("external commit ran before directory conflict was rejected")
	}
	if _, err := fs.StatPath(-100, "/tmp/source"); err != nil {
		t.Fatalf("source directory was removed: %v", err)
	}
}

func TestRenameatUsesCaseInsensitiveEntryNames(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/Old.txt", []byte("source"), ModeRead)
	fs.CreateFile("/tmp/Target.txt", []byte("destination"), ModeRead)

	if err := fs.Renameat(-100, "/TMP/OLD.TXT", -100, "/tmp/TARGET.TXT"); err != nil {
		t.Fatal(err)
	}
	parent, err := fs.Resolve("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if len(parent.Children) != 1 {
		t.Fatalf("directory has %d entries, want 1", len(parent.Children))
	}
	node := parent.Children["TARGET.TXT"]
	if node == nil || string(node.Data) != "source" {
		t.Fatalf("renamed entry = %#v", node)
	}
}

func TestRenameatWithCommitCanRetainSource(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/old.txt", []byte("source"), ModeRead)

	err := fs.RenameatWithCommit(-100, "/tmp/old.txt", -100, "/tmp/new.txt", RenameOptions{}, func(RenameCommitSource) (RenameCommitResult, error) {
		return RenameCommitResult{KeepSource: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	oldNode, err := fs.StatPath(-100, "/tmp/old.txt")
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := fs.StatPath(-100, "/tmp/new.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(oldNode.Data) != "source" || string(newNode.Data) != "source" {
		t.Fatalf("source data = %q, destination data = %q", oldNode.Data, newNode.Data)
	}
	if oldNode.Ino == newNode.Ino {
		t.Fatalf("copied entries share inode %d", oldNode.Ino)
	}
	if oldNode.Mode != newNode.Mode || oldNode.FileMode != newNode.FileMode ||
		oldNode.Uid != newNode.Uid || oldNode.Gid != newNode.Gid ||
		oldNode.Size != newNode.Size {
		t.Fatalf("copied metadata differs: old=%#v new=%#v", oldNode, newNode)
	}
}

func TestSymlinkat(t *testing.T) {
	fs := New()
	fs.CreateFile("/tmp/target.txt", []byte("content"), ModeRead)
	if err := fs.Symlinkat("/tmp/target.txt", -100, "/tmp/link.txt"); err != nil {
		t.Fatal(err)
	}
	target, err := fs.Readlinkat(-100, "/tmp/link.txt")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/tmp/target.txt" {
		t.Fatalf("expected /tmp/target.txt, got %s", target)
	}
}

func TestOpenAtReadsHostTemporaryFile(t *testing.T) {
	hostPath := filepath.Join(t.TempDir(), "host.txt")
	if err := os.WriteFile(hostPath, []byte("host data"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := New()
	fd, err := fs.OpenAt(-100, hostPath, O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(fd)

	buf := make([]byte, 32)
	n, err := fs.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "host data" {
		t.Fatalf("Read: got %q", got)
	}
}
