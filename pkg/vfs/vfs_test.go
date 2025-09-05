package vfs

import (
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

func TestDup(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/tmp/dup.txt", O_CREAT|O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	fs.Write(fd, []byte("data"))

	fd2, err := fs.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	if fd2 == fd {
		t.Fatal("Dup returned same fd")
	}
	// Both fds should share the same node
	node1 := fs.Stat(fd)
	node2 := fs.Stat(fd2)
	if node1.Ino != node2.Ino {
		t.Fatal("Dup'd fds don't share inode")
	}
}

func TestDup3(t *testing.T) {
	fs := New()
	// Dup stdout (fd=1) to fd 10
	err := fs.Dup3(1, 10)
	if err != nil {
		t.Fatal(err)
	}
	node := fs.Stat(10)
	if node == nil {
		t.Fatal("fd 10 not open after Dup3")
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

func TestDevNull(t *testing.T) {
	fs := New()
	fd, err := fs.OpenAt(-100, "/dev/null", 0, 0)
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
