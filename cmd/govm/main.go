package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mirkobrombin/go-vm/pkg/cpu"
	"github.com/mirkobrombin/go-vm/pkg/loader"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
	gosyscall "github.com/mirkobrombin/go-vm/pkg/syscall"
	"github.com/mirkobrombin/go-vm/pkg/thread"
	"github.com/mirkobrombin/go-vm/pkg/vfs"
)

func main() {
	trace := flag.Bool("trace", false, "enable instruction trace to stderr")
	memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: govm [flags] <elf-binary> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Tech VM - in-process RISC-V Library OS\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	_ = memMB // reserved for future use

	elfPath := args[0]
	absPath, _ := filepath.Abs(elfPath)
	guestArgv := args
	guestEnvp := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/",
		"TERM=dumb",
	}

	// Initialise subsystems
	mem := mmu.New()
	fs := vfs.New()
	fs.ElfPath = absPath

	// Route stdout/stderr to host
	fs.HostOut = func(fd int, data []byte) {
		if fd == 1 {
			os.Stdout.Write(data)
		} else {
			os.Stderr.Write(data)
		}
	}

	// Load ELF
	result, err := loader.LoadELF(elfPath, mem, guestArgv, guestEnvp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "govm: load error: %v\n", err)
		os.Exit(1)
	}

	// Syscall handler
	sh := gosyscall.NewHandler(mem, fs)
	sh.Trace = *trace

	// Thread manager + main thread
	tm := thread.NewManager(mem, sh.Handle)
	sh.ThreadM = tm

	mainThread := tm.MainThread(result.EntryPoint, result.StackPtr)

	// Set TP (thread pointer, x4) if TLS was loaded
	if result.TLSAddr != 0 {
		mainThread.CPU.X[4] = result.TLSAddr
	}

	// Run
	if err := mainThread.CPU.Run(); err != nil {
		if exitErr, ok := err.(*cpu.ExitError); ok {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "govm: runtime error: %v\n", err)
		os.Exit(1)
	}

	// Wait for spawned threads
	tm.Wait()

	// Guest exit code is in a0
	os.Exit(int(mainThread.CPU.X[10]))
}
