//go:build guest_linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/cpu"
	"github.com/mirkobrombin/Raven/pkg/loader"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	gosyscall "github.com/mirkobrombin/Raven/pkg/syscall"
	"github.com/mirkobrombin/Raven/pkg/thread"
	"github.com/mirkobrombin/Raven/pkg/vfs"
	"github.com/mirkobrombin/Raven/pkg/x64"
)

// runELF runs a Linux ELF binary (original code path).
func runELF(absPath string, guestArgv []string, trace bool, enableWayland bool) {
	guestEnvp := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"TERM=dumb",
		"SHELL=/bin/sh",
		"USER=root",
		"LOGNAME=root",
	}

	if enableWayland {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = "/run/user/1000"
		}
		guestEnvp = append(guestEnvp, "XDG_RUNTIME_DIR="+xdg)
		waylandDisp := os.Getenv("WAYLAND_DISPLAY")
		if waylandDisp == "" {
			waylandDisp = "wayland-0"
		}
		guestEnvp = append(guestEnvp, "WAYLAND_DISPLAY="+waylandDisp)
		// Explicit EGL platform so libglvnd registers only one winsys backend.
		// Without this, glvnd probes both X11 and Wayland, triggering a double-
		// registration assertion in __glvndWinsysDispatchAllocIndex.
		guestEnvp = append(guestEnvp, "EGL_PLATFORM=wayland")
		// Software GL via Mesa/Gallium - no GPU device needed.
		guestEnvp = append(guestEnvp, "LIBGL_ALWAYS_SOFTWARE=1")
		guestEnvp = append(guestEnvp, "GALLIUM_DRIVER=softpipe")
		// Also expose DISPLAY for apps that fall back to X11 for font/cursor etc.
		if display := os.Getenv("DISPLAY"); display != "" {
			guestEnvp = append(guestEnvp, "DISPLAY="+display)
		}
	}

	mem := mmu.New()
	fs := vfs.New()
	fs.ElfPath = absPath

	if enableWayland {
		xdg := os.Getenv("XDG_RUNTIME_DIR")
		if xdg == "" {
			xdg = "/run/user/1000"
		}
		fs.MkdirAll(xdg)
		waylandDisp := os.Getenv("WAYLAND_DISPLAY")
		if waylandDisp == "" {
			waylandDisp = "wayland-0"
		}
		// Dummy VFS entry so guest can stat/access the socket path.
		fs.CreateFile(filepath.Join(xdg, waylandDisp), nil, 0666)
		// Also expose X11 for libs that probe DISPLAY (fontconfig, cursors, etc.)
		if display := os.Getenv("DISPLAY"); display != "" {
			dispNum := strings.TrimPrefix(display, ":")
			if dot := strings.Index(dispNum, "."); dot >= 0 {
				dispNum = dispNum[:dot]
			}
			x11Dir := "/tmp/.X11-unix"
			fs.MkdirAll(x11Dir)
			fs.CreateFile(filepath.Join(x11Dir, "X"+dispNum), nil, 0666)
		}
	}
	fs.HostOut = func(fd int, data []byte) {
		if fd == 1 {
			os.Stdout.Write(data)
		} else {
			os.Stderr.Write(data)
		}
	}
	fs.HostIn = func(fd int, buf []byte) int {
		n, _ := os.Stdin.Read(buf)
		return n
	}

	result, err := loader.LoadELF(absPath, mem, guestArgv, guestEnvp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "govm: load error: %v\n", err)
		os.Exit(1)
	}

	var guest arch.CPU
	switch result.Arch {
	case arch.ArchRISCV64:
		c := cpu.New(mem)
		c.SetPC(result.EntryPoint)
		c.SetSP(result.StackPtr)
		if result.TLSAddr != 0 {
			c.SetTLS(result.TLSAddr)
		}
		guest = c
	case arch.ArchAMD64:
		c := x64.New(mem)
		c.SetPC(result.EntryPoint)
		c.SetSP(result.StackPtr)
		if result.TLSAddr != 0 {
			c.SetTLS(result.TLSAddr)
		}
		// Fix Lapce double-free: only apply when running Lapce specifically.
		// After glibc realloc moves a buffer the old chunk is freed internally,
		// but Lapce's caller (at 0x55555799d5d3) tries to free the old ptr a
		// second time.  Patch the conditional jump JZ→JMP (0x74→0xeb) at
		// 0x55555799d5d9 so the redundant free is always skipped.
		if strings.Contains(absPath, "lapce") {
			const patchAddr = uint64(0x55555799d5d9)
			pageStart := patchAddr &^ (mmu.PageSize - 1)
			mem.Mprotect(pageStart, mmu.PageSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
			if err := mem.Write8(patchAddr, 0xeb); err != nil {
				ravelog.Logf("[PATCH] FAILED to apply double-free fix: %v\n", err)
			}
			mem.Mprotect(pageStart, mmu.PageSize, mmu.PermRead|mmu.PermExecute)
		}
		guest = c
	}

	sh := gosyscall.NewHandler(mem, fs)
	sh.Trace = trace
	sh.Arch = result.Arch

	tm := thread.NewManager(mem, sh.Handle)
	sh.ThreadM = tm

	mainThread := tm.MainThread(guest)

	if err := mainThread.CPU.Run(); err != nil {
		if exitErr, ok := err.(*arch.ExitError); ok {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "govm: runtime error: %v\n", err)
		os.Exit(1)
	}

	tm.Wait()
}

// runPE runs a Windows PE binary with the NT subsystem.
