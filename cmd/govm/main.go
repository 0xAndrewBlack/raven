package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

func main() {
	ravelog.Banner("v0.1.0")

	trace := flag.Bool("trace", false, "enable instruction trace to stderr")
	traceSyscall := flag.Bool("trace-syscall", false, "trace Nt*/NtUser*/NtGdi* seam crossings only (no instruction noise; PE mode)")
	callExport := flag.String("call-export", "", "PE DLL mode: run DllMain then call an export, e.g. -call-export 'raven_add:2,2' (DLL export check)")
	renderPNG := flag.String("render-png", "", "after -call-export, render the win32k windows to a PNG (visual stack proof)")
	memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")
	sysroot := flag.String("sysroot", "", "path to Windows system DLL directory (for PE mode)")
	regFile := flag.String("registry", "", "path to registry hive JSON file (for PE mode)")
	cpuprof := flag.String("cpuprofile", "", "write CPU profile to file")
	cpuprofDuration := flag.Duration("cpuprofile-duration", 0, "stop CPU profiling after this duration")
	wayland := flag.Bool("wayland", true, "enable Wayland passthrough (use --wayland=false for headless)")
	autoScript := flag.String("auto", "", "automation script: semicolon-separated commands\n"+
		"  <delay>:screenshot:<path>    - save PNG screenshot\n"+
		"  <delay>:click:<x>,<y>        - inject left click\n"+
		"  <delay>:key:<linux_keycode>  - inject key press+release\n"+
		"  Example: '2:screenshot:/tmp/s1.png;3:click:100,50;4:screenshot:/tmp/s2.png'")

	flag.Usage = func() {
		ravelog.Banner("v0.1.0")
		fmt.Fprintf(os.Stderr, "Usage: raven [flags] <binary> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Raven - in-process x86-64 Windows PE / ELF emulator\n\n")
		fmt.Fprintf(os.Stderr, "Supports ELF (Linux) and PE (Windows) executables.\n")
		fmt.Fprintf(os.Stderr, "PE mode is auto-detected from the file header (.exe/.dll or MZ magic).\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *cpuprof != "" {
		f, err := os.Create(*cpuprof)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
			f.Close()
			os.Exit(1)
		}
		stopProfile := sync.OnceFunc(func() {
			pprof.StopCPUProfile()
			f.Close()
		})
		defer stopProfile()
		if *cpuprofDuration > 0 {
			timer := time.AfterFunc(*cpuprofDuration, stopProfile)
			defer timer.Stop()
		}
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	_ = memMB // reserved for future use

	binPath := args[0]
	absPath, _ := filepath.Abs(binPath)
	guestArgv := args

	// Detect binary format
	isPE := detectPE(binPath)

	if isPE {
		if !hasWindowsSupport() {
			fmt.Fprintf(os.Stderr, "Error: Windows guest support is not compiled into this binary.\n")
			fmt.Fprintf(os.Stderr, "Rebuild with: go build -tags guest_windows\n")
			os.Exit(1)
		}
		runPE(absPath, guestArgv, *sysroot, *regFile, *trace, *traceSyscall, *wayland, *autoScript, *callExport, *renderPNG)
	} else {
		if !hasLinuxSupport() {
			fmt.Fprintf(os.Stderr, "Error: Linux guest support is not compiled into this binary.\n")
			fmt.Fprintf(os.Stderr, "Rebuild with: go build -tags guest_linux\n")
			os.Exit(1)
		}
		runELF(absPath, guestArgv, *trace, *wayland)
	}
}

// detectPE checks if a file is a PE binary (MZ magic or .exe/.dll extension).
func detectPE(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".exe" || ext == ".dll" {
		return true
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	f.Read(magic[:])
	return magic[0] == 'M' && magic[1] == 'Z'
}
