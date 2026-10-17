package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
)

func main() {
	ravelog.Banner("v0.1.0")

	trace := flag.Bool("trace", false, "enable instruction trace to stderr")
	memMB := flag.Int("mem", 256, "guest memory limit in MiB (advisory)")
	sysroot := flag.String("sysroot", "", "path to Windows system DLL directory (for PE mode)")
	winePrefix := flag.String("wine-prefix", "", "path to Wine prefix (e.g. /path/to/runner/lib/wine/x86_64-windows or lib32/wine/i386-windows) to load real Wine PE DLLs alongside synthetic ones")
	regFile := flag.String("registry", "", "path to registry hive JSON file (for PE mode)")
	cpuprof := flag.String("cpuprofile", "", "write CPU profile to file")
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
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
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
		runPE(absPath, guestArgv, *sysroot, *winePrefix, *regFile, *trace, *wayland, *autoScript)
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
