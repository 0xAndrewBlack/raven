// Package log provides colored terminal logging for Raven.
// All colors are drawn from the Raven brand gradient: red → pink → purple.
package log

import (
	"fmt"
	"os"
	"strings"
)

// isTTY is true when stderr is an interactive terminal.
var isTTY = func() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}()

// Raven brand gradient (red → crimson → hot-pink → deep-purple).
const (
	colorRed      = "\033[38;2;255;58;45m"  // #FF3A2D - bright red
	colorCrimson  = "\033[38;2;225;30;100m" // #E11E64 - crimson
	colorPink     = "\033[38;2;190;20;155m" // #BE149B - hot pink
	colorViolet   = "\033[38;2;155;15;190m" // #9B0FBE - violet
	colorPurple   = "\033[38;2;120;10;210m" // #780AD2 - deep purple
	colorDim      = "\033[38;2;140;100;160m\033[2m" // muted purple-grey
	colorReset    = "\033[0m"
)

// tagColor maps a log tag to its brand gradient color.
var tagColor = map[string]string{
	// red end - low-level PE/load machinery
	"pe":           colorRed,
	"resolve":      colorRed,
	"PATCH":        colorRed,
	"loader":       colorRed,
	"HEAP-CORRUPT": colorRed,
	// crimson - win32 surface / window management
	"win32":     colorCrimson,
	"wl":        colorCrimson,
	"wndclass":  colorCrimson,
	"ordinal":   colorCrimson,
	"paint":     colorCrimson,
	"wm":        colorCrimson,
	"msg":       colorCrimson,
	"wndlong":   colorCrimson,
	"clipboard": colorCrimson,
	"dde":       colorCrimson,
	// hot pink - high-level win32 subsystem
	"menu":     colorPink,
	"setpos":   colorPink,
	"dispatch": colorPink,
	"destroy":  colorPink,
	"comctl32": colorPink,
	"gdi":      colorPink,
	"sci":      colorPink,
	"hook":     colorPink,
	"font":     colorPink,
	"cursor":   colorPink,
	"accel":    colorPink,
	// violet - system-level / SEH / registry
	"seh":    colorViolet,
	"reg":    colorViolet,
	"regkey": colorViolet,
	"ss":     colorViolet,
	"atom":   colorViolet,
	// purple end - ntapi / syscall / runtime / threading
	"ntapi":     colorPurple,
	"govm":      colorPurple,
	"trace":     colorPurple,
	"x11-trace": colorPurple,
	"brk":       colorPurple,
	"heap-sig":  colorPurple,
	"delay":     colorPurple,
	"loadstr":   colorPurple,
	"flags":     colorPurple,
	"commit":    colorPurple,
	"thr":       colorPurple,
	"thread":    colorPurple,
	"timer":     colorPurple,
	// dim - verbose diagnostic / muted
	"heap": colorDim,
	"mmap": colorDim,
}

// Logf writes a formatted log line to stderr.
// If the message begins with "[tag]", the tag is colorized using the Raven
// brand gradient; otherwise the message is printed verbatim.
func Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !isTTY {
		fmt.Fprint(os.Stderr, msg)
		return
	}
	if len(msg) > 2 && msg[0] == '[' {
		end := strings.IndexByte(msg, ']')
		if end > 0 {
			tag := msg[1:end]
			rest := msg[end+1:]
			if color, ok := tagColor[tag]; ok {
				fmt.Fprintf(os.Stderr, "%s[%s]%s%s", color, tag, colorReset, rest)
				return
			}
		}
	}
	fmt.Fprint(os.Stderr, msg)
}

// Banner prints the Raven startup banner to stderr.
// It is a no-op when stderr is not a terminal.
func Banner(version string) {
	if !isTTY {
		return
	}
	// Each letter of RAVEN gets a step along the red→purple gradient.
	r := colorRed
	a := colorCrimson
	v := colorPink
	e := colorViolet
	n := colorPurple
	dim := colorDim
	rst := colorReset

	fmt.Fprintf(os.Stderr,
		"\n  %sR%sA%sV%sE%sN%s  %s─  Windows PE · ELF · x86-64 emulator%s\n",
		r, a, v, e, n, rst, dim, rst,
	)
	fmt.Fprintf(os.Stderr,
		"  %s%s  ·  MIT License  ·  Wayland native%s\n\n",
		dim, version, rst,
	)
}
