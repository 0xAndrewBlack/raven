//go:build guest_windows

package gdi

import (
	"os"
	"os/exec"
	"strings"
	"sync"
)

var windowsFontMap = map[string]string{
	"arial":                "sans-serif",
	"helvetica":            "sans-serif",
	"times new roman":      "serif",
	"times":                "serif",
	"courier new":          "monospace",
	"courier":              "monospace",
	"segoe ui":             "sans-serif",
	"tahoma":               "sans-serif",
	"verdana":              "sans-serif",
	"microsoft sans serif": "sans-serif",
	"ms sans serif":        "sans-serif",
	"ms shell dlg":         "sans-serif",
	"ms shell dlg 2":       "sans-serif",
	"consolas":             "monospace",
	"lucida console":       "monospace",
	"system":               "sans-serif",
	"fixedsys":             "monospace",
	"symbol":               "sans-serif",
	"":                     "sans-serif",
}

var (
	fontMatchMu    sync.Mutex
	fontMatchCache = make(map[string]string)
)

func fontSpecKey(family string, bold, italic bool) string {
	return strings.ToLower(strings.TrimSpace(family)) + "|" + boolKey(bold) + "|" + boolKey(italic)
}

func boolKey(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func fontStyleName(bold, italic bool) string {
	switch {
	case bold && italic:
		return "Bold Italic"
	case bold:
		return "Bold"
	case italic:
		return "Italic"
	default:
		return "Regular"
	}
}

func mapWindowsFontFamily(family string) string {
	trimmed := strings.TrimSpace(family)
	if mapped := windowsFontMap[strings.ToLower(trimmed)]; mapped != "" {
		return mapped
	}
	if trimmed == "" {
		return "sans-serif"
	}
	return trimmed
}

func findSystemFont(family string, bold, italic bool) string {
	key := fontSpecKey(family, bold, italic)
	fontMatchMu.Lock()
	if path, ok := fontMatchCache[key]; ok {
		fontMatchMu.Unlock()
		return path
	}
	fontMatchMu.Unlock()

	mapped := mapWindowsFontFamily(family)
	style := fontStyleName(bold, italic)
	path := runFcMatch(mapped, style)
	if path == "" && mapped != family {
		path = runFcMatch(strings.TrimSpace(family), style)
	}
	if path == "" {
		path = fallbackFont()
	}

	fontMatchMu.Lock()
	fontMatchCache[key] = path
	fontMatchMu.Unlock()
	return path
}

func runFcMatch(family, style string) string {
	pattern := strings.TrimSpace(family)
	if pattern == "" {
		pattern = "sans-serif"
	}
	if style != "" {
		pattern += ":style=" + style
	}
	out, err := exec.Command("fc-match", "-f", "%{file}", pattern).Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return ""
	}
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

func fallbackFont() string {
	if path := runFcMatch("sans-serif", "Regular"); path != "" {
		return path
	}
	for _, p := range []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/TTF/DejaVuSans.ttf",
		"/usr/share/fonts/noto/NotoSans-Regular.ttf",
		"/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
