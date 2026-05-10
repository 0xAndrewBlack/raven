//go:build guest_windows

package gdi

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type fontMatch struct {
	path  string
	index int
}

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
	fontMatchCache = make(map[string]fontMatch)
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

func findSystemFont(family string, bold, italic bool) fontMatch {
	key := fontSpecKey(family, bold, italic)
	fontMatchMu.Lock()
	if match, ok := fontMatchCache[key]; ok {
		fontMatchMu.Unlock()
		return match
	}
	fontMatchMu.Unlock()

	mapped := mapWindowsFontFamily(family)
	style := fontStyleName(bold, italic)
	match := runFcMatch(mapped, style)
	if match.path == "" && mapped != family {
		match = runFcMatch(strings.TrimSpace(family), style)
	}
	if match.path == "" {
		match = fallbackFont()
	}

	fontMatchMu.Lock()
	fontMatchCache[key] = match
	fontMatchMu.Unlock()
	return match
}

func fontPattern(family, style string) string {
	pattern := strings.TrimSpace(family)
	if pattern == "" {
		pattern = "sans-serif"
	}
	if style != "" {
		pattern += ":style=" + style
	}
	return pattern
}

func parseFontMatches(out []byte) []fontMatch {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	matches := make([]fontMatch, 0, len(lines))
	for _, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		path := strings.TrimSpace(parts[0])
		if path == "" {
			continue
		}
		index := 0
		if len(parts) == 2 {
			index, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		if _, err := os.Stat(path); err == nil {
			matches = append(matches, fontMatch{path: path, index: index})
		}
	}
	return matches
}

func runFcMatch(family, style string) fontMatch {
	out, err := exec.Command("fc-match", "-f", "%{file}\t%{index}\n", fontPattern(family, style)).Output()
	if err != nil {
		return fontMatch{}
	}
	matches := parseFontMatches(out)
	if len(matches) == 0 {
		return fontMatch{}
	}
	return matches[0]
}

func runFcMatchAll(family, style string) []fontMatch {
	out, err := exec.Command("fc-match", "-s", "-f", "%{file}\t%{index}\n", fontPattern(family, style)).Output()
	if err != nil {
		return nil
	}
	return parseFontMatches(out)
}

func findSystemFallbackFonts(family string, r rune) []fontMatch {
	generic := "sans-serif"
	lower := strings.ToLower(family)
	if strings.Contains(lower, "mono") ||
		strings.Contains(lower, "courier") ||
		strings.Contains(lower, "consolas") ||
		strings.Contains(lower, "fixed") {
		generic = "monospace"
	}
	return runFcMatchAll(generic+":charset="+strconv.FormatInt(int64(r), 16), "")
}

func fallbackFont() fontMatch {
	if match := runFcMatch("sans-serif", "Regular"); match.path != "" {
		return match
	}
	for _, p := range []string{
		"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
		"/usr/share/fonts/TTF/DejaVuSans.ttf",
		"/usr/share/fonts/noto/NotoSans-Regular.ttf",
		"/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
	} {
		if _, err := os.Stat(p); err == nil {
			return fontMatch{path: p}
		}
	}
	return fontMatch{}
}
