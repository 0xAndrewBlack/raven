package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

const (
	ofnFileMustExist = 0x00001000
	sFalse           = 0x00000001
	eNotImpl         = 0x80004001
)

type dialogFilter struct {
	name     string
	patterns []string
}

var (
	portalHandleRE = regexp.MustCompile(`objectpath '([^']+)'`)
	portalURIRE    = regexp.MustCompile(`file://[^'>\]\s]+`)
	rgbColorRE     = regexp.MustCompile(`rgb\(\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*\)`)
	hexColorRE     = regexp.MustCompile(`(?i)#?([0-9a-f]{6})`)
	fontSizeRE     = regexp.MustCompile(`\s+([0-9]+(?:\.[0-9]+)?)\s*$`)
)

func parseDialogFilters(items []string) []dialogFilter {
	if len(items) == 0 {
		return nil
	}
	filters := make([]dialogFilter, 0, len(items)/2)
	for i := 0; i+1 < len(items); i += 2 {
		name := strings.TrimSpace(items[i])
		patternText := strings.TrimSpace(items[i+1])
		if patternText == "" {
			continue
		}
		patternText = strings.ReplaceAll(patternText, "|", ";")
		rawPatterns := strings.Split(patternText, ";")
		patterns := make([]string, 0, len(rawPatterns))
		for _, pattern := range rawPatterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			if pattern == "*.*" {
				pattern = "*"
			}
			patterns = append(patterns, pattern)
		}
		if len(patterns) == 0 {
			continue
		}
		if name == "" {
			name = strings.Join(patterns, " ")
		}
		filters = append(filters, dialogFilter{name: name, patterns: patterns})
	}
	return filters
}

func normalizeDialogHostPath(pathValue string) string {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return ""
	}
	if strings.HasPrefix(pathValue, "file://") {
		if decoded, err := url.PathUnescape(strings.TrimPrefix(pathValue, "file://")); err == nil && decoded != "" {
			pathValue = decoded
		}
	}
	if strings.Contains(pathValue, `\`) || (len(pathValue) >= 2 && pathValue[1] == ':') {
		return winToLinuxPath(pathValue)
	}
	return filepath.Clean(pathValue)
}

func normalizeDialogGuestPath(pathValue string) string {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return ""
	}
	if strings.HasPrefix(pathValue, "file://") {
		if decoded, err := url.PathUnescape(strings.TrimPrefix(pathValue, "file://")); err == nil && decoded != "" {
			pathValue = decoded
		}
	}
	if strings.Contains(pathValue, `\`) || (len(pathValue) >= 2 && pathValue[1] == ':') {
		return pathValue
	}
	if filepath.IsAbs(pathValue) {
		return linuxToWinPath(pathValue)
	}
	return pathValue
}

func formatGVariantString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func formatGVariantByteArray(value string) string {
	b := append([]byte(value), 0)
	parts := make([]string, 0, len(b))
	for _, v := range b {
		parts = append(parts, fmt.Sprintf("byte %d", v))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func formatPortalFilters(filters []dialogFilter) string {
	if len(filters) == 0 {
		return ""
	}
	items := make([]string, 0, len(filters))
	for _, filter := range filters {
		patterns := make([]string, 0, len(filter.patterns))
		for _, pattern := range filter.patterns {
			patterns = append(patterns, fmt.Sprintf("(uint32 0, %s)", formatGVariantString(pattern)))
		}
		if len(patterns) == 0 {
			continue
		}
		items = append(items, fmt.Sprintf("(%s, [%s])", formatGVariantString(filter.name), strings.Join(patterns, ", ")))
	}
	if len(items) == 0 {
		return ""
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func buildPortalOptions(filters []dialogFilter, initialDir, defaultName string) string {
	entries := []string{"'modal': <true>"}
	if initialDir != "" {
		entries = append(entries, "'current_folder': <"+formatGVariantByteArray(normalizeDialogHostPath(initialDir))+">")
	}
	if defaultName != "" {
		entries = append(entries, "'current_name': <"+formatGVariantString(filepath.Base(defaultName))+">")
	}
	if filterText := formatPortalFilters(filters); filterText != "" {
		entries = append(entries, "'filters': <"+filterText+">")
	}
	return "{" + strings.Join(entries, ", ") + "}"
}

func runPortalFileChooser(method, title string, filters []dialogFilter, initialDir, defaultName string) (string, bool) {
	gdbusPath, err := exec.LookPath("gdbus")
	if err != nil {
		return "", false
	}
	options := buildPortalOptions(filters, initialDir, defaultName)
	callArgs := []string{
		"call",
		"--session",
		"--dest", "org.freedesktop.portal.Desktop",
		"--object-path", "/org/freedesktop/portal/desktop",
		"--method", "org.freedesktop.portal.FileChooser." + method,
		"",
		title,
		options,
	}
	out, err := exec.Command(gdbusPath, callArgs...).CombinedOutput()
	if err != nil {
		ravelog.Logf("[comdlg32] portal %s failed: %v (%s)\n", method, err, strings.TrimSpace(string(out)))
		return "", false
	}
	match := portalHandleRE.FindStringSubmatch(string(out))
	if len(match) < 2 {
		ravelog.Logf("[comdlg32] portal %s returned unexpected handle: %s\n", method, strings.TrimSpace(string(out)))
		return "", false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitorArgs := []string{
		"monitor",
		"--session",
		"--dest", "org.freedesktop.portal.Desktop",
		"--object-path", match[1],
	}
	cmd := exec.CommandContext(ctx, gdbusPath, monitorArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", false
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		ravelog.Logf("[comdlg32] portal monitor start failed: %v\n", err)
		return "", false
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	var chosen string
	var ok bool
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "org.freedesktop.portal.Request.Response") {
			continue
		}
		if strings.Contains(line, "(uint32 0,") {
			if uri := portalURIRE.FindString(line); uri != "" {
				if decoded, err := url.PathUnescape(strings.TrimPrefix(uri, "file://")); err == nil {
					chosen = decoded
					ok = true
				}
			}
		}
		break
	}
	cancel()
	_ = cmd.Wait()
	if scanErr := scanner.Err(); scanErr != nil {
		ravelog.Logf("[comdlg32] portal monitor failed: %v\n", scanErr)
	}
	return chosen, ok
}

func findDialogTool() string {
	for _, tool := range []string{"zenity", "kdialog", "yad"} {
		if p, err := exec.LookPath(tool); err == nil {
			return p
		}
	}
	return ""
}

func buildZenityFilters(filters []dialogFilter) []string {
	args := make([]string, 0, len(filters))
	for _, filter := range filters {
		if len(filter.patterns) == 0 {
			continue
		}
		args = append(args, "--file-filter="+filter.name+" | "+strings.Join(filter.patterns, " "))
	}
	return args
}

func buildKDialogFilter(filters []dialogFilter) string {
	if len(filters) == 0 {
		return ""
	}
	lines := make([]string, 0, len(filters))
	for _, filter := range filters {
		if len(filter.patterns) == 0 {
			continue
		}
		lines = append(lines, strings.Join(filter.patterns, " ")+" | "+filter.name)
	}
	return strings.Join(lines, "\n")
}

func runDialogCommand(tool string, args ...string) (string, bool) {
	if tool == "" {
		return "", false
	}
	out, err := exec.Command(tool, args...).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func openFileDialog(initialDir string, filters []dialogFilter, title string) (string, bool) {
	if result, ok := runPortalFileChooser("OpenFile", title, filters, initialDir, ""); ok {
		return result, true
	}
	switch filepath.Base(findDialogTool()) {
	case "zenity":
		args := []string{"--file-selection"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		if dir := normalizeDialogHostPath(initialDir); dir != "" {
			args = append(args, "--filename="+dir+string(os.PathSeparator))
		}
		args = append(args, buildZenityFilters(filters)...)
		return runDialogCommand(findDialogTool(), args...)
	case "kdialog":
		dir := normalizeDialogHostPath(initialDir)
		if dir == "" {
			dir = "."
		}
		args := []string{"--getopenfilename", dir}
		if filter := buildKDialogFilter(filters); filter != "" {
			args = append(args, filter)
		}
		return runDialogCommand(findDialogTool(), args...)
	case "yad":
		args := []string{"--file"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		if dir := normalizeDialogHostPath(initialDir); dir != "" {
			args = append(args, "--filename="+dir+string(os.PathSeparator))
		}
		return runDialogCommand(findDialogTool(), args...)
	default:
		return "", false
	}
}

func saveFileDialog(initialDir string, filters []dialogFilter, title, defaultName string) (string, bool) {
	if result, ok := runPortalFileChooser("SaveFile", title, filters, initialDir, defaultName); ok {
		return result, true
	}
	switch filepath.Base(findDialogTool()) {
	case "zenity":
		args := []string{"--file-selection", "--save", "--confirm-overwrite"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		filename := normalizeDialogHostPath(defaultName)
		if filename == "" && defaultName != "" {
			filename = filepath.Base(defaultName)
		}
		if filename == "" {
			filename = normalizeDialogHostPath(initialDir)
		}
		if filename != "" {
			if info, err := os.Stat(filename); err == nil && info.IsDir() {
				filename = filepath.Join(filename, "")
			}
			args = append(args, "--filename="+filename)
		}
		args = append(args, buildZenityFilters(filters)...)
		return runDialogCommand(findDialogTool(), args...)
	case "kdialog":
		filename := normalizeDialogHostPath(defaultName)
		if filename == "" {
			if dir := normalizeDialogHostPath(initialDir); dir != "" {
				filename = filepath.Join(dir, filepath.Base(defaultName))
			}
		}
		if filename == "" {
			filename = "."
		}
		args := []string{"--getsavefilename", filename}
		if filter := buildKDialogFilter(filters); filter != "" {
			args = append(args, filter)
		}
		return runDialogCommand(findDialogTool(), args...)
	case "yad":
		args := []string{"--file", "--save", "--confirm-overwrite"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		filename := normalizeDialogHostPath(defaultName)
		if filename == "" && initialDir != "" {
			filename = filepath.Join(normalizeDialogHostPath(initialDir), filepath.Base(defaultName))
		}
		if filename != "" {
			args = append(args, "--filename="+filename)
		}
		return runDialogCommand(findDialogTool(), args...)
	default:
		return "", false
	}
}

func parseColorOutput(value string) (uint32, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if match := rgbColorRE.FindStringSubmatch(value); len(match) == 4 {
		r, _ := strconv.Atoi(match[1])
		g, _ := strconv.Atoi(match[2])
		b, _ := strconv.Atoi(match[3])
		return uint32(r&0xFF) | uint32(g&0xFF)<<8 | uint32(b&0xFF)<<16, true
	}
	if match := hexColorRE.FindStringSubmatch(value); len(match) == 2 {
		parsed, err := strconv.ParseUint(match[1], 16, 32)
		if err != nil {
			return 0, false
		}
		r := uint32((parsed >> 16) & 0xFF)
		g := uint32((parsed >> 8) & 0xFF)
		b := uint32(parsed & 0xFF)
		return r | (g << 8) | (b << 16), true
	}
	return 0, false
}

func colorDialog(initialColor uint32) (uint32, bool) {
	tool := findDialogTool()
	if tool == "" {
		return 0, false
	}
	r := initialColor & 0xFF
	g := (initialColor >> 8) & 0xFF
	b := (initialColor >> 16) & 0xFF
	initHex := fmt.Sprintf("#%02x%02x%02x", r, g, b)
	switch filepath.Base(tool) {
	case "zenity":
		if out, ok := runDialogCommand(tool, "--color-selection", "--show-palette", "--color="+initHex); ok {
			return parseColorOutput(out)
		}
	case "kdialog":
		if out, ok := runDialogCommand(tool, "--getcolor", initHex); ok {
			return parseColorOutput(out)
		}
	case "yad":
		if out, ok := runDialogCommand(tool, "--color", "--init-color="+initHex); ok {
			return parseColorOutput(out)
		}
	}
	return 0, false
}

func parseFontOutput(value string) (string, int32, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, false
	}
	size := int32(10)
	name := value
	if match := fontSizeRE.FindStringSubmatch(value); len(match) == 2 {
		if parsed, err := strconv.ParseFloat(match[1], 64); err == nil {
			size = int32(parsed + 0.5)
		}
		name = strings.TrimSpace(value[:len(value)-len(match[0])])
	}
	if name == "" {
		name = value
	}
	return name, size, true
}

func fontDialog() (string, int32, bool) {
	tool := findDialogTool()
	if tool == "" {
		return "", 0, false
	}
	switch filepath.Base(tool) {
	case "zenity":
		if out, ok := runDialogCommand(tool, "--font-selection"); ok {
			return parseFontOutput(out)
		}
	case "yad":
		if out, ok := runDialogCommand(tool, "--font"); ok {
			return parseFontOutput(out)
		}
	}
	return "", 0, false
}

func hostMessageBox(title, text string, uType uint32) (int, bool) {
	const (
		mbOK           = 0
		mbOKCancel     = 1
		mbYesNoCancel  = 3
		mbYesNo        = 4
		mbIconMask     = 0xF0
		mbIconError    = 0x10
		mbIconQuestion = 0x20
		mbIconWarning  = 0x30
		idOK           = 1
		idCancel       = 2
		idNo           = 7
		idYes          = 6
	)

	tool := findDialogTool()
	if tool == "" {
		return 0, false
	}
	buttons := uType & 0xF
	icon := uType & mbIconMask
	switch filepath.Base(tool) {
	case "zenity":
		switch buttons {
		case mbYesNo, mbYesNoCancel:
			args := []string{"--question", "--text=" + text}
			if title != "" {
				args = append(args, "--title="+title)
			}
			if icon == mbIconWarning {
				args = append(args, "--icon-name=dialog-warning")
			} else if icon == mbIconError {
				args = append(args, "--icon-name=dialog-error")
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idYes, true
			}
			if buttons == mbYesNo {
				return idNo, true
			}
			return idCancel, true
		case mbOKCancel:
			args := []string{"--question", "--ok-label=OK", "--cancel-label=Cancel", "--text=" + text}
			if title != "" {
				args = append(args, "--title="+title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idOK, true
			}
			return idCancel, true
		default:
			mode := "--info"
			switch icon {
			case mbIconError:
				mode = "--error"
			case mbIconWarning:
				mode = "--warning"
			case mbIconQuestion:
				mode = "--question"
			}
			args := []string{mode, "--text=" + text}
			if title != "" {
				args = append(args, "--title="+title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil || mode == "--question" {
				if err == nil {
					return idOK, true
				}
				return idCancel, true
			}
		}
	case "kdialog":
		switch buttons {
		case mbYesNoCancel:
			args := []string{"--yesnocancel", text}
			if title != "" {
				args = append(args, "--title", title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idYes, true
			}
			return idCancel, true
		case mbYesNo:
			args := []string{"--yesno", text}
			if title != "" {
				args = append(args, "--title", title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idYes, true
			}
			return idNo, true
		case mbOKCancel:
			args := []string{"--warningcontinuecancel", text}
			if title != "" {
				args = append(args, "--title", title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idOK, true
			}
			return idCancel, true
		default:
			mode := "--msgbox"
			if icon == mbIconError {
				mode = "--error"
			} else if icon == mbIconWarning {
				mode = "--sorry"
			}
			args := []string{mode, text}
			if title != "" {
				args = append(args, "--title", title)
			}
			if err := exec.Command(tool, args...).Run(); err == nil {
				return idOK, true
			}
		}
	}
	return 0, false
}

func registerComdlg32Handlers(hctx *HandlerCtx) {
	d := hctx.Disp
	mem := hctx.Mem
	readGuestString := hctx.ReadGuestString
	readGuestUTF16 := hctx.ReadGuestUTF16
	stdinReader := hctx.StdinReader

	comdlg32, ok := hctx.SynthByName["comdlg32.dll"]
	if !ok {
		return
	}

	readANSIWithLimit := func(addr uint64, maxBytes uint32) string {
		if addr == 0 || maxBytes == 0 {
			return ""
		}
		buf := make([]byte, 0, maxBytes)
		for i := uint32(0); i < maxBytes; i++ {
			b, err := mem.Read8(addr + uint64(i))
			if err != nil || b == 0 {
				break
			}
			buf = append(buf, b)
		}
		return string(buf)
	}

	writeANSIWithLimit := func(addr uint64, maxBytes uint32, s string) bool {
		if addr == 0 || maxBytes == 0 {
			return false
		}
		b := []byte(s)
		if uint32(len(b))+1 > maxBytes {
			if maxBytes == 0 {
				return false
			}
			b = b[:maxBytes-1]
		}
		for i, c := range b {
			mem.Write8(addr+uint64(i), c)
		}
		mem.Write8(addr+uint64(len(b)), 0)
		return true
	}

	writeUTF16WithLimit := func(addr uint64, maxChars uint32, s string) bool {
		if addr == 0 || maxChars == 0 {
			return false
		}
		ws := utf16Encode(s)
		if uint32(len(ws))+1 > maxChars {
			if maxChars == 0 {
				return false
			}
			ws = ws[:maxChars-1]
		}
		for i, w := range ws {
			mem.Write16(addr+uint64(i)*2, w)
		}
		mem.Write16(addr+uint64(len(ws))*2, 0)
		return true
	}

	readFilterW := func(addr uint64) []string {
		if addr == 0 {
			return nil
		}
		items := make([]string, 0, 8)
		cur := addr
		for len(items) < 32 {
			var chars []uint16
			for {
				w, err := mem.Read16(cur)
				if err != nil {
					return items
				}
				cur += 2
				if w == 0 {
					break
				}
				chars = append(chars, w)
			}
			if len(chars) == 0 {
				break
			}
			items = append(items, string(utf16Decode(chars)))
		}
		return items
	}

	readFilterA := func(addr uint64) []string {
		if addr == 0 {
			return nil
		}
		items := make([]string, 0, 8)
		cur := addr
		for len(items) < 32 {
			var bytes []byte
			for {
				b, err := mem.Read8(cur)
				if err != nil {
					return items
				}
				cur++
				if b == 0 {
					break
				}
				bytes = append(bytes, b)
			}
			if len(bytes) == 0 {
				break
			}
			items = append(items, string(bytes))
		}
		return items
	}

	promptPath := func(dialogTitle, kind, defaultPath, initialDir string, mustExist bool) (string, bool) {
		if stdinReader == nil {
			return "", false
		}
		reader := stdinReader
		if reader == nil {
			reader = bufio.NewReader(os.Stdin)
		}
		fmt.Fprintf(os.Stderr, "[comdlg32] %s (%s)\n", dialogTitle, kind)
		if initialDir != "" {
			fmt.Fprintf(os.Stderr, "[comdlg32] initial dir: %s\n", initialDir)
		}
		if defaultPath != "" {
			fmt.Fprintf(os.Stderr, "[comdlg32] default path: %s\n", defaultPath)
		}
		if mustExist {
			fmt.Fprintln(os.Stderr, "[comdlg32] file must exist")
		}
		fmt.Fprint(os.Stderr, "[comdlg32] Enter path (blank to cancel): ")
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			return "", false
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return "", false
		}
		return line, true
	}

	normalizePath := func(pathValue, initialDir, defExt string, forSave bool) string {
		pathValue = strings.TrimSpace(pathValue)
		if pathValue == "" {
			return ""
		}
		pathValue = normalizeDialogHostPath(pathValue)
		if !filepath.IsAbs(pathValue) {
			base := initialDir
			if base == "" {
				base = "."
			}
			base = normalizeDialogHostPath(base)
			pathValue = filepath.Join(base, pathValue)
		}
		pathValue = filepath.Clean(pathValue)
		if forSave && defExt != "" && filepath.Ext(pathValue) == "" {
			ext := defExt
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			pathValue += ext
		}
		return pathValue
	}

	writeOpenFileMetadata := func(ofnPtr uint64, result string, fileTitlePtr uint64, maxFileTitle uint32, ansi bool) {
		base := filepath.Base(result)
		fileOffset := uint16(0)
		if idx := strings.LastIndexAny(result, `/\`); idx >= 0 {
			fileOffset = uint16(idx + 1)
		}
		fileExt := uint16(0)
		if dot := strings.LastIndex(base, "."); dot >= 0 {
			fileExt = uint16(int(fileOffset) + dot + 1)
		}
		mem.Write16(ofnPtr+100, fileOffset)
		mem.Write16(ofnPtr+102, fileExt)
		if fileTitlePtr != 0 && maxFileTitle > 0 {
			if ansi {
				writeANSIWithLimit(fileTitlePtr, maxFileTitle, base)
			} else {
				writeUTF16WithLimit(fileTitlePtr, maxFileTitle, base)
			}
		}
	}

	handleFileDialogW := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}

		lpstrFilter, _ := mem.Read64(pOFN + 24)
		nFilterIndex, _ := mem.Read32(pOFN + 44)
		lpstrFile, _ := mem.Read64(pOFN + 48)
		nMaxFile, _ := mem.Read32(pOFN + 56)
		lpstrFileTitle, _ := mem.Read64(pOFN + 64)
		nMaxFileTitle, _ := mem.Read32(pOFN + 72)
		lpstrInitialDir, _ := mem.Read64(pOFN + 80)
		lpstrTitle, _ := mem.Read64(pOFN + 88)
		flags, _ := mem.Read32(pOFN + 96)
		lpstrDefExt, _ := mem.Read64(pOFN + 104)

		initialDir := ""
		if lpstrInitialDir != 0 {
			initialDir = readGuestUTF16(lpstrInitialDir)
		}
		title := "Open File"
		if saving {
			title = "Save File"
		}
		if lpstrTitle != 0 {
			if s := readGuestUTF16(lpstrTitle); s != "" {
				title = s
			}
		}
		defExt := ""
		if lpstrDefExt != 0 {
			defExt = readGuestUTF16(lpstrDefExt)
		}
		currentPath := readGuestUTF16(lpstrFile)
		filterPairs := readFilterW(lpstrFilter)
		if len(filterPairs) > 0 {
			ravelog.Logf("[comdlg32] %sW filters=%v index=%d\n", title, filterPairs, nFilterIndex)
		}

		filters := parseDialogFilters(filterPairs)
		hostInitialDir := normalizeDialogHostPath(initialDir)
		hostCurrentPath := normalizeDialogHostPath(currentPath)
		hostResult := ""
		if saving {
			defaultName := hostCurrentPath
			if defaultName == "" && currentPath != "" {
				defaultName = currentPath
			}
			hostResult, _ = saveFileDialog(hostInitialDir, filters, title, defaultName)
		} else {
			hostResult, _ = openFileDialog(hostInitialDir, filters, title)
		}
		result := normalizePath(hostResult, initialDir, defExt, saving)
		if result == "" {
			prompted, ok := promptPath(title, map[bool]string{true: "save", false: "open"}[saving], currentPath, initialDir, !saving && (flags&ofnFileMustExist) != 0)
			if !ok {
				ctx.SetReturn(0)
				return
			}
			result = normalizePath(prompted, initialDir, defExt, saving)
		}
		if result == "" {
			ctx.SetReturn(0)
			return
		}
		if !saving && (flags&ofnFileMustExist) != 0 {
			if _, err := os.Stat(result); err != nil {
				ravelog.Logf("[comdlg32] %sW rejecting missing file %q: %v\n", title, result, err)
				ctx.SetReturn(0)
				return
			}
		}

		guestResult := normalizeDialogGuestPath(result)
		if !writeUTF16WithLimit(lpstrFile, nMaxFile, guestResult) {
			ctx.SetReturn(0)
			return
		}
		writeOpenFileMetadata(pOFN, guestResult, lpstrFileTitle, nMaxFileTitle, false)
		ravelog.Logf("[comdlg32] %sW selected host=%q guest=%q\n", title, result, guestResult)
		ctx.SetReturn(1)
	}

	handleFileDialogA := func(ctx *ntapi.TrapContext, saving bool) {
		pOFN := ctx.Arg(0)
		if pOFN == 0 {
			ctx.SetReturn(0)
			return
		}

		lpstrFilter, _ := mem.Read64(pOFN + 24)
		nFilterIndex, _ := mem.Read32(pOFN + 44)
		lpstrFile, _ := mem.Read64(pOFN + 48)
		nMaxFile, _ := mem.Read32(pOFN + 56)
		lpstrFileTitle, _ := mem.Read64(pOFN + 64)
		nMaxFileTitle, _ := mem.Read32(pOFN + 72)
		lpstrInitialDir, _ := mem.Read64(pOFN + 80)
		lpstrTitle, _ := mem.Read64(pOFN + 88)
		flags, _ := mem.Read32(pOFN + 96)
		lpstrDefExt, _ := mem.Read64(pOFN + 104)

		initialDir := ""
		if lpstrInitialDir != 0 {
			initialDir = readGuestString(lpstrInitialDir)
		}
		title := "Open File"
		if saving {
			title = "Save File"
		}
		if lpstrTitle != 0 {
			if s := readGuestString(lpstrTitle); s != "" {
				title = s
			}
		}
		defExt := ""
		if lpstrDefExt != 0 {
			defExt = readGuestString(lpstrDefExt)
		}
		currentPath := readANSIWithLimit(lpstrFile, nMaxFile)
		filterPairs := readFilterA(lpstrFilter)
		if len(filterPairs) > 0 {
			ravelog.Logf("[comdlg32] %sA filters=%v index=%d\n", title, filterPairs, nFilterIndex)
		}

		filters := parseDialogFilters(filterPairs)
		hostInitialDir := normalizeDialogHostPath(initialDir)
		hostCurrentPath := normalizeDialogHostPath(currentPath)
		hostResult := ""
		if saving {
			defaultName := hostCurrentPath
			if defaultName == "" && currentPath != "" {
				defaultName = currentPath
			}
			hostResult, _ = saveFileDialog(hostInitialDir, filters, title, defaultName)
		} else {
			hostResult, _ = openFileDialog(hostInitialDir, filters, title)
		}
		result := normalizePath(hostResult, initialDir, defExt, saving)
		if result == "" {
			prompted, ok := promptPath(title, map[bool]string{true: "save", false: "open"}[saving], currentPath, initialDir, !saving && (flags&ofnFileMustExist) != 0)
			if !ok {
				ctx.SetReturn(0)
				return
			}
			result = normalizePath(prompted, initialDir, defExt, saving)
		}
		if result == "" {
			ctx.SetReturn(0)
			return
		}
		if !saving && (flags&ofnFileMustExist) != 0 {
			if _, err := os.Stat(result); err != nil {
				ravelog.Logf("[comdlg32] %sA rejecting missing file %q: %v\n", title, result, err)
				ctx.SetReturn(0)
				return
			}
		}

		guestResult := normalizeDialogGuestPath(result)
		if !writeANSIWithLimit(lpstrFile, nMaxFile, guestResult) {
			ctx.SetReturn(0)
			return
		}
		writeOpenFileMetadata(pOFN, guestResult, lpstrFileTitle, nMaxFileTitle, true)
		ravelog.Logf("[comdlg32] %sA selected host=%q guest=%q\n", title, result, guestResult)
		ctx.SetReturn(1)
	}

	d.RegisterAutoStubHandler(comdlg32, "GetFileTitleW", func(ctx *ntapi.TrapContext) uint32 {
		src := readGuestUTF16(ctx.Arg(0))
		dst := ctx.Arg(1)
		cch := uint32(ctx.Arg(2))
		if dst != 0 && cch > 0 {
			writeUTF16WithLimit(dst, cch, filepath.Base(src))
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "GetFileTitleA", func(ctx *ntapi.TrapContext) uint32 {
		src := readGuestString(ctx.Arg(0))
		dst := ctx.Arg(1)
		cch := uint32(ctx.Arg(2))
		if dst != 0 && cch > 0 {
			writeANSIWithLimit(dst, cch, filepath.Base(src))
		}
		ctx.SetReturn(0)
		return 0
	})

	hctx.HandleFileDialogW = handleFileDialogW
	hctx.HandleFileDialogA = handleFileDialogA

	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogW(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameW", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogW(ctx, true)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetOpenFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogA(ctx, false)
		return 0
	})
	d.RegisterAutoStubHandler(comdlg32, "GetSaveFileNameA", func(ctx *ntapi.TrapContext) uint32 {
		handleFileDialogA(ctx, true)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseColorW", func(ctx *ntapi.TrapContext) uint32 {
		lpcc := ctx.Arg(0)
		if lpcc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rgb, _ := mem.Read32(lpcc + 24)
		lpCustColors, _ := mem.Read64(lpcc + 32)
		flags, _ := mem.Read32(lpcc + 40)
		ravelog.Logf("[comdlg32] ChooseColorW default=0x%08x cust=0x%x flags=0x%x\n", rgb, lpCustColors, flags)
		if chosen, ok := colorDialog(rgb); ok {
			mem.Write32(lpcc+24, chosen)
			ctx.SetReturn(1)
			return 0
		}
		mem.Write32(lpcc+24, rgb)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseColorA", func(ctx *ntapi.TrapContext) uint32 {
		lpcc := ctx.Arg(0)
		if lpcc == 0 {
			ctx.SetReturn(0)
			return 0
		}
		rgb, _ := mem.Read32(lpcc + 24)
		lpCustColors, _ := mem.Read64(lpcc + 32)
		flags, _ := mem.Read32(lpcc + 40)
		ravelog.Logf("[comdlg32] ChooseColorA default=0x%08x cust=0x%x flags=0x%x\n", rgb, lpCustColors, flags)
		if chosen, ok := colorDialog(rgb); ok {
			mem.Write32(lpcc+24, chosen)
			ctx.SetReturn(1)
			return 0
		}
		mem.Write32(lpcc+24, rgb)
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseFontW", func(ctx *ntapi.TrapContext) uint32 {
		lpcf := ctx.Arg(0)
		if lpcf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lpLogFont, _ := mem.Read64(lpcf + 24)
		pointSize, _ := mem.Read32(lpcf + 32)
		flags, _ := mem.Read32(lpcf + 36)
		rgbColors, _ := mem.Read32(lpcf + 40)
		ravelog.Logf("[comdlg32] ChooseFontW logfont=0x%x pointSize=%d flags=0x%x color=0x%08x\n", lpLogFont, pointSize, flags, rgbColors)
		if face, size, ok := fontDialog(); ok {
			if lpLogFont != 0 {
				mem.Write32(lpLogFont+0, uint32(^uint32(size)+1))
				writeUTF16WithLimit(lpLogFont+28, 32, face)
			}
			mem.Write32(lpcf+32, uint32(size*10))
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ChooseFontA", func(ctx *ntapi.TrapContext) uint32 {
		lpcf := ctx.Arg(0)
		if lpcf == 0 {
			ctx.SetReturn(0)
			return 0
		}
		lpLogFont, _ := mem.Read64(lpcf + 24)
		pointSize, _ := mem.Read32(lpcf + 32)
		flags, _ := mem.Read32(lpcf + 36)
		rgbColors, _ := mem.Read32(lpcf + 40)
		ravelog.Logf("[comdlg32] ChooseFontA logfont=0x%x pointSize=%d flags=0x%x color=0x%08x\n", lpLogFont, pointSize, flags, rgbColors)
		if face, size, ok := fontDialog(); ok {
			if lpLogFont != 0 {
				mem.Write32(lpLogFont+0, uint32(^uint32(size)+1))
				writeANSIWithLimit(lpLogFont+28, 32, face)
			}
			mem.Write32(lpcf+32, uint32(size*10))
			ctx.SetReturn(1)
			return 0
		}
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] PrintDlgW cancelled: no printer backend\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] PrintDlgA cancelled: no printer backend\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExW", func(ctx *ntapi.TrapContext) uint32 {
		pPD := ctx.Arg(0)
		if pPD != 0 {
			mem.Write32(pPD+72, 0) // dwResultAction = PD_RESULT_CANCEL for current struct assumption
		}
		ctx.SetReturn(eNotImpl)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgExA", func(ctx *ntapi.TrapContext) uint32 {
		pPD := ctx.Arg(0)
		if pPD != 0 {
			mem.Write32(pPD+72, 0)
		}
		ctx.SetReturn(eNotImpl)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgW", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "PageSetupDlgA", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "FindTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] FindTextW unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "FindTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] FindTextA unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextW", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] ReplaceTextW unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextA", func(ctx *ntapi.TrapContext) uint32 {
		ravelog.Logf("[comdlg32] ReplaceTextA unsupported modeless dialog\n")
		ctx.SetReturn(0)
		return 0
	})

	d.RegisterAutoStubHandler(comdlg32, "CommDlgExtendedError", func(ctx *ntapi.TrapContext) uint32 {
		ctx.SetReturn(0)
		return 0
	})

	_ = sFalse
}
