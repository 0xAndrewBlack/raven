//go:build guest_windows

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
	"sync"

	"github.com/mirkobrombin/Raven/pkg/arch"
	"github.com/mirkobrombin/Raven/pkg/gdi"
	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"github.com/mirkobrombin/Raven/pkg/mmu"
	"github.com/mirkobrombin/Raven/pkg/ntapi"
	"github.com/mirkobrombin/Raven/pkg/vfs"
)

const (
	ofnFileMustExist   = 0x00001000
	pdReturnDC         = 0x00000100
	pdReturnIC         = 0x00000200
	pdReturnDefault    = 0x00000400
	pdPageNums         = 0x00000002
	pdNoPageNums       = 0x00000008
	pdUseDevModeCopies = 0x00040000
	dmCopies           = 0x00000100
	sFalse             = 0x00000001
	eNotImpl           = 0x80004001
)

type printDialogLayout struct {
	size            uint32
	hDevModeOffset  uint64
	hDevNamesOffset uint64
	hDCOffset       uint64
	flagsOffset     uint64
	copiesOffset    uint64
	pointerSize     uint64
}

func printDialogStructLayout(is64 bool) printDialogLayout {
	if is64 {
		return printDialogLayout{size: 120, hDevModeOffset: 16, hDevNamesOffset: 24, hDCOffset: 32, flagsOffset: 40, copiesOffset: 52, pointerSize: 8}
	}
	return printDialogLayout{size: 66, hDevModeOffset: 8, hDevNamesOffset: 12, hDCOffset: 16, flagsOffset: 20, copiesOffset: 32, pointerSize: 4}
}

func readDialogPointer(mem *mmu.MMU, addr uint64, size uint64) uint64 {
	if size == 8 {
		value, _ := mem.Read64(addr)
		return value
	}
	value, _ := mem.Read32(addr)
	return uint64(value)
}

func writeDialogPointer(mem *mmu.MMU, addr uint64, size uint64, value uint64) {
	if size == 8 {
		mem.Write64(addr, value)
		return
	}
	mem.Write32(addr, uint32(value))
}

func writePrintDialogString(mem *mmu.MMU, addr uint64, value string, wide bool) uint64 {
	if wide {
		for i, r := range []rune(value) {
			mem.Write16(addr+uint64(i)*2, uint16(r))
		}
		mem.Write16(addr+uint64(len([]rune(value)))*2, 0)
		return uint64(len([]rune(value)) + 1)
	}
	for i := range value {
		mem.Write8(addr+uint64(i), value[i])
	}
	mem.Write8(addr+uint64(len(value)), 0)
	return uint64(len(value) + 1)
}

func allocPrintDevMode(hctx *HandlerCtx, wide bool) uint64 {
	size := uint64(156)
	nameBytes := uint64(32)
	if wide {
		size = 220
		nameBytes = 64
	}
	addr := hctx.allocGlobal(size)
	writePrintDialogString(hctx.Mem, addr, "Raven Virtual Printer", wide)
	hctx.Mem.Write16(addr+nameBytes, 0x0401)
	hctx.Mem.Write16(addr+nameBytes+2, 1)
	hctx.Mem.Write16(addr+nameBytes+4, uint16(size))
	return addr
}

func printDevModeCopies(mem *mmu.MMU, addr uint64, wide bool) uint16 {
	if addr == 0 {
		return 0
	}
	offset := uint64(54)
	if wide {
		offset = 86
	}
	copies, _ := mem.Read16(addr + offset)
	return copies
}

func setPrintDevModeCopies(mem *mmu.MMU, addr uint64, wide bool, copies uint16) {
	fieldsOffset, copiesOffset := uint64(40), uint64(54)
	if wide {
		fieldsOffset, copiesOffset = 72, 86
	}
	fields, _ := mem.Read32(addr + fieldsOffset)
	mem.Write32(addr+fieldsOffset, fields|dmCopies)
	mem.Write16(addr+copiesOffset, copies)
}

func allocPrintDevNames(hctx *HandlerCtx, wide bool) uint64 {
	values := []string{"Raven", "Raven Virtual Printer", "FILE:"}
	headerChars := uint64(8)
	if wide {
		headerChars = 4
	}
	chars := headerChars
	for _, value := range values {
		chars += uint64(len(value) + 1)
	}
	charSize := uint64(1)
	if wide {
		charSize = 2
	}
	addr := hctx.allocGlobal(chars * charSize)
	offset := headerChars
	for i, value := range values {
		hctx.Mem.Write16(addr+uint64(i)*2, uint16(offset))
		offset += writePrintDialogString(hctx.Mem, addr+offset*charSize, value, wide)
	}
	hctx.Mem.Write16(addr+6, 1)
	return addr
}

type dialogFilter struct {
	name     string
	patterns []string
}

var (
	portalHandleRE = regexp.MustCompile(`objectpath '([^']+)'`)
	portalURIRE    = regexp.MustCompile(`file://[^"'>\]\s]+`)
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

func prepareDialogGuestFile(hctx *HandlerCtx, fs *vfs.VFS, hostPath, guestPath string, saving bool) error {
	if hctx == nil || fs == nil {
		return fmt.Errorf("dialog filesystem is unavailable")
	}
	vfsPath := winPathToVFS(guestPath)
	fs.MkdirAll(filepath.Dir(vfsPath))
	if saving {
		if err := os.MkdirAll(filepath.Dir(hostPath), 0755); err != nil {
			return err
		}
	}
	data, err := os.ReadFile(hostPath)
	if err != nil {
		if !saving || !os.IsNotExist(err) {
			return err
		}
		data = nil
	}
	if err := fs.CreateFile(vfsPath, data, 0644); err != nil {
		return err
	}
	hctx.bindHostSavePath(vfsPath, hostPath)
	return nil
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
	monitorPath, err := exec.LookPath("dbus-monitor")
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithCancel(context.Background())
	monitor := exec.CommandContext(ctx, monitorPath, "--session", "--monitor",
		"type='signal',interface='org.freedesktop.portal.Request',member='Response'")
	stdout, err := monitor.StdoutPipe()
	if err != nil {
		cancel()
		return "", false
	}
	monitor.Stderr = os.Stderr
	if err := monitor.Start(); err != nil {
		cancel()
		ravelog.Logf("[comdlg32] portal monitor start failed: %v\n", err)
		return "", false
	}
	defer func() {
		cancel()
		_ = monitor.Wait()
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	if !scanner.Scan() {
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
	ravelog.Logf("[comdlg32] portal %s handle=%s\n", method, match[1])

	chosen, ok := scanPortalResponse(scanner, match[1])
	if scanErr := scanner.Err(); scanErr != nil {
		ravelog.Logf("[comdlg32] portal monitor failed: %v\n", scanErr)
	}
	return chosen, ok
}

func scanPortalResponse(scanner *bufio.Scanner, handle string) (string, bool) {
	matched := false
	accepted := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "signal ") {
			if matched {
				return "", false
			}
			matched = strings.Contains(line, "path="+handle+";") &&
				strings.Contains(line, "interface=org.freedesktop.portal.Request;") &&
				strings.Contains(line, "member=Response")
			continue
		}
		if !matched {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == "uint32" {
			accepted = fields[1] == "0"
			if !accepted {
				return "", false
			}
			continue
		}
		if accepted {
			if uri := portalURIRE.FindString(line); uri != "" {
				decoded, err := url.PathUnescape(strings.TrimPrefix(uri, "file://"))
				return decoded, err == nil && decoded != ""
			}
		}
	}
	return "", false
}

func findDialogTool() string {
	if os.Getenv("GOVM_NO_DIALOGS") != "" {
		return ""
	}
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

func fileDialogOverride() (string, bool) {
	path := strings.TrimSpace(os.Getenv("RAVEN_FILE_DIALOG_PATH"))
	return path, path != ""
}

func openFileDialog(initialDir string, filters []dialogFilter, title string) (string, bool) {
	if result, ok := fileDialogOverride(); ok {
		return result, true
	}
	tool := findDialogTool()
	switch filepath.Base(tool) {
	case "zenity":
		args := []string{"--file-selection"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		if dir := normalizeDialogHostPath(initialDir); dir != "" {
			args = append(args, "--filename="+dir+string(os.PathSeparator))
		}
		args = append(args, buildZenityFilters(filters)...)
		return runDialogCommand(tool, args...)
	case "kdialog":
		dir := normalizeDialogHostPath(initialDir)
		if dir == "" {
			dir = "."
		}
		args := []string{"--getopenfilename", dir}
		if filter := buildKDialogFilter(filters); filter != "" {
			args = append(args, filter)
		}
		return runDialogCommand(tool, args...)
	case "yad":
		args := []string{"--file"}
		if title != "" {
			args = append(args, "--title="+title)
		}
		if dir := normalizeDialogHostPath(initialDir); dir != "" {
			args = append(args, "--filename="+dir+string(os.PathSeparator))
		}
		return runDialogCommand(tool, args...)
	default:
		return runPortalFileChooser("OpenFile", title, filters, initialDir, "")
	}
}

func saveFileDialog(initialDir string, filters []dialogFilter, title, defaultName string) (string, bool) {
	if result, ok := fileDialogOverride(); ok {
		return result, true
	}
	tool := findDialogTool()
	switch filepath.Base(tool) {
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
		return runDialogCommand(tool, args...)
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
		return runDialogCommand(tool, args...)
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
		return runDialogCommand(tool, args...)
	default:
		return runPortalFileChooser("SaveFile", title, filters, initialDir, defaultName)
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
	if value, exists := os.LookupEnv("RAVEN_COLOR_DIALOG_VALUE"); exists {
		value = strings.TrimSpace(value)
		if value == "" {
			return initialColor, false
		}
		return parseColorOutput(value)
	}
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
		// No dialog tool available: silently return default affirmative button.
		switch uType & 0xF {
		case 4, 3: // MB_YESNO, MB_YESNOCANCEL
			return idYes, true
		default:
			return idOK, true
		}
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
	extendedErrors := make(map[uint64]uint32)
	var extendedErrorMu sync.Mutex
	extendedErrorKey := func(ctx *ntapi.TrapContext) uint64 {
		if ctx.CPU.GetArch() == arch.ArchAMD64 {
			if cpu, ok := ctx.CPU.(interface{ GetGSBase() uint64 }); ok {
				return cpu.GetGSBase()
			}
		}
		return ctx.CPU.GetTLS()
	}
	setExtendedError := func(ctx *ntapi.TrapContext, value uint32) {
		extendedErrorMu.Lock()
		extendedErrors[extendedErrorKey(ctx)] = value
		extendedErrorMu.Unlock()
	}
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
		if err := prepareDialogGuestFile(hctx, ctx.FS, result, guestResult, saving); err != nil {
			ravelog.Logf("[comdlg32] %sW cannot prepare %q: %v\n", title, result, err)
			ctx.SetReturn(0)
			return
		}
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
		if err := prepareDialogGuestFile(hctx, ctx.FS, result, guestResult, saving); err != nil {
			ravelog.Logf("[comdlg32] %sA cannot prepare %q: %v\n", title, result, err)
			ctx.SetReturn(0)
			return
		}
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

	printDialog := func(ctx *ntapi.TrapContext, wide bool) uint32 {
		setExtendedError(ctx, 0)
		pPD := ctx.Arg(0)
		if pPD == 0 {
			setExtendedError(ctx, 1) // CDERR_STRUCTSIZE
			ctx.SetReturn(0)
			return 0
		}
		layout := printDialogStructLayout(ctx.CPU.GetArch() != arch.ArchI386)
		structSize, _ := mem.Read32(pPD)
		if structSize != layout.size {
			setExtendedError(ctx, 1) // CDERR_STRUCTSIZE
			ctx.SetReturn(0)
			return 0
		}
		flags, _ := mem.Read32(pPD + layout.flagsOffset)
		outputPath := strings.TrimSpace(os.Getenv("RAVEN_PRINT_OUTPUT"))
		if outputPath == "" {
			outputPath = "raven-print.png"
		}
		hDevMode := readDialogPointer(mem, pPD+layout.hDevModeOffset, layout.pointerSize)
		hDevNames := readDialogPointer(mem, pPD+layout.hDevNamesOffset, layout.pointerSize)
		copies, _ := mem.Read16(pPD + layout.copiesOffset)
		if flags&pdUseDevModeCopies != 0 {
			if devModeCopies := printDevModeCopies(mem, hDevMode, wide); devModeCopies != 0 {
				copies = devModeCopies
			}
		}
		if copies == 0 {
			copies = 1
		}
		if flags&pdReturnDefault != 0 && (hDevMode != 0 || hDevNames != 0) {
			setExtendedError(ctx, 0x1003) // PDERR_RETDEFFAILURE
			ctx.SetReturn(0)
			return 0
		}
		if flags&pdReturnDefault == 0 {
			result := strings.ToLower(strings.TrimSpace(os.Getenv("RAVEN_PRINT_DIALOG_RESULT")))
			if result != "" && result != "1" && result != "ok" && result != "print" {
				ravelog.Logf("[comdlg32] PrintDlg cancelled\n")
				ctx.SetReturn(0)
				return 0
			}
			if result == "" {
				if !hctx.PrintDialogMu.TryLock() {
					setExtendedError(ctx, 0x1009) // PDERR_CREATEFAILURE
					ctx.SetReturn(0)
					return 0
				}
				defer hctx.PrintDialogMu.Unlock()
				ownerOffset := uint64(4)
				if layout.pointerSize == 8 {
					ownerOffset = 8
				}
				owner := readDialogPointer(mem, pPD+ownerOffset, layout.pointerSize)
				if owner == 0 {
					owner = hctx.MainHWND
				}
				fromPage, _ := mem.Read16(pPD + layout.flagsOffset + 4)
				toPage, _ := mem.Read16(pPD + layout.flagsOffset + 6)
				minPage, _ := mem.Read16(pPD + layout.flagsOffset + 8)
				maxPage, _ := mem.Read16(pPD + layout.flagsOffset + 10)
				if minPage == 0 {
					minPage = 1
				}
				if maxPage < minPage {
					maxPage = 0xffff
				}
				if fromPage < minPage || fromPage > maxPage {
					fromPage = minPage
				}
				if toPage < fromPage || toPage > maxPage {
					toPage = fromPage
				}
				dlgHWND := hctx.HwndAlloc()
				hctx.HwndChildren[dlgHWND] = &controlState{
					className:  "dialog",
					parentHWND: owner,
					visible:    true,
					showCalled: true,
					text:       "Print",
					w:          520,
					h:          360,
				}
				hctx.PrintDialog = &PrintDialogState{
					DlgHWND:        dlgHWND,
					OwnerHWND:      owner,
					OutputPath:     outputPath,
					AllPages:       flags&pdPageNums == 0 || flags&pdNoPageNums != 0,
					FromPage:       fromPage,
					ToPage:         toPage,
					MinPage:        minPage,
					MaxPage:        maxPage,
					AllowPageRange: flags&pdNoPageNums == 0,
					Copies:         copies,
				}
				if hctx.RequestWindowRepaint != nil {
					hctx.RequestWindowRepaint(dlgHWND)
				}
				if hctx.WlWindows[dlgHWND] == nil {
					delete(hctx.HwndChildren, dlgHWND)
					hctx.PrintDialog = nil
					setExtendedError(ctx, 0x1009) // PDERR_CREATEFAILURE
					ctx.SetReturn(0)
					return 0
				}
				ravelog.Logf("[comdlg32] PrintDlg dialog hwnd=0x%x owner=0x%x\n", dlgHWND, owner)
				for hctx.PrintDialog != nil && hctx.PrintDialog.Result == 0 {
					if hctx.PumpWaylandOnce == nil {
						hctx.PrintDialog.Result = 2
						break
					}
					if !hctx.PumpWaylandOnce() {
						hctx.PrintDialog.Result = 2
						setExtendedError(ctx, 0x100E) // CDERR_DIALOGFAILURE
					}
				}
				accepted := hctx.PrintDialog != nil && hctx.PrintDialog.Result == 1
				if accepted {
					copies = hctx.PrintDialog.Copies
					mem.Write16(pPD+layout.flagsOffset+4, hctx.PrintDialog.FromPage)
					mem.Write16(pPD+layout.flagsOffset+6, hctx.PrintDialog.ToPage)
					if hctx.PrintDialog.AllPages {
						flags &^= pdPageNums
					} else {
						flags |= pdPageNums
					}
					mem.Write32(pPD+layout.flagsOffset, flags)
				}
				if hctx.DestroyOwnedDialog != nil {
					hctx.DestroyOwnedDialog(dlgHWND)
				}
				delete(hctx.HwndChildren, dlgHWND)
				hctx.PrintDialog = nil
				if !accepted {
					ravelog.Logf("[comdlg32] PrintDlg dialog cancelled\n")
					ctx.SetReturn(0)
					return 0
				}
			}
		}
		if flags&(pdReturnDC|pdReturnIC) != 0 && hctx.GdiMgr == nil {
			setExtendedError(ctx, 0x1008) // PDERR_NODEVICES
			ctx.SetReturn(0)
			return 0
		}
		if hDevMode == 0 {
			hDevMode = allocPrintDevMode(hctx, wide)
			writeDialogPointer(mem, pPD+layout.hDevModeOffset, layout.pointerSize, hDevMode)
		}
		if hDevNames == 0 {
			hDevNames = allocPrintDevNames(hctx, wide)
			writeDialogPointer(mem, pPD+layout.hDevNamesOffset, layout.pointerSize, hDevNames)
		}
		if flags&pdUseDevModeCopies != 0 {
			setPrintDevModeCopies(mem, hDevMode, wide, copies)
			mem.Write16(pPD+layout.copiesOffset, 1)
		} else {
			mem.Write16(pPD+layout.copiesOffset, copies)
		}
		if flags&(pdReturnDC|pdReturnIC) != 0 {
			hDC, dc := hctx.GdiMgr.AllocMemDC()
			if hDC == 0 || dc == nil {
				setExtendedError(ctx, 0x1008) // PDERR_NODEVICES
				ctx.SetReturn(0)
				return 0
			}
			dc.Target = gdi.NewSurface(1240, 1754)
			dc.InfoOnly = flags&pdReturnIC != 0 && flags&pdReturnDC == 0
			dc.Target.FillRect(0, 0, dc.Target.Width, dc.Target.Height, 0xFFFFFF)
			dc.ClipX0, dc.ClipY0 = 0, 0
			dc.ClipX1, dc.ClipY1 = dc.Target.Width, dc.Target.Height
			writeDialogPointer(mem, pPD+layout.hDCOffset, layout.pointerSize, hDC)
			hctx.PrintJobsMu.Lock()
			if hctx.PrintJobs == nil {
				hctx.PrintJobs = make(map[uint64]*printJobState)
			}
			hctx.PrintJobs[hDC] = &printJobState{
				outputPath: outputPath,
				infoOnly:   dc.InfoOnly,
				copies:     copies,
			}
			hctx.PrintJobsMu.Unlock()
		}
		structCopies, _ := mem.Read16(pPD + layout.copiesOffset)
		ravelog.Logf("[comdlg32] PrintDlg accepted flags=0x%x copies=%d nCopies=%d devmode=0x%x devnames=0x%x\n", flags, copies, structCopies, hDevMode, hDevNames)
		ctx.SetReturn(1)
		return 0
	}

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgW", func(ctx *ntapi.TrapContext) uint32 {
		return printDialog(ctx, true)
	})

	d.RegisterAutoStubHandler(comdlg32, "PrintDlgA", func(ctx *ntapi.TrapContext) uint32 {
		return printDialog(ctx, false)
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

	// FINDREPLACEW 64-bit layout:
	//   +0  lStructSize (4), +4 pad(4), +8 hwndOwner(8), +16 hInstance(8)
	//   +24 Flags(4), +28 pad(4), +32 lpstrFindWhat(8), +40 lpstrReplaceWith(8)
	//   +48 wFindWhatLen(2), +50 wReplaceWithLen(2), +52 pad(4)  total=80
	openFindReplaceDialog := func(ctx *ntapi.TrapContext, isReplace bool) uint32 {
		pfr := ctx.Arg(0)
		if pfr == 0 {
			ctx.SetReturn(0)
			return 0
		}
		ownerHWND, _ := mem.Read64(pfr + 8)
		if ownerHWND == 0 {
			ownerHWND = hctx.MainHWND
		}
		lpstrFindWhat, _ := mem.Read64(pfr + 32)
		wFindWhatLen16, _ := mem.Read16(pfr + 48)
		lpstrReplaceWith, _ := mem.Read64(pfr + 40)
		wReplaceWithLen16, _ := mem.Read16(pfr + 50)

		// Read initial search text if the buffer already contains something.
		initFind := ""
		if lpstrFindWhat != 0 && wFindWhatLen16 > 0 {
			initFind = readGuestUTF16(lpstrFindWhat)
		}

		// Register (or look up) the FINDMSGSTRING message ID.
		// Both FindTextW and the host app call RegisterWindowMessage("commdlg_FindReplace").
		const findMsgName = "commdlg_FindReplace"
		msgID, hasMsgID := hctx.RegisteredMsgNames[findMsgName]
		if !hasMsgID {
			msgID = hctx.NextMsgID
			hctx.NextMsgID++
			hctx.RegisteredMsgNames[findMsgName] = msgID
		}

		// Allocate the modeless owned dialog HWND returned to the application.
		dlgHwnd := hctx.HwndAlloc()
		dlgW := int32(380)
		dlgH := int32(130)
		title := "Find"
		if isReplace {
			dlgH = 160
			title = "Replace"
		}
		cs := &controlState{
			className:  "dialog",
			parentHWND: ownerHWND,
			visible:    true,
			showCalled: true,
			text:       title,
			w:          dlgW,
			h:          dlgH,
		}
		hctx.HwndChildren[dlgHwnd] = cs

		hctx.FindDialog = &FindDialogState{
			DlgHWND:          dlgHwnd,
			OwnerHWND:        ownerHWND,
			PFR:              pfr,
			LpstrFindWhat:    lpstrFindWhat,
			FindWhatLen:      wFindWhatLen16,
			LpstrReplaceWith: lpstrReplaceWith,
			ReplaceWithLen:   wReplaceWithLen16,
			MsgID:            msgID,
			IsReplace:        isReplace,
			FindText:         initFind,
			SearchDown:       true,
		}

		label := map[bool]string{false: "FindTextW", true: "ReplaceTextW"}[isReplace]
		ravelog.Logf("[comdlg32] %s owner=0x%x dlgHwnd=0x%x msgID=0x%x\n",
			label, ownerHWND, dlgHwnd, msgID)

		if hctx.RequestWindowRepaint != nil {
			hctx.RequestWindowRepaint(dlgHwnd)
		} else {
			hctx.QueuePaint(dlgHwnd)
		}
		ctx.SetReturn(dlgHwnd)
		return 0
	}

	d.RegisterAutoStubHandler(comdlg32, "FindTextW", func(ctx *ntapi.TrapContext) uint32 {
		return openFindReplaceDialog(ctx, false)
	})

	d.RegisterAutoStubHandler(comdlg32, "FindTextA", func(ctx *ntapi.TrapContext) uint32 {
		return openFindReplaceDialog(ctx, false)
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextW", func(ctx *ntapi.TrapContext) uint32 {
		return openFindReplaceDialog(ctx, true)
	})

	d.RegisterAutoStubHandler(comdlg32, "ReplaceTextA", func(ctx *ntapi.TrapContext) uint32 {
		return openFindReplaceDialog(ctx, true)
	})

	d.RegisterAutoStubHandler(comdlg32, "CommDlgExtendedError", func(ctx *ntapi.TrapContext) uint32 {
		extendedErrorMu.Lock()
		value := extendedErrors[extendedErrorKey(ctx)]
		extendedErrorMu.Unlock()
		ctx.SetReturn(uint64(value))
		return 0
	})

	_ = sFalse
}
