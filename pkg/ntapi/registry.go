package ntapi

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
)

// Registry value types.
const (
	RegNone              uint32 = 0
	RegSZ                uint32 = 1  // null-terminated UTF-16LE string
	RegExpandSZ          uint32 = 2  // expandable string
	RegBinary            uint32 = 3  // binary data
	RegDWORD             uint32 = 4  // 32-bit integer
	RegDWORDBigEndian    uint32 = 5
	RegLink              uint32 = 6
	RegMultiSZ           uint32 = 7  // double-null-terminated string list
	RegQWORD             uint32 = 11 // 64-bit integer
)

// RegistryValue holds a single registry value.
type RegistryValue struct {
	Name string `json:"name"`
	Type uint32 `json:"type"`
	Data []byte `json:"data"`
}

// RegistryKey is a node in the registry tree.
type RegistryKey struct {
	Name     string                    `json:"name"`
	Children map[string]*RegistryKey   `json:"children,omitempty"`
	Values   map[string]*RegistryValue `json:"values,omitempty"`
}

// RegistryHive is the in-memory registry.
type RegistryHive struct {
	mu   sync.RWMutex
	root *RegistryKey
}

// NewRegistryHive creates a registry with pre-populated essential keys.
func NewRegistryHive() *RegistryHive {
	hive := &RegistryHive{
		root: &RegistryKey{
			Name:     "",
			Children: make(map[string]*RegistryKey),
			Values:   make(map[string]*RegistryValue),
		},
	}
	hive.populateDefaults()
	return hive
}

// populateDefaults fills in essential registry keys that Windows DLLs expect.
func (h *RegistryHive) populateDefaults() {
	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
	ntCur := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	ntCur.setString("ProductName", "Windows 10 Pro")
	ntCur.setString("CurrentBuildNumber", "19045")
	ntCur.setString("BuildBranch", "vb_release")
	ntCur.setString("DisplayVersion", "22H2")
	ntCur.setDWORD("CurrentMajorVersionNumber", 10)
	ntCur.setDWORD("CurrentMinorVersionNumber", 0)
	ntCur.setDWORD("UBR", 3803)
	ntCur.setString("EditionID", "Professional")
	ntCur.setString("InstallationType", "Client")

	// HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage
	codePage := h.createPath(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\CodePage`)
	codePage.setString("ACP", "1252")
	codePage.setString("OEMCP", "437")
	codePage.setString("MACCP", "10000")

	// HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language
	lang := h.createPath(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\Language`)
	lang.setString("Default", "0409")
	lang.setString("InstallLanguage", "0409")

	// HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
	sysEnv := h.createPath(`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	sysEnv.setExpandSZ("Path", `C:\Windows\system32;C:\Windows`)
	sysEnv.setExpandSZ("TEMP", `C:\Windows\TEMP`)
	sysEnv.setExpandSZ("TMP", `C:\Windows\TEMP`)
	sysEnv.setString("OS", "Windows_NT")
	sysEnv.setString("PROCESSOR_ARCHITECTURE", "AMD64")
	sysEnv.setString("NUMBER_OF_PROCESSORS", "4")
	sysEnv.setExpandSZ("PATHEXT", ".COM;.EXE;.BAT;.CMD")

	// HKCU\Environment
	userEnv := h.createPath(`HKEY_CURRENT_USER\Environment`)
	userEnv.setExpandSZ("TEMP", `C:\Users\user\AppData\Local\Temp`)
	userEnv.setExpandSZ("TMP", `C:\Users\user\AppData\Local\Temp`)

	// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
	winCur := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion`)
	winCur.setString("ProgramFilesDir", `C:\Program Files`)
	winCur.setString("CommonFilesDir", `C:\Program Files\Common Files`)

	// HKCR (HKEY_CLASSES_ROOT) - minimal
	h.createPath(`HKEY_CLASSES_ROOT`)

	// HKLM\SOFTWARE\Microsoft\Cryptography
	crypto := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`)
	crypto.setString("MachineGuid", "12345678-1234-1234-1234-123456789012")

	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts
	// Provides font name → filename mappings used by GDI and font loading code.
	fonts := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`)
	fonts.setString("Arial (TrueType)", "arial.ttf")
	fonts.setString("Arial Bold (TrueType)", "arialbd.ttf")
	fonts.setString("Courier New (TrueType)", "cour.ttf")
	fonts.setString("Times New Roman (TrueType)", "times.ttf")
	fonts.setString("Segoe UI (TrueType)", "segoeui.ttf")
	fonts.setString("Tahoma (TrueType)", "tahoma.ttf")
	fonts.setString("Verdana (TrueType)", "verdana.ttf")
	fonts.setString("Calibri (TrueType)", "calibri.ttf")
	fonts.setString("Consolas (TrueType)", "consolas.ttf")
	fonts.setString("Lucida Console (TrueType)", "lucon.ttf")

	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes
	// Maps legacy font names to their replacements.
	fontSubs := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes`)
	fontSubs.setString("MS Shell Dlg", "Microsoft Sans Serif")
	fontSubs.setString("MS Shell Dlg 2", "Tahoma")
	fontSubs.setString("Helv", "Arial")
	fontSubs.setString("Tms Rmn", "Times New Roman")

	// HKCU\Control Panel\Desktop\WindowMetrics - font size/DPI preferences
	wm := h.createPath(`HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics`)
	wm.setDWORD("AppliedDPI", 96)
	wm.setString("Shell Icon Size", "32")

	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\GRE_Initialize
	// Controls font rasterizer settings.
	gre := h.createPath(`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\GRE_Initialize`)
	gre.setDWORD("DisableMetaFiles", 0)
}

// OpenKey opens a registry key by path. Returns nil if not found.
func (h *RegistryHive) OpenKey(path string) *RegistryKey {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.walkPath(normalizRegPath(path))
}

// CreateKey creates a registry key and all intermediate keys.
func (h *RegistryHive) CreateKey(path string) *RegistryKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.createPathLocked(normalizRegPath(path))
}

// DeleteKey removes a key (and all its children).
func (h *RegistryHive) DeleteKey(path string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	parts := splitRegPath(normalizRegPath(path))
	if len(parts) == 0 {
		return false
	}

	parent := h.walkPathParts(parts[:len(parts)-1])
	if parent == nil {
		return false
	}

	keyName := strings.ToUpper(parts[len(parts)-1])
	if _, ok := parent.Children[keyName]; !ok {
		return false
	}
	delete(parent.Children, keyName)
	return true
}

// Save serializes the registry to disk as JSON.
func (h *RegistryHive) Save(path string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := json.MarshalIndent(h.root, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Load deserializes the registry from a JSON file.
func (h *RegistryHive) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	root := &RegistryKey{}
	if err := json.Unmarshal(data, root); err != nil {
		return err
	}
	h.root = root
	return nil
}

// EnumerateKeys returns sorted child key names.
func (h *RegistryHive) EnumerateKeys(key *RegistryKey) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	names := make([]string, 0, len(key.Children))
	for name := range key.Children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// EnumerateValues returns sorted value names.
func (h *RegistryHive) EnumerateValues(key *RegistryKey) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	names := make([]string, 0, len(key.Values))
	for name := range key.Values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// --- internal helpers ---

func (h *RegistryHive) createPath(path string) *RegistryKey {
	return h.createPathLocked(normalizRegPath(path))
}

func (h *RegistryHive) createPathLocked(path string) *RegistryKey {
	parts := splitRegPath(path)
	node := h.root
	for _, part := range parts {
		upper := strings.ToUpper(part)
		child, ok := node.Children[upper]
		if !ok {
			child = &RegistryKey{
				Name:     part,
				Children: make(map[string]*RegistryKey),
				Values:   make(map[string]*RegistryValue),
			}
			node.Children[upper] = child
		}
		node = child
	}
	return node
}

func (h *RegistryHive) walkPath(path string) *RegistryKey {
	return h.walkPathParts(splitRegPath(path))
}

func (h *RegistryHive) walkPathParts(parts []string) *RegistryKey {
	node := h.root
	for _, part := range parts {
		child, ok := node.Children[strings.ToUpper(part)]
		if !ok {
			return nil
		}
		node = child
	}
	return node
}

func splitRegPath(path string) []string {
	path = strings.ReplaceAll(path, "/", `\`)
	parts := strings.Split(path, `\`)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// normalizRegPath normalizes a registry path:
// - \REGISTRY\MACHINE → HKEY_LOCAL_MACHINE
// - \REGISTRY\USER → HKEY_CURRENT_USER
func normalizRegPath(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	upper := strings.ToUpper(path)

	if strings.HasPrefix(upper, `\REGISTRY\MACHINE\`) {
		return `HKEY_LOCAL_MACHINE\` + path[len(`\REGISTRY\MACHINE\`):]
	}
	if strings.HasPrefix(upper, `\REGISTRY\MACHINE`) {
		return `HKEY_LOCAL_MACHINE`
	}
	if strings.HasPrefix(upper, `\REGISTRY\USER\.DEFAULT\`) {
		return `HKEY_CURRENT_USER\` + path[len(`\REGISTRY\USER\.DEFAULT\`):]
	}
	if strings.HasPrefix(upper, `\REGISTRY\USER\`) {
		return `HKEY_CURRENT_USER\` + path[len(`\REGISTRY\USER\`):]
	}

	return path
}

// --- RegistryKey value helpers ---

func (k *RegistryKey) setString(name, value string) {
	data := encodeUTF16LE(value)
	data = append(data, 0, 0) // null terminator
	k.Values[name] = &RegistryValue{Name: name, Type: RegSZ, Data: data}
}

func (k *RegistryKey) setExpandSZ(name, value string) {
	data := encodeUTF16LE(value)
	data = append(data, 0, 0)
	k.Values[name] = &RegistryValue{Name: name, Type: RegExpandSZ, Data: data}
}

func (k *RegistryKey) setDWORD(name string, value uint32) {
	data := make([]byte, 4)
	data[0] = byte(value)
	data[1] = byte(value >> 8)
	data[2] = byte(value >> 16)
	data[3] = byte(value >> 24)
	k.Values[name] = &RegistryValue{Name: name, Type: RegDWORD, Data: data}
}
