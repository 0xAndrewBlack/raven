package ntapi

import (
	"strings"
)

// NtPathToVFS translates a Windows NT kernel path to a VFS path.
//
// NT paths come in several forms:
//   - \??\C:\Windows\System32\kernel32.dll
//   - \Device\HarddiskVolume1\Windows\...
//   - \\?\C:\path
//   - C:\path (DOS path, already partially resolved)
//   - \SystemRoot\...
//
// We map C:\ to the VFS root ("/"), treating all drives identically.
func NtPathToVFS(ntPath string) string {
	if ntPath == "" {
		return "/"
	}

	path := ntPath

	// Strip NT kernel prefixes
	path = stripPrefix(path, `\??\`)
	path = stripPrefix(path, `\\?\`)
	path = stripPrefix(path, `\Device\HarddiskVolume1`)
	path = stripPrefix(path, `\Device\HarddiskVolume2`)
	path = stripPrefix(path, `\Device\HarddiskVolume3`)

	// Handle \SystemRoot → C:\Windows
	if strings.HasPrefix(path, `\SystemRoot`) {
		path = `C:\Windows` + path[len(`\SystemRoot`):]
	}

	// Handle \KnownDlls\... - redirect to system32
	if strings.HasPrefix(path, `\KnownDlls\`) {
		path = `C:\Windows\System32\` + path[len(`\KnownDlls\`):]
	}

	// Handle \BaseNamedObjects\... - special NT namespace, return as-is for now
	if strings.HasPrefix(path, `\BaseNamedObjects\`) {
		return "/dev/null" // placeholder
	}

	// Strip drive letter (e.g., C:\)
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		path = path[2:]
	} else if len(path) >= 2 && path[1] == ':' {
		path = path[2:]
		if path == "" {
			path = "/"
		}
	}

	// Convert backslashes to forward slashes
	path = strings.ReplaceAll(path, `\`, "/")

	// Ensure absolute path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Normalize double slashes
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	return path
}

// VFSToNtPath converts a VFS path back to a Windows NT path.
func VFSToNtPath(vfsPath string) string {
	if vfsPath == "" || vfsPath == "/" {
		return `C:\`
	}
	// Convert forward slashes to backslashes and prepend C:
	winPath := strings.ReplaceAll(vfsPath, "/", `\`)
	if !strings.HasPrefix(winPath, `\`) {
		winPath = `\` + winPath
	}
	return `C:` + winPath
}

// stripPrefix removes a prefix (case-insensitive) if present.
func stripPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):]
	}
	return s
}

// ReadObjectAttributes reads an OBJECT_ATTRIBUTES structure from guest memory
// and returns the object name as a Go string.
//
// OBJECT_ATTRIBUTES layout (x64):
//
//	+0x00  Length (ULONG)
//	+0x08  RootDirectory (HANDLE)
//	+0x10  ObjectName (PUNICODE_STRING)
//	+0x18  Attributes (ULONG)
//	+0x20  SecurityDescriptor (PVOID)
//	+0x28  SecurityQualityOfService (PVOID)
func ReadObjectAttributes(ctx *TrapContext, addr uint64) (rootDir Handle, name string, attrs uint32, err error) {
	if addr == 0 {
		return 0, "", 0, nil
	}

	rootDirVal, err := ctx.Mem.Read64(addr + 0x08)
	if err != nil {
		return 0, "", 0, err
	}
	rootDir = Handle(rootDirVal)

	namePtr, err := ctx.Mem.Read64(addr + 0x10)
	if err != nil {
		return 0, "", 0, err
	}

	attrsVal, err := ctx.Mem.Read32(addr + 0x18)
	if err != nil {
		return 0, "", 0, err
	}
	attrs = attrsVal

	if namePtr != 0 {
		name, err = ReadUnicodeString(ctx.Mem, namePtr)
		if err != nil {
			return 0, "", 0, err
		}
	}

	return rootDir, name, attrs, nil
}

// ResolveObjectPath resolves the full path from OBJECT_ATTRIBUTES, considering
// the root directory handle.
func ResolveObjectPath(ctx *TrapContext, addr uint64) (string, error) {
	rootDir, name, _, err := ReadObjectAttributes(ctx, addr)
	if err != nil {
		return "", err
	}

	if rootDir != 0 {
		// Relative to a directory handle
		fh := ctx.Handles.GetFile(rootDir)
		if fh != nil {
			basePath := fh.Path
			if !strings.HasSuffix(basePath, "/") {
				basePath += "/"
			}
			return basePath + NtPathToVFS(name), nil
		}
	}

	return NtPathToVFS(name), nil
}

// ApiSetResolve maps api-ms-win-* virtual DLL names to real DLL names.
// This handles the Windows API Set schema redirection.
func ApiSetResolve(name string) string {
	lower := strings.ToLower(name)
	lower = strings.TrimSuffix(lower, ".dll")

	// Static mapping of the most common API sets
	apiSetMap := map[string]string{
		"api-ms-win-core-console-l1-1-0":        "kernel32.dll",
		"api-ms-win-core-console-l1-2-0":        "kernel32.dll",
		"api-ms-win-core-datetime-l1-1-0":       "kernel32.dll",
		"api-ms-win-core-debug-l1-1-0":          "kernel32.dll",
		"api-ms-win-core-errorhandling-l1-1-0":  "kernel32.dll",
		"api-ms-win-core-file-l1-1-0":           "kernel32.dll",
		"api-ms-win-core-file-l1-2-0":           "kernel32.dll",
		"api-ms-win-core-file-l2-1-0":           "kernel32.dll",
		"api-ms-win-core-handle-l1-1-0":         "kernel32.dll",
		"api-ms-win-core-heap-l1-1-0":           "kernel32.dll",
		"api-ms-win-core-heap-l2-1-0":           "kernel32.dll",
		"api-ms-win-core-interlocked-l1-1-0":    "kernel32.dll",
		"api-ms-win-core-libraryloader-l1-1-0":  "kernel32.dll",
		"api-ms-win-core-libraryloader-l1-2-0":  "kernel32.dll",
		"api-ms-win-core-localization-l1-1-0":   "kernel32.dll",
		"api-ms-win-core-localization-l1-2-0":   "kernel32.dll",
		"api-ms-win-core-memory-l1-1-0":         "kernel32.dll",
		"api-ms-win-core-namedpipe-l1-1-0":      "kernel32.dll",
		"api-ms-win-core-processenvironment-l1-1-0": "kernel32.dll",
		"api-ms-win-core-processthreads-l1-1-0": "kernel32.dll",
		"api-ms-win-core-processthreads-l1-1-1": "kernel32.dll",
		"api-ms-win-core-profile-l1-1-0":        "kernel32.dll",
		"api-ms-win-core-registry-l1-1-0":       "kernelbase.dll",
		"api-ms-win-core-rtlsupport-l1-1-0":     "ntdll.dll",
		"api-ms-win-core-string-l1-1-0":          "kernel32.dll",
		"api-ms-win-core-synch-l1-1-0":           "kernel32.dll",
		"api-ms-win-core-synch-l1-2-0":           "kernel32.dll",
		"api-ms-win-core-sysinfo-l1-1-0":         "kernel32.dll",
		"api-ms-win-core-timezone-l1-1-0":        "kernel32.dll",
		"api-ms-win-core-util-l1-1-0":            "kernel32.dll",
		"api-ms-win-core-io-l1-1-0":              "kernel32.dll",
		"api-ms-win-core-com-l1-1-0":             "combase.dll",
		"api-ms-win-crt-conio-l1-1-0":            "ucrtbase.dll",
		"api-ms-win-crt-convert-l1-1-0":          "ucrtbase.dll",
		"api-ms-win-crt-environment-l1-1-0":      "ucrtbase.dll",
		"api-ms-win-crt-filesystem-l1-1-0":       "ucrtbase.dll",
		"api-ms-win-crt-heap-l1-1-0":             "ucrtbase.dll",
		"api-ms-win-crt-locale-l1-1-0":           "ucrtbase.dll",
		"api-ms-win-crt-math-l1-1-0":             "ucrtbase.dll",
		"api-ms-win-crt-multibyte-l1-1-0":        "ucrtbase.dll",
		"api-ms-win-crt-private-l1-1-0":          "ucrtbase.dll",
		"api-ms-win-crt-process-l1-1-0":          "ucrtbase.dll",
		"api-ms-win-crt-runtime-l1-1-0":          "ucrtbase.dll",
		"api-ms-win-crt-stdio-l1-1-0":            "ucrtbase.dll",
		"api-ms-win-crt-string-l1-1-0":           "ucrtbase.dll",
		"api-ms-win-crt-time-l1-1-0":             "ucrtbase.dll",
		"api-ms-win-crt-utility-l1-1-0":          "ucrtbase.dll",
	}

	// Try exact match
	if dll, ok := apiSetMap[lower]; ok {
		return dll
	}

	// Try prefix match (strip version suffix)
	for prefix, dll := range apiSetMap {
		// api-ms-win-core-file-l1 prefix match
		if strings.HasPrefix(lower, prefix[:len(prefix)-2]) {
			return dll
		}
	}

	// Default: if it starts with api-ms-win-crt, assume ucrtbase
	if strings.HasPrefix(lower, "api-ms-win-crt-") {
		return "ucrtbase.dll"
	}
	if strings.HasPrefix(lower, "api-ms-win-core-") {
		return "kernel32.dll"
	}

	return name // not an API set, return as-is
}
