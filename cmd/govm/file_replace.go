//go:build guest_windows

package main

import (
	"strings"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func replaceVFSFile(fs *vfs.VFS, replacedPath, replacementPath, backupPath string) error {
	return fs.ReplaceFile(replacedPath, replacementPath, backupPath)
}

func replaceVFSFileWithHost(fs *vfs.VFS, hctx *HandlerCtx, replacedPath, replacementPath, backupPath string) error {
	return fs.ReplaceFileWithCommit(replacedPath, replacementPath, backupPath, func(replacedData, replacementData []byte) error {
		return hctx.commitHostSaveReplace(replacedPath, replacementPath, backupPath, replacedData, replacementData)
	})
}

func sameWindowsVolume(paths ...string) bool {
	volume := ""
	for _, filePath := range paths {
		if filePath == "" {
			continue
		}
		current := windowsVolume(filePath)
		if current == "" {
			continue
		}
		if volume == "" {
			volume = current
			continue
		}
		if !strings.EqualFold(volume, current) {
			return false
		}
	}
	return true
}

func windowsVolume(filePath string) string {
	filePath = strings.ReplaceAll(filePath, "/", `\`)
	filePath = strings.TrimPrefix(filePath, `\\?\`)
	if len(filePath) >= 2 && filePath[1] == ':' {
		return strings.ToUpper(filePath[:2])
	}
	if strings.HasPrefix(filePath, `\\`) {
		parts := strings.Split(strings.TrimPrefix(filePath, `\\`), `\`)
		if len(parts) >= 2 {
			return `\\` + strings.ToLower(parts[0]) + `\` + strings.ToLower(parts[1])
		}
	}
	return ""
}
