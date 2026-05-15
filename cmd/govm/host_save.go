//go:build guest_windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mirkobrombin/Raven/pkg/vfs"
	"golang.org/x/sys/unix"
)

type hostSaveRenameOptions struct {
	replaceExisting bool
	allowCopy       bool
}

type hostSaveRenameOps struct {
	rename func(sourcePath, targetPath string, replaceExisting bool) error
	remove func(path string) error
	write  func(path string, data []byte, replaceExisting bool) error
	lstat  func(path string) (os.FileInfo, error)
}

var defaultHostSaveRenameOps = hostSaveRenameOps{
	rename: renameHostSaveFile,
	remove: os.Remove,
	write:  writeHostSaveFile,
	lstat:  os.Lstat,
}

func (hctx *HandlerCtx) bindHostSavePath(vfsPath, hostPath string) {
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	defer hctx.HostSaveMu.Unlock()
	if hctx.HostSavePaths == nil {
		hctx.HostSavePaths = make(map[string]string)
	}
	hctx.HostSavePaths[vfsPath] = hostPath
}

func (hctx *HandlerCtx) unbindHostSavePath(vfsPath string) {
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	defer hctx.HostSaveMu.Unlock()
	cleanPath := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(vfsPath)), "/")
	pathPrefix := strings.ToLower(cleanPath) + "/"
	for key := range hctx.HostSavePaths {
		cleanKey := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(key)), "/")
		if strings.EqualFold(cleanKey, cleanPath) || strings.HasPrefix(strings.ToLower(cleanKey), pathPrefix) {
			delete(hctx.HostSavePaths, key)
		}
	}
}

func (hctx *HandlerCtx) flushHostSavePath(fs *vfs.VFS, vfsPath string) error {
	return hctx.flushHostSavePathWithSnapshot(vfsPath, func() ([]byte, error) {
		return fs.FileBytes(vfsPath)
	})
}

func (hctx *HandlerCtx) flushHostSavePathWithSnapshot(vfsPath string, snapshot func() ([]byte, error)) error {
	hctx.HostSaveMu.Lock()
	_, hostPath := hostSaveBindingFold(hctx.HostSavePaths, vfsPath)
	hctx.HostSaveMu.Unlock()
	if hostPath == "" {
		return nil
	}
	data, err := snapshot()
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	_, currentHostPath := hostSaveBindingFold(hctx.HostSavePaths, vfsPath)
	hctx.HostSaveMu.Unlock()
	if currentHostPath != hostPath {
		return nil
	}
	if err != nil {
		return err
	}
	return os.WriteFile(hostPath, data, 0644)
}

func (hctx *HandlerCtx) flushHostFileBuffers(fs *vfs.VFS, fd int, vfsPath string) error {
	if hostFile := fs.GetHostFile(fd); hostFile != nil {
		hctx.HostSaveIOMu.Lock()
		defer hctx.HostSaveIOMu.Unlock()
		return hostFile.Sync()
	}
	hctx.HostSaveMu.Lock()
	_, hostPath := hostSaveBindingFold(hctx.HostSavePaths, vfsPath)
	hctx.HostSaveMu.Unlock()
	if hostPath == "" {
		return nil
	}
	data, err := fs.FileBytes(vfsPath)
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	_, currentHostPath := hostSaveBindingFold(hctx.HostSavePaths, vfsPath)
	hctx.HostSaveMu.Unlock()
	if currentHostPath != hostPath {
		return nil
	}
	if err != nil {
		return err
	}
	hostFile, err := os.OpenFile(hostPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	n, writeErr := hostFile.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	syncErr := error(nil)
	if writeErr == nil {
		syncErr = hostFile.Sync()
	}
	closeErr := hostFile.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func (hctx *HandlerCtx) commitHostSaveRename(srcPath, dstPath string, source vfs.RenameCommitSource, options hostSaveRenameOptions) (vfs.RenameCommitResult, error) {
	return hctx.commitHostSaveRenameWithOps(srcPath, dstPath, source, options, defaultHostSaveRenameOps)
}

func (hctx *HandlerCtx) commitHostSaveRenameWithOps(srcPath, dstPath string, source vfs.RenameCommitSource, options hostSaveRenameOptions, ops hostSaveRenameOps) (vfs.RenameCommitResult, error) {
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	srcKey, srcHost := hostSaveBindingFold(hctx.HostSavePaths, srcPath)
	dstKey, dstHost := hostSaveBindingFold(hctx.HostSavePaths, dstPath)
	hctx.HostSaveMu.Unlock()
	if srcKey != "" && dstKey == srcKey && srcPath != dstPath {
		dstKey, dstHost = "", ""
	}
	if srcHost == "" && dstHost == "" {
		return vfs.RenameCommitResult{}, nil
	}
	if dstHost == "" {
		dstHost = hostSavePathFromVFS(dstPath)
	}
	if source.IsDir && srcHost == "" {
		return vfs.RenameCommitResult{}, syscall.EISDIR
	}

	sameHostPath := srcHost != "" && filepath.Clean(srcHost) == filepath.Clean(dstHost)
	if !sameHostPath && !options.replaceExisting {
		if _, err := ops.lstat(dstHost); err == nil {
			return vfs.RenameCommitResult{}, fmt.Errorf("%w: %s", os.ErrExist, dstHost)
		} else if !os.IsNotExist(err) {
			return vfs.RenameCommitResult{}, err
		}
	}

	keepSource := false
	if srcHost == "" {
		if err := ops.write(dstHost, source.Data, options.replaceExisting); err != nil {
			return vfs.RenameCommitResult{}, err
		}
	} else if !sameHostPath {
		replaceHostTarget := options.replaceExisting && !source.IsDir
		if err := ops.rename(srcHost, dstHost, replaceHostTarget); err != nil {
			if !options.allowCopy || !errors.Is(err, syscall.EXDEV) {
				return vfs.RenameCommitResult{}, err
			}
			if source.IsDir {
				return vfs.RenameCommitResult{}, syscall.EXDEV
			}
			if err := ops.write(dstHost, source.Data, options.replaceExisting); err != nil {
				return vfs.RenameCommitResult{}, err
			}
			if err := ops.remove(srcHost); err != nil {
				keepSource = !os.IsNotExist(err)
			}
		}
	}
	hctx.HostSaveMu.Lock()
	for key := range hctx.HostSavePaths {
		if strings.EqualFold(key, dstPath) || (!keepSource && strings.EqualFold(key, srcPath)) {
			delete(hctx.HostSavePaths, key)
		}
	}
	hctx.HostSavePaths[dstPath] = dstHost
	hctx.HostSaveMu.Unlock()
	return vfs.RenameCommitResult{KeepSource: keepSource}, nil
}

func hostSavePathFromVFS(vfsPath string) string {
	clean := filepath.ToSlash(filepath.Clean(vfsPath))
	if !strings.HasPrefix(clean, "/") {
		clean = "/" + clean
	}
	return winToLinuxPath(`C:` + strings.ReplaceAll(clean, "/", `\`))
}

func renameHostSaveFile(sourcePath, targetPath string, replaceExisting bool) error {
	if replaceExisting {
		return os.Rename(sourcePath, targetPath)
	}
	err := unix.Renameat2(unix.AT_FDCWD, sourcePath, unix.AT_FDCWD, targetPath, unix.RENAME_NOREPLACE)
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return syscall.ENOTSUP
}

func writeHostSaveFile(hostPath string, data []byte, replaceExisting bool) error {
	if replaceExisting {
		return atomicWriteHostFile(hostPath, data)
	}
	return atomicWriteHostFileNoReplace(hostPath, data)
}

func hostSaveMoveErrorCode(err error) uint32 {
	switch {
	case err == nil:
		return 0
	case os.IsNotExist(err), strings.Contains(err.Error(), "not found"):
		return 2 // ERROR_FILE_NOT_FOUND
	case os.IsExist(err), errors.Is(err, os.ErrExist):
		return 183 // ERROR_ALREADY_EXISTS
	case errors.Is(err, syscall.EXDEV):
		return 17 // ERROR_NOT_SAME_DEVICE
	case errors.Is(err, vfs.ErrRenameParentNotFound), errors.Is(err, syscall.ENOTDIR), strings.Contains(err.Error(), "parent directory"):
		return 3 // ERROR_PATH_NOT_FOUND
	default:
		return 5 // ERROR_ACCESS_DENIED
	}
}

func (hctx *HandlerCtx) commitHostSaveReplace(replacedPath, replacementPath, backupPath string, replacedData, replacementData []byte) error {
	hctx.HostSaveIOMu.Lock()
	defer hctx.HostSaveIOMu.Unlock()
	hctx.HostSaveMu.Lock()
	replacedKey, replacedHost := hostSaveBindingFold(hctx.HostSavePaths, replacedPath)
	replacementKey, replacementHost := hostSaveBindingFold(hctx.HostSavePaths, replacementPath)
	backupKey, backupHost := hostSaveBindingFold(hctx.HostSavePaths, backupPath)
	hctx.HostSaveMu.Unlock()

	if replacedHost == "" && replacementHost == "" {
		return nil
	}
	if replacedHost == "" {
		replacedHost = filepath.Join(filepath.Dir(replacementHost), filepath.Base(replacedPath))
	}
	if backupPath != "" && backupHost == "" {
		backupHost = filepath.Join(filepath.Dir(replacedHost), filepath.Base(backupPath))
	}

	if backupHost != "" {
		if replacementHost != "" {
			if err := atomicLinkHostFile(replacedHost, backupHost); err != nil {
				return err
			}
		} else if err := atomicWriteHostFile(backupHost, replacedData); err != nil {
			return err
		}
	}
	if replacementHost != "" && replacementHost != replacedHost {
		targetInfo, statErr := os.Stat(replacedHost)
		if err := os.Rename(replacementHost, replacedHost); err != nil {
			return err
		}
		if statErr == nil {
			if err := os.Chmod(replacedHost, targetInfo.Mode().Perm()); err != nil {
				return err
			}
		}
	} else if err := atomicWriteHostFile(replacedHost, replacementData); err != nil {
		return err
	}

	hctx.HostSaveMu.Lock()
	if replacementKey != "" {
		delete(hctx.HostSavePaths, replacementKey)
	}
	if replacedKey == "" {
		replacedKey = replacedPath
	}
	hctx.HostSavePaths[replacedKey] = replacedHost
	if backupPath != "" {
		if backupKey == "" {
			backupKey = backupPath
		}
		hctx.HostSavePaths[backupKey] = backupHost
	}
	hctx.HostSaveMu.Unlock()
	return nil
}

func atomicLinkHostFile(sourcePath, targetPath string) error {
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".raven-backup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := os.Link(sourcePath, tmpPath); err != nil {
		return err
	}
	return os.Rename(tmpPath, targetPath)
}

func hostSaveBindingFold(bindings map[string]string, requested string) (string, string) {
	if requested == "" {
		return "", ""
	}
	if hostPath := bindings[requested]; hostPath != "" {
		return requested, hostPath
	}
	for key, hostPath := range bindings {
		if strings.EqualFold(key, requested) {
			return key, hostPath
		}
	}
	return "", ""
}

func atomicWriteHostFile(hostPath string, data []byte) error {
	dir := filepath.Dir(hostPath)
	mode := os.FileMode(0644)
	if info, err := os.Stat(hostPath); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".raven-replace-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, hostPath)
}

func atomicWriteHostFileNoReplace(hostPath string, data []byte) error {
	dir := filepath.Dir(hostPath)
	tmp, err := os.CreateTemp(dir, ".raven-create-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmpPath, hostPath)
}
