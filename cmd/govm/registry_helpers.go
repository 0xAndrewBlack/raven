//go:build guest_windows

package main

import (
	"strings"

	"github.com/mirkobrombin/Raven/pkg/ntapi"
)

func regCloneSubtree(src *ntapi.RegistryKey) *ntapi.RegistryKey {
	if src == nil {
		return nil
	}
	dst := &ntapi.RegistryKey{
		Name:     src.Name,
		Children: make(map[string]*ntapi.RegistryKey),
		Values:   make(map[string]*ntapi.RegistryValue),
	}
	for name, val := range src.Values {
		cp := make([]byte, len(val.Data))
		copy(cp, val.Data)
		dst.Values[name] = &ntapi.RegistryValue{Name: val.Name, Type: val.Type, Data: cp}
	}
	for name, child := range src.Children {
		dst.Children[name] = regCloneSubtree(child)
	}
	return dst
}

func regCopyTree(dst, src *ntapi.RegistryKey) {
	if dst == nil || src == nil {
		return
	}
	if dst.Children == nil {
		dst.Children = make(map[string]*ntapi.RegistryKey)
	}
	if dst.Values == nil {
		dst.Values = make(map[string]*ntapi.RegistryValue)
	}
	for name, val := range src.Values {
		cp := make([]byte, len(val.Data))
		copy(cp, val.Data)
		dst.Values[name] = &ntapi.RegistryValue{Name: val.Name, Type: val.Type, Data: cp}
	}
	for name, child := range src.Children {
		dst.Children[name] = regCloneSubtree(child)
	}
}

func regKeyPath(handles *ntapi.HandleTable, hKey uint64, subKey string) string {
	var base string
	switch hKey {
	case 0x80000000:
		base = `HKEY_CLASSES_ROOT`
	case 0x80000001:
		base = `HKEY_CURRENT_USER`
	case 0x80000002:
		base = `HKEY_LOCAL_MACHINE`
	case 0x80000003:
		base = `HKEY_USERS`
	case 0x80000005:
		base = `HKEY_CURRENT_CONFIG`
	default:
		rk := handles.GetRegKey(ntapi.Handle(hKey))
		if rk != nil {
			base = rk.Path
		}
	}
	if subKey == "" {
		return base
	}
	if base == "" {
		return subKey
	}
	return base + `\` + subKey
}

// regIsProbeKey returns true for registry paths used by VM/sandbox detection tools.
// These keys should not be auto-created on open.
func regIsProbeKey(path string) bool {
	lp := strings.ToLower(path)
	probes := []string{
		`\wine`, `\oracle\virtualbox`, `\vmware`,
		`\vbox`, `\qemu`, `\bochs`,
		`\sandboxie`, `\cuckoo`,
		`\services\vboxguest`, `\services\vboxmouse`,
		`\services\vboxservice`, `\services\vboxsf`, `\services\vboxvideo`,
		`\acpi\dsdt\vbox__`, `\acpi\fadt\vbox__`, `\acpi\rsdt\vbox__`,
	}
	for _, p := range probes {
		if strings.Contains(lp, p) {
			return true
		}
	}
	return false
}

func regQueryValue(handles *ntapi.HandleTable, ctx *ntapi.TrapContext, hKey uint64, valueName string) uint32 {
	lpType := ctx.Arg(3)
	lpData := ctx.Arg(4)
	lpcbData := ctx.Arg(5)
	rk := handles.GetRegKey(ntapi.Handle(hKey))
	if rk == nil || rk.Key == nil {
		return 2 // ERROR_FILE_NOT_FOUND
	}
	var val *ntapi.RegistryValue
	for k, v := range rk.Key.Values {
		if strings.EqualFold(k, valueName) {
			val = v
			break
		}
	}
	if val == nil {
		return 2 // ERROR_FILE_NOT_FOUND
	}
	if lpType != 0 {
		ctx.Mem.Write32(lpType, val.Type)
	}
	needed := uint32(len(val.Data))
	if lpcbData != 0 {
		avail, _ := ctx.Mem.Read32(lpcbData)
		ctx.Mem.Write32(lpcbData, needed)
		if lpData != 0 && avail < needed {
			return 234 // ERROR_MORE_DATA
		}
	}
	if lpData != 0 {
		ctx.Mem.WriteBytes(lpData, val.Data)
	}
	return 0
}
