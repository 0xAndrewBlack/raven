//go:build guest_windows

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/mirkobrombin/Raven/pkg/vfs"
)

func binaryTypePEFixture(optionalMagic, characteristics, subsystem uint16) []byte {
	data := make([]byte, 0x200)
	binary.LittleEndian.PutUint16(data[0:], 0x5A4D)
	binary.LittleEndian.PutUint32(data[0x3C:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x80+20:], 0xF0)
	binary.LittleEndian.PutUint16(data[0x80+22:], characteristics)
	binary.LittleEndian.PutUint16(data[0x80+24:], optionalMagic)
	binary.LittleEndian.PutUint16(data[0x80+24+68:], subsystem)
	return data
}

func TestClassifyWindowsBinary(t *testing.T) {
	pe32 := binaryTypePEFixture(0x10B, 0x0002, 2)
	pe64 := binaryTypePEFixture(0x20B, 0x0002, 2)
	dll32 := binaryTypePEFixture(0x10B, 0x2002, 2)
	dll64 := binaryTypePEFixture(0x20B, 0x2002, 2)
	posix := binaryTypePEFixture(0x10B, 0x0002, 7)
	dos := make([]byte, 0x40)
	binary.LittleEndian.PutUint16(dos, 0x5A4D)
	binary.LittleEndian.PutUint32(dos[0x3C:], 0x1000)
	os2 := make([]byte, 0x100)
	binary.LittleEndian.PutUint16(os2, 0x5A4D)
	binary.LittleEndian.PutUint32(os2[0x3C:], 0x40)
	copy(os2[0x40:], "NE\x00\x00")
	os2[0x40+0x36] = 1
	wow := append([]byte(nil), os2...)
	wow[0x40+0x36] = 2
	pif := make([]byte, 0x200)
	copy(pif[0x80:], "MICROSOFT PIFEX")

	tests := []struct {
		name      string
		path      string
		data      []byte
		wantType  uint32
		wantError uint32
	}{
		{name: "PE32", path: "app.exe", data: pe32, wantType: scs32BitBinary},
		{name: "PE64", path: "app.exe", data: pe64, wantType: scs64BitBinary},
		{name: "POSIX PE", path: "app.exe", data: posix, wantType: scsPOSIXBinary},
		{name: "PE32 DLL", path: "plugin.dll", data: dll32, wantError: errorBadExeFormat},
		{name: "PE64 DLL", path: "plugin.dll", data: dll64, wantError: errorBadExeFormat},
		{name: "DOS", path: "app.com", data: dos, wantType: scsDOSBinary},
		{name: "OS2 NE", path: "app.exe", data: os2, wantType: scsOS216Binary},
		{name: "Windows NE", path: "app.exe", data: wow, wantType: scsWOWBinary},
		{name: "PIF", path: "app.pif", data: pif, wantType: scsPIFBinary},
		{name: "invalid image", path: "data.bin", data: []byte("not executable"), wantError: errorBadExeFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotError := classifyWindowsBinary(bytes.NewReader(tt.data), tt.path)
			if gotType != tt.wantType || gotError != tt.wantError {
				t.Fatalf("classifyWindowsBinary() = (%d, %d), want (%d, %d)", gotType, gotError, tt.wantType, tt.wantError)
			}
		})
	}
}

func TestClassifyWindowsBinaryReadsVFSAndHostFiles(t *testing.T) {
	pe32 := binaryTypePEFixture(0x10B, 0x0002, 2)
	pe64 := binaryTypePEFixture(0x20B, 0x0002, 2)
	fs := vfs.New()
	fs.MkdirAll("/fixtures")
	if err := fs.CreateFile("/fixtures/pe32.exe", pe32, vfs.ModeRead); err != nil {
		t.Fatal(err)
	}

	virtualFD, err := fs.Open("/fixtures/pe32.exe", vfs.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	gotType, gotError := classifyWindowsBinary(vfsBinaryReader{fs: fs, fd: virtualFD}, "/fixtures/pe32.exe")
	fs.Close(virtualFD)
	if gotType != scs32BitBinary || gotError != 0 {
		t.Fatalf("virtual PE32 = (%d, %d), want (%d, 0)", gotType, gotError, scs32BitBinary)
	}

	hostPath := filepath.Join(t.TempDir(), "pe64.exe")
	if err := os.WriteFile(hostPath, pe64, 0600); err != nil {
		t.Fatal(err)
	}
	hostFD, err := fs.Open(hostPath, vfs.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	gotType, gotError = classifyWindowsBinary(vfsBinaryReader{fs: fs, fd: hostFD}, hostPath)
	fs.Close(hostFD)
	if gotType != scs64BitBinary || gotError != 0 {
		t.Fatalf("host PE64 = (%d, %d), want (%d, 0)", gotType, gotError, scs64BitBinary)
	}
}
