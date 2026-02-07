//go:build guest_linux

package syscall

import "encoding/binary"

// cmsg helpers for parsing and building struct cmsghdr.
// On RISC-V 64-bit, CMSG_ALIGN rounds to 8 bytes.

const cmsgAlign = 8

// cmsghdr layout: cmsg_len(8) + cmsg_level(4) + cmsg_type(4) = 16 bytes header
const cmsghdrSize = 16

// cmsgAlignUp rounds n up to cmsg alignment.
func cmsgAlignUp(n uint64) uint64 {
	return (n + cmsgAlign - 1) & ^uint64(cmsgAlign-1)
}

// CmsgHeader represents a parsed cmsghdr.
type CmsgHeader struct {
	Len   uint64
	Level int32
	Type  int32
	Data  []byte // payload after the header
}

// ParseCmsgs parses all cmsghdr entries from a control message buffer.
func ParseCmsgs(buf []byte) []CmsgHeader {
	var result []CmsgHeader
	offset := 0
	for offset+cmsghdrSize <= len(buf) {
		cmsgLen := binary.LittleEndian.Uint64(buf[offset:])
		if cmsgLen < cmsghdrSize || int(cmsgLen) > len(buf)-offset {
			break
		}
		level := int32(binary.LittleEndian.Uint32(buf[offset+8:]))
		ctype := int32(binary.LittleEndian.Uint32(buf[offset+12:]))
		dataLen := cmsgLen - cmsghdrSize
		data := make([]byte, dataLen)
		copy(data, buf[offset+cmsghdrSize:offset+int(cmsgLen)])
		result = append(result, CmsgHeader{
			Len:   cmsgLen,
			Level: level,
			Type:  ctype,
			Data:  data,
		})
		offset += int(cmsgAlignUp(cmsgLen))
	}
	return result
}

// BuildCmsg serializes a cmsghdr with its data.
func BuildCmsg(level, ctype int32, data []byte) []byte {
	totalLen := cmsghdrSize + uint64(len(data))
	aligned := cmsgAlignUp(totalLen)
	buf := make([]byte, aligned)
	binary.LittleEndian.PutUint64(buf[0:], totalLen)
	binary.LittleEndian.PutUint32(buf[8:], uint32(level))
	binary.LittleEndian.PutUint32(buf[12:], uint32(ctype))
	copy(buf[cmsghdrSize:], data)
	return buf
}

// ExtractSCMRightsFDs extracts FD numbers from an SCM_RIGHTS cmsg data payload.
// Each FD is a 4-byte int32.
func ExtractSCMRightsFDs(data []byte) []int32 {
	count := len(data) / 4
	fds := make([]int32, count)
	for i := 0; i < count; i++ {
		fds[i] = int32(binary.LittleEndian.Uint32(data[i*4:]))
	}
	return fds
}

// PackSCMRightsFDs packs FD numbers into SCM_RIGHTS cmsg data.
func PackSCMRightsFDs(fds []int32) []byte {
	data := make([]byte, len(fds)*4)
	for i, fd := range fds {
		binary.LittleEndian.PutUint32(data[i*4:], uint32(fd))
	}
	return data
}
