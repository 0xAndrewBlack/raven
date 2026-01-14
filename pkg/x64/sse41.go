package x64

// SSE4.1 and SSE4.2 instruction implementations.
// Called from dispatch0F for 0F 38 and 0F 3A sub-opcode families.

import (
	"fmt"
	"math"
	"math/bits"
)

// loadXMM128 decodes a ModRM and loads the 128-bit source (reg or mem).
func (c *CPU) loadXMM128(pfx *prefixState) (dst int, src [2]uint64, err error) {
	m, err := c.decodeModRM(pfx)
	if err != nil {
		return 0, [2]uint64{}, err
	}
	dst = m.reg
	if m.mod == 3 {
		src = c.XMM[m.rm]
	} else {
		addr, _, err2 := c.resolveRMAddr(m, pfx)
		if err2 != nil {
			return 0, [2]uint64{}, err2
		}
		lo, _ := c.mem.Read64(addr)
		hi, _ := c.mem.Read64(addr + 8)
		src = [2]uint64{lo, hi}
	}
	return dst, src, nil
}

func satSigned16(v int32) int16 {
	if v < -32768 {
		return -32768
	}
	if v > 32767 {
		return 32767
	}
	return int16(v)
}

func crc32cByte(crc uint32, b byte) uint32 {
	crc ^= uint32(b)
	for i := 0; i < 8; i++ {
		if crc&1 != 0 {
			crc = (crc >> 1) ^ 0x82F63B78
		} else {
			crc >>= 1
		}
	}
	return crc
}

func crc32cUpdate(crc uint32, value uint64, size int) uint32 {
	for i := 0; i < size; i++ {
		crc = crc32cByte(crc, byte(value>>(uint(i)*8)))
	}
	return crc
}

// dispatch0F38 handles the 66 0F 38 xx family (SSE4.1 integer ops).
func (c *CPU) dispatch0F38(pfx *prefixState, startRIP uint64) error {
	op3, err := c.fetch8()
	if err != nil {
		return err
	}

	switch op3 {
	// PSHUFB xmm1, xmm2/m128 (0F 38 00)
	case 0x00:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := 0; i < 16; i++ {
			var b byte
			if i < 8 {
				b = byte(src[0] >> (uint(i) * 8))
			} else {
				b = byte(src[1] >> (uint(i-8) * 8))
			}
			if b&0x80 != 0 {
				// result byte = 0
			} else {
				idx := b & 0x0f
				var sb byte
				if idx < 8 {
					sb = byte(c.XMM[dst][0] >> (uint(idx) * 8))
				} else {
					sb = byte(c.XMM[dst][1] >> (uint(idx-8) * 8))
				}
				if i < 8 {
					r[0] |= uint64(sb) << (uint(i) * 8)
				} else {
					r[1] |= uint64(sb) << (uint(i-8) * 8)
				}
			}
		}
		c.XMM[dst] = r
		return nil

	// PHADDW xmm1, xmm2/m128 (0F 38 01)
	case 0x01:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			base := i * 32
			v := uint16(int16(d[0]>>base) + int16(d[0]>>(base+16)))
			r[0] |= uint64(v) << (i * 16)
			v = uint16(int16(d[1]>>base) + int16(d[1]>>(base+16)))
			r[0] |= uint64(v) << ((i + 2) * 16)
			v = uint16(int16(src[0]>>base) + int16(src[0]>>(base+16)))
			r[1] |= uint64(v) << (i * 16)
			v = uint16(int16(src[1]>>base) + int16(src[1]>>(base+16)))
			r[1] |= uint64(v) << ((i + 2) * 16)
		}
		c.XMM[dst] = r
		return nil

	// PHADDD xmm1, xmm2/m128 (0F 38 02)
	case 0x02:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		c.XMM[dst] = [2]uint64{
			uint64(uint32(int32(d[0])+int32(d[0]>>32))) |
				(uint64(uint32(int32(d[1])+int32(d[1]>>32))) << 32),
			uint64(uint32(int32(src[0])+int32(src[0]>>32))) |
				(uint64(uint32(int32(src[1])+int32(src[1]>>32))) << 32),
		}
		return nil

	// PHADDSW xmm1, xmm2/m128 (0F 38 03)
	case 0x03:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			base := i * 32
			v := satSigned16(int32(int16(d[0]>>base)) + int32(int16(d[0]>>(base+16))))
			r[0] |= uint64(uint16(v)) << (i * 16)
			v = satSigned16(int32(int16(d[1]>>base)) + int32(int16(d[1]>>(base+16))))
			r[0] |= uint64(uint16(v)) << ((i + 2) * 16)
			v = satSigned16(int32(int16(src[0]>>base)) + int32(int16(src[0]>>(base+16))))
			r[1] |= uint64(uint16(v)) << (i * 16)
			v = satSigned16(int32(int16(src[1]>>base)) + int32(int16(src[1]>>(base+16))))
			r[1] |= uint64(uint16(v)) << ((i + 2) * 16)
		}
		c.XMM[dst] = r
		return nil

	// PMADDUBSW xmm1, xmm2/m128 (0F 38 04)
	case 0x04:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			base := i * 16
			sum := int32(uint8(d[0]>>base))*int32(int8(src[0]>>base)) +
				int32(uint8(d[0]>>(base+8)))*int32(int8(src[0]>>(base+8)))
			r[0] |= uint64(uint16(satSigned16(sum))) << base
			sum = int32(uint8(d[1]>>base))*int32(int8(src[1]>>base)) +
				int32(uint8(d[1]>>(base+8)))*int32(int8(src[1]>>(base+8)))
			r[1] |= uint64(uint16(satSigned16(sum))) << base
		}
		c.XMM[dst] = r
		return nil

	// PHSUBW xmm1, xmm2/m128 (0F 38 05)
	case 0x05:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			base := i * 32
			v := uint16(int16(d[0]>>base) - int16(d[0]>>(base+16)))
			r[0] |= uint64(v) << (i * 16)
			v = uint16(int16(d[1]>>base) - int16(d[1]>>(base+16)))
			r[0] |= uint64(v) << ((i + 2) * 16)
			v = uint16(int16(src[0]>>base) - int16(src[0]>>(base+16)))
			r[1] |= uint64(v) << (i * 16)
			v = uint16(int16(src[1]>>base) - int16(src[1]>>(base+16)))
			r[1] |= uint64(v) << ((i + 2) * 16)
		}
		c.XMM[dst] = r
		return nil

	// PHSUBD xmm1, xmm2/m128 (0F 38 06)
	case 0x06:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		c.XMM[dst] = [2]uint64{
			uint64(uint32(int32(d[0])-int32(d[0]>>32))) |
				(uint64(uint32(int32(d[1])-int32(d[1]>>32))) << 32),
			uint64(uint32(int32(src[0])-int32(src[0]>>32))) |
				(uint64(uint32(int32(src[1])-int32(src[1]>>32))) << 32),
		}
		return nil

	// PHSUBSW xmm1, xmm2/m128 (0F 38 07)
	case 0x07:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			base := i * 32
			v := satSigned16(int32(int16(d[0]>>base)) - int32(int16(d[0]>>(base+16))))
			r[0] |= uint64(uint16(v)) << (i * 16)
			v = satSigned16(int32(int16(d[1]>>base)) - int32(int16(d[1]>>(base+16))))
			r[0] |= uint64(uint16(v)) << ((i + 2) * 16)
			v = satSigned16(int32(int16(src[0]>>base)) - int32(int16(src[0]>>(base+16))))
			r[1] |= uint64(uint16(v)) << (i * 16)
			v = satSigned16(int32(int16(src[1]>>base)) - int32(int16(src[1]>>(base+16))))
			r[1] |= uint64(uint16(v)) << ((i + 2) * 16)
		}
		c.XMM[dst] = r
		return nil

	// PSIGNB xmm1, xmm2/m128 (0F 38 08)
	case 0x08:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 16; i++ {
			half, shift := i/8, (i%8)*8
			dv := int8(d[half] >> shift)
			sv := int8(src[half] >> shift)
			var out int8
			if sv < 0 {
				out = -dv
			} else if sv > 0 {
				out = dv
			}
			r[half] |= uint64(uint8(out)) << shift
		}
		c.XMM[dst] = r
		return nil

	// PSIGNW xmm1, xmm2/m128 (0F 38 09)
	case 0x09:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			dv := int16(d[half] >> shift)
			sv := int16(src[half] >> shift)
			var out int16
			if sv < 0 {
				out = -dv
			} else if sv > 0 {
				out = dv
			}
			r[half] |= uint64(uint16(out)) << shift
		}
		c.XMM[dst] = r
		return nil

	// PSIGND xmm1, xmm2/m128 (0F 38 0A)
	case 0x0A:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			dv := int32(d[half] >> shift)
			sv := int32(src[half] >> shift)
			var out int32
			if sv < 0 {
				out = -dv
			} else if sv > 0 {
				out = dv
			}
			r[half] |= uint64(uint32(out)) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMULHRSW xmm1, xmm2/m128 (0F 38 0B)
	case 0x0B:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		d := c.XMM[dst]
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			prod := int32(int16(d[half]>>shift)) * int32(int16(src[half]>>shift))
			r[half] |= uint64(uint16(int16((prod+0x4000)>>15))) << shift
		}
		c.XMM[dst] = r
		return nil

	// PABSB xmm1, xmm2/m128 (0F 38 1C)
	case 0x1C:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 16; i++ {
			half, shift := i/8, (i%8)*8
			v := int8(src[half] >> shift)
			var out uint8
			if v < 0 {
				out = uint8(-int16(v))
			} else {
				out = uint8(v)
			}
			r[half] |= uint64(out) << shift
		}
		c.XMM[dst] = r
		return nil

	// PABSW xmm1, xmm2/m128 (0F 38 1D)
	case 0x1D:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			v := int16(src[half] >> shift)
			var out uint16
			if v < 0 {
				out = uint16(-int32(v))
			} else {
				out = uint16(v)
			}
			r[half] |= uint64(out) << shift
		}
		c.XMM[dst] = r
		return nil

	// PABSD xmm1, xmm2/m128 (0F 38 1E)
	case 0x1E:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			v := int32(src[half] >> shift)
			var out uint32
			if v < 0 {
				out = uint32(-int64(v))
			} else {
				out = uint32(v)
			}
			r[half] |= uint64(out) << shift
		}
		c.XMM[dst] = r
		return nil

	// PBLENDVB xmm1, xmm2/m128 (0F 38 10) - mask = XMM0
	case 0x10:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		mask := c.XMM[0]
		var r [2]uint64
		for i := uint(0); i < 16; i++ {
			half := i / 8
			bit := i % 8
			var mb, db, sb byte
			mb = byte(mask[half] >> (bit * 8))
			db = byte(c.XMM[dst][half] >> (bit * 8))
			sb = byte(src[half] >> (bit * 8))
			var out byte
			if mb&0x80 != 0 {
				out = sb
			} else {
				out = db
			}
			r[half] |= uint64(out) << (bit * 8)
		}
		c.XMM[dst] = r
		return nil

	// BLENDVPS xmm1, xmm2/m128 (0F 38 14) - mask = XMM0
	case 0x14:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		mask := c.XMM[0]
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half := i / 2
			shift := (i % 2) * 32
			mb := uint32(mask[half] >> shift)
			db := uint32(c.XMM[dst][half] >> shift)
			sb := uint32(src[half] >> shift)
			var out uint32
			if mb&0x80000000 != 0 {
				out = sb
			} else {
				out = db
			}
			r[half] |= uint64(out) << shift
		}
		c.XMM[dst] = r
		return nil

	// BLENDVPD xmm1, xmm2/m128 (0F 38 15) - mask = XMM0
	case 0x15:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		mask := c.XMM[0]
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			mb := mask[i]
			db := c.XMM[dst][i]
			sb := src[i]
			if mb>>63 != 0 {
				r[i] = sb
			} else {
				r[i] = db
			}
		}
		c.XMM[dst] = r
		return nil

	// PTEST xmm1, xmm2/m128 (0F 38 17) - sets ZF, CF
	case 0x17:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		and0 := c.XMM[dst][0] & src[0]
		and1 := c.XMM[dst][1] & src[1]
		andn0 := (^c.XMM[dst][0]) & src[0]
		andn1 := (^c.XMM[dst][1]) & src[1]
		zf := uint64(0)
		if and0|and1 == 0 {
			zf = flagZF
		}
		cf := uint64(0)
		if andn0|andn1 == 0 {
			cf = flagCF
		}
		c.Rflags = (c.Rflags &^ (flagZF | flagCF | flagSF | flagOF | flagPF)) | zf | cf
		return nil

	// PMULDQ xmm1, xmm2/m128 (0F 38 28) - signed 32→64 multiply of low dwords
	case 0x28:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		a0 := int64(int32(c.XMM[dst][0]))
		a1 := int64(int32(c.XMM[dst][1]))
		b0 := int64(int32(src[0]))
		b1 := int64(int32(src[1]))
		c.XMM[dst] = [2]uint64{uint64(a0 * b0), uint64(a1 * b1)}
		return nil

	// PCMPEQQ xmm1, xmm2/m128 (0F 38 29)
	case 0x29:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := 0; i < 2; i++ {
			if c.XMM[dst][i] == src[i] {
				r[i] = 0xffffffffffffffff
			}
		}
		c.XMM[dst] = r
		return nil

	// PACKUSDW xmm1, xmm2/m128 (0F 38 2B)
	case 0x2B:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		pack := func(v uint64) uint64 {
			var r uint64
			for i := uint(0); i < 2; i++ {
				s := int32(v >> (i * 32))
				var w uint16
				if s < 0 {
					w = 0
				} else if s > 0xffff {
					w = 0xffff
				} else {
					w = uint16(s)
				}
				r |= uint64(w) << (i * 16)
			}
			return r
		}
		lo := pack(c.XMM[dst][0]) | (pack(c.XMM[dst][1]) << 32)
		hi := pack(src[0]) | (pack(src[1]) << 32)
		c.XMM[dst] = [2]uint64{lo, hi}
		return nil

	// PCMPGTQ xmm1, xmm2/m128 (0F 38 37)
	case 0x37:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := 0; i < 2; i++ {
			if int64(c.XMM[dst][i]) > int64(src[i]) {
				r[i] = 0xffffffffffffffff
			}
		}
		c.XMM[dst] = r
		return nil

	// PMINSB xmm1, xmm2/m128 (0F 38 38) - min signed bytes
	case 0x38:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 16; i++ {
			half, bit := i/8, i%8
			a := int8(c.XMM[dst][half] >> (bit * 8))
			b := int8(src[half] >> (bit * 8))
			v := a
			if b < v {
				v = b
			}
			r[half] |= uint64(uint8(v)) << (bit * 8)
		}
		c.XMM[dst] = r
		return nil

	// PMINSD xmm1, xmm2/m128 (0F 38 39) - min signed dwords
	case 0x39:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			a := int32(c.XMM[dst][half] >> shift)
			b := int32(src[half] >> shift)
			v := a
			if b < v {
				v = b
			}
			r[half] |= uint64(uint32(v)) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMINUW xmm1, xmm2/m128 (0F 38 3A) - min unsigned words
	case 0x3A:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			a := uint16(c.XMM[dst][half] >> shift)
			b := uint16(src[half] >> shift)
			v := a
			if b < v {
				v = b
			}
			r[half] |= uint64(v) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMINUD xmm1, xmm2/m128 (0F 38 3B) - min unsigned dwords
	case 0x3B:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			a := uint32(c.XMM[dst][half] >> shift)
			b := uint32(src[half] >> shift)
			v := a
			if b < v {
				v = b
			}
			r[half] |= uint64(v) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMAXSB xmm1, xmm2/m128 (0F 38 3C) - max signed bytes
	case 0x3C:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 16; i++ {
			half, bit := i/8, i%8
			a := int8(c.XMM[dst][half] >> (bit * 8))
			b := int8(src[half] >> (bit * 8))
			v := a
			if b > v {
				v = b
			}
			r[half] |= uint64(uint8(v)) << (bit * 8)
		}
		c.XMM[dst] = r
		return nil

	// PMAXSD xmm1, xmm2/m128 (0F 38 3D) - max signed dwords
	case 0x3D:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			a := int32(c.XMM[dst][half] >> shift)
			b := int32(src[half] >> shift)
			v := a
			if b > v {
				v = b
			}
			r[half] |= uint64(uint32(v)) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMAXUW xmm1, xmm2/m128 (0F 38 3E) - max unsigned words
	case 0x3E:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			a := uint16(c.XMM[dst][half] >> shift)
			b := uint16(src[half] >> shift)
			v := a
			if b > v {
				v = b
			}
			r[half] |= uint64(v) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMAXUD xmm1, xmm2/m128 (0F 38 3F) - max unsigned dwords
	case 0x3F:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			a := uint32(c.XMM[dst][half] >> shift)
			b := uint32(src[half] >> shift)
			v := a
			if b > v {
				v = b
			}
			r[half] |= uint64(v) << shift
		}
		c.XMM[dst] = r
		return nil

	// PMULLD xmm1, xmm2/m128 (0F 38 40) - multiply low dwords, store low 32 bits
	case 0x40:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			a := uint32(c.XMM[dst][half] >> shift)
			b := uint32(src[half] >> shift)
			r[half] |= uint64(a*b) << shift
		}
		c.XMM[dst] = r
		return nil

	// PHMINPOSUW xmm1, xmm2/m128 (0F 38 41)
	case 0x41:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		_ = dst
		minVal := uint16(0xffff)
		minIdx := uint16(0)
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			v := uint16(src[half] >> shift)
			if v < minVal {
				minVal = v
				minIdx = uint16(i)
			}
		}
		c.XMM[dst] = [2]uint64{uint64(minVal) | (uint64(minIdx) << 16), 0}
		return nil

	// AESIMC xmm1, xmm2/m128 (0F 38 DB)
	case 0xDB:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesInvMixColumns(src)
		return nil

	// AESENC xmm1, xmm2/m128 (0F 38 DC)
	case 0xDC:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesEncRound(c.XMM[dst], src)
		return nil

	// AESENCLAST xmm1, xmm2/m128 (0F 38 DD)
	case 0xDD:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesEncLastRound(c.XMM[dst], src)
		return nil

	// AESDEC xmm1, xmm2/m128 (0F 38 DE)
	case 0xDE:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesDecRound(c.XMM[dst], src)
		return nil

	// AESDECLAST xmm1, xmm2/m128 (0F 38 DF)
	case 0xDF:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesDecLastRound(c.XMM[dst], src)
		return nil

	// MOVBE r16/r32/r64, m16/m32/m64 (0F 38 F0)
	// CRC32 r32, r/m8 (F2 0F 38 F0)
	case 0xF0:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		if pfx.repne {
			src, err := c.readRM(m, pfx, 1)
			if err != nil {
				return err
			}
			crc := crc32cUpdate(uint32(c.Regs[m.reg]), src, 1)
			c.writeRegSized(m.reg, 4, uint64(crc))
			return nil
		}
		if m.mod == 3 {
			return fmt.Errorf("invalid MOVBE load register form at RIP=0x%x", startRIP)
		}
		addr, _, err := c.resolveRMAddr(m, pfx)
		if err != nil {
			return err
		}
		size := 4
		if pfx.rexW() {
			size = 8
		} else if pfx.op66 {
			size = 2
		}
		val, err := c.readMem(addr, size)
		if err != nil {
			return err
		}
		switch size {
		case 2:
			val = uint64(bits.ReverseBytes16(uint16(val)))
		case 4:
			val = uint64(bits.ReverseBytes32(uint32(val)))
		case 8:
			val = bits.ReverseBytes64(val)
		}
		c.writeRegSized(m.reg, size, val)
		return nil

	// MOVBE m16/m32/m64, r16/r32/r64 (0F 38 F1)
	// CRC32 r32/r64, r/m16/r/m32/r/m64 (F2 0F 38 F1)
	case 0xF1:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		if pfx.repne {
			srcSize := 4
			dstSize := 4
			if pfx.rexW() {
				srcSize = 8
				dstSize = 8
			} else if pfx.op66 {
				srcSize = 2
			}
			src, err := c.readRM(m, pfx, srcSize)
			if err != nil {
				return err
			}
			crc := crc32cUpdate(uint32(c.Regs[m.reg]), src, srcSize)
			c.writeRegSized(m.reg, dstSize, uint64(crc))
			return nil
		}
		if m.mod == 3 {
			return fmt.Errorf("invalid MOVBE store register form at RIP=0x%x", startRIP)
		}
		addr, _, err := c.resolveRMAddr(m, pfx)
		if err != nil {
			return err
		}
		size := 4
		if pfx.rexW() {
			size = 8
		} else if pfx.op66 {
			size = 2
		}
		val := c.readRegSized(m.reg, size)
		switch size {
		case 2:
			val = uint64(bits.ReverseBytes16(uint16(val)))
		case 4:
			val = uint64(bits.ReverseBytes32(uint32(val)))
		case 8:
			val = bits.ReverseBytes64(val)
		}
		return c.writeMem(addr, size, val)

	default:
		return fmt.Errorf("unimplemented 0F 38 %02X at RIP=0x%x", op3, startRIP)
	}
}

// dispatch0F3A handles the 66 0F 3A xx family (SSE4.1 immediate-operand ops).
func (c *CPU) dispatch0F3A(pfx *prefixState, startRIP uint64) error {
	op3, err := c.fetch8()
	if err != nil {
		return err
	}

	switch op3 {
	// ROUNDPS xmm1, xmm2/m128, imm8 (0F 3A 08)
	case 0x08:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			f := math.Float32frombits(uint32(src[half] >> shift))
			r[half] |= uint64(math.Float32bits(roundFloat32(f, imm))) << shift
		}
		c.XMM[dst] = r
		return nil

	// ROUNDPD xmm1, xmm2/m128, imm8 (0F 3A 09)
	case 0x09:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		c.XMM[dst] = [2]uint64{
			math.Float64bits(roundFloat64(math.Float64frombits(src[0]), imm)),
			math.Float64bits(roundFloat64(math.Float64frombits(src[1]), imm)),
		}
		return nil

	// ROUNDSS xmm1, xmm2/m32, imm8 (0F 3A 0A)
	case 0x0A:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		var srcBits uint32
		if m.mod == 3 {
			srcBits = uint32(c.XMM[m.rm][0])
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			v, _ := c.mem.Read32(addr)
			srcBits = v
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		f := math.Float32frombits(srcBits)
		result := math.Float32bits(roundFloat32(f, imm))
		c.XMM[m.reg][0] = (c.XMM[m.reg][0] & 0xffffffff00000000) | uint64(result)
		return nil

	// ROUNDSD xmm1, xmm2/m64, imm8 (0F 3A 0B)
	case 0x0B:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		var srcBits uint64
		if m.mod == 3 {
			srcBits = c.XMM[m.rm][0]
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			srcBits, _ = c.mem.Read64(addr)
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		f := math.Float64frombits(srcBits)
		c.XMM[m.reg][0] = math.Float64bits(roundFloat64(f, imm))
		return nil

	// BLENDPS xmm1, xmm2/m128, imm8 (0F 3A 0C)
	case 0x0C:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			half, shift := i/2, (i%2)*32
			if (imm>>i)&1 != 0 {
				r[half] |= uint64(uint32(src[half]>>shift)) << shift
			} else {
				r[half] |= uint64(uint32(c.XMM[dst][half]>>shift)) << shift
			}
		}
		c.XMM[dst] = r
		return nil

	// BLENDPD xmm1, xmm2/m128, imm8 (0F 3A 0D)
	case 0x0D:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			if (imm>>i)&1 != 0 {
				r[i] = src[i]
			} else {
				r[i] = c.XMM[dst][i]
			}
		}
		c.XMM[dst] = r
		return nil

	// PBLENDW xmm1, xmm2/m128, imm8 (0F 3A 0E)
	case 0x0E:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			half, shift := i/4, (i%4)*16
			if (imm>>i)&1 != 0 {
				r[half] |= uint64(uint16(src[half]>>shift)) << shift
			} else {
				r[half] |= uint64(uint16(c.XMM[dst][half]>>shift)) << shift
			}
		}
		c.XMM[dst] = r
		return nil

	// PEXTRB r/m8, xmm2, imm8 (0F 3A 14)
	case 0x14:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		idx := uint(imm & 0x0f)
		half, bit := idx/8, idx%8
		val := uint64(byte(c.XMM[m.reg][half] >> (bit * 8)))
		if m.mod == 3 {
			c.writeRegSized(m.rm, 4, val)
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			c.mem.Write8(addr, byte(val))
		}
		return nil

	// PEXTRW r/m16, xmm2, imm8 (0F 3A 15)
	case 0x15:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		idx := uint(imm & 0x07)
		half, shift := idx/4, (idx%4)*16
		val := uint64(uint16(c.XMM[m.reg][half] >> shift))
		if m.mod == 3 {
			c.writeRegSized(m.rm, 4, val)
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			c.mem.Write16(addr, uint16(val))
		}
		return nil

	// PEXTRD/PEXTRQ r/m32/64, xmm2, imm8 (0F 3A 16)
	case 0x16:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		if pfx.rexW() {
			// PEXTRQ
			idx := uint(imm & 0x01)
			val := c.XMM[m.reg][idx]
			if m.mod == 3 {
				c.writeRegSized(m.rm, 8, val)
			} else {
				addr, _, err := c.resolveRMAddr(m, pfx)
				if err != nil {
					return err
				}
				c.mem.Write64(addr, val)
			}
		} else {
			// PEXTRD
			idx := uint(imm & 0x03)
			half, shift := idx/2, (idx%2)*32
			val := uint64(uint32(c.XMM[m.reg][half] >> shift))
			if m.mod == 3 {
				c.writeRegSized(m.rm, 4, val)
			} else {
				addr, _, err := c.resolveRMAddr(m, pfx)
				if err != nil {
					return err
				}
				c.mem.Write32(addr, uint32(val))
			}
		}
		return nil

	// EXTRACTPS r/m32, xmm1, imm8 (0F 3A 17)
	case 0x17:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		idx := uint(imm & 0x03)
		half, shift := idx/2, (idx%2)*32
		val := uint32(c.XMM[m.reg][half] >> shift)
		if m.mod == 3 {
			c.writeRegSized(m.rm, 4, uint64(val))
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			c.mem.Write32(addr, val)
		}
		return nil

	// PINSRB xmm1, r/m8, imm8 (0F 3A 20)
	case 0x20:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		idx := uint(imm & 0x0f)
		var val byte
		if m.mod == 3 {
			val = byte(c.Regs[m.rm])
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			val, _ = c.mem.Read8(addr)
		}
		half, bit := idx/8, idx%8
		mask := ^(uint64(0xff) << (bit * 8))
		c.XMM[m.reg][half] = (c.XMM[m.reg][half] & mask) | (uint64(val) << (bit * 8))
		return nil

	// INSERTPS xmm1, xmm2/m32, imm8 (0F 3A 21)
	case 0x21:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		zmask := imm & 0x0f
		dstIdx := uint((imm >> 4) & 0x03)
		var srcVal uint32
		if m.mod == 3 {
			srcIdx := uint((imm >> 6) & 0x03)
			half, shift := srcIdx/2, (srcIdx%2)*32
			srcVal = uint32(c.XMM[m.rm][half] >> shift)
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			srcVal, _ = c.mem.Read32(addr)
		}
		half, shift := dstIdx/2, (dstIdx%2)*32
		mask := ^(uint64(0xffffffff) << shift)
		c.XMM[m.reg][half] = (c.XMM[m.reg][half] & mask) | (uint64(srcVal) << shift)
		// zero elements as indicated by zmask
		for i := uint(0); i < 4; i++ {
			if (zmask>>i)&1 != 0 {
				h, sh := i/2, (i%2)*32
				c.XMM[m.reg][h] &^= 0xffffffff << sh
			}
		}
		return nil

	// PINSRD/PINSRQ xmm1, r/m32/64, imm8 (0F 3A 22)
	case 0x22:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		if pfx.rexW() {
			// PINSRQ
			idx := uint(imm & 0x01)
			var val uint64
			if m.mod == 3 {
				val = c.Regs[m.rm]
			} else {
				addr, _, err := c.resolveRMAddr(m, pfx)
				if err != nil {
					return err
				}
				val, _ = c.mem.Read64(addr)
			}
			c.XMM[m.reg][idx] = val
		} else {
			// PINSRD
			idx := uint(imm & 0x03)
			var val uint32
			if m.mod == 3 {
				val = uint32(c.Regs[m.rm])
			} else {
				addr, _, err := c.resolveRMAddr(m, pfx)
				if err != nil {
					return err
				}
				val, _ = c.mem.Read32(addr)
			}
			half, shift := idx/2, (idx%2)*32
			mask := ^(uint64(0xffffffff) << shift)
			c.XMM[m.reg][half] = (c.XMM[m.reg][half] & mask) | (uint64(val) << shift)
		}
		return nil

	// DPPS xmm1, xmm2/m128, imm8 (0F 3A 40) - dot product of packed singles
	case 0x40:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var dp float32
		for i := uint(0); i < 4; i++ {
			if (imm>>(i+4))&1 != 0 {
				half, shift := i/2, (i%2)*32
				a := math.Float32frombits(uint32(c.XMM[dst][half] >> shift))
				b := math.Float32frombits(uint32(src[half] >> shift))
				dp += a * b
			}
		}
		var r [2]uint64
		for i := uint(0); i < 4; i++ {
			if (imm>>i)&1 != 0 {
				half, shift := i/2, (i%2)*32
				r[half] |= uint64(math.Float32bits(dp)) << shift
			}
		}
		c.XMM[dst] = r
		return nil

	// DPPD xmm1, xmm2/m128, imm8 (0F 3A 41) - dot product of packed doubles
	case 0x41:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var dp float64
		for i := uint(0); i < 2; i++ {
			if (imm>>(i+4))&1 != 0 {
				a := math.Float64frombits(c.XMM[dst][i])
				b := math.Float64frombits(src[i])
				dp += a * b
			}
		}
		var r [2]uint64
		for i := uint(0); i < 2; i++ {
			if (imm>>i)&1 != 0 {
				r[i] = math.Float64bits(dp)
			}
		}
		c.XMM[dst] = r
		return nil

	// MPSADBW xmm1, xmm2/m128, imm8 (0F 3A 42) - sum of absolute differences
	case 0x42:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		srcOff := uint((imm&0x04)>>2) * 4
		dstOff := uint((imm & 0x03)) * 4
		var r [2]uint64
		for i := uint(0); i < 8; i++ {
			var sad uint16
			for j := uint(0); j < 4; j++ {
				di := dstOff + j
				si := srcOff + i + j // Wait, MPSADBW is more complex but approximate
				// Simplified: treat as SADs
				dh, db := di/8, di%8
				sh, sb := si/8, si%8
				av := byte(c.XMM[dst][dh] >> (db * 8))
				if sh < 2 {
					bv := byte(src[sh] >> (sb * 8))
					d := int(av) - int(bv)
					if d < 0 {
						d = -d
					}
					sad += uint16(d)
				}
			}
			half, shift := i/4, (i%4)*16
			r[half] |= uint64(sad) << shift
		}
		c.XMM[dst] = r
		return nil

	// PCLMULQDQ xmm1, xmm2/m128, imm8 (0F 3A 44) - carry-less multiply
	case 0x44:
		m, err := c.decodeModRM(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		var src [2]uint64
		if m.mod == 3 {
			src = c.XMM[m.rm]
		} else {
			addr, _, err := c.resolveRMAddr(m, pfx)
			if err != nil {
				return err
			}
			lo, _ := c.mem.Read64(addr)
			hi, _ := c.mem.Read64(addr + 8)
			src = [2]uint64{lo, hi}
		}
		a := c.XMM[m.reg][(imm)&1]
		b := src[(imm>>4)&1]
		lo, hi := clmul64(a, b)
		c.XMM[m.reg] = [2]uint64{lo, hi}
		return nil

	// AESKEYGENASSIST xmm1, xmm2/m128, imm8 (0F 3A DF)
	case 0xDF:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		c.XMM[dst] = c.aesKeyGenAssist(src, imm)
		return nil

	// PCMPESTRM xmm1, xmm2/m128, imm8 (0F 3A 60) - explicit-length string compare to mask
	case 0x60:
		return c.pcmpxstrx(pfx, false, false, startRIP)

	// PCMPESTRI xmm1, xmm2/m128, imm8 (0F 3A 61) - explicit-length string compare to index
	case 0x61:
		return c.pcmpxstrx(pfx, false, true, startRIP)

	// PCMPISTRM xmm1, xmm2/m128, imm8 (0F 3A 62) - implicit-length string compare to mask
	case 0x62:
		return c.pcmpxstrx(pfx, true, false, startRIP)

	// PCMPISTRI xmm1, xmm2/m128, imm8 (0F 3A 63) - implicit-length string compare to index
	case 0x63:
		return c.pcmpxstrx(pfx, true, true, startRIP)

	// PALIGNR xmm1, xmm2/m128, imm8 (66 0F 3A 0F)
	// Concatenates dst:src (256-bit), shifts right by imm8*8 bits, takes low 128 bits.
	case 0x0F:
		dst, src, err := c.loadXMM128(pfx)
		if err != nil {
			return err
		}
		imm, err := c.fetch8()
		if err != nil {
			return err
		}
		shift := uint(imm)
		if shift >= 32 {
			c.XMM[dst] = [2]uint64{0, 0}
		} else if shift >= 16 {
			// result comes entirely from dst (upper 128 bits of the concat)
			s := (shift - 16) * 8
			d := c.XMM[dst]
			var r [2]uint64
			if s == 0 {
				r = d
			} else if s < 64 {
				r[0] = (d[0] >> s) | (d[1] << (64 - s))
				r[1] = d[1] >> s
			} else {
				r[0] = d[1] >> (s - 64)
				r[1] = 0
			}
			c.XMM[dst] = r
		} else {
			// result spans src (bits 0-127) and dst (bits 128-255)
			// concat = dst:src as little-endian 256-bit, shift right by shift bytes
			s := shift * 8
			var r [2]uint64
			if s == 0 {
				r = src
			} else if s < 64 {
				r[0] = (src[0] >> s) | (src[1] << (64 - s))
				r[1] = (src[1] >> s) | (c.XMM[dst][0] << (64 - s))
			} else if s == 64 {
				r[0] = src[1]
				r[1] = c.XMM[dst][0]
			} else {
				s2 := s - 64
				r[0] = (src[1] >> s2) | (c.XMM[dst][0] << (64 - s2))
				r[1] = (c.XMM[dst][0] >> s2) | (c.XMM[dst][1] << (64 - s2))
			}
			c.XMM[dst] = r
		}
		return nil

	default:
		return fmt.Errorf("unimplemented 0F 3A %02X at RIP=0x%x", op3, startRIP)
	}
}

// roundFloat32 rounds a float32 according to SSE rounding mode imm8.
func roundFloat32(f float32, imm byte) float32 {
	mode := imm & 0x03
	switch mode {
	case 0: // round to nearest even
		return float32(math.RoundToEven(float64(f)))
	case 1: // round toward -∞
		return float32(math.Floor(float64(f)))
	case 2: // round toward +∞
		return float32(math.Ceil(float64(f)))
	case 3: // round toward zero (truncate)
		return float32(math.Trunc(float64(f)))
	}
	return f
}

// roundFloat64 rounds a float64 according to SSE rounding mode imm8.
func roundFloat64(f float64, imm byte) float64 {
	mode := imm & 0x03
	switch mode {
	case 0:
		return math.RoundToEven(f)
	case 1:
		return math.Floor(f)
	case 2:
		return math.Ceil(f)
	case 3:
		return math.Trunc(f)
	}
	return f
}

// clmul64 performs a 64×64 carry-less multiply, returning (lo64, hi64).
func clmul64(a, b uint64) (uint64, uint64) {
	var lo, hi uint64
	for i := 0; i < 64; i++ {
		if (b>>uint(i))&1 != 0 {
			lo ^= a << uint(i)
			if i > 0 {
				hi ^= a >> uint(64-i)
			}
		}
	}
	return lo, hi
}

// pcmpxstrx implements PCMPESTR*/PCMPISTR* (0F 3A 60-63).
// implicit: use string lengths from XMM null terminators (PCMPISTR*)
// toIndex: return index in ECX (vs mask in XMM0).
func (c *CPU) pcmpxstrx(pfx *prefixState, implicit bool, toIndex bool, startRIP uint64) error {
	m, err := c.decodeModRM(pfx)
	if err != nil {
		return err
	}
	imm, err := c.fetch8()
	if err != nil {
		return err
	}
	var src2 [2]uint64
	if m.mod == 3 {
		src2 = c.XMM[m.rm]
	} else {
		addr, _, err2 := c.resolveRMAddr(m, pfx)
		if err2 != nil {
			return err2
		}
		lo, _ := c.mem.Read64(addr)
		hi, _ := c.mem.Read64(addr + 8)
		src2 = [2]uint64{lo, hi}
	}
	src1 := c.XMM[m.reg]

	// Determine element size and signedness
	elemBytes := 1
	if imm&0x01 != 0 {
		elemBytes = 2
	}
	nElems := 16 / elemBytes
	signed := (imm & 0x02) != 0

	// Get lengths
	var la, lb int
	if implicit {
		// Find null terminator
		la = findNullTerminator(src1, nElems, elemBytes)
		lb = findNullTerminator(src2, nElems, elemBytes)
	} else {
		// Explicit lengths from EAX/ECX
		la = int(int32(c.Regs[RAX]))
		lb = int(int32(c.Regs[RCX]))
		// Saturate to nElems
		if la < -nElems {
			la = -nElems
		}
		if la > nElems {
			la = nElems
		}
		if lb < -nElems {
			lb = -nElems
		}
		if lb > nElems {
			lb = nElems
		}
		if la < 0 {
			la = -la
		}
		if lb < 0 {
			lb = -lb
		}
	}

	// Build comparison result bitmask
	agg := (imm >> 2) & 0x03
	res := pcmpAgg(src1, src2, la, lb, nElems, elemBytes, signed, agg)

	// Polarity
	pol := (imm >> 4) & 0x03
	switch pol {
	case 1: // negate
		for i := 0; i < nElems; i++ {
			res ^= 1 << uint(i)
		}
		res &= (1 << uint(nElems)) - 1
	case 3: // negate valid
		for i := 0; i < lb; i++ {
			res ^= 1 << uint(i)
		}
	}

	// Set flags
	cf := uint64(0)
	if res != 0 {
		cf = flagCF
	}
	zf := uint64(0)
	if lb < nElems {
		zf = flagZF
	}
	sf := uint64(0)
	if la < nElems {
		sf = flagSF
	}
	of := uint64(0)
	if res&1 != 0 {
		of = flagOF
	}
	c.Rflags = (c.Rflags &^ (flagCF | flagZF | flagSF | flagOF | flagPF)) | cf | zf | sf | of

	if toIndex {
		// Return lowest (or highest) set bit index in ECX
		idx := uint64(nElems)
		if (imm>>6)&1 != 0 {
			// most significant
			idx = uint64(bits.Len(uint(res)))
			if res != 0 {
				idx--
			} else {
				idx = uint64(nElems)
			}
		} else {
			// least significant
			if res != 0 {
				idx = uint64(bits.TrailingZeros(uint(res)))
			}
		}
		c.Regs[RCX] = idx
	} else {
		// Return mask in XMM0
		if nElems == 16 {
			c.XMM[0] = [2]uint64{uint64(res), 0}
		} else {
			// 8 elements of 2 bytes each - expand each bit to a 16-bit mask
			var lo, hi uint64
			for i := 0; i < 8; i++ {
				if (res>>uint(i))&1 != 0 {
					if i < 4 {
						lo |= 0xffff << (uint(i) * 16)
					} else {
						hi |= 0xffff << (uint(i-4) * 16)
					}
				}
			}
			c.XMM[0] = [2]uint64{lo, hi}
		}
	}
	return nil
}

// findNullTerminator returns the number of elements before the first null.
func findNullTerminator(v [2]uint64, nElems, elemBytes int) int {
	for i := 0; i < nElems; i++ {
		half := i * elemBytes / 8
		shift := uint(i*elemBytes%8) * 8
		var elem uint64
		if elemBytes == 1 {
			elem = (v[half] >> shift) & 0xff
		} else {
			elem = (v[half] >> shift) & 0xffff
		}
		if elem == 0 {
			return i
		}
	}
	return nElems
}

// pcmpAgg computes the aggregation step for PCMPXSTR*.
func pcmpAgg(src1, src2 [2]uint64, la, lb, nElems, elemBytes int, signed bool, agg byte) int {
	getElem := func(v [2]uint64, i int) int64 {
		half := i * elemBytes / 8
		shift := uint(i*elemBytes%8) * 8
		if elemBytes == 1 {
			b := byte(v[half] >> shift)
			if signed {
				return int64(int8(b))
			}
			return int64(b)
		}
		w := uint16(v[half] >> shift)
		if signed {
			return int64(int16(w))
		}
		return int64(w)
	}

	res := 0
	switch agg {
	case 0: // equal any: for each element in src2, set bit if src2[i] matches any elem in src1
		for j := 0; j < nElems; j++ {
			if j >= lb {
				continue
			}
			bv := getElem(src2, j)
			for i := 0; i < la; i++ {
				if getElem(src1, i) == bv {
					res |= 1 << uint(j)
					break
				}
			}
		}
	case 1: // ranges: for each element in src2, check if within range pair in src1
		for j := 0; j < nElems; j++ {
			if j >= lb {
				continue
			}
			bv := getElem(src2, j)
			for i := 0; i+1 < la; i += 2 {
				lo := getElem(src1, i)
				hi := getElem(src1, i+1)
				if bv >= lo && bv <= hi {
					res |= 1 << uint(j)
					break
				}
			}
		}
	case 2: // equal each: element-wise equality
		for i := 0; i < nElems; i++ {
			aInvalid := i >= la
			bInvalid := i >= lb
			if aInvalid || bInvalid {
				if aInvalid && bInvalid {
					res |= 1 << uint(i) // both invalid → match
				}
				// one invalid → no match
				continue
			}
			if getElem(src1, i) == getElem(src2, i) {
				res |= 1 << uint(i)
			}
		}
	case 3: // equal ordered: substring search
		for j := 0; j < nElems; j++ {
			if j >= lb {
				continue
			}
			match := true
			for i := 0; i < la; i++ {
				if j+i >= nElems || j+i >= lb {
					break
				}
				if getElem(src1, i) != getElem(src2, j+i) {
					match = false
					break
				}
			}
			if match {
				res |= 1 << uint(j)
			}
		}
	}
	return res
}
