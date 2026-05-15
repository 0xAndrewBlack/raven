//go:build guest_windows

package main

import (
	"bytes"
	"encoding/binary"
	"image"
)

type iconHandleData struct {
	width, height int32
	pixels        []byte
}

func decodeIconResource(data []byte) (*iconHandleData, bool) {
	if len(data) >= 8 && bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}) {
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, false
		}
		bounds := img.Bounds()
		width, height := bounds.Dx(), bounds.Dy()
		if width <= 0 || height <= 0 {
			return nil, false
		}
		pixels := make([]byte, width*height*4)
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				r, g, b, a := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
				offset := (y*width + x) * 4
				pixels[offset+0] = byte(b >> 8)
				pixels[offset+1] = byte(g >> 8)
				pixels[offset+2] = byte(r >> 8)
				pixels[offset+3] = byte(a >> 8)
			}
		}
		return &iconHandleData{width: int32(width), height: int32(height), pixels: pixels}, true
	}

	bitmap, err := decodeICODIB(data)
	if err != nil || bitmap == nil {
		return nil, false
	}
	return &iconHandleData{
		width:  int32(bitmap.width),
		height: int32(bitmap.height),
		pixels: append([]byte(nil), bitmap.pixels...),
	}, true
}

func scaleIconPixels(icon *iconHandleData, width, height int32) []byte {
	if icon == nil || icon.width <= 0 || icon.height <= 0 || len(icon.pixels) < int(icon.width*icon.height*4) {
		return nil
	}
	if width <= 0 {
		width = icon.width
	}
	if height <= 0 {
		height = icon.height
	}
	if width == icon.width && height == icon.height {
		return append([]byte(nil), icon.pixels...)
	}
	pixels := make([]byte, width*height*4)
	for y := int32(0); y < height; y++ {
		sourceY := y * icon.height / height
		for x := int32(0); x < width; x++ {
			sourceX := x * icon.width / width
			sourceOffset := (sourceY*icon.width + sourceX) * 4
			targetOffset := (y*width + x) * 4
			copy(pixels[targetOffset:targetOffset+4], icon.pixels[sourceOffset:sourceOffset+4])
		}
	}
	return pixels
}

func selectGroupIconResource(data []byte, desiredWidth, desiredHeight int32) uint32 {
	if len(data) < 6 || binary.LittleEndian.Uint16(data[0:2]) != 0 ||
		binary.LittleEndian.Uint16(data[2:4]) != 1 {
		return 0
	}
	count := int(binary.LittleEndian.Uint16(data[4:6]))
	bestID := uint32(0)
	bestScore := int64(1<<62 - 1)
	for i := 0; i < count; i++ {
		offset := 6 + i*14
		if offset+14 > len(data) {
			break
		}
		width := int32(data[offset])
		height := int32(data[offset+1])
		if width == 0 {
			width = 256
		}
		if height == 0 {
			height = 256
		}
		targetWidth, targetHeight := desiredWidth, desiredHeight
		if targetWidth <= 0 {
			targetWidth = 32
		}
		if targetHeight <= 0 {
			targetHeight = 32
		}
		widthDelta := int64(width - targetWidth)
		if widthDelta < 0 {
			widthDelta = -widthDelta
		}
		heightDelta := int64(height - targetHeight)
		if heightDelta < 0 {
			heightDelta = -heightDelta
		}
		bitCount := int64(binary.LittleEndian.Uint16(data[offset+6 : offset+8]))
		score := (widthDelta+heightDelta)*1024 - bitCount
		if score < bestScore {
			bestScore = score
			bestID = uint32(binary.LittleEndian.Uint16(data[offset+12 : offset+14]))
		}
	}
	return bestID
}
