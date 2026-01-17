package dsound

import (
	"encoding/binary"
	"math"
)

type Mixer struct {
	OutputFormat WAVEFORMATEX
	Buffers      []*SoundBuffer
	MixBuffer    []float32
}

func (m *Mixer) Mix(outSamples int) []byte {
	if outSamples <= 0 {
		return nil
	}
	outFmt := NormalizeFormat(m.OutputFormat)
	if outFmt.WBitsPerSample == 0 {
		outFmt.WBitsPerSample = 16
	}
	channels := int(outFmt.NChannels)
	if channels <= 0 {
		channels = 2
	}
	needed := outSamples * channels
	if cap(m.MixBuffer) < needed {
		m.MixBuffer = make([]float32, needed)
	} else {
		m.MixBuffer = m.MixBuffer[:needed]
		for i := range m.MixBuffer {
			m.MixBuffer[i] = 0
		}
	}
	for _, buffer := range m.Buffers {
		if buffer == nil {
			continue
		}
		mixSoundBuffer(m.MixBuffer, buffer, outFmt, outSamples, channels)
	}
	out := make([]byte, needed*2)
	for i, sample := range m.MixBuffer {
		if sample < -1 {
			sample = -1
		} else if sample > 1 {
			sample = 1
		}
		binary.LittleEndian.PutUint16(out[i*2:], uint16(int16(sample*32767)))
	}
	return out
}

func mixSoundBuffer(dst []float32, buffer *SoundBuffer, outputFormat WAVEFORMATEX, outSamples, outChannels int) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	inputFormat := NormalizeFormat(buffer.Format)
	if !buffer.Playing || buffer.Size == 0 || len(buffer.Data) == 0 || inputFormat.WFormatTag != WaveFormatPCM || inputFormat.NBlockAlign == 0 {
		return
	}
	totalFrames := int(buffer.Size / uint32(inputFormat.NBlockAlign))
	if totalFrames == 0 {
		buffer.Playing = false
		return
	}
	inputRate := buffer.Frequency
	if inputRate == 0 {
		inputRate = inputFormat.NSamplesPerSec
	}
	if inputRate == 0 || outputFormat.NSamplesPerSec == 0 {
		return
	}
	step := float64(inputRate) / float64(outputFormat.NSamplesPerSec)
	framePos := float64(buffer.PlayCursor) / float64(inputFormat.NBlockAlign)
	baseGain := float32(math.Pow(10, float64(buffer.Volume)/2000.0))
	leftGain := baseGain
	rightGain := baseGain
	if buffer.Pan > 0 {
		leftGain *= float32(1.0 - float64(buffer.Pan)/10000.0)
	}
	if buffer.Pan < 0 {
		rightGain *= float32(1.0 + float64(buffer.Pan)/10000.0)
	}
	for frame := 0; frame < outSamples; frame++ {
		if !buffer.Looping && framePos >= float64(totalFrames) {
			buffer.Playing = false
			break
		}
		left, right := sampleAt(buffer.Data, inputFormat, framePos, buffer.Looping)
		idx := frame * outChannels
		if outChannels == 1 {
			dst[idx] += (left + right) * 0.5 * baseGain
		} else {
			dst[idx] += left * leftGain
			dst[idx+1] += right * rightGain
		}
		framePos += step
		if buffer.Looping {
			framePos = math.Mod(framePos, float64(totalFrames))
			if framePos < 0 {
				framePos += float64(totalFrames)
			}
		}
	}
	if buffer.Playing {
		if buffer.Looping {
			framePos = math.Mod(framePos, float64(totalFrames))
			if framePos < 0 {
				framePos += float64(totalFrames)
			}
			buffer.PlayCursor = uint32(framePos*float64(inputFormat.NBlockAlign)) % buffer.Size
		} else if framePos >= float64(totalFrames) {
			buffer.PlayCursor = 0
			buffer.Playing = false
		} else {
			buffer.PlayCursor = uint32(framePos * float64(inputFormat.NBlockAlign))
		}
	}
}

func sampleAt(data []byte, format WAVEFORMATEX, framePos float64, looping bool) (float32, float32) {
	frame0 := int(math.Floor(framePos))
	frac := float32(framePos - float64(frame0))
	left0, right0 := decodeFrame(data, format, frame0, looping)
	if frac == 0 {
		return left0, right0
	}
	left1, right1 := decodeFrame(data, format, frame0+1, looping)
	return left0 + (left1-left0)*frac, right0 + (right1-right0)*frac
}

func decodeFrame(data []byte, format WAVEFORMATEX, frameIndex int, looping bool) (float32, float32) {
	frameBytes := int(format.NBlockAlign)
	if frameBytes <= 0 {
		return 0, 0
	}
	totalFrames := len(data) / frameBytes
	if totalFrames == 0 {
		return 0, 0
	}
	if looping {
		frameIndex %= totalFrames
		if frameIndex < 0 {
			frameIndex += totalFrames
		}
	} else {
		if frameIndex < 0 || frameIndex >= totalFrames {
			return 0, 0
		}
	}
	frameOffset := frameIndex * frameBytes
	sampleWidth := int(format.WBitsPerSample) / 8
	if sampleWidth <= 0 {
		return 0, 0
	}
	readSample := func(channel int) float32 {
		offset := frameOffset + channel*sampleWidth
		if offset+sampleWidth > len(data) {
			return 0
		}
		switch format.WBitsPerSample {
		case 8:
			return (float32(data[offset]) - 128.0) / 128.0
		case 16:
			return float32(int16(binary.LittleEndian.Uint16(data[offset:]))) / 32768.0
		default:
			return 0
		}
	}
	left := readSample(0)
	right := left
	if format.NChannels >= 2 {
		right = readSample(1)
	}
	return left, right
}
