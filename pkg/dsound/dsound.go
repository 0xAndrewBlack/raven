//go:build guest_windows

package dsound

import "sync"

type DirectSound struct {
	Buffers          []*SoundBuffer
	SecondaryBuffers []*SoundBuffer
	PrimaryBuffer    *SoundBuffer
	PrimaryFormat    WAVEFORMATEX
	Format           WAVEFORMATEX
	CooperativeLevel uint32
	mu               sync.Mutex
}

func NewDirectSound() *DirectSound {
	format := DefaultFormat()
	return &DirectSound{PrimaryFormat: format, Format: format}
}

func (d *DirectSound) CreateSoundBuffer(desc DSBUFFERDESC) *SoundBuffer {
	d.mu.Lock()
	defer d.mu.Unlock()

	format := d.PrimaryFormat
	if desc.LpwfxFormat != nil {
		format = NormalizeFormat(*desc.LpwfxFormat)
	}
	if desc.DwFlags&DSBCAPS_PRIMARYBUFFER != 0 {
		d.PrimaryFormat = format
		d.Format = format
	}
	if desc.DwBufferBytes == 0 {
		desc.DwBufferBytes = format.NAvgBytesPerSec
		if desc.DwBufferBytes == 0 {
			desc.DwBufferBytes = 4096
		}
	}
	buffer := &SoundBuffer{
		Data:      make([]byte, desc.DwBufferBytes),
		Size:      desc.DwBufferBytes,
		Format:    format,
		Volume:    0,
		Frequency: format.NSamplesPerSec,
		Pan:       0,
		IsPrimary: desc.DwFlags&DSBCAPS_PRIMARYBUFFER != 0,
	}
	if buffer.IsPrimary {
		d.PrimaryBuffer = buffer
	} else {
		d.SecondaryBuffers = append(d.SecondaryBuffers, buffer)
	}
	d.Buffers = append(d.Buffers, buffer)
	return buffer
}

func (d *DirectSound) ReleaseSoundBuffer(target *SoundBuffer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if target == nil {
		return
	}
	if d.PrimaryBuffer == target {
		d.PrimaryBuffer = nil
	}
	filter := func(src []*SoundBuffer) []*SoundBuffer {
		dst := src[:0]
		for _, buf := range src {
			if buf != target {
				dst = append(dst, buf)
			}
		}
		return dst
	}
	d.Buffers = filter(d.Buffers)
	d.SecondaryBuffers = filter(d.SecondaryBuffers)
}

func (d *DirectSound) GetCaps() DSCAPS {
	d.mu.Lock()
	defer d.mu.Unlock()
	caps := DSCAPS{
		DwSize:                         96,
		DwFlags:                        DSBCAPS_LOCSOFTWARE,
		DwMinSecondarySampleRate:       100,
		DwMaxSecondarySampleRate:       200000,
		DwPrimaryBuffers:               1,
		DwMaxHwMixingAllBuffers:        16,
		DwMaxHwMixingStaticBuffers:     16,
		DwMaxHwMixingStreamingBuffers:  16,
		DwFreeHwMixingAllBuffers:       16,
		DwFreeHwMixingStaticBuffers:    16,
		DwFreeHwMixingStreamingBuffers: 16,
		DwUnlockTransferRateHwBuffers:  100,
		DwPlayCpuOverheadSwBuffers:     1,
	}
	if d.PrimaryBuffer != nil {
		caps.DwFlags |= DSBCAPS_PRIMARYBUFFER
	}
	return caps
}

func (d *DirectSound) SetCooperativeLevel(hwnd, level uint32) {
	_ = hwnd
	d.mu.Lock()
	d.CooperativeLevel = level
	d.mu.Unlock()
}

func DefaultFormat() WAVEFORMATEX {
	return NormalizeFormat(WAVEFORMATEX{WFormatTag: WaveFormatPCM, NChannels: 2, NSamplesPerSec: 44100, WBitsPerSample: 16})
}

func (d *DirectSound) Mixer(outputFormat WAVEFORMATEX) *Mixer {
	d.mu.Lock()
	defer d.mu.Unlock()
	format := NormalizeFormat(outputFormat)
	if format.WBitsPerSample == 0 {
		format = NormalizeFormat(d.Format)
	}
	buffers := append([]*SoundBuffer(nil), d.SecondaryBuffers...)
	return &Mixer{OutputFormat: format, Buffers: buffers}
}

func NormalizeFormat(format WAVEFORMATEX) WAVEFORMATEX {
	if format.WFormatTag == 0 {
		format.WFormatTag = WaveFormatPCM
	}
	if format.NChannels == 0 {
		format.NChannels = 2
	}
	if format.NSamplesPerSec == 0 {
		format.NSamplesPerSec = 44100
	}
	if format.WBitsPerSample == 0 {
		format.WBitsPerSample = 16
	}
	blockAlign := uint32(format.NChannels) * uint32(format.WBitsPerSample) / 8
	if blockAlign == 0 {
		blockAlign = 4
	}
	format.NBlockAlign = uint16(blockAlign)
	avgBytesPerSec := uint64(format.NSamplesPerSec) * uint64(format.NBlockAlign)
	if avgBytesPerSec == 0 {
		avgBytesPerSec = 44100 * 4
	}
	format.NAvgBytesPerSec = uint32(avgBytesPerSec)
	return format
}
