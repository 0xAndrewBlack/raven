//go:build guest_windows

package dsound

import (
	"sync"
	"unsafe"
)

type SoundBuffer struct {
	Data        []byte
	Size        uint32
	Format      WAVEFORMATEX
	PlayCursor  uint32
	WriteCursor uint32
	Playing     bool
	Looping     bool
	Volume      int32
	Pan         int32
	Frequency   uint32
	Locked      bool
	LockOffset  uint32
	LockSize    uint32
	IsPrimary   bool
	mu          sync.Mutex
}

type Buffer = SoundBuffer

func (b *SoundBuffer) Lock(offset, bytes, flags uint32) (uintptr, uint32, uintptr, uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.Size == 0 || len(b.Data) == 0 {
		return 0, 0, 0, 0
	}
	if flags&DSBLOCK_ENTIREBUFFER != 0 || bytes == 0 || bytes > b.Size {
		bytes = b.Size
	}
	if flags&DSBLOCK_FROMWRITECURSOR != 0 {
		offset = b.WriteCursor
	}
	if offset >= b.Size {
		offset %= b.Size
	}
	b.Locked = true
	b.LockOffset = offset
	b.LockSize = bytes
	len1 := bytes
	len2 := uint32(0)
	if offset+bytes > b.Size {
		len1 = b.Size - offset
		len2 = bytes - len1
	}
	var ptr1, ptr2 uintptr
	if len1 != 0 {
		ptr1 = uintptr(unsafe.Pointer(&b.Data[offset]))
	}
	if len2 != 0 {
		ptr2 = uintptr(unsafe.Pointer(&b.Data[0]))
	}
	return ptr1, len1, ptr2, len2
}

func (b *SoundBuffer) Unlock(ptr1 uintptr, len1 uint32, ptr2 uintptr, len2 uint32) {
	_, _, _, _ = ptr1, len1, ptr2, len2
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		return
	}
	advance := len1 + len2
	if advance == 0 {
		advance = b.LockSize
	}
	if b.Size != 0 {
		b.WriteCursor = (b.LockOffset + advance) % b.Size
	} else {
		b.WriteCursor = 0
	}
	b.Locked = false
	b.LockOffset = 0
	b.LockSize = 0
}

func (b *SoundBuffer) Play(reserved, priority, flags uint32) {
	_, _ = reserved, priority
	b.mu.Lock()
	b.Playing = true
	b.Looping = flags&DSBPLAY_LOOPING != 0
	b.mu.Unlock()
}

func (b *SoundBuffer) Stop() {
	b.mu.Lock()
	b.Playing = false
	b.Looping = false
	b.mu.Unlock()
}

func (b *SoundBuffer) SetCurrentPosition(pos uint32) {
	b.mu.Lock()
	if b.Size != 0 {
		pos %= b.Size
	} else {
		pos = 0
	}
	b.PlayCursor = pos
	b.mu.Unlock()
}

func (b *SoundBuffer) GetCurrentPosition() (uint32, uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.PlayCursor, b.WriteCursor
}

func (b *SoundBuffer) GetStatus() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	status := uint32(0)
	if b.Playing {
		status |= DSBSTATUS_PLAYING
	}
	if b.Looping {
		status |= DSBSTATUS_LOOPING
	}
	return status
}

func (b *SoundBuffer) SetVolume(vol int32) {
	if vol < -10000 {
		vol = -10000
	}
	if vol > 0 {
		vol = 0
	}
	b.mu.Lock()
	b.Volume = vol
	b.mu.Unlock()
}

func (b *SoundBuffer) GetVolume() int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Volume
}

func (b *SoundBuffer) SetPan(pan int32) {
	if pan < -10000 {
		pan = -10000
	}
	if pan > 10000 {
		pan = 10000
	}
	b.mu.Lock()
	b.Pan = pan
	b.mu.Unlock()
}

func (b *SoundBuffer) GetPan() int32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Pan
}

func (b *SoundBuffer) SetFrequency(freq uint32) {
	b.mu.Lock()
	if freq == 0 {
		freq = NormalizeFormat(b.Format).NSamplesPerSec
	}
	if freq < 100 {
		freq = 100
	}
	if freq > 200000 {
		freq = 200000
	}
	b.Frequency = freq
	b.mu.Unlock()
}

func (b *SoundBuffer) GetFrequency() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Frequency == 0 {
		return NormalizeFormat(b.Format).NSamplesPerSec
	}
	return b.Frequency
}

func (b *SoundBuffer) SetFormat(format WAVEFORMATEX) {
	format = NormalizeFormat(format)
	b.mu.Lock()
	b.Format = format
	if b.Frequency == 0 {
		b.Frequency = format.NSamplesPerSec
	}
	b.mu.Unlock()
}

func (b *SoundBuffer) GetFormat() WAVEFORMATEX {
	b.mu.Lock()
	defer b.mu.Unlock()
	return NormalizeFormat(b.Format)
}
