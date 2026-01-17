package dsound

const (
	WaveFormatPCM = 0x0001
)

const (
	DSBCAPS_PRIMARYBUFFER       = 0x00000001
	DSBCAPS_LOCSOFTWARE         = 0x00000008
	DSBCAPS_CTRLFREQUENCY       = 0x00000020
	DSBCAPS_CTRLPAN             = 0x00000040
	DSBCAPS_CTRLVOLUME          = 0x00000080
	DSBCAPS_CTRLPOSITIONNOTIFY  = 0x00000100
	DSBCAPS_GLOBALFOCUS         = 0x00008000
	DSBCAPS_GETCURRENTPOSITION2 = 0x00010000
)

const (
	DSBSTATUS_PLAYING    = 0x00000001
	DSBSTATUS_BUFFERLOST = 0x00000002
	DSBSTATUS_LOOPING    = 0x00000004
)

const (
	DSBPLAY_LOOPING = 0x00000001
)

const (
	DSBLOCK_FROMWRITECURSOR = 0x00000001
	DSBLOCK_ENTIREBUFFER    = 0x00000002
)

type WAVEFORMATEX struct {
	WFormatTag      uint16
	NChannels       uint16
	NSamplesPerSec  uint32
	NAvgBytesPerSec uint32
	NBlockAlign     uint16
	WBitsPerSample  uint16
	CbSize          uint16
}

type DSBUFFERDESC struct {
	DwSize        uint32
	DwFlags       uint32
	DwBufferBytes uint32
	DwReserved    uint32
	LpwfxFormat   *WAVEFORMATEX
}

type DSCAPS struct {
	DwSize                         uint32
	DwFlags                        uint32
	DwMinSecondarySampleRate       uint32
	DwMaxSecondarySampleRate       uint32
	DwPrimaryBuffers               uint32
	DwMaxHwMixingAllBuffers        uint32
	DwMaxHwMixingStaticBuffers     uint32
	DwMaxHwMixingStreamingBuffers  uint32
	DwFreeHwMixingAllBuffers       uint32
	DwFreeHwMixingStaticBuffers    uint32
	DwFreeHwMixingStreamingBuffers uint32
	DwTotalHwMemBytes              uint32
	DwFreeHwMemBytes               uint32
	DwMaxContigFreeHwMemBytes      uint32
	DwUnlockTransferRateHwBuffers  uint32
	DwPlayCpuOverheadSwBuffers     uint32
}

type DSBCAPS = DSCAPS
