package audio

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	pwDirectionOutput       = 1
	pwStreamFlagAutoConnect = 1 << 0
	pwStreamFlagMapBuffers  = 1 << 2

	pwVersionStreamEvents = 2

	spaTypeID     = 3
	spaTypeInt    = 4
	spaTypeObject = 15

	spaTypeObjectFormat = 0x40003

	spaParamEnumFormat = 3

	spaFormatMediaType     = 1
	spaFormatMediaSubtype  = 2
	spaFormatAudioFormat   = 0x10000
	spaFormatAudioRate     = 0x10002
	spaFormatAudioChannels = 0x10003

	spaMediaTypeAudio   = 1
	spaMediaSubtypeRaw  = 1
	spaAudioFormatS16LE = 0x103
)

type spaPod struct {
	Size uint32
	Type uint32
}

type spaChunk struct {
	Offset uint32
	Size   uint32
	Stride int32
	Flags  int32
}

type spaData struct {
	Type      uint32
	Flags     uint32
	FD        int64
	MapOffset uint32
	MaxSize   uint32
	Data      unsafe.Pointer
	Chunk     *spaChunk
}

type spaBuffer struct {
	NMetas uint32
	NDatas uint32
	Metas  unsafe.Pointer
	Datas  *spaData
}

type pwBuffer struct {
	Buffer    *spaBuffer
	UserData  unsafe.Pointer
	Size      uint64
	Requested uint64
	Time      uint64
}

type spaAudioInfoRaw struct {
	Format   uint32
	Flags    uint32
	Rate     uint32
	Channels uint32
	Position [64]uint32
}

type pwStreamEvents struct {
	Version      uint32
	_            uint32
	Destroy      uintptr
	StateChanged uintptr
	ControlInfo  uintptr
	IOChanged    uintptr
	ParamChanged uintptr
	AddBuffer    uintptr
	RemoveBuffer uintptr
	Process      uintptr
	Drained      uintptr
	Command      uintptr
	TriggerDone  uintptr
}

type pipewireAPI struct {
	lib uintptr

	pwInit                func(argc *int, argv ***byte)
	pwMainLoopNew         func(props unsafe.Pointer) unsafe.Pointer
	pwMainLoopDestroy     func(loop unsafe.Pointer)
	pwMainLoopRun         func(loop unsafe.Pointer) int32
	pwMainLoopQuit        func(loop unsafe.Pointer) int32
	pwMainLoopGetLoop     func(loop unsafe.Pointer) unsafe.Pointer
	pwStreamNewSimple     func(loop unsafe.Pointer, name string, props unsafe.Pointer, events *pwStreamEvents, data unsafe.Pointer) unsafe.Pointer
	pwStreamConnect       func(stream unsafe.Pointer, direction uint32, targetID uint32, flags uint32, params **spaPod, nParams uint32) int32
	pwStreamQueueBuffer   func(stream unsafe.Pointer, buffer *pwBuffer) int32
	pwStreamDequeueBuffer func(stream unsafe.Pointer) *pwBuffer
	pwStreamDestroy       func(stream unsafe.Pointer)
	pwPropertiesNew       func(key string, args ...any) unsafe.Pointer
}

var (
	pipewireOnce sync.Once
	pipewireInst pipewireAPI
	pipewireErr  error
)

func loadPipeWire() (*pipewireAPI, error) {
	pipewireOnce.Do(func() {
		var lib uintptr
		for _, candidate := range []string{"libpipewire-0.3.so", "libpipewire-0.3.so.0"} {
			lib, pipewireErr = purego.Dlopen(candidate, purego.RTLD_LAZY|purego.RTLD_LOCAL)
			if pipewireErr == nil {
				break
			}
		}
		if lib == 0 {
			pipewireErr = fmt.Errorf("dlopen libpipewire-0.3.so: %w", pipewireErr)
			return
		}
		pipewireInst.lib = lib

		for _, sym := range []struct {
			name string
			fn   any
		}{
			{"pw_init", &pipewireInst.pwInit},
			{"pw_main_loop_new", &pipewireInst.pwMainLoopNew},
			{"pw_main_loop_destroy", &pipewireInst.pwMainLoopDestroy},
			{"pw_main_loop_run", &pipewireInst.pwMainLoopRun},
			{"pw_main_loop_quit", &pipewireInst.pwMainLoopQuit},
			{"pw_main_loop_get_loop", &pipewireInst.pwMainLoopGetLoop},
			{"pw_stream_new_simple", &pipewireInst.pwStreamNewSimple},
			{"pw_stream_connect", &pipewireInst.pwStreamConnect},
			{"pw_stream_queue_buffer", &pipewireInst.pwStreamQueueBuffer},
			{"pw_stream_dequeue_buffer", &pipewireInst.pwStreamDequeueBuffer},
			{"pw_stream_destroy", &pipewireInst.pwStreamDestroy},
			{"pw_properties_new", &pipewireInst.pwPropertiesNew},
		} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						pipewireErr = fmt.Errorf("resolve %s: %v", sym.name, r)
					}
				}()
				purego.RegisterLibFunc(sym.fn, lib, sym.name)
			}()
			if pipewireErr != nil {
				return
			}
		}
	})
	if pipewireErr != nil {
		return nil, pipewireErr
	}
	return &pipewireInst, nil
}

func buildRawAudioFormatPod(info spaAudioInfoRaw) []byte {
	buf := make([]byte, 0, 128)
	appendU32 := func(v uint32) { buf = binary.LittleEndian.AppendUint32(buf, v) }
	pad8 := func() {
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
	}
	appendProp := func(key, valueType uint32, body []byte) {
		appendU32(key)
		appendU32(0)
		appendU32(uint32(len(body)))
		appendU32(valueType)
		buf = append(buf, body...)
		pad8()
	}

	buf = make([]byte, 8)
	appendU32(spaTypeObjectFormat)
	appendU32(spaParamEnumFormat)
	appendProp(spaFormatMediaType, spaTypeID, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, spaMediaTypeAudio)
		return b
	}())
	appendProp(spaFormatMediaSubtype, spaTypeID, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, spaMediaSubtypeRaw)
		return b
	}())
	appendProp(spaFormatAudioFormat, spaTypeID, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, info.Format)
		return b
	}())
	appendProp(spaFormatAudioRate, spaTypeInt, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, info.Rate)
		return b
	}())
	appendProp(spaFormatAudioChannels, spaTypeInt, func() []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, info.Channels)
		return b
	}())
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)-8))
	binary.LittleEndian.PutUint32(buf[4:8], spaTypeObject)
	return buf
}
