//go:build guest_windows

package audio

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/mirkobrombin/Raven/pkg/dsound"
)

const (
	paStreamPlayback = 1
	paSampleS16NE    = 3
)

type paSampleSpec struct {
	Format   uint32
	Rate     uint32
	Channels uint8
	_        [3]byte
}

type pulseAPI struct {
	paSimpleNew   func(server, name unsafe.Pointer, dir int32, dev, streamName unsafe.Pointer, spec *paSampleSpec, channelMap, attr unsafe.Pointer, err *int32) unsafe.Pointer
	paSimpleWrite func(s unsafe.Pointer, data unsafe.Pointer, nbytes uint64, err *int32) int32
	paSimpleDrain func(s unsafe.Pointer, err *int32) int32
	paSimpleFree  func(s unsafe.Pointer)
}

var (
	pulseOnce sync.Once
	pulseInst pulseAPI
	pulseErr  error
)

type PulseOutput struct {
	stream        unsafe.Pointer
	sampleRate    int
	channels      int
	bitsPerSample int
	running       bool
	mixer         *dsound.Mixer
	mu            sync.Mutex

	api *pulseAPI
	wg  sync.WaitGroup
}

func loadPulse() (*pulseAPI, error) {
	pulseOnce.Do(func() {
		lib, err := purego.Dlopen("libpulse-simple.so.0", purego.RTLD_LAZY|purego.RTLD_LOCAL)
		if err != nil {
			pulseErr = fmt.Errorf("dlopen libpulse-simple.so.0: %w", err)
			return
		}
		for _, sym := range []struct {
			name string
			fn   any
		}{
			{"pa_simple_new", &pulseInst.paSimpleNew},
			{"pa_simple_write", &pulseInst.paSimpleWrite},
			{"pa_simple_drain", &pulseInst.paSimpleDrain},
			{"pa_simple_free", &pulseInst.paSimpleFree},
		} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						pulseErr = fmt.Errorf("resolve %s: %v", sym.name, r)
					}
				}()
				purego.RegisterLibFunc(sym.fn, lib, sym.name)
			}()
			if pulseErr != nil {
				return
			}
		}
	})
	if pulseErr != nil {
		return nil, pulseErr
	}
	return &pulseInst, nil
}

func NewPulseOutput(sampleRate, channels, bitsPerSample int) (*PulseOutput, error) {
	api, err := loadPulse()
	if err != nil {
		return nil, err
	}
	sampleRate, channels, bitsPerSample = normalizeFormat(sampleRate, channels, bitsPerSample)
	appName := cString("Raven")
	streamName := cString("DirectSound")
	spec := paSampleSpec{Format: paSampleS16NE, Rate: uint32(sampleRate), Channels: uint8(channels)}
	var paErr int32
	stream := api.paSimpleNew(nil, ptr(appName), paStreamPlayback, nil, ptr(streamName), &spec, nil, nil, &paErr)
	if stream == nil {
		return nil, fmt.Errorf("pa_simple_new failed: %d", paErr)
	}
	po := &PulseOutput{
		api:           api,
		stream:        stream,
		sampleRate:    sampleRate,
		channels:      channels,
		bitsPerSample: bitsPerSample,
		running:       true,
	}
	po.wg.Add(1)
	go po.loop()
	return po, nil
}

func (po *PulseOutput) SetMixer(mixer *dsound.Mixer) {
	po.mu.Lock()
	po.mixer = mixer
	po.mu.Unlock()
}

func (po *PulseOutput) loop() {
	defer po.wg.Done()
	frames := po.sampleRate / 100
	if frames < 256 {
		frames = 256
	}
	frameBytes := po.channels * po.bitsPerSample / 8
	if frameBytes <= 0 {
		frameBytes = 4
	}
	ticker := time.NewTicker(time.Second * time.Duration(frames) / time.Duration(po.sampleRate))
	defer ticker.Stop()
	for range ticker.C {
		po.mu.Lock()
		if !po.running {
			po.mu.Unlock()
			return
		}
		stream := po.stream
		mixer := po.mixer
		po.mu.Unlock()

		pcm := make([]byte, frames*frameBytes)
		if mixer != nil {
			if mixed := mixer.Mix(frames); len(mixed) != 0 {
				copy(pcm, mixed)
			}
		}
		var paErr int32
		if rc := po.api.paSimpleWrite(stream, unsafe.Pointer(&pcm[0]), uint64(len(pcm)), &paErr); rc < 0 {
			return
		}
	}
}

func (po *PulseOutput) Close() {
	po.mu.Lock()
	if !po.running {
		po.mu.Unlock()
		return
	}
	po.running = false
	stream := po.stream
	api := po.api
	po.mu.Unlock()

	po.wg.Wait()
	if stream != nil {
		var paErr int32
		_ = api.paSimpleDrain(stream, &paErr)
		api.paSimpleFree(stream)
	}
}

func cString(s string) []byte {
	return append([]byte(s), 0)
}

func ptr(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}
