//go:build guest_windows

package audio

import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/mirkobrombin/Raven/pkg/dsound"
)

type AudioOutput struct {
	stream        unsafe.Pointer
	sampleRate    int
	channels      int
	bitsPerSample int
	running       bool
	mixer         *dsound.Mixer
	mu            sync.Mutex

	api      *pipewireAPI
	mainLoop unsafe.Pointer
	events   pwStreamEvents
	userData unsafe.Pointer
	wg       sync.WaitGroup
}

var (
	audioOutputSeq uint64
	audioOutputs   sync.Map
)

func NewAudioOutput(sampleRate, channels, bitsPerSample int) (*AudioOutput, error) {
	api, err := loadPipeWire()
	if err != nil {
		return nil, err
	}
	sampleRate, channels, bitsPerSample = normalizeFormat(sampleRate, channels, bitsPerSample)
	api.pwInit(nil, nil)

	ao := &AudioOutput{
		api:           api,
		sampleRate:    sampleRate,
		channels:      channels,
		bitsPerSample: bitsPerSample,
		running:       true,
	}
	userID := uintptr(atomic.AddUint64(&audioOutputSeq, 1))
	audioOutputs.Store(userID, ao)
	ao.userData = unsafe.Pointer(userID)
	ao.events = pwStreamEvents{
		Version: pwVersionStreamEvents,
		Process: purego.NewCallback(pipeWireProcessCallback),
	}

	ao.mainLoop = api.pwMainLoopNew(nil)
	if ao.mainLoop == nil {
		audioOutputs.Delete(userID)
		return nil, fmt.Errorf("pw_main_loop_new failed")
	}
	props := api.pwPropertiesNew(
		"application.name", "Raven",
		"media.type", "Audio",
		"media.category", "Playback",
		"media.role", "Game",
		unsafe.Pointer(nil),
	)
	stream := api.pwStreamNewSimple(api.pwMainLoopGetLoop(ao.mainLoop), "Raven DirectSound", props, &ao.events, ao.userData)
	if stream == nil {
		api.pwMainLoopDestroy(ao.mainLoop)
		audioOutputs.Delete(userID)
		return nil, fmt.Errorf("pw_stream_new_simple failed")
	}
	ao.stream = stream

	format := spaAudioInfoRaw{Format: spaAudioFormatS16LE, Rate: uint32(sampleRate), Channels: uint32(channels)}
	paramBuf := buildRawAudioFormatPod(format)
	param := (*spaPod)(unsafe.Pointer(&paramBuf[0]))
	params := []*spaPod{param}
	if rc := api.pwStreamConnect(stream, pwDirectionOutput, 0xffffffff, pwStreamFlagAutoConnect|pwStreamFlagMapBuffers, &params[0], uint32(len(params))); rc != 0 {
		api.pwStreamDestroy(stream)
		api.pwMainLoopDestroy(ao.mainLoop)
		audioOutputs.Delete(userID)
		return nil, fmt.Errorf("pw_stream_connect failed: %d", rc)
	}

	ao.wg.Add(1)
	go func() {
		defer ao.wg.Done()
		api.pwMainLoopRun(ao.mainLoop)
	}()
	return ao, nil
}

func (ao *AudioOutput) SetMixer(mixer *dsound.Mixer) {
	ao.mu.Lock()
	ao.mixer = mixer
	ao.mu.Unlock()
}

func (ao *AudioOutput) mix(frames int) []byte {
	if frames <= 0 {
		frames = 256
	}
	ao.mu.Lock()
	mixer := ao.mixer
	channels := ao.channels
	bitsPerSample := ao.bitsPerSample
	running := ao.running
	ao.mu.Unlock()
	if !running {
		return nil
	}
	frameBytes := channels * bitsPerSample / 8
	if frameBytes <= 0 {
		frameBytes = 4
	}
	if mixer == nil {
		return make([]byte, frames*frameBytes)
	}
	pcm := mixer.Mix(frames)
	if len(pcm) == 0 {
		return make([]byte, frames*frameBytes)
	}
	return pcm
}

func (ao *AudioOutput) Close() {
	ao.mu.Lock()
	if !ao.running {
		ao.mu.Unlock()
		return
	}
	ao.running = false
	stream := ao.stream
	mainLoop := ao.mainLoop
	api := ao.api
	userData := ao.userData
	ao.mu.Unlock()

	audioOutputs.Delete(uintptr(userData))
	if mainLoop != nil {
		api.pwMainLoopQuit(mainLoop)
	}
	ao.wg.Wait()
	if stream != nil {
		api.pwStreamDestroy(stream)
	}
	if mainLoop != nil {
		api.pwMainLoopDestroy(mainLoop)
	}
}

func pipeWireProcessCallback(userdata unsafe.Pointer) {
	value := uintptr(userdata)
	if value == 0 {
		return
	}
	stored, ok := audioOutputs.Load(value)
	if !ok {
		return
	}
	ao := stored.(*AudioOutput)
	ao.process()
}

func (ao *AudioOutput) process() {
	ao.mu.Lock()
	if !ao.running || ao.stream == nil {
		ao.mu.Unlock()
		return
	}
	stream := ao.stream
	api := ao.api
	channels := ao.channels
	bitsPerSample := ao.bitsPerSample
	ao.mu.Unlock()

	buf := api.pwStreamDequeueBuffer(stream)
	if buf == nil || buf.Buffer == nil || buf.Buffer.NDatas == 0 || buf.Buffer.Datas == nil {
		return
	}
	data := buf.Buffer.Datas
	if data.Data == nil || data.MaxSize == 0 {
		_ = api.pwStreamQueueBuffer(stream, buf)
		return
	}
	frameBytes := channels * bitsPerSample / 8
	if frameBytes <= 0 {
		frameBytes = 4
	}
	frames := int(data.MaxSize) / frameBytes
	if buf.Requested > 0 && int(buf.Requested) < frames {
		frames = int(buf.Requested)
	}
	if frames <= 0 {
		frames = 256
	}
	pcm := ao.mix(frames)
	maxBytes := int(data.MaxSize)
	if len(pcm) > maxBytes {
		pcm = pcm[:maxBytes]
	}
	dst := unsafe.Slice((*byte)(data.Data), maxBytes)
	clear(dst)
	copy(dst, pcm)
	if data.Chunk != nil {
		data.Chunk.Offset = 0
		data.Chunk.Size = uint32(len(pcm))
		data.Chunk.Stride = int32(frameBytes)
	}
	buf.Size = uint64(len(pcm) / frameBytes)
	_ = api.pwStreamQueueBuffer(stream, buf)
}

func normalizeFormat(sampleRate, channels, bitsPerSample int) (int, int, int) {
	if sampleRate <= 0 {
		sampleRate = 44100
	}
	if channels <= 0 {
		channels = 2
	}
	if bitsPerSample != 16 {
		bitsPerSample = 16
	}
	return sampleRate, channels, bitsPerSample
}
