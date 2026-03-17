//go:build guest_windows

package audio

import (
	"fmt"

	"github.com/mirkobrombin/Raven/pkg/dsound"
)

type Output interface {
	SetMixer(mixer *dsound.Mixer)
	Close()
}

func Init(sampleRate, channels, bitsPerSample int) (Output, error) {
	out, err := NewAudioOutput(sampleRate, channels, bitsPerSample)
	if err == nil {
		return out, nil
	}
	pwErr := err

	pulseOut, err := NewPulseOutput(sampleRate, channels, bitsPerSample)
	if err == nil {
		return pulseOut, nil
	}
	return nil, fmt.Errorf("audio output unavailable: pipewire: %w; pulse: %w", pwErr, err)
}
