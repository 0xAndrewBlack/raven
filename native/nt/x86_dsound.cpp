#include "x86_dsound.h"

#include <algorithm>
#include <array>
#include <sys/mman.h>

namespace raven {

namespace {

constexpr ComMethod methods[] = {
#include "x86_dsound_vtables.inc"
};

constexpr uint32_t ds_ok = 0, e_nointerface = 0x80004002U, e_notimpl = 0x80004001U, ds_invalid_param = 0x80070057U;
constexpr uint32_t status_playing = 1, status_looping = 4;
constexpr std::array<std::pair<std::string_view, uint32_t>, 4> entries{{
	{"DirectSoundCreate", 3}, {"DirectSoundCreate8", 3}, {"DirectSoundEnumerateA", 2}, {"DirectSoundEnumerateW", 2},
}};

}

NativeX86DirectSound::NativeX86DirectSound(NativeProcess &process) : process(process), com_(process, methods) {}

std::vector<std::string_view> NativeX86DirectSound::method_names()
{
	return com_names(methods);
}

uint32_t NativeX86DirectSound::method_words(std::string_view name)
{
	return com_words(methods, name);
}

std::span<const std::string_view> NativeX86DirectSound::entry_names()
{
	static constexpr std::array<std::string_view, 4> names{"DirectSoundCreate", "DirectSoundCreate8", "DirectSoundEnumerateA", "DirectSoundEnumerateW"};
	return names;
}

uint32_t NativeX86DirectSound::entry_words(std::string_view name)
{
	for (const auto &[entry, words] : entries)
		if (entry == name)
			return words;
	return 0;
}

uint64_t NativeX86DirectSound::make_buffer(uint32_t size, uint64_t format)
{
	const auto object = com_.make_object("IDirectSoundBuffer8");
	Buffer buffer;
	buffer.size = size;
	if (size)
		buffer.memory = process.map_memory((uint64_t(size) + 4095) & ~uint64_t(4095), PROT_READ | PROT_WRITE);
	// WAVEFORMATEX: tag, channels, samples per second, average bytes per second, block align, bits per sample.
	if (format) {
		buffer.frequency = com_.read32(format + 4);
		buffer.bytes_per_second = com_.read32(format + 8);
	}
	buffers[object] = buffer;
	return object;
}

uint32_t NativeX86DirectSound::play_cursor(const Buffer &buffer) const
{
	if (!buffer.size)
		return 0;
	if (!buffer.playing)
		return buffer.position % buffer.size;
	const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - buffer.started).count();
	const uint64_t advanced = uint64_t(elapsed) * buffer.bytes_per_second / 1000000;
	return uint32_t((buffer.position + advanced) % buffer.size);
}

bool NativeX86DirectSound::finished(const Buffer &buffer) const
{
	if (!buffer.playing || buffer.looping || !buffer.bytes_per_second)
		return !buffer.playing;
	const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - buffer.started).count();
	return uint64_t(elapsed) * buffer.bytes_per_second / 1000000 + buffer.position >= buffer.size;
}

bool NativeX86DirectSound::dispatch(std::string_view name)
{
	if (name == "DirectSoundCreate" || name == "DirectSoundCreate8") {
		const auto args = process.api_arguments(3);
		if (args[1])
			com_.write32(args[1], uint32_t(com_.make_object("IDirectSound8")));
		process.return_api(ds_ok);
		return true;
	}
	if (name == "DirectSoundEnumerateA" || name == "DirectSoundEnumerateW") {
		process.api_arguments(2);
		process.return_api(ds_ok);
		return true;
	}
	if (!com_.owns(name))
		return false;
	const auto args = process.api_arguments(com_.words(name));
	const auto [interface, method] = com_.split(name);
	if (com_.counted(method, args))
		return true;
	if (method == "QueryInterface") {
		// IUnknown, IDirectSound, IDirectSound8, IDirectSoundBuffer and IDirectSoundBuffer8 are what these objects can be.
		const uint32_t first = args[1] ? com_.read32(args[1]) : 0;
		const bool known = first == 0 || first == 0x279afa83 || first == 0xc50a7e93 || first == 0x279afa85 || first == 0x6825a449;
		if (!known || !args[2]) {
			if (args[2])
				com_.write32(args[2], 0);
			process.return_api(e_nointerface);
		} else {
			com_.write32(args[2], uint32_t(args[0]));
			com_.write32(args[0] + 4, com_.read32(args[0] + 4) + 1);
			process.return_api(ds_ok);
		}
		return true;
	}
	if (interface == "IDirectSound8") {
		if (method == "CreateSoundBuffer") {
			// DSBUFFERDESC: size, flags, buffer bytes, reserved, format.
			if (!args[1] || !args[2]) {
				process.return_api(ds_invalid_param);
			} else {
				const uint32_t flags = com_.read32(args[1] + 4), bytes = com_.read32(args[1] + 8);
				const bool primary = flags & 1;
				com_.write32(args[2], uint32_t(make_buffer(primary ? 0 : bytes, com_.read32(args[1] + 16))));
				process.return_api(ds_ok);
			}
		} else if (method == "DuplicateSoundBuffer") {
			const auto source = buffers.find(args[1]);
			if (source == buffers.end() || !args[2]) {
				process.return_api(ds_invalid_param);
			} else {
				const auto copy = com_.make_object("IDirectSoundBuffer8");
				buffers[copy] = source->second;
				buffers[copy].playing = false;
				com_.write32(args[2], uint32_t(copy));
				process.return_api(ds_ok);
			}
		} else if (method == "GetCaps") {
			process.return_api(ds_ok);
		} else if (method == "GetSpeakerConfig") {
			if (args[1])
				com_.write32(args[1], 3);
			process.return_api(ds_ok);
		} else if (method == "VerifyCertification") {
			if (args[1])
				com_.write32(args[1], 0);
			process.return_api(ds_ok);
		} else {
			process.return_api(ds_ok);
		}
		return true;
	}
	const auto found = buffers.find(args[0]);
	if (found == buffers.end()) {
		process.return_api(ds_invalid_param);
		return true;
	}
	auto &buffer = found->second;
	if (method == "Lock") {
		const uint32_t offset = uint32_t(args[1]), flags = uint32_t(args[7]);
		uint32_t bytes = uint32_t(args[2]);
		if (!buffer.size || offset > buffer.size) {
			process.return_api(ds_invalid_param);
			return true;
		}
		if (flags & 2)
			bytes = buffer.size;
		bytes = std::min(bytes, buffer.size);
		const uint32_t first = std::min(bytes, buffer.size - offset);
		if (args[3])
			com_.write32(args[3], uint32_t(buffer.memory + offset));
		if (args[4])
			com_.write32(args[4], first);
		if (args[5])
			com_.write32(args[5], first < bytes ? uint32_t(buffer.memory) : 0);
		if (args[6])
			com_.write32(args[6], bytes - first);
		process.return_api(ds_ok);
	} else if (method == "Play") {
		buffer.position = play_cursor(buffer);
		buffer.playing = true;
		buffer.looping = args[3] & 1;
		buffer.started = std::chrono::steady_clock::now();
		process.return_api(ds_ok);
	} else if (method == "Stop") {
		buffer.position = play_cursor(buffer);
		buffer.playing = false;
		process.return_api(ds_ok);
	} else if (method == "SetCurrentPosition") {
		buffer.position = uint32_t(args[1]);
		buffer.started = std::chrono::steady_clock::now();
		process.return_api(ds_ok);
	} else if (method == "GetCurrentPosition") {
		const auto cursor = play_cursor(buffer);
		if (args[1])
			com_.write32(args[1], cursor);
		if (args[2])
			com_.write32(args[2], buffer.size ? (cursor + buffer.bytes_per_second / 20) % buffer.size : 0);
		process.return_api(ds_ok);
	} else if (method == "GetStatus") {
		bool playing = buffer.playing && !finished(buffer);
		if (buffer.playing && !playing)
			buffer.playing = false;
		if (args[1])
			com_.write32(args[1], (playing ? status_playing : 0) | (playing && buffer.looping ? status_looping : 0));
		process.return_api(ds_ok);
	} else if (method == "GetFrequency") {
		if (args[1])
			com_.write32(args[1], buffer.frequency);
		process.return_api(ds_ok);
	} else if (method == "GetVolume" || method == "GetPan") {
		if (args[1])
			com_.write32(args[1], 0);
		process.return_api(ds_ok);
	} else if (method == "GetCaps") {
		// DSBCAPS: size, flags, buffer bytes, unlock transfer rate, play CPU overhead.
		if (args[1]) {
			com_.write32(args[1] + 8, buffer.size);
		}
		process.return_api(ds_ok);
	} else if (method == "SetFX" || method == "AcquireResources" || method == "GetObjectInPath") {
		process.return_api(e_notimpl);
	} else {
		process.return_api(ds_ok);
	}
	return true;
}

}
