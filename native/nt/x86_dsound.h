#pragma once

#include "x86_com.h"

#include <chrono>
#include <map>

namespace raven {

// DirectSound for 32-bit programs without an audio device: buffers hold the samples a program writes and play them to nowhere, at the
// pace of their format, so that programs that watch play cursors and status flags see sound being played and finishing.
class NativeX86DirectSound {
public:
	explicit NativeX86DirectSound(NativeProcess &process);
	NativeX86Com &com() { return com_; }
	static std::vector<std::string_view> method_names();
	static uint32_t method_words(std::string_view name);
	static std::span<const std::string_view> entry_names();
	static uint32_t entry_words(std::string_view name);
	bool dispatch(std::string_view name);

private:
	struct Buffer {
		uint64_t memory = 0;
		uint32_t size = 0, bytes_per_second = 0, frequency = 0, position = 0;
		bool playing = false, looping = false;
		std::chrono::steady_clock::time_point started;
	};
	NativeProcess &process;
	NativeX86Com com_;
	std::map<uint64_t, Buffer> buffers;
	uint64_t make_buffer(uint32_t size, uint64_t format);
	uint32_t play_cursor(const Buffer &buffer) const;
	bool finished(const Buffer &buffer) const;
};

}
