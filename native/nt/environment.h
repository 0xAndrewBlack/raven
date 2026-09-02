#pragma once

#include "cpu/native_cpu.h"

#include <string_view>
#include <string>
#include <optional>
#include <array>

namespace raven {

inline constexpr uint64_t native_user_limit = 0x700000000000ULL;

struct NativeStartup {
	std::optional<std::u16string> title;
	std::array<uint32_t,7> geometry{};
	uint32_t flags = 0;
	uint16_t show_window = 1;
	std::vector<uint8_t> runtime_data;
};

struct NativeLaunch {
	std::u16string image_path;
	std::u16string command_line;
	uint32_t ansi_code_page = 1252;
	NativeStartup startup{};
	std::array<int,3> standard_fds{-1,-1,-1};
	// The current directory the program starts in; empty for the default.
	std::u16string directory;
};

// Initial x64 thread fields only. Mappings belong to the process and survive this view.
class NativeEnvironment {
public:
	NativeEnvironment(NativeProcess &process, uint64_t image_base, uint32_t process_id, uint32_t thread_id);
	uint64_t teb() const { return thread_block; }
	uint64_t peb() const { return process_block; }
	// Guest address of the ANSI command line, valid once process parameters exist.
	uint64_t command_line() const { return command_line_ansi; }
	uint32_t last_error() const;
	void set_last_error(uint32_t error);
	uint64_t prepare_heaps();
	void publish_process_heap(uint64_t heap);
	uint64_t process_heap() const;
	void prepare_parameters(const NativeLaunch &launch,
		std::array<uint64_t,3> standard_handles={UINT64_MAX,UINT64_MAX,UINT64_MAX});
	// Per-thread TEB for guest threads beyond the first (x64). The block is not current until set_current names it.
	uint64_t create_thread_block(uint64_t stack_base, uint64_t stack_limit, uint32_t thread_id);
	void release_thread_block(uint64_t teb);
	void set_current(uint64_t teb) { thread_block = teb; }
	static constexpr uint32_t heap_capacity = 512;
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> nt_exports();

private:
	NativeProcess &process;
	uint64_t thread_block = 0;
	uint64_t process_block = 0;
	uint64_t heap_storage = 0;
	uint64_t command_line_ansi = 0;
	uint32_t ansi_code_page = 0;
	uint64_t startup_info_ansi = 0;
	void require_current() const;
	void x86_constructor(uint64_t image_base, uint32_t process_id, uint32_t thread_id);
	void prepare_parameters_x86(const NativeLaunch &launch, std::array<uint64_t,3> standard_handles);
	uint64_t pointer(uint64_t address) const;
	bool system_information();
	bool startup_information(std::string_view name);
	bool multibyte_information(std::string_view name);
};

}
