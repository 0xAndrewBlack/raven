#pragma once

#include "objects.h"
#include "nt/environment.h"
#include "nt/resources.h"
#include <functional>
#ifdef RAVEN_SKIA
#include "graphics/text.h"
#endif

namespace raven {

class NativeDesktop {
public:
	NativeDesktop(NativeProcess &process, NativeEnvironment &environment, DesktopObjects &objects, NativeResources &resources);
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> user_exports();
	static std::span<const std::string_view> gdi_exports();
	static std::span<const std::string_view> control_exports();
	void set_updated(std::function<void(uint64_t)> notify) { updated=std::move(notify); }
	void set_source(std::function<std::optional<std::vector<uint8_t>>(std::string_view)> read) { source=std::move(read); }

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	DesktopObjects &objects;
	NativeResources &resources;
	std::function<void(uint64_t)> updated;
	std::function<std::optional<std::vector<uint8_t>>(std::string_view)> source;
#ifdef RAVEN_SKIA
	bool text_dispatch(std::string_view name);
	uint64_t text_output(std::span<const uint64_t> arguments);
#endif
	uint64_t load_icon(std::span<const uint64_t> arguments);
	uint64_t load_string(std::span<const uint64_t> arguments);
	bool menu_dispatch(std::string_view name);
	bool color_dispatch(std::string_view name);
	bool clip_dispatch(std::string_view name);
	bool pen_dispatch(std::string_view name);
	bool caps_dispatch(std::string_view name);
	bool load_dispatch(std::string_view name);
	uint64_t scratch=0;
	uint64_t lookup(std::span<const uint64_t> arguments);
	uint64_t create(std::span<const uint64_t> arguments);
	uint64_t create_icon(std::span<const uint8_t> bytes,uint32_t width,uint32_t height,uint32_t flags);
	bool extract_dispatch(std::string_view name);
	bool info(uint64_t handle, uint64_t output);
	uint64_t get_object(std::span<const uint64_t> arguments, bool ansi);
	uint64_t create_font(uint64_t definition);
	uint64_t get_bits(std::span<const uint64_t> arguments);
	uint64_t create_dc(uint64_t source);
	bool delete_dc(uint64_t handle);
	uint64_t select(uint64_t dc, uint64_t bitmap);
	uint64_t create_section(std::span<const uint64_t> arguments);
	uint64_t compatible_bitmap(std::span<const uint64_t> arguments);
	uint64_t allocate_bitmap(uint32_t width,uint32_t height,uint32_t depth,bool section,bool top_down);
	bool delete_bitmap(uint64_t handle);
	bool draw(std::span<const uint64_t> arguments);
	bool fill(std::span<const uint64_t> arguments);
	bool frame(std::span<const uint64_t> arguments);
};

}
