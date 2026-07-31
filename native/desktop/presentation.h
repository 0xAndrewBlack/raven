#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <chrono>
#include <vector>
#include <string>

namespace raven {

enum class DesktopEventKind { message, pointer_motion, pointer_button, keymap, modifiers, keyboard_focus, key };

struct DesktopEvent {
	uint64_t window;
	uint32_t message;
	uint64_t wparam=0,lparam=0;
	DesktopEventKind kind=DesktopEventKind::message;
	int32_t x=0,y=0;
	std::string keymap{};
	std::vector<uint32_t> held_keys{};
};

struct DesktopPresentation {
	std::function<void(uint64_t,std::string_view,uint32_t,uint32_t,std::span<const uint8_t>)> present;
	std::function<void(uint64_t)> remove;
	std::function<std::vector<DesktopEvent>(std::chrono::milliseconds)> poll;
};

}
