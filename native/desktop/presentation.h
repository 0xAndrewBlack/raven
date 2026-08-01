#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <chrono>
#include <vector>
#include <string>

namespace raven {

// popup_done: the compositor dismissed a popup (for example by a click outside it).
enum class DesktopEventKind { message, pointer_motion, pointer_button, keymap, modifiers, keyboard_focus, key, popup_done, resize };

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
	// Shows or updates a popup anchored at (x, y) of its parent surface, taking a pointer and keyboard grab.
	std::function<void(uint64_t handle,uint64_t parent,int32_t x,int32_t y,uint32_t width,uint32_t height,std::span<const uint8_t> pixels)> popup;
	// Hands a pointer drag that began on the frame to the compositor: 0 moves the window, 1..10 resize from that edge.
	std::function<void(uint64_t handle,uint32_t action)> interactive;
};

}
