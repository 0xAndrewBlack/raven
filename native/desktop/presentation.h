#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <span>
#include <string_view>
#include <chrono>
#include <vector>
#include <string>

namespace raven {

// pointer_wheel: message carries the signed wheel delta in 1/120 notches (wparam 1 for the horizontal wheel), x and y the pointer position.
// popup_done: the compositor dismissed a popup (for example by a click outside it).
enum class DesktopEventKind { message, pointer_motion, pointer_button, keymap, modifiers, keyboard_focus, key, popup_done, resize, pointer_wheel };

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
	// Offers UTF-8 text as the host selection.
	std::function<void(std::string_view text)> clipboard_publish;
	// Text of a selection owned by another client with a counter that changes with every new selection; empty when there is none.
	std::function<std::optional<std::pair<uint64_t,std::string>>()> clipboard_fetch;
};

}
