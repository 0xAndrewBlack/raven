#pragma once

#include <array>
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
// pointer_relative: x and y carry the movement of the mouse itself, unaccelerated and not stopped by the screen edges.
enum class DesktopEventKind { message, pointer_motion, pointer_button, keymap, modifiers, keyboard_focus, key, popup_done, resize, pointer_wheel,
	pointer_relative };

struct DesktopEvent {
	uint64_t window;
	uint32_t message;
	uint64_t wparam=0,lparam=0;
	DesktopEventKind kind=DesktopEventKind::message;
	int32_t x=0,y=0;
	std::string keymap{};
	std::vector<uint32_t> held_keys{};
};

// A host surface a graphics driver can present into: the Wayland display connection and a surface that sits over a window's client area.
struct HostSurface {
	void *display = nullptr;
	void *surface = nullptr;
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
	// Creates a child surface of the window over the rectangle (x, y, width, height) of its frame and returns it for a driver to render to; null
	// when there is no such window. Pointer and keyboard input keep going to the window itself.
	std::function<std::optional<HostSurface>(uint64_t handle,int32_t x,int32_t y,uint32_t width,uint32_t height)> host_surface;
	std::function<void(uint64_t handle)> release_host_surface;
	// Keeps the pointer inside the rectangle (left, top, right, bottom) of the window's frame, or holds it still when the rectangle is a
	// point; no rectangle lets it go.
	std::function<void(uint64_t handle,std::optional<std::array<int32_t,4>> rectangle)> confine;
};

}
