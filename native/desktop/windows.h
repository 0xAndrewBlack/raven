#pragma once

#include "objects.h"
#include "presentation.h"
#include "keyboard.h"
#include <array>
#include "nt/environment.h"
#include <functional>
#include <deque>
#include <optional>

namespace raven {

class NativeWindows {
public:
	NativeWindows(NativeProcess &process, NativeEnvironment &environment, DesktopObjects &objects);
	void set_call(std::function<NativeResult(uint64_t,std::span<const uint64_t>)> invoke);
	void set_presentation(DesktopPresentation presentation);
	void set_deadline(std::chrono::steady_clock::time_point deadline);
	bool dispatch(std::string_view name);
	void drawing(uint64_t window);
	void shutdown();

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	DesktopObjects &objects;
	std::function<NativeResult(uint64_t,std::span<const uint64_t>)> invoke;
	DesktopPresentation presentation;
	struct Message {
		uint64_t window, wparam, lparam;
		uint32_t message, time;
		int32_t x=0,y=0;
		uint32_t character=0;
	};
	// Initial guest thread queue; HWNDs and drawing resources stay in DesktopObjects.
	std::deque<Message> messages;
	std::optional<uint32_t> quit;
	std::chrono::steady_clock::time_point deadline;
	uint32_t mouse_buttons=0;
	int32_t cursor_x=0,cursor_y=0;
	uint64_t focus=0,active=0;
	bool activating=false,focusing=false;
	KeyboardMap keyboard_map;
	std::array<bool,256> key_down{};
	std::optional<Message> key_translation;
	void activate(uint64_t window);
	uint64_t set_focus(uint64_t window);
	void receive(const DesktopEvent &event);
	uint64_t retrieve(std::span<const uint64_t> arguments,bool blocking);
	void post(uint64_t window,uint32_t message,uint64_t wparam,uint64_t lparam);
	uint64_t surface_dc(uint64_t window);
	bool tree_dispatch(std::string_view name);
	// Classic frame geometry in window-relative coordinates, derived from AdjustWindowRectEx rules.
	struct FrameLayout {
		int32_t border, caption_height, menu_height;
		bool edge;
		DesktopRect caption, menu_bar, close, maximize, minimize, icon;
	};
	FrameLayout frame_layout(const DesktopWindow &window) const;
	std::vector<DesktopRect> menu_bar_items(const DesktopWindow &window);
	void paint_nonclient(uint64_t window);
	uint64_t nonclient_hit(const DesktopWindow &window,int32_t x,int32_t y) const;
	// Menu bar item currently shown as pressed, and the window that owns it.
	std::optional<size_t> open_menu_item;
	uint64_t open_menu_window=0;
	bool system_dispatch(std::string_view name);
	// Mouse capture and timers belong to the initial guest thread's input state.
	uint64_t capture=0;
	struct Timer { uint64_t window,id,procedure; uint32_t interval; std::chrono::steady_clock::time_point due; };
	std::vector<Timer> timers;
	uint64_t next_timer_id=0x1000;
	void post_due_timers();
	void recalculate_client(uint64_t window);
	void reshape(uint64_t window,DesktopRect outer);
	uint64_t desktop_window();
	uint64_t desktop=0;
	struct Modifiers { bool shift,control,alt; };
	Modifiers modifier_state() const;
	void parent_notify(uint64_t window,uint32_t message);
	void discard_tree(uint64_t window);
	void reject_tree(uint64_t window);
	uint64_t pointer_child(uint64_t window,int32_t x,int32_t y);
	void present(uint64_t window);
	void release_surface(uint64_t window);
	DesktopRect update_rect(uint64_t window,uint64_t address);
	struct PaintStart { uint64_t dc; DesktopRect rect; bool erase; };
	PaintStart start_paint(uint64_t window);
	std::string text(uint64_t address);
	std::u16string window_text(uint64_t address);
	uint64_t copy_window_text(uint64_t window,uint64_t output,uint64_t capacity);
	uint16_t atom(uint64_t name, uint64_t instance);
	uint64_t send(uint64_t window, uint32_t message, uint64_t wparam, uint64_t lparam);
	uint64_t create(std::span<const uint64_t> arguments);
	uint64_t map_points(uint64_t from,uint64_t to,uint64_t points,uint32_t count);
	bool destroy(uint64_t window);
	uint64_t default_message(std::span<const uint64_t> arguments);
	uint64_t long_value(std::string_view name,std::span<const uint64_t> arguments);
	uint64_t class_info(std::string_view name,std::span<const uint64_t> arguments);
};

}
