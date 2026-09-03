#pragma once

#include "objects.h"
#include "foreign_surface.h"
#include "presentation.h"
#include "keyboard.h"
#include <array>
#include <chrono>
#include <map>
#include <set>
#include "nt/api.h"
#include "nt/environment.h"
#include <functional>
#include <deque>
#include <memory>
#include <optional>

namespace raven {

class NativeWindows {
public:
	NativeWindows(NativeProcess &process, NativeEnvironment &environment, DesktopObjects &objects);
	void set_call(std::function<NativeResult(uint64_t,std::span<const uint64_t>)> invoke);
	void set_presentation(DesktopPresentation presentation);
	// A host surface over the client area of a window for a graphics driver to present into, and its release; null when the host shows no such window.
	std::optional<HostSurface> host_surface(uint64_t window);
	void release_host_surface(uint64_t window);
	// The client area of a window as its swap chains see it; empty for a window that does not exist.
	std::optional<std::pair<uint32_t,uint32_t>> client_size(uint64_t window);
	void set_deadline(std::chrono::steady_clock::time_point deadline);
	// Lets other guest threads run while this one waits for messages; returns true when one ran.
	void set_yield(std::function<bool()> yield) { yield_hook = std::move(yield); }
	// Blocks the calling guest thread until the condition holds while the others run (a message sent to another thread's window).
	void set_block(std::function<void(std::function<bool()>)> block) { block_hook = std::move(block); }
	// Resolves the default menu of a window class (module, resource identifier) to a menu handle.
	// Allocates guest global memory for clipboard data that arrives from the host.
	void set_global_allocator(std::function<uint64_t(uint64_t)> allocator) { global_allocator = std::move(allocator); }
	void set_menu_loader(std::function<uint64_t(uint64_t,uint64_t)> loader) { menu_loader = std::move(loader); }
	bool dispatch(std::string_view name);
	// user32 entry points that follow the shared registry conventions; every handler runs on the calling guest thread.
	void register_api(ApiRegistry &registry);
	// Drawing marks the surface dirty; the next message retrieval presents it, so a burst of primitives costs one frame.
	void drawing(uint64_t window);
	void flush_dirty();
	// Whether a message, paint request or due timer waits for the guest; host input is delivered to the windows on the way, so this
	// runs only inside a call of the guest thread.
	bool input_ready();
	// The same question for a waiting thread's condition: host input is only collected, and no window procedure runs.
	bool input_pending(uint32_t thread);
	void dump_windows();
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
		// The guest thread whose queue holds the message; zero for one any thread may take.
		uint32_t thread=0;
	};
	// The posted messages of every guest thread, each marked with the thread that owns it; HWNDs and drawing resources stay in
	// DesktopObjects.
	std::deque<Message> messages;
	// Queues a message for the thread that owns its window (the calling thread for a message to no window).
	void queue(Message message);
	uint32_t owner(uint64_t window) const;
	bool queued_for(uint32_t thread) const;
	// A message sent to a window of another thread waits here until that thread retrieves messages; the sender waits for the result.
	struct SentMessage { uint64_t window; uint32_t message; uint64_t wparam, lparam, result=0; uint32_t thread; bool taken=false, done=false; };
	std::deque<std::shared_ptr<SentMessage>> sent;
	// Runs the messages other threads sent to windows of the calling thread.
	void serve_sent();
	bool sent_for(uint32_t thread) const;
	std::function<void(std::function<bool()>)> block_hook;
	// A window of the calling thread that needs painting, under the filter window when one is given.
	uint64_t invalid_owned(uint64_t filter) const;
	// Device contexts over windows of other processes, and the frames other processes drew into this process's windows.
	struct ForeignTarget { std::shared_ptr<ForeignSurface> surface; uint64_t bitmap=0; };
	std::map<uint64_t,ForeignTarget> foreign_targets;
	uint64_t foreign_dc(uint64_t window);
	std::map<uint64_t,uint32_t> foreign_frames;
	std::chrono::steady_clock::time_point foreign_checked{};
	void import_foreign_frames();
	// Host input collected while threads waited, delivered by the next input_ready.
	std::deque<DesktopEvent> pending_events;
	void deliver_pending();
	// PostQuitMessage codes by thread.
	std::map<uint32_t,uint32_t> quits;
	std::set<uint64_t> dirty_roots;
	bool dumped=false;
	std::chrono::steady_clock::time_point started=std::chrono::steady_clock::now();
	std::chrono::steady_clock::time_point deadline;
	std::function<bool()> yield_hook;
	std::function<uint64_t(uint64_t,uint64_t)> menu_loader;
	uint32_t mouse_buttons=0;
	int32_t cursor_x=0,cursor_y=0;
	uint64_t focus=0,active=0;
	bool activating=false,has_queued_activation=false;
	uint64_t queued_activation=0;
	int focusing=0;
	bool keep_host_window=false;
	// Roots whose host window carries a surface handed to a graphics driver: such a window must survive a resize.
	std::set<uint64_t> hosting_surface;
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
	uint64_t pressed_frame_hit=0,pressed_frame_window=0;
	struct MenuPopup {
		uint64_t handle,menu,parent;
		int32_t x,y,width,height;
		std::vector<DesktopRect> items;
		std::optional<size_t> highlight;
		std::vector<uint8_t> pixels;
	};
	// Open drop-downs, outermost first; handles live in their own range so they never collide with window handles.
	std::vector<MenuPopup> popups;
	uint64_t next_popup=0x7b000000;
	bool menu_active() const { return open_menu_item.has_value() || !popups.empty(); }
	bool menu_event(const DesktopEvent &event);
	void menu_open_bar(uint64_t window,size_t index);
	void menu_open_popup(uint64_t menu,uint64_t parent,int32_t x,int32_t y);
	void menu_render(MenuPopup &popup);
	void menu_highlight(size_t level,std::optional<size_t> index);
	void menu_select(size_t level,size_t index);
	void menu_close();
	void nonclient_pointer(uint64_t window,uint64_t hit,uint32_t message,int32_t x,int32_t y);
	bool system_dispatch(std::string_view name);
	void register_message_api(ApiRegistry &registry);
	void register_manager_api(ApiRegistry &registry);
	void register_menu_api(ApiRegistry &registry);
	void register_ext_api(ApiRegistry &registry);
	void register_scroll_api(ApiRegistry &registry);
	void register_long_api(ApiRegistry &registry);
	void register_ansi_api(ApiRegistry &registry);
	// Layout of one non-client scroll bar in screen coordinates.
	struct ScrollGeometry {
		DesktopRect bar{},up{},down{},track{},thumb{};
		bool present=false,vertical=false,has_thumb=false;
	};
	ScrollGeometry scroll_geometry(const DesktopWindow &window,int bar) const;
	int scroll_part_at(const DesktopWindow &window,int bar,int32_t x,int32_t y) const;
	uint64_t scroll_hit(const DesktopWindow &window,int32_t x,int32_t y) const;
	bool scroll_sync_visibility(uint64_t window,int bar,bool allow_disable);
	void refresh_frame(uint64_t window);
	void paint_scrollbars(uint64_t root);
	void paint_child_frames(uint64_t root);
	void scroll_notify(uint64_t window,int bar,uint32_t code,int32_t position);
	bool scroll_pointer(uint64_t window,uint64_t hit,uint32_t message,int32_t x,int32_t y);
	bool scroll_motion(uint32_t message,int32_t x,int32_t y);
	void scroll_idle();
	// The scroll bar being operated with the pointer: which part, and for the thumb where it was grabbed.
	struct ScrollDrag { uint64_t window=0; int bar=0; int part=0; int32_t grab=0; std::chrono::steady_clock::time_point next{}; };
	ScrollDrag scroll_drag;
	// Text caret of the input queue: one per thread in Windows, one here. Its rectangle is drawn by inverting pixels.
	struct Caret {
		uint64_t window=0;
		int32_t width=0,height=0,x=0,y=0;
		int hidden=1;
		bool drawn=false;
		std::chrono::steady_clock::time_point next{};
	};
	std::optional<Caret> caret;
	void caret_sync();
	void caret_idle();
	// Hooks installed with SetWindowsHookEx, newest first; handles live in their own range.
	struct Hook { uint64_t handle; int32_t id; uint64_t procedure; };
	std::vector<Hook> hooks;
	uint64_t next_hook=0x7e000000;
	bool has_hook(int32_t id) const;
	uint64_t call_hooks(int32_t id,int32_t code,uint64_t wparam,uint64_t lparam,uint64_t after=0);
	// In-process clipboard: each format maps to the global memory handle the owner supplied.
	std::map<uint32_t,uint64_t> clipboard_data;
	uint64_t clipboard_window=0,clipboard_owner=0;
	uint32_t clipboard_sequence=1;
	// Sequence already offered to the host selection and the host selection already imported.
	uint32_t clipboard_published=0;
	uint64_t host_selection=0;
	std::function<uint64_t(uint64_t)> global_allocator;
	std::array<uint8_t,256> vk_state{},vk_async{};
	std::map<uint64_t,uint64_t> system_menus;
	struct Tracking { uint64_t window=0; uint32_t flags=0; };
	Tracking tracking;
	void track_pointer(uint64_t window);
	// Persistent guest scratch memory for API handlers that need to pass structures to guest callbacks.
	uint64_t scratch_base=0;
	size_t scratch_used=0;
	uint64_t scratch_allocate(size_t size);
	// Shows, hides, minimizes, maximizes or restores a window; returns whether it was visible before.
	bool show_window(uint64_t window,uint32_t command);
	// Moves and resizes a window (screen coordinates for the outer rectangle) with the WM_WINDOWPOSCHANGING/CHANGED protocol.
	void place_window(uint64_t window,DesktopRect outer,uint64_t insert_after,uint32_t flags);
	void shift_window(uint64_t window,int32_t dx,int32_t dy);
	std::vector<uint64_t> top_level_windows() const;
	uint64_t window_at(int32_t x,int32_t y);
	bool enable_window(uint64_t window,bool enable);
	void invalidate_tree(uint64_t window,bool erase);
	// Window messages registered by name (RegisterWindowMessage); ids start at 0xc000 like atoms.
	std::map<std::u16string,uint32_t> registered_messages;
	int32_t cursor_count=0;
	uint64_t current_cursor=0;
	// Mouse capture and timers belong to the initial guest thread's input state.
	uint64_t capture=0;
	struct Timer { uint64_t window,id,procedure; uint32_t interval; std::chrono::steady_clock::time_point due; bool system=false; uint32_t thread=0; };
	std::vector<Timer> timers;
	uint64_t next_timer_id=0x1000;
	void post_due_timers();
	// The previous client size, when the caller has already stored a provisional one, decides whether WM_SIZE is due.
	void recalculate_client(uint64_t window,int32_t previous_width=-1,int32_t previous_height=-1);
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
