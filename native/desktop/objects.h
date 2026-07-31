#pragma once

#include "graphics/icon_bitmap.h"
#include "graphics/icon_group.h"
#include "region.h"
#include "shared_pixels.h"
#include "nonclient.h"
#include "colors.h"
#include "menu.h"
#include <array>
#include <span>
#include <memory>
#include <optional>
#ifdef RAVEN_SKIA
#include "graphics/text.h"
#endif

#include <map>
#include <variant>
#include <string>
#include <string_view>

namespace raven {

struct DesktopIcon {
	IconBitmap image;
	bool monochrome;
	bool shared;
};

struct DesktopBitmap {
	uint32_t width;
	uint32_t height;
	uint32_t depth;
	// Top-down DDB rows: word-aligned monochrome bits or straight-alpha BGRA32.
	std::vector<uint8_t> bits;
	uint64_t address = 0;
	bool top_down = true;
	bool stock = false;
	// Guest-backed window storage does not imply a public DIB section.
	bool dib_section = false;
	// Host view of the guest-visible pixels; guest-backed bitmaps always carry one.
	std::shared_ptr<SharedPixels> shared{};
	std::span<uint8_t> pixels() { return shared ? std::span<uint8_t>(shared->data(), shared->size()) : std::span<uint8_t>(bits); }
	std::span<const uint8_t> pixels() const { return shared ? std::span<const uint8_t>(shared->data(), shared->size()) : std::span<const uint8_t>(bits); }
};

struct DesktopFont {
	std::array<uint8_t,92> definition{};
	bool pending_delete = false;
};

inline constexpr uint64_t desktop_system_font = 0xfffe;
inline constexpr uint64_t desktop_stock_brush = 0xfff0;
inline constexpr uint64_t desktop_system_brush = 0xffc0;
inline constexpr uint64_t desktop_stock_pen = 0xffb0;
// IDC_* identifiers 32512..32651 map onto this block of system cursor handles.
inline constexpr uint64_t desktop_stock_cursor = 0xfa00;
inline constexpr uint32_t desktop_stock_cursor_count = 140;

struct DesktopBrush {
	uint32_t color = 0;
	bool hollow = false,pending_delete = false;
};

struct DesktopPen {
	uint32_t color=0;
	bool hollow=false,pending_delete=false;
};

struct DesktopDC {
	uint64_t bitmap;
	uint64_t default_bitmap;
	uint64_t window = 0;
	std::optional<DesktopRegion> clip{};
	uint64_t font = desktop_system_font;
	bool leased = false;
	bool window_frame = false;
	uint32_t text_color = 0,background_color = 0xffffff,background_mode = 2;
	uint64_t brush = desktop_stock_brush;
	int32_t origin_x=0,origin_y=0;
	std::optional<DesktopRect> bounds{};
	// Application clipping is independent of BeginPaint's update region.
	std::optional<DesktopRegion> application_clip{};
	uint64_t pen=desktop_stock_pen+1;
	int32_t position_x=0,position_y=0;
	// R2_COPYPEN until SetROP2 changes how pens combine with the destination.
	uint32_t rop2=13;
	// Clip coordinates belong to the DC, not its bitmap backing.
	bool contains(int64_t x,int64_t y) const
	{
		x-=origin_x; y-=origin_y;
		if (bounds && (x<bounds->left || y<bounds->top || x>=bounds->right || y>=bounds->bottom)) return false;
		if (x<INT32_MIN || x>INT32_MAX || y<INT32_MIN || y>INT32_MAX) return false;
		return (!clip || clip->contains(int32_t(x),int32_t(y))) &&
			(!application_clip || application_clip->contains(int32_t(x),int32_t(y)));
	}
};

struct DesktopClass {
	std::string name;
	uint64_t instance;
	uint64_t procedure;
	uint64_t background = 0;
	uint32_t window_extra = 0;
	std::vector<uint8_t> extra{};
	uint32_t style = 0;
	uint16_t atom = 0;
	uint64_t icon = 0,cursor = 0;
	// Default menu resource: an integer identifier, or a name when the identifier is zero.
	uint32_t menu_id = 0;
	std::u16string menu_name{};
};

struct DesktopAccelerator {
	uint8_t flags;
	uint16_t key,command;
};

struct DesktopMenuItem {
	uint32_t type,state,id;
	std::u16string text;
	uint64_t submenu=0;
	// Owner-draw payload and the check-mark and item bitmaps an application attached.
	uint64_t data=0,bitmap_checked=0,bitmap_unchecked=0,bitmap_item=0;
};

struct DesktopMenu {
	std::vector<DesktopMenuItem> items;
	uint32_t help=0;
	uint64_t parent=0;
};

struct DesktopWindow {
	uint16_t class_id;
	uint64_t procedure;
	std::u16string title;
	int32_t x, y, width, height;
	bool destroying = false;
	uint64_t bitmap = 0, dc = 0;
	bool visible = false;
	bool painting = false, erase_pending = false;
	DesktopRegion update{};
	uint64_t instance = 0,userdata = 0;
	uint32_t style = 0x84000000;
	std::vector<uint8_t> extra{};
	// Client origin and extent stay distinct from the outer window rectangle.
	DesktopRect outer{x,y,int32_t(int64_t(x)+width),int32_t(int64_t(y)+height)};
	uint64_t parent = 0,child_id = 0;
	uint32_t ex_style = 0;
	uint64_t menu = 0;
	bool client_ready = true;
	// Owner of a top-level window (a different relation from the parent of a child) and the sibling order, bottom to top.
	uint64_t owner = 0;
	uint64_t order = 0;
	// Outer rectangle to return to when a maximized or minimized window is restored.
	DesktopRect restore{};
	std::map<std::u16string,uint64_t> properties{};
};

class DesktopObjects {
public:
	explicit DesktopObjects(size_t limit = 256 * 1024 * 1024, IconDisplay display = {},DesktopMetrics metrics = {},DesktopColors colors = desktop_colors);
	DesktopObjects(const DesktopObjects &) = delete;
	DesktopObjects &operator=(const DesktopObjects &) = delete;
	using Object = std::variant<DesktopIcon, DesktopBitmap, DesktopDC, DesktopWindow, DesktopFont, DesktopBrush, DesktopMenu, DesktopRegion, DesktopPen>;
	uint64_t add(Object object);
	bool erase(uint64_t handle);
	const DesktopMenu *menu(uint64_t handle) const;
	DesktopMenu *edit_menu(uint64_t handle);
	// Accelerator tables live outside the object map; their handles never collide with GDI or window handles.
	uint64_t add_accelerators(std::vector<DesktopAccelerator> table);
	const std::vector<DesktopAccelerator> *accelerators(uint64_t handle) const;
	bool remove_accelerators(uint64_t handle);
	uint64_t load_menu(const MenuTemplate &definition);
	const DesktopIcon *icon(uint64_t handle) const;
	const DesktopBitmap *bitmap(uint64_t handle) const;
	DesktopBitmap *bitmap(uint64_t handle);
	DesktopDC *dc(uint64_t handle);
	const DesktopRegion *region(uint64_t handle) const;
	bool replace_region(uint64_t handle,DesktopRegion region);
	bool select_clip(uint64_t dc,std::optional<DesktopRegion> region);
	const DesktopFont *font(uint64_t handle) const;
	uint64_t select_font(uint64_t dc, uint64_t font);
	bool delete_font(uint64_t font);
	const DesktopBrush *brush(uint64_t handle) const;
	uint32_t system_color(int32_t index) const;
	uint64_t system_brush(int32_t index) const;
	uint64_t select_brush(uint64_t dc,uint64_t brush);
	bool delete_brush(uint64_t brush);
	const DesktopPen *pen(uint64_t handle) const;
	uint64_t select_pen(uint64_t dc,uint64_t pen);
	bool delete_pen(uint64_t pen);
	void update_window_dcs(uint64_t window);
	void detach_window_dcs(uint64_t window);
	DesktopWindow *window(uint64_t handle);
	const DesktopWindow *window(uint64_t handle) const;
	uint64_t window_root(uint64_t handle) const;
	// Children of a window in z-order, bottom to top. Top-level windows are the children of window zero.
	std::vector<uint64_t> child_windows(uint64_t parent) const;
	// Moves a window to the top or bottom of its siblings.
	void restack(uint64_t window,bool top);
	bool is_child(uint64_t parent,uint64_t child) const;
	bool window_visible(uint64_t handle) const;
	void configure_window_dc(uint64_t window,DesktopDC &device,bool frame) const;
	uint64_t invalid_window(uint64_t filter) const;
	std::vector<uint64_t> window_handles() const;
	bool set_title(uint64_t window,std::u16string title);
	bool invalidate(uint64_t window,DesktopRect rect,bool erase);
	bool validate(uint64_t window,DesktopRect rect);
	bool start_paint(uint64_t window);
	void finish_paint(uint64_t window);
	uint16_t register_class(DesktopClass definition);
	uint32_t unregister_class(uint16_t atom);
	uint16_t find_class(uint64_t instance, std::string_view name) const;
	uint16_t find_class(uint64_t instance,uint16_t atom) const;
	bool class_registered(uint64_t instance,std::string_view name,bool global) const;
	const DesktopClass *window_class(uint16_t atom) const;
	DesktopClass *window_class(uint16_t atom);
	bool selected(uint64_t bitmap) const;
	size_t count() const;
	size_t bytes() const;
	IconDisplay display() const;
#ifdef RAVEN_SKIA
	// One glyph engine serves every GDI and nonclient text operation of the process.
	TextRenderer &text();
#endif
	const DesktopMetrics &nonclient_metrics() const;

private:
	std::map<uint64_t, Object> objects;
	std::map<uint16_t,DesktopClass> classes;
	std::map<uint64_t,std::vector<DesktopAccelerator>> accelerator_tables;
#ifdef RAVEN_SKIA
	std::unique_ptr<TextRenderer> text_engine;
#endif
	uint32_t next_atom = 0xc000;
	uint32_t next_class = 1;
	uint64_t next = 0x10000;
	uint64_t next_order = 0;
	size_t used = 0;
	size_t limit;
	IconDisplay icon_display;
	DesktopMetrics window_metrics;
	// Immutable default bitmap identity, shared by all memory DCs in this owner.
	DesktopBitmap default_bitmap{1,1,1,{0,0},0,true,true};
	DesktopFont system_font;
	std::array<DesktopBrush,31> system_brushes{};
	std::array<DesktopBrush,6> stock_brushes{{{0xffffff},{0xc0c0c0},{0x808080},{0x404040},{0},{0,true}}};
	std::array<DesktopPen,3> stock_pens{{{0xffffff},{0},{0,true}}};
	bool font_selected(uint64_t handle) const;
	bool brush_selected(uint64_t handle) const;
	bool pen_selected(uint64_t handle) const;
};

}
