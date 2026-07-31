#include "windows.h"
#include "canvas.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace raven {

using namespace paint;

NativeWindows::FrameLayout NativeWindows::frame_layout(const DesktopWindow &window) const
{
	const auto &metrics = objects.nonclient_metrics();
	const uint32_t style = window.style & ~0x10000000U;
	FrameLayout layout{};
	const int32_t width = window.outer.right - window.outer.left, height = window.outer.bottom - window.outer.top;
	// AdjustWindowRect already encodes ReactOS' border and caption rules; its deltas are the frame thickness.
	const auto adjusted = adjust_window_rect(metrics, {0, 0, 0, 0}, style, false, window.ex_style);
	layout.border = -adjusted.left;
	layout.caption_height = (style & 0xc00000U) == 0xc00000U ? metrics.caption : 0;
	layout.menu_height = window.menu ? metrics.menu : 0;
	layout.edge = (style & 0x40000U) || (style & 0xc00000U) == 0x400000U || (style & 0xc00000U) == 0xc00000U;
	const int32_t border = layout.border;
	layout.caption = {border, border, width - border, border + std::max(layout.caption_height - 1, 0)};
	layout.menu_bar = {border, border + layout.caption_height, width - border, border + layout.caption_height + layout.menu_height};
	const int32_t button_height = std::max(layout.caption.bottom - layout.caption.top - 4, 0);
	const int32_t button_width = std::min(metrics.button_x, std::max(layout.caption.right - layout.caption.left, 0));
	int32_t cursor = layout.caption.right - 2;
	layout.close = layout.maximize = layout.minimize = {0, 0, 0, 0};
	if (layout.caption_height && (style & 0x80000U)) {
		layout.close = {cursor - button_width, layout.caption.top + 2, cursor, layout.caption.top + 2 + button_height};
		cursor = layout.close.left - 2;
		if (style & 0x30000U) {
			layout.maximize = {cursor - button_width, layout.caption.top + 2, cursor, layout.caption.top + 2 + button_height};
			layout.minimize = {layout.maximize.left - button_width, layout.maximize.top, layout.maximize.left, layout.maximize.bottom};
			// WS_MINIMIZEBOX or WS_MAXIMIZEBOX alone leaves the other button visible but disabled in Windows.
			if (!(style & 0x20000U) && !(style & 0x10000U))
				layout.minimize = layout.maximize = {0, 0, 0, 0};
		}
	}
	layout.icon = {layout.caption.left + 2, layout.caption.top + (layout.caption.bottom - layout.caption.top - 16) / 2, layout.caption.left + 18,
		layout.caption.top + (layout.caption.bottom - layout.caption.top - 16) / 2 + 16};
	return layout;
}

uint64_t NativeWindows::nonclient_hit(const DesktopWindow &window,int32_t x,int32_t y) const
{
	constexpr uint64_t nowhere=0,client=1,caption=2,system_menu=3,menu=5,minimize=8,maximize=9,left=10,right=11,top=12,top_left=13,
		top_right=14,bottom=15,bottom_left=16,bottom_right=17,border=18,close=20;
	const auto &outer=window.outer;
	if (x<outer.left || y<outer.top || x>=outer.right || y>=outer.bottom) return nowhere;
	if (x>=window.x && y>=window.y && int64_t(x)<int64_t(window.x)+window.width && int64_t(y)<int64_t(window.y)+window.height) return client;
	const auto layout=frame_layout(window);
	const int32_t px=x-outer.left,py=y-outer.top;
	const auto inside=[&](DesktopRect rect) { return px>=rect.left && px<rect.right && py>=rect.top && py<rect.bottom; };
	if (inside(layout.close)) return close;
	if (inside(layout.maximize)) return maximize;
	if (inside(layout.minimize)) return minimize;
	if (layout.caption_height && (window.style & 0x80000U) && inside(layout.icon)) return system_menu;
	if (layout.caption_height && inside({layout.caption.left,layout.caption.top,layout.caption.right,layout.caption.bottom+1})) return caption;
	if (layout.menu_height && inside(layout.menu_bar)) return menu;
	if (window.style & 0x40000U) {
		const int32_t width=outer.right-outer.left,height=outer.bottom-outer.top,corner=layout.border*2+8;
		const bool west=px<layout.border,east=px>=width-layout.border,north=py<layout.border,south=py>=height-layout.border;
		if (north && px<corner) return top_left;
		if (north && px>=width-corner) return top_right;
		if (south && px<corner) return bottom_left;
		if (south && px>=width-corner) return bottom_right;
		if (west && py<corner) return top_left;
		if (west && py>=height-corner) return bottom_left;
		if (east && py<corner) return top_right;
		if (east && py>=height-corner) return bottom_right;
		if (north) return top;
		if (south) return bottom;
		if (west) return left;
		if (east) return right;
	}
	return border;
}

void NativeWindows::nonclient_pointer(uint64_t handle,uint64_t hit,uint32_t message,int32_t x,int32_t y)
{
	// Only primary-button transitions act on the frame so far; hover and other buttons are ignored.
	const auto *window=objects.window(handle);
	if (!window) return;
	constexpr uint64_t menu_hit=5,minimize_hit=8,maximize_hit=9,close_hit=20;
	if (message==0x201) {
		pressed_frame_hit=hit; pressed_frame_window=handle;
		if (hit==menu_hit) {
			const auto rects=menu_bar_items(*window);
			for (size_t index=0;index<rects.size();++index)
				if (x>=rects[index].left && x<rects[index].right) { menu_open_bar(handle,index); break; }
		}
		return;
	}
	if (message==0x202 && pressed_frame_window==handle && pressed_frame_hit==hit) {
		pressed_frame_hit=0; pressed_frame_window=0;
		if (hit==close_hit) send(handle,0x112,0xf060,0);
		else if (hit==minimize_hit) send(handle,0x112,0xf020,0);
		else if (hit==maximize_hit) send(handle,0x112,0xf030,0);
	}
	(void)y;
}

#ifdef RAVEN_SKIA
std::vector<DesktopRect> NativeWindows::menu_bar_items(const DesktopWindow &window)
{
	std::vector<DesktopRect> rects;
	const auto *menu = objects.menu(window.menu);
	if (!menu)
		return rects;
	const auto layout = frame_layout(window);
	auto &renderer = objects.text();
	const auto font = interface_font();
	int32_t x = layout.menu_bar.left;
	for (const auto &item : menu->items) {
		const auto label = menu_label(item.text).first;
		const auto characters = printable(label);
		const int32_t width = (characters.empty() ? 0 : renderer.extent(font, characters).width) + 2 * 8;
		rects.push_back({x, layout.menu_bar.top, x + width, layout.menu_bar.bottom});
		x += width;
	}
	return rects;
}

void NativeWindows::paint_nonclient(uint64_t handle)
{
	auto *window = objects.window(handle);
	if (!window || window->parent || !window->bitmap)
		return;
	const auto layout = frame_layout(*window);
	if (!layout.border && !layout.caption_height && !layout.menu_height)
		return;
	const auto *bitmap = objects.bitmap(window->bitmap);
	if (!bitmap || !bitmap->shared || bitmap->depth != 32)
		return;
	Canvas canvas{objects.bitmap(window->bitmap)->pixels().data(), int32_t(bitmap->width), int32_t(bitmap->height)};
	const int32_t width = window->outer.right - window->outer.left, height = window->outer.bottom - window->outer.top;
	const bool is_active = active == handle;
	const auto color = [&](int index) { return rgb(objects.system_color(index)); };
	if (layout.border) {
		// The ring first takes the frame color, then the bevel is laid over its outer two pixels.
		const DesktopRect all{0, 0, width, height};
		const DesktopRect inner{layout.border, layout.border, width - layout.border, height - layout.border};
		canvas.fill({all.left, all.top, all.right, inner.top}, color(color_button_face));
		canvas.fill({all.left, inner.bottom, all.right, all.bottom}, color(color_button_face));
		canvas.fill({all.left, inner.top, inner.left, inner.bottom}, color(color_button_face));
		canvas.fill({inner.right, inner.top, all.right, inner.bottom}, color(color_button_face));
		if (layout.edge && layout.border >= 2)
			canvas.edge(all, color(color_light), color(color_dark_shadow), color(color_button_highlight), color(color_button_shadow));
	}
	if (layout.caption_height) {
		const auto from = color(is_active ? color_active_caption : color_inactive_caption);
		const auto to = color(is_active ? color_gradient_active : color_gradient_inactive);
		const auto span = layout.caption.right - layout.caption.left;
		for (int32_t x = layout.caption.left; x < layout.caption.right; ++x)
			canvas.fill({x, layout.caption.top, x + 1, layout.caption.bottom}, mix(from, to, x - layout.caption.left, span - 1));
		canvas.fill({layout.caption.left, layout.caption.bottom, layout.caption.right, layout.caption.bottom + 1}, color(color_button_face));
		auto &renderer = objects.text();
		const auto text_color = color(is_active ? color_caption_text : color_inactive_text);
		const int32_t text_left = layout.caption.left + (window->style & 0x80000U ? 20 : 4);
		int32_t text_right = layout.caption.right - 2;
		for (const auto &button : {layout.minimize, layout.maximize, layout.close})
			if (button.right > button.left)
				text_right = std::min(text_right, button.left - 4);
		const auto metrics = renderer.metrics(interface_font());
		draw_text(renderer, canvas, window->title, text_left, layout.caption.top + (layout.caption.bottom - layout.caption.top - metrics.height) / 2,
			text_color, std::nullopt, text_right - text_left);
		const auto button = [&](DesktopRect rect, int glyph) {
			if (rect.right <= rect.left)
				return;
			canvas.fill(rect, color(color_button_face));
			canvas.edge(rect, color(color_button_highlight), color(color_dark_shadow), color(color_light), color(color_button_shadow));
			const int32_t cx = (rect.left + rect.right) / 2, cy = (rect.top + rect.bottom) / 2;
			const auto ink = color(color_menu_text);
			if (glyph == 0) {
				for (int32_t d = -3; d <= 3; ++d) { canvas.set(cx + d, cy + d, ink); canvas.set(cx + d, cy - d, ink); }
			} else if (glyph == 1) {
				for (int32_t d = -4; d <= 4; ++d) { canvas.set(cx + d, cy - 4, ink); canvas.set(cx + d, cy + 4, ink); canvas.set(cx - 4, cy + d, ink); canvas.set(cx + 4, cy + d, ink); }
			} else {
				for (int32_t d = -3; d <= 3; ++d) canvas.set(cx + d, cy + 4, ink);
			}
		};
		button(layout.close, 0);
		button(layout.maximize, 1);
		button(layout.minimize, 2);
	}
	if (layout.menu_height) {
		canvas.fill(layout.menu_bar, color(color_menu_bar));
		auto &renderer = objects.text();
		const auto metrics = renderer.metrics(interface_font());
		const auto *menu = objects.menu(window->menu);
		const auto rects = menu_bar_items(*window);
		for (size_t index = 0; menu && index < rects.size() && index < menu->items.size(); ++index) {
			const auto &rect = rects[index];
			if (rect.right > layout.menu_bar.right)
				break;
			const auto [label, mnemonic] = menu_label(menu->items[index].text);
			const bool open = open_menu_item && open_menu_window == handle && *open_menu_item == index;
			if (open) {
				canvas.fill(rect, color(13));
				draw_text(renderer, canvas, label, rect.left + 8, rect.top + (rect.bottom - rect.top - metrics.height) / 2, color(14), mnemonic);
			} else {
				draw_text(renderer, canvas, label, rect.left + 8, rect.top + (rect.bottom - rect.top - metrics.height) / 2, color(color_menu_text), mnemonic);
			}
		}
	}
}
#else
void NativeWindows::paint_nonclient(uint64_t)
{
	// Without the text engine, nonclient text cannot be drawn; the window keeps its unpainted frame.
}

std::vector<DesktopRect> NativeWindows::menu_bar_items(const DesktopWindow &)
{
	return {};
}
#endif

}
