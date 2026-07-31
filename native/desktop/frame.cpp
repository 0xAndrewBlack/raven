#include "windows.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace raven {

namespace {

constexpr int color_active_caption = 2, color_inactive_caption = 3, color_menu = 4, color_window_frame = 6, color_menu_text = 7,
	color_caption_text = 9, color_button_face = 15, color_button_shadow = 16, color_button_highlight = 20, color_dark_shadow = 21,
	color_light = 22, color_gradient_active = 27, color_gradient_inactive = 28, color_menu_bar = 30, color_inactive_text = 19;

// BGRA pixels of one window surface, edited in host memory and written back once.
struct Canvas {
	std::vector<uint8_t> pixels;
	int32_t width, height;

	void set(int32_t x, int32_t y, uint32_t rgb)
	{
		if (x < 0 || y < 0 || x >= width || y >= height)
			return;
		const auto at = (size_t(y) * size_t(width) + size_t(x)) * 4;
		pixels[at] = uint8_t(rgb >> 16);
		pixels[at + 1] = uint8_t(rgb >> 8);
		pixels[at + 2] = uint8_t(rgb);
		pixels[at + 3] = 0;
	}

	void fill(DesktopRect rect, uint32_t rgb)
	{
		for (int32_t y = std::max(rect.top, 0); y < std::min(rect.bottom, height); ++y)
			for (int32_t x = std::max(rect.left, 0); x < std::min(rect.right, width); ++x)
				set(x, y, rgb);
	}

	// Two-pixel raised or sunken bevel inside rect, using four shades like DrawEdge.
	void edge(DesktopRect rect, uint32_t outer_top_left, uint32_t outer_bottom_right, uint32_t inner_top_left, uint32_t inner_bottom_right)
	{
		for (int32_t x = rect.left; x < rect.right; ++x) {
			set(x, rect.top, outer_top_left);
			set(x, rect.bottom - 1, outer_bottom_right);
		}
		for (int32_t y = rect.top; y < rect.bottom; ++y) {
			set(rect.left, y, outer_top_left);
			set(rect.right - 1, y, outer_bottom_right);
		}
		set(rect.right - 1, rect.top, outer_bottom_right);
		set(rect.left, rect.bottom - 1, outer_bottom_right);
		for (int32_t x = rect.left + 1; x < rect.right - 1; ++x) {
			set(x, rect.top + 1, inner_top_left);
			set(x, rect.bottom - 2, inner_bottom_right);
		}
		for (int32_t y = rect.top + 1; y < rect.bottom - 1; ++y) {
			set(rect.left + 1, y, inner_top_left);
			set(rect.right - 2, y, inner_bottom_right);
		}
		set(rect.right - 2, rect.top + 1, inner_bottom_right);
		set(rect.left + 1, rect.bottom - 2, inner_bottom_right);
	}

	void blend(const std::vector<uint8_t> &coverage, int32_t mask_width, int32_t x, int32_t y, uint32_t rgb)
	{
		const int32_t mask_height = int32_t(coverage.size() / size_t(mask_width));
		for (int32_t row = 0; row < mask_height; ++row)
			for (int32_t column = 0; column < mask_width; ++column)
				if (coverage[size_t(row) * size_t(mask_width) + size_t(column)])
					set(x + column, y + row, rgb);
	}
};

uint32_t mix(uint32_t from, uint32_t to, int64_t step, int64_t steps)
{
	if (steps <= 0)
		return from;
	uint32_t result = 0;
	for (int shift = 0; shift <= 16; shift += 8) {
		const int64_t a = (from >> shift) & 0xff, b = (to >> shift) & 0xff;
		result |= uint32_t(a + (b - a) * step / steps) << shift;
	}
	return result;
}

// System colors are COLORREF values (0x00BBGGRR), which is also what Canvas stores; no channel swap is needed.
uint32_t rgb(uint32_t colorref)
{
	return colorref;
}

}

// Fonts of the nonclient area: the qualified sans face at the classic 8 point size.
static std::array<uint8_t, 92> interface_font()
{
	std::array<uint8_t, 92> definition{};
	const int32_t height = -11;
	for (size_t byte = 0; byte < 4; ++byte)
		definition[byte] = uint8_t(uint32_t(height) >> (byte * 8));
	definition[16] = 0x90;
	definition[17] = 0x01;
	definition[26] = 3;
	const std::string_view name = "Liberation Sans";
	for (size_t index = 0; index < name.size(); ++index)
		definition[28 + index * 2] = uint8_t(name[index]);
	return definition;
}

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

#ifdef RAVEN_SKIA
static std::vector<uint16_t> printable(std::u16string_view text)
{
	std::vector<uint16_t> result;
	for (const auto character : text) {
		const bool supported = (character >= 32 && character <= 126) || (character >= 0x00a0 && character <= 0x024f) ||
			(character >= 0x0370 && character <= 0x03ff) || (character >= 0x1e00 && character <= 0x1eff);
		result.push_back(supported ? uint16_t(character) : uint16_t('?'));
	}
	return result;
}

// Draws one line of text and returns its pixel width; underline marks a mnemonic character index.
static int32_t draw_text(TextRenderer &renderer, Canvas &canvas, std::u16string_view text, int32_t x, int32_t y, uint32_t color,
	std::optional<size_t> underline = std::nullopt, int32_t limit = INT32_MAX)
{
	const auto font = interface_font();
	auto characters = printable(text);
	if (characters.empty())
		return 0;
	auto extent = renderer.extent(font, characters);
	if (extent.width > limit) {
		// Truncate with an ellipsis rather than overdrawing the neighboring control.
		while (characters.size() > 1 && renderer.extent(font, characters).width + 3 * 3 > limit)
			characters.pop_back();
		characters.insert(characters.end(), 3, uint16_t('.'));
		extent = renderer.extent(font, characters);
	}
	const auto metrics = renderer.metrics(font);
	const int32_t mask_width = extent.width + 2, mask_height = extent.height;
	const auto coverage = renderer.mask(font, characters, uint32_t(mask_width), uint32_t(mask_height), 0, 0);
	canvas.blend(coverage, mask_width, x, y, color);
	if (underline && *underline < characters.size()) {
		const auto before = renderer.extent(font, std::span<const uint16_t>(characters).first(*underline)).width;
		const auto glyph = renderer.extent(font, std::span<const uint16_t>(characters).subspan(*underline, 1)).width;
		for (int32_t offset = 0; offset < glyph; ++offset)
			canvas.set(x + before + offset, y + metrics.ascent + 1, color);
	}
	return extent.width;
}

// Menu text without ampersand markers; the mnemonic index points into the returned text.
static std::pair<std::u16string, std::optional<size_t>> menu_label(std::u16string_view text)
{
	std::u16string result;
	std::optional<size_t> mnemonic;
	for (size_t index = 0; index < text.size(); ++index) {
		if (text[index] == u'&' && index + 1 < text.size()) {
			if (text[index + 1] != u'&' && !mnemonic)
				mnemonic = result.size();
			++index;
		}
		if (text[index] == u'\t')
			break;
		result.push_back(text[index]);
	}
	return {result, mnemonic};
}

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
	if (!bitmap || !bitmap->address || bitmap->depth != 32)
		return;
	Canvas canvas{process.read_memory(bitmap->address, size_t(bitmap->width) * bitmap->height * 4), int32_t(bitmap->width), int32_t(bitmap->height)};
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
	process.write_memory(bitmap->address, canvas.pixels);
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
