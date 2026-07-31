#include "api.h"
#include "gdi.h"
#include "nt/text.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <new>
#include <sys/mman.h>

#ifdef RAVEN_SKIA

namespace raven {

namespace {

std::vector<uint16_t> to_units(std::u16string_view text)
{
	return std::vector<uint16_t>(text.begin(), text.end());
}

void write_size(const ApiCall &call, uint64_t address, int32_t width, int32_t height)
{
	if (!address)
		return;
	call.store<int32_t>(address, width);
	call.store<int32_t>(address + 4, height);
}

std::u16string widen(const ApiCall &call, uint64_t address, int32_t count, bool ansi)
{
	if (count < 0)
		throw uint32_t(87);
	if (count > 65536)
		throw uint32_t(87);
	if (!count)
		return {};
	if (!ansi) {
		const auto bytes = call.read(address, size_t(count) * 2);
		std::u16string text(size_t(count), 0);
		std::memcpy(text.data(), bytes.data(), bytes.size());
		return text;
	}
	const auto bytes = call.read(address, size_t(count));
	return from_ansi(std::string(bytes.begin(), bytes.end()), 1252);
}

}

void NativeDesktop::register_text_api(ApiRegistry &registry)
{
	const auto require_dc = [this](const ApiCall &call, size_t index) -> DesktopDC & {
		auto *dc = objects.dc(call[index]);
		if (!dc)
			throw uint32_t(6);
		return *dc;
	};
	const auto selected_font = [this](const DesktopDC &dc) -> const DesktopFont & {
		const auto *font = objects.font(dc.font);
		if (!font)
			throw uint32_t(6);
		return *font;
	};
	const auto guarded = [](ApiCall &call, uint64_t failure, const std::function<void()> &body) {
		try {
			body();
		} catch (const uint32_t &error) {
			call.fail(error, failure);
		} catch (const std::bad_alloc &) {
			call.fail(8, failure);
		}
	};
	// Cumulative advances: the qualified measurement when the font is inside the measured subset, the general one otherwise.
	const auto measured_advances = [this](std::span<const uint8_t, 92> definition, std::span<const uint16_t> units) {
		try {
			return objects.text().advances(definition, units);
		} catch (const uint32_t &error) {
			if (std::getenv("RAVEN_TRACE_API")) fprintf(stderr, "logical fallback after %u\n", error);
			return objects.text().logical_advances(definition, units);
		}
	};
	// Draws one run of text with GDI alignment, background and clipping rules; returns the run's advance width.
	const auto draw_run = [this, measured_advances](DesktopDC &dc, int32_t x, int32_t y, uint32_t options, const DesktopRect *clip_rect,
		std::u16string_view text, std::span<const int32_t> deltas) -> int32_t {
		Painter painter(objects, dc);
		const auto &font = *objects.font(dc.font);
		const auto metrics = objects.text().logical_metrics(font.definition);
		const auto units = to_units(text);
		int32_t advance = 0;
		std::vector<int32_t> offsets;
		if (!units.empty()) {
			if (!deltas.empty()) {
				int32_t position = 0;
				for (size_t i = 0; i < units.size(); ++i) {
					offsets.push_back(position);
					position += deltas[i];
				}
				advance = position;
			} else {
				const auto cumulative = measured_advances(font.definition, units);
				advance = cumulative.back();
			}
		}
		// Horizontal alignment moves the starting point by the run width; vertical alignment by the cell.
		const uint32_t align = dc.text_align;
		if ((align & 6) == 6)
			x -= advance / 2;
		else if (align & 2)
			x -= advance;
		if ((align & 24) == 24)
			y -= metrics.ascent;
		else if (align & 8)
			y -= metrics.height;
		const int64_t device_x = int64_t(x) + dc.origin_x, device_y = int64_t(y) + dc.origin_y;
		DesktopRect clip{INT32_MIN, INT32_MIN, INT32_MAX, INT32_MAX};
		if (clip_rect && (options & 4))
			clip = *clip_rect;
		if (clip_rect && (options & 2)) {
			DesktopBrush brush;
			brush.color = dc.background_color;
			painter.fill(clip_rect->left, clip_rect->top, clip_rect->right, clip_rect->bottom, brush);
		}
		if (!units.empty() && dc.background_mode == 2) {
			DesktopBrush brush;
			brush.color = dc.background_color;
			const int32_t left = std::min(x, x + advance), right = std::max(x, x + advance);
			painter.fill(std::max(left, clip.left), std::max(y, clip.top), std::min(right, clip.right), std::min(y + metrics.height, clip.bottom), brush);
		}
		if (units.empty() || advance == 0)
			return advance;
		const int32_t margin = 4;
		const uint32_t box_width = uint32_t(std::min<int64_t>(int64_t(advance) + 2 * margin + 2 * metrics.height, 16384));
		const uint32_t box_height = uint32_t(metrics.height + 4);
		std::vector<uint8_t> coverage;
		try {
			// Qualified fonts keep their measured monochrome glyphs; everything else is anti-aliased.
			try {
				std::vector<std::array<int32_t, 2>> positions;
				for (const auto offset : offsets)
					positions.push_back({offset, 0});
				const auto binary = objects.text().mask(font.definition, units, box_width, box_height, margin, 2, positions);
				coverage.assign(binary.size(), 0);
				for (size_t i = 0; i < binary.size(); ++i)
					coverage[i] = binary[i] ? 255 : 0;
			} catch (const uint32_t &) {
				coverage = objects.text().render(font.definition, units, box_width, box_height, margin, 2, offsets);
			}
		} catch (const uint32_t &) {
			return advance;
		}
		const bool underline = font.definition[21] != 0, strike = font.definition[22] != 0;
		const uint32_t color = dc.text_color;
		for (uint32_t row = 0; row < box_height; ++row)
			for (uint32_t column = 0; column < box_width; ++column) {
				const int64_t px = device_x - margin + column, py = device_y - 2 + row;
				const int64_t logical_x = px - dc.origin_x, logical_y = py - dc.origin_y;
				if (logical_x < clip.left || logical_x >= clip.right || logical_y < clip.top || logical_y >= clip.bottom)
					continue;
				const uint8_t alpha = coverage[size_t(row) * box_width + column];
				if (!alpha)
					continue;
				if (alpha >= 250 || painter.bitmap.depth == 1) {
					painter.plot(px, py, color, 13);
					continue;
				}
				if (!painter.visible(px, py))
					continue;
				const uint32_t below = painter.read(px, py);
				const auto mix = [&](uint32_t foreground, uint32_t background) { return (foreground * alpha + background * (255 - alpha) + 127) / 255; };
				painter.plot(px, py, mix(color_red(color), color_red(below)) | mix(color_green(color), color_green(below)) << 8 | mix(color_blue(color), color_blue(below)) << 16, 13);
			}
		const int32_t thickness = std::max(1, int32_t(std::lround(metrics.height / 16.0)));
		const auto line_across = [&](int32_t line_y) {
			for (int32_t t = 0; t < thickness; ++t)
				for (int32_t dx = 0; dx < advance; ++dx) {
					const int64_t px = device_x + dx, py = device_y + line_y + t;
					const int64_t logical_x = px - dc.origin_x, logical_y = py - dc.origin_y;
					if (logical_x < clip.left || logical_x >= clip.right || logical_y < clip.top || logical_y >= clip.bottom)
						continue;
					painter.plot(px, py, color, 13);
				}
		};
		if (underline)
			line_across(metrics.ascent + std::max(1, metrics.descent / 3));
		if (strike)
			line_across(metrics.ascent * 3 / 5);
		if (painter.changed() && dc.window && dc.leased && updated)
			updated(dc.window);
		return advance;
	};
	const auto extended_text_out = [=, this](ApiCall &call, bool ansi) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			selected_font(dc);
			const uint32_t options = call.u32(3);
			const int32_t count = call.i32(6);
			std::optional<DesktopRect> rect;
			if (call[4] && (options & 6))
				rect = DesktopRect{call.load<int32_t>(call[4]), call.load<int32_t>(call[4] + 4), call.load<int32_t>(call[4] + 8), call.load<int32_t>(call[4] + 12)};
			if ((options & 2) && !rect)
				throw uint32_t(87);
			if (count < 0)
				throw uint32_t(87);
			const auto text = count > 0 ? widen(call, call[5], count, ansi) : std::u16string();
			std::vector<int32_t> deltas;
			if (call[7] && count > 0) {
				const bool pair = (options & 0x2000) != 0;
				const auto bytes = call.read(call[7], size_t(count) * (pair ? 8 : 4));
				for (int32_t i = 0; i < count; ++i) {
					int32_t value;
					std::memcpy(&value, bytes.data() + size_t(i) * (pair ? 8 : 4), 4);
					deltas.push_back(value);
				}
			}
			int32_t x = call.i32(1), y = call.i32(2);
			if (dc.text_align & 1) {
				x = dc.position_x;
				y = dc.position_y;
			}
			const auto advance = draw_run(dc, x, y, options, rect ? &*rect : nullptr, text, deltas);
			if (dc.text_align & 1)
				dc.position_x = x + advance;
			call.ret(1);
		});
	};
	registry.add("ExtTextOutW", 8, [=](ApiCall &call) { extended_text_out(call, false); });
	registry.add("ExtTextOutA", 8, [=](ApiCall &call) { extended_text_out(call, true); });
	const auto text_out = [=, this](ApiCall &call, bool ansi) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			selected_font(dc);
			if (call.i32(4) < 0)
				throw uint32_t(87);
			const auto text = call.i32(4) > 0 ? widen(call, call[3], call.i32(4), ansi) : std::u16string();
			int32_t x = call.i32(1), y = call.i32(2);
			if (dc.text_align & 1) {
				x = dc.position_x;
				y = dc.position_y;
			}
			const auto advance = draw_run(dc, x, y, 0, nullptr, text, {});
			if (dc.text_align & 1)
				dc.position_x = x + advance;
			call.ret(1);
		});
	};
	registry.add("TextOutW", 5, [=](ApiCall &call) { text_out(call, false); });
	registry.add("TextOutA", 5, [=](ApiCall &call) { text_out(call, true); });

	// ---- measurements ----
	const auto extent = [=, this](ApiCall &call, bool ansi) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const auto text = widen(call, call[1], call.i32(2), ansi);
			if (text.empty()) {
				write_size(call, call[3], 0, 0);
				call.ret(1);
				return;
			}
			const auto cumulative = measured_advances(font.definition, to_units(text));
			write_size(call, call[3], cumulative.back(), objects.text().logical_metrics(font.definition).height);
			call.ret(1);
		});
	};
	for (const auto *name : {"GetTextExtentPoint32W", "GetTextExtentPointW"})
		registry.add(name, 4, [=](ApiCall &call) { extent(call, false); });
	for (const auto *name : {"GetTextExtentPoint32A", "GetTextExtentPointA"})
		registry.add(name, 4, [=](ApiCall &call) { extent(call, true); });
	const auto extent_ex = [=, this](ApiCall &call, bool ansi) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const auto text = widen(call, call[1], call.i32(2), ansi);
			const int32_t max_extent = call.i32(3);
			std::vector<int32_t> cumulative;
			if (!text.empty())
				cumulative = measured_advances(font.definition, to_units(text));
			int32_t fit = 0;
			if (call[4]) {
				fit = int32_t(cumulative.size());
				if (max_extent >= 0)
					for (size_t i = 0; i < cumulative.size(); ++i)
						if (cumulative[i] > max_extent) {
							fit = int32_t(i);
							break;
						}
				call.store<int32_t>(call[4], fit);
			}
			if (call[5])
				for (size_t i = 0; i < cumulative.size(); ++i)
					call.store<int32_t>(call[5] + i * 4, cumulative[i]);
			write_size(call, call[6], cumulative.empty() ? 0 : cumulative.back(), cumulative.empty() ? 0 : objects.text().logical_metrics(font.definition).height);
			call.ret(1);
		});
	};
	registry.add("GetTextExtentExPointW", 7, [=](ApiCall &call) { extent_ex(call, false); });
	registry.add("GetTextExtentExPointA", 7, [=](ApiCall &call) { extent_ex(call, true); });
	const auto text_metrics = [=, this](ApiCall &call, bool ansi) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const auto info = objects.text().logical_metrics(font.definition);
			std::vector<uint8_t> bytes(ansi ? 56 : 60, 0);
			const auto put32 = [&](size_t at, int32_t value) { std::memcpy(bytes.data() + at, &value, 4); };
			put32(0, info.height); put32(4, info.ascent); put32(8, info.descent); put32(12, info.internal_leading);
			put32(16, info.external_leading); put32(20, info.average_width); put32(24, info.maximum_width);
			uint32_t weight;
			std::memcpy(&weight, font.definition.data() + 16, 4);
			put32(28, int32_t(weight ? weight : 400));
			put32(36, 96); put32(40, 96);
			size_t at = 44;
			if (ansi) {
				bytes[at] = uint8_t(info.first); bytes[at + 1] = uint8_t(std::min<uint32_t>(info.last, 255)); bytes[at + 2] = uint8_t(info.default_character); bytes[at + 3] = uint8_t(info.break_character);
				at += 4;
			} else {
				const uint16_t chars[4] = {info.first, info.last, info.default_character, info.break_character};
				std::memcpy(bytes.data() + at, chars, 8);
				at += 8;
			}
			bytes[at] = font.definition[20];
			bytes[at + 1] = font.definition[21];
			bytes[at + 2] = font.definition[22];
			bytes[at + 3] = info.pitch;
			bytes[at + 4] = font.definition[23];
			call.write(call[1], bytes);
			call.ret(1);
		});
	};
	registry.add("GetTextMetricsW", 2, [=](ApiCall &call) { text_metrics(call, false); });
	registry.add("GetTextMetricsA", 2, [=](ApiCall &call) { text_metrics(call, true); });
	registry.add("GetCharWidthW", 4, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const uint32_t first = call.u32(1), last = call.u32(2);
			if (last < first || last - first > 65535)
				throw uint32_t(87);
			for (uint32_t c = first; c <= last; ++c) {
				const uint16_t unit = uint16_t(c);
				const auto advance = measured_advances(font.definition, std::span<const uint16_t>(&unit, 1));
				call.store<int32_t>(call[3] + uint64_t(c - first) * 4, advance.empty() ? 0 : advance[0]);
			}
			call.ret(1);
		});
	});
	registry.add("GetCharABCWidthsW", 4, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const uint32_t first = call.u32(1), last = call.u32(2);
			if (last < first || last - first > 65535)
				throw uint32_t(87);
			for (uint32_t c = first; c <= last; ++c) {
				const uint16_t unit = uint16_t(c);
				const auto advance = measured_advances(font.definition, std::span<const uint16_t>(&unit, 1));
				// ABC spacing: no side bearings, so the whole advance is the glyph body.
				const uint64_t at = call[3] + uint64_t(c - first) * 12;
				call.store<int32_t>(at, 0);
				call.store<uint32_t>(at + 4, uint32_t(advance.empty() ? 0 : advance[0]));
				call.store<int32_t>(at + 8, 0);
			}
			call.ret(1);
		});
	});
	registry.add("GetCharWidthInfo", 2, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			require_dc(call, 0);
			// CHAR_WIDTH_INFO: left bearing, right bearing, and the run width in device units.
			call.store<int32_t>(call[1], 0);
			call.store<int32_t>(call[1] + 4, 0);
			call.store<int32_t>(call[1] + 8, 0);
			call.ret(1);
		});
	});
	registry.add("GdiGetCharDimensions", 3, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			auto &dc = require_dc(call, 0);
			const auto &font = selected_font(dc);
			const auto info = objects.text().logical_metrics(font.definition);
			static const std::u16string alphabet = u"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
			const auto cumulative = measured_advances(font.definition, to_units(alphabet));
			if (call[1]) {
				std::vector<uint8_t> bytes(60, 0);
				const auto put32 = [&](size_t at, int32_t value) { std::memcpy(bytes.data() + at, &value, 4); };
				put32(0, info.height); put32(4, info.ascent); put32(8, info.descent); put32(20, info.average_width); put32(24, info.maximum_width);
				call.write(call[1], bytes);
			}
			if (call[2])
				call.store<int32_t>(call[2], info.height);
			call.ret(uint64_t((cumulative.back() / 26 + 1) / 2));
		});
	});

	// ---- fonts ----
	const auto add_font = [this](const std::array<uint8_t, 92> &definition) {
		DesktopFont font;
		font.definition = definition;
		const auto handle = objects.add(font);
		if (!handle)
			throw uint32_t(8);
		return handle;
	};
	registry.add("CreateFontIndirectW", 1, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			const auto bytes = call.read(call[0], 92);
			std::array<uint8_t, 92> definition{};
			std::copy(bytes.begin(), bytes.end(), definition.begin());
			call.ret(add_font(definition));
		});
	});
	registry.add("CreateFontIndirectA", 1, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			const auto bytes = call.read(call[0], 60);
			std::array<uint8_t, 92> definition{};
			std::copy(bytes.begin(), bytes.begin() + 28, definition.begin());
			std::string face;
			for (size_t i = 0; i < 32 && bytes[28 + i]; ++i)
				face.push_back(char(bytes[28 + i]));
			const auto wide = from_ansi(face, 1252);
			for (size_t i = 0; i < std::min<size_t>(wide.size(), 31); ++i) {
				definition[28 + i * 2] = uint8_t(wide[i]);
				definition[29 + i * 2] = uint8_t(wide[i] >> 8);
			}
			call.ret(add_font(definition));
		});
	});
	registry.add("CreateFontW", 14, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			std::array<uint8_t, 92> definition{};
			const auto put32 = [&](size_t at, int32_t value) { std::memcpy(definition.data() + at, &value, 4); };
			put32(0, call.i32(0)); put32(4, call.i32(1)); put32(8, call.i32(2)); put32(12, call.i32(3)); put32(16, call.i32(4));
			definition[20] = uint8_t(call.u32(5)); definition[21] = uint8_t(call.u32(6)); definition[22] = uint8_t(call.u32(7));
			definition[23] = uint8_t(call.u32(8)); definition[24] = uint8_t(call.u32(9)); definition[25] = uint8_t(call.u32(10));
			definition[26] = uint8_t(call.u32(11)); definition[27] = uint8_t(call.u32(12));
			if (call[13]) {
				const auto face = call.wide(call[13], 64);
				for (size_t i = 0; i < std::min<size_t>(face.size(), 31); ++i) {
					definition[28 + i * 2] = uint8_t(face[i]);
					definition[29 + i * 2] = uint8_t(face[i] >> 8);
				}
			}
			call.ret(add_font(definition));
		});
	});
	// The bundled families stand for the common Windows faces; callers see the usual names.
	registry.add("EnumFontFamiliesExW", 5, [=, this](ApiCall &call) {
		guarded(call, 0, [&] {
			require_dc(call, 0);
			static const char16_t *families[] = {u"Arial", u"Courier New", u"Times New Roman", u"MS Shell Dlg", u"MS Sans Serif", u"Tahoma",
				u"Segoe UI", u"Verdana", u"Lucida Console", u"Consolas"};
			std::u16string wanted;
			if (call[1]) {
				const auto bytes = call.read(call[1] + 28, 64);
				for (size_t i = 0; i < 32; ++i) {
					const char16_t c = char16_t(bytes[i * 2] | (bytes[i * 2 + 1] << 8));
					if (!c)
						break;
					wanted.push_back(c);
				}
			}
			if (!call[2]) {
				call.ret(0);
				return;
			}
			const auto lower = [](std::u16string text) {
				for (auto &c : text)
					if (c >= 'A' && c <= 'Z')
						c = char16_t(c + 32);
				return text;
			};
			uint64_t result = 1;
			const auto scratch_size = uint64_t(4096);
			const auto scratch = process.map_memory(scratch_size, PROT_READ | PROT_WRITE);
			try {
				for (const auto *family : families) {
					if (!wanted.empty() && lower(family) != lower(wanted))
						continue;
					// ENUMLOGFONTEXW (LOGFONTW, full name, style, script) followed by NEWTEXTMETRICEXW.
					std::vector<uint8_t> record(512, 0);
					int32_t height = -12;
					std::memcpy(record.data(), &height, 4);
					const int32_t weight = 400;
					std::memcpy(record.data() + 16, &weight, 4);
					record[23] = 0;
					record[27] = std::u16string_view(family) == u"Courier New" || std::u16string_view(family) == u"Lucida Console" || std::u16string_view(family) == u"Consolas" ? 0x31 : 0x22;
					for (size_t i = 0; i < std::char_traits<char16_t>::length(family) && i < 31; ++i) {
						record[28 + i * 2] = uint8_t(family[i]);
						record[29 + i * 2] = uint8_t(family[i] >> 8);
						record[92 + i * 2] = uint8_t(family[i]);
						record[93 + i * 2] = uint8_t(family[i] >> 8);
					}
					const char16_t style[] = u"Regular", script[] = u"Western";
					for (size_t i = 0; i < 7; ++i) {
						record[92 + 128 + i * 2] = uint8_t(style[i]);
						record[92 + 192 + i * 2] = uint8_t(script[i]);
					}
					call.write(scratch, record);
					const uint64_t arguments[] = {scratch, scratch + 348, 4, call[3]};
					const auto outcome = invoke(call[2], arguments);
					if (outcome.stop != NativeStop::returned)
						throw outcome;
					result = outcome.value;
					if (!uint32_t(outcome.value))
						break;
				}
			} catch (...) {
				process.unmap_memory(scratch);
				throw;
			}
			process.unmap_memory(scratch);
			call.ret(uint32_t(result));
		});
	});
	// Complex-script shaping is not provided; callers fall back to plain GDI text.
	for (const auto *name : {"ScriptBreak", "ScriptStringAnalyse", "ScriptStringCPtoX", "ScriptStringFree", "ScriptStringGetLogicalWidths",
			"ScriptStringOut", "ScriptStringXtoCP", "ScriptString_pSize", "ScriptString_pcOutChars"})
		registry.add(name, 8, [](ApiCall &call) { call.ret(0x80004001); });
}

}

#else

namespace raven {

void NativeDesktop::register_text_api(ApiRegistry &)
{
}

}

#endif
