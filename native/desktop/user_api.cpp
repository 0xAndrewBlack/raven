#include "windows.h"
#include "nt/text.h"

#include <algorithm>
#include <cstdio>
#include <cwctype>

namespace raven {

namespace {

struct Rect {
	int32_t left, top, right, bottom;
	bool empty() const { return right <= left || bottom <= top; }
};

Rect read_rect(ApiCall &call, uint64_t address)
{
	const auto bytes = call.read(address, 16);
	Rect rect;
	std::memcpy(&rect, bytes.data(), 16);
	return rect;
}

void write_rect(ApiCall &call, uint64_t address, const Rect &rect)
{
	call.write(address, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&rect), 16));
}

}

void NativeWindows::register_api(ApiRegistry &registry)
{
	register_message_api(registry);
	register_manager_api(registry);
	register_menu_api(registry);
	register_ext_api(registry);
	register_scroll_api(registry);
	register_long_api(registry);
	register_ansi_api(registry);

	// Rectangle helpers are pure arithmetic on guest RECTs.
	registry.add("InflateRect", 3, [](ApiCall &call) {
		auto rect = read_rect(call, call[0]);
		rect.left -= call.i32(1);
		rect.right += call.i32(1);
		rect.top -= call.i32(2);
		rect.bottom += call.i32(2);
		write_rect(call, call[0], rect);
		call.ret(1);
	});
	registry.add("OffsetRect", 3, [](ApiCall &call) {
		auto rect = read_rect(call, call[0]);
		rect.left += call.i32(1);
		rect.right += call.i32(1);
		rect.top += call.i32(2);
		rect.bottom += call.i32(2);
		write_rect(call, call[0], rect);
		call.ret(1);
	});
	registry.add("SetRectEmpty", 1, [](ApiCall &call) {
		write_rect(call, call[0], {0, 0, 0, 0});
		call.ret(1);
	});
	registry.add("CopyRect", 2, [](ApiCall &call) {
		write_rect(call, call[0], read_rect(call, call[1]));
		call.ret(1);
	});
	registry.add("EqualRect", 2, [](ApiCall &call) {
		const auto a = read_rect(call, call[0]), b = read_rect(call, call[1]);
		call.ret(a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom);
	});
	registry.add("IsRectEmpty", 1, [](ApiCall &call) { call.ret(read_rect(call, call[0]).empty()); });
	registry.add("IntersectRect", 3, [](ApiCall &call) {
		const auto a = read_rect(call, call[1]), b = read_rect(call, call[2]);
		Rect result{std::max(a.left, b.left), std::max(a.top, b.top), std::min(a.right, b.right), std::min(a.bottom, b.bottom)};
		const bool empty = a.empty() || b.empty() || result.empty();
		write_rect(call, call[0], empty ? Rect{0, 0, 0, 0} : result);
		call.ret(!empty);
	});
	registry.add("UnionRect", 3, [](ApiCall &call) {
		const auto a = read_rect(call, call[1]), b = read_rect(call, call[2]);
		Rect result;
		if (a.empty() && b.empty()) result = {0, 0, 0, 0};
		else if (a.empty()) result = b;
		else if (b.empty()) result = a;
		else result = {std::min(a.left, b.left), std::min(a.top, b.top), std::max(a.right, b.right), std::max(a.bottom, b.bottom)};
		write_rect(call, call[0], result);
		call.ret(!(a.empty() && b.empty()));
	});

	// Character classification follows the invariant (en-US) rules of the Windows ANSI/Unicode helpers.
	registry.add("CharUpperW", 1, [](ApiCall &call) {
		if (call[0] <= 0xffff) {
			call.ret(upper_case(char16_t(call[0])));
			return;
		}
		auto text = call.wide(call[0]);
		for (auto &character : text) character = upper_case(character);
		call.put_wide(call[0], text, text.size() + 1);
		call.ret(call[0]);
	});
	registry.add("CharLowerW", 1, [](ApiCall &call) {
		if (call[0] <= 0xffff) {
			call.ret(fold_case(char16_t(call[0])));
			return;
		}
		auto text = call.wide(call[0]);
		for (auto &character : text) character = fold_case(character);
		call.put_wide(call[0], text, text.size() + 1);
		call.ret(call[0]);
	});
	registry.add("IsCharAlphaW", 1, [](ApiCall &call) { call.ret(std::iswalpha(wint_t(call.u32(0) & 0xffff)) != 0); });
	registry.add("IsCharAlphaNumericW", 1, [](ApiCall &call) { call.ret(std::iswalnum(wint_t(call.u32(0) & 0xffff)) != 0); });
	registry.add("IsCharLowerW", 1, [](ApiCall &call) { call.ret(std::iswlower(wint_t(call.u32(0) & 0xffff)) != 0); });
	registry.add("IsCharUpperW", 1, [](ApiCall &call) { call.ret(std::iswupper(wint_t(call.u32(0) & 0xffff)) != 0); });
	registry.add("MessageBeep", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("LockWindowUpdate", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("NotifyWinEvent", 4, [](ApiCall &) {});
	registry.add("FlashWindowEx", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("GetDoubleClickTime", 0, [](ApiCall &call) { call.ret(500); });
	registry.add("GetCaretBlinkTime", 0, [](ApiCall &call) { call.ret(530); });
	registry.add("GetKeyboardLayout", 1, [](ApiCall &call) { call.ret(0x04090409); });
	registry.add("GetMessageExtraInfo", 0, [](ApiCall &call) { call.ret(0); });
	// The one keyboard layout, US English, by its KLID.
	registry.add("GetKeyboardLayoutNameW", 1, [](ApiCall &call) {
		call.put_wide(call[0], u"00000409", 9);
		call.ret(1);
	});
	registry.add("GetKeyboardLayoutNameA", 1, [](ApiCall &call) {
		call.put_narrow(call[0], "00000409", 9);
		call.ret(1);
	});
	// No accessibility server runs, so there are no standard accessible objects to hand out.
	registry.add("CreateStdAccessibleObject", 4, [](ApiCall &call) {
		if (call[3])
			call.store_pointer(call[3], 0);
		call.ret(0x80004001U);
	});
	// When the user last gave input, in GetTickCount's clock; the session counts as just used.
	registry.add("GetLastInputInfo", 1, [&registry](ApiCall &call) {
		if (!call[0] || call.load<uint32_t>(call[0]) != 8) {
			call.fail(87);
			return;
		}
		uint64_t now = 0;
		if (const auto ticks = registry.find("GetTickCount")) {
			ApiCall inner(call.process, call.environment, {});
			ticks->second(inner);
			now = inner.result;
		}
		call.store<uint32_t>(call[0] + 4, uint32_t(now));
		call.ret(1);
	});
	registry.add("GetMessageTime", 0, [](ApiCall &call) {
		call.ret(uint32_t(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()));
	});
	// The handles a process holds in the window system: windows, device contexts and drawing objects are one table here.
	registry.add("GetGuiResources", 2, [this](ApiCall &call) {
		const auto flags = call.u32(1);
		if (flags > 4 || flags == 3) {
			call.fail(87);
			return;
		}
		call.ret(std::max<size_t>(1, objects.count()));
	});
	registry.add("GetCursorPos", 1, [this](ApiCall &call) {
		call.store<int32_t>(call[0], cursor_x);
		call.store<int32_t>(call[0] + 4, cursor_y);
		call.ret(1);
	});
	// Raw input: the mouse (usage page 1, usage 2) is the device that reports; RIDEV_REMOVE ends the registration and
	// RIDEV_NOLEGACY leaves out the ordinary mouse messages. Keyboards keep their ordinary messages.
	registry.add("RegisterRawInputDevices", 3, [this](ApiCall &call) {
		const size_t width = call.pointer_width(), size = width == 4 ? 12 : 16;
		if (!call[0] || !call.u32(1) || call.u32(2) != size) {
			call.fail(87);
			return;
		}
		for (uint32_t index = 0; index < call.u32(1); ++index) {
			const uint64_t entry = call[0] + index * size;
			const uint16_t page = call.load<uint16_t>(entry), usage = call.load<uint16_t>(entry + 2);
			const uint32_t flags = call.load<uint32_t>(entry + 4);
			const uint64_t target = call.load_pointer(entry + 8);
			if (target && !objects.window(target)) {
				call.fail(1400);
				return;
			}
			if (page != 1 || usage != 2)
				continue;
			if (flags & 1) {
				raw_mouse = {false, false, raw_mouse.relative};
				continue;
			}
			raw_mouse.registered = true;
			raw_mouse.no_legacy = (flags & 0x30) == 0x30;
			raw_mouse.target = target;
		}
		call.ret(1);
	});
	// RAWINPUT: the header (type, size, device, wParam) and RAWMOUSE (flags, button flags and data, raw buttons, last X and Y, extra).
	registry.add("GetRawInputData", 5, [this](ApiCall &call) {
		const size_t width = call.pointer_width(), header = width == 4 ? 16 : 24, total = header + 24;
		const uint32_t command = call.u32(1);
		const auto found = raw_reports.find(call[0]);
		if ((command != 0x10000003U && command != 0x10000005U) || call.u32(4) != header || !call[3] || found == raw_reports.end()) {
			call.fail(found == raw_reports.end() ? 6 : 87, UINT32_MAX);
			return;
		}
		const size_t size = command == 0x10000005U ? header : total;
		if (!call[2]) {
			call.store<uint32_t>(call[3], uint32_t(size));
			call.ret(0);
			return;
		}
		if (call.load<uint32_t>(call[3]) < size) {
			call.store<uint32_t>(call[3], uint32_t(size));
			call.fail(122, UINT32_MAX);
			return;
		}
		std::vector<uint8_t> bytes(size);
		const auto put = [&](size_t at, uint64_t value, size_t length) { std::memcpy(bytes.data() + at, &value, length); };
		const auto &report = found->second;
		put(0, 0, 4);
		put(4, total, 4);
		put(8, 1, width);
		if (size == total) {
			put(header, 0, 2);
			put(header + 4, uint16_t(report[2]), 2);
			put(header + 6, uint16_t(int16_t(report[3])), 2);
			put(header + 12, uint32_t(report[0]), 4);
			put(header + 16, uint32_t(report[1]), 4);
		}
		call.write(call[2], bytes);
		call.ret(size);
	});
	registry.add("SetCursorPos", 2, [this](ApiCall &call) {
		cursor_x = call.i32(0);
		cursor_y = call.i32(1);
		update_warp_lock(true);
		call.ret(1);
	});
	registry.add("ShowCursor", 1, [this](ApiCall &call) {
		cursor_count += call.u32(0) ? 1 : -1;
		update_warp_lock(false);
		call.ret(uint32_t(cursor_count));
	});
	registry.add("SetCursor", 1, [this](ApiCall &call) {
		const auto previous = current_cursor;
		current_cursor = call[0];
		update_warp_lock(false);
		call.ret(previous);
	});
	registry.add("DestroyCursor", 1, [](ApiCall &call) { call.ret(1); });
	// Message boxes need the dialog manager; until it exists the text is reported and the first button is chosen.
	const auto message_box = [](ApiCall &call, bool wide) {
		const auto text = wide ? call.wide(call[1], 8192) : from_utf8(call.narrow(call[1], 8192));
		const auto caption = call[2] ? (wide ? call.wide(call[2], 512) : from_utf8(call.narrow(call[2], 512))) : std::u16string(u"Error");
		std::fprintf(stderr, "raven: MessageBox \"%s\": %s\n", to_utf8(caption).c_str(), to_utf8(text).c_str());
		const uint32_t type = call.u32(3) & 0xf;
		// MB_OK/OKCANCEL answer IDOK, ABORTRETRYIGNORE IDABORT, YESNOCANCEL/YESNO IDYES, RETRYCANCEL IDRETRY, CANCELTRYCONTINUE IDCANCEL.
		static constexpr uint32_t answers[] = {1, 1, 3, 6, 6, 4, 2, 0};
		call.ret(type < 7 ? answers[type] : 1);
	};
	registry.add("MessageBoxW", 4, [message_box](ApiCall &call) { message_box(call, true); });
	registry.add("MessageBoxA", 4, [message_box](ApiCall &call) { message_box(call, false); });
	registry.add("GetCapture", 0, [this](ApiCall &call) { call.ret(capture && objects.window(capture) ? capture : 0); });
}

void NativeWindows::register_message_api(ApiRegistry &registry)
{
	registry.add("RegisterWindowMessageA", 1, [this](ApiCall &call) {
		const auto narrow = call.narrow(call[0], 255);
		const std::u16string name(narrow.begin(), narrow.end());
		if (name.empty()) {
			call.fail(87);
			return;
		}
		auto found = registered_messages.find(name);
		if (found == registered_messages.end()) {
			if (registered_messages.size() >= 0x3fff) {
				call.fail(8);
				return;
			}
			found = registered_messages.emplace(name, uint32_t(0xc000 + registered_messages.size())).first;
		}
		call.ret(found->second);
	});
	registry.add("RegisterWindowMessageW", 1, [this](ApiCall &call) {
		const auto name = call.wide(call[0], 255);
		if (name.empty()) {
			call.fail(87);
			return;
		}
		// Window message names compare case-sensitively, unlike class names.
		auto found = registered_messages.find(name);
		if (found == registered_messages.end()) {
			if (registered_messages.size() >= 0x3fff) {
				call.fail(8);
				return;
			}
			found = registered_messages.emplace(name, uint32_t(0xc000 + registered_messages.size())).first;
		}
		call.ret(found->second);
	});
}

}
