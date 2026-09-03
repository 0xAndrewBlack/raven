#include "windows.h"
#include "nonclient.h"

#include <algorithm>
#include <cstring>

namespace raven {

namespace {

constexpr uint32_t ws_visible = 0x10000000U;

uint64_t extra_access(std::vector<uint8_t> &bytes, int32_t index, size_t width, bool write, uint64_t value)
{
	if (index < 0 || size_t(index) > bytes.size() || width > bytes.size() - size_t(index))
		throw uint32_t(1413);
	uint64_t previous = 0;
	std::memcpy(&previous, bytes.data() + index, width);
	if (write)
		std::memcpy(bytes.data() + index, &value, width);
	return previous;
}

}

// Window and class data access: every documented index, for both widths and both character sets.
void NativeWindows::register_long_api(ApiRegistry &registry)
{
	const auto window_long = [this](ApiCall &call, bool write, bool wide) {
		auto *window = objects.window(call[0]);
		if (!window) {
			call.fail(1400);
			return;
		}
		const int32_t index = call.i32(1);
		const uint64_t value = write ? (wide ? call[2] : uint64_t(uint32_t(call[2]))) : 0;
		const auto narrow = [&](uint64_t result) { return wide ? result : uint64_t(uint32_t(result)); };
		try {
			if (index >= 0) {
				call.ret(narrow(extra_access(window->extra, index, wide ? 8 : 4, write, value)));
				return;
			}
			// Pointer-sized values have no 32-bit accessor on a 64-bit system; on a 32-bit one they are 32 bits wide.
			if (!wide && process.mode() != NativeMode::x86 && (index == -4 || index == -6 || index == -8)) {
				call.fail(1413);
				return;
			}
			switch (index) {
			case -21: {
				const auto previous = window->userdata;
				if (write)
					window->userdata = wide ? value : uint64_t(int64_t(int32_t(uint32_t(value))));
				call.ret(narrow(previous));
				return;
			}
			case -4: {
				const auto previous = window->procedure;
				if (write) {
					if (!value) {
						call.fail(87);
						return;
					}
					window->procedure = value;
				}
				call.ret(narrow(previous));
				return;
			}
			case -6: {
				const auto previous = window->instance;
				if (write)
					window->instance = value;
				call.ret(narrow(previous));
				return;
			}
			case -12: {
				const auto previous = window->child_id;
				if (write)
					window->child_id = value;
				call.ret(narrow(previous));
				return;
			}
			case -8: {
				const auto previous = window->parent ? window->parent : window->owner;
				if (write) {
					if (window->parent) {
						const uint64_t arguments[] = {call[0], value};
						(void)arguments;
						window->parent = value;
					} else {
						window->owner = value;
					}
				}
				call.ret(narrow(previous));
				return;
			}
			case -16:
			case -20: {
				const bool style = index == -16;
				// The index travels in the message as a signed word of the program's own width.
				const uint64_t index_word = process.mode() == NativeMode::x86 ? uint64_t(uint32_t(index)) : uint64_t(int64_t(index));
				const uint32_t previous = style ? window->style : window->ex_style;
				if (write) {
					uint32_t next = uint32_t(value);
					// The window may adjust the change before it applies.
					const auto scratch = scratch_allocate(8);
					std::vector<uint8_t> bytes(8);
					std::memcpy(bytes.data(), &previous, 4);
					std::memcpy(bytes.data() + 4, &next, 4);
					process.write_memory(scratch, bytes);
					send(call[0], 0x7c, index_word, scratch);
					if (!objects.window(call[0]))
						return;
					const auto changed = process.read_memory(scratch, 8);
					std::memcpy(&next, changed.data() + 4, 4);
					window = objects.window(call[0]);
					if (style) {
						window->style = next;
						const bool visible = (next & ws_visible) != 0;
						if (visible != window->visible)
							window->visible = visible;
					} else {
						window->ex_style = next;
					}
					std::memcpy(bytes.data() + 4, &next, 4);
					process.write_memory(scratch, bytes);
					send(call[0], 0x7d, index_word, scratch);
					if (objects.window(call[0]) && objects.window_visible(call[0])) {
						invalidate_tree(call[0], true);
						drawing(call[0]);
					}
				}
				call.ret(previous);
				return;
			}
			default:
				call.fail(1413);
			}
		} catch (const uint32_t &error) {
			call.fail(error);
		}
	};
	for (const auto *name : {"GetWindowLongW", "GetWindowLongA"})
		registry.add(name, 2, [=](ApiCall &call) { window_long(call, false, false); });
	for (const auto *name : {"GetWindowLongPtrW", "GetWindowLongPtrA"})
		registry.add(name, 2, [=](ApiCall &call) { window_long(call, false, true); });
	for (const auto *name : {"SetWindowLongW", "SetWindowLongA"})
		registry.add(name, 3, [=](ApiCall &call) { window_long(call, true, false); });
	for (const auto *name : {"SetWindowLongPtrW", "SetWindowLongPtrA"})
		registry.add(name, 3, [=](ApiCall &call) { window_long(call, true, true); });

	const auto class_long = [this](ApiCall &call, bool write, bool wide) {
		const auto *window = objects.window(call[0]);
		if (!window) {
			call.fail(1400);
			return;
		}
		auto *definition = objects.window_class(window->class_id);
		const int32_t index = call.i32(1);
		const uint64_t value = write ? (wide ? call[2] : uint64_t(uint32_t(call[2]))) : 0;
		const auto narrow = [&](uint64_t result) { return wide ? result : uint64_t(uint32_t(result)); };
		try {
			if (index >= 0) {
				call.ret(narrow(extra_access(definition->extra, index, wide ? 8 : 4, write, value)));
				return;
			}
			const auto exchange = [&](uint64_t &field) {
				const auto previous = field;
				if (write)
					field = value;
				call.ret(narrow(previous));
			};
			switch (index) {
			case -32: call.ret(definition->atom); return;
			case -26: {
				uint64_t style = definition->style;
				const auto previous = style;
				if (write)
					definition->style = uint32_t(value);
				call.ret(narrow(previous));
				return;
			}
			case -20: call.ret(definition->extra.size()); return;
			case -18: {
				const auto previous = definition->window_extra;
				if (write)
					definition->window_extra = uint32_t(value);
				call.ret(previous);
				return;
			}
			case -16: exchange(definition->instance); return;
			case -24: exchange(definition->procedure); return;
			case -10: exchange(definition->background); return;
			case -12: exchange(definition->cursor); return;
			case -14: exchange(definition->icon); return;
			case -34: {
				uint64_t small = 0;
				exchange(small);
				return;
			}
			case -8: call.ret(0); return;
			default: call.fail(1413);
			}
		} catch (const uint32_t &error) {
			call.fail(error);
		}
	};
	for (const auto *name : {"GetClassLongW", "GetClassLongA"})
		registry.add(name, 2, [=](ApiCall &call) { class_long(call, false, false); });
	for (const auto *name : {"GetClassLongPtrW", "GetClassLongPtrA"})
		registry.add(name, 2, [=](ApiCall &call) { class_long(call, false, true); });
	for (const auto *name : {"SetClassLongW", "SetClassLongA"})
		registry.add(name, 3, [=](ApiCall &call) { class_long(call, true, false); });
	for (const auto *name : {"SetClassLongPtrW", "SetClassLongPtrA"})
		registry.add(name, 3, [=](ApiCall &call) { class_long(call, true, true); });
	registry.add("CallWindowProcW", 5, [this](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		const uint64_t arguments[] = {call[1], call[2], call[3], call[4]};
		const auto result = invoke(call[0], arguments);
		if (result.stop != NativeStop::returned)
			throw result;
		call.ret(result.value);
	});

	// System metrics: the classic desktop values; the frame values come from the nonclient metrics in use.
	// The frame a style adds around a client rectangle, at a given DPI: the frame of 96 DPI scaled by the ratio.
	registry.add("AdjustWindowRectExForDpi", 5, [this](ApiCall &call) {
		const uint32_t dpi = call.u32(4);
		if (!call[0] || !dpi) {
			call.fail(87);
			return;
		}
		const auto bytes = call.read(call[0], 16);
		int32_t value[4];
		std::memcpy(value, bytes.data(), 16);
		const auto frame = adjust_window_rect(objects.nonclient_metrics(), {0, 0, 0, 0}, call.u32(1), call.u32(2) != 0, call.u32(3));
		const auto scale = [dpi](int32_t extent) { return int32_t((int64_t(extent) * dpi + (extent < 0 ? -48 : 48)) / 96); };
		const int32_t adjusted[4] = {value[0] + scale(frame.left), value[1] + scale(frame.top), value[2] + scale(frame.right), value[3] + scale(frame.bottom)};
		call.write(call[0], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(adjusted), 16));
		call.ret(1);
	});
	// The cursor is never confined here: the clip rectangle is the whole screen, and a confinement request is accepted as one.
	registry.add("GetClipCursor", 1, [this](ApiCall &call) {
		if (!call[0]) {
			call.fail(87);
			return;
		}
		const auto &screen = objects.nonclient_metrics();
		const int32_t rect[4] = {0, 0, int32_t(screen.screen_x), int32_t(screen.screen_y)};
		call.write(call[0], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(rect), sizeof(rect)));
		call.ret(1);
	});
	registry.add("ClipCursor", 1, [](ApiCall &call) { call.ret(1); });
	// Touch input reaches windows as mouse input here; registering for it changes nothing and succeeds.
	registry.add("RegisterTouchWindow", 2, [this](ApiCall &call) {
		if (!objects.window(call[0])) {
			call.fail(1400);
			return;
		}
		call.ret(1);
	});
	registry.add("UnregisterTouchWindow", 1, [this](ApiCall &call) {
		if (!objects.window(call[0])) {
			call.fail(1400);
			return;
		}
		call.ret(1);
	});
	registry.add("GetSystemMetrics", 1, [this](ApiCall &call) {
		const auto &screen = objects.nonclient_metrics();
		const int32_t index = call.i32(0);
		switch (index) {
		case 0: call.ret(uint32_t(screen.screen_x)); return;
		case 1: call.ret(uint32_t(screen.screen_y)); return;
		case 2: case 3: case 9: case 10: case 20: case 21: call.ret(17); return;
		case 4: call.ret(uint32_t(screen.caption)); return;
		case 5: case 6: call.ret(uint32_t(screen.border_x)); return;
		case 7: call.ret(uint32_t(screen.dialog_x)); return;
		case 8: call.ret(uint32_t(screen.dialog_y)); return;
		case 11: case 12: case 13: case 14: call.ret(32); return;
		case 15: call.ret(uint32_t(screen.menu)); return;
		case 16: call.ret(uint32_t(screen.screen_x)); return;
		case 17: call.ret(uint32_t(screen.screen_y - screen.caption)); return;
		case 19: call.ret(1); return;
		case 22: case 23: case 41: case 44: case 63: case 67: case 70: case 73: case 74: case 82: case 86: case 87: case 88: case 89: call.ret(0); return;
		case 28: call.ret(136); return;
		case 29: call.ret(39); return;
		case 30: call.ret(uint32_t(screen.button_x)); return;
		case 31: call.ret(uint32_t(screen.button_y)); return;
		case 32: call.ret(uint32_t(screen.frame_x)); return;
		case 33: call.ret(uint32_t(screen.frame_y)); return;
		case 34: call.ret(136); return;
		case 35: call.ret(39); return;
		case 36: case 37: case 68: case 69: call.ret(4); return;
		case 38: case 39: call.ret(75); return;
		case 40: call.ret(0); return;
		case 42: call.ret(0); return;
		case 43: call.ret(3); return;
		case 45: case 46: call.ret(2); return;
		case 47: case 48: call.ret(160); return;
		case 49: case 50: call.ret(16); return;
		case 51: call.ret(uint32_t(screen.small_caption)); return;
		case 52: call.ret(uint32_t(screen.small_button_x)); return;
		case 53: call.ret(uint32_t(screen.small_button_y)); return;
		case 54: call.ret(uint32_t(screen.small_button_x)); return;
		case 55: call.ret(uint32_t(screen.menu)); return;
		case 56: call.ret(8); return;
		case 57: call.ret(160); return;
		case 58: call.ret(24); return;
		case 59: case 61: call.ret(uint32_t(screen.screen_x + 8)); return;
		case 60: case 62: call.ret(uint32_t(screen.screen_y + 8)); return;
		case 71: case 72: call.ret(15); return;
		case 75: case 91: call.ret(1); return;
		case 76: case 77: call.ret(0); return;
		case 78: call.ret(uint32_t(screen.screen_x)); return;
		case 79: call.ret(uint32_t(screen.screen_y)); return;
		case 80: case 81: call.ret(1); return;
		case 83: case 84: call.ret(1); return;
		case 92: call.ret(0); return;
		case 97: call.ret(0); return;
		case 0x1000: case 0x2000: case 0x2001: call.ret(0); return;
		default: call.ret(0); return;
		}
	});
}

}
