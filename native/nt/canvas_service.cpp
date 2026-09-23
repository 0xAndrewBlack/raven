#include "kernel_context.h"

#ifdef RAVEN_SKIA
#include "graphics/canvas.h"
#endif

#include <cstring>

namespace raven {

#ifdef RAVEN_SKIA

// The host side of the Direct2D component: surfaces live here and are drawn into with Skia; the guest holds their numbers, sends one
// command record per drawing operation and moves pixels only when a program reads or presents them.
void register_canvas_service(ApiRegistry &registry, KernelContext &)
{
	registry.add("RavenCanvasCreate", 2, [](ApiCall &call) { call.ret(canvas::create(call.u32(0), call.u32(1))); });
	registry.add("RavenCanvasDestroy", 1, [](ApiCall &call) { canvas::destroy(call.u32(0)); });
	// RavenCanvasSize(surface, size): the width and height as two words; zero when there is no such surface.
	registry.add("RavenCanvasSize", 2, [](ApiCall &call) {
		uint32_t width = 0, height = 0;
		const bool found = canvas::size(call.u32(0), width, height);
		if (found && call[1]) {
			call.store<uint32_t>(call[1], width);
			call.store<uint32_t>(call[1] + 4, height);
		}
		call.ret(found);
	});
	// RavenCanvasPixels(surface, x, y, width, height, buffer, pitch, write).
	registry.add("RavenCanvasPixels", 8, [](ApiCall &call) {
		const uint32_t width = call.u32(3), height = call.u32(4), pitch = call.u32(6);
		if (!width || !height || !call[5] || pitch < width * 4 || uint64_t(pitch) * height > (512ull << 20)) {
			call.ret(0);
			return;
		}
		const size_t bytes = size_t(pitch) * (height - 1) + size_t(width) * 4;
		std::vector<uint8_t> buffer(size_t(pitch) * height);
		const bool write = call.u32(7) != 0;
		if (write) {
			const auto source = call.read(call[5], bytes);
			std::memcpy(buffer.data(), source.data(), bytes);
		}
		if (!canvas::pixels(call.u32(0), call.i32(1), call.i32(2), width, height, buffer.data(), pitch, write)) {
			call.ret(0);
			return;
		}
		if (!write)
			call.write(call[5], std::span<const uint8_t>(buffer.data(), bytes));
		call.ret(1);
	});
	// RavenPathCombine(one, one floats, two, two floats, fills, mode, result, capacity): two paths in the command's float form combined;
	// the fill modes are bits 0 and 1 of `fills`, the result's fill mode comes back in bit 31 of the answer, which is the float count, or
	// 0x7fffffff when the paths cannot be combined. A result larger than the capacity is counted and not written.
	registry.add("RavenPathCombine", 8, [](ApiCall &call) {
		const auto floats = [&](uint64_t address, uint32_t count) {
			std::vector<float> values(count);
			if (count) {
				const auto bytes = call.read(address, size_t(count) * 4);
				std::memcpy(values.data(), bytes.data(), bytes.size());
			}
			return values;
		};
		if (call.u32(1) > (16u << 20) || call.u32(3) > (16u << 20)) {
			call.ret(0x7fffffff);
			return;
		}
		const auto one = floats(call[0], call.u32(1)), two = floats(call[2], call.u32(3));
		std::vector<float> result;
		uint32_t fill = 0;
		if (!canvas::combine(one, call.u32(4) & 1, two, (call.u32(4) >> 1) & 1, call.u32(5), result, fill) || result.size() >= 0x7fffffff) {
			call.ret(0x7fffffff);
			return;
		}
		if (call[6] && result.size() <= call.u32(7) && !result.empty())
			call.write(call[6], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(result.data()), result.size() * 4));
		call.ret(uint32_t(result.size()) | (fill << 31));
	});
	// RavenPathWiden(path, floats, fill, stroke, stroke floats, result, capacity): the area a stroke covers, answered as RavenPathCombine
	// answers.
	registry.add("RavenPathWiden", 7, [](ApiCall &call) {
		const auto floats = [&](uint64_t address, uint32_t count) {
			std::vector<float> values(count);
			if (count) {
				const auto bytes = call.read(address, size_t(count) * 4);
				std::memcpy(values.data(), bytes.data(), bytes.size());
			}
			return values;
		};
		if (call.u32(1) > (16u << 20) || call.u32(4) > 128) {
			call.ret(0x7fffffff);
			return;
		}
		const auto path = floats(call[0], call.u32(1)), stroke = floats(call[3], call.u32(4));
		std::vector<float> result;
		uint32_t fill = 0;
		if (!canvas::widen(path, call.u32(2), stroke, result, fill) || result.size() >= 0x7fffffff) {
			call.ret(0x7fffffff);
			return;
		}
		if (call[5] && result.size() <= call.u32(6) && !result.empty())
			call.write(call[5], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(result.data()), result.size() * 4));
		call.ret(uint32_t(result.size()) | (fill << 31));
	});
	// RavenCanvasDraw(surface, command, data, size): one command record and the variable parts after it.
	registry.add("RavenCanvasDraw", 4, [](ApiCall &call) {
		if (!call[1] || call.u32(3) > (300u << 20)) {
			call.ret(0);
			return;
		}
		canvas::Command command;
		const auto record = call.read(call[1], sizeof command);
		std::memcpy(&command, record.data(), sizeof command);
		const auto data = call.u32(3) ? call.read(call[2], call.u32(3)) : std::vector<uint8_t>();
		call.ret(canvas::draw(call.u32(0), command, data));
	});
}

#else

void register_canvas_service(ApiRegistry &, KernelContext &)
{
}

#endif

}
