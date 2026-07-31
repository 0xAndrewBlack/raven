#include "api.h"

#include <new>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

// Legacy LoadIcon/LoadCursor/LoadAccelerators entry points over the module resource tables.
bool NativeDesktop::load_dispatch(std::string_view name)
{
	if (name == "LoadCursorW") {
		const auto args = process.api_arguments(2);
		uint64_t result = 0;
		// Only the system cursors exist so far; module cursor resources are reported as unsupported.
		if (!args[0] && args[1] >= 32512 && args[1] < 32512 + desktop_stock_cursor_count)
			result = desktop_stock_cursor + (args[1] - 32512);
		else
			environment.set_last_error(args[0] ? 120 : 1813);
		process.return_api(result);
		return true;
	}
	if (name == "LoadAcceleratorsW") {
		const auto args = process.api_arguments(2);
		uint64_t result = 0;
		try {
			const auto view = resources.view(args[0], 9, args[1]);
			if (view) {
				if (view->size < 8 || view->size > 8192)
					throw uint32_t(13);
				const auto bytes = process.read_memory(view->address, view->size);
				std::vector<DesktopAccelerator> table;
				// ACCELTABLEENTRY: flags word, key word, command word, padding word; bit 0x80 ends the table.
				for (size_t at = 0; at + 8 <= bytes.size(); at += 8) {
					table.push_back({uint8_t(bytes[at] & 0x7f), uint16_t(bytes[at + 2] | bytes[at + 3] << 8), uint16_t(bytes[at + 4] | bytes[at + 5] << 8)});
					if (bytes[at] & 0x80)
						break;
				}
				result = objects.add_accelerators(std::move(table));
				if (!result)
					throw uint32_t(8);
			}
		} catch (uint32_t error) { environment.set_last_error(error); }
		process.return_api(result);
		return true;
	}
	if (name != "LoadIconW")
		return false;
	const auto args = process.api_arguments(2);
	uint64_t result = 0;
	try {
		if (!args[0])
			throw uint32_t(120);
		if (!scratch)
			scratch = process.map_memory(4096, PROT_READ | PROT_WRITE);
		// LoadIcon picks the default icon size of the display, exactly like a zero-sized LoadImage.
		const uint64_t forwarded[] = {args[0], args[1], 0, 0, scratch};
		const auto status = load_icon(forwarded);
		if (status) {
			if ((status & 0xffff0000U) == 0x80070000U)
				environment.set_last_error(uint32_t(status & 0xffffU));
			else
				environment.set_last_error(120);
		} else {
			const auto bytes = process.read_memory(scratch, 8);
			for (size_t index = 0; index < 8; ++index)
				result |= uint64_t(bytes[index]) << (index * 8);
		}
	} catch (uint32_t error) { environment.set_last_error(error); }
	catch (const std::bad_alloc &) { environment.set_last_error(8); }
	process.return_api(result);
	return true;
}

}
