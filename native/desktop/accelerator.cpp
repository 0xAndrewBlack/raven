#include "objects.h"

namespace raven {

uint64_t DesktopObjects::add_accelerators(std::vector<DesktopAccelerator> table)
{
	constexpr uint64_t first = 0x7a000000ULL;
	if (table.empty() || table.size() > 1024 || accelerator_tables.size() >= 1024)
		return 0;
	const uint64_t handle = first + accelerator_tables.size() + 1;
	accelerator_tables.emplace(handle, std::move(table));
	return handle;
}

const std::vector<DesktopAccelerator> *DesktopObjects::accelerators(uint64_t handle) const
{
	const auto found = accelerator_tables.find(handle);
	return found == accelerator_tables.end() ? nullptr : &found->second;
}

}
