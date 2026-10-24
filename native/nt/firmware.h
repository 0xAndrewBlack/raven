#pragma once

#include <cstdint>
#include <span>

namespace raven {

// Installed memory in KiB from SMBIOS Type 17 records; zero means missing or invalid data.
uint64_t smbios_memory(std::span<const uint8_t> table);

}
