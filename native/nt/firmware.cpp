#include "firmware.h"

namespace raven {

uint64_t smbios_memory(std::span<const uint8_t> table)
{
	uint64_t total = 0;
	while (!table.empty()) {
		if (table.size() < 4 || table[1] < 4 || table[1] > table.size()) return 0;
		const size_t length = table[1];
		size_t end = length;
		while (end + 1 < table.size() && (table[end] || table[end + 1])) ++end;
		if (end + 1 >= table.size()) return 0;
		if (table[0] == 127) return total;
		if (table[0] == 17) {
			if (length < 0x15) return 0;
			uint64_t size = uint32_t(table[12]) | uint32_t(table[13]) << 8;
			if (size == 0xffff) return 0;
			if (size == 0x7fff) {
				if (length < 0x20) return 0;
				size = uint32_t(table[28]) | uint32_t(table[29]) << 8 | uint32_t(table[30]) << 16 | uint32_t(table[31]) << 24;
				if (!size || (size & 0x80000000U)) return 0;
				size *= 1024;
			} else if (size & 0x8000)
				size &= 0x7fff;
			else
				size *= 1024;
			if (size > UINT64_MAX - total) return 0;
			total += size;
		}
		table = table.subspan(end + 2);
	}
	return total;
}

}
