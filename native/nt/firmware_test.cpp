#include "firmware.h"

#include <cstdlib>
#include <iostream>
#include <vector>

static void check(bool condition, const char *message)
{
	if (!condition) {
		std::cerr << message << '\n';
		std::exit(1);
	}
}

int main()
{
	std::vector<uint8_t> device(34);
	device[0] = 17;
	device[1] = 32;
	device[13] = 0x20;
	check(raven::smbios_memory(device) == 8ULL * 1024 * 1024, "8 GiB device size differs");
	std::vector<uint8_t> table = device;
	table.insert(table.end(), device.begin(), device.end());
	table.insert(table.end(), {127, 4, 0, 0, 0, 0});
	check(raven::smbios_memory(table) == 16ULL * 1024 * 1024, "multiple devices differ");
	device[13] = 0x80;
	device[12] = 64;
	check(raven::smbios_memory(device) == 64, "KiB size interpreted as MiB");
	device[13] = 0;
	device[12] = 0;
	check(raven::smbios_memory(device) == 0, "empty slot has memory");
	device[13] = 0x7f;
	device[12] = 0xff;
	device[30] = 2;
	check(raven::smbios_memory(device) == 128ULL * 1024 * 1024, "extended device size differs");
	for (size_t size = 0; size < device.size(); ++size)
		check(raven::smbios_memory(std::span(device).first(size)) == 0, "truncated device accepted");
	device[31] = 0x80;
	check(!raven::smbios_memory(device), "reserved extended size bit accepted");
	device[31] = 0;
	device[30] = 0;
	check(!raven::smbios_memory(device), "zero extended size accepted");
	device[13] = 0xff;
	check(!raven::smbios_memory(device), "unknown device size accepted");
	device[1] = 3;
	check(!raven::smbios_memory(device), "short header accepted");
	device[1] = 35;
	check(!raven::smbios_memory(device), "oversized record accepted");
	table.back() = 1;
	check(!raven::smbios_memory(table), "unterminated string set accepted");
	return 0;
}
