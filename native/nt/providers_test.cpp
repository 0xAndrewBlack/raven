#include "providers.h"

#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static void rejected(const std::function<void()> &operation)
{
	try { operation(); } catch (const std::runtime_error &) { return; }
	throw std::runtime_error("unsupported native provider operation was accepted");
}

int main(int argc, char **argv)
{
	try {
		if (argc != 2)
			throw std::runtime_error("bootstrap path required");
		const uint64_t base = 0x180000000ULL;
		auto bytes = raven::environment_provider("kernel32.dll", base);
		const raven::PEImage image(bytes);
		check(image.is_64 && image.entry == 0 && image.imports().empty() && image.exports().size() == 45,
			"provider PE metadata differs");
		for (const auto &symbol : image.exports())
			check(symbol.ordinal > UINT16_MAX && symbol.names.size() == 1 && symbol.forwarder.empty(), "provider invented a 16-bit Windows ordinal");
		const std::array<std::string_view,1> controls{"LoadIconWithScaleDown"};
		const auto control_bytes = raven::runtime_provider("comctl32.dll",base,controls);
		const auto control_exports = raven::PEImage(control_bytes).exports();
		check(control_exports.size() == 1 && control_exports[0].ordinal == 381 && control_exports[0].names[0] == controls[0],
			"verified icon control ordinal differs");
		std::vector<std::string> storage;
		for (size_t index = 0; index < 128; ++index)
			storage.push_back("A" + std::string(3 - std::to_string(index).size(), '0') + std::to_string(index));
		std::vector<std::string_view> names;
		for (const auto &name : storage)
			names.push_back(name);
		const auto capacity_bytes = raven::runtime_provider("capacity.dll", base, names);
		const auto capacity_exports = raven::PEImage(capacity_bytes).exports();
		check(capacity_exports.size() == 128, "provider table capacity differs");
		for (size_t index = 0; index < names.size(); ++index)
			check(capacity_exports[index].names.at(0) == names[index] && capacity_exports[index].address == 0x1000 + index * 16,
				"provider tables overlap at capacity");
		names.resize(4097, "Z");
		rejected([&] { raven::runtime_provider("capacity.dll", base, names); });
		rejected([&] { raven::environment_provider("unknown.dll", base); });
		// Turn this original header into a bare executable whose entry returns 42.
		bytes[0x96] = 3;
		bytes[0x97] = 0;
		bytes[0xa8] = 0;
		bytes[0xa9] = 0x10;
		const uint8_t entry_code[] = {0xb8, 42, 0, 0, 0, 0xc3};
		std::copy(std::begin(entry_code), std::end(entry_code), bytes.begin() + 0x200);
		raven::ModuleSet modules;
		auto &entry = modules.add("program.exe", bytes, base);
		rejected([&] { raven::run_native_process(modules, entry, argv[1], std::chrono::milliseconds(0)); });
		const auto result = raven::run_native_process(modules, entry, argv[1], std::chrono::seconds(2));
		check(result.stop == raven::NativeStop::returned && result.value == 42, "provider placement fixture did not execute");
		// Providers land after the executable and never overlap each other, whatever their export tables weigh.
		std::vector<std::pair<uint64_t, uint64_t>> ranges;
		for (const auto &[name, module] : modules.all())
			ranges.emplace_back(module->loaded.base(), module->loaded.base() + module->loaded.data().size());
		std::sort(ranges.begin(), ranges.end());
		bool placed = modules.all().at("kernel32.dll")->loaded.base() >= base + 65536;
		for (size_t index = 1; index < ranges.size(); ++index)
			placed = placed && ranges[index - 1].second <= ranges[index].first;
		if (!placed)
			for (const auto &range : ranges)
				std::cerr << std::hex << range.first << ' ' << range.second << '\n';
		check(placed, "provider placement overlapped the executable or another provider");
		rejected([&] { modules.resolve({"kernel32.dll", "Unimplemented", 0, false, 0}); });
		rejected([&] { modules.resolve({"kernel32.dll", "", 1, true, 0}); });
		raven::ModuleSet supplied;
		auto &other_entry = supplied.add("program.exe", bytes, base);
		auto &original = supplied.add("kernel32.dll", raven::environment_provider("kernel32.dll", base + 65536), base + 65536);
		const auto original_bytes = original.bytes;
		check(raven::run_native_process(supplied, other_entry, argv[1], std::chrono::seconds(2)).value == 42,
			"supplied-module graph did not execute");
		check(supplied.all().at("kernel32.dll").get() == &original && original.bytes == original_bytes,
			"runtime replaced a supplied DLL");
		std::cout << "Original native provider PE exports, placement, supplied DLL preservation and unsupported symbol/ordinal contracts passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
