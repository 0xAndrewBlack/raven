#include "providers.h"
#include "system_exports.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>

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

static void served_thread_result(const std::string &bootstrap)
{
	const auto timeout = std::chrono::seconds(2);
	const uint64_t base = 0x180000000ULL;
	const std::array<std::string_view, 1> names{"vkCmdDrawIndexed"};
	const auto bytes = raven::runtime_provider("vulkan-1.dll", base, names);
	const raven::PEImage image(bytes);
	raven::LoadedImage loaded(image, base);
	raven::LoadedImage *images[] = {&loaded};
	raven::NativeProcess process(images, bootstrap, timeout);
	const uint64_t stub = base + image.exports().at(0).address;
	const int file = memfd_create("served-thread-test", MFD_CLOEXEC);
	check(file >= 0 && ftruncate(file, 4096) == 0, "cannot create served test block");
	auto *block = static_cast<uint64_t *>(mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0));
	check(block != MAP_FAILED, "cannot map served test block");
	const uint64_t guest = process.map_shared(file, 4096);
	close(file);
	int32_t displacement = 0;
	std::memcpy(&displacement, loaded.data().data() + stub - base + 3, 4);
	std::memcpy(loaded.data().data() + stub - base + 7 + displacement, &guest, 8);
	const auto other_stack = process.map_memory(65536, PROT_READ | PROT_WRITE);
	const auto other = process.new_thread(other_stack + 65536, 0);
	unsigned calls = 0, switches = 0;
	bool nested = false;
	process.set_served_calls(block, {stub}, 112, 85, {stub + 101}, [&](uint64_t address) {
		check(address == stub, "served call used another stub");
		const auto words = process.api_arguments(6);
		uint64_t sum = 0;
		for (size_t index = 0; index < words.size(); ++index) {
			check(words[index] == (nested ? 200 : 100) + index, "thread switch changed served arguments");
			sum += words[index];
		}
		++calls;
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
		process.return_api(sum);
	});
	process.set_time_slicing(std::chrono::milliseconds(1), [&] { return !nested; }, [&] {
		check(process.context().registers.rip == stub + 102, "served thread yielded before its result was private");
		const auto saved = process.save_thread();
		nested = true;
		process.load_thread(other);
		const uint64_t arguments[] = {200, 201, 202, 203, 204, 205};
		const auto result = process.call(stub, arguments, timeout);
		check(result.stop == raven::NativeStop::returned && result.value == 1215, "second served thread lost its result");
		process.load_thread(saved);
		nested = false;
		++switches;
	});
	const uint64_t arguments[] = {100, 101, 102, 103, 104, 105};
	const auto result = process.call(stub, arguments, timeout);
	check(result.stop == raven::NativeStop::returned && result.value == 615 && calls == 2 && switches == 1,
		"served thread result was overwritten across the yield");
	process.set_time_slicing(std::chrono::milliseconds(0), {}, {});
	const auto unsliced = process.call(stub, arguments, timeout);
	check(unsliced.stop == raven::NativeStop::returned && unsliced.value == 615 && calls == 3 && switches == 1 && !block[11],
		"served call retained a disabled yield request");
	process.set_served_calls(nullptr, {}, 0, 0, {}, {});
	process.unmap_memory(other_stack);
	process.unmap_memory(guest);
	munmap(block, 4096);
}

static void parallel_served_result(const std::string &bootstrap)
{
	const auto timeout = std::chrono::seconds(2);
	const uint64_t base = 0x180000000ULL;
	const std::array<std::string_view, 1> names{"vkCmdDrawIndexed"};
	const raven::PEImage image(raven::runtime_provider("vulkan-1.dll", base, names));
	raven::LoadedImage loaded(image, base);
	raven::LoadedImage *images[] = {&loaded};
	raven::NativeProcess process(images, bootstrap, timeout);
	check(process.parallel(), "parallel served test needs separate execution tasks");
	const uint64_t stub = base + image.exports().at(0).address;
	const std::array<uint8_t, 12> local{0x65, 0x4c, 0x8b, 0x14, 0x25, 0xf0, 0x1f, 0, 0, 0x90, 0x90, 0x90};
	std::copy(local.begin(), local.end(), loaded.data().data() + stub - base);
	const auto teb = process.map_memory(8192, PROT_READ | PROT_WRITE);
	auto context = process.context();
	context.registers.gs_base = teb;
	process.set_context(context);
	raven::NativeThreadState other;
	bool nested = false;
	unsigned calls = 0;
	process.set_served_calls(nullptr, {stub}, 112, 85, {}, [&](uint64_t address) {
		check(address == stub, "parallel call used another stub");
		const auto words = process.api_arguments(6);
		uint64_t sum = 0;
		for (size_t i = 0; i < words.size(); ++i) {
			check(words[i] == (nested ? 200 : 100) + i, "parallel served arguments crossed threads");
			sum += words[i];
		}
		if (!nested) {
			const auto saved = process.save_thread();
			process.load_thread(other);
			nested = true;
			const uint64_t arguments[] = {200, 201, 202, 203, 204, 205};
			const auto result = process.call(stub, arguments, timeout);
			check(result.stop == raven::NativeStop::returned && result.value == 1215, "nested served result crossed threads");
			other = process.save_thread();
			process.load_thread(saved);
			nested = false;
			check(process.api_arguments(6) == words, "resumed served call lost its stack arguments");
		}
		++calls;
		process.return_api(sum);
	});
	const auto other_teb = process.map_memory(8192, PROT_READ | PROT_WRITE);
	const auto stack = process.map_memory(65536, PROT_READ | PROT_WRITE);
	other = process.new_thread(stack + 65536, other_teb);
	process.set_execution_wait([](std::function<bool()> ready, auto limit) {
		while (!ready() && std::chrono::steady_clock::now() < limit)
			std::this_thread::yield();
	});
	const uint64_t arguments[] = {100, 101, 102, 103, 104, 105};
	for (unsigned i = 0; i < 64; ++i) {
		const auto result = process.call(stub, arguments, timeout);
		check(result.stop == raven::NativeStop::returned && result.value == 615, "outer served result crossed threads");
	}
	check(calls == 128, "parallel served call was lost or repeated");
	process.stop_thread(other);
	// A responsive served loop must give ready host work a turn even when its guest never reaches the wait trap.
	loaded.data()[stub - base + 85] = 0x90;
	unsigned turns = 0;
	process.set_served_calls(nullptr, {stub}, 112, 85, {}, [&](uint64_t) {
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
		process.return_api(615);
	});
	process.set_time_slicing(std::chrono::milliseconds(1), [] { return true; }, [&] { ++turns; });
	process.load_thread(process.save_thread());
	const auto fair = process.call(stub, arguments, timeout);
	check(fair.stop == raven::NativeStop::returned && fair.value == 615 && turns > 0,
		"parallel served loop starved ready host work");
	process.set_time_slicing(std::chrono::milliseconds(0), {}, {});
}

int main(int argc, char **argv)
{
	try {
		if (argc == 3 && std::string(argv[2]) == "--parallel-served") {
			parallel_served_result(argv[1]);
			std::cout << "Parallel served arguments and results passed\n";
			return 0;
		}
		if (argc != 2)
			throw std::runtime_error("bootstrap path required");
		served_thread_result(argv[1]);
		const uint64_t base = 0x180000000ULL;
		auto bytes = raven::environment_provider("kernel32.dll", base);
		const raven::PEImage image(bytes);
		check(image.is_64 && image.entry == 0 && image.imports().empty() && image.exports().size() == 47,
			"provider PE metadata differs");
		for (const auto &symbol : image.exports())
			check(symbol.ordinal >= 0x10000 - image.exports().size() && symbol.ordinal <= UINT16_MAX && symbol.names.size() == 1 && symbol.forwarder.empty(),
				"provider numbered a name outside the top of the 16-bit ordinal range");
		const std::array<std::string_view,1> controls{"LoadIconWithScaleDown"};
		const auto control_bytes = raven::runtime_provider("comctl32.dll",base,controls);
		const auto control_exports = raven::PEImage(control_bytes).exports();
		check(control_exports.size() == 1 && control_exports[0].ordinal == 381 && control_exports[0].names[0] == controls[0],
			"verified icon control ordinal differs");
		const std::array<std::pair<std::string_view, uint16_t>, 18> ldap_ordinals{{
			{"ldap_set_optionW", 14}, {"ldap_first_entry", 26}, {"ldap_next_entry", 27}, {"ldap_msgfree", 41},
			{"ldap_unbind_s", 46}, {"ldap_bind_sW", 73}, {"ldap_value_free_len", 79}, {"ldap_err2stringA", 117},
			{"ldap_first_attributeW", 127}, {"ldap_get_dnW", 133}, {"ldap_get_values_lenW", 142}, {"ldap_initW", 145},
			{"ldap_memfreeW", 147}, {"ldap_next_attributeW", 167}, {"ldap_search_sW", 208},
			{"ldap_simple_bind_sW", 216}, {"ldap_sslinitW", 219}, {"ber_free", 301},
		}};
		for (const bool x86 : {false, true}) {
			const auto ldap_bytes = raven::runtime_provider("wldap32.dll", x86 ? 0x70000000ULL : base,
				raven::system_export_names("wldap32.dll"), x86, {}, raven::system_export_ordinals("wldap32.dll"));
			const auto exports = raven::PEImage(ldap_bytes).exports();
			for (const auto &[name, ordinal] : ldap_ordinals)
				check(std::any_of(exports.begin(), exports.end(), [&](const auto &symbol) {
					return symbol.ordinal == ordinal && symbol.names.size() == 1 && symbol.names[0] == name;
				}), "LDAP provider export ordinal differs");
		}
		const std::array<std::string_view, 4> natives{"NtClose", "NtOpenThread", "NtRavenMissing", "ZwOpenThread"};
		const auto nt_bytes = raven::runtime_provider("ntdll.dll", base, natives);
		const raven::PEImage nt_image(nt_bytes);
		const auto nt_exports = nt_image.exports();
		const auto service = nt_image.file_span(nt_exports[1].address, 11);
		check(service[0] == 0x4c && service[1] == 0x8b && service[2] == 0xd1 && service[3] == 0xb8 &&
			service[8] == 0x0f && service[9] == 0x05 && service[10] == 0xc3, "NT service entry differs");
		check(std::ranges::equal(service, nt_image.file_span(nt_exports[3].address, 11)), "Zw service identity differs");
		const std::array<std::string_view, 1> only_thread{"NtOpenThread"};
		const auto smaller = raven::runtime_provider("ntdll.dll", base + 65536, only_thread);
		const raven::PEImage smaller_image(smaller);
		check(std::ranges::equal(service, smaller_image.file_span(smaller_image.exports()[0].address, 11)),
			"NT service identity depends on the process import graph");
		check(nt_image.file_span(nt_exports[2].address, 1)[0] == 0xcc, "unknown NT function received a service identity");
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
		const std::span<const uint8_t> original_view = original.bytes;
		const std::vector<uint8_t> original_bytes(original_view.begin(), original_view.end());
		check(raven::run_native_process(supplied, other_entry, argv[1], std::chrono::seconds(2)).value == 42,
			"supplied-module graph did not execute");
		check(supplied.all().at("kernel32.dll").get() == &original && std::ranges::equal(std::span<const uint8_t>(original.bytes), original_bytes),
			"runtime replaced a supplied DLL");
		std::cout << "Original native provider PE exports, placement, supplied DLL preservation and unsupported symbol/ordinal contracts passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
