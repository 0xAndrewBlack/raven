#include "providers.h"
#include "tls.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool condition, const char *message)
{
	if (!condition)
		throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg() > 0 && file.tellg() < 1024 * 1024, "cannot read TLS fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()))), "truncated TLS fixture");
	return bytes;
}

static uint64_t integer(raven::PEModule &module, size_t offset, size_t width = 8)
{
	const auto bytes = module.loaded.data().subspan(offset, width);
	uint64_t result = 0;
	for (size_t index = 0; index < width; ++index)
		result |= uint64_t(bytes[index]) << (index * 8);
	return result;
}

static void put(raven::PEModule &module, size_t offset, uint64_t value, size_t width = 8)
{
	auto bytes = module.loaded.data().subspan(offset, width);
	for (size_t index = 0; index < width; ++index)
		bytes[index] = static_cast<uint8_t>(value >> (index * 8));
}

static void late_tls(const std::filesystem::path &directory, const std::string &bootstrap, bool populated)
{
	raven::ModuleSet modules;
	auto &entry = modules.add("client.exe", read_file(directory / "client.exe"));
	entry.loaded.data()[entry.image.entry] = 0xcc;
	entry.loaded.data()[entry.image.entry + 1] = 0xc3;
	raven::LoadedImage *images[] = {&entry.loaded};
	raven::NativeProcess process(images, bootstrap, std::chrono::seconds(2));
	raven::NativeEnvironment environment(process, entry.loaded.base(), 1, 1);
	const raven::PEModule *order[] = {&entry};
	raven::NativeTLS tls(process, environment, std::span(order).first(populated ? 1 : 0));
	const auto number = [&](uint64_t address, size_t width = 8) {
		const auto bytes = process.read_memory(address, width);
		uint64_t value = 0;
		for (size_t index = 0; index < width; ++index)
			value |= uint64_t(bytes[index]) << (index * 8);
		return value;
	};
	const auto rejected = [&](const auto &operation) {
		bool failed = false;
		try { operation(); } catch (const std::runtime_error &) { failed = true; }
		check(failed, "invalid late loader TLS operation succeeded");
	};
	process.add_api_trap(entry.loaded.base() + entry.image.entry);
	const uint64_t arguments[] = {17, 23};
	check(process.call(entry.loaded.base() + entry.image.entry, arguments, std::chrono::seconds(2)).stop == raven::NativeStop::api,
		"late TLS fixture did not reach API suspension");
	if (!populated) {
		process.protect_memory(environment.teb(), 8192, PROT_READ);
		rejected([&] { tls.add(entry); });
		process.protect_memory(environment.teb(), 8192, PROT_READ | PROT_WRITE);
		check(number(environment.teb() + 0x58) == 0, "failed first TLS publication changed the TEB vector");
		rejected([&] { tls.callbacks(entry); });
		tls.add(entry);
	}
	const auto vector = number(environment.teb() + 0x58);
	const auto original_block = number(vector);
	const uint8_t marker[] = {25, 0, 0, 0};
	process.write_memory(original_block, marker);
	auto &first = modules.add("tlsprobe.dll", read_file(directory / "tlsprobe.dll"));
	auto &second = modules.add("second.dll", read_file(directory / "tlsprobe.dll"));
	rejected([&] { tls.add(first); });
	process.map_image(first.loaded);
	process.map_image(second.loaded);
	tls.add(first);
	tls.add(second);
	rejected([&] { tls.add(first); });
	const auto first_index_address = first.loaded.base() + first.image.directories[9].address + 16;
	const auto index_address = number(first_index_address);
	const auto first_slot = number(index_address, 4);
	const auto first_block = number(vector + first_slot * 8);
	check(first_slot == 1 && number(environment.teb() + 0x58) == vector && number(vector) == original_block &&
		number(original_block, 4) == 25 && number(first_block, 4) == 17 && number(first_block + 8) == 0,
		"late loader TLS changed existing values or template/zero-fill");
	const auto invoke = [&](const raven::PEModule &module, const char *name, std::span<const uint64_t> args = {}) {
		const auto address = modules.resolve({module.name, name, 0, false, 0});
		const auto result = process.callback(address, args, std::chrono::seconds(2));
		check(result.stop == raven::NativeStop::returned, "compiled late TLS access did not return");
		return result.value;
	};
	check(invoke(first, "ReadTLSValue") == 17 && invoke(second, "ReadTLSValue") == 17,
		"compiled TLS reads differ after late mapping");
	const uint64_t update[] = {91};
	check(invoke(first, "WriteTLSValue", update) == 17 && invoke(first, "ReadTLSValue") == 91 &&
		invoke(second, "ReadTLSValue") == 17, "late TLS blocks alias or did not retain guest writes");
	process.protect_memory(vector, 4096, PROT_READ);
	rejected([&] { tls.remove(first); });
	process.protect_memory(vector, 4096, PROT_READ | PROT_WRITE);
	check(number(vector + first_slot * 8) == first_block, "failed TLS release cleared a live slot");
	auto &third = modules.add("third.dll", read_file(directory / "tlsprobe.dll"));
	process.map_image(third.loaded);
	const auto third_index = number(third.loaded.base() + third.image.directories[9].address + 16);
	const auto old_index = number(third_index, 4);
	process.protect_memory(vector, 4096, PROT_READ);
	rejected([&] { tls.add(third); });
	process.protect_memory(vector, 4096, PROT_READ | PROT_WRITE);
	check(number(third_index, 4) == old_index && number(vector + first_slot * 8) == first_block,
		"failed TLS publication changed indexes or an existing slot");
	rejected([&] { tls.callbacks(third); });
	tls.add(third);
	check(invoke(third, "ReadTLSValue") == 17, "TLS add after publication failure retained a stale block");
	tls.remove(third);
	tls.remove(first);
	check(number(vector + first_slot * 8) == 0, "TLS release retained its block pointer");
	rejected([&] { process.read_memory(first_block, 1); });
	rejected([&] { tls.remove(first); });
	tls.add(first);
	check(number(index_address, 4) == first_slot && invoke(first, "ReadTLSValue") == 17 &&
		invoke(second, "ReadTLSValue") == 17 && number(original_block, 4) == 25,
		"reused TLS slot retained stale contents or changed another module");
	tls.remove(first);
	tls.remove(second);
	check(process.api_arguments(2) == std::vector<uint64_t>{17, 23}, "late TLS operations lost pending API arguments");
	process.return_api(88);
	check(process.resume(std::chrono::seconds(2)).value == 88, "late TLS operations lost guest return");
	std::cout << "Late loader TLS slot reuse, block isolation, compiled guest access and suspended API preservation passed\n";
}

int main(int argc, char **argv)
{
	try {
		check(argc == 5, "bootstrap and three TLS fixture directories required");
		late_tls(argv[2], argv[1], false);
		late_tls(argv[2], argv[1], true);
		for (unsigned sample = 0; sample < 3; ++sample) {
			const std::filesystem::path directory(argv[2 + sample]);
			for (unsigned mode = 0; mode < (sample ? 1U : 11U); ++mode) {
				raven::ModuleSet modules;
				const auto add = [&](const char *name) -> raven::PEModule & {
					auto bytes = read_file(directory / name);
					const auto base = raven::PEImage(bytes).image_base;
					if (sample == 2)
						return modules.add(name, std::move(bytes));
					return modules.add(name, std::move(bytes), base + 0x1000000);
				};
				auto &entry = add("client.exe");
				auto &library = add("tlsprobe.dll");
				if (sample == 2)
					check(entry.loaded.base() == entry.image.image_base && library.image.image_base == entry.image.image_base &&
						library.loaded.base() != library.image.image_base, "compiled colliding DLL was not automatically relocated");
				const size_t tls = library.image.directories[9].address;
				check(tls && library.image.directories[9].size == 40, "compiler did not emit PE64 TLS metadata");
				const auto index = integer(library, tls + 16) - library.loaded.base();
				const auto array = integer(library, tls + 24) - library.loaded.base();
				const auto callback = integer(library, array) - library.loaded.base();
				if (mode == 1) library.image.directories[9].size = 39;
				if (mode == 2) put(library, tls + 8, integer(library, tls) - 1);
				if (mode == 3) put(library, tls, library.loaded.base() - 8);
				if (mode == 4) put(library, tls + 16, library.loaded.base());
				if (mode == 5) put(library, array, library.loaded.base() + index);
				if (mode == 6) put(library, tls + 36, 0xf00000, 4);
				if (mode == 7) put(library, tls + 32, 0xffffffff, 4);
				if (mode == 8) put(library, tls + 24, library.loaded.base() + library.image.image_size - 4);
				if (mode == 9) put(library, callback, 0x0b0f, 2);
				if (mode == 10) put(library, callback, 0xfeeb, 2);
				bool rejected = false;
				raven::NativeResult result{};
				try {
					result = raven::run_native_process(modules, entry, argv[1], std::chrono::milliseconds(mode == 10 ? 300 : 2000));
				} catch (const std::runtime_error &error) {
					if (!mode || mode >= 9) throw;
					const std::string expected[] = {
						"", "invalid PE64 TLS directory: tlsprobe.dll",
						"invalid static TLS size or alignment: tlsprobe.dll",
						"static TLS address is outside its module: tlsprobe.dll",
						"native write exceeds writable guest memory",
						"static TLS callback is not executable",
						"invalid static TLS size or alignment: tlsprobe.dll",
						"static TLS exceeds initial thread allocation limit",
						"static TLS address is outside its module: tlsprobe.dll"
					};
					check(error.what() == expected[mode], "malformed TLS failed for an unrelated reason");
					rejected = true;
				}
				if (!rejected) {
					if (!mode) {
						check(result.stop == raven::NativeStop::returned && result.value == 0, "compiled static TLS workflow failed");
						const auto state = [&](raven::PEModule &module) {
							const auto address = modules.resolve({module.name, "tls_state", 0, false, 0});
							return integer(module, address - module.loaded.base(), 4);
						};
						check(state(library) == 123564 && state(entry) == 12356, "TLS/DllMain attach or detach callback order differs");
						const auto exe_index = modules.resolve({entry.name, "_tls_index", 0, false, 0});
						check(integer(entry, exe_index - entry.loaded.base(), 4) != integer(library, index, 4), "module TLS indexes alias");
						check(integer(library, integer(library, tls) - library.loaded.base(), 4) == 17 &&
							integer(entry, integer(entry, entry.image.directories[9].address) - entry.loaded.base(), 4) == 17,
							"TLS callbacks modified the source templates");
					} else if (mode >= 9) {
						check(result.stop == (mode == 9 ? raven::NativeStop::fault : raven::NativeStop::timeout), "TLS callback failure became apparent success");
						if (mode == 9) check(result.signal == SIGILL, "TLS callback fault signal differs");
						const auto address = modules.resolve({library.name, "tls_state", 0, false, 0});
						check(integer(library, address - library.loaded.base(), 4) == 0, "TLS callback failure ran extra guest cleanup");
					} else {
						throw std::runtime_error("malformed TLS was accepted");
					}
				}
				if (mode && mode < 9) check(rejected, "malformed TLS was not rejected");
				if (mode) {
					const auto address = modules.resolve({entry.name, "entered", 0, false, 0});
					check(integer(entry, address - entry.loaded.base(), 4) == 0, "EXE entry ran after TLS initialization failure");
				}
			}
		}
		std::cout << "Compiled relocated PE64 TLS template, zero-fill, alignment, slot isolation, callbacks and checked failures passed\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
