#include "native_cpu.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static std::vector<uint8_t> read_file(const char *path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file || file.tellg() < 0 || file.tellg() > 1024 * 1024)
		throw std::runtime_error("cannot read callback fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
	file.seekg(0);
	if (!file.read(reinterpret_cast<char *>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
		throw std::runtime_error("truncated callback fixture");
	return bytes;
}

static raven::NativeResult dispatch(raven::NativeProcess &process, raven::NativeResult result, uint64_t trap, size_t &calls)
{
	const auto timeout = std::chrono::seconds(2);
	while (result.stop == raven::NativeStop::api) {
		if (result.value != trap || ++calls > 8)
			throw std::runtime_error("unexpected callback fixture API");
		const auto arguments = process.api_arguments(2);
		const uint64_t value[] = {arguments[1]};
		const auto returned = dispatch(process, process.callback(arguments[0], value, timeout), trap, calls);
		if (returned.stop != raven::NativeStop::returned)
			throw std::runtime_error("compiled callback did not return");
		process.return_api(returned.value);
		result = process.resume(timeout);
	}
	return result;
}

int main(int argc, char **argv)
{
	try {
		if (argc != 4)
			throw std::runtime_error("bootstrap, client and probe fixture paths required");
		raven::ModuleSet modules;
		raven::PEModule *entry = nullptr;
		for (int index = 2; index < argc; ++index) {
			auto bytes = read_file(argv[index]);
			const auto base = raven::PEImage(bytes).image_base;
			auto &module = modules.add(std::filesystem::path(argv[index]).filename().string(), std::move(bytes), base);
			if (!entry)
				entry = &module;
		}
		if (modules.bind_imports() != 1)
			throw std::runtime_error("compiled callback import count differs");
		std::vector<raven::LoadedImage *> images;
		for (const auto &[name, module] : modules.all())
			images.push_back(&module->loaded);
		raven::NativeProcess process(images, argv[1], std::chrono::seconds(2));
		const auto trap = modules.resolve({"ravenprobe.dll", "Dispatch", 0, false, 0});
		process.add_api_trap(trap);
		size_t calls = 0;
		const auto result = dispatch(process, process.call(entry->loaded.base() + entry->image.entry, {}, std::chrono::seconds(2)), trap, calls);
		if (result.stop != raven::NativeStop::returned || result.value != 26 || calls != 2)
			throw std::runtime_error("compiled nested callback result differs");
		std::cout << "Compiled PE64 imports, two nested callbacks and original caller resume returned 26\n";
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << '\n';
		return 1;
	}
}
