#include "x86_loader.h"

#include "apiset.h"
#include "system_exports.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace raven {

namespace {

std::string lowered(std::string text)
{
	for (auto &character : text)
		if (character >= 'A' && character <= 'Z')
			character = static_cast<char>(character + ('a' - 'A'));
	return text;
}

std::vector<uint8_t> read_all(const std::filesystem::path &path)
{
	std::ifstream stream(path, std::ios::binary | std::ios::ate);
	const auto size = stream ? stream.tellg() : std::streampos(-1);
	if (size <= 0)
		return {};
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	stream.seekg(0);
	if (!stream.read(reinterpret_cast<char *>(bytes.data()), size))
		bytes.resize(static_cast<size_t>(stream.gcount()));
	return bytes;
}

bool trace()
{
	return getenv("RAVEN_TRACE_X86") != nullptr;
}

}

NativeX86Loader::NativeX86Loader(NativeProcess &process, NativeEnvironment &environment, ModuleSet &modules, const NativePaths &paths,
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call)
	: process(process), environment(environment), modules(modules), paths(paths), call(std::move(call))
{
}

std::optional<std::vector<uint8_t>> NativeX86Loader::read_library(const std::string &name, std::string &identity) const
{
	// The runtime's own components come from beside it, in their 32-bit builds.
	if (std::find(std::begin(runtime_components), std::end(runtime_components), name) != std::end(runtime_components)) {
		const auto component = std::filesystem::read_symlink("/proc/self/exe").parent_path() / "x86" / name;
		if (std::filesystem::exists(component)) {
			identity = name;
			return read_all(component);
		}
	}
	// The C runtime comes from the runtime's own directory, in its 32-bit build.
	if (name == "ucrtbase.dll") {
		const auto component = std::filesystem::read_symlink("/proc/self/exe").parent_path() / "ucrtbase32.dll";
		if (!std::filesystem::exists(component))
			return std::nullopt;
		identity = name;
		return read_all(component);
	}
	// A name alone is looked for beside the program, then in the system directory, then in the current directory.
	auto resolved = paths.resolve(std::u16string(name.begin(), name.end()));
	if (name.find_first_of("/\\:") == std::string::npos) {
		const auto system = paths.resolve(NativePaths::system_directory(false) + u"\\" + std::u16string(name.begin(), name.end()));
		if (system && system->exists)
			resolved = system;
		const auto beside = application_directory.empty() ? std::nullopt :
			paths.resolve(application_directory + u"\\" + std::u16string(name.begin(), name.end()));
		if (beside && beside->exists)
			resolved = beside;
	}
	if (!resolved || !resolved->exists || !std::filesystem::is_regular_file(resolved->host))
		return std::nullopt;
	identity = lowered(resolved->host.filename().string());
	return read_all(resolved->host);
}

// Brings one library into the process, with its dependencies; null when it is not available.
PEModule *NativeX86Loader::bring(const std::string &requested)
{
	auto name = lowered(requested);
	if (name.find('.') == std::string::npos)
		name += ".dll";
	if (const auto host = apiset_host(name); !host.empty()) {
		if (!modules.all().contains(host) && !bring(host))
			return nullptr;
		if (!modules.all().contains(name))
			modules.add_alias(name, host);
		name = host;
	}
	if (const auto found = modules.all().find(name); found != modules.all().end())
		return found->second.get();
	// A system library named by its path is the runtime's, as it is by its name; any library named by its path in the system directory is
	// looked for as by its name, so a program that loads comctl32.dll from System32 gets the one the runtime has.
	if (const auto slash = name.find_last_of("/\\:"); slash != std::string::npos) {
		const auto base = name.substr(slash + 1);
		if (const auto found = modules.all().find(base); found != modules.all().end() && found->second->runtime_api)
			return found->second.get();
		const auto folder = name.substr(0, slash);
		if (folder == "c:\\windows\\system32" || folder == "c:\\windows\\syswow64")
			return bring(base);
	}
	std::string identity;
	auto bytes = read_library(name, identity);
	if (!bytes) {
		if (trace())
			std::cerr << "raven: library file not found: " << requested << '\n';
		environment.set_last_error(126);
		return nullptr;
	}
	const PEImage image(*bytes);
	if (image.is_64 || !(image.characteristics & 0x2000)) {
		environment.set_last_error(193);
		return nullptr;
	}
	if (modules.all().contains(identity))
		identity += "#" + std::to_string(modules.all().size());
	auto &added = modules.add(identity, std::move(*bytes));
	staged.push_back(&added);
	std::string missing;
	for (const auto &symbol : added.imports) {
		const auto dependency = lowered(symbol.module);
		if (!modules.all().contains(dependency) && !bring(dependency)) {
			missing += " " + symbol.module + "!";
			continue;
		}
		try {
			modules.resolve(symbol);
		} catch (const std::runtime_error &) {
			missing += " " + symbol.module + "!" + (symbol.by_ordinal ? "#" + std::to_string(symbol.ordinal) : symbol.name);
		}
	}
	if (!missing.empty())
		throw std::runtime_error("unresolved imports in " + identity + ":" + missing);
	return &added;
}

std::optional<std::string> NativeX86Loader::path_key(const std::string &name) const
{
	std::optional<NativePaths::Resolved> resolved;
	if (name.find_first_of("/\\:") != std::string::npos)
		resolved = paths.resolve(std::u16string(name.begin(), name.end()));
	else if (!application_directory.empty())
		resolved = paths.resolve(application_directory + u"\\" + std::u16string(name.begin(), name.end()));
	if (!resolved || !resolved->exists || !std::filesystem::is_regular_file(resolved->host))
		return std::nullopt;
	return lowered(resolved->host.string());
}

uint64_t NativeX86Loader::find(const std::string &name) const
{
	const auto key = path_key(name);
	const auto found = key ? held.find(*key) : held.end();
	return found == held.end() ? 0 : found->second.module->loaded.base();
}

bool NativeX86Loader::release(uint64_t handle)
{
	const auto found = std::find_if(held.begin(), held.end(), [&](const auto &item) { return item.second.module->loaded.base() == handle; });
	if (found == held.end())
		return false;
	if (--found->second.references)
		return true;
	const auto module = found->second.module;
	held.erase(found);
	if (call && module->image.entry) {
		const uint64_t arguments[] = {module->loaded.base(), 0, 0};
		const auto result = call(module->loaded.base() + module->image.entry, arguments);
		if (result.stop != NativeStop::returned)
			throw result;
	}
	return true;
}

uint64_t NativeX86Loader::load(std::string name)
{
	if (!call)
		return 0;
	const auto key = path_key(name);
	if (key)
		if (const auto found = held.find(*key); found != held.end()) {
			++found->second.references;
			return found->second.module->loaded.base();
		}
	staged.clear();
	const auto existing = modules.all().size();
	bool mapped = false;
	try {
		auto *root = bring(name);
		if (!root) {
			for (auto item = staged.rbegin(); item != staged.rend(); ++item)
				modules.remove(**item);
			return 0;
		}
		if (staged.empty())
			return root->loaded.base();
		modules.bind_imports();
		// Dependencies start before the library that needs them: the order the imports were followed, reversed.
		for (auto item = staged.rbegin(); item != staged.rend(); ++item) {
			process.map_image((*item)->loaded);
			mapped = true;
			if (mapped_hook)
				mapped_hook(**item);
			if (tls)
				tls->add(**item);
		}
		for (auto item = staged.rbegin(); item != staged.rend(); ++item) {
			if (tls)
				for (const auto callback : tls->callbacks(**item)) {
					const uint64_t arguments[] = {(*item)->loaded.base(), 1, 0};
					const auto result = call(callback, arguments);
					if (result.stop != NativeStop::returned)
						throw result;
				}
			if (!(*item)->image.entry)
				continue;
			const uint64_t arguments[] = {(*item)->loaded.base(), 1, 0};
			const auto result = call((*item)->loaded.base() + (*item)->image.entry, arguments);
			if (result.stop != NativeStop::returned)
				throw result;
			if (!uint32_t(result.value)) {
				environment.set_last_error(1114);
				return 0;
			}
		}
		if (key)
			held[*key] = {root, 1};
		return root->loaded.base();
	} catch (const NativeResult &) {
		throw;
	} catch (const std::exception &failure) {
		if (trace())
			std::cerr << "raven: cannot load " << name << ": " << failure.what() << '\n';
		// An image that never reached the guest must not stay in the set, or every later import binding would trip over it.
		if (!mapped)
			for (auto item = staged.rbegin(); item != staged.rend(); ++item)
				modules.remove(**item);
		(void)existing;
		environment.set_last_error(126);
		return 0;
	}
}

}
