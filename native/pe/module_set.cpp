#include "module_set.h"

#include <algorithm>
#include <charconv>
#include <fcntl.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace raven {

static std::string module_name(std::string name)
{
	if (name.empty() || name == "." || name == "..")
		throw std::runtime_error("invalid module identity");
	for (auto &character : name) {
		if (character == '/' || character == '\\' || character == ':' || static_cast<unsigned char>(character) < 32)
			throw std::runtime_error("module identity must be a basename");
		if (character >= 'A' && character <= 'Z')
			character = static_cast<char>(character + ('a' - 'A'));
	}
	if (name.find('.') == std::string::npos)
		name += ".dll";
	return name;
}

std::optional<ModuleBytes> ModuleBytes::map(const std::filesystem::path &path)
{
	const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
	if (descriptor < 0)
		return std::nullopt;
	struct stat status{};
	void *address = MAP_FAILED;
	if (::fstat(descriptor, &status) == 0 && status.st_size > 0)
		address = ::mmap(nullptr, size_t(status.st_size), PROT_READ, MAP_PRIVATE, descriptor, 0);
	::close(descriptor);
	if (address == MAP_FAILED)
		return std::nullopt;
	const size_t size = size_t(status.st_size);
	ModuleBytes result;
	result.mapping = std::shared_ptr<const void>(address, [size](const void *mapped) { ::munmap(const_cast<void *>(mapped), size); });
	result.view = {static_cast<const uint8_t *>(address), size};
	return result;
}

PEModule::PEModule(std::string name, ModuleBytes bytes, uint64_t base)
	: name(std::move(name)), bytes(std::move(bytes)), image(std::span<const uint8_t>(this->bytes)), loaded(image, base),
	imports(image.imports()), exports(image.exports())
{
	for (size_t index = 0; index < exports.size(); ++index)
		for (const auto &export_name : exports[index].names)
			export_names.emplace(export_name, index);
}

PEModule &ModuleSet::add(std::string name, ModuleBytes bytes)
{
	const PEImage image(bytes);
	const uint64_t limit = image.is_64 ? 0x800000000000ULL : 0x100000000ULL;
	uint64_t base = image.image_base;
	if (!base || base % 65536 || base >= limit || image.image_size > limit - base)
		throw std::runtime_error("invalid guest image base");
	const auto overlap = [&](uint64_t candidate) {
		for (const auto &[key, previous] : modules) {
			const uint64_t start = previous->loaded.base();
			const uint64_t end = start + previous->loaded.data().size();
			if (candidate < end && start < candidate + image.image_size)
				return (end + 65535) & ~uint64_t(65535);
		}
		return uint64_t(0);
	};
	if (overlap(base)) {
		base = image.is_64 ? 0x180000000ULL : 0x10000000ULL;
		for (;;) {
			if (base >= limit || image.image_size > limit - base)
				throw std::runtime_error("no guest address available for PE module");
			const uint64_t next = overlap(base);
			if (!next)
				break;
			base = next;
		}
	}
	return add(std::move(name), std::move(bytes), base);
}

PEModule &ModuleSet::add(std::string name, ModuleBytes bytes, uint64_t base)
{
	name = module_name(std::move(name));
	if (modules.contains(name))
		throw std::runtime_error("duplicate PE module: " + name);
	auto module = std::make_unique<PEModule>(name, std::move(bytes), base);
	for (const auto &[key, previous] : modules) {
		if (base < previous->loaded.base() + previous->loaded.data().size() &&
			previous->loaded.base() < base + module->loaded.data().size())
			throw std::runtime_error("overlapping PE module addresses: " + name + " and " + key);
		if (module->image.is_64 != previous->image.is_64)
			throw std::runtime_error("mixed PE32/PE64 module graph");
	}
	auto &result = *module;
	modules.emplace(name, std::move(module));
	return result;
}

void ModuleSet::add_alias(std::string name, std::string target)
{
	name = module_name(std::move(name));
	target = module_name(std::move(target));
	if (modules.contains(name) || !modules.contains(target))
		throw std::runtime_error("module alias needs a free name and a loaded target");
	aliases[name] = target;
}

const std::map<std::string, std::unique_ptr<PEModule>> &ModuleSet::all() const { return modules; }

void ModuleSet::remove(const PEModule &module)
{
	const auto found = modules.find(module.name);
	if (found == modules.end() || found->second.get() != &module)
		throw std::runtime_error("PE removal requires an owned module");
	modules.erase(found);
}

uint64_t ModuleSet::resolve(const PEImport &symbol) const
{
	std::set<std::pair<std::string, uint32_t>> chain;
	return resolve(symbol.module, symbol.name, symbol.ordinal, symbol.by_ordinal, chain);
}

std::vector<const PEModule *> ModuleSet::resolution_path(const PEImport &symbol) const
{
	std::set<std::pair<std::string, uint32_t>> chain;
	std::vector<const PEModule *> path;
	resolve(symbol.module, symbol.name, symbol.ordinal, symbol.by_ordinal, chain, &path);
	return path;
}

uint64_t ModuleSet::resolve(std::string module, std::string name, uint32_t ordinal, bool by_ordinal,
	std::set<std::pair<std::string, uint32_t>> &chain, std::vector<const PEModule *> *path) const
{
	module = module_name(std::move(module));
	if (const auto alias = aliases.find(module); alias != aliases.end() && !modules.contains(module))
		module = alias->second;
	const auto found = modules.find(module);
	if (found == modules.end())
		throw std::runtime_error("missing PE module: " + module);
	const auto &target = *found->second;
	if (path)
		path->push_back(&target);
	auto exported = target.exports.end();
	if (by_ordinal)
		exported = std::find_if(target.exports.begin(), target.exports.end(), [&](const auto &entry) { return entry.ordinal == ordinal; });
	else if (const auto named = target.export_names.find(name); named != target.export_names.end())
		exported = target.exports.begin() + std::ptrdiff_t(named->second);
	else
		// An export added after the module was built is not indexed.
		exported = std::find_if(target.exports.begin(), target.exports.end(), [&](const auto &entry) {
			return std::find(entry.names.begin(), entry.names.end(), name) != entry.names.end();
		});
	if (exported == target.exports.end() || !exported->address)
		throw std::runtime_error("missing PE export: " + module + "!" + (by_ordinal ? "#" + std::to_string(ordinal) : name));
	if (!chain.emplace(module, exported->ordinal).second || chain.size() > 256)
		throw std::runtime_error("cyclic or excessive PE forwarder chain");
	if (exported->forwarder.empty())
		return target.loaded.base() + exported->address;
	const auto separator = exported->forwarder.rfind('.');
	if (separator == std::string::npos || separator == 0 || separator + 1 == exported->forwarder.size())
		throw std::runtime_error("invalid PE forwarder: " + exported->forwarder);
	const auto forwarded_name = exported->forwarder.substr(separator + 1);
	uint32_t forwarded_ordinal = 0;
	const bool forwarded_by_ordinal = forwarded_name[0] == '#';
	if (forwarded_by_ordinal) {
		const char *begin = forwarded_name.data() + 1;
		const char *end = forwarded_name.data() + forwarded_name.size();
		const auto parsed = std::from_chars(begin, end, forwarded_ordinal);
		if (parsed.ec != std::errc{} || parsed.ptr != end)
			throw std::runtime_error("invalid PE forwarder ordinal");
	}
	return resolve(exported->forwarder.substr(0, separator), forwarded_name,
		forwarded_ordinal, forwarded_by_ordinal, chain, path);
}

size_t ModuleSet::bind_imports()
{
	struct Binding { PEModule *module; uint32_t address; size_t width; uint64_t value; };
	std::vector<Binding> bindings;
	// Every import that cannot be resolved is reported at once, the first one leading, so that a graph is fixed in one pass.
	std::vector<std::string> unresolved, labels;
	for (const auto &[name, module] : modules) {
		const size_t width = module->image.is_64 ? 8 : 4;
		for (const auto &symbol : module->imports) {
			uint64_t value = 0;
			try {
				value = resolve(symbol);
			} catch (const std::runtime_error &failure) {
				if (std::string_view(failure.what()).starts_with("missing PE ")) {
					unresolved.emplace_back(failure.what());
					labels.push_back(symbol.module + "!" + (symbol.by_ordinal ? "#" + std::to_string(symbol.ordinal) : symbol.name));
					continue;
				}
				throw;
			}
			if (width == 4 && value > UINT32_MAX)
				throw std::runtime_error("PE32 import target exceeds address space");
			// Import addresses must occupy actual headers or section bytes, not image holes.
			for (size_t byte = 0; byte < width; ++byte) {
				const uint64_t address = uint64_t(symbol.iat_address) + byte;
				const bool mapped = address < module->image.headers_size ||
					std::any_of(module->image.sections.begin(), module->image.sections.end(), [&](const auto &section) {
						return address >= section.address && address < uint64_t(section.address) +
							std::max(section.virtual_size, section.file_size);
					});
				if (!mapped)
					throw std::runtime_error("PE IAT targets an image hole: " + name);
			}
			bindings.push_back({module.get(), symbol.iat_address, width, value});
		}
	}
	if (!unresolved.empty()) {
		std::string message = unresolved.front();
		if (unresolved.size() > 1) {
			message += " (all unresolved:";
			for (size_t index = 0; index < labels.size() && index < 400; ++index)
				message += " " + labels[index];
			message += labels.size() > 400 ? " ...)" : ")";
		}
		throw std::runtime_error(message);
	}
	// Commit only after every import resolves; failed binding leaves all images unchanged.
	for (const auto &binding : bindings) {
		auto data = binding.module->loaded.data();
		for (size_t byte = 0; byte < binding.width; ++byte)
			data[binding.address + byte] = static_cast<uint8_t>(binding.value >> (byte * 8));
	}
	return bindings.size();
}

}
