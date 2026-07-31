#pragma once

#include "loaded_image.h"

#include <map>
#include <memory>
#include <set>

namespace raven {

struct PEModule {
	PEModule(std::string name, std::vector<uint8_t> bytes, uint64_t base);
	std::string name;
	std::vector<uint8_t> bytes;
	PEImage image;
	LoadedImage loaded;
	std::vector<PEImport> imports;
	std::vector<PEExport> exports;
	bool runtime_api = false;
};

// Owns module bytes and shared images. Resolves only explicitly supplied modules.
class ModuleSet {
public:
	// Keep a free preferred base; relocate colliding images into graph-owned space.
	PEModule &add(std::string name, std::vector<uint8_t> bytes);
	PEModule &add(std::string name, std::vector<uint8_t> bytes, uint64_t base);
	// The process loader must release guest mappings and references before erasing an image.
	void remove(const PEModule &module);
	const std::map<std::string, std::unique_ptr<PEModule>> &all() const;
	uint64_t resolve(const PEImport &symbol) const;
	std::vector<const PEModule *> resolution_path(const PEImport &symbol) const;
	size_t bind_imports();

private:
	std::map<std::string, std::unique_ptr<PEModule>> modules;
	uint64_t resolve(std::string module, std::string name, uint32_t ordinal, bool by_ordinal,
		std::set<std::pair<std::string, uint32_t>> &chain, std::vector<const PEModule *> *path = nullptr) const;
};

}
