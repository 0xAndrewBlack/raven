#include "loader.h"

#include <algorithm>
#include <stdexcept>

namespace raven {

void validate_native_image(const PEImage &image,std::string_view name)
{
	if (!image.is_64) throw std::runtime_error("native PE32 execution is not implemented");
	if (image.directories[13].address || image.directories[13].size)
		for (const auto &descriptor:image.delay_imports())
			if (!(image.file_span(descriptor.descriptor_address,4)[0] & 1))
				throw std::runtime_error("native legacy-VA delay helper execution is not implemented: "+std::string(name));
	if (image.directories[14].address || image.directories[14].size)
		throw std::runtime_error("native process requires unsupported CLR initialization: "+std::string(name));
}

void load_initial_dependencies(ModuleSet &modules,
	const std::function<std::optional<std::vector<uint8_t>>(std::string_view)> &source,
	std::span<const std::string_view> native_modules)
{
	if (!source) return;
	std::vector<PEModule *> pending,staged;
	for (const auto &[name,module]:modules.all()) pending.push_back(module.get());
	try {
		for (size_t index=0;index<pending.size();++index)
			for (const auto &symbol:pending[index]->imports)
				for (;;) {
					try { modules.resolve(symbol);break; }
					catch (const std::runtime_error &error) {
						const std::string_view message=error.what();
						if (!message.starts_with("missing PE module: ")) throw;
						const std::string identity(message.substr(19));
						if (std::find(native_modules.begin(),native_modules.end(),identity)!=native_modules.end()) break;
						if (modules.all().size()>=10000) throw std::runtime_error("native DLL graph exceeds module limit");
						auto bytes=source(identity);
						if (!bytes) throw;
						const PEImage image(*bytes);validate_native_image(image,identity);
						if (!(image.characteristics & 0x2000)) throw std::runtime_error("native startup dependency must be a DLL: "+identity);
						staged.reserve(staged.size()+1);pending.reserve(pending.size()+1);
						auto &module=modules.add(identity,std::move(*bytes));
						staged.push_back(&module);pending.push_back(&module);
					}
				}
	} catch (...) {
		for (auto item=staged.rbegin();item!=staged.rend();++item) modules.remove(**item);
		throw;
	}
}

}
