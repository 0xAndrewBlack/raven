#include "menu.h"

#include <stdexcept>

namespace raven {

MenuTemplate decode_menu(std::span<const uint8_t> bytes)
{
	if (bytes.size()>1024*1024) throw std::runtime_error("menu resource exceeds limit");
	size_t offset=0,count=0;
	const auto read=[&](size_t size) {
		if (offset>bytes.size() || size>bytes.size()-offset) throw std::runtime_error("truncated menu resource");
		uint32_t value=0;
		for (size_t i=0;i<size;++i) value|=uint32_t(bytes[offset+i])<<(i*8);
		offset+=size;
		return value;
	};
	const auto version=read(2),skip=read(2);
	if (version>1 || (version==1 && skip<4)) throw std::runtime_error("invalid menu header");
	MenuTemplate result;
	if (version==1) result.help=read(4);
	offset=4+skip;
	if (offset>bytes.size() || (offset & (version ? 3U : 1U))) throw std::runtime_error("invalid menu offset");
	const auto items=[&](auto &&self,unsigned depth)->std::vector<MenuTemplateItem> {
		if (depth>64) throw std::runtime_error("menu nesting exceeds limit");
		std::vector<MenuTemplateItem> output;
		for (;;) {
			if (++count>4096) throw std::runtime_error("menu item count exceeds limit");
			MenuTemplateItem item;
			uint32_t flags;
			if (version) {
				offset=(offset+3)&~size_t(3);
				item.type=read(4); item.state=read(4); item.id=read(4); flags=read(2);
				if (flags & ~0x81U) throw std::runtime_error("invalid extended menu flags");
			} else {
				flags=read(2);
				item.type=flags & 0x6b64U; item.state=flags & 0x100bU;
				if (!(flags & 0x10)) item.id=read(2);
				if (flags & ~0x7bffU) throw std::runtime_error("invalid standard menu flags");
			}
			for (uint32_t word=read(2);word;word=read(2)) item.text.push_back(char16_t(word));
			if (flags & (version ? 1U : 0x10U)) {
				if (version) offset=(offset+3)&~size_t(3);
				item.submenu_help=version ? read(4) : 0;
				item.children=self(self,depth+1);
			} else if (!version && item.text.empty() && !item.id) item.type|=0x800;
			if (item.type & 0x800) item.state|=3;
			output.push_back(std::move(item));
			if (flags & 0x80) return output;
		}
	};
	result.items=items(items,0);
	return result;
}

}
