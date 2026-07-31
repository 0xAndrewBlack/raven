#include "windows.h"
#include <algorithm>

namespace raven {

static void put(std::span<uint8_t> bytes,size_t at,uint64_t value,size_t width)
{
	for (size_t i=0;i<width;++i) bytes[at+i]=uint8_t(value>>(i*8));
}

uint64_t NativeWindows::class_info(std::string_view name,std::span<const uint64_t> args)
{
	if (name=="GetClassNameW" || name=="GetClassNameA") {
		const auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
		const auto count=uint32_t(args[2]); if (count<=1) throw uint32_t(122);
		const auto &value=objects.window_class(window->class_id)->name;
		const auto length=std::min(size_t(count-1),value.size()),width=name=="GetClassNameW" ? size_t(2) : size_t(1);
		std::vector<uint8_t> bytes((length+1)*width);
		for (size_t i=0;i<length;++i) bytes[i*width]=uint8_t(value[i]);
		process.write_memory(args[1],bytes); return length;
	}
	const auto id=atom(args[1],args[0]);
	const auto *definition=objects.window_class(id); if (!definition) throw uint32_t(1411);
	const bool extended=name=="GetClassInfoExW";
	const auto old=process.read_memory(args[2],extended ? 80 : 72);
	std::vector<uint8_t> bytes(old.size());
	if (extended) std::copy_n(old.begin(),4,bytes.begin());
	put(bytes,extended ? 4 : 0,definition->style,4);
	put(bytes,8,definition->procedure,8);
	put(bytes,16,definition->extra.size(),4); put(bytes,20,definition->window_extra,4);
	put(bytes,24,args[0],8); put(bytes,48,definition->background,8); put(bytes,64,args[1],8);
	process.write_memory(args[2],bytes);
	return definition->atom;
}

}
