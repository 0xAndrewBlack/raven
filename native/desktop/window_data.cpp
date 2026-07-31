#include "windows.h"

namespace raven {

static uint64_t extra_value(std::span<uint8_t> bytes,int32_t index,size_t width,bool write,uint64_t value)
{
	if (index<0 || size_t(index)>bytes.size() || width>bytes.size()-size_t(index)) throw uint32_t(1413);
	uint64_t previous=0;
	for (size_t i=0;i<width;++i) previous|=uint64_t(bytes[size_t(index)+i])<<(i*8);
	if (write)
		for (size_t i=0;i<width;++i) bytes[size_t(index)+i]=uint8_t(value>>(i*8));
	return previous;
}

uint64_t NativeWindows::long_value(std::string_view name,std::span<const uint64_t> args)
{
	auto *window=objects.window(args[0]); if (!window) throw uint32_t(1400);
	const bool write=name.starts_with("Set"),wide=name.find("Ptr")!=name.npos,klass=name.find("Class")!=name.npos;
	const auto index=int32_t(uint32_t(args[1])); const auto value=write ? args[2] : 0;
	const auto width=wide ? size_t(8) : size_t(4);
	if (klass) {
		auto *definition=objects.window_class(window->class_id);
		if (index>=0) return extra_value(definition->extra,index,width,write,value);
		if (write) {
			if (index==-32 || index==-20 || index==-18 || index==-16 || index==-26 || index==-24 || index==-10 || index==-14 || index==-12 || index==-8 || index==-34) throw uint32_t(120);
			throw uint32_t(1413);
		}
		uint64_t result=0;
		if (index==-32) result=definition->atom;
		else if (index==-26) result=definition->style;
		else if (index==-20) result=definition->extra.size();
		else if (index==-18) result=definition->window_extra;
		else if (index==-16) result=definition->instance;
		else if (index==-24) { if (name.ends_with("A")) throw uint32_t(120); result=definition->procedure; }
		else if (index==-10) result=definition->background;
		else if (index!=-26 && index!=-14 && index!=-12 && index!=-8 && index!=-34) throw uint32_t(1413);
		return wide ? result : uint32_t(result);
	}
	if (index>=0) return extra_value(window->extra,index,width,write,value);
	if (index==-21) {
		const auto previous=window->userdata;
		if (write) window->userdata=wide ? value : uint64_t(int64_t(int32_t(uint32_t(value))));
		return wide ? previous : uint32_t(previous);
	}
	if (index==-4) {
		if (!wide) throw uint32_t(1413);
		if (name.ends_with("A")) throw uint32_t(120);
		const auto previous=window->procedure;
		if (write) { if (!value) throw uint32_t(120); window->procedure=value; }
		return previous;
	}
	if (index==-6) {
		if (!wide) throw uint32_t(1413);
		if (write) throw uint32_t(120);
		return window->instance;
	}
	if (index==-16 || index==-20 || index==-8 || index==-12) {
		if (write) throw uint32_t(120);
		const auto result=index==-16 ? window->style : index==-20 ? window->ex_style : index==-8 ? window->parent : window->child_id;
		return wide ? result : uint32_t(result);
	}
	throw uint32_t(1413);
}

}
