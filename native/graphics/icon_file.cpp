#include "icon_file.h"

#include <algorithm>
#include <stdexcept>

namespace raven {

static uint32_t read(std::span<const uint8_t> bytes,size_t offset,size_t size)
{
	if (offset>bytes.size() || size>bytes.size()-offset) throw std::runtime_error("truncated icon file");
	uint32_t value=0;for(size_t i=0;i<size;++i)value|=uint32_t(bytes[offset+i])<<(i*8);return value;
}

IconFile::IconFile(std::span<const uint8_t> bytes):bytes(bytes)
{
	if (bytes.size()>=2 && bytes[0]=='M' && bytes[1]=='Z') {
		if (bytes.size()>=64) {
			const auto header=read(bytes,60,4);
			if (header<=bytes.size() && bytes.size()-header>=2 && bytes[header]=='N' && bytes[header+1]=='E') throw uint32_t(120);
		}
		pe.emplace(bytes);resources=pe->resources();
		for (const auto &item:resources)
			if (item.type==ResourceKey(uint32_t(14)) && std::find(groups.begin(),groups.end(),item.name)==groups.end()) groups.push_back(item.name);
	} else if (bytes.size()>=4 && !read(bytes,0,2) && read(bytes,2,2)==1) {
		const auto count=read(bytes,4,2);
		if (!count || size_t(count)*16>bytes.size()-6) throw std::runtime_error("invalid ICO directory");
		for (uint32_t i=0;i<count;++i) {
			const auto offset=6+size_t(i)*16;
			const auto size=read(bytes,offset+8,4),address=read(bytes,offset+12,4);
			if (bytes[offset+3] || !size || address<6+size_t(count)*16 || address>bytes.size() || size>bytes.size()-address)
				throw std::runtime_error("ICO image exceeds file payload");
			entries.push_back({bytes[offset] ? uint32_t(bytes[offset]) : 256,bytes[offset+1] ? uint32_t(bytes[offset+1]) : 256,
				uint16_t(read(bytes,offset+6,2)),size,uint16_t(i+1)});
			images.push_back(bytes.subspan(address,size));
		}
	} else if ((bytes.size()>=4 && !read(bytes,0,2) && read(bytes,2,2)==2) ||
		(bytes.size()>=2 && bytes[0]=='B' && bytes[1]=='M') ||
		(bytes.size()>=4 && std::equal(bytes.begin(),bytes.begin()+4,"RIFF"))) throw uint32_t(120);
}

size_t IconFile::count() const { return pe ? groups.size() : entries.empty() ? 0 : 1; }

std::optional<size_t> IconFile::group(int32_t index) const
{
	if (!pe) return !entries.empty() && index<=0 ? std::optional<size_t>(0) : std::nullopt;
	if (index>=0) return size_t(index)<groups.size() ? std::optional<size_t>(size_t(index)) : std::nullopt;
	const auto id=uint32_t(-int64_t(index));
	const auto found=std::find(groups.begin(),groups.end(),ResourceKey(id));
	return found==groups.end() ? std::nullopt : std::optional<size_t>(size_t(found-groups.begin()));
}

const PEResource *IconFile::resource(uint32_t type,const ResourceKey &name,uint32_t language) const
{
	std::vector<const PEResource *> candidates;
	for (const auto &item:resources) if (item.type==ResourceKey(type) && item.name==name) candidates.push_back(&item);
	for (const auto desired:{language,language & 0x3ffU,0U}) {
		const auto found=std::find_if(candidates.begin(),candidates.end(),[&](const auto *item) { return item->language==desired; });
		if (found!=candidates.end()) return *found;
	}
	if (!language && candidates.size()==1) return candidates.front();
	if (!candidates.empty()) throw uint32_t(120);
	return nullptr;
}

std::optional<FileIcon> IconFile::image(size_t group,uint32_t width,uint32_t height,IconDisplay display) const
{
	if (!pe) {
		if (group || entries.empty()) return std::nullopt;
		const auto id=lookup_icon(entries,width,height,display,false);
		return id && size_t(id)<=images.size() ? std::optional<FileIcon>({images[id-1],uint32_t(id-1)}) : std::nullopt;
	}
	if (group>=groups.size()) return std::nullopt;
	const auto *directory=resource(14,groups[group],0);if (!directory) return std::nullopt;
	const auto available=decode_icon_group(pe->file_span(directory->data_address,directory->size));
	const auto id=lookup_icon(available,width,height,display,false);if (!id) return std::nullopt;
	const auto *payload=resource(3,ResourceKey(uint32_t(id)),directory->language);if (!payload) return std::nullopt;
	const auto expected=std::find_if(available.begin(),available.end(),[&](const auto &item) { return item.id==id; });
	if (expected==available.end() || expected->size!=payload->size) throw std::runtime_error("icon group image size differs");
	return FileIcon{pe->file_span(payload->data_address,payload->size),id};
}

}
