#include "api.h"
#include "graphics/icon_file.h"
#include "nt/nls.h"

#include <array>
#include <new>
#include <stdexcept>

namespace raven {

bool NativeDesktop::extract_dispatch(std::string_view name)
{
	if (name!="PrivateExtractIconsW") return false;
	const auto args=process.api_arguments(8);
	const auto count=uint32_t(args[6]);
	uint64_t result=UINT32_MAX;
	std::vector<uint64_t> staged;
	try {
		if (!args[0]) throw uint32_t(87);
		if (uint32_t(args[7]) & ~64U) throw uint32_t(120);
		if (count>1024 || (!args[4] && args[5] && count)) throw uint32_t(120);
		std::u16string path;
		for (;;) {
			if (path.size()==32766) throw uint32_t(120);
			if (args[0]>UINT64_MAX-path.size()*2-2) throw uint32_t(87);
			const auto bytes=process.read_memory(args[0]+path.size()*2,2);
			const auto value=char16_t(uint16_t(bytes[0]) | uint16_t(bytes[1])<<8);
			if (!value) break;
			path.push_back(value);
		}
		if (path.starts_with(u".\\") || path.starts_with(u"./")) path.erase(0,2);
		if (path.find_first_of(u"/\\:")!=path.npos || path==u"." || path==u"..") throw uint32_t(120);
		if (path.empty()) throw uint32_t(87);
		auto filename=encode_utf8(path);
		for (auto &value:filename) if (value>='A' && value<='Z') value=char(value-'A'+'a');
		if (!source) throw uint32_t(120);
		const auto bytes=source(filename);
		if (!bytes) throw uint32_t(2);
		if (bytes->empty()) throw uint32_t(1006);
		if (bytes->size()>128*1024*1024) throw uint32_t(120);
		std::optional<IconFile> file;
		try { file.emplace(*bytes); }
		catch (const std::runtime_error &) { throw uint32_t(13); }
		environment.set_last_error(0);
		result=0;
		if (args[5]) {
			const std::array<uint8_t,4> invalid{255,255,255,255};process.write_memory(args[5],invalid);
		}
		if (!args[4]) {
			if (!args[5] || (bytes->size()>=4 && (*bytes)[0]==0 && (*bytes)[1]==0 && (*bytes)[2]==1 && (*bytes)[3]==0)) result=file->count();
		} else if (!count) {
			// ICO has one logical icon even when no output slots were requested.
			if (bytes->size()>=4 && (*bytes)[0]==0 && (*bytes)[1]==0 && (*bytes)[2]==1 && (*bytes)[3]==0) result=file->count();
		} else {
			const auto first=file->group(int32_t(uint32_t(args[1])));
			if (first) {
				const uint32_t cx=uint32_t(args[2]),cy=uint32_t(args[3]);
				const bool pair=(cx>>16) && (cy>>16);
				if (bool(cx>>16)!=bool(cy>>16) || (pair && (count & 1))) throw uint32_t(120);
				std::vector<uint32_t> ids;
				staged.reserve(size_t(count));ids.reserve(size_t(count));
				for (size_t group=*first;group<file->count() && staged.size()<count;++group) {
					std::optional<FileIcon> primary;
					for (unsigned part=0;part<(pair ? 2U : 1U) && staged.size()<count;++part) {
						const auto display=objects.display();
						const uint32_t width=((cx>>(part*16)) & 65535U) ? ((cx>>(part*16)) & 65535U) : display.width;
						const uint32_t height=((cy>>(part*16)) & 65535U) ? ((cy>>(part*16)) & 65535U) : display.height;
						if (width>8192 || height>8192 || uint64_t(width)*height>16*1024*1024) throw uint32_t(87);
						std::optional<FileIcon> image;
						try { image=file->image(group,width,height,display); }
						catch (const std::runtime_error &) { throw uint32_t(13); }
						if (!image) continue;
						if (!part) primary=image;
						// The pinned reference scales both packed outputs from the first selected payload.
						const auto icon=create_icon(primary ? primary->bytes : image->bytes,width,height,0);
						if (!icon) throw environment.last_error();
						staged.push_back(icon);ids.push_back(image->id);
					}
				}
				if (!staged.empty()) process.validate_write_memory(args[4],staged.size()*8);
				if (args[5] && !ids.empty()) process.validate_write_memory(args[5],ids.size()*4);
				std::vector<uint8_t> handles(staged.size()*8),identifiers(ids.size()*4);
				for (size_t i=0;i<staged.size();++i) {
					for (unsigned j=0;j<8;++j) handles[i*8+j]=uint8_t(staged[i]>>(j*8));
					for (unsigned j=0;j<4;++j) identifiers[i*4+j]=uint8_t(ids[i]>>(j*8));
				}
				if (!handles.empty()) process.write_memory(args[4],handles);
				if (args[5] && !identifiers.empty()) process.write_memory(args[5],identifiers);
				result=staged.size();staged.clear();
			}
		}
	} catch (uint32_t error) { result=UINT32_MAX;environment.set_last_error(error); }
	catch (const std::bad_alloc &) { result=UINT32_MAX;environment.set_last_error(8); }
	catch (...) { for (const auto icon:staged) objects.erase(icon);throw; }
	for (const auto icon:staged) objects.erase(icon);
	process.return_api(result);
	return true;
}

}
