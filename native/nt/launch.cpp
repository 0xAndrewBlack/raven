#include "launch.h"

#include <stdexcept>
#include <cstdint>

namespace raven {

std::u16string launch_utf16(std::string_view text)
{
	if (text.size()>131064) throw std::runtime_error("native launch input exceeds the UTF-16 limit");
	std::u16string result;
	for (size_t offset=0;offset<text.size();) {
		const auto first=static_cast<unsigned char>(text[offset++]);
		uint32_t value=first,minimum=0;size_t continuation=0;
		if (first>=0xc2 && first<=0xdf) { value=first&0x1f;minimum=0x80;continuation=1; }
		else if (first>=0xe0 && first<=0xef) { value=first&0x0f;minimum=0x800;continuation=2; }
		else if (first>=0xf0 && first<=0xf4) { value=first&7;minimum=0x10000;continuation=3; }
		else if (first>=0x80) throw std::runtime_error("native launch input is not UTF-8");
		if (continuation>text.size()-offset) throw std::runtime_error("truncated native launch UTF-8");
		for (size_t i=0;i<continuation;++i) {
			const auto byte=static_cast<unsigned char>(text[offset++]);
			if ((byte&0xc0)!=0x80) throw std::runtime_error("invalid native launch UTF-8 continuation");
			value=(value<<6)|(byte&0x3f);
		}
		if (!value || value<minimum || value>0x10ffff || (value>=0xd800 && value<=0xdfff))
			throw std::runtime_error("invalid native launch Unicode scalar");
		if (value<=0xffff) result.push_back(char16_t(value));
		else { value-=0x10000;result.push_back(char16_t(0xd800+(value>>10)));result.push_back(char16_t(0xdc00+(value&0x3ff))); }
		if (result.size()>32766) throw std::runtime_error("native launch input exceeds the UTF-16 limit");
	}
	return result;
}

std::u16string launch_command_line(std::u16string_view image,std::span<const std::string_view> arguments)
{
	if (image.empty() || image.size()>32764 || image.find(u'"')!=image.npos || image.find(u'\0')!=image.npos)
		throw std::runtime_error("invalid native command-line image identity");
	// argv[0] uses pathname quoting; later arguments are quoted only when they are empty or hold a space, a tab or a quote, as Windows
	// programs write them, and then escape backslashes before quotes. Programs that pass their own command line on rely on it.
	std::u16string result=u"\""+std::u16string(image)+u"\"";
	for (const auto argument : arguments) {
		const auto text=launch_utf16(argument);
		if (!text.empty() && text.find_first_of(u" \t\"")==text.npos) {
			result+=u" "+text;
			if (result.size()>32766) throw std::runtime_error("native command line exceeds the UTF-16 limit");
			continue;
		}
		result+=u" \"";
		size_t slashes=0;
		for (const auto character : text) {
			if (character==u'\\') { ++slashes;continue; }
			result.append(character==u'"' ? slashes*2+1 : slashes,u'\\');
			slashes=0;result.push_back(character);
		}
		result.append(slashes*2,u'\\');result.push_back(u'"');
		if (result.size()>32766) throw std::runtime_error("native command line exceeds the UTF-16 limit");
	}
	return result;
}

}
