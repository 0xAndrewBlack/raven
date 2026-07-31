#include "nls.h"

#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==2,"CP1252 NT reference file required");
		std::ifstream file(argv[1],std::ios::binary);
		std::string expected(65536,'\0');
		check(bool(file.read(expected.data(),std::streamsize(expected.size()))) && file.get()==EOF,"invalid CP1252 reference size");
		std::u16string text;
		for (uint32_t value=0;value<65536;++value) text.push_back(char16_t(value));
		check(raven::encode_ansi(text,1252)==expected,"native CP1252 differs from the full NT reference");
		check(raven::encode_ansi(u"",1252).empty() && raven::encode_ansi(u"ASCII",1252)=="ASCII","empty or ASCII conversion differs");
		check(raven::encode_ansi(u"\u00e9\u4e2d\U0001f642",1252)==std::string("\xe9???",4),"best-fit/default/surrogate conversion differs");
		for (const uint32_t code_page : {0U,1251U,932U,65001U}) {
			bool rejected=false;
			try { raven::encode_ansi(u"",code_page); } catch (const std::runtime_error &) { rejected=true; }
			check(rejected,"unsupported code page produced apparent success");
		}
		std::cout<<"All 65536 native CP1252 code units match NT; unsupported code pages reject explicitly\n";
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
