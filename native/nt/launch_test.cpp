#include "launch.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		const std::vector<std::string_view> arguments{"","plain","with space","with\ttab","a\"b","C:\\tail\\","\\\"","--","\xc3\xa9\xe4\xb8\xad\xf0\x9f\x99\x82"};
		const auto command=raven::launch_command_line(u"program.exe",arguments);
		check(command==u"\"program.exe\" \"\" \"plain\" \"with space\" \"with\ttab\" \"a\\\"b\" \"C:\\tail\\\\\" \"\\\\\\\"\" \"--\" \"\u00e9\u4e2d\U0001f642\"",
			"Windows command-line quoting differs");
		check(raven::launch_command_line(u"C:\\path\\",{})==u"\"C:\\path\\\"","argv zero incorrectly escaped pathname backslashes");
		check(raven::launch_utf16("\xc3\xa9\xe4\xb8\xad\xf0\x9f\x99\x82")==u"\u00e9\u4e2d\U0001f642","UTF-8 launch scalars changed");
		for (const auto input : {std::string("\xc0\x80",2),std::string("\xed\xa0\x80",3),std::string("\xf4\x90\x80\x80",4),
			std::string("\xe2\x82",2),std::string("\xe2\x41\x80",3),std::string("\x80",1),std::string("a\0b",3),std::string(32767,'a')}) {
			bool rejected=false;
			try { raven::launch_utf16(input); } catch (const std::runtime_error &) { rejected=true; }
			check(rejected,"malformed or oversized launch input produced success");
		}
		check(raven::launch_command_line(std::u16string(32764,u'a'),{}).size()==32766,"maximum command line rejected");
		for (const auto image : {std::u16string(),std::u16string(u"a\"b"),std::u16string(32765,u'a')}) {
			bool rejected=false;
			try { raven::launch_command_line(image,{}); } catch (const std::runtime_error &) { rejected=true; }
			check(rejected,"invalid argv-zero identity accepted");
		}
		if (argc==2) {
			std::ofstream output(argv[1],std::ios::binary);
			for (const auto character : command) { output.put(char(character&255));output.put(char(character>>8)); }
			output.put(0);output.put(0);check(bool(output),"cannot write command-line reference input");
		}
		std::cout<<"Windows launch quoting, UTF-8 scalar conversion and malformed/bounded input checks passed\n";
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
