#include "nt/providers.h"

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
		check(argc==3,"bootstrap and queue fixture required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024,"invalid queue fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short queue fixture");
		raven::ModuleSet modules;
		auto &entry=modules.add("queue.exe",bytes);
		unsigned frames=0,removed=0;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t,std::string_view,uint32_t,uint32_t,std::span<const uint8_t>) { ++frames; };
		presentation.remove=[&](uint64_t) { ++removed; };
		const auto result=entry.image.is_64 ?
			raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),{},{},presentation) :
			raven::run_native_process_x86(modules,entry,argv[1],std::chrono::seconds(5),{},presentation);
		std::cout<<"Queue workflow returned "<<result.value<<"\n";
		check(result.stop==raven::NativeStop::returned && !result.value && frames && removed==1,"queue workflow failed");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
