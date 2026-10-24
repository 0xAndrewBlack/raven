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
		check(argc==3,"bootstrap and raw-buffer fixture required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024,"invalid raw-buffer fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short raw-buffer fixture");
		raven::ModuleSet modules;
		auto &entry=modules.add("raw-buffer.exe",bytes);
		uint64_t window=0;
		bool ready=false,injected=false;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t,uint32_t,std::span<const uint8_t>) {
			window=handle; ready=title=="raw: ready";
		};
		presentation.poll=[&](std::chrono::milliseconds) {
			std::vector<raven::DesktopEvent> events;
			if (ready && !injected) {
				injected=true;
				events.push_back({window,0,0,0,raven::DesktopEventKind::keyboard_focus});
				events.push_back({window,0,0,0,raven::DesktopEventKind::pointer_relative,5,-3});
				events.push_back({window,0x110,1,0,raven::DesktopEventKind::pointer_button,6,7});
				events.push_back({window,0x110,0,0,raven::DesktopEventKind::pointer_button,6,7});
				events.push_back({window,120,0,0,raven::DesktopEventKind::pointer_wheel,6,7});
				events.push_back({window,0,0,0,raven::DesktopEventKind::pointer_relative,7,9});
			}
			return events;
		};
		const auto result=entry.image.is_64 ?
			raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),{},{},presentation) :
			raven::run_native_process_x86(modules,entry,argv[1],std::chrono::seconds(5),{},presentation);
		std::cout<<"Raw-buffer workflow returned "<<result.value<<"\n";
		check(result.stop==raven::NativeStop::returned && !result.value && injected,"raw-buffer workflow failed");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
