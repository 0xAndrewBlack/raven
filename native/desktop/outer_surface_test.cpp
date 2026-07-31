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
		check(argc>=3 && argc<=5,"bootstrap and outer surface fixture required");
		const bool input=argc>3 && std::string_view(argv[3])=="input";
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0,"cannot read outer surface fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short outer surface fixture");
		raven::ModuleSet modules; auto &entry=modules.add("outer-surface.exe",bytes);
		unsigned frames=0,removed=0; uint64_t window=0;
		std::vector<uint8_t> final;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
			check(handle && (!window || window==handle) && title=="outer surface" && width==320 && height==240 && pixels.size()==320*240*4,"outer surface identity differs");
			window=handle; final.assign(pixels.begin(),pixels.end()); ++frames;
		};
		presentation.remove=[&](uint64_t handle) { check(handle==window,"removed wrong outer surface"); ++removed; };
		bool injected=false;
		presentation.poll=[&](std::chrono::milliseconds) {
			std::vector<raven::DesktopEvent> events;
			if (input && !injected) {
				check(window && frames>=6,"input was requested before drawing completed");
				injected=true;
				events.push_back({window,0,0,0,raven::DesktopEventKind::pointer_motion,3,4});
				events.push_back({window,0,0,0,raven::DesktopEventKind::pointer_motion,19,24});
			}
			return events;
		};
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(10),{},{},presentation);
		check(result.stop==raven::NativeStop::returned && !result.value && frames>=6 && removed==1,"SDK outer surface workflow failed");
		check(!input || injected,"client input was not delivered");
		unsigned ink=0;
		for (unsigned y=0;y<240;++y) for (unsigned x=0;x<320;++x) {
			const auto at=(y*320+x)*4;
			if (x<7 || x>=307 || y<11 || y>=223)
				check(final[at]==255 && !final[at+1] && !final[at+2],"client drawing damaged the outer border");
			if (final[at]==255 && final[at+1]==255 && final[at+2]==255) ++ink;
		}
		check(ink>0,"client text was not presented");
		if (argc==5) {
			check(std::string_view(argv[3])=="capture","invalid outer surface capture option");
			std::ofstream output(argv[4],std::ios::binary | std::ios::trunc);
			output.write(reinterpret_cast<const char *>(final.data()),std::streamsize(final.size()));
			check(bool(output),"cannot save outer surface pixels");
		}
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
