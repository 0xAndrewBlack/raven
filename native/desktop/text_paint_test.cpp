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
		check(argc==4,"bootstrap, text paint fixture and capture path required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate); check(bool(file) && file.tellg()>0,"cannot read text paint fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short text paint fixture");
		raven::ModuleSet modules; auto &entry=modules.add("text-paint.exe",bytes);
		bool ready=false,closed=false,lease_seen=false; unsigned removed=0; uint64_t window=0; std::vector<uint8_t> image;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
			check(handle && (!window || handle==window) && width==320 && height==120 && pixels.size()==320*120*4,"text presentation identity differs"); window=handle;
			if (title=="Raven native text")
				for (size_t at=84*320*4;at<pixels.size();at+=4)
					if (pixels[at]==100 && pixels[at+1]==53 && pixels[at+2]==12) lease_seen=true;
			if (title=="Text: ready") { image.assign(pixels.begin(),pixels.end()); ready=true; }
		};
		presentation.remove=[&](uint64_t handle) { check(handle==window,"removed wrong text window"); ++removed; };
		presentation.poll=[&](std::chrono::milliseconds) {
			std::vector<raven::DesktopEvent> events;
			if (ready && !closed) { closed=true; events.push_back({window,0x10}); }
			return events;
		};
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(10),{},{},presentation);
		check(result.stop==raven::NativeStop::returned && !result.value && ready && closed && lease_seen && removed==1,"guest text paint lifecycle failed");
		unsigned ink=0,white=0,clipped_ink=0;
		for (size_t at=0;at<image.size();at+=4) {
			if (image[at]==100 && image[at+1]==53 && image[at+2]==12) ++ink;
			else if (image[at]==31 && image[at+1]==44 && image[at+2]==166) {
				const auto x=at/4%320,y=at/4/320; check(x>=12 && x<42 && y>=12 && y<29,"text escaped the paint clip"); ++clipped_ink;
			} else if (image[at]==255 && image[at+1]==255 && image[at+2]==255) ++white;
			else check(!image[at] && !image[at+1] && !image[at+2],"unexpected text window color");
		}
		check(ink>500 && white>1000 && clipped_ink>20,"guest text did not paint actual pixels");
		std::ofstream output(argv[3],std::ios::binary);
		check(bool(output.write(reinterpret_cast<const char *>(image.data()),std::streamsize(image.size()))),"cannot save text paint capture");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
