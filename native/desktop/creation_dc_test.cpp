#include "nt/providers.h"
#include "desktop/objects.h"
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
		{
			raven::DesktopObjects objects;
			const auto atom=objects.register_class({"dc owner",1,1});
			const auto window=objects.add(raven::DesktopWindow{atom,1,u"",20,30,320,240});
			const auto bitmap=objects.add(raven::DesktopBitmap{320,240,32,std::vector<uint8_t>(320*240*4)});
			const auto font=objects.add(raven::DesktopFont{});
			raven::DesktopDC client{bitmap,bitmap,window}; client.leased=true; client.font=font;
			client.bounds=raven::DesktopRect{0,0,320,240}; client.clip.emplace(); client.clip->add({1,2,5,6});
			const auto dc=objects.add(client);
			raven::DesktopDC outer{bitmap,bitmap,window}; outer.leased=true;
			const auto frame=objects.add(outer);
			check(atom && window && bitmap && font && dc && frame && objects.delete_font(font),"cannot establish DC ownership check");
			auto *geometry=objects.window(window); geometry->x=27; geometry->y=41; geometry->width=300; geometry->height=212;
			objects.update_window_dcs(window);
			check(objects.dc(dc)->origin_x==7 && objects.dc(dc)->origin_y==11 && objects.dc(dc)->bounds->right==300 &&
				objects.dc(dc)->bounds->bottom==212 && objects.dc(dc)->clip->contains(1,2) && !objects.dc(frame)->bounds &&
				!objects.dc(frame)->origin_x && !objects.dc(frame)->origin_y,"DC rebase changed frame origin or logical clipping");
			objects.detach_window_dcs(window);
			check(!objects.dc(dc)->bitmap && !objects.dc(frame)->bitmap && !objects.dc(dc)->clip && objects.dc(dc)->font==font &&
				!objects.dc(dc)->contains(7,11),"detached DC retained drawable storage or lost its font");
			check(objects.erase(bitmap) && objects.erase(window) && !objects.unregister_class(atom) && objects.count()==3 &&
				objects.bytes()==2*sizeof(raven::DesktopDC)+sizeof(raven::DesktopFont),"detachment retained window backing or damaged accounting");
			check(objects.erase(dc) && !objects.font(font) && objects.erase(frame) && !objects.count() && !objects.bytes(),
				"final DC collection leaked selected resources");
		}
		check(argc==3 || argc==4,"bootstrap and creation DC fixture required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0,"cannot read creation DC fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short creation DC fixture");
		raven::ModuleSet modules; auto &entry=modules.add("creation-dc.exe",bytes);
		unsigned frames=0,removed=0; uint64_t visible=0;
		raven::DesktopPresentation presentation;
		presentation.present=[&](uint64_t handle,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels) {
			check(handle && (!visible || visible==handle) && title=="creation dc" && width==320 && height==240 && pixels.size()==320*240*4,"creation DC surface differs");
			visible=handle; ++frames;
		};
		presentation.remove=[&](uint64_t handle) { check(handle!=0,"removed an invalid creation surface"); ++removed; };
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(10),{},{},presentation);
		check(result.stop==raven::NativeStop::returned && !result.value && frames>=1 && frames<=3 && removed==(argc==4 ? 4U : 3U),"SDK creation DC lifecycle failed");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
