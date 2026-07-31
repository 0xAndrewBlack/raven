#include "nt/providers.h"
#include "objects.h"
#include "api.h"

#include <algorithm>
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
			raven::DesktopObjects objects(sizeof(raven::DesktopDC)+2*sizeof(raven::DesktopRegion)+32);
			raven::DesktopRegion first;first.add({1,2,5,6});
			const auto a=objects.add(first),b=objects.add(raven::DesktopRegion{}),dc=objects.add(raven::DesktopDC{0,0});
			check(a && b && dc && objects.select_clip(dc,first),"clip owner rejected its budgeted snapshot");
			raven::DesktopRegion second;second.add({1,2,5,6});second.add({8,9,12,13});
			const auto used=objects.bytes();
			check(!objects.replace_region(b,second) && objects.bytes()==used && objects.region(b)->empty(),"failed region update damaged state or budget");
			check(!objects.select_clip(dc,second) && objects.bytes()==used && objects.dc(dc)->application_clip->equals(first),"failed clip update damaged its snapshot");
			check(objects.erase(a) && objects.dc(dc)->application_clip->contains(2,3),"deleting the region invalidated a selected copy");
			check(objects.select_clip(dc,std::nullopt) && objects.replace_region(b,first) && objects.erase(dc) && objects.erase(b) &&
				!objects.bytes() && !objects.count(),"region/DC lifetime leaked owned bytes");
		}
		{
			raven::DesktopObjects objects;
			const auto window=objects.add(raven::DesktopWindow{0,1,u"",0,0,16,12});
			const auto bitmap=objects.add(raven::DesktopBitmap{16,12,32,std::vector<uint8_t>(16*12*4)});
			const auto dc=objects.add(raven::DesktopDC{bitmap,bitmap,window});objects.window(window)->dc=dc;
			check(objects.invalidate(window,{1,1,6,6},false) && objects.invalidate(window,{9,7,15,11},false),"paint setup rejected its update regions");
			objects.start_paint(window);raven::DesktopRegion application;application.add({0,0,3,12});
			check(objects.select_clip(dc,application) && objects.dc(dc)->contains(2,2) && !objects.dc(dc)->contains(4,2) &&
				!objects.dc(dc)->contains(0,0),"application clip replaced the paint restriction");
			check(objects.select_clip(dc,std::nullopt) && objects.dc(dc)->contains(4,2) && !objects.dc(dc)->contains(0,0),"removing application clipping escaped BeginPaint");
			objects.finish_paint(window);check(!objects.dc(dc)->clip && !objects.dc(dc)->application_clip,"paint completion retained transient clipping");
			check(objects.erase(dc) && objects.erase(bitmap) && objects.erase(window) && !objects.bytes(),"paint and application clips leaked budget");
		}
		check(argc>=3 && argc<=5,"bootstrap, clipping fixture, optional paint mode and output prefix required");
		const bool paint=argc>=4 && std::string_view(argv[3])=="--paint";
		const char *prefix=paint ? (argc==5 ? argv[4] : nullptr) : (argc==4 ? argv[3] : nullptr);
		std::ifstream file(argv[2],std::ios::binary|std::ios::ate);check(bool(file) && file.tellg()>0,"cannot read clipping fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short clipping fixture");
		raven::ModuleSet modules;auto &entry=modules.add("clip.exe",bytes);
		unsigned frames=0,removed=0;std::vector<uint8_t> last;raven::DesktopPresentation presentation;
		if(paint){
			presentation.present=[&](uint64_t window,std::string_view title,uint32_t width,uint32_t height,std::span<const uint8_t> pixels){
				check(window && title=="clip paint" && width==16 && height==12 && pixels.size()==16*12*4,"clip paint presentation differs");
				++frames;last.assign(pixels.begin(),pixels.end());
			};
			presentation.remove=[&](uint64_t){++removed;};
		}
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(20),{},{},presentation);
		if(result.stop!=raven::NativeStop::returned || result.value)std::cerr<<"clipping SDK stop="<<int(result.stop)<<" value="<<result.value<<'\n';
		check(result.stop==raven::NativeStop::returned && !result.value,"clipping SDK contract differs");
		const std::array<std::pair<std::string_view,size_t>,3> outputs=paint ?
			std::array<std::pair<std::string_view,size_t>,3>{{{"paint_rows",8*16*4},{"paint_pixels",16*12*4},{"paint_raw_pixels",16*12*4}}} :
			std::array<std::pair<std::string_view,size_t>,3>{{{"clip_rows",128*16*4},{"clip_pixels",32*16*12*4},{"clip_errors",16*2*4}}};
		for(const auto &[name,size]:outputs) {
			const auto found=std::find_if(entry.exports.begin(),entry.exports.end(),[&](const auto &symbol) {
				return std::find(symbol.names.begin(),symbol.names.end(),name)!=symbol.names.end();
			});check(found!=entry.exports.end(),"clipping evidence export missing");
			const auto data=entry.loaded.data().subspan(found->address,size);
			if(paint && name=="paint_pixels")check(frames>=3 && removed==1 && std::equal(last.begin(),last.end(),data.begin()),"application clipping damaged root presentation or lifetime");
			if(prefix){
				std::ofstream output(std::string(prefix)+"."+std::string(name),std::ios::binary);
				output.write(reinterpret_cast<const char *>(data.data()),std::streamsize(data.size()));check(bool(output),"cannot save clipping evidence");
			}
		}
		auto &gdi=*modules.all().at("gdi32.dll");raven::LoadedImage *images[]={&entry.loaded,&gdi.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(3));
		for(const auto &symbol:gdi.exports)process.add_api_trap(gdi.loaded.base()+symbol.address);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);raven::DesktopObjects objects;
		raven::NativeResources resources(process,environment,modules,entry);raven::NativeDesktop desktop(process,environment,objects,resources);
		const auto call=[&](const char *name,std::initializer_list<uint64_t> arguments){
			const auto function=modules.resolve({"gdi32.dll",name,0,false,0});
			check(process.call(function,std::span(arguments.begin(),arguments.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"clip policy API did not trap");
			check(desktop.dispatch(name),"clip policy API not dispatched");const auto run=process.resume(std::chrono::seconds(1));
			check(run.stop==raven::NativeStop::returned,"clip policy API did not return");return run.value;
		};
		const auto region=call("CreateRectRgn",{1,2,5,6});check(region,"clip policy region allocation failed");
		const auto count=objects.count(),used=objects.bytes();environment.set_last_error(71);
		check(!call("CreateRectRgn",{0,0,0x4000000,1}) && environment.last_error()==120 && objects.count()==count && objects.bytes()==used,
			"unsupported region geometry allocated an object");
		environment.set_last_error(71);
		check(!call("OffsetRgn",{region,0x4000000,0}) && environment.last_error()==120 && objects.region(region)->contains(2,3) && objects.bytes()==used,
			"unsupported region offset mutated its source");
		const auto dc=objects.add(raven::DesktopDC{0,0});environment.set_last_error(71);
		check(!call("DPtoLP",{dc,0,65537}) && environment.last_error()==120,"unsupported point count returned success");
	} catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
	return 0;
}
