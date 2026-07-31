#include "nt/providers.h"
#include "objects.h"
#include "api.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
	if(!value)throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try{
		{
			raven::DesktopObjects objects(2*sizeof(raven::DesktopDC)+sizeof(raven::DesktopPen));
			const auto pen=objects.add(raven::DesktopPen{0x112233}),a=objects.add(raven::DesktopDC{0,0}),b=objects.add(raven::DesktopDC{0,0});
			check(pen && a && b && !objects.add(raven::DesktopPen{}),"pen owner ignored its byte budget");
			check(objects.select_pen(a,pen)==raven::desktop_stock_pen+1 && objects.select_pen(b,pen)==raven::desktop_stock_pen+1 &&
				objects.delete_pen(pen) && objects.pen(pen),"selected pen lifetime differs");
			check(objects.select_pen(a,raven::desktop_stock_pen+1)==pen && objects.pen(pen) && objects.erase(b) && !objects.pen(pen),"deferred pen deletion missed the last DC");
			check(objects.erase(a) && !objects.count() && !objects.bytes(),"pen lifetime leaked owned bytes");
		}
		check(argc==4 || argc==5,"bootstrap, drawing fixture, mode and optional output prefix required");
		const bool pen=std::string_view(argv[3])=="--pen";check(pen || std::string_view(argv[3])=="--text","unknown drawing fixture mode");
		std::ifstream file(argv[2],std::ios::binary|std::ios::ate);check(bool(file) && file.tellg()>0,"cannot read drawing fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short drawing fixture");
		raven::ModuleSet modules;auto &entry=modules.add("drawing.exe",bytes);
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(30));
		if(argc==5){
			std::vector<std::pair<std::string_view,size_t>> outputs=pen ?
				std::vector<std::pair<std::string_view,size_t>>{{"pen_pixels",132*32*32*4},{"pen_rows",132*8*4}} :
				std::vector<std::pair<std::string_view,size_t>>{{"draw_pixels",200*64*32*4},{"draw_rows",200*8*4},{"fit_rows",192*20*4}};
			for(const auto &[name,size]:outputs){
				const auto found=std::find_if(entry.exports.begin(),entry.exports.end(),[&](const auto &symbol){return std::find(symbol.names.begin(),symbol.names.end(),name)!=symbol.names.end();});
				check(found!=entry.exports.end(),"drawing evidence export missing");const auto data=entry.loaded.data().subspan(found->address,size);
				std::ofstream output(std::string(argv[4])+"."+std::string(name),std::ios::binary);output.write(reinterpret_cast<const char *>(data.data()),std::streamsize(data.size()));check(bool(output),"cannot save drawing evidence");
			}
		}
		if(result.stop!=raven::NativeStop::returned || result.value)std::cerr<<"drawing SDK stop="<<int(result.stop)<<" value="<<result.value<<'\n';
		check(result.stop==raven::NativeStop::returned && !result.value,"drawing SDK contract differs");
		auto &gdi=*modules.all().at("gdi32.dll");raven::LoadedImage *images[]={&entry.loaded,&gdi.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(3));for(const auto &symbol:gdi.exports)process.add_api_trap(gdi.loaded.base()+symbol.address);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);raven::NativeResources resources(process,environment,modules,entry);
		raven::DesktopObjects objects;raven::NativeDesktop desktop(process,environment,objects,resources);
		const auto call=[&](const char *name,std::initializer_list<uint64_t> arguments){
			const auto function=modules.resolve({"gdi32.dll",name,0,false,0});check(process.call(function,std::span(arguments.begin(),arguments.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"drawing policy API did not trap");
			check(desktop.dispatch(name),"drawing policy API not dispatched");const auto run=process.resume(std::chrono::seconds(1));check(run.stop==raven::NativeStop::returned,"drawing policy API did not return");return run.value;
		};
		const auto bitmap=objects.add(raven::DesktopBitmap{16,16,32,std::vector<uint8_t>(16*16*4)}),dc=objects.add(raven::DesktopDC{bitmap,bitmap});
		const auto count=objects.count(),used=objects.bytes();environment.set_last_error(71);
		check(!call("CreatePen",{1,1,0}) && environment.last_error()==120 && objects.count()==count && objects.bytes()==used,"unsupported pen style allocated a resource");
		check(!call("CreatePen",{0,3,0}) && environment.last_error()==120,"wide pen returned a cosmetic approximation");
		check(!call("LineTo",{dc,1048577,0}) && environment.last_error()==120 && !objects.dc(dc)->position_x && !objects.dc(dc)->position_y &&
			std::all_of(objects.bitmap(bitmap)->bits.begin(),objects.bitmap(bitmap)->bits.end(),[](uint8_t byte){return !byte;}),"unsupported line geometry damaged position or pixels");
		if(!pen){
			check(!call("ExtTextOutW",{dc,0,0,0x10,0,0,1,0}) && environment.last_error()==120,"unqualified glyph-index mode returned success");
			check(!call("ExtTextOutW",{dc,0,0,0,0,0,4097,0}) && environment.last_error()==87,"unqualified text length returned success");
		}
	}catch(const std::exception &error){std::cerr<<error.what()<<'\n';return 1;}
	return 0;
}
