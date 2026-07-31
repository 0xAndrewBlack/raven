#include "windows.h"
#include "api.h"
#include "nt/providers.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool condition,const char *message)
{
	if (!condition) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==3,"bootstrap and coordinate fixture required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024*1024,"invalid coordinate fixture");
		std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
		file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),static_cast<std::streamsize>(bytes.size()))),"cannot read coordinate fixture");
		raven::ModuleSet modules;
		auto &entry=modules.add("client.exe",std::move(bytes));
		auto &user=modules.add("user32.dll",raven::runtime_provider("user32.dll",0x180000000ULL,raven::NativeDesktop::user_exports()));
		raven::LoadedImage *images[]={&entry.loaded,&user.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(2));
		for (const auto &symbol:user.exports) process.add_api_trap(user.loaded.base()+symbol.address);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);
		raven::DesktopObjects objects;
		raven::NativeWindows windows(process,environment,objects);
		const auto window=objects.add(raven::DesktopWindow{0,0,u"",20,30,320,240});
		check(window,"window allocation failed");
		auto *record=objects.window(window);
		record->x=27; record->y=41; record->width=300; record->height=212;
		const auto call=[&](const char *name,std::initializer_list<uint64_t> args) {
			const auto function=modules.resolve({"user32.dll",name,0,false,0});
			check(process.call(function,std::span(args.begin(),args.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"coordinate API did not trap");
			check(windows.dispatch(name),"coordinate API not dispatched");
			const auto result=process.resume(std::chrono::seconds(1));
			check(result.stop==raven::NativeStop::returned,"coordinate API did not return");
			return result.value;
		};
		const auto page=process.map_memory(8192,PROT_READ | PROT_WRITE);
		process.protect_memory(page+4096,4096,PROT_NONE);
		const auto output=page+4096-16;
		const auto words=[&](uint64_t address,size_t count) {
			const auto data=process.read_memory(address,count*4);
			std::vector<int32_t> result(count);
			for (size_t i=0;i<count;++i) {
				uint32_t value=0;
				for (unsigned k=0;k<4;++k) value|=uint32_t(data[i*4+k])<<(k*8);
				result[i]=int32_t(value);
			}
			return result;
		};
		check(call("GetWindowRect",{window,output})==1 && words(output,4)==std::vector<int32_t>{20,30,340,270},"outer rectangle followed client geometry");
		check(call("GetClientRect",{window,output})==1 && words(output,4)==std::vector<int32_t>{0,0,300,212},"client extent differs");
		const auto point=page+4096-8;
		const std::array<uint8_t,8> zero{};
		process.write_memory(point,zero);
		environment.set_last_error(71);
		check(call("ClientToScreen",{window,point})==1 && words(point,2)==std::vector<int32_t>{27,41} && environment.last_error()==71,"client origin did not use live window state");
		check(call("ScreenToClient",{window,point})==1 && words(point,2)==std::vector<int32_t>{0,0},"inverse coordinate mapping differs");
		check(call("MapWindowPoints",{window,0,0x400000000000ULL,0})==(27U | (41U<<16)),"zero-point mapping accessed the buffer");
		check(call("MapWindowPoints",{0x12345,window,0x400000000000ULL,0})==0 && environment.last_error()==1400,"invalid zero-point source accepted");
		check(call("MapWindowPoints",{0,window,point,65537})==0 && environment.last_error()==120 && words(point,2)==std::vector<int32_t>{0,0},"unqualified point count mutated memory");
		check(call("MapWindowPoints",{0,window,0x400000000000ULL,1})==0 && environment.last_error()==998,"unreadable points accepted");
		process.protect_memory(page,4096,PROT_READ);
		check(call("ClientToScreen",{window,point})==0 && environment.last_error()==998 && words(point,2)==std::vector<int32_t>{0,0},"readonly point was modified");
		std::cout<<"Owned outer/client geometry, live mapping and guard-page negatives passed\n";
		return 0;
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
}
