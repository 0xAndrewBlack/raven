#include "windows.h"
#include "api.h"
#include "nt/providers.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==3,"bootstrap and nonclient fixture required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate);
		check(bool(file) && file.tellg()>0,"cannot read nonclient fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short nonclient fixture");
		raven::ModuleSet modules; auto &entry=modules.add("client.exe",bytes);
		auto &user=modules.add("user32.dll",raven::runtime_provider("user32.dll",0x180000000ULL,raven::NativeDesktop::user_exports()));
		raven::LoadedImage *images[]={&entry.loaded,&user.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(3));
		for (const auto &symbol:user.exports) process.add_api_trap(user.loaded.base()+symbol.address);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);
		raven::DesktopMetrics metrics; metrics.caption=30; metrics.frame_x=9;
		raven::DesktopObjects objects(256*1024*1024,{48,16,32},metrics),defaults;
		raven::NativeWindows windows(process,environment,objects),other(process,environment,defaults);
		const auto call=[&](raven::NativeWindows &owner,const char *name,std::initializer_list<uint64_t> args) {
			const auto function=modules.resolve({"user32.dll",name,0,false,0});
			check(process.call(function,std::span(args.begin(),args.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"nonclient API did not trap");
			check(owner.dispatch(name),"nonclient API not dispatched");
			const auto result=process.resume(std::chrono::seconds(1));
			check(result.stop==raven::NativeStop::returned,"nonclient API did not return"); return result.value;
		};
		check(call(windows,"GetSystemMetrics",{4})==30 && call(other,"GetSystemMetrics",{4})==26 &&
			call(windows,"GetSystemMetrics",{32})==9,"metric owners shared global state");
		check(call(windows,"GetSystemMetrics",{11})==48 && call(windows,"GetSystemMetrics",{12})==16 &&
			call(other,"GetSystemMetrics",{11})==32 && call(other,"GetSystemMetrics",{12})==32,"icon metrics ignored the display owner");
		const auto page=process.map_memory(8192,PROT_READ | PROT_WRITE); process.protect_memory(page+4096,4096,PROT_NONE);
		const auto rect=page+4096-16;
		const std::array<uint8_t,16> input{0,0,0,0,0,0,0,0,64,1,0,0,240,0,0,0}; process.write_memory(rect,input);
		environment.set_last_error(71);
		check(call(windows,"AdjustWindowRectEx",{rect,0xcf0000,0,0})==1 && environment.last_error()==71,"configured rectangle adjustment failed");
		const auto output=process.read_memory(rect,16);
		const int32_t expected[]={-9,-34,329,244};
		for (unsigned i=0;i<4;++i) {
			uint32_t value=0; for (unsigned j=0;j<4;++j) value|=uint32_t(output[i*4+j])<<(j*8);
			check(int32_t(value)==expected[i],"adjustment ignored its owning metrics");
		}
		process.protect_memory(page,4096,PROT_READ);
		check(!call(windows,"AdjustWindowRect",{rect,0xcf0000,0}) && environment.last_error()==998 && process.read_memory(rect,16)==output,
			"readonly rectangle was modified");
		check(!call(windows,"AdjustWindowRectEx",{rect+4,0xcf0000,0,0}) && environment.last_error()==998 && process.read_memory(rect,16)==output,
			"guard-page rectangle was partially modified");
		metrics.frame_x=2; bool rejected=false;
		try { raven::DesktopObjects invalid(256*1024*1024,{},metrics); } catch (const std::runtime_error &) { rejected=true; }
		check(rejected,"inconsistent frame metrics accepted");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
