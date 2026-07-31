#include "api.h"
#include "graphics/icon_file.h"
#include "nt/providers.h"
#include "nt/nls.h"

#include <fstream>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

static std::vector<uint8_t> read(const char *path)
{
	std::ifstream file(path,std::ios::binary|std::ios::ate);
	check(bool(file) && file.tellg()>0,"cannot read extraction fixture");
	std::vector<uint8_t> bytes(size_t(file.tellg()));file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short extraction fixture");return bytes;
}

int main(int argc,char **argv)
{
	try {
		check(argc==5 || argc==6,"bootstrap, client, PE icons and ICO required");
		const auto client=read(argv[2]),pe=read(argv[3]),ico=read(argv[4]);
		const auto source=[&](std::string_view name)->std::optional<std::vector<uint8_t>> {
			if (name=="icons.dll") return pe;
			if (name=="icons.ico" || name=="caf\xc3\xa9.ico") return ico;
			if (name=="empty.bin") return std::vector<uint8_t>{};
			if (name=="not-icon.txt") return std::vector<uint8_t>{'t','e','x','t'};
			return std::nullopt;
		};
		for (const auto bytes:{std::vector<uint8_t>{0,0,2,0},std::vector<uint8_t>{'B','M'},std::vector<uint8_t>{'R','I','F','F'}}) {
			bool rejected=false;try { raven::IconFile unsupported(bytes); } catch(uint32_t error) { rejected=error==120; }
			check(rejected,"unsupported icon format reported no icons");
		}
		for (const auto bytes:{std::vector<uint8_t>{0,0,1,0},std::vector<uint8_t>{0,0,1,0,1,0},std::vector<uint8_t>{'M','Z'}}) {
			bool rejected=false;try { raven::IconFile malformed(bytes); } catch(const std::runtime_error &) { rejected=true; }
			check(rejected,"malformed icon file accepted");
		}
		raven::ModuleSet modules;auto &entry=modules.add("client.exe",client);
		const auto run=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(10),source);
		check(run.stop==raven::NativeStop::returned && !run.value,"SDK extraction fixture failed");
		if (argc==6) {
			const auto found=std::find_if(entry.exports.begin(),entry.exports.end(),[](const auto &symbol) {
				return std::find(symbol.names.begin(),symbol.names.end(),"icon_digests")!=symbol.names.end();
			});
			check(found!=entry.exports.end(),"icon digest export missing");std::ofstream output(argv[5]);
			const auto data=entry.loaded.data().subspan(found->address,128);
			for (unsigned i=0;i<16;++i) {
				uint64_t digest=0;for(unsigned j=0;j<8;++j)digest|=uint64_t(data[i*8+j])<<(j*8);
				if (!digest) break;
				output<<"row="<<std::dec<<i<<" digest="<<std::hex<<std::setfill('0')<<std::setw(16)<<digest<<'\n';
			}
			check(bool(output),"cannot write icon digests");
			const auto pixels=std::find_if(entry.exports.begin(),entry.exports.end(),[](const auto &symbol) {
				return std::find(symbol.names.begin(),symbol.names.end(),"icon_payloads")!=symbol.names.end();
			});check(pixels!=entry.exports.end(),"icon pixel export missing");
			const auto bytes=entry.loaded.data().subspan(pixels->address,16*8192);
			std::ofstream binary(std::string(argv[5])+".pixels",std::ios::binary);
			binary.write(reinterpret_cast<const char *>(bytes.data()),std::streamsize(bytes.size()));check(bool(binary),"cannot write icon pixels");

		}

		check(raven::encode_utf8(u"caf\u00e9 \U0001f600")=="caf\xc3\xa9 \xf0\x9f\x98\x80","UTF-8 filename encoding differs");
		for (const auto text:{std::u16string(1,char16_t(0xd800)),std::u16string(1,char16_t(0xdc00))}) {
			bool rejected=false;try { raven::encode_utf8(text); } catch(uint32_t error) { rejected=error==87; }
			check(rejected,"unpaired filename surrogate accepted");
		}
		for (size_t size=0;size<ico.size();++size) {
			if (size>1024 && size+1<ico.size()) continue;
			bool accepted=false;
			try { raven::IconFile truncated{std::span<const uint8_t>(ico).first(size)};accepted=truncated.count()!=0; }
			catch (const std::runtime_error &) {}
			check(!accepted,"truncated ICO accepted");
		}
		auto &user=*modules.all().at("user32.dll");
		raven::LoadedImage *images[]={&entry.loaded,&user.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(3));
		const auto function=modules.resolve({"user32.dll","PrivateExtractIconsW",0,false,0});process.add_api_trap(function);
		raven::NativeEnvironment environment(process,entry.loaded.base(),1,1);
		raven::NativeResources resources(process,environment,modules,entry);
		raven::DesktopObjects objects;raven::NativeDesktop desktop(process,environment,objects,resources);desktop.set_source(source);
		const auto page=process.map_memory(8192,PROT_READ|PROT_WRITE);process.protect_memory(page+4096,4096,PROT_NONE);
		const auto names=process.map_memory(4096,PROT_READ|PROT_WRITE);
		const auto set_name=[&](std::u16string_view path) {
			std::vector<uint8_t> bytes((path.size()+1)*2);
			for(size_t i=0;i<path.size();++i){bytes[i*2]=uint8_t(path[i]);bytes[i*2+1]=uint8_t(path[i]>>8);}process.write_memory(names,bytes);
		};
		const auto call=[&](uint64_t handles,uint64_t ids,uint32_t count=1,uint32_t flags=0) {
			const uint64_t args[]={names,0,32,32,handles,ids,count,flags};
			check(process.call(function,args,std::chrono::seconds(1)).stop==raven::NativeStop::api,"extraction API did not trap");
			check(desktop.dispatch("PrivateExtractIconsW"),"extraction API not dispatched");
			const auto result=process.resume(std::chrono::seconds(1));check(result.stop==raven::NativeStop::returned,"extraction API did not return");return result.value;
		};
		set_name(u"icons.ico");
		const uint64_t poisoned[]={names,0,32,32,page,0,(1ULL<<40)|1,0};
		check(process.call(function,poisoned,std::chrono::seconds(1)).stop==raven::NativeStop::api,"UINT width API did not trap");
		desktop.dispatch("PrivateExtractIconsW");check(process.resume(std::chrono::seconds(1)).value==1 && objects.count()==1,"UINT argument used unspecified upper bits");
		const auto poisoned_handle=process.read_memory(page,8);uint64_t owned=0;for(unsigned i=0;i<8;++i)owned|=uint64_t(poisoned_handle[i])<<(i*8);
		check(objects.erase(owned),"UINT width control leaked an icon");
		set_name(u".\\ICONS.ICO");
		check(call(page+4096-8,page+4096-12)==1 && objects.count()==1,"page-boundary extraction failed");
		const auto handles=process.read_memory(page+4096-8,8);uint64_t handle=0;for(unsigned i=0;i<8;++i)handle|=uint64_t(handles[i])<<(i*8);
		check(objects.icon(handle) && !objects.icon(handle)->shared && objects.erase(handle) && !objects.count(),"extracted icon lifetime differs");
		set_name(u"caf\u00e9.ico");check(call(0,0,0)==1,"Unicode filename failed");
		set_name(u"Z:\\icons.ico");check(call(0,0,0)==UINT32_MAX && environment.last_error()==120,"unsupported namespace disguised as missing file");
		set_name(u"icons.ico");check(call(page,0,1025)==UINT32_MAX && environment.last_error()==120 && !objects.count(),"extraction count budget ignored");
		check(call(page,0,1,1)==UINT32_MAX && environment.last_error()==120,"unsupported monochrome flag accepted");
		check(call(0,page,1)==UINT32_MAX && environment.last_error()==120,"unqualified null-handle output combination accepted");
		raven::DesktopObjects tiny(1);raven::NativeDesktop limited(process,environment,tiny,resources);limited.set_source(source);
		const uint64_t args[]={names,0,32,32,page,0,1,0};
		check(process.call(function,args,std::chrono::seconds(1)).stop==raven::NativeStop::api,"budget API did not trap");
		limited.dispatch("PrivateExtractIconsW");check(process.resume(std::chrono::seconds(1)).value==UINT32_MAX && environment.last_error()==8 && !tiny.count(),"icon budget leaked a resource");
		set_name(u"icons.dll");
		const auto saved=process.read_memory(names+512,16);
		bool guarded=false;
		try { call(names+512,page+4092,2); } catch (const std::runtime_error &) { guarded=true; }
		check(guarded && !objects.count() && process.read_memory(names+512,16)==saved,"guarded IDs published handles or leaked staged icons");
		process.return_api(0);process.resume(std::chrono::seconds(1));
		set_name(u"icons.ico");
		process.protect_memory(page,4096,PROT_READ);
		check(process.call(function,args,std::chrono::seconds(1)).stop==raven::NativeStop::api,"readonly API did not trap");
		bool rejected=false;try { desktop.dispatch("PrivateExtractIconsW"); } catch(const std::runtime_error &) { rejected=true; }
		check(rejected && !objects.count(),"readonly output leaked an icon");process.return_api(0);process.resume(std::chrono::seconds(1));
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
