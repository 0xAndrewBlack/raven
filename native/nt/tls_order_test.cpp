#include "providers.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const std::filesystem::path &path)
{
	std::ifstream file(path,std::ios::binary | std::ios::ate);
	check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024,"invalid TLS order fixture");
	std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short TLS order fixture");
	return bytes;
}

int main(int argc,char **argv)
{
	try {
		check(argc==3,"bootstrap and TLS order fixture directory required");
		const std::filesystem::path directory(argv[2]);
		for (const bool shutdown : {false,true}) {
			raven::ModuleSet modules;
			auto &entry=modules.add("client.exe",read_file(directory/(shutdown ? "shutdown.exe" : "unload.exe")));
			unsigned loads=0;
			const auto source=[&](std::string_view name)->std::optional<std::vector<uint8_t>> {
				check(name=="tls-order.dll","unexpected TLS order dependency"); ++loads;
				return read_file(directory/name);
			};
			const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(5),source);
			if (result.stop!=raven::NativeStop::returned || result.value) {
				std::cerr<<"TLS/DllMain sequence failed: stop="<<int(result.stop)<<" value=0x"<<std::hex<<result.value<<'\n';
				return 1;
			}
			const auto offset=modules.resolve({"client.exe","sequence",0,false,0})-entry.loaded.base();
			const auto bytes=entry.loaded.data().subspan(size_t(offset),4);
			uint32_t sequence=0; for (unsigned i=0;i<4;++i) sequence|=uint32_t(bytes[i])<<(i*8);
			check(sequence==1234 && loads==1 && modules.all().contains("tls-order.dll")==shutdown,"DLL detach sequence, lifetime or load count differs");
		}
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
