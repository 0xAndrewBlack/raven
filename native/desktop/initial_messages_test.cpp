#include "nt/providers.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool condition,const char *message)
{
	if (!condition) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==3,"bootstrap and initial-message fixture directory required");
		for (const auto name:{"client.exe","exit.exe"}) {
			std::ifstream file(std::filesystem::path(argv[2])/name,std::ios::binary | std::ios::ate);
			check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024*1024,"invalid initial-message fixture");
			std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg()));
			file.seekg(0);
			check(bool(file.read(reinterpret_cast<char *>(bytes.data()),static_cast<std::streamsize>(bytes.size()))),"cannot read initial-message fixture");
			raven::ModuleSet modules;
			auto &entry=modules.add(name,std::move(bytes));
			const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(2));
			if (std::string_view(name)=="client.exe")
				check(result.stop==raven::NativeStop::returned && !result.value,"initial size/move or destruction workflow failed");
			else {
				check(result.stop==raven::NativeStop::exited && result.value==0x1234,"ExitProcess inside initial WM_SIZE lost its terminal status");
				const auto phase=modules.resolve({name,"exit_phase",0,false,0})-entry.loaded.base();
				check(phase<entry.loaded.data().size() && entry.loaded.data()[size_t(phase)]==2,"initial callback exit did not reach its guest phase");
			}
		}
		std::cout<<"Initial size/move, callback destruction and terminal exit workflows passed\n";
		return 0;
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
}
