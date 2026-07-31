#include "nt/providers.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

static void check(bool value,const std::string &message)
{
	if (!value) throw std::runtime_error(message);
}

int main(int argc,char **argv)
{
	try {
		check(argc==4,"bootstrap, text fixture and output directory required");
		std::ifstream file(argv[2],std::ios::binary | std::ios::ate); check(bool(file) && file.tellg()>0,"cannot read text fixture");
		std::vector<uint8_t> bytes(size_t(file.tellg())); file.seekg(0);
		check(bool(file.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short text fixture");
		raven::ModuleSet modules; auto &entry=modules.add("text.exe",bytes);
		const auto result=raven::run_native_process(modules,entry,argv[1],std::chrono::seconds(30));
		check(result.stop==raven::NativeStop::returned && !result.value,"SDK text workflow returned "+std::to_string(result.value));
		const auto frames=modules.resolve({"text.exe","text_frames",0,false,0})-entry.loaded.base();
		const auto pixels=modules.resolve({"text.exe","text_pixels",0,false,0})-entry.loaded.base();
		const auto data=entry.loaded.data(); check(frames+4<=data.size() && pixels+390*512*64*4<=data.size(),"text snapshots exceed loaded image");
		check((uint32_t(data[size_t(frames)])|(uint32_t(data[size_t(frames+1)])<<8))==390,"text frame count differs");
		std::filesystem::create_directories(argv[3]);
		for (size_t i=0;i<390;++i) {
			std::ofstream output(std::filesystem::path(argv[3])/(std::to_string(i)+".bgra"),std::ios::binary);
			const auto image=data.subspan(size_t(pixels)+i*512*64*4,512*64*4);
			check(bool(output.write(reinterpret_cast<const char *>(image.data()),std::streamsize(image.size()))),"cannot save native text frame");
		}
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
