#include <cstring>
#include "object_api.h"
#include "providers.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

static size_t descriptors()
{
	return size_t(std::distance(std::filesystem::directory_iterator("/proc/self/fd"),std::filesystem::directory_iterator{}));
}

int main(int argc,char **argv)
{
	try {
		check(argc==4,"bootstrap, SDK executable and output path required");
		const auto fd=open(argv[3],O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC,0600);
		check(fd>=0,"cannot open file contract output");
		raven::NativeObjects objects;
		const auto inherited=objects.inherit_file(fd);
		check(!inherited.status && objects.file_type(inherited.value).value==1,"disk inheritance or type differs");
		const uint8_t marker[]={1,0,2,3};
		check(objects.write_file(inherited.value,marker).value==4 && lseek(fd,0,SEEK_CUR)==4,"inherited file offset or binary output differs");
		check(objects.set_event(inherited.value,true).status==0xc0000024U && objects.query_event(inherited.value).status==0xc0000024U &&
			objects.wait(inherited.value,0,std::chrono::steady_clock::now()).status==0xc0000024U,"file handle accepted as event");
		check(!objects.close(inherited.value) && objects.file_type(inherited.value).status==0xc0000008U && fcntl(fd,F_GETFD)>=0,
			"file close changed host descriptor or retained guest access");
		raven::NativeObjects limited(0);
		const auto before=descriptors();
		for (size_t i=0;i<16;++i) check(limited.inherit_file(fd).status==0xc000009aU,"file handle budget ignored");
		check(descriptors()==before && !limited.count() && limited.inherit_file(-1).status==0xc0000008U,"failed inheritance leaked descriptors");
		int pipes[2];check(!pipe2(pipes,O_CLOEXEC),"cannot create pipe control");
		const auto pipe=objects.inherit_file(pipes[1]);
		// A pipe write reaches the other end byte for byte (the pipe is empty, so the write cannot block).
		const auto piped=objects.write_file(pipe.value,marker);
		uint8_t received[8]{};
		check(!pipe.status && objects.file_type(pipe.value).value==3 && !piped.status && piped.value==sizeof marker &&
			read(pipes[0],received,sizeof received)==ssize_t(sizeof marker) && !memcmp(received,marker,sizeof marker),
			"pipe write did not deliver its bytes");
		objects.close(pipe.value);close(pipes[0]);close(pipes[1]);
		const auto readonly=open(argv[3],O_RDONLY | O_CLOEXEC);check(readonly>=0,"cannot open readonly control");
		const auto read_handle=objects.inherit_file(readonly);close(readonly);
		check(objects.write_file(read_handle.value,marker).status==0xc0000022U,"readonly file accepted output");
		objects.close(read_handle.value);
		raven::ModuleSet modules;
		auto &proxy=modules.add("proxy.exe",raven::environment_provider("kernel32.dll",0x180000000ULL));
		raven::LoadedImage *images[]{&proxy.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(5));
		raven::NativeEnvironment environment(process,proxy.loaded.base(),1,1);
		const auto live=objects.inherit_file(fd);
		environment.prepare_parameters({u"proxy.exe",u"proxy.exe"},{UINT64_MAX,live.value,UINT64_MAX});
		raven::NativeObjectAPI api(process,environment,objects,std::chrono::steady_clock::now()+std::chrono::seconds(5));
		const auto address=modules.resolve({"proxy.exe","GetLastError",0,false,0});process.add_api_trap(address);
		const auto invoke=[&](std::string_view name,std::initializer_list<uint64_t> args) {
			check(process.call(address,std::span(args.begin(),args.size()),std::chrono::seconds(1)).stop==raven::NativeStop::api,"file API proxy did not stop");
			check(environment.dispatch(name) || api.dispatch(name),"file API did not dispatch");
			const auto result=process.resume(std::chrono::seconds(1));
			check(result.stop==raven::NativeStop::returned,"file API did not return");return result.value;
		};
		check(invoke("GetStdHandle",{uint32_t(-11)})==live.value,"standard handle is not the owned file");
		const auto memory=process.map_memory(8192,PROT_READ | PROT_WRITE);
		process.write_memory(memory,marker);process.protect_memory(memory+4096,4096,PROT_NONE);
		const auto position=lseek(fd,0,SEEK_CUR);
		for (const auto output : {memory+4096,memory+4094}) {
			check(!invoke("WriteFile",{live.value,memory,4,output,0}) && environment.last_error()==998 && lseek(fd,0,SEEK_CUR)==position,
				"bad byte-count output changed the host file");
		}
		process.protect_memory(memory,4096,PROT_READ);
		check(!invoke("WriteFile",{live.value,memory,4,memory,0}) && environment.last_error()==998 && lseek(fd,0,SEEK_CUR)==position,
			"readonly byte-count output changed the host file");
		process.protect_memory(memory,4096,PROT_READ | PROT_WRITE);
		check(!invoke("WriteFile",{live.value,memory+4096,4,memory+16,0}) && environment.last_error()==998 && lseek(fd,0,SEEK_CUR)==position,
			"unreadable input changed the host file");
		check(!invoke("WriteFile",{live.value,memory,1048577,memory+16,0}) && environment.last_error()==120 &&
			!invoke("WriteFile",{live.value,memory,4,memory+16,memory}) && environment.last_error()==120 && lseek(fd,0,SEEK_CUR)==position,
			"unsupported file mode changed the host file");
		process.unmap_memory(memory);objects.close(live.value);
		check(!ftruncate(fd,0) && lseek(fd,0,SEEK_SET)==0,"cannot reset SDK output");
		std::ifstream input(argv[2],std::ios::binary | std::ios::ate);
		check(bool(input) && input.tellg()>0 && input.tellg()<1024*1024,"invalid file SDK executable");
		std::vector<uint8_t> bytes(size_t(input.tellg()));input.seekg(0);
		check(bool(input.read(reinterpret_cast<char *>(bytes.data()),std::streamsize(bytes.size()))),"short file SDK input");
		raven::ModuleSet sdk;auto &entry=sdk.add("client.exe",std::move(bytes));
		raven::NativeLaunch launch{u"client.exe",u"client.exe"};launch.standard_fds={-1,fd,fd};launch.startup.flags=256;
		const auto result=raven::run_native_process(sdk,entry,argv[1],std::chrono::seconds(5),{},{},{},launch);
		check(result.stop==raven::NativeStop::returned && !result.value,"compiled standard-file SDK failed");
		std::array<uint8_t,8> actual{};
		check(lseek(fd,0,SEEK_SET)==0 && read(fd,actual.data(),actual.size())==4 &&
			std::equal(actual.begin(),actual.begin()+4,std::array<uint8_t,4>{'A',0,'B','\n'}.begin()),"SDK file bytes or length differ");
		close(fd);
		std::cout<<"Native owned standard files, binary writes, shared offset, lifetime and memory boundaries passed\n";
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n';return 1; }
	return 0;
}
