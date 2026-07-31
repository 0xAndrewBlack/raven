#include "bitblt.h"
#include "nt/providers.h"
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
		check(argc==2,"bootstrap required");
		raven::ModuleSet modules;
		auto &module=modules.add("kernel32.dll",raven::environment_provider("kernel32.dll",0x180000000));
		raven::LoadedImage *images[]{&module.loaded};
		raven::NativeProcess process(images,argv[1],std::chrono::seconds(2));
		raven::DesktopObjects objects;
		std::vector<uint8_t> source(4*3*4),destination(source.size(),0x73);
		for (size_t i=0;i<source.size();++i) source[i]=uint8_t(i*13);
		const auto sa=objects.add(raven::DesktopBitmap{4,3,32,source}),sb=objects.add(raven::DesktopBitmap{4,3,32,destination});
		const auto a=objects.add(raven::DesktopDC{sa,sa}),b=objects.add(raven::DesktopDC{sb,sb});
		check(sa && sb && a && b,"cannot create blit resources");
		objects.dc(a)->clip.emplace();
		objects.dc(b)->clip.emplace(); objects.dc(b)->clip->add({1,0,4,3}); objects.dc(b)->clip->subtract({2,1,3,2});
		uint64_t args[]{b,0,0,4,3,a,0,0,0x00cc0020};
		check(raven::bit_blt(process,objects,args),"blit incorrectly used source clipping");
		for (unsigned y=0;y<3;++y) for (unsigned x=0;x<4;++x) for (unsigned c=0;c<4;++c) {
			const size_t at=(y*4+x)*4+c;
			check(objects.bitmap(sb)->bits[at]==(x>=1 && !(x==2 && y==1) ? source[at] : 0x73),"blit escaped destination clip or missed a region");
		}
		objects.dc(b)->clip.reset(); objects.bitmap(sb)->bits=source;
		args[5]=b; args[1]=1; args[3]=3;
		check(raven::bit_blt(process,objects,args),"overlapping blit failed");
		for (unsigned y=0;y<3;++y) for (unsigned x=1;x<4;++x) for (unsigned c=0;c<4;++c)
			check(objects.bitmap(sb)->bits[(y*4+x)*4+c]==source[(y*4+x-1)*4+c],"overlapping source was not snapshotted");
		const auto before=objects.bitmap(sb)->bits;
		for (unsigned failure=0;failure<5;++failure) {
			args[0]=failure==0 ? 0 : b; args[5]=failure==1 ? 0 : a; args[8]=failure==2 ? 0x40cc0020 : 0x00cc0020; args[3]=failure==3 ? uint32_t(-1) : 3;
			if (failure==4) objects.bitmap(sa)->depth=1;
			bool rejected=false;
			try { raven::bit_blt(process,objects,args); } catch (uint32_t error) { rejected=error==(failure<2 ? 6U : 120U); }
			check(rejected && objects.bitmap(sb)->bits==before,"unsupported blit succeeded or mutated destination");
		}
		objects.bitmap(sa)->depth=32;
		args[0]=b; args[5]=a; args[3]=3; args[8]=0x00cc0020;
		const auto address=process.map_memory(4096,PROT_READ | PROT_WRITE);
		process.write_memory(address,before); objects.bitmap(sb)->address=address;
		process.protect_memory(address,4096,PROT_READ);
		bool rejected=false;
		try { raven::bit_blt(process,objects,args); } catch (const std::runtime_error &) { rejected=true; }
		check(rejected && process.read_memory(address,before.size())==before,"readonly blit damaged guest destination");
		process.unmap_memory(address);
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
