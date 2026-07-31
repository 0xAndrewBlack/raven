#include "objects.h"
#include "pe/loaded_image.h"
#include "pe/resources.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

static void check(bool condition,const char *message)
{
	if (!condition) throw std::runtime_error(message);
}

static std::vector<uint8_t> read_file(const char *path)
{
	std::ifstream file(path,std::ios::binary|std::ios::ate);
	check(bool(file) && file.tellg()>0 && file.tellg()<1024*1024*1024,"invalid menu fixture");
	std::vector<uint8_t> bytes(static_cast<size_t>(file.tellg())); file.seekg(0);
	check(bool(file.read(reinterpret_cast<char *>(bytes.data()),static_cast<std::streamsize>(bytes.size()))),"cannot read menu fixture");
	return bytes;
}

static void rejected(std::span<const uint8_t> bytes)
{
	bool failure=false;
	try { raven::decode_menu(bytes); } catch (const std::runtime_error &) { failure=true; }
	check(failure,"malformed menu accepted");
}

int main(int argc,char **argv)
{
	try {
		check(argc==2 || argc==3,"menu image and optional dump required");
		const bool dump=argc==3;
		const auto bytes=read_file(argv[1]); raven::PEImage image(bytes); raven::LoadedImage loaded(image,image.image_base);
		unsigned resources=0;
		for (const auto &resource:image.resources()) {
			if (resource.type!=raven::ResourceKey(uint32_t(4))) continue;
			++resources;
			const auto payload=loaded.data().subspan(resource.data_address,resource.size);
			const auto definition=raven::decode_menu(payload);
			for (size_t size=0;size<payload.size();++size) {
				// Resource alignment can leave padding after the terminal item.
				try { raven::decode_menu(payload.first(size)); }
				catch (const std::runtime_error &) { continue; }
				check(payload.size()-size<=3,"truncated menu item accepted");
			}
			auto invalid=std::vector<uint8_t>(payload.begin(),payload.end()); invalid[0]=2; rejected(invalid);
			invalid.assign(payload.begin(),payload.end()); invalid[2]=0xff; invalid[3]=0xff; rejected(invalid);
			raven::DesktopObjects objects;
			const auto root=objects.load_menu(definition),second=objects.load_menu(definition);
			check(root && second && root!=second,"menu loads alias handles");
			const auto traversal=[&](auto &&self,uint64_t handle,unsigned depth)->void {
				const auto *menu=objects.menu(handle); check(menu!=nullptr,"submenu handle missing");
				if (dump) std::cout<<"menu depth="<<depth<<" count="<<menu->items.size()<<'\n';
				for (size_t i=0;i<menu->items.size();++i) {
					const auto &item=menu->items[i];
					if (dump) {
						std::cout<<"item depth="<<depth<<" position="<<i<<" id="<<item.id<<" type="<<item.type<<" state="<<item.state<<" submenu="<<(item.submenu!=0)<<" text=";
						for (const auto word:item.text) std::cout<<std::hex<<std::setfill('0')<<std::setw(4)<<unsigned(word);
						std::cout<<std::dec<<'\n';
					}
					if (item.submenu) {
						check(objects.menu(item.submenu)->parent==handle && !objects.erase(item.submenu),"submenu ownership lost");
						self(self,item.submenu,depth+1);
					}
				}
			};
			traversal(traversal,root,0);
			const auto used=objects.bytes(); check(used>0,"menu memory was not charged");
			check(objects.erase(root) && objects.menu(second) && objects.bytes()==used/2,"recursive menu release damaged another tree");
			check(objects.erase(second) && !objects.count() && !objects.bytes(),"menu memory leaked");
			raven::DesktopObjects limited(used/2-1);
			bool exhausted=false;
			try { limited.load_menu(definition); } catch (uint32_t error) { exhausted=error==8; }
			check(exhausted && !limited.count() && !limited.bytes(),"partial menu allocation was retained");
		}
		check(resources>0,"menu resource missing");
		std::vector<uint8_t> deep{0,0,0,0};
		for (unsigned i=0;i<66;++i) deep.insert(deep.end(),{0x90,0,0,0});
		deep.insert(deep.end(),{0x80,0,1,0,0,0}); rejected(deep);
		std::vector<uint8_t> many{0,0,0,0};
		for (unsigned i=0;i<4097;++i) many.insert(many.end(),{0,0,1,0,0,0});
		many[many.size()-6]=0x80; rejected(many);
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
