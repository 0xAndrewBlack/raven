#include "objects.h"
#include <iostream>
#include <stdexcept>

static void check(bool value,const char *message)
{
	if (!value) throw std::runtime_error(message);
}

int main()
{
	try {
		const auto class_size=sizeof(raven::DesktopClass)+1+32;
		const auto window_size=sizeof(raven::DesktopWindow)+32;
		raven::DesktopObjects objects(class_size+2*window_size);
		const auto atom=objects.register_class({"x",1,2,0,32,std::vector<uint8_t>(32)});
		check(atom && objects.bytes()==class_size && objects.window_class(atom)->window_extra==32,"class extra budget differs");
		raven::DesktopWindow record{atom,2,u"",0,0,1,1}; record.extra.resize(32);
		const auto a=objects.add(record),b=objects.add(record);
		check(a && b && objects.bytes()==class_size+2*window_size && !objects.add(record),"window extra budget is not bounded");
		objects.window(a)->extra[0]=0x77; objects.window_class(atom)->extra[0]=0x44;
		check(!objects.window(b)->extra[0] && objects.window_class(objects.window(b)->class_id)->extra[0]==0x44,"window/class storage aliases incorrectly");
		check(objects.erase(a) && objects.bytes()==class_size+window_size && objects.window(b)->extra[0]==0,"window deletion damaged shared class data");
		check(objects.erase(b) && !objects.unregister_class(atom) && !objects.bytes(),"extra storage remains charged after deletion");
		raven::DesktopObjects small(class_size-1);
		check(!small.register_class({"x",1,2,0,32,std::vector<uint8_t>(32)}) && !small.bytes(),"failed class registration published extra data");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
