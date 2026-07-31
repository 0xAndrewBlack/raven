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
		raven::DesktopObjects objects;
		const auto a=objects.register_class({"MiXeD",1,2}),b=objects.register_class({"mixed",2,3});
		const auto g=objects.register_class({"MIXED",1,4,0,0,{},0x4000});
		check(a && b && g && a!=b && a!=g && objects.window_class(a)->atom==objects.window_class(b)->atom &&
			objects.window_class(a)->atom==objects.window_class(g)->atom,"class definitions alias their public atom");
		const auto atom=objects.window_class(a)->atom;
		check(objects.find_class(1,"mixed")==a && objects.find_class(2,atom)==b && objects.find_class(3,atom)==g,"local/global class precedence differs");
		check(!objects.register_class({"mixed",1,5}) && !objects.register_class({"mixed",9,5,0,0,{},0x4000}),"duplicate class scope accepted");
		const auto wa=objects.add(raven::DesktopWindow{a,2,u"",0,0,1,1}),wb=objects.add(raven::DesktopWindow{b,3,u"",0,0,1,1});
		check(wa && wb && !objects.unregister_class(g) && objects.window(wa) && objects.window(wb),"public atom blocked unrelated global class deletion");
		check(objects.erase(wa) && !objects.unregister_class(a) && objects.window(wb) && objects.window_class(b)->procedure==3,"local class deletion damaged another definition");
		check(objects.erase(wb) && !objects.unregister_class(b) && !objects.bytes(),"class scope ownership leaked state");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
