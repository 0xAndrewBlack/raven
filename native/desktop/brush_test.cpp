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
		raven::DesktopObjects objects(sizeof(raven::DesktopBrush)+2*sizeof(raven::DesktopDC));
		const auto brush=objects.add(raven::DesktopBrush{0x123456}),a=objects.add(raven::DesktopDC{0x10000,0x10000}),b=objects.add(raven::DesktopDC{0x10000,0x10000});
		check(brush && a && b && !objects.add(raven::DesktopBrush{0}),"brush budget differs");
		check(!objects.brush(a) && objects.brush(raven::desktop_stock_brush+5)->hollow,"brush kind or hollow stock differs");
		check(objects.select_brush(a,brush)==raven::desktop_stock_brush && objects.select_brush(b,brush)==raven::desktop_stock_brush,"shared brush selection failed");
		check(objects.delete_brush(brush) && objects.brush(brush)->pending_delete && objects.erase(a) && objects.brush(brush),"pending brush lifetime differs");
		check(objects.select_brush(b,raven::desktop_stock_brush)==brush && !objects.brush(brush),"final brush selection was not collected");
		check(objects.erase(b) && !objects.bytes() && !objects.count() && !objects.delete_brush(brush),"brush lifetime leaks budget or accepts stale identity");
		check(objects.delete_brush(raven::desktop_stock_brush) && objects.brush(raven::desktop_stock_brush),"stock brush deletion removes its identity");
		raven::DesktopObjects classes;
		const auto background=classes.add(raven::DesktopBrush{0x123456});
		const auto atom=classes.register_class({"background",1,2,background});
		check(atom && classes.window_class(atom)->background==background && !classes.register_class({"wrong",1,2,0xdead}),"class brush identity accepts a forged handle");
		const auto window=classes.add(raven::DesktopWindow{atom,2,u"",0,0,1,1});
		check(window && classes.unregister_class(atom)==1412 && classes.brush(background),"failed unregister deleted its background brush");
		const auto dc=classes.add(raven::DesktopDC{0x10000,0x10000});
		check(dc && classes.select_brush(dc,background) && classes.erase(window) && !classes.unregister_class(atom),"class brush unregister failed");
		check(classes.brush(background) && classes.brush(background)->pending_delete && classes.erase(dc) && !classes.brush(background) && !classes.bytes(),"class deletion bypassed selected brush lifetime");
		const auto stock=classes.register_class({"stock",1,2,raven::desktop_stock_brush});
		check(stock && !classes.unregister_class(stock) && classes.brush(raven::desktop_stock_brush) && !classes.bytes(),"class unregister deleted a stock brush or leaked budget");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
