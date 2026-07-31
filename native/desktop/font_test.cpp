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
		raven::DesktopObjects objects(sizeof(raven::DesktopFont)+2*sizeof(raven::DesktopDC));
		raven::DesktopFont definition; definition.definition[0]=0xf0;
		const auto font=objects.add(definition),dc=objects.add(raven::DesktopDC{0x10000,0x10000}),other=objects.add(raven::DesktopDC{0x10000,0x10000,42});
		check(font && dc && other && !objects.add(definition),"font budget differs");
		check(objects.font(raven::desktop_system_font) && !objects.font(dc),"font identity accepts wrong kind");
		check(objects.select_font(dc,font)==raven::desktop_system_font && objects.select_font(other,font)==raven::desktop_system_font,"font selection or window DC failed");
		check(objects.delete_font(font) && objects.font(font)->pending_delete,"selected font was not deferred");
		check(objects.erase(dc) && objects.font(font),"DC deletion released a font still selected elsewhere");
		check(objects.select_font(other,raven::desktop_system_font)==font && !objects.font(font),"last font release did not collect deletion");
		check(objects.bytes()==sizeof(raven::DesktopDC) && objects.erase(other) && !objects.bytes() && !objects.count(),"font lifetime leaks budget");
		check(objects.delete_font(raven::desktop_system_font) && objects.font(raven::desktop_system_font),"stock deletion destroys its identity");
		const auto fresh=objects.add(definition),last=objects.add(raven::DesktopDC{0x10000,0x10000});
		check(fresh>other && last>fresh && objects.select_font(last,fresh) && objects.delete_font(fresh) && objects.erase(last) && !objects.bytes(),"final DC deletion leaks deferred font");
		check(!objects.delete_font(fresh) && !objects.select_font(last,raven::desktop_system_font),"stale font or DC accepted");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
