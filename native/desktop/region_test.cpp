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
		raven::DesktopRegion region;
		region.add({2,3,10,11}); region.add({20,21,28,29}); region.subtract({4,5,6,7});
		check(region.contains(3,4) && !region.contains(4,5) && !region.contains(15,15) && region.contains(21,22),"region hole or disjoint gap differs");
		const auto bounds=region.bounds(); check(bounds.left==2 && bounds.top==3 && bounds.right==28 && bounds.bottom==29,"region bounds differ");
		auto copy=region; copy.add({0,0,32,32});
		check(copy.contains(4,5) && !region.contains(4,5),"region copy shares mutable state");
		copy.subtract({0,0,32,32}); check(copy.empty() && !copy.bytes(),"empty region retains rectangle budget");
		raven::DesktopObjects objects(sizeof(raven::DesktopWindow)+32);
		const auto window=objects.add(raven::DesktopWindow{1,2,u"",0,0,32,32});
		check(window && objects.invalidate(window,{0,0,2,2},false) && objects.invalidate(window,{4,4,6,6},true),"region budget rejects allowed rectangles");
		const auto used=objects.bytes();
		check(!objects.invalidate(window,{8,8,10,10},false) && objects.bytes()==used && !objects.window(window)->update.contains(9,9),"rejected region mutation damages ownership");
		check(objects.validate(window,{0,0,32,32}) && objects.bytes()==sizeof(raven::DesktopWindow) && !objects.window(window)->erase_pending,
			"validation leaks region budget or erase state");
		check(objects.erase(window) && !objects.bytes(),"region lifetime leaks budget");
	} catch (const std::exception &error) { std::cerr<<error.what()<<'\n'; return 1; }
	return 0;
}
