#pragma once
#include <cstdint>
#include <memory>
#include <vector>

namespace raven {
struct DesktopRect { int32_t left=0,top=0,right=0,bottom=0; };
class DesktopRegion {
public:
	DesktopRegion();
	~DesktopRegion();
	DesktopRegion(const DesktopRegion &other);
	DesktopRegion &operator=(const DesktopRegion &other);
	DesktopRegion(DesktopRegion &&) noexcept;
	DesktopRegion &operator=(DesktopRegion &&) noexcept;
	void add(DesktopRect rect);
	void subtract(DesktopRect rect);
	void combine(const DesktopRegion &first,const DesktopRegion &second,uint32_t mode);
	void offset(int32_t x,int32_t y);
	uint32_t complexity() const;
	bool equals(const DesktopRegion &other) const;
	bool empty() const;
	bool contains(int32_t x,int32_t y) const;
	// The region as disjoint rectangles, banded top to bottom.
	std::vector<DesktopRect> rectangles() const;
	DesktopRect bounds() const;
	size_t bytes() const;
private:
	struct State;
	std::unique_ptr<State> state;
	void change(DesktopRect rect,bool remove);
};
}
