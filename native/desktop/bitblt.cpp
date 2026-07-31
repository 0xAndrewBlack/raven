#include "bitblt.h"
#include "cpu/native_cpu.h"
#include <algorithm>

namespace raven {

bool bit_blt(NativeProcess &process,DesktopObjects &objects,std::span<const uint64_t> args)
{
	const auto *dc=objects.dc(args[0]);
	if (!dc) throw uint32_t(6);
	const auto rop=uint32_t(args[8]);
	const auto operation=uint8_t(rop>>16);
	const bool uses_source=((operation^(operation>>2)) & 0x33)!=0;
	const bool uses_pattern=((operation^(operation>>4)) & 0x0f)!=0;
	const auto *source_dc=uses_source ? objects.dc(args[5]) : nullptr;
	if (uses_source && !source_dc) throw uint32_t(6);
	const auto *destination=objects.bitmap(dc->bitmap);
	const auto *source=source_dc ? objects.bitmap(source_dc->bitmap) : nullptr;
	const auto *brush=uses_pattern ? objects.brush(dc->brush) : nullptr;
	if (!destination || destination->depth!=32 || (source_dc && (!source || source->depth!=32)) ||
		(uses_pattern && (!brush || brush->hollow)) || (rop & 0x7f000000)) throw uint32_t(120);
	const int64_t width=int32_t(args[3]),height=int32_t(args[4]);
	if (width<0 || height<0) throw uint32_t(120);
	const int64_t dx=int64_t(int32_t(args[1]))+dc->origin_x,dy=int64_t(int32_t(args[2]))+dc->origin_y;
	const int64_t sx=int64_t(int32_t(args[6]))+(source_dc ? source_dc->origin_x : 0);
	const int64_t sy=int64_t(int32_t(args[7]))+(source_dc ? source_dc->origin_y : 0);
	auto left=std::max(int64_t(0),-dx),top=std::max(int64_t(0),-dy);
	auto right=std::min(width,int64_t(destination->width)-dx),bottom=std::min(height,int64_t(destination->height)-dy);
	if (source) {
		left=std::max(left,-sx); top=std::max(top,-sy);
		right=std::min(right,int64_t(source->width)-sx); bottom=std::min(bottom,int64_t(source->height)-sy);
	}
	if (right<=left || bottom<=top || (dc->clip && dc->clip->empty())) return false;
	// Snapshot before writing: source and destination can be the same bitmap or guest allocation.
	std::vector<uint8_t> snapshot;
	std::span<const uint8_t> input;
	if (source) {
		if (source==destination) { snapshot.assign(source->pixels().begin(),source->pixels().end()); input=snapshot; }
		else input=source->pixels();
	}
	const auto output=objects.bitmap(dc->bitmap)->pixels();
	if (output.size()<size_t(destination->width)*destination->height*4 ||
		(source && input.size()<size_t(source->width)*source->height*4)) throw uint32_t(120);
	const uint32_t pattern=brush ? ((brush->color & 0xff)<<16) | (brush->color & 0xff00) | ((brush->color>>16)&0xff) : 0;
	bool changed=false;
	for (auto y=top;y<bottom;++y) for (auto x=left;x<right;++x) {
		if (!dc->contains(dx+x,dy+y)) continue;
		const auto target_row=destination->top_down ? size_t(dy+y) : destination->height-1-size_t(dy+y);
		const size_t target=(target_row*destination->width+size_t(dx+x))*4;
		const auto source_row=source ? (source->top_down ? size_t(sy+y) : source->height-1-size_t(sy+y)) : 0;
		const size_t origin=source ? (source_row*source->width+size_t(sx+x))*4 : 0;
		for (unsigned c=0;c<4;++c) {
			const auto s=source ? input[origin+c] : uint8_t(0),d=output[target+c],p=uint8_t(pattern>>(c*8));
			uint8_t value=0;
			for (unsigned term=0;term<8;++term) if (operation & (1U<<term))
				value|=uint8_t((term & 4 ? p : ~p) & (term & 2 ? s : ~s) & (term & 1 ? d : ~d));
			output[target+c]=value;
		}
		changed=true;
	}
	return changed;
}

}
