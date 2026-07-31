#include "api.h"

#include <algorithm>
#include <array>
#include <new>
#include <sys/mman.h>

namespace raven {

static uint32_t field(std::span<const uint8_t> bytes, size_t offset, size_t width = 4)
{
	uint32_t value = 0;
	for (size_t byte = 0; byte < width; ++byte)
		value |= uint32_t(bytes[offset+byte]) << (byte*8);
	return value;
}

uint64_t NativeDesktop::create_dc(uint64_t source)
{
	if (source && !objects.dc(source)) {
		environment.set_last_error(6);
		return 0;
	}
	const auto dc = objects.add(DesktopDC{0x10000,0x10000});
	if (!dc)
		environment.set_last_error(8);
	return dc;
}

bool NativeDesktop::delete_dc(uint64_t handle)
{
	const auto *dc = objects.dc(handle);
	if (!dc || dc->window)
		return false;
	return objects.erase(handle);
}

uint64_t NativeDesktop::select(uint64_t handle, uint64_t bitmap_handle)
{
	auto *dc = objects.dc(handle);
	if (dc && objects.font(bitmap_handle)) return objects.select_font(handle,bitmap_handle);
	if (dc && objects.brush(bitmap_handle)) return objects.select_brush(handle,bitmap_handle);
	if (dc && objects.pen(bitmap_handle)) return objects.select_pen(handle,bitmap_handle);
	if (dc && objects.region(bitmap_handle)) {
		const auto value=*objects.region(bitmap_handle);const auto result=value.complexity();
		if (!objects.select_clip(handle,value)) {environment.set_last_error(8);return 0;}
		return result;
	}
	const auto *bitmap = objects.bitmap(bitmap_handle);
	if (!dc || !bitmap || dc->window || (bitmap->stock && bitmap_handle != dc->default_bitmap)) {
		environment.set_last_error(6);
		return 0;
	}
	if (dc->bitmap == bitmap_handle)
		return bitmap_handle;
	if (!bitmap->stock && objects.selected(bitmap_handle)) {
		environment.set_last_error(87);
		return 0;
	}
	const auto previous = dc->bitmap;
	dc->bitmap = bitmap_handle;
	return previous;
}

bool NativeDesktop::delete_bitmap(uint64_t handle)
{
	const auto *bitmap = objects.bitmap(handle);
	if (!bitmap) return false;
	if (bitmap->stock) return true;
	if (objects.selected(handle)) return false;
	if (bitmap->address)
		process.unmap_memory(bitmap->address);
	return objects.erase(handle);
}

uint64_t NativeDesktop::create_section(std::span<const uint64_t> args)
{
	if (!args[3]) {
		environment.set_last_error(87);
		return 0;
	}
	std::array<uint8_t,8> output{};
	process.write_memory(args[3],output);
	if (args[0] && !objects.dc(args[0])) {
		environment.set_last_error(6);
		return 0;
	}
	if (uint32_t(args[2]) || args[4]) {
		environment.set_last_error(120);
		return 0;
	}
	const auto header = process.read_memory(args[1],40);
	const auto width = int32_t(field(header,4)), height = int32_t(field(header,8));
	if (width <= 0 || width > 8192 || !height || height < -8192 || height > 8192 ||
		size_t(width) * uint32_t(height < 0 ? -height : height) > 16*1024*1024) {
		environment.set_last_error(87);
		return 0;
	}
	if (field(header,0) != 40 || field(header,12,2) != 1 || field(header,14,2) != 32 ||
		field(header,16) || field(header,32)) {
		environment.set_last_error(120);
		return 0;
	}
	const auto bitmap=allocate_bitmap(uint32_t(width),uint32_t(height<0 ? -height : height),32,true,height<0);
	if (!bitmap) return 0;
	try {
		const auto address=objects.bitmap(bitmap)->address;
		for (size_t byte=0;byte<output.size();++byte) output[byte]=uint8_t(address>>(byte*8));
		process.write_memory(args[3],output);
	} catch (...) { delete_bitmap(bitmap); throw; }
	return bitmap;
}

uint64_t NativeDesktop::allocate_bitmap(uint32_t width,uint32_t height,uint32_t depth,bool section,bool top_down)
{
	const size_t stride=depth==1 ? ((size_t(width)+15)/16)*2 : size_t(width)*4;
	if (height>64*1024*1024/stride) { environment.set_last_error(8); return 0; }
	const size_t bytes=stride*height;
	uint64_t address=0,bitmap=0;
	try {
		std::shared_ptr<SharedPixels> shared;
		if (section) {
			shared=std::make_shared<SharedPixels>((bytes+4095)&~size_t(4095));
			address=process.map_shared(shared->descriptor(),shared->size());
		}
		bitmap=objects.add(DesktopBitmap{width,height,depth,section ? std::vector<uint8_t>{} : std::vector<uint8_t>(bytes),address,top_down,false,section,shared});
	} catch (const std::bad_alloc &) {
		if (address) process.unmap_memory(address);
		environment.set_last_error(8); return 0;
	} catch (...) {
		if (address) process.unmap_memory(address);
		throw;
	}
	if (!bitmap) {
		if (address) process.unmap_memory(address);
		environment.set_last_error(8);
	}
	return bitmap;
}

uint64_t NativeDesktop::compatible_bitmap(std::span<const uint64_t> args)
{
	const int64_t width=int32_t(uint32_t(args[1])),height=int32_t(uint32_t(args[2]));
	// Zero extents return the immutable default identity before validating the DC.
	if (!width || !height) return 0x10000;
	const auto *dc=objects.dc(args[0]);
	if (!dc) { environment.set_last_error(87); return 0; }
	const auto *selected=objects.bitmap(dc->bitmap);
	if (!selected || (selected->depth!=1 && selected->depth!=32)) { environment.set_last_error(120); return 0; }
	if (selected->dib_section && width<0) return 0;
	return allocate_bitmap(uint32_t(width<0 ? -width : width),uint32_t(height<0 ? -height : height),
		selected->depth,selected->dib_section,selected->dib_section ? height<0 : true);
}

bool NativeDesktop::draw(std::span<const uint64_t> args)
{
	const auto *dc = objects.dc(args[0]);
	const auto *icon = objects.icon(args[3]);
	if (!dc || !icon) {
		environment.set_last_error(6);
		return false;
	}
	auto *bitmap = objects.bitmap(dc->bitmap);
	const auto &image = icon->image;
	const auto width = int32_t(uint32_t(args[4])), height = int32_t(uint32_t(args[5]));
	const auto flags = uint32_t(args[8]), mode = flags & 3;
	if (bitmap->depth != 32 || args[7] || !mode || (flags & ~7U) ||
		(width && uint32_t(width) != image.color.width) || (height && uint32_t(height) != image.color.height)) {
		environment.set_last_error(120);
		return false;
	}
	const int64_t left = int64_t(int32_t(uint32_t(args[1])))+dc->origin_x;
	const int64_t top = int64_t(int32_t(uint32_t(args[2])))+dc->origin_y;
	const auto x0 = std::max(int64_t(0),left), y0 = std::max(int64_t(0),top);
	const auto x1 = std::min(int64_t(bitmap->width),left+image.color.width);
	const auto y1 = std::min(int64_t(bitmap->height),top+image.color.height);
	if (x0 >= x1 || y0 >= y1)
		return true;
	if (dc->clip && dc->clip->empty()) return true;
	const auto pixels = bitmap->pixels();
	bool changed=false;
	for (auto y = y0; y < y1; ++y)
		for (auto x = x0; x < x1; ++x) {
			if (!dc->contains(x,y)) continue;
			changed=true;
			const size_t source = size_t(y-top)*image.color.width+size_t(x-left);
			const size_t row = bitmap->top_down ? size_t(y) : bitmap->height-1-size_t(y);
			const size_t target = (row*bitmap->width+size_t(x))*4;
			const auto alpha = image.color.rgba[source*4+3];
			for (size_t channel = 0; channel < 4; ++channel) {
				const auto color = image.color.rgba[source*4+(channel<3 ? 2-channel : 3)];
				auto &destination = pixels[target+channel];
				if (mode == 1)
					destination = channel==3 ? 0 : uint8_t(image.and_mask[source]*255);
				else if (image.has_alpha)
					destination = uint8_t((channel==3 ? alpha : (uint32_t(color)*alpha+127)/255) +
						(uint32_t(destination)*(255-alpha)+127)/255);
				else {
					const uint8_t component = channel==3 ? uint8_t(0) : color;
					destination = mode==2 ? component : uint8_t((destination & uint8_t(image.and_mask[source]*255)) ^ component);
				}
			}
		}
	if (!changed) return true;
	if (dc->window && dc->leased && updated) updated(dc->window);
	return true;
}

}
