#include "text.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkFont.h"
#include "include/core/SkFontMetrics.h"
#include "include/core/SkFontMgr.h"
#include "include/core/SkPaint.h"
#include "include/core/SkTypeface.h"
#include "include/ports/SkFontMgr_empty.h"
#include <cmath>
#include <stdexcept>

namespace raven {

static uint32_t field(std::span<const uint8_t> bytes,size_t at,size_t count=4)
{
	uint32_t value=0;
	for (size_t i=0;i<count;++i) value|=uint32_t(bytes[at+i])<<(i*8);
	return value;
}

struct TextRenderer::State {
	std::array<sk_sp<SkTypeface>,3> faces;
	std::pair<SkFont,size_t> font(std::span<const uint8_t,92> definition)
	{
		const auto height=int32_t(field(definition,0));
		if (height>=0 || height < -256 || field(definition,4) || field(definition,8) || field(definition,12) ||
			(field(definition,16)!=400 && field(definition,16)!=0) || definition[20] || definition[21] || definition[22] ||
			definition[23] || definition[24] || definition[25] || definition[26]!=3 || definition[27]) throw uint32_t(120);
		std::string name;
		for (size_t i=0;i<32;++i) {
			const auto c=field(definition,28+i*2,2); if (!c) break;
			if (c>127) throw uint32_t(120);
			name.push_back(char(c>='A' && c<='Z' ? c+32 : c));
		}
		size_t family;
		if (name=="liberation sans" || name=="arial") family=0;
		else if (name=="liberation mono" || name=="courier new") family=1;
		else if (name=="liberation serif" || name=="times new roman") family=2;
		else throw uint32_t(120);
		SkFont result(faces[family],SkScalar(-height));
		result.setHinting(SkFontHinting::kFull); result.setSubpixel(false); result.setLinearMetrics(false);
		result.setEdging(SkFont::Edging::kAntiAlias);
		return {result,family};
	}
};

TextRenderer::TextRenderer(const std::string &directory) : state(std::make_unique<State>())
{
	auto manager=SkFontMgr_New_Custom_Empty();
	const std::array<const char *,3> files{"LiberationSans-Regular.ttf","LiberationMono-Regular.ttf","LiberationSerif-Regular.ttf"};
	for (size_t i=0;i<files.size();++i) {
		state->faces[i]=manager->makeFromFile((directory+"/"+files[i]).c_str());
		if (!state->faces[i]) throw std::runtime_error("cannot load qualified native font file");
	}
}

TextRenderer::~TextRenderer() = default;

TextMetrics TextRenderer::metrics(std::span<const uint8_t,92> definition)
{
	auto [font,family]=state->font(definition); SkFontMetrics source; font.getMetrics(&source);
	const auto rounded=[](float value) { return int32_t(std::lround(value)); };
	const auto ascent=rounded(-source.fAscent),descent=rounded(source.fDescent);
	std::array<uint8_t,96> table{};
	if (state->faces[family]->getTableData(0x4f532f32,0,table.size(),table.data())!=table.size())
		throw std::runtime_error("qualified font has no complete OS/2 metrics");
	const auto character=[&](size_t at) { return uint16_t((uint16_t(table[at])<<8)|table[at+1]); };
	return {ascent+descent,ascent,descent,rounded(-source.fAscent+source.fDescent-font.getSize()),rounded(source.fLeading),
		rounded(source.fAvgCharWidth),rounded(source.fMaxCharWidth),character(64),character(66),31,character(92),
		uint8_t(family==0 ? 39 : family==1 ? 54 : 23)};
}

static std::vector<SkGlyphID> glyphs(const SkFont &font,std::span<const uint16_t> text)
{
	if (text.size()>4096) throw uint32_t(87);
	for (const auto c : text)
		if (!((c>=32 && c<=126) || (c>=0x00a0 && c<=0x024f) || (c>=0x0370 && c<=0x03ff) || (c>=0x1e00 && c<=0x1eff))) throw uint32_t(120);
	std::vector<SkGlyphID> result(text.size());
	const auto count=font.textToGlyphs(text.data(),text.size_bytes(),SkTextEncoding::kUTF16,result);
	if (count!=text.size()) throw uint32_t(120);
	for (const auto glyph : result) if (!glyph) throw uint32_t(120);
	return result;
}

TextExtent TextRenderer::extent(std::span<const uint8_t,92> definition,std::span<const uint16_t> text)
{
	auto [font,family]=state->font(definition); (void)family;
	const auto ids=glyphs(font,text); std::vector<SkScalar> widths(ids.size()); font.getWidths(ids,widths);
	float width=0; for (const auto value : widths) width+=value;
	return {int32_t(std::lround(width)),metrics(definition).height};
}

std::vector<uint8_t> TextRenderer::mask(std::span<const uint8_t,92> definition,std::span<const uint16_t> text,
	uint32_t width,uint32_t height,int32_t x,int32_t y,std::span<const std::array<int32_t,2>> positions)
{
	if (!width || !height || width>8192 || height>8192 || uint64_t(width)*height>16*1024*1024) throw uint32_t(87);
	auto [font,family]=state->font(definition); (void)family;
	const auto ids=glyphs(font,text);
	font.setEdging(SkFont::Edging::kAlias);
	std::vector<uint8_t> pixels(size_t(width)*height*4);
	SkBitmap bitmap;
	if (!bitmap.installPixels(SkImageInfo::Make(int(width),int(height),kBGRA_8888_SkColorType,kOpaque_SkAlphaType),pixels.data(),size_t(width)*4))
		throw std::bad_alloc();
	SkCanvas canvas(bitmap); canvas.clear(SK_ColorWHITE); SkPaint paint; paint.setColor(SK_ColorBLACK);
	const auto ascent=metrics(definition).ascent;
	if(positions.empty())canvas.drawSimpleText(text.data(),text.size_bytes(),SkTextEncoding::kUTF16,SkScalar(x),SkScalar(int64_t(y)+ascent),font,paint);
	else{
		if(positions.size()!=ids.size())throw uint32_t(87);
		std::vector<SkPoint> points;points.reserve(positions.size());
		for(const auto &position:positions)points.push_back({SkScalar(int64_t(x)+position[0]),SkScalar(int64_t(y)+ascent+position[1])});
		canvas.drawGlyphs({ids.data(),ids.size()},{points.data(),points.size()},{0,0},font,paint);
	}
	std::vector<uint8_t> coverage(size_t(width)*height);
	for (size_t i=0;i<coverage.size();++i) {
		if (pixels[i*4]!=0 && pixels[i*4]!=255) throw std::runtime_error("qualified monochrome text produced intermediate coverage");
		coverage[i]=pixels[i*4]==0;
	}
	return coverage;
}

std::vector<int32_t> TextRenderer::advances(std::span<const uint8_t,92> definition,std::span<const uint16_t> text)
{
	auto [font,family]=state->font(definition);(void)family;
	const auto ids=glyphs(font,text);std::vector<SkScalar> widths(ids.size());font.getWidths(ids,widths);
	std::vector<int32_t> result;result.reserve(widths.size());float total=0;
	for(const auto width:widths){total+=width;result.push_back(int32_t(std::lround(total)));}
	return result;
}

}
