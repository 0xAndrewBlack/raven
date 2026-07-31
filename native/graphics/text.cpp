#include "text.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkFont.h"
#include "include/core/SkFontMetrics.h"
#include "include/core/SkFontMgr.h"
#include "include/core/SkPaint.h"
#include "include/core/SkTypeface.h"
#include "include/ports/SkFontMgr_empty.h"
#include <algorithm>
#include <cmath>
#include <initializer_list>
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
	// Every bundled style: family (sans, mono, serif) by regular, bold, italic, bold italic.
	std::array<std::array<sk_sp<SkTypeface>,4>,3> styled;

	static bool contains_any(const std::string &name,std::initializer_list<const char *> words)
	{
		for (const auto *word : words)
			if (name.find(word)!=name.npos) return true;
		return false;
	}

	// Maps any logical font onto the bundled families and style, sizing it the way GDI does.
	SkFont logical(std::span<const uint8_t,92> definition)
	{
		const auto height=int32_t(field(definition,0)),weight=int32_t(field(definition,16));
		const bool italic=definition[20]!=0;
		const uint8_t quality=definition[26],pitch=definition[27];
		std::string name;
		for (size_t i=0;i<32;++i) {
			const auto c=field(definition,28+i*2,2); if (!c) break;
			name.push_back(c<128 ? char(c>='A' && c<='Z' ? c+32 : c) : '?');
		}
		size_t family=0;
		if (contains_any(name,{"courier","consolas","mono","fixed","lucida console","terminal","menlo","monaco","typewriter"}) || ((pitch&0x30)==0x30 && !contains_any(name,{"sans","arial","tahoma","segoe"})))
			family=1;
		else if (contains_any(name,{"times","serif","georgia","cambria","garamond","palatino","book antiqua","century"}) && !contains_any(name,{"sans"}))
			family=2;
		const size_t style=(weight>=600 ? 1U : 0U)|(italic ? 2U : 0U);
		auto face=styled[family][style];
		if (!face) face=styled[family][0];
		if (!face) face=faces[family];
		float size=height<0 ? float(-height) : height>0 ? float(height) : 12.0f;
		SkFont probe(face,100.0f);
		SkFontMetrics source; probe.getMetrics(&source);
		if (height>0) {
			// A positive height is the whole cell (ascent plus descent); scale so the rounded cell matches it.
			const float cell=(-source.fAscent+source.fDescent)/100.0f;
			size=float(height)/cell;
			SkFont trial(face,size); SkFontMetrics measured; trial.getMetrics(&measured);
			const float adjusted=float(height)/std::max(1.0f,float(std::lround(-measured.fAscent)+std::lround(measured.fDescent)))*size;
			if (std::fabs(adjusted-size)<size*0.15f) size=adjusted;
		}
		SkFont result(face,std::max(size,1.0f));
		result.setHinting(SkFontHinting::kFull); result.setSubpixel(false); result.setLinearMetrics(false);
		result.setEdging(quality==3 ? SkFont::Edging::kAlias : SkFont::Edging::kAntiAlias);
		return result;
	}

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
		state->styled[i][0]=state->faces[i];
	}
	const std::array<std::array<const char *,3>,3> styles{{
		{"LiberationSans-Bold.ttf","LiberationSans-Italic.ttf","LiberationSans-BoldItalic.ttf"},
		{"LiberationMono-Bold.ttf","LiberationMono-Italic.ttf","LiberationMono-BoldItalic.ttf"},
		{"LiberationSerif-Bold.ttf","LiberationSerif-Italic.ttf","LiberationSerif-BoldItalic.ttf"}}};
	for (size_t family=0;family<3;++family)
		for (size_t style=0;style<3;++style)
			state->styled[family][style+1]=manager->makeFromFile((directory+"/"+styles[family][style]).c_str());
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


// The glyphs for UTF-16 text; characters the face lacks use its replacement glyph and controls draw nothing.
static std::vector<SkGlyphID> logical_glyphs(const SkFont &font,std::span<const uint16_t> text)
{
	std::vector<SkGlyphID> result(text.size(),0);
	std::vector<uint16_t> printable;
	for (size_t i=0;i<text.size();++i) {
		const uint16_t c=text[i];
		printable.push_back(c<32 ? 32 : c);
	}
	if (!printable.empty()) {
		// Surrogate pairs map to one glyph; the second unit keeps glyph 0 so positions stay unit-indexed.
		for (size_t i=0;i<printable.size();++i) {
			SkGlyphID id=0;
			font.textToGlyphs(&printable[i],2,SkTextEncoding::kUTF16,{&id,1});
			result[i]=id;
		}
	}
	return result;
}

TextMetrics TextRenderer::logical_metrics(std::span<const uint8_t,92> definition)
{
	// Fonts inside the qualified subset keep their measured OS/2 metrics.
	try { return metrics(definition); } catch (const uint32_t &) {}
	auto font=state->logical(definition); SkFontMetrics source; font.getMetrics(&source);
	const auto rounded=[](float value) { return int32_t(std::lround(value)); };
	const auto ascent=rounded(-source.fAscent),descent=rounded(source.fDescent);
	const auto average=source.fAvgCharWidth>0 ? source.fAvgCharWidth : font.getSize()*0.5f;
	const auto maximum=source.fMaxCharWidth>0 ? source.fMaxCharWidth : font.getSize();
	// Fixed-pitch faces report no variable-pitch flag.
	const auto *face=font.getTypeface();
	const bool fixed=face==state->styled[1][0].get() || face==state->styled[1][1].get() ||
		face==state->styled[1][2].get() || face==state->styled[1][3].get();
	return {ascent+descent,ascent,descent,std::max(0,rounded(-source.fAscent+source.fDescent-font.getSize())),rounded(source.fLeading),
		rounded(average),rounded(maximum),32,255,31,32,uint8_t(fixed ? 0x36 : 0x27)};
}

std::vector<int32_t> TextRenderer::logical_advances(std::span<const uint8_t,92> definition,std::span<const uint16_t> text)
{
	auto font=state->logical(definition);
	const auto ids=logical_glyphs(font,text);
	std::vector<SkScalar> widths(ids.size(),0);
	if (!ids.empty()) font.getWidths(ids,widths);
	std::vector<int32_t> result; result.reserve(ids.size());
	// Prefixes round the running float sum, like the qualified measurement, so widths never drift per glyph.
	float total=0;
	for (size_t i=0;i<ids.size();++i) {
		if (text[i]>=32 && !(text[i]>=0xdc00 && text[i]<=0xdfff)) total+=widths[i];
		result.push_back(int32_t(std::lround(total)));
	}
	return result;
}

std::vector<uint8_t> TextRenderer::render(std::span<const uint8_t,92> definition,std::span<const uint16_t> text,
	uint32_t width,uint32_t height,int32_t origin_x,int32_t origin_y,std::span<const int32_t> offsets)
{
	if (!width || !height || width>16384 || height>16384 || uint64_t(width)*height>32*1024*1024) throw uint32_t(87);
	auto font=state->logical(definition);
	const auto ids=logical_glyphs(font,text);
	std::vector<uint8_t> alpha(size_t(width)*height);
	SkBitmap bitmap;
	if (!bitmap.installPixels(SkImageInfo::MakeA8(int(width),int(height)),alpha.data(),width)) throw std::bad_alloc();
	SkCanvas canvas(bitmap); canvas.clear(SK_ColorTRANSPARENT);
	SkPaint paint; paint.setColor(SK_ColorBLACK); paint.setAntiAlias(font.getEdging()!=SkFont::Edging::kAlias);
	SkFontMetrics source; font.getMetrics(&source);
	const auto baseline=SkScalar(origin_y)+SkScalar(std::lround(-source.fAscent));
	std::vector<SkScalar> widths(ids.size(),0);
	if (!ids.empty()) font.getWidths(ids,widths);
	std::vector<SkGlyphID> drawn; std::vector<SkPoint> points;
	SkScalar cursor=0;
	for (size_t i=0;i<ids.size();++i) {
		const SkScalar step=text[i]>=32 && !(text[i]>=0xdc00 && text[i]<=0xdfff) ? SkScalar(std::lround(widths[i])) : 0;
		if (text[i]>=32 && ids[i]) {
			drawn.push_back(ids[i]);
			points.push_back({SkScalar(origin_x)+(offsets.empty() ? cursor : SkScalar(offsets[i])),baseline});
		}
		cursor+=step;
	}
	if (!drawn.empty()) canvas.drawGlyphs({drawn.data(),drawn.size()},{points.data(),points.size()},{0,0},font,paint);
	return alpha;
}

}
