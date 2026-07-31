#include <windows.h>
#ifndef RAVEN_ORACLE
#include "text_output_reference.h"
#else
#include <stdio.h>
#endif

__declspec(dllexport) DWORD draw_pixels[200][64*32];
__declspec(dllexport) DWORD draw_rows[200][8];
__declspec(dllexport) DWORD fit_rows[192][20];
static unsigned frame,fit_row;
static const WCHAR *faces[]={L"Liberation Sans",L"Liberation Mono",L"Liberation Serif"};
static const WCHAR *samples[]={L"Raven",L"Wi Ag",L"AVATAR",L"\x03a9\x00e9"};

static unsigned length(const WCHAR *text)
{
	unsigned n=0;while(text[n])++n;return n;
}

static int save(DWORD *pixels)
{
	unsigned long long hash=14695981039346656037ULL;
	for(unsigned i=0;i<64*32;++i){draw_pixels[frame][i]=pixels[i];for(unsigned b=0;b<4;++b)hash=(hash^(BYTE)(pixels[i]>>(8*b)))*1099511628211ULL;}
#ifndef RAVEN_ORACLE
	if(hash!=draw_hashes[frame])return 0;
#endif
	++frame;return 1;
}

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(NULL);BITMAPINFO bi={0};bi.bmiHeader.biSize=40;bi.bmiHeader.biWidth=64;bi.bmiHeader.biHeight=-32;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;
	DWORD *pixels;HBITMAP bitmap=CreateDIBSection(dc,&bi,0,(void **)&pixels,NULL,0);if(!dc || !bitmap)return 1;
	HGDIOBJ old_bitmap=SelectObject(dc,bitmap);if(!old_bitmap)return 2;
	HRGN clip=CreateRectRgn(0,0,58,30),hole=CreateRectRgn(14,6,20,18),saved=CreateRectRgn(0,0,0,0);
	if(!clip || !hole || !saved || !CombineRgn(clip,clip,hole,RGN_DIFF))return 3;
	SetBkColor(dc,RGB(220,75,33));SetTextColor(dc,RGB(41,111,231));
	static const int limits[]={-1,0,1,5,17,35,100,0x7fffffff};
	for(unsigned family=0;family<3;++family)for(unsigned size=0;size<2;++size){
		LOGFONTW lf={0};lf.lfHeight=size ? -16 : -12;lf.lfWeight=400;lf.lfQuality=NONANTIALIASED_QUALITY;
		for(unsigned i=0;faces[family][i];++i)lf.lfFaceName[i]=faces[family][i];
		HFONT font=CreateFontIndirectW(&lf);HGDIOBJ old_font=SelectObject(dc,font);if(!font || !old_font)return 4;
		for(unsigned sample=0;sample<4;++sample)for(unsigned limit=0;limit<8;++limit){
			int fit=71,widths[8];for(unsigned i=0;i<8;++i)widths[i]=0x71717171;SIZE extent={71,71},alias={0};
			unsigned count=length(samples[sample]);SetLastError(71);
			BOOL result=GetTextExtentExPointW(dc,samples[sample],count,limits[limit],&fit,widths,&extent);DWORD error=GetLastError();
			if(!result || fit<0 || (unsigned)fit>count || !GetTextExtentPointW(dc,samples[sample],count,&alias) || alias.cx!=extent.cx || alias.cy!=extent.cy)return 5;
			DWORD *out=fit_rows[fit_row++];out[0]=family;out[1]=size;out[2]=sample;out[3]=limit;out[4]=result;out[5]=error;out[6]=fit;out[7]=extent.cx;out[8]=extent.cy;
			for(unsigned i=0;i<count;++i)out[9+i]=widths[i];
		}
		for(unsigned mode=1;mode<=2;++mode)for(unsigned flags=0;flags<=6;flags+=2)for(unsigned spacing=0;spacing<2;++spacing)for(unsigned box=0;box<2;++box){
			for(unsigned i=0;i<64*32;++i)pixels[i]=0x775bcb11;
			if(!SetBkMode(dc,mode) || !SelectClipRgn(dc,box ? NULL : clip))return 6;
			RECT rect=box ? (RECT){45,9,60,27} : (RECT){4,3,28,24};const int steps[5]={9,0,-3,11,8};
			SetLastError(71);BOOL result=ExtTextOutW(dc,3,2,flags,&rect,L"Wi Ag",5,spacing ? steps : NULL);DWORD error=GetLastError();
			if(!result || !GdiFlush())return 7;
			int has=GetClipRgn(dc,saved);if(has!=(box ? 0 : 1) || (!box && !EqualRgn(saved,clip)))return 8;
			DWORD *out=draw_rows[frame];out[0]=family;out[1]=size;out[2]=mode;out[3]=flags;out[4]=spacing;out[5]=box;out[6]=result;out[7]=error;
			if(!save(pixels))return 20;
		}
		if(SelectObject(dc,old_font)!=font || !DeleteObject(font))return 9;
	}
	if(!SelectClipRgn(dc,NULL))return 10;
	for(unsigned mode=1;mode<=2;++mode)for(unsigned flags=0;flags<=6;flags+=2){
		for(unsigned i=0;i<64*32;++i)pixels[i]=0x775bcb11;
		SetBkMode(dc,mode);RECT rect={4,3,28,24};SetLastError(71);BOOL result=ExtTextOutW(dc,3,2,flags,&rect,NULL,0,NULL);DWORD error=GetLastError();
		if(!result || !GdiFlush())return 11;draw_rows[frame][2]=mode;draw_rows[frame][3]=flags;draw_rows[frame][6]=result;draw_rows[frame][7]=error;if(!save(pixels))return 21;
	}
	SIZE empty={71,71};int fit=71;if(!GetTextExtentExPointW(dc,NULL,0,0,&fit,NULL,&empty) || fit || empty.cx || empty.cy || !GetTextExtentPoint32W(dc,L"",0,&empty) || empty.cx || empty.cy)return 12;
	if(!DeleteObject(clip) || !DeleteObject(hole) || !DeleteObject(saved) || SelectObject(dc,old_bitmap)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(dc))return 13;
	return frame==200 && fit_row==192 ? 0 : 14;
}

#ifdef RAVEN_ORACLE
int main(void)
{
	int result=raven_entry();FILE *f=fopen("wine-draw-pixels.bin","wb");if(!f)return 90;if(fwrite(draw_pixels,1,sizeof(draw_pixels),f)!=sizeof(draw_pixels)||fclose(f))return 91;
	f=fopen("wine-draw-rows.bin","wb");if(!f)return 92;if(fwrite(draw_rows,1,sizeof(draw_rows),f)!=sizeof(draw_rows)||fclose(f))return 93;
	f=fopen("wine-fit-rows.bin","wb");if(!f)return 94;if(fwrite(fit_rows,1,sizeof(fit_rows),f)!=sizeof(fit_rows)||fclose(f))return 95;
	printf("result=%d frames=%u fit_rows=%u\n",result,frame,fit_row);return result;
}
#endif
