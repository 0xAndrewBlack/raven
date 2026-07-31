#include <windows.h>
#ifdef RAVEN_ORACLE
#include <stdio.h>
#else
#include "layout_alignment_reference.h"
#endif
#ifdef RAVEN_BASELINE
#define RavenDrawTextExW DrawTextExW
#else
__declspec(dllimport) INT WINAPI RavenDrawTextExW(HDC,LPWSTR,INT,LPRECT,UINT,LPDRAWTEXTPARAMS);
#endif

__declspec(dllexport) DWORD alignment_pixels[588][128*32];
__declspec(dllexport) DWORD alignment_rows[588][16];
static unsigned frame;
static HDC dc;
static DWORD *pixels;
static const WCHAR *faces[]={L"Liberation Sans",L"Liberation Mono",L"Liberation Serif"};

#ifndef RAVEN_ORACLE
static unsigned hash(const void *data,unsigned count)
{
	const BYTE *bytes=data;unsigned value=2166136261U;for(unsigned i=0;i<count;++i)value=(value^bytes[i])*16777619U;return value;
}
#endif

static int render(unsigned family,unsigned size,unsigned group,unsigned mode,int width,int height,int left,int right)
{
	if(frame>=588)return 1;
	for(unsigned i=0;i<128*32;++i)pixels[i]=0x00172937;
	WCHAR ordinary[]=L"Raven",longer[]=L"Raven text requires ellipsis";RECT rect={32,10,32+width,10+height};DRAWTEXTPARAMS params={sizeof(params),4,left,right,0};
	UINT flags=DT_NOPREFIX|DT_SINGLELINE|DT_NOCLIP;
	if(group==0)flags|=mode;else if(group==1)flags|=DT_VCENTER;else flags|=DT_END_ELLIPSIS;
	SetLastError(71);int result=RavenDrawTextExW(dc,group==2?longer:ordinary,-1,&rect,flags,&params);DWORD error=GetLastError();
	if(result<=0||!GdiFlush())return 2;
	DWORD *row=alignment_rows[frame];row[0]=family;row[1]=size;row[2]=group;row[3]=mode;row[4]=width;row[5]=height;row[6]=left;row[7]=right;row[8]=result;row[9]=error;row[10]=rect.left;row[11]=rect.top;row[12]=rect.right;row[13]=rect.bottom;row[14]=params.uiLengthDrawn;
	for(unsigned i=0;i<128*32;++i)alignment_pixels[frame][i]=pixels[i];
#ifndef RAVEN_ORACLE
	if(hash(alignment_pixels[frame],sizeof(alignment_pixels[frame]))!=alignment_pixels_reference[frame] || hash(row,sizeof(alignment_rows[frame]))!=alignment_rows_reference[frame])return 3;
#endif
	++frame;return 0;
}

int raven_entry(void)
{
	dc=CreateCompatibleDC(0);BITMAPINFO info={0};info.bmiHeader.biSize=40;info.bmiHeader.biWidth=128;info.bmiHeader.biHeight=-32;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
	HBITMAP bitmap=CreateDIBSection(dc,&info,0,(void **)&pixels,0,0);HGDIOBJ old_bitmap=SelectObject(dc,bitmap);if(!dc||!bitmap||!old_bitmap)return 1;
	SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(91,173,223));
	const int widths[]={0,1,3,30,70},margins[][2]={{0,0},{2,3},{3,2},{-3,2},{2,-3}},ellipsis_widths[]={30,50,70};
	for(unsigned family=0;family<3;++family)for(unsigned size=0;size<2;++size){
		LOGFONTW lf={0};lf.lfHeight=size?-16:-12;lf.lfWeight=400;lf.lfQuality=3;for(unsigned i=0;faces[family][i];++i)lf.lfFaceName[i]=faces[family][i];
		HFONT font=CreateFontIndirectW(&lf);HGDIOBJ previous=SelectObject(dc,font);if(!font||!previous)return 2;
		for(unsigned mode=0;mode<3;++mode)for(unsigned margin=0;margin<5;++margin)for(unsigned width=0;width<5;++width)
			if(render(family,size,0,mode,widths[width],20,margins[margin][0],margins[margin][1]))return 10;
		for(unsigned height=0;height<8;++height)if(render(family,size,1,0,70,height,0,0))return 11;
		for(unsigned margin=0;margin<5;++margin)for(unsigned width=0;width<3;++width)
			if(render(family,size,2,0,ellipsis_widths[width],20,margins[margin][0],margins[margin][1]))return 12;
		if(SelectObject(dc,previous)!=font||!DeleteObject(font))return 3;
	}
	if(SelectObject(dc,old_bitmap)!=bitmap||!DeleteObject(bitmap)||!DeleteDC(dc))return 4;
	return frame==588?0:5;
}
#ifdef RAVEN_ORACLE
int main(void)
{
	int result=raven_entry();FILE *f=fopen("wine-alignment-pixels.bin","wb");if(!f||fwrite(alignment_pixels,1,sizeof(alignment_pixels),f)!=sizeof(alignment_pixels)||fclose(f))return 90;
	f=fopen("wine-alignment-rows.bin","wb");if(!f||fwrite(alignment_rows,1,sizeof(alignment_rows),f)!=sizeof(alignment_rows)||fclose(f))return 91;
	printf("result=%d frames=%u\n",result,frame);return result;
}
#endif
