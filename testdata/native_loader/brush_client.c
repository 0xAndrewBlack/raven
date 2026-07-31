#define WIN32_LEAN_AND_MEAN
#include <windows.h>
__declspec(dllexport) volatile BYTE brush_pixels[16*12*4];
int raven_entry(void)
{
	HDC a=CreateCompatibleDC(NULL),b=CreateCompatibleDC(NULL); if(!a || !b) return 1;
	HBRUSH brush=CreateSolidBrush(RGB(37,91,173)); LOGBRUSH info={0}; if(!brush || GetObjectW(brush,sizeof(info),&info)!=16 || info.lbStyle!=BS_SOLID || info.lbColor!=RGB(37,91,173) || info.lbHatch) return 2;
	for(int n=0;n<=18;++n) {
		BYTE bytes[24]; for(unsigned i=0;i<24;++i) bytes[i]=0xcc;
		unsigned count=n>16 ? 16 : (unsigned)n;
		if(GetObjectW(brush,n,bytes)!=(int)count || GetObjectW(brush,n,NULL)!=16) return 3;
		for(unsigned i=0;i<count;++i) if(bytes[i]!=((BYTE *)&info)[i]) return 4;
		for(unsigned i=count;i<24;++i) if(bytes[i]!=0xcc) return 5;
	}
	HGDIOBJ olda=SelectObject(a,brush),oldb=SelectObject(b,brush); if(!olda || !oldb || GetCurrentObject(a,OBJ_BRUSH)!=brush || !DeleteObject(brush) || GetObjectW(brush,0,NULL)!=16) return 6;
	if(SelectObject(a,olda)!=brush || GetObjectW(brush,0,NULL)!=16 || !DeleteDC(b) || GetObjectW(brush,0,NULL)) return 7;
	const COLORREF colors[]={0xffffff,0xc0c0c0,0x808080,0x404040,0,0};
	for(int i=0;i<6;++i) { HGDIOBJ stock=GetStockObject(i); LOGBRUSH value={0}; if(!stock || GetObjectW(stock,sizeof(value),&value)!=16 || value.lbStyle!=(i==5 ? BS_HOLLOW : BS_SOLID) || value.lbColor!=colors[i] || value.lbHatch || !DeleteObject(stock) || GetObjectW(stock,0,NULL)!=16) return 8; }
	BITMAPINFO bitmap={0}; bitmap.bmiHeader.biSize=40; bitmap.bmiHeader.biWidth=16; bitmap.bmiHeader.biHeight=-12; bitmap.bmiHeader.biPlanes=1; bitmap.bmiHeader.biBitCount=32;
	void *storage=NULL; HBITMAP surface=CreateDIBSection(a,&bitmap,DIB_RGB_COLORS,&storage,NULL,0); if(!surface || !storage) return 9;
	HGDIOBJ previous=SelectObject(a,surface); if(!previous) return 10;
	BYTE *pixels=storage; for(unsigned i=0;i<16*12*4;++i) pixels[i]=119;
	brush=CreateSolidBrush(RGB(37,91,173)); RECT rect={2,3,10,9},empty={9,8,2,3};
	if(!brush || !FillRect(a,&rect,brush) || !FillRect(a,&empty,brush) || !FillRect(a,&rect,GetStockObject(NULL_BRUSH))) return 11;
	for(unsigned y=0;y<12;++y) for(unsigned x=0;x<16;++x) {
		unsigned at=(y*16+x)*4; BOOL inside=x>=2 && x<10 && y>=3 && y<9;
		if(pixels[at]!=(inside ? 173 : 119) || pixels[at+1]!=(inside ? 91 : 119) || pixels[at+2]!=(inside ? 37 : 119) || pixels[at+3]!=(inside ? 0 : 119)) return 12;
		for(unsigned c=0;c<4;++c) brush_pixels[at+c]=pixels[at+c];
	}
	SelectObject(a,previous); if(!DeleteDC(a) || !DeleteObject(surface) || !DeleteObject(brush)) return 13;
	return 0;
}
