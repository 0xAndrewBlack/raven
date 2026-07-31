#include <windows.h>
#ifndef RAVEN_ORACLE
#include "pen_reference.h"
#else
#include <stdio.h>
#endif

__declspec(dllexport) DWORD pen_pixels[132][32*32];
__declspec(dllexport) DWORD pen_rows[132][8];
static unsigned frame;

static int save(DWORD *pixels)
{
	unsigned long long hash=14695981039346656037ULL;
	for(unsigned i=0;i<32*32;++i){pen_pixels[frame][i]=pixels[i];for(unsigned b=0;b<4;++b)hash=(hash^(BYTE)(pixels[i]>>(8*b)))*1099511628211ULL;}
#ifndef RAVEN_ORACLE
	if(hash!=pen_hashes[frame])return 0;
#endif
	++frame;return 1;
}

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(NULL);BITMAPINFO bi={0};bi.bmiHeader.biSize=40;bi.bmiHeader.biWidth=32;bi.bmiHeader.biHeight=-32;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;
	DWORD *pixels;HBITMAP bitmap=CreateDIBSection(dc,&bi,0,(void **)&pixels,NULL,0);if(!dc || !bitmap)return 1;
	HGDIOBJ old=SelectObject(dc,bitmap);HPEN pen=CreatePen(PS_SOLID,1,RGB(23,105,201));HGDIOBJ before=SelectObject(dc,pen);
	if(!old || !before || !pen || GetObjectType(pen)!=OBJ_PEN || GetCurrentObject(dc,OBJ_PEN)!=pen)return 2;
	SIZE w={0},v={0};if(GetGraphicsMode(dc)!=GM_COMPATIBLE || !GetWindowExtEx(dc,&w) || !GetViewportExtEx(dc,&v) || w.cx!=1 || w.cy!=1 || v.cx!=1 || v.cy!=1)return 3;
	static const int slopes[16][2]={{0,0},{0,1},{1,0},{1,1},{1,2},{2,1},{1,3},{3,1},{2,3},{3,2},{3,4},{4,3},{5,10},{10,5},{15,7},{7,15}};
	POINT position={0};
	for(unsigned k=0;k<128;++k){
		int dx=slopes[k/8][0],dy=slopes[k/8][1];if(k&1){int t=dx;dx=dy;dy=t;}if(k&2)dx=-dx;if(k&4)dy=-dy;
		for(unsigned i=0;i<32*32;++i)pixels[i]=0x00aabbcc;
		HRGN clip=NULL,hole=NULL;
		if(k&1){clip=CreateRectRgn(7,5,25,27);if(k&2){hole=CreateRectRgn(11,11,20,20);if(!CombineRgn(clip,clip,hole,RGN_DIFF))return 4;}if(!SelectClipRgn(dc,clip))return 5;}
		POINT previous={0};if(!MoveToEx(dc,16,16,&previous) || previous.x!=position.x || previous.y!=position.y)return 6;
		SetLastError(71);BOOL result=LineTo(dc,16+dx,16+dy);DWORD error=GetLastError();if(!result || !GetCurrentPositionEx(dc,&position) || position.x!=16+dx || position.y!=16+dy || !GdiFlush())return 7;
		pen_rows[frame][0]=result;pen_rows[frame][1]=error;pen_rows[frame][2]=position.x;pen_rows[frame][3]=position.y;pen_rows[frame][4]=previous.x;pen_rows[frame][5]=previous.y;
		if(!save(pixels))return 20;
		if(clip){if(!SelectClipRgn(dc,NULL) || !DeleteObject(clip) || (hole && !DeleteObject(hole)))return 8;}
	}
	for(int index=WHITE_PEN;index<=NULL_PEN;++index){
		HGDIOBJ stock=GetStockObject(index);if(!stock || GetObjectType(stock)!=OBJ_PEN || !SelectObject(dc,stock) || !DeleteObject(stock))return 9;
		for(unsigned i=0;i<32*32;++i)pixels[i]=0x00aabbcc;
		if(!MoveToEx(dc,0,0,NULL) || !LineTo(dc,32,32) || !GdiFlush() || !save(pixels))return 21;
	}
	if(SelectObject(dc,pen)==NULL || !DeleteObject(pen) || GetObjectType(pen)!=OBJ_PEN || SelectObject(dc,before)!=pen || GetObjectType(pen))return 10;
	if(SelectObject(dc,old)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(dc))return 11;
	return frame==131 ? 0 : 12;
}

#ifdef RAVEN_ORACLE
int main(void)
{
	int result=raven_entry();FILE *f=fopen("wine-pen-pixels.bin","wb");if(!f)return 90;
	if(fwrite(pen_pixels,1,sizeof(pen_pixels),f)!=sizeof(pen_pixels)||fclose(f))return 91;
	f=fopen("wine-pen-rows.bin","wb");if(!f)return 92;if(fwrite(pen_rows,1,sizeof(pen_rows),f)!=sizeof(pen_rows)||fclose(f))return 93;
	printf("result=%d frames=%u\n",result,frame);return result;
}
#endif
