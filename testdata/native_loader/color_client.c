#include <windows.h>
#include <stdint.h>
#include "color_reference.h"

__declspec(dllexport) DWORD color_rows[31][4];
__declspec(dllexport) DWORD color_pixels[31][16*12];
__declspec(dllexport) unsigned long long frame_rows[32][3];
__declspec(dllexport) DWORD frame_pixels[32][16*12];

static unsigned long long digest(const DWORD *pixels)
{
	unsigned long long value=14695981039346656037ULL;
	for(unsigned i=0;i<16*12;++i)for(unsigned c=0;c<4;++c){value^=(pixels[i]>>(c*8))&255U;value*=1099511628211ULL;}return value;
}

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(NULL);BITMAPINFO info={0};DWORD *pixels=0;
	info.bmiHeader.biSize=40;info.bmiHeader.biWidth=16;info.bmiHeader.biHeight=-12;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
	HBITMAP bitmap=CreateDIBSection(dc,&info,0,(void **)&pixels,NULL,0);HGDIOBJ old=SelectObject(dc,bitmap);
	if(!dc || !bitmap || !old || GetObjectType(dc)!=OBJ_MEMDC || GetObjectType(bitmap)!=OBJ_BITMAP) return 1;
	RECT rect={0,0,16,12};
	for(int index=0;index<31;++index) {
		SetLastError(71);COLORREF color=GetSysColor(index);if(color!=color_reference[index] || GetLastError()!=71)return 2;
		HBRUSH brush=GetSysColorBrush(index);LOGBRUSH descriptor={0};
		if(!brush || GetLastError()!=71 || GetSysColorBrush(index)!=brush || GetObjectType(brush)!=OBJ_BRUSH ||
			GetObjectW(brush,sizeof(descriptor),&descriptor)!=sizeof(descriptor) || descriptor.lbStyle!=BS_SOLID || descriptor.lbColor!=color) return 3;
		color_rows[index][0]=index;color_rows[index][1]=color;color_rows[index][2]=descriptor.lbStyle;color_rows[index][3]=descriptor.lbColor;
		if(!FillRect(dc,&rect,brush))return 4;
		DWORD expected=((color&255U)<<16)|(color&0xff00U)|((color>>16)&255U);
		for(unsigned i=0;i<16*12;++i){color_pixels[index][i]=pixels[i];if(pixels[i]!=expected)return 5;pixels[i]=0x123456;}
		if(!FillRect(dc,&rect,(HBRUSH)(UINT_PTR)(index+1)))return 6;
		for(unsigned i=0;i<16*12;++i)if(pixels[i]!=expected)return 7;
		if(!DeleteObject(brush) || GetSysColorBrush(index)!=brush || GetObjectW(brush,sizeof(descriptor),&descriptor)!=sizeof(descriptor))return 8;
	}
	const int invalid[]={-1,31,32,INT32_MIN,INT32_MAX};
	for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){SetLastError(71);if(GetSysColor(invalid[i]) || GetSysColorBrush(invalid[i]) || GetLastError()!=71)return 9;}
	HINSTANCE instance=GetModuleHandleW(NULL);WNDCLASSW wc={0};wc.hInstance=instance;wc.lpfnWndProc=DefWindowProcW;wc.lpszClassName=L"RavenSystemColors";wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
	if(!RegisterClassW(&wc))return 10;
	HWND window=CreateWindowExW(0,wc.lpszClassName,L"system colors",WS_POPUP,100,100,16,12,NULL,NULL,instance,NULL);
	WNDCLASSW copy={0};
	if(!window)return 110;
	if(!GetClassInfoW(instance,wc.lpszClassName,&copy))return 111;
	if(copy.hbrBackground!=wc.hbrBackground)return 112;
	if(GetClassLongPtrW(window,GCLP_HBRBACKGROUND)!=(ULONG_PTR)wc.hbrBackground)return 113;
	if(!SendMessageW(window,WM_ERASEBKGND,(WPARAM)dc,0))return 114;
	for(unsigned i=0;i<16*12;++i)if(pixels[i]!=0xffffff)return 12;
	HDC common=GetDC(window);if(!common || GetObjectType(common)!=OBJ_DC || !ReleaseDC(window,common))return 13;
	for(UINT message=WM_CTLCOLORMSGBOX;message<=WM_CTLCOLORSTATIC;++message) {
		if(message==WM_CTLCOLORSCROLLBAR)continue;
		SetTextColor(dc,RGB(1,2,3));SetBkColor(dc,RGB(4,5,6));SetBkMode(dc,TRANSPARENT);SetLastError(71);
		HBRUSH brush=(HBRUSH)DefWindowProcW(window,message,(WPARAM)dc,(LPARAM)window);
		const int index=message==WM_CTLCOLOREDIT || message==WM_CTLCOLORLISTBOX ? COLOR_WINDOW : COLOR_BTNFACE;
		if(brush!=GetSysColorBrush(index) || GetTextColor(dc)!=GetSysColor(COLOR_WINDOWTEXT) || GetBkColor(dc)!=GetSysColor(index) ||
			GetBkMode(dc)!=TRANSPARENT || GetLastError()!=71)return 14;
	}
	const RECT cases[]={{3,4,11,10},{0,0,1,1},{2,2,2,9},{2,2,9,2},{9,9,2,2},{-2,-3,6,5},{10,6,2,9},{INT32_MIN,INT32_MIN,INT32_MAX,INT32_MAX}};
	HBRUSH solid=CreateSolidBrush(RGB(1,2,3));if(!solid)return 15;
	for(unsigned i=0;i<8;++i)for(unsigned h=0;h<4;++h) {
		for(unsigned j=0;j<16*12;++j)pixels[j]=0x123456;
		SetLastError(71);int result=FrameRect(dc,&cases[i],h==0?solid:h==1?(HBRUSH)(COLOR_WINDOW+1):h==2?GetStockObject(NULL_BRUSH):(HBRUSH)0xdead);
		const unsigned at=i*4+h;frame_rows[at][0]=result;frame_rows[at][1]=GetLastError();frame_rows[at][2]=digest(pixels);
		for(unsigned j=0;j<3;++j)if(frame_rows[at][j]!=frame_reference[at][j])return 16;
		for(unsigned j=0;j<16*12;++j)frame_pixels[at][j]=pixels[j];
	}
	if(!DeleteObject(solid) || !DestroyWindow(window) || !UnregisterClassW(wc.lpszClassName,instance) ||
		SelectObject(dc,old)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(dc))return 17;
	return 0;
}

#ifdef COLOR_ORACLE
#include <stdio.h>
int main(void)
{
	int result=raven_entry();printf("result=%d\n",result);
	FILE *file=fopen("wine-color-pixels.bin","wb");if(file){fwrite(color_pixels,1,sizeof(color_pixels),file);fclose(file);}
	file=fopen("wine-frame-pixels.bin","wb");if(file){fwrite(frame_pixels,1,sizeof(frame_pixels),file);fclose(file);}
	file=fopen("wine-color-rows.bin","wb");if(file){fwrite(color_rows,1,sizeof(color_rows),file);fclose(file);}
	file=fopen("wine-frame-rows.bin","wb");if(file){fwrite(frame_rows,1,sizeof(frame_rows),file);fclose(file);}return result;
}
#endif
