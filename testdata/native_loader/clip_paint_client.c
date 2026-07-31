#include <windows.h>
#ifdef RAVEN_ORACLE
#include <stdio.h>
#endif

__declspec(dllexport) DWORD paint_rows[8][16];
__declspec(dllexport) DWORD paint_pixels[16*12];
__declspec(dllexport) DWORD paint_raw_pixels[16*12];
static unsigned row,paints,errors;

static void record(HDC dc,HRGN saved,int result)
{
	DWORD error=GetLastError();RECT region={0},visible={0};
	int has=GetClipRgn(dc,saved),type=GetRgnBox(saved,&region),kind=GetClipBox(dc,&visible);
	if(row>=8){++errors;return;}
	DWORD *out=paint_rows[row++];out[0]=result;out[1]=error;out[2]=has;out[3]=type;
	out[4]=region.left;out[5]=region.top;out[6]=region.right;out[7]=region.bottom;out[8]=kind;
	out[9]=visible.left;out[10]=visible.top;out[11]=visible.right;out[12]=visible.bottom;
}

static LRESULT CALLBACK proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if(message==WM_PAINT){
		PAINTSTRUCT ps;HDC dc=BeginPaint(window,&ps);if(!dc){++errors;return 0;}
		++paints;HRGN saved=CreateRectRgn(90,91,92,93);RECT all={0,0,16,12},left={0,0,4,12};
		SetLastError(71);record(dc,saved,0);
		HBRUSH red=CreateSolidBrush(RGB(180,20,40)),green=CreateSolidBrush(RGB(20,180,40)),blue=CreateSolidBrush(RGB(20,40,180));
		if(!FillRect(dc,&all,red))++errors;
		SetLastError(71);record(dc,saved,IntersectClipRect(dc,3,0,13,12));
		if(!FillRect(dc,&all,green))++errors;
		SetLastError(71);record(dc,saved,SelectClipRgn(dc,NULL));
		if(!FillRect(dc,&left,blue))++errors;
		SetLastError(71);record(dc,saved,IntersectClipRect(dc,1,1,5,4));
		SetLastError(71);record(dc,saved,SelectClipRgn(dc,NULL));
		if(!DeleteObject(red) || !DeleteObject(green) || !DeleteObject(blue) || !DeleteObject(saved) || !EndPaint(window,&ps))++errors;
		return 0;
	}
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);const WCHAR *klass=L"RavenClipPaintFixture";
	WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=klass;
	if(!RegisterClassW(&wc))return 1;
	HWND window=CreateWindowExW(0,klass,L"clip paint",WS_POPUP,100,100,16,12,NULL,NULL,instance,NULL);if(!window)return 2;
	ShowWindow(window,SW_SHOW);if(!UpdateWindow(window) || errors || !ValidateRect(window,NULL))return 3;
	row=paints=0;
	HDC dc=GetDC(window);HBRUSH base=CreateSolidBrush(RGB(10,12,14));RECT all={0,0,16,12};
	if(!FillRect(dc,&all,base) || !DeleteObject(base) || !ReleaseDC(window,dc))return 4;
	RECT a={1,1,7,6},b={9,7,15,11};
	if(!InvalidateRect(window,&a,FALSE) || !InvalidateRect(window,&b,FALSE) || !UpdateWindow(window) || paints!=1)return 5;
	dc=GetDC(window);HDC copy=CreateCompatibleDC(dc);BITMAPINFO bi={0};bi.bmiHeader.biSize=40;bi.bmiHeader.biWidth=16;bi.bmiHeader.biHeight=-12;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;
	DWORD *bits;HBITMAP bitmap=CreateDIBSection(copy,&bi,0,(void **)&bits,NULL,0);if(!bitmap)return 6;
	HGDIOBJ old=SelectObject(copy,bitmap);if(!old || !BitBlt(copy,0,0,16,12,dc,0,0,SRCCOPY))return 7;
	for(unsigned y=0;y<12;++y)for(unsigned x=0;x<16;++x){
		DWORD expected=0x000a0c0e;
		if((x>=1 && x<7 && y>=1 && y<6) || (x>=9 && x<15 && y>=7 && y<11)){
			expected=x<4 ? 0x001428b4 : x<13 ? 0x0014b428 : 0x00b41428;
		}
		paint_raw_pixels[y*16+x]=bits[y*16+x];paint_pixels[y*16+x]=bits[y*16+x]&0xffffff;
		if(paint_pixels[y*16+x]!=expected)++errors;
	}
	if(SelectObject(copy,old)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(copy) || !ReleaseDC(window,dc) || !DestroyWindow(window) || !UnregisterClassW(klass,instance))return 8;
	return errors ? 9 : 0;
}

#ifdef RAVEN_ORACLE
int main(void)
{
	int result=raven_entry();FILE *f=fopen("wine-paint-rows.bin","wb");if(!f)return 90;
	if(fwrite(paint_rows,1,sizeof(paint_rows),f)!=sizeof(paint_rows) || fclose(f))return 91;
	f=fopen("wine-paint-pixels.bin","wb");if(!f)return 92;
	if(fwrite(paint_pixels,1,sizeof(paint_pixels),f)!=sizeof(paint_pixels) || fclose(f))return 93;
	f=fopen("wine-paint-raw-pixels.bin","wb");if(!f)return 94;
	if(fwrite(paint_raw_pixels,1,sizeof(paint_raw_pixels),f)!=sizeof(paint_raw_pixels) || fclose(f))return 95;
	printf("result=%d rows=%u paints=%u errors=%u\n",result,row,paints,errors);return result;
}
#endif
