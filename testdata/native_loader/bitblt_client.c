#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	for (unsigned orientation=0;orientation<4;++orientation) {
		BITMAPINFO info={0};
		info.bmiHeader.biSize=40; info.bmiHeader.biWidth=2; info.bmiHeader.biHeight=orientation & 1 ? 2 : -2;
		info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
		DWORD *source,*destination;
		HDC a=CreateCompatibleDC(NULL),b=CreateCompatibleDC(NULL);
		HBITMAP sa=CreateDIBSection(a,&info,0,(void **)&source,NULL,0);
		info.bmiHeader.biHeight=orientation & 2 ? 2 : -2;
		HBITMAP sb=CreateDIBSection(b,&info,0,(void **)&destination,NULL,0);
		if (!a || !b || !sa || !sb) return 1;
		HGDIOBJ old_a=SelectObject(a,sa),old_b=SelectObject(b,sb);
		HBRUSH brush=CreateSolidBrush(RGB(0x12,0x34,0x56));
		HGDIOBJ old_brush=SelectObject(b,brush);
		if (!old_a || !old_b || !brush || !old_brush) return 2;
		for (unsigned op=0;op<256;++op) {
			for (unsigned i=0;i<4;++i) { source[i]=0x12345678+i; destination[i]=0x98765432+i; }
			SetLastError(0x7654);
			if (!BitBlt(b,0,0,2,2,a,0,0,op<<16) || GetLastError()!=0x7654) return 3;
			for (unsigned y=0;y<2;++y) for (unsigned x=0;x<2;++x) {
				unsigned si=((orientation & 1 ? 1-y : y)*2+x),di=((orientation & 2 ? 1-y : y)*2+x);
				DWORD s=0x12345678+si,d=0x98765432+di,p=0x00123456,expected=0;
				for (unsigned bit=0;bit<32;++bit) {
					unsigned index=(((p>>bit)&1)<<2)|(((s>>bit)&1)<<1)|((d>>bit)&1);
					expected|=((DWORD)((op>>index)&1))<<bit;
				}
				if (destination[di]!=expected) return 4;
			}
		}
		for (unsigned edge=0;edge<6;++edge) {
			for (unsigned i=0;i<4;++i) { source[i]=0x12345678+i; destination[i]=0x98765432; }
			int sx=edge==0 ? -1 : edge==1 ? 1 : edge==2 ? 2 : 0;
			int sy=edge==3 ? -1 : edge==4 ? 1 : edge==5 ? 2 : 0;
			if (!BitBlt(b,0,0,2,2,a,sx,sy,SRCCOPY)) return 5;
			for (int y=0;y<2;++y) for (int x=0;x<2;++x) {
				unsigned di=((orientation & 2 ? 1-y : y)*2+x);
				DWORD expected=0x98765432;
				if (sx+x>=0 && sx+x<2 && sy+y>=0 && sy+y<2)
					expected=0x12345678+((orientation & 1 ? 1-(sy+y) : sy+y)*2+sx+x);
				if (destination[di]!=expected) return 6;
			}
		}
		for (unsigned i=0;i<4;++i) destination[i]=0x11223344+i;
		if (!BitBlt(b,1,0,1,2,b,0,0,SRCCOPY)) return 7;
		if (destination[1]!=0x11223344 || destination[3]!=0x11223346) return 8;
		if (!BitBlt(b,0,0,2,2,NULL,0,0,PATCOPY)) return 9;
		for (unsigned i=0;i<4;++i) if (destination[i]!=0x00123456) return 10;
		if (!BitBlt(b,0,0,0,2,a,0,0,SRCCOPY) || !BitBlt(b,0,0,2,0,a,0,0,SRCCOPY)) return 11;
		if (SelectObject(a,old_a)!=sa || SelectObject(b,old_b)!=sb || SelectObject(b,old_brush)!=brush ||
			!DeleteObject(sa) || !DeleteObject(sb) || !DeleteObject(brush) || !DeleteDC(a) || !DeleteDC(b)) return 12;
	}
	return 0;
}
