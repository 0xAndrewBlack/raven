#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	HDC mono=CreateCompatibleDC(NULL),other=CreateCompatibleDC(NULL);
	HGDIOBJ stock=GetCurrentObject(mono,OBJ_BITMAP);
	if (!mono || !other || !stock) return 1;
	for (unsigned zero=0;zero<3;++zero) {
		SetLastError(0x7654);
		HBITMAP bitmap=CreateCompatibleBitmap(zero==0 ? NULL : zero==1 ? (HDC)(ULONG_PTR)0xdead : mono,zero==2 ? 3 : 0,zero==0 ? 2 : 0);
		BITMAP info;
		if (bitmap!=stock || GetLastError()!=0x7654 || GetObjectW(bitmap,sizeof(info),&info)!=sizeof(info) ||
			info.bmWidth!=1 || info.bmHeight!=1 || info.bmWidthBytes!=2 || info.bmBitsPixel!=1 || info.bmBits ||
			!DeleteObject(bitmap) || GetCurrentObject(mono,OBJ_BITMAP)!=stock) return 2;
	}
	for (unsigned negative=0;negative<4;++negative) {
		SetLastError(0x7654);
		HBITMAP bitmap=CreateCompatibleBitmap(mono,negative & 1 ? -3 : 3,negative & 2 ? -2 : 2);
		BITMAP info;
		if (!bitmap || GetLastError()!=0x7654 || GetObjectW(bitmap,sizeof(info),&info)!=sizeof(info) ||
			info.bmWidth!=3 || info.bmHeight!=2 || info.bmWidthBytes!=2 || info.bmBitsPixel!=1 || info.bmBits ||
			SelectObject(other,bitmap)!=stock || SelectObject(other,stock)!=bitmap || !DeleteObject(bitmap)) return 3;
	}
	SetLastError(0x7654);
	if (CreateCompatibleBitmap(NULL,3,2) || GetLastError()!=ERROR_INVALID_PARAMETER) return 4;
	for (unsigned orientation=0;orientation<2;++orientation) {
		BITMAPINFO definition={0}; definition.bmiHeader.biSize=40; definition.bmiHeader.biWidth=3;
		definition.bmiHeader.biHeight=orientation ? -2 : 2; definition.bmiHeader.biPlanes=1; definition.bmiHeader.biBitCount=32;
		DWORD *input; HBITMAP source=CreateDIBSection(mono,&definition,0,(void **)&input,NULL,0);
		if (!source || SelectObject(mono,source)!=stock) return 5;
		for (unsigned sign=0;sign<2;++sign) {
			SetLastError(0x7654);
			HBITMAP clone=CreateCompatibleBitmap(mono,3,sign ? -2 : 2);
			DIBSECTION info;
			if (!clone || clone==source || GetLastError()!=0x7654 || GetObjectW(clone,sizeof(info),&info)!=sizeof(info) ||
				info.dsBm.bmWidth!=3 || info.dsBm.bmHeight!=2 || info.dsBm.bmWidthBytes!=12 || info.dsBm.bmBitsPixel!=32 ||
				!info.dsBm.bmBits || info.dsBm.bmBits==input || info.dsBmih.biHeight!=2 || info.dsBmih.biSizeImage!=24 ||
				info.dshSection || info.dsOffset || SelectObject(other,clone)!=stock) return 6;
			for (unsigned i=0;i<6;++i) { input[i]=0; ((DWORD *)info.dsBm.bmBits)[i]=0x12345670+i; }
			if (!BitBlt(mono,0,0,3,2,other,0,0,SRCCOPY)) return 7;
			for (unsigned y=0;y<2;++y) for (unsigned x=0;x<3;++x) {
				unsigned source_row=sign ? y : 1-y,target_row=orientation ? y : 1-y;
				if (input[target_row*3+x]!=0x12345670+source_row*3+x) return 8;
			}
			if (SelectObject(other,stock)!=clone || !DeleteObject(clone)) return 9;
		}
		SetLastError(0x7654);
		if (CreateCompatibleBitmap(mono,-3,2) || GetLastError()!=0x7654) return 10;
		HBITMAP wide=CreateCompatibleBitmap(mono,8193,1); DIBSECTION info;
		if (!wide || GetObjectW(wide,sizeof(info),&info)!=sizeof(info) || info.dsBm.bmWidthBytes!=32772 || !DeleteObject(wide)) return 11;
		if (SelectObject(mono,stock)!=source || !DeleteObject(source)) return 12;
	}
	if (!DeleteDC(mono) || !DeleteDC(other)) return 13;
	return 0;
}
