#include <windows.h>
#include "extract_reference.h"

__declspec(dllexport) unsigned long long icon_digests[16];
__declspec(dllexport) unsigned char icon_payloads[16][8192];
static unsigned row;

static int image(HICON icon,int width,int height)
{
	ICONINFO info={0};BITMAP bitmap={0};
	if (!icon || !GetIconInfo(icon,&info)) return 0;
	int valid=info.fIcon && GetObjectW(info.hbmColor ? info.hbmColor : info.hbmMask,sizeof(bitmap),&bitmap)==sizeof(bitmap) &&
		bitmap.bmWidth==width && bitmap.bmHeight==(info.hbmColor ? height : height*2);
	unsigned long long digest=14695981039346656037ULL;
	static unsigned char bytes[65536];
	unsigned offset=0;
	HBITMAP bitmaps[]={info.hbmMask,info.hbmColor};
	for (unsigned i=0;i<2;++i) if (bitmaps[i]) {
		BITMAP data={0};
		if (!GetObjectW(bitmaps[i],sizeof(data),&data)) valid=0;
		LONG size=data.bmWidthBytes*data.bmHeight;
		if (size<=0 || size>sizeof(bytes) || GetBitmapBits(bitmaps[i],size,bytes)!=size) valid=0;
		else for (LONG j=0;j<size;++j) { digest^=bytes[j];digest*=1099511628211ULL;if(row<16 && offset<8192)icon_payloads[row][offset++]=bytes[j]; }
	}
	if (row<sizeof(extract_reference)/sizeof(extract_reference[0])) {
		if (digest!=extract_reference[row]) valid=0;
		icon_digests[row++]=digest;
	}
	else valid=0;
	if (info.hbmColor && !DeleteObject(info.hbmColor)) valid=0;
	if (info.hbmMask && !DeleteObject(info.hbmMask)) valid=0;
	return valid && DestroyIcon(icon);
}

int raven_entry(void)
{
	const WCHAR *files[]={L"icons.dll",L"icons.ico"};
	for (unsigned f=0;f<2;++f) {
		SetLastError(71);
		if (PrivateExtractIconsW(files[f],0,32,32,NULL,NULL,0,0)!=(f ? 1U : 2U) || GetLastError()) return 1;
		HICON icons[3]={(HICON)0x7777,(HICON)0x7777,(HICON)0x7777};UINT ids[3]={77,77,77};
		if (PrivateExtractIconsW(files[f],0,32,32,NULL,ids,0,0)!=(f ? 1U : 0U) || ids[0]!=UINT_MAX || ids[1]!=77) return 2;
		if (PrivateExtractIconsW(files[f],0,32,32,icons,ids,1,0)!=1 || GetLastError() || ids[0]!=(f ? 1U : 4U) ||
			icons[1]!=(HICON)0x7777 || ids[1]!=77 || !image(icons[0],32,32)) return 3;
		icons[0]=(HICON)0x7777;ids[0]=77;
		if (PrivateExtractIconsW(files[f],0,32|(16<<16),32|(16<<16),icons,ids,2,0)!=2 || GetLastError() ||
			ids[0]!=(f ? 1U : 4U) || ids[1]!=(f ? 0U : 3U) || icons[2]!=(HICON)0x7777 || ids[2]!=77 ||
			!image(icons[0],32,32) || !image(icons[1],16,16)) return 4;
		if (PrivateExtractIconsW(files[f],0,16,16,icons,ids,1,0)!=1 || ids[0]!=(f ? 0U : 3U) || !image(icons[0],16,16)) return 10;
		if (PrivateExtractIconsW(files[f],0,16|(32<<16),16|(32<<16),icons,ids,2,0)!=2 || ids[0]!=(f ? 0U : 3U) ||
			ids[1]!=(f ? 1U : 4U) || !image(icons[0],16,16) || !image(icons[1],32,32)) return 11;
		if (PrivateExtractIconsW(files[f],-201,0,0,icons,ids,1,LR_DEFAULTSIZE)!=1 || ids[0]!=(f ? 1U : 2U) || !image(icons[0],32,32)) return 5;
		icons[0]=(HICON)0x7777;ids[0]=77;
		if (PrivateExtractIconsW(files[f],999,32,32,icons,ids,1,0) || icons[0]!=(HICON)0x7777 || ids[0]!=UINT_MAX) return 6;
	}
	HICON icon=(HICON)0x7777;UINT id=77;
	if (PrivateExtractIconsW(L"missing.ico",0,32,32,&icon,&id,1,0)!=UINT_MAX || GetLastError()!=2 || icon!=(HICON)0x7777 || id!=77) return 7;
	if (PrivateExtractIconsW(L"empty.bin",0,32,32,&icon,&id,1,0)!=UINT_MAX || GetLastError()!=1006 || icon!=(HICON)0x7777 || id!=77) return 8;
	if (PrivateExtractIconsW(L"not-icon.txt",0,32,32,&icon,&id,1,0) || GetLastError() || icon!=(HICON)0x7777 || id!=UINT_MAX) return 9;
	return row==sizeof(extract_reference)/sizeof(extract_reference[0]) ? 0 : 12;
}

#ifdef EXTRACT_ORACLE
#include <stdio.h>
int main(void)
{
	int result=raven_entry();
	FILE *pixels=fopen("wine-icon-payloads.bin","wb");if(pixels){fwrite(icon_payloads,1,sizeof(icon_payloads),pixels);fclose(pixels);}
	printf("result=%d\n",result);
	for (unsigned i=0;i<row;++i) printf("row=%u digest=%016llx\n",i,icon_digests[i]);
	return result;
}
#endif
