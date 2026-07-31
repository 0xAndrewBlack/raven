#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static int measure(int source_size, int target_size, int vertical, int block)
{
	int sw=vertical?24:source_size,sh=vertical?source_size:24;
	int tw=vertical?24:target_size,th=vertical?target_size:24;
	size_t ss=((sw+15)/16)*2,ts=((tw+15)/16)*2;
	BYTE *data=malloc(ss*sh),*actual=calloc(ts*th,1);
	if(!data || !actual)return 0;
	memset(data,255,ss*sh);
	for(int bit=0;bit<24 && block+bit<source_size;bit++) {
		int x=vertical?bit:block+bit,y=vertical?block+bit:bit;
		data[y*ss+x/8]&=(BYTE)~(1U<<(7-x%8));
	}
	HDC source=CreateCompatibleDC(NULL),target=CreateCompatibleDC(NULL);
	HBITMAP bitmap=CreateBitmap(sw,sh,1,1,data),output=CreateBitmap(tw,th,1,1,actual);
	if(!source || !target || !bitmap || !output)return 0;
	HGDIOBJ old_source=SelectObject(source,bitmap),old_target=SelectObject(target,output);
	if(!old_source || !old_target || !SetStretchBltMode(target,BLACKONWHITE) ||
		!StretchBlt(target,0,0,tw,th,source,0,0,sw,sh,SRCCOPY) || !GdiFlush() ||
		GetBitmapBits(output,(LONG)(ts*th),actual)!=(LONG)(ts*th))return 0;
	printf("%d,%d,%d,%d",source_size,target_size,vertical,block);
	for(int index=0;index<target_size;index++) {
		DWORD footprint=0;
		for(int bit=0;bit<24 && block+bit<source_size;bit++) {
			int x=vertical?bit:index,y=vertical?index:bit;
			if(!(actual[y*ts+x/8]>>(7-x%8)&1))footprint|=1U<<bit;
		}
		printf(",%06lx",footprint);
	}
	printf("\n");
	SelectObject(source,old_source);SelectObject(target,old_target);
	free(data);free(actual);
	return DeleteObject(bitmap)&&DeleteObject(output)&&DeleteDC(source)&&DeleteDC(target);
}

int main(void)
{
	for (int source = 1; source <= 256; ++source) {
		if (source > 40 && source != 48 && source != 64 && source != 128 && source != 256)
			continue;
		for (int target = 1; target <= 300; ++target) {
			if (target > 50 && target != 64 && target != 96 && target != 128 && target != 192 &&
				target != 200 && target != 255 && target != 256 && target != 300)
				continue;
			for (int vertical = 0; vertical < 2; ++vertical)
				for (int block = 0; block < source; block += 24)
					if (!measure(source, target, vertical, block))
						return 1;
		}
	}
	return 0;
}
