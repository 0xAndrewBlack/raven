#include <windows.h>
#include <limits.h>

__declspec(dllimport) INT WINAPI RavenDrawTextExW(HDC,LPWSTR,INT,LPRECT,UINT,LPDRAWTEXTPARAMS);
__declspec(dllexport) DWORD failure_rows[28][8];

static const WCHAR *faces[]={L"Liberation Sans",L"Unqualified Raven Font"};

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(0);BITMAPINFO info={0};info.bmiHeader.biSize=40;info.bmiHeader.biWidth=64;info.bmiHeader.biHeight=-32;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;DWORD *pixels;
	HBITMAP bitmap=CreateDIBSection(dc,&info,0,(void **)&pixels,0,0);HGDIOBJ old_bitmap=SelectObject(dc,bitmap);
	HRGN clip=CreateRectRgn(1,2,61,30),copy=CreateRectRgn(0,0,0,0);if(!dc||!bitmap||!old_bitmap||!clip||!copy)return 1;
	unsigned frame=0;
	for(unsigned clipped=0;clipped<2;++clipped)for(unsigned family=0;family<7;++family){
		LOGFONTW lf={0};lf.lfHeight=-12;lf.lfWeight=400;lf.lfQuality=3;
		for(unsigned i=0;faces[family==1][i];++i)lf.lfFaceName[i]=faces[family==1][i];
		HFONT font=CreateFontIndirectW(&lf);HGDIOBJ before=SelectObject(dc,font);if(!font||!before)return 2;
		for(unsigned mode=0;mode<(family>=3?1:family==2?2:4);++mode){
			if(!SelectClipRgn(dc,clipped?clip:0))return 3;
			WCHAR text[]={L'R',L'a',family?L'v':0x4e2d,L'e',L'n',0};RECT rect={3,5,50,25};DRAWTEXTPARAMS params={sizeof(params),4,0,0,99};
			UINT flags=DT_NOPREFIX|(mode&1?DT_CALCRECT:0)|(mode&2?DT_WORDBREAK:DT_SINGLELINE);
			if(family==2)flags=DT_NOPREFIX|DT_RTLREADING|(mode?DT_WORDBREAK:DT_SINGLELINE);
			if(family==3 || family==4)params.iLeftMargin=params.iRightMargin=family==3?INT_MAX:INT_MIN;
			if(family==5){rect.left=rect.right=INT_MIN;flags=DT_NOPREFIX|DT_SINGLELINE|DT_RIGHT;}
			if(family==6){rect.left=INT_MAX-1;rect.right=INT_MAX;params.iLeftMargin=2;}
			HGDIOBJ pen=GetCurrentObject(dc,OBJ_PEN);SetLastError(71);
			int result=RavenDrawTextExW(dc,text,-1,&rect,flags,&params);DWORD error=GetLastError();int has_clip=GetClipRgn(dc,copy),equal=clipped?EqualRgn(clip,copy):1;
			DWORD *row=failure_rows[frame++];row[0]=result;row[1]=error;row[2]=has_clip;row[3]=equal;row[4]=params.uiLengthDrawn;row[5]=rect.right;row[6]=rect.bottom;
			if(result||error!=120||has_clip!=(int)clipped||!equal||GetCurrentObject(dc,OBJ_PEN)!=pen)return 10;
		}
		if(SelectObject(dc,before)!=font||!DeleteObject(font))return 4;
	}
	if(!SelectClipRgn(dc,0)||!DeleteObject(clip)||!DeleteObject(copy)||SelectObject(dc,old_bitmap)!=bitmap||!DeleteObject(bitmap)||!DeleteDC(dc))return 5;
	return frame==28?0:6;
}
