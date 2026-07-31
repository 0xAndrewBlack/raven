#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static BOOL equal(const void *a,const void *b,unsigned count)
{
	const unsigned char *x=a,*y=b;
	for(unsigned i=0;i<count;++i) if(x[i]!=y[i]) return FALSE;
	return TRUE;
}

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(NULL),other=CreateCompatibleDC(NULL),third=CreateCompatibleDC(NULL);
	if(!dc || !other || !third) return 1;
	HFONT stock=GetStockObject(SYSTEM_FONT);
	if(!stock || GetCurrentObject(dc,OBJ_FONT)!=stock || GetCurrentObject(other,OBJ_FONT)!=stock) return 2;
	if(!DeleteObject(stock) || GetObjectW(stock,0,NULL)!=sizeof(LOGFONTW)) return 3;
	LOGFONTW input={0},wide={0}; LOGFONTA ansi={0};
	input.lfHeight=-16; input.lfWeight=400; input.lfQuality=NONANTIALIASED_QUALITY;
	const WCHAR face[]=L"Arial";
	for(unsigned i=0;i<sizeof(face)/sizeof(face[0]);++i) input.lfFaceName[i]=face[i];
	input.lfFaceName[10]=0x1234; input.lfFaceName[31]=0x4321;
	HFONT font=CreateFontIndirectW(&input); if(!font) return 4;
	if(GetObjectW(font,sizeof(wide),&wide)!=sizeof(wide) || !equal(&input,&wide,sizeof(wide))) return 5;
	if(GetObjectA(font,sizeof(ansi),&ansi)!=sizeof(ansi) || ansi.lfHeight!=-16 || ansi.lfWeight!=400 || ansi.lfFaceName[0]!='A' || ansi.lfFaceName[5]) return 6;
	int sizes[]={0,1,27,28,60,91,92,128,-1};
	for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i) {
		unsigned char bytes[128]; for(unsigned j=0;j<sizeof(bytes);++j) bytes[j]=0xcc;
		unsigned expected=sizes[i]<0 || sizes[i]>92 ? 92 : (unsigned)sizes[i];
		if(GetObjectW(font,sizes[i],bytes)!=(int)expected || !equal(bytes,&input,expected)) return 7;
		for(unsigned j=expected;j<sizeof(bytes);++j) if(bytes[j]!=0xcc) return 8;
		if(GetObjectW(font,sizes[i],NULL)!=92) return 9;
	}
	if(SelectObject(dc,font)!=stock || SelectObject(other,font)!=stock || SelectObject(dc,font)!=font) return 10;
	if(GetCurrentObject(dc,OBJ_FONT)!=font || !GetCurrentObject(dc,OBJ_BITMAP)) return 11;
	if(!DeleteObject(font) || !DeleteObject(font) || GetObjectW(font,0,NULL)!=92) return 12;
	if(SelectObject(third,font)!=stock || GetCurrentObject(third,OBJ_FONT)!=font) return 13;
	if(!DeleteDC(third) || GetObjectW(font,0,NULL)!=92) return 14;
	if(SelectObject(dc,stock)!=font || GetObjectW(font,0,NULL)!=92) return 15;
	if(!DeleteDC(other) || GetObjectW(font,0,NULL) || DeleteObject(font)) return 16;
	if(!DeleteDC(dc)) return 17;
	input.lfFaceName[0]=0x03a9;
	font=CreateFontIndirectW(&input);
	if(!font || GetObjectW(font,sizeof(wide),&wide)!=92 || !equal(&input,&wide,sizeof(wide)) || !DeleteObject(font)) return 18;
	if(GetObjectW(font,0,NULL) || SelectObject((HDC)(ULONG_PTR)0xdead,font)) return 19;
	WNDCLASSW definition={0}; definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenFontContract";
	if(!RegisterClassW(&definition)) return 20;
	HWND window=CreateWindowExW(0,definition.lpszClassName,L"Font owner",WS_POPUP,0,0,32,32,NULL,NULL,NULL,NULL);
	if(!window) return 21;
	dc=GetDC(window); font=CreateFontIndirectW(&input);
	if(!dc || !font || GetCurrentObject(dc,OBJ_FONT)!=stock || SelectObject(dc,font)!=stock) return 22;
	other=GetDC(window);
	if(!other || other==dc || GetCurrentObject(other,OBJ_FONT)!=stock || GetCurrentObject(dc,OBJ_FONT)!=font || !ReleaseDC(window,other)) return 29;
#ifdef RAVEN_FONT_BOUNDARY
	unsigned char output[92]; for(unsigned i=0;i<sizeof(output);++i) output[i]=0xcc;
	SetLastError(0);
	if(GetObjectA(font,60,output) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 23;
	for(unsigned i=0;i<sizeof(output);++i) if(output[i]!=0xcc) return 24;
	if(GetObjectA(font,28,output)!=28 || !equal(output,&input,28) || GetObjectA(font,0,NULL)!=60) return 25;
	SetLastError(0);
	if(GetStockObject(DEFAULT_GUI_FONT) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 26;
	SetLastError(0);
	if(GetCurrentObject(dc,OBJ_BITMAP) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 35;
#endif
	if(!DeleteObject(font) || !GetObjectW(font,0,NULL) || !ReleaseDC(window,dc) || GetObjectW(font,0,NULL)) return 27;
	PAINTSTRUCT paint;
	if(!InvalidateRect(window,NULL,FALSE)) return 31;
	dc=BeginPaint(window,&paint); other=GetDC(window); font=CreateFontIndirectW(&input);
	if(!dc || !other || !font || dc==other || SelectObject(dc,font)!=stock || SelectObject(other,font)!=stock) return 32;
	if(!DeleteObject(font) || !EndPaint(window,&paint) || GetCurrentObject(other,OBJ_FONT)!=font || GetObjectW(font,0,NULL)!=92) return 33;
	if(!ReleaseDC(window,other) || GetObjectW(font,0,NULL) || !DestroyWindow(window)) return 34;
	if(!UnregisterClassW(definition.lpszClassName,NULL)) return 28;
	return 0;
}
