#include <windows.h>

__declspec(dllexport) unsigned long long reject_rows[64][4];
static unsigned row,bad;
static HWND child,nested;
static HINSTANCE instance;
static const WCHAR klass[]=L"RavenChildReject";

static LRESULT CALLBACK proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if(message==WM_NCCREATE)SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)((CREATESTRUCTW *)lparam)->lpCreateParams);
	const LONG_PTR tag=GetWindowLongPtrW(window,GWLP_USERDATA);
	if(message==WM_NCCREATE || message==WM_NCCALCSIZE || message==WM_CREATE || message==WM_SIZE || message==WM_MOVE ||
		message==WM_PARENTNOTIFY || message==WM_DESTROY || message==WM_NCDESTROY) {
		if(row<64) {
			reject_rows[row][0]=tag;reject_rows[row][1]=message;reject_rows[row][2]=wparam;
			reject_rows[row][3]=message==WM_PARENTNOTIFY ? GetWindowLongPtrW((HWND)lparam,GWLP_USERDATA) :
				message==WM_SIZE || message==WM_MOVE ? lparam : 0;
		} else ++bad;
		++row;
	}
	if(message==WM_CREATE && tag==1) {
		child=CreateWindowExW(0,klass,L"child",WS_CHILD,5,6,20,15,window,(HMENU)101,instance,(void *)2);
		if(!child || !nested)++bad;
		HDC dc=GetDC(nested);if(!dc || !ReleaseDC(nested,dc))++bad;
		return -1;
	}
	if(message==WM_CREATE && tag==2) {
		nested=CreateWindowExW(WS_EX_NOPARENTNOTIFY,klass,L"nested",WS_CHILD,1,2,8,7,window,(HMENU)102,instance,(void *)3);
		if(!nested)++bad;
	}
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	instance=GetModuleHandleW(NULL);WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=klass;
	if(!RegisterClassW(&wc))return 1;
	HWND parent=CreateWindowExW(0,klass,L"rejected parent",WS_POPUP,100,200,80,60,NULL,NULL,instance,(void *)1);
	if(parent || !child || !nested || IsWindow(child) || IsWindow(nested) || bad || !UnregisterClassW(klass,instance))return 2;
	unsigned long long digest=14695981039346656037ULL;
	for(unsigned i=0;i<row && i<64;++i)for(unsigned j=0;j<4;++j)for(unsigned c=0;c<8;++c){digest^=(reject_rows[i][j]>>(c*8)) & 255;digest*=1099511628211ULL;}
#ifndef REJECT_ORACLE
	if(row!=17 || digest!=0x87d3923230669275ULL)return 3;
#endif
	return 0;
}

#ifdef REJECT_ORACLE
#include <stdio.h>
int main(void)
{
	int result=raven_entry();printf("result=%d bad=%u rows=%u\n",result,bad,row);
	for(unsigned i=0;i<row && i<64;++i)printf("row=%u %llu,%llu,%llu,%llu\n",i,reject_rows[i][0],reject_rows[i][1],reject_rows[i][2],reject_rows[i][3]);return result;
}
#endif
