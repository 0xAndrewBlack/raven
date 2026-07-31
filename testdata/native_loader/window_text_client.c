#include <windows.h>
#ifdef RAVEN_ORACLE
#include <stdio.h>
#endif

__declspec(dllexport) DWORD text_rows[512][24];
static unsigned row,errors;
static const WCHAR klass[]=L"RavenWindowTextFixture";
static WCHAR long_text[32767];
static const WCHAR *const values[]={L"",L"ASCII",L"caf\x00e9",L"\x4e2d\x6587",L"\xd83d\xde80",L"e\x0301",L"\xd800",L"\xdc00",L"A\xd800" L"B\xdc00" L"C",L"\xffff",NULL};

static unsigned length(const WCHAR *text)
{
	unsigned n=0;if (text) while(text[n]) ++n;return n;
}

static LRESULT CALLBACK proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (GetWindowLongPtrW(window,GWLP_USERDATA)==1) {
		if (message==WM_GETTEXTLENGTH) return 10;
		if (message==WM_SETTEXT) return 0;
		if (message==WM_GETTEXT) {
			const WCHAR *text=L"overridden";unsigned n=0;
			if (wparam) { while(n+1<wparam && text[n]) { ((WCHAR *)lparam)[n]=text[n];++n; } ((WCHAR *)lparam)[n]=0; }
			return n;
		}
	}
	if (message==WM_APP+1) {
		if (!SetWindowTextW(window,(const WCHAR *)lparam)) ++errors;
		return GetWindowTextLengthW(window);
	}
	return DefWindowProcW(window,message,wparam,lparam);
}

static void read_text(HWND window,unsigned value,unsigned capacity,unsigned api,const WCHAR *expected)
{
	WCHAR buffer[16];for(unsigned i=0;i<16;++i) buffer[i]=0x7171;
	SetLastError(71);
	LRESULT result=api==2 ? InternalGetWindowText(window,buffer,(int)capacity) : api==1 ? GetWindowTextW(window,buffer,(int)capacity) : SendMessageW(window,WM_GETTEXT,capacity,(LPARAM)buffer);
	DWORD error=GetLastError();unsigned n=length(expected);if (capacity && n>=capacity) n=capacity-1;if(!capacity)n=0;
	if (result!=n) ++errors;
	for(unsigned i=0;i<16;++i) {
		WCHAR want=capacity && i<n ? expected[i] : capacity && i==n ? 0 : 0x7171;
		if(buffer[i]!=want) ++errors;
	}
	if(row>=512) {++errors;return;}
	text_rows[row][0]=value;text_rows[row][1]=capacity;text_rows[row][2]=api;text_rows[row][3]=(DWORD)result;text_rows[row][4]=error;
	for(unsigned i=0;i<16;++i)text_rows[row][5+i]=buffer[i];
	++row;
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=klass;
	if(!RegisterClassW(&wc))return 1;
	HWND root=CreateWindowExW(0,klass,L"initial-\x00e9-\x4e2d-\xd83d\xde80",WS_POPUP,0,0,32,24,NULL,NULL,instance,NULL);
	if(!root)return 2;
	read_text(root,100,16,0,L"initial-\x00e9-\x4e2d-\xd83d\xde80");
	HWND child=CreateWindowExW(0,klass,L"child-\x00e9",WS_CHILD,0,0,8,8,root,(HMENU)7,instance,NULL);
	if(!child)return 3;
	read_text(child,101,16,1,L"child-\x00e9");
	for(unsigned value=0;value<11;++value) {
		SetLastError(71);
		if(!SetWindowTextW(child,values[value]))++errors;
		if(GetWindowTextLengthW(child)!=length(values[value]) || SendMessageW(child,WM_GETTEXTLENGTH,0,0)!=length(values[value]))++errors;
		for(unsigned capacity=0;capacity<=8;++capacity)for(unsigned api=0;api<3;++api)read_text(child,value,capacity,api,values[value]);
	}
	for(unsigned i=0;i<32766;++i)long_text[i]=(i%3)==0 ? 0x4e2d : (i%3)==1 ? 0xd83d : 0xde80;
	if(!SetWindowTextW(child,long_text) || GetWindowTextLengthW(child)!=32766)return 4;
	read_text(child,102,16,1,long_text);
	if(SendMessageW(child,WM_APP+1,0,(LPARAM)L"nested-\x00e9")!=8)return 5;
	read_text(child,103,16,1,L"nested-\x00e9");
	SetWindowLongPtrW(child,GWLP_USERDATA,1);
	if(GetWindowTextLengthW(child)!=10 || SetWindowTextW(child,L"discarded"))return 6;
	read_text(child,104,16,1,L"overridden");
	read_text(child,106,16,2,L"nested-\x00e9");
	SetWindowLongPtrW(child,GWLP_USERDATA,0);
	read_text(child,105,16,0,L"nested-\x00e9");
	if(GetWindowTextW(child,NULL,0) || GetWindowTextW(child,NULL,-1))return 7;
	if(!DestroyWindow(root) || !UnregisterClassW(klass,instance))return 8;
	return errors ? 9 : 0;
}

#ifdef RAVEN_ORACLE
int main(void)
{
	int result=raven_entry();FILE *file=fopen("wine-window-text.bin","wb");
	if(!file)return 90;
	if(fwrite(text_rows,1,sizeof(text_rows),file)!=sizeof(text_rows) || fclose(file))return 91;
	printf("result=%d rows=%u errors=%u\n",result,row,errors);return result;
}
#endif
