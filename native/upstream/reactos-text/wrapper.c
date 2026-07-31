#include "user32.h"
INT WINAPI DrawTextExWorker(HDC,LPWSTR,INT,LPRECT,UINT,LPDRAWTEXTPARAMS);
__declspec(dllexport) INT WINAPI RavenDrawTextExW(HDC dc,LPWSTR text,INT count,LPRECT rect,UINT flags,LPDRAWTEXTPARAMS params)
{
 return DrawTextExWorker(dc,text,count,rect,flags,params);
}
