#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nonclient_reference.h"

static int verify(RECT input,unsigned index,BOOL extended)
{
	struct { DWORD before; RECT rect; DWORD after; } packet={0x12345678,input,0x87654321};
	SetLastError(71);
	BOOL result=extended ? AdjustWindowRectEx(&packet.rect,adjustment_reference[index].style,adjustment_reference[index].menu,adjustment_reference[index].ex_style) :
		AdjustWindowRect(&packet.rect,adjustment_reference[index].style,adjustment_reference[index].menu);
	if (!result || GetLastError()!=71 || packet.before!=0x12345678 || packet.after!=0x87654321) return 1;
	if ((DWORD)packet.rect.left!=(DWORD)input.left+(DWORD)adjustment_reference[index].left ||
		(DWORD)packet.rect.top!=(DWORD)input.top+(DWORD)adjustment_reference[index].top ||
		(DWORD)packet.rect.right!=(DWORD)input.right+(DWORD)(adjustment_reference[index].right-320) ||
		(DWORD)packet.rect.bottom!=(DWORD)input.bottom+(DWORD)(adjustment_reference[index].bottom-240)) return 2;
	return 0;
}

int raven_entry(void)
{
	for (unsigned i=0;i<sizeof(metric_reference)/sizeof(metric_reference[0]);++i) {
		SetLastError(71);
		if (GetSystemMetrics(metric_reference[i].index)!=metric_reference[i].value) return 1;
	}
	const RECT inputs[]={{0,0,320,240},{17,-19,-23,29},{(-2147483647L-1),(-2147483647L-1),2147483647L,2147483647L}};
	for (unsigned i=0;i<sizeof(adjustment_reference)/sizeof(adjustment_reference[0]);++i)
		for (unsigned j=0;j<sizeof(inputs)/sizeof(inputs[0]);++j) {
			if (verify(inputs[j],i,TRUE)) return 2;
			if (!adjustment_reference[i].ex_style && verify(inputs[j],i,FALSE)) return 3;
		}
#ifdef RAVEN_NONCLIENT_BOUNDARY
	// Display metrics report the virtual display; an unknown index yields zero.
	if (GetSystemMetrics(SM_CXSCREEN)<=0 || GetSystemMetrics(SM_CYSCREEN)<=0) return 5;
	if (GetSystemMetrics(SM_CXCURSOR)!=32 || GetSystemMetrics(SM_CXVSCROLL)!=17 || GetSystemMetrics(-1)) return 4;
#endif
	return 0;
}
