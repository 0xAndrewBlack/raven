#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	HANDLE heap=GetProcessHeap();
	if (!heap || heap!=GetProcessHeap()) return 1;
	BYTE *first=(BYTE *)HeapAlloc(heap,HEAP_ZERO_MEMORY,100);
	BYTE *second=(BYTE *)HeapAlloc(heap,0,100);
	if (!first || !second || first==second) return 2;
	for (int index=0; index<100; ++index)
		if (first[index]) return 3;
	for (int index=0; index<100; ++index) first[index]=(BYTE)index;
	if (HeapSize(heap,0,first)<100) return 4;
	first=(BYTE *)HeapReAlloc(heap,0,first,5000);
	if (!first || HeapSize(heap,0,first)<5000) return 5;
	for (int index=0; index<100; ++index)
		if (first[index]!=index) return 6;
	if (!HeapFree(heap,0,second)) return 7;
	BYTE *again=(BYTE *)HeapAlloc(heap,HEAP_ZERO_MEMORY,100);
	if (again!=second) return 8;
	for (int index=0; index<100; ++index)
		if (again[index]) return 9;
	BYTE *large=(BYTE *)HeapAlloc(heap,0,3<<20);
	if (!large) return 10;
	large[0]=1;
	large[(3<<20)-1]=2;
	if (!HeapFree(heap,0,large) || !HeapFree(heap,0,first) || !HeapFree(heap,0,again)) return 11;
	return 0;
}
