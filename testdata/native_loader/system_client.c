#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <stddef.h>

LONG NTAPI NtQuerySystemInformation(ULONG,void *,ULONG,ULONG *);

typedef struct {
	ULONG reserved,timer,page,pages,lowest,highest,granularity;
	ULONG_PTR minimum,maximum,affinity;
	BYTE processors;
} BasicInformation;

__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	BasicInformation info;
	ULONG length=0;
	SetLastError(71);
	if (sizeof(info)!=64 || NtQuerySystemInformation(0,&info,sizeof(info),&length)!=0 || length!=sizeof(info) ||
		GetLastError()!=71 || info.reserved || info.page!=4096 || info.granularity!=65536 ||
		!info.pages || info.highest<info.lowest || info.minimum!=65536 ||
		info.maximum<=info.minimum || !info.affinity || !info.processors)
		return 1;
	length=0;
	if ((ULONG)NtQuerySystemInformation(0,&info,sizeof(info)-1,&length)!=0xc0000004UL || length!=sizeof(info))
		return 2;
	if (NtQuerySystemInformation(0,&info,sizeof(info),NULL)!=0)
		return 3;
	{
		SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX group;
		DWORD size=0;
		const DWORD required=offsetof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,Group.GroupInfo)+sizeof(PROCESSOR_GROUP_INFO);
		if (GetLogicalProcessorInformationEx(RelationGroup,NULL,&size) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size!=required)
			return 4;
		unsigned char *bytes=(unsigned char *)&group;
		for (unsigned index=0;index<sizeof(group);++index) bytes[index]=0xa5;
		size=required-1;
		if (GetLogicalProcessorInformationEx(RelationGroup,&group,&size) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size!=required)
			return 5;
		for (unsigned index=0;index<sizeof(group);++index) if(bytes[index]!=0xa5) return 6;
		SetLastError(71);
		if (!GetLogicalProcessorInformationEx(RelationGroup,&group,&size) || GetLastError()!=71 || size!=required ||
			group.Relationship!=RelationGroup || group.Size!=required || group.Group.ActiveGroupCount!=1 || group.Group.MaximumGroupCount!=1)
			return 7;
		PROCESSOR_GROUP_INFO *processors=&group.Group.GroupInfo[0];
		SYSTEM_INFO system;
		GetSystemInfo(&system);
		if (processors->ActiveProcessorCount!=system.dwNumberOfProcessors || processors->MaximumProcessorCount<processors->ActiveProcessorCount ||
			processors->MaximumProcessorCount>64 || processors->ActiveProcessorMask!=system.dwActiveProcessorMask)
			return 8;
		for (unsigned index=0;index<sizeof(group.Group.Reserved);++index) if(group.Group.Reserved[index]) return 9;
		for (unsigned index=0;index<sizeof(processors->Reserved);++index) if(processors->Reserved[index]) return 10;
		if (GetLogicalProcessorInformationEx(RelationGroup,&group,NULL) || GetLastError()!=ERROR_INVALID_PARAMETER)
			return 11;
		size=sizeof(group);
		if (GetLogicalProcessorInformationEx((LOGICAL_PROCESSOR_RELATIONSHIP)0x1234,&group,&size) || GetLastError()!=ERROR_INVALID_PARAMETER || size!=sizeof(group))
			return 12;
		static unsigned char all[4096];
		size=sizeof(all);
		if (!GetLogicalProcessorInformationEx(RelationAll,(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)all,&size))
			return 13;
		unsigned offset=0,groups=0;
		while(offset<size) {
			PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX entry=(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(all+offset);
			if(size-offset<8 || entry->Size<8 || entry->Size>size-offset) return 14;
			if(entry->Relationship==RelationGroup) {
				if(entry->Size!=required) return 15;
				for(unsigned index=0;index<required;++index) if(all[offset+index]!=bytes[index]) return 16;
				++groups;
			}
			offset+=entry->Size;
		}
		if(groups!=1) return 17;
	}
	phase=1;
	return 0;
}
