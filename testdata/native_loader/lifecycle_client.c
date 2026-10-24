#include <windows.h>
#include <winternl.h>

__declspec(dllimport) unsigned int Query(void);
__declspec(dllimport) unsigned int DependentState(void);
__declspec(dllexport) unsigned int entered;
__declspec(dllexport) unsigned int exit_requested;

static unsigned int verify_list(LIST_ENTRY *head, unsigned int member, unsigned int *found)
{
	unsigned int count = 0;
	LIST_ENTRY *previous = head;
	for (LIST_ENTRY *link = head->Flink; link != head; link = link->Flink) {
		if (++count > 128 || link->Blink != previous || link->Flink->Blink != link)
			return 0;
		unsigned char *entry = (unsigned char *)link - member;
		PVOID image = *(PVOID *)(entry + 0x30);
		UNICODE_STRING *name = (UNICODE_STRING *)(entry + 0x48);
		if (!image || !name->Length || name->Length % 2 || name->MaximumLength < name->Length + 2 ||
			name->Buffer[name->Length / 2] != 0)
			return 0;
		WCHAR *basename = name->Buffer;
		for (unsigned int character = 0; character < name->Length / 2; ++character)
			if (name->Buffer[character] == '\\' || name->Buffer[character] == '/')
				basename = name->Buffer + character + 1;
		if (GetModuleHandleW(basename) != image)
			return 0;
		IMAGE_DOS_HEADER *dos = image;
		IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((unsigned char *)image + dos->e_lfanew);
		if (*(unsigned int *)(entry + 0x40) != nt->OptionalHeader.SizeOfImage)
			return 0;
		if (image == GetModuleHandleA("base.dll")) *found |= 1;
		if (image == GetModuleHandleA("dependent.dll")) *found |= 2;
		previous = link;
	}
	return head->Blink == previous ? count : 0;
}

unsigned int raven_entry(void)
{
	entered = 1;
	PPEB_LDR_DATA loader = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
	if (!loader || Query() != 112 || DependentState() != 21)
		return 1;
	unsigned int found = 0;
	unsigned int load_count = verify_list((LIST_ENTRY *)((unsigned char *)loader + 0x10), 0, &found);
	unsigned int memory_count = verify_list(&loader->InMemoryOrderModuleList, 0x10, &found);
	unsigned int init_count = verify_list((LIST_ENTRY *)((unsigned char *)loader + 0x30), 0x20, &found);
	if (load_count < 4 || memory_count != load_count || init_count != load_count - 1 || found != 3)
		return 2;
	if (exit_requested)
		ExitProcess(0);
	return 0;
}
