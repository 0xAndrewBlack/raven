#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define THREADS 4
#define SLOTS 48
#define ROUNDS 4000

static HANDLE shared_heap;

static unsigned next(unsigned *state)
{
	*state = *state * 1664525u + 1013904223u;
	return *state >> 8;
}

// Several threads allocate, fill, verify and free blocks of all sizes in one growable heap, so that the heap commits and releases pages while
// the threads are interrupted at arbitrary points; a block that changes under its owner, or a fault, fails the program.
static DWORD WINAPI worker(LPVOID parameter)
{
	const unsigned id = (unsigned)(ULONG_PTR)parameter;
	unsigned state = 12345u + id * 7919u;
	BYTE *block[SLOTS] = {0};
	unsigned size[SLOTS] = {0};
	for (int round = 0; round < ROUNDS; ++round) {
		const unsigned slot = next(&state) % SLOTS;
		if (block[slot]) {
			for (unsigned index = 0; index < size[slot]; index += 61)
				if (block[slot][index] != (BYTE)(id * 31u + slot + index))
					return 1;
			if (!HeapFree(shared_heap, 0, block[slot]))
				return 2;
			block[slot] = 0;
		}
		const unsigned choice = next(&state) % 16;
		const unsigned bytes = choice == 0 ? 20000 + next(&state) % 100000 : choice < 4 ? 1000 + next(&state) % 8000 : 16 + next(&state) % 400;
		block[slot] = (BYTE *)HeapAlloc(shared_heap, 0, bytes);
		if (!block[slot])
			return 3;
		size[slot] = bytes;
		for (unsigned index = 0; index < bytes; index += 61)
			block[slot][index] = (BYTE)(id * 31u + slot + index);
	}
	for (int slot = 0; slot < SLOTS; ++slot)
		if (block[slot] && !HeapFree(shared_heap, 0, block[slot]))
			return 4;
	return 0;
}

int raven_entry(void)
{
	shared_heap = HeapCreate(0, 0x10000, 0);
	if (!shared_heap)
		return 1;
	HANDLE threads[THREADS];
	for (int index = 0; index < THREADS; ++index) {
		threads[index] = CreateThread(0, 0, worker, (LPVOID)(ULONG_PTR)(index + 1), 0, 0);
		if (!threads[index])
			return 2;
	}
	for (int index = 0; index < THREADS; ++index) {
		if (WaitForSingleObject(threads[index], 120000) != WAIT_OBJECT_0)
			return 3;
		DWORD code = 99;
		GetExitCodeThread(threads[index], &code);
		if (code)
			return 10 + (int)code;
	}
	return HeapDestroy(shared_heap) ? 0 : 4;
}
