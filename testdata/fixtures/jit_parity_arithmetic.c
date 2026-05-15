#ifdef _WIN32
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

__declspec(dllimport) void __stdcall ExitProcess(uint32_t exit_code);
#else
#include <stdint.h>
#include <stdio.h>
#endif

static volatile uint32_t jit_parity_words[64];

static __attribute__((noinline)) uint32_t
jit_parity_mix(uint32_t value, uint32_t salt)
{
	uint32_t shift = (salt & 15U) + 1U;
	uint32_t rotated = (value << shift) | (value >> (32U - shift));

	if ((rotated ^ salt) & 1U)
		return (rotated ^ 0x9e3779b9U) + salt * 33U;
	return (rotated + 0x7f4a7c15U) ^ (salt * 17U);
}

static uint32_t
jit_parity_compute(void)
{
	uint32_t acc = 0x13579bdfU;
	uint32_t i;

	for (i = 0; i < 64U; i++)
		jit_parity_words[i] = i * 0x10203U + 0x55aaU;

	for (i = 0; i < 8192U; i++) {
		uint32_t index = (i * 13U + (acc >> 27)) & 63U;
		uint32_t value = jit_parity_words[index];

		value = jit_parity_mix(value ^ acc, i + index);
		if ((i & 7U) == 3U)
			value += jit_parity_words[(index + 17U) & 63U];
		else if ((i & 7U) == 6U)
			value ^= jit_parity_words[(index + 41U) & 63U];
		else
			value -= i * 9U;

		jit_parity_words[index] = value;
		acc = jit_parity_mix(acc + value, i ^ index);
	}

	for (i = 0; i < 64U; i++)
		acc = jit_parity_mix(acc ^ jit_parity_words[i], i + 0xa5U);

	return acc;
}

#ifdef _WIN32
void
raven_entry(void)
{
	ExitProcess(jit_parity_compute());
}
#else
int
main(void)
{
	printf("%u\n", jit_parity_compute());
	return 0;
}
#endif
