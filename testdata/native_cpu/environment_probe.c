__attribute__((naked)) unsigned int GetLastError(void)
{
	__asm__("int3; ret");
}

__attribute__((naked)) void SetLastError(unsigned int error)
{
	__asm__("int3; ret");
}

__attribute__((naked)) unsigned int GetCurrentProcessId(void)
{
	__asm__("int3; ret");
}

__attribute__((naked)) unsigned int GetCurrentThreadId(void)
{
	__asm__("int3; ret");
}
