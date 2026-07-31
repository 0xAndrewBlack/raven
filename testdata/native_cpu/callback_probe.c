__attribute__((naked)) unsigned int Dispatch(void *function, unsigned int value)
{
	__asm__("int3; ret");
}
