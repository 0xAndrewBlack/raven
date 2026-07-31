__declspec(dllimport) unsigned int Named(unsigned int value);
__declspec(dllimport) unsigned int Ordinal(unsigned int value);

unsigned int raven_entry(void)
{
	return Named(10) + Ordinal(20);
}
