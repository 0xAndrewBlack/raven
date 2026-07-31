__declspec(dllimport) unsigned Query(void);

int raven_entry(void)
{
	return Query()==11 ? 0 : 1;
}
