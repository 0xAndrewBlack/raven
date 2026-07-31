typedef unsigned int (*callback_fn)(unsigned int);

__declspec(dllimport) unsigned int Dispatch(callback_fn function, unsigned int value);

static unsigned int leaf(unsigned int value)
{
	return value * 2;
}

static unsigned int nested(unsigned int value)
{
	return Dispatch(leaf, value + 3) + 5;
}

unsigned int raven_entry(void)
{
	return Dispatch(nested, 7) + 1;
}
