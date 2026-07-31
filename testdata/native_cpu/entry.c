static volatile unsigned int observed;

unsigned int raven_entry(void)
{
	unsigned int sum = 0;
	for (unsigned int i = 1; i <= 1000; ++i) {
		observed = i;
		sum += observed;
	}
	return sum;
}
