extern "C" __declspec(dllimport) void __stdcall ExitProcess(unsigned long);
extern "C" __declspec(dllimport) char *__stdcall GetCommandLineA();
extern "C" __declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(
	void *, char *, unsigned long);
extern "C" __declspec(dllimport) void *__stdcall CreateFileA(
	const char *, unsigned long, unsigned long, void *, unsigned long,
	unsigned long, void *);
extern "C" __declspec(dllimport) int __stdcall ReadFile(
	void *, void *, unsigned long, unsigned long *, void *);
extern "C" __declspec(dllimport) void *__stdcall GetStdHandle(unsigned long);
extern "C" __declspec(dllimport) int __stdcall WriteFile(
	void *, const void *, unsigned long, unsigned long *, void *);
extern "C" __declspec(dllimport) int __stdcall CloseHandle(void *);

static volatile unsigned unwind_trace;
static volatile unsigned copy_count;
static volatile unsigned exception_destructor_count;
static char module_path[32768];
static unsigned char dump_input[4096];
static char dump_output[8192];

static void write_hex(void *output, const unsigned char *bytes, unsigned long count)
{
	static const char digits[] = "0123456789abcdef";
	for (unsigned long index = 0; index < count; ++index) {
		const unsigned char value = bytes[index];
		dump_output[index * 2] = digits[value >> 4];
		dump_output[index * 2 + 1] = digits[value & 15];
	}
	unsigned long written = 0;
	if (!WriteFile(output, dump_output, count * 2, &written, 0) ||
		written != count * 2)
		ExitProcess(205);
}

static bool get_dump_self_offset(const char *command_line, unsigned long *offset)
{
	static const char argument[] = "--dump-self";
	for (const char *cursor = command_line; *cursor; ++cursor) {
		unsigned index = 0;
		while (argument[index] && cursor[index] == argument[index])
			++index;
		if (!argument[index]) {
			if (cursor[index] != 0 && cursor[index] != '=' &&
				cursor[index] != ' ' && cursor[index] != '\t' &&
				cursor[index] != '"')
				continue;
			*offset = 0;
			if (cursor[index] == '=') {
				++index;
				if (cursor[index] < '0' || cursor[index] > '9')
					continue;
				while (cursor[index] >= '0' && cursor[index] <= '9') {
					*offset = *offset * 10 + static_cast<unsigned long>(
						cursor[index] - '0');
					++index;
				}
				if (cursor[index] != 0 && cursor[index] != ' ' &&
					cursor[index] != '\t' && cursor[index] != '"')
					continue;
			}
			return true;
		}
	}
	return false;
}

static void dump_self(unsigned long offset)
{
	const unsigned long generic_read = 0x80000000UL;
	const unsigned long open_existing = 3;
	const unsigned long file_attribute_normal = 0x80;
	const unsigned long chunk_size = 12 * 1024;
	const unsigned long fingerprint_size = 512;
	void *const invalid_handle = reinterpret_cast<void *>(~static_cast<unsigned long long>(0));

	if (!GetModuleFileNameA(0, module_path, sizeof(module_path)))
		ExitProcess(201);
	void *input = CreateFileA(
		module_path,
		generic_read,
		1,
		0,
		open_existing,
		file_attribute_normal,
		0);
	if (input == invalid_handle)
		ExitProcess(202);
	void *output = GetStdHandle(static_cast<unsigned long>(-11));
	if (!output || output == invalid_handle)
		ExitProcess(203);

	unsigned long read = 0;
	if (!ReadFile(input, dump_input, sizeof(dump_input), &read, 0) ||
		read < fingerprint_size)
		ExitProcess(204);
	write_hex(output, dump_input, fingerprint_size);

	unsigned long position = 0;
	unsigned long emitted = 0;
	while (emitted < chunk_size) {
		if (position + read <= offset) {
			position += read;
		} else {
			unsigned long begin = offset > position ? offset - position : 0;
			unsigned long count = read - begin;
			if (count > chunk_size - emitted)
				count = chunk_size - emitted;
			write_hex(output, dump_input + begin, count);
			emitted += count;
			position += read;
		}
		if (emitted == chunk_size)
			break;
		read = 0;
		if (!ReadFile(input, dump_input, sizeof(dump_input), &read, 0))
			ExitProcess(204);
		if (!read)
			break;
	}
	CloseHandle(input);
	ExitProcess(0);
}

struct Base {
	int marker;
};

struct Derived : Base {
	int payload;
};

struct Guard {
	unsigned digit;

	explicit Guard(unsigned value) : digit(value) {}

	~Guard()
	{
		unwind_trace = unwind_trace * 10 + digit;
	}
};

struct CopyValue {
	int payload;
	unsigned generation;

	explicit CopyValue(int value) : payload(value), generation(0) {}

	CopyValue(const CopyValue &other)
		: payload(other.payload), generation(other.generation + 1)
	{
		++copy_count;
	}

	~CopyValue()
	{
		++exception_destructor_count;
	}
};

__declspec(noinline) static void throw_derived()
{
	Guard inner(1);
	Derived value;
	value.marker = 0x2468;
	value.payload = 0x1357;
	throw value;
}

__declspec(noinline) static void throw_integer()
{
	Guard inner(3);
	throw 42;
}

__declspec(noinline) static void throw_copy_value()
{
	CopyValue value(0x5a5a);
	throw value;
}

extern "C" void raven_entry()
{
	unsigned long dump_offset = 0;
	if (get_dump_self_offset(GetCommandLineA(), &dump_offset))
		dump_self(dump_offset);

	unsigned failures = 0;

	unwind_trace = 0;
	try {
		Guard outer(2);
		throw_derived();
	} catch (const Base &value) {
		if (value.marker != 0x2468)
			failures |= 1;
		if (unwind_trace != 12)
			failures |= 2;
	}

	unwind_trace = 0;
	try {
		Guard outer(4);
		throw_integer();
	} catch (...) {
		if (unwind_trace != 34)
			failures |= 4;
	}

	copy_count = 0;
	exception_destructor_count = 0;
	try {
		throw_copy_value();
	} catch (CopyValue value) {
		if (value.payload != 0x5a5a || value.generation < 2)
			failures |= 8;
		if (copy_count < 2)
			failures |= 16;
	}
	if (exception_destructor_count < 3)
		failures |= 32;

	unwind_trace = 0;
	try {
		Guard outer(6);
		try {
			Guard inner(5);
			throw 7;
		} catch (const int &) {
			Guard catch_guard(7);
			throw;
		}
	} catch (int value) {
		if (value != 7)
			failures |= 64;
		if (unwind_trace != 576)
			failures |= 128;
	}

	ExitProcess(failures);
}
