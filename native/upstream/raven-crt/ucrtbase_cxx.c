/* What programs built against the system msvcrt.dll import for C++: exit handlers kept by a library, and, for 32-bit programs, the
 * exceptions of the Microsoft C++ compiler. A throw is dispatched here, in the program's own process, along the chain of exception
 * frames the thread registered: each frame's handler is asked in turn, and the C++ frame handler finds the catch block that takes the
 * object, unwinds the frames above it, runs the block and resumes the function after it. Included by ucrtbase.c. */

/* The handlers' type is the headers' _onexit_t, which returns an int nobody reads. */
typedef int (__cdecl *exit_function)(void);

CRT exit_function _onexit(exit_function function) { return _crt_atexit((void (__cdecl *)(void))function) ? NULL : function; }

/* A library's own table of exit handlers, from *begin to *end, grows by one. */
CRT exit_function __dllonexit(exit_function function, exit_function **begin, exit_function **end)
{
	if (!function || !begin || !end)
		return NULL;
	const size_t count = *begin ? (size_t)(*end - *begin) : 0;
	exit_function *table = realloc(*begin, (count + 1) * sizeof *table);
	if (!table)
		return NULL;
	table[count] = function;
	*begin = table;
	*end = table + count + 1;
	return function;
}

#ifdef __i386__

#define THISCALL __attribute__((thiscall))

#define CXX_EXCEPTION 0xe06d7363
#define CXX_MAGIC_FIRST 0x19930520
#define CXX_MAGIC_LAST 0x19930522
#define FUNCTION_SYNCHRONOUS 1
#define CATCH_CONST 1
#define CATCH_VOLATILE 2
#define CATCH_REFERENCE 8
#define TYPE_SIMPLE 1
#define TYPE_VIRTUAL_BASE 4
#define UNWINDING (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)

/* The tables the compiler emits, as 32-bit programs lay them out. */
typedef struct { const void *vtable; char *name; char mangled[1]; } cxx_type;
typedef struct { int this_offset, base_offset, base_entry; } cxx_offsets;
typedef struct { unsigned flags; const cxx_type *type; cxx_offsets offsets; unsigned size; void *copy; } cxx_catchable;
typedef struct { int count; const cxx_catchable *types[1]; } cxx_catchables;
typedef struct { unsigned flags; void *destructor; void *forward; const cxx_catchables *catchable; } cxx_throw_info;
typedef struct { int previous; void *handler; } cxx_unwind;
typedef struct { unsigned flags; const cxx_type *type; int offset; void *handler; } cxx_catch;
typedef struct { int start, end, catch_level, count; const cxx_catch *catches; } cxx_try;
typedef struct { unsigned magic, unwind_count; const cxx_unwind *unwind; unsigned try_count; const cxx_try *tries; unsigned ip_count;
	const void *ip_map; const void *expected; unsigned flags; } cxx_function;

/* The exception frame a C++ function registers: the link and handler, its current state, and the function's frame pointer, which is
 * the address of the saved one. The stack pointer the function keeps after its prologue sits just below. */
typedef struct cxx_registration { struct cxx_registration *next; void *handler; } cxx_registration;
typedef struct { cxx_registration link; int state; unsigned ebp; } cxx_frame;
typedef int (__cdecl *frame_handler)(EXCEPTION_RECORD *, void *, CONTEXT *, void *);

static cxx_registration *frame_list(void)
{
	cxx_registration *head;
	__asm__ volatile ("movl %%fs:0, %0" : "=r"(head));
	return head;
}

static void set_frame_list(cxx_registration *head)
{
	__asm__ volatile ("movl %0, %%fs:0" : : "r"(head) : "memory");
}

/* Runs a part of a function, a catch block or an unwind action, with the function's frame pointer; returns what the part returns. */
__asm__(".text\n"
	"_raven_call_with_frame:\n\t"
	"pushl %ebp\n\tpushl %ebx\n\tpushl %esi\n\tpushl %edi\n\t"
	"movl 24(%esp), %ebp\n\t"
	"call *20(%esp)\n\t"
	"popl %edi\n\tpopl %esi\n\tpopl %ebx\n\tpopl %ebp\n\t"
	"ret\n");
void *raven_call_with_frame(void *code, void *frame_pointer);

/* Leaves the catch block for good: the function's stack and frame pointers come back and it goes on at the address the block gave. */
__asm__(".text\n"
	"_raven_resume_function:\n\t"
	"movl 4(%esp), %edx\n\t"
	"movl 8(%esp), %eax\n\t"
	"movl -4(%edx), %esp\n\t"
	"leal 12(%edx), %ebp\n\t"
	"jmp *%eax\n");
void raven_resume_function(cxx_frame *frame, void *address) __attribute__((noreturn));

/* The exception a catch block is handling on each thread, which a rethrow sends on. */
static DWORD current_slot = TLS_OUT_OF_INDEXES;

static EXCEPTION_RECORD *current_exception(void)
{
	return current_slot == TLS_OUT_OF_INDEXES ? NULL : TlsGetValue(current_slot);
}

static void set_current_exception(EXCEPTION_RECORD *record)
{
	if (current_slot == TLS_OUT_OF_INDEXES) {
		DWORD slot = TlsAlloc();
		if (InterlockedCompareExchange((LONG *)&current_slot, (LONG)slot, (LONG)TLS_OUT_OF_INDEXES) != (LONG)TLS_OUT_OF_INDEXES)
			TlsFree(slot);
	}
	TlsSetValue(current_slot, record);
}

/* Calls the unwind actions of a function from its current state back to the state asked for, destroying what was built since. */
static void unwind_function(cxx_frame *frame, const cxx_function *function, int target)
{
	int state = frame->state;
	while (state > target && state >= 0 && (unsigned)state < function->unwind_count) {
		const cxx_unwind *entry = &function->unwind[state];
		frame->state = entry->previous;
		if (entry->handler)
			raven_call_with_frame(entry->handler, &frame->ebp);
		state = entry->previous;
	}
	frame->state = target;
}

/* The dispatcher's own frame says that an exception raised while a handler runs is a nested one. */
static int __cdecl nested_handler(EXCEPTION_RECORD *record, void *frame, CONTEXT *context, void *dispatcher)
{
	return record->ExceptionFlags & UNWINDING ? ExceptionContinueSearch : ExceptionNestedException;
}

/* Calls a frame's handler as Windows does: with a frame of the dispatcher's own above it, which the C++ runtime's unwinding takes off
 * and links again, and which leaves the chain when the handler returns. */
static int call_handler(cxx_registration *frame, EXCEPTION_RECORD *record, CONTEXT *context, void *dispatcher)
{
	cxx_registration own = {frame_list(), (void *)nested_handler};
	set_frame_list(&own);
	const int disposition = ((frame_handler)frame->handler)(record, frame, context, dispatcher);
	set_frame_list(own.next);
	return disposition;
}

/* Every frame registered above the target hears that it is being unwound and leaves the chain. */
static void unwind_frames(cxx_registration *target, EXCEPTION_RECORD *record)
{
	CONTEXT context = {0};
	void *dispatcher = NULL;
	record->ExceptionFlags |= EXCEPTION_UNWINDING;
	for (cxx_registration *frame = frame_list(); frame && frame != target && frame != (cxx_registration *)-1;) {
		call_handler(frame, record, &context, &dispatcher);
		cxx_registration *next = frame->next;
		set_frame_list(next);
		frame = next;
	}
	record->ExceptionFlags &= ~EXCEPTION_UNWINDING;
}

static void *adjusted(const cxx_offsets *offsets, void *object)
{
	char *at = object;
	if (!at)
		return NULL;
	if (offsets->base_offset >= 0) {
		at += offsets->base_offset;
		at += *(int *)(*(char **)at + offsets->base_entry);
	}
	return at + offsets->this_offset;
}

/* The type of the thrown object that a catch block takes, by name as the compiler decorates it. */
static const cxx_catchable *caught_type(const cxx_throw_info *info, const cxx_catch *block)
{
	for (int index = 0; index < info->catchable->count; ++index) {
		const cxx_catchable *type = info->catchable->types[index];
		if (block->type != type->type && strcmp(block->type->mangled, type->type->mangled))
			continue;
		if (((info->flags & CATCH_CONST) && !(block->flags & CATCH_CONST)) || ((info->flags & CATCH_VOLATILE) && !(block->flags & CATCH_VOLATILE)))
			continue;
		return type;
	}
	return NULL;
}

/* The catch block's own copy of the object, or a reference to it, where the block finds it in the function's frame. */
static void copy_object(void *object, cxx_frame *frame, const cxx_catch *block, const cxx_catchable *type)
{
	char *to = (char *)&frame->ebp + block->offset;
	if (block->flags & CATCH_REFERENCE) {
		*(void **)to = adjusted(&type->offsets, object);
	} else if (type->flags & TYPE_SIMPLE) {
		memmove(to, object, type->size);
		if (type->size == sizeof(void *))
			*(void **)to = adjusted(&type->offsets, *(void **)to);
	} else if (type->copy) {
		if (type->flags & TYPE_VIRTUAL_BASE)
			((void (THISCALL *)(void *, void *, int))type->copy)(to, adjusted(&type->offsets, object), 1);
		else
			((void (THISCALL *)(void *, void *))type->copy)(to, adjusted(&type->offsets, object));
	} else {
		memmove(to, adjusted(&type->offsets, object), type->size);
	}
}

/* A catch block takes the exception: the frames above are unwound, then the function's own actions back to the try block, the block
 * runs with the exception current, the object is destroyed and the function goes on after the block. */
static void run_catch(EXCEPTION_RECORD *record, cxx_frame *frame, const cxx_function *function, const cxx_try *try_block,
	const cxx_catch *block, const cxx_catchable *type)
{
	const cxx_throw_info *info = type ? (const cxx_throw_info *)record->ExceptionInformation[2] : NULL;
	void *object = type ? (void *)record->ExceptionInformation[1] : NULL;
	if (type && block->offset && block->type && block->type->mangled[0])
		copy_object(object, frame, block, type);
	unwind_frames(&frame->link, record);
	unwind_function(frame, function, try_block->start);
	frame->state = try_block->end + 1;
	EXCEPTION_RECORD *previous = current_exception();
	set_current_exception(record);
	void *resume = raven_call_with_frame(block->handler, &frame->ebp);
	set_current_exception(previous);
	if (info && info->destructor && object)
		((void (THISCALL *)(void *))info->destructor)(object);
	raven_resume_function(frame, resume);
}

__attribute__((used)) int raven_cxx_frame_search(EXCEPTION_RECORD *record, cxx_frame *frame, CONTEXT *context, void *dispatcher, const cxx_function *function)
{
	const unsigned magic = function->magic & 0x1fffffff;
	if (magic < CXX_MAGIC_FIRST || magic > CXX_MAGIC_LAST)
		return ExceptionContinueSearch;
	if (record->ExceptionFlags & UNWINDING) {
		if (function->unwind_count)
			unwind_function(frame, function, -1);
		return ExceptionContinueSearch;
	}
	const BOOL cxx = record->ExceptionCode == CXX_EXCEPTION && record->NumberParameters >= 3 &&
		record->ExceptionInformation[0] >= CXX_MAGIC_FIRST && record->ExceptionInformation[0] <= CXX_MAGIC_LAST;
	/* Functions compiled for synchronous exceptions only catch what C++ throws. */
	if (!cxx && magic >= CXX_MAGIC_LAST && (function->flags & FUNCTION_SYNCHRONOUS))
		return ExceptionContinueSearch;
	const cxx_throw_info *info = cxx ? (const cxx_throw_info *)record->ExceptionInformation[2] : NULL;
	for (unsigned index = 0; index < function->try_count; ++index) {
		const cxx_try *try_block = &function->tries[index];
		if (frame->state < try_block->start || frame->state > try_block->end)
			continue;
		for (int choice = 0; choice < try_block->count; ++choice) {
			const cxx_catch *block = &try_block->catches[choice];
			const BOOL any = !block->type || !block->type->mangled[0];
			const cxx_catchable *type = NULL;
			if (!any) {
				if (!info || !info->catchable || !(type = caught_type(info, block)))
					continue;
			}
			run_catch(record, frame, function, try_block, block, info ? (type ? type : info->catchable->types[0]) : NULL);
		}
	}
	return ExceptionContinueSearch;
}

/* The handler compiled functions register takes its function's tables in EAX. */
__asm__(".text\n"
	".globl _raven_cxx_frame_handler\n"
	"_raven_cxx_frame_handler:\n\t"
	"pushl %eax\n\t"
	"pushl 20(%esp)\n\t"
	"pushl 20(%esp)\n\t"
	"pushl 20(%esp)\n\t"
	"pushl 20(%esp)\n\t"
	"call _raven_cxx_frame_search\n\t"
	"addl $20, %esp\n\t"
	"ret\n");

/* Ends the process for an exception no frame took, as Windows does after the last chance. */
static void unhandled(EXCEPTION_RECORD *record, CONTEXT *context)
{
	EXCEPTION_POINTERS pointers = {record, context};
	UnhandledExceptionFilter(&pointers);
	ExitProcess(record->ExceptionCode);
}

/* Raises the exception along the thread's frames; a frame that takes it never returns here, and one that continues execution of a
 * continuable exception returns to the caller. */
static void dispatch(EXCEPTION_RECORD *record, CONTEXT *context)
{
	void *dispatcher = NULL;
	for (cxx_registration *frame = frame_list(); frame && frame != (cxx_registration *)-1; frame = frame->next) {
		const int disposition = call_handler(frame, record, context, &dispatcher);
		if (disposition == ExceptionContinueExecution && !(record->ExceptionFlags & EXCEPTION_NONCONTINUABLE))
			return;
	}
	unhandled(record, context);
}

/* The caller's control registers, from this function's frame: its return address, frame pointer and stack after the arguments. */
#define CALLER_CONTEXT(context, arguments) do { \
		(context).ContextFlags = CONTEXT_CONTROL; \
		(context).Eip = (DWORD)__builtin_return_address(0); \
		(context).Ebp = *(DWORD *)__builtin_frame_address(0); \
		(context).Esp = (DWORD)__builtin_frame_address(0) + 8 + (arguments); \
	} while (0)

/* RaiseException for 32-bit programs: the runtime sends the program's call here, with its arguments, so the handlers of the frames run
 * in the program as they do on Windows. */
void __stdcall raven_raise_exception(DWORD code, DWORD flags, DWORD count, const ULONG_PTR *arguments)
{
	EXCEPTION_RECORD record = {0};
	CONTEXT context = {0};
	CALLER_CONTEXT(context, 16);
	record.ExceptionCode = code;
	record.ExceptionFlags = flags & EXCEPTION_NONCONTINUABLE;
	record.ExceptionAddress = __builtin_return_address(0);
	record.NumberParameters = count > EXCEPTION_MAXIMUM_PARAMETERS ? EXCEPTION_MAXIMUM_PARAMETERS : count;
	for (DWORD index = 0; arguments && index < record.NumberParameters; ++index)
		record.ExceptionInformation[index] = arguments[index];
	dispatch(&record, &context);
}

/* RtlUnwind for 32-bit programs: the frames above the target hear that they are being unwound and leave the chain. The compiled code
 * that calls it continues right after the call, which is where it returns. */
void __stdcall raven_unwind(cxx_registration *target, void *target_ip, EXCEPTION_RECORD *record, void *value)
{
	EXCEPTION_RECORD local = {0};
	if (!record) {
		local.ExceptionCode = 0xc0000027; /* STATUS_UNWIND */
		local.ExceptionAddress = __builtin_return_address(0);
		record = &local;
	}
	if (!target)
		record->ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
	unwind_frames(target, record);
}

/* throw: the object and its type's description; with neither, the exception the current catch block handles goes on. */
void __stdcall raven_cxx_throw(void *object, const cxx_throw_info *info)
{
	EXCEPTION_RECORD record = {0};
	record.ExceptionCode = CXX_EXCEPTION;
	record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	record.ExceptionAddress = __builtin_return_address(0);
	record.NumberParameters = 3;
	record.ExceptionInformation[0] = CXX_MAGIC_FIRST;
	record.ExceptionInformation[1] = (ULONG_PTR)object;
	record.ExceptionInformation[2] = (ULONG_PTR)info;
	if (!object && !info) {
		const EXCEPTION_RECORD *current = current_exception();
		if (!current)
			abort();
		record.ExceptionInformation[1] = current->ExceptionInformation[1];
		record.ExceptionInformation[2] = current->ExceptionInformation[2];
	}
	CONTEXT context = {0};
	CALLER_CONTEXT(context, 8);
	dispatch(&record, &context);
	abort();
}

CRT int _purecall(void)
{
	ExitProcess(255);
	return 0;
}

/* type_info: its decorated name, and the readable one made from it on demand. */
typedef struct { const void *vtable; char *name; char mangled[1]; } type_info;

void THISCALL raven_type_info_destroy(type_info *self) { free(self->name); }
const char *THISCALL raven_type_info_raw_name(const type_info *self) { return self->mangled; }
const char *THISCALL raven_type_info_name(type_info *self) { return self->mangled; }
int THISCALL raven_type_info_equal(const type_info *self, const type_info *other) { return !strcmp(self->mangled, other->mangled); }
int THISCALL raven_type_info_unequal(const type_info *self, const type_info *other) { return strcmp(self->mangled, other->mangled) != 0; }
int THISCALL raven_type_info_before(const type_info *self, const type_info *other) { return strcmp(self->mangled, other->mangled) < 0; }

/* std::exception as msvcrt has it: a table of virtual functions, the message and whether the object owns it. */
typedef struct { const void *vtable; const char *message; int owned; } exception_object;

const char *THISCALL raven_exception_what(const exception_object *self) { return self->message ? self->message : "Unknown exception"; }
void *THISCALL raven_exception_delete(exception_object *self, unsigned flags);
const void *const raven_exception_vtable[] = {(const void *)raven_exception_delete, (const void *)raven_exception_what};

static void set_message(exception_object *self, const char *message)
{
	self->vtable = raven_exception_vtable;
	self->message = NULL;
	self->owned = 0;
	if (message) {
		char *copy = malloc(strlen(message) + 1);
		if (copy) {
			strcpy(copy, message);
			self->message = copy;
			self->owned = 1;
		}
	}
}

exception_object *THISCALL raven_exception_construct(exception_object *self)
{
	set_message(self, NULL);
	return self;
}

exception_object *THISCALL raven_exception_construct_message(exception_object *self, const char *const *message)
{
	set_message(self, *message);
	return self;
}

exception_object *THISCALL raven_exception_construct_message_shared(exception_object *self, const char *const *message, int unused)
{
	self->vtable = raven_exception_vtable;
	self->message = *message;
	self->owned = 0;
	return self;
}

exception_object *THISCALL raven_exception_copy(exception_object *self, const exception_object *other)
{
	if (other->owned)
		set_message(self, other->message);
	else {
		self->vtable = raven_exception_vtable;
		self->message = other->message;
		self->owned = 0;
	}
	return self;
}

void THISCALL raven_exception_destroy(exception_object *self)
{
	self->vtable = raven_exception_vtable;
	if (self->owned)
		free((void *)self->message);
}

exception_object *THISCALL raven_exception_assign(exception_object *self, const exception_object *other)
{
	if (self != other) {
		raven_exception_destroy(self);
		raven_exception_copy(self, other);
	}
	return self;
}

/* The deleting destructor: flag 1 frees the object, flag 2 an array whose count precedes it. */
void *THISCALL raven_exception_delete(exception_object *self, unsigned flags)
{
	if (flags & 2) {
		int *count = (int *)self - 1;
		for (int index = 0; index < *count; ++index)
			raven_exception_destroy(self + index);
		if (flags & 1)
			free(count);
		return count;
	}
	raven_exception_destroy(self);
	if (flags & 1)
		free(self);
	return self;
}

#endif
