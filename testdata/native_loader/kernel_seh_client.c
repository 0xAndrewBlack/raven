#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <excpt.h>

#define CHECK(code,condition) do { if(!(condition)) return code; } while(0)

// The scope table that the compiler emits for each function using __try; the handler walks it for the faulting pc.
typedef struct { ULONG begin, end, handler, target; } SCOPE;
typedef struct { ULONG count; SCOPE scopes[1]; } SCOPE_TABLE;

EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD record,PVOID frame,PCONTEXT context,PDISPATCHER_CONTEXT dispatcher)
{
	const SCOPE_TABLE *table=(const SCOPE_TABLE *)dispatcher->HandlerData;
	const ULONG64 base=dispatcher->ImageBase;
	const ULONG64 pc=dispatcher->ControlPc-base;
	for(ULONG index=dispatcher->ScopeIndex;index<table->count;++index) {
		const SCOPE *scope=&table->scopes[index];
		if(pc<scope->begin || pc>=scope->end) continue;
		if(record->ExceptionFlags&(EXCEPTION_UNWINDING|EXCEPTION_EXIT_UNWIND)) {
			// Unwinding runs termination handlers (no target) for scopes the exception leaves.
			if(scope->target==0) {
				dispatcher->ScopeIndex=index+1;
				((void (*)(BOOLEAN,PVOID))(base+scope->handler))(TRUE,frame);
			} else if(dispatcher->TargetIp==base+scope->target) {
				return ExceptionContinueSearch;
			}
			continue;
		}
		if(scope->target==0) continue;
		LONG decision=EXCEPTION_EXECUTE_HANDLER;
		if(scope->handler!=1) {
			EXCEPTION_POINTERS pointers={record,context};
			decision=((LONG (*)(PEXCEPTION_POINTERS,PVOID))(base+scope->handler))(&pointers,frame);
		}
		if(decision==EXCEPTION_CONTINUE_EXECUTION) return ExceptionContinueExecution;
		if(decision==EXCEPTION_EXECUTE_HANDLER) {
			RtlUnwindEx(frame,(PVOID)(base+scope->target),record,0,dispatcher->ContextRecord,dispatcher->HistoryTable);
			return ExceptionContinueSearch;
		}
	}
	return ExceptionContinueSearch;
}

static volatile LONG trail[16];
static volatile LONG trail_count;
static void note(LONG value) { trail[trail_count++]=value; }

static int fault_code;
static LONG record_code(PEXCEPTION_POINTERS pointers)
{
	fault_code=(int)pointers->ExceptionRecord->ExceptionCode;
	return EXCEPTION_EXECUTE_HANDLER;
}

static int null_write(void)
{
	volatile int *pointer=0;
	__try {
		*pointer=1;
		return 0;
	} __except(record_code(GetExceptionInformation())) {
		return fault_code==(int)EXCEPTION_ACCESS_VIOLATION ? 1 : 2;
	}
}

static int divide(volatile int zero)
{
	__try {
		return 10/zero;
	} __except(EXCEPTION_EXECUTE_HANDLER) {
		return -1;
	}
}

static void cleanup_inner(void)
{
	__try {
		note(1);
		RaiseException(0xe0001234,EXCEPTION_NONCONTINUABLE,0,0);
		note(99);
	} __finally {
		note(2);
	}
}

static int cleanup_outer(void)
{
	__try {
		cleanup_inner();
		note(98);
		return 0;
	} __except(GetExceptionCode()==0xe0001234 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		note(3);
		return 1;
	}
}

static int deep(int depth)
{
	if(depth==0) {
		RaiseException(0xe0000042,0,1,(const ULONG_PTR []){7});
		return 0;
	}
	volatile char padding[200];
	padding[0]=(char)depth;
	return deep(depth-1)+padding[0];
}

static LONG resume_filter(PEXCEPTION_POINTERS pointers)
{
	return pointers->ExceptionRecord->ExceptionCode==0xe0000077 ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

static int continuable(void)
{
	int reached=0;
	__try {
		RaiseException(0xe0000077,0,0,0);
		reached=1;
	} __except(resume_filter(GetExceptionInformation())) {
		return -1;
	}
	return reached;
}

static LONG parameter_filter(PEXCEPTION_POINTERS pointers)
{
	fault_code=(int)pointers->ExceptionRecord->ExceptionInformation[0];
	return EXCEPTION_EXECUTE_HANDLER;
}

static LONG WINAPI last_resort(PEXCEPTION_POINTERS pointers)
{
	(void)pointers;
	return EXCEPTION_EXECUTE_HANDLER;
}

int raven_entry(void)
{
	CHECK(1,null_write()==1);
	CHECK(2,divide(0)==-1 && divide(2)==5);
	CHECK(3,cleanup_outer()==1);
	CHECK(4,trail_count==3 && trail[0]==1 && trail[1]==2 && trail[2]==3);
	int caught=0;
	__try {
		deep(20);
	} __except(parameter_filter(GetExceptionInformation())) {
		caught=1;
	}
	CHECK(5,caught==1 && fault_code==7);
	CHECK(6,continuable()==1);
	// Nothing handles this one: the program's own top-level filter must see it before the process dies.
	CHECK(7,SetUnhandledExceptionFilter(last_resort)==0);
	CHECK(8,SetUnhandledExceptionFilter(0)==last_resort);
	return 0;
}
