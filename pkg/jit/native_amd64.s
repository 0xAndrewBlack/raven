#include "textflag.h"

// func enterNative(code uintptr, env *NativeEnv)
// Enters generated code with the register-file pointer in DI. Generated
// code preserves DI, clobbers only caller-saved registers, makes no calls
// and returns with RET.
TEXT ·enterNative(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ code+0(FP), AX
	MOVQ env+8(FP), DI
	CALL AX
	RET
