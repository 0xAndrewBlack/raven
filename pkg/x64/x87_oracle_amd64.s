//go:build linux && amd64

#include "textflag.h"

TEXT hostX87Add(SB), NOSPLIT, $128-26
	MOVQ a+0(FP), AX
	MOVQ AX, 0(SP)
	MOVQ b+8(FP), AX
	MOVQ AX, 8(SP)
	BYTE $0xdd
	BYTE $0x74
	BYTE $0x24
	BYTE $0x10
	BYTE $0xdd
	BYTE $0x04
	BYTE $0x24
	BYTE $0xdc
	BYTE $0x44
	BYTE $0x24
	BYTE $0x08
	BYTE $0xdd
	BYTE $0x1c
	BYTE $0x24
	MOVQ 0(SP), AX
	MOVQ AX, result+16(FP)
	BYTE $0xdf
	BYTE $0xe0
	MOVW AX, status+24(FP)
	BYTE $0xdd
	BYTE $0x64
	BYTE $0x24
	BYTE $0x10
	RET
