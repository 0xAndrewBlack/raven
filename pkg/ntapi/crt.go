package ntapi

import "github.com/mirkobrombin/go-vm/pkg/mmu"

// PatchCRTFunctions replaces synthetic ntdll CRT stubs with real x64 machine
// code so they execute natively in the emulator instead of trapping.
func PatchCRTFunctions(synth *SynthPE, mem *mmu.MMU) {
	// memcpy(rcx=dst, rdx=src, r8=count) → rax=dst
	synth.PatchStub(mem, "memcpy", []byte{
		0x48, 0x89, 0xC8, //  0: mov rax, rcx
		0x4D, 0x85, 0xC0, //  3: test r8, r8
		0x74, 0x10, //        6: je 24 (done)
		0x56,       //        8: push rsi
		0x57,       //        9: push rdi
		0x48, 0x89, 0xCF, // 10: mov rdi, rcx
		0x48, 0x89, 0xD6, // 13: mov rsi, rdx
		0x4C, 0x89, 0xC1, // 16: mov rcx, r8
		0xF3, 0xA4, //       19: rep movsb
		0x5F,       //       21: pop rdi
		0x5E,       //       22: pop rsi
		0xC3,       //       23: ret
		0xC3,       //       24: ret (done - no pushes were done)
	})

	// memmove(rcx=dst, rdx=src, r8=count) → rax=dst
	synth.PatchStub(mem, "memmove", []byte{
		0x48, 0x89, 0xC8, //  0: mov rax, rcx
		0x4D, 0x85, 0xC0, //  3: test r8, r8
		0x74, 0x33, //        6: je 59 (done)
		0x48, 0x39, 0xD1, //  8: cmp rcx, rdx
		0x76, 0x1E, //       11: jbe 43 (forward)
		// backward copy
		0x56,             // 13: push rsi
		0x57,             // 14: push rdi
		0x48, 0x89, 0xCF, // 15: mov rdi, rcx
		0x48, 0x89, 0xD6, // 18: mov rsi, rdx
		0x4C, 0x89, 0xC1, // 21: mov rcx, r8
		0xFD,             // 24: std
		0x48, 0x01, 0xCF, // 25: add rdi, rcx
		0x48, 0xFF, 0xCF, // 28: dec rdi
		0x48, 0x01, 0xCE, // 31: add rsi, rcx
		0x48, 0xFF, 0xCE, // 34: dec rsi
		0xF3, 0xA4,       // 37: rep movsb
		0xFC,             // 39: cld
		0x5F,             // 40: pop rdi
		0x5E,             // 41: pop rsi
		0xC3,             // 42: ret
		// forward copy
		0x56,             // 43: push rsi
		0x57,             // 44: push rdi
		0x48, 0x89, 0xCF, // 45: mov rdi, rcx
		0x48, 0x89, 0xD6, // 48: mov rsi, rdx
		0x4C, 0x89, 0xC1, // 51: mov rcx, r8
		0xF3, 0xA4,       // 54: rep movsb
		0x5F,             // 56: pop rdi
		0x5E,             // 57: pop rsi
		0xC3,             // 58: ret
		0xC3,             // 59: ret (done - no pushes)
	})

	// memset(rcx=dst, edx=val, r8=count) → rax=dst
	synth.PatchStub(mem, "memset", []byte{
		0x57,             //  0: push rdi
		0x48, 0x89, 0xCF, //  1: mov rdi, rcx
		0x48, 0x89, 0xC8, //  4: mov rax, rcx (save dst)
		0x4D, 0x85, 0xC0, //  7: test r8, r8
		0x74, 0x09, //       10: je 21 (done)
		0x50,             // 12: push rax
		0x88, 0xD0,       // 13: mov al, dl
		0x4C, 0x89, 0xC1, // 15: mov rcx, r8
		0xF3, 0xAA,       // 18: rep stosb
		0x58,             // 20: pop rax
		0x5F,             // 21: pop rdi (done)
		0xC3,             // 22: ret
	})

	// memcmp(rcx=s1, rdx=s2, r8=count) → eax (neg/0/pos)
	synth.PatchStub(mem, "memcmp", []byte{
		0x56,             //  0: push rsi
		0x57,             //  1: push rdi
		0x48, 0x89, 0xCF, //  2: mov rdi, rcx
		0x48, 0x89, 0xD6, //  5: mov rsi, rdx
		0x4C, 0x89, 0xC1, //  8: mov rcx, r8
		0x31, 0xC0,       // 11: xor eax, eax
		0x48, 0x85, 0xC9, // 13: test rcx, rcx
		0x74, 0x07, //       16: je 25 (done)
		0xF3, 0xA6,       // 18: repe cmpsb
		0x74, 0x03, //       20: je 25 (done)
		0x0F, 0x92, 0xC0, // 22: setb al
		0x5F,             // 25: pop rdi (done)
		0x5E,             // 26: pop rsi
		0xC3,             // 27: ret
	})

	// strlen(rcx=str) → rax=length
	synth.PatchStub(mem, "strlen", []byte{
		0x48, 0x31, 0xC0,       //  0: xor rax, rax
		0x80, 0x3C, 0x01, 0x00, //  3: cmp byte [rcx+rax], 0
		0x74, 0x04,             //  7: je 13 (done)
		0x48, 0xFF, 0xC0,       //  9: inc rax
		0xEB, 0xF5,             // 12: jmp 3 (loop)
		0xC3,                   // 13: ret
	})

	// wcslen(rcx=str) → rax=length (wide chars)
	synth.PatchStub(mem, "wcslen", []byte{
		0x48, 0x31, 0xC0,             //  0: xor rax, rax
		0x66, 0x83, 0x3C, 0x41, 0x00, //  3: cmp word [rcx+rax*2], 0
		0x74, 0x04,                   //  8: je 14 (done)
		0x48, 0xFF, 0xC0,             // 10: inc rax
		0xEB, 0xF4,                   // 13: jmp 3 (loop)
		0xC3,                         // 14: ret (was already 15, OK)
	})

	// wcsnlen(rcx=str, rdx=maxlen) → rax=length
	synth.PatchStub(mem, "wcsnlen", []byte{
		0x48, 0x31, 0xC0,             //  0: xor rax, rax
		0x48, 0x39, 0xD0,             //  3: cmp rax, rdx
		0x7D, 0x0C,                   //  6: jge 20 (done)
		0x66, 0x83, 0x3C, 0x41, 0x00, //  8: cmp word [rcx+rax*2], 0
		0x74, 0x05,                   // 13: je 20 (done)
		0x48, 0xFF, 0xC0,             // 15: inc rax
		0xEB, 0xEF,                   // 18: jmp 3 (loop)
		0xC3,                         // 20: ret
	})

	// strcpy(rcx=dst, rdx=src) → rax=dst
	synth.PatchStub(mem, "strcpy", []byte{
		0x48, 0x89, 0xC8,       //  0: mov rax, rcx
		0x44, 0x8A, 0x1A,       //  3: mov r11b, [rdx]  (loop)
		0x44, 0x88, 0x19,       //  6: mov [rcx], r11b
		0x45, 0x84, 0xDB,       //  9: test r11b, r11b
		0x74, 0x08,             // 12: je 22 (done)
		0x48, 0xFF, 0xC1,       // 14: inc rcx
		0x48, 0xFF, 0xC2,       // 17: inc rdx
		0xEB, 0xED,             // 20: jmp 3 (loop)
		0xC3,                   // 22: ret
	})

	// wcscpy(rcx=dst, rdx=src) → rax=dst
	synth.PatchStub(mem, "wcscpy", []byte{
		0x48, 0x89, 0xC8,             //  0: mov rax, rcx
		0x66, 0x44, 0x8B, 0x1A,       //  3: mov r11w, [rdx]  (loop)
		0x66, 0x44, 0x89, 0x19,       //  7: mov [rcx], r11w
		0x66, 0x45, 0x85, 0xDB,       // 11: test r11w, r11w
		0x74, 0x0A,                   // 15: je 27 (done)
		0x48, 0x83, 0xC1, 0x02,       // 17: add rcx, 2
		0x48, 0x83, 0xC2, 0x02,       // 21: add rdx, 2
		0xEB, 0xE8,                   // 25: jmp 3 (loop)
		0xC3,                         // 27: ret
	})

	// strcmp(rcx=s1, rdx=s2) → eax
	synth.PatchStub(mem, "strcmp", []byte{
		0x8A, 0x01,       //  0: mov al, [rcx]  (loop)
		0x3A, 0x02,       //  2: cmp al, [rdx]
		0x75, 0x0C,       //  4: jne 18 (diff)
		0x84, 0xC0,       //  6: test al, al
		0x74, 0x11,       //  8: je 27 (equal)
		0x48, 0xFF, 0xC1, // 10: inc rcx
		0x48, 0xFF, 0xC2, // 13: inc rdx
		0xEB, 0xEE,       // 16: jmp 0 (loop)
		// diff:
		0x0F, 0xB6, 0xC0, // 18: movzx eax, al
		0x0F, 0xB6, 0x0A, // 21: movzx ecx, byte [rdx]
		0x29, 0xC8,       // 24: sub eax, ecx
		0xC3,             // 26: ret
		// equal:
		0x31, 0xC0,       // 27: xor eax, eax
		0xC3,             // 29: ret
	})

	// wcscmp(rcx=s1, rdx=s2) → eax
	synth.PatchStub(mem, "wcscmp", []byte{
		0x66, 0x8B, 0x01,       //  0: mov ax, [rcx]  (loop)
		0x66, 0x3B, 0x02,       //  3: cmp ax, [rdx]
		0x75, 0x0F,             //  6: jne 23 (diff)
		0x66, 0x85, 0xC0,       //  8: test ax, ax
		0x74, 0x13,             // 11: je 32 (equal)
		0x48, 0x83, 0xC1, 0x02, // 13: add rcx, 2
		0x48, 0x83, 0xC2, 0x02, // 17: add rdx, 2
		0xEB, 0xE9,             // 21: jmp 0 (loop)
		// diff:
		0x0F, 0xB7, 0xC0, // 23: movzx eax, ax
		0x0F, 0xB7, 0x0A, // 26: movzx ecx, word [rdx]
		0x29, 0xC8,       // 29: sub eax, ecx
		0xC3,             // 31: ret
		// equal:
		0x31, 0xC0,       // 32: xor eax, eax
		0xC3,             // 34: ret
	})

	// strncmp(rcx=s1, rdx=s2, r8=n) → eax
	synth.PatchStub(mem, "strncmp", []byte{
		0x4D, 0x85, 0xC0, //  0: test r8, r8
		0x74, 0x20,       //  3: je 37 (equal)
		0x8A, 0x01,       //  5: mov al, [rcx]  (loop)
		0x3A, 0x02,       //  7: cmp al, [rdx]
		0x75, 0x11,       //  9: jne 28 (diff)
		0x84, 0xC0,       // 11: test al, al
		0x74, 0x16,       // 13: je 37 (equal)
		0x48, 0xFF, 0xC1, // 15: inc rcx
		0x48, 0xFF, 0xC2, // 18: inc rdx
		0x49, 0xFF, 0xC8, // 21: dec r8
		0x75, 0xEB,       // 24: jnz 5 (loop)
		0xEB, 0x09,       // 26: jmp 37 (equal)
		// diff:
		0x0F, 0xB6, 0xC0, // 28: movzx eax, al
		0x0F, 0xB6, 0x0A, // 31: movzx ecx, byte [rdx]
		0x29, 0xC8,       // 34: sub eax, ecx
		0xC3,             // 36: ret
		// equal:
		0x31, 0xC0,       // 37: xor eax, eax
		0xC3,             // 39: ret
	})

	// wcsncmp(rcx=s1, rdx=s2, r8=n) → eax
	synth.PatchStub(mem, "wcsncmp", []byte{
		0x4D, 0x85, 0xC0,       //  0: test r8, r8
		0x74, 0x25,             //  3: je 42 (equal)
		0x66, 0x8B, 0x01,       //  5: mov ax, [rcx]  (loop)
		0x66, 0x3B, 0x02,       //  8: cmp ax, [rdx]
		0x75, 0x14,             // 11: jne 33 (diff)
		0x66, 0x85, 0xC0,       // 13: test ax, ax
		0x74, 0x18,             // 16: je 42 (equal)
		0x48, 0x83, 0xC1, 0x02, // 18: add rcx, 2
		0x48, 0x83, 0xC2, 0x02, // 22: add rdx, 2
		0x49, 0xFF, 0xC8,       // 26: dec r8
		0x75, 0xE6,             // 29: jnz 5 (loop)
		0xEB, 0x09,             // 31: jmp 42 (equal)
		// diff:
		0x0F, 0xB7, 0xC0, // 33: movzx eax, ax
		0x0F, 0xB7, 0x0A, // 36: movzx ecx, word [rdx]
		0x29, 0xC8,       // 39: sub eax, ecx
		0xC3,             // 41: ret
		// equal:
		0x31, 0xC0,       // 42: xor eax, eax
		0xC3,             // 44: ret
	})

	// wcscat(rcx=dst, rdx=src) → rax=dst
	synth.PatchStub(mem, "wcscat", []byte{
		0x48, 0x89, 0xC8,             //  0: mov rax, rcx
		0x66, 0x83, 0x39, 0x00,       //  3: cmp word [rcx], 0  (findEnd)
		0x74, 0x06,                   //  7: je 15 (copy)
		0x48, 0x83, 0xC1, 0x02,       //  9: add rcx, 2
		0xEB, 0xF4,                   // 13: jmp 3 (findEnd)
		// copy
		0x66, 0x44, 0x8B, 0x1A,       // 15: mov r11w, [rdx]  (copyLoop)
		0x66, 0x44, 0x89, 0x19,       // 19: mov [rcx], r11w
		0x66, 0x45, 0x85, 0xDB,       // 23: test r11w, r11w
		0x74, 0x0A,                   // 27: je 39 (done)
		0x48, 0x83, 0xC1, 0x02,       // 29: add rcx, 2
		0x48, 0x83, 0xC2, 0x02,       // 33: add rdx, 2
		0xEB, 0xE8,                   // 37: jmp 15 (copyLoop)
		0xC3,                         // 39: ret
	})

	// strcat(rcx=dst, rdx=src) → rax=dst
	synth.PatchStub(mem, "strcat", []byte{
		0x48, 0x89, 0xC8, //  0: mov rax, rcx
		0x80, 0x39, 0x00, //  3: cmp byte [rcx], 0  (findEnd)
		0x74, 0x05,       //  6: je 13 (copy)
		0x48, 0xFF, 0xC1, //  8: inc rcx
		0xEB, 0xF6,       // 11: jmp 3 (findEnd)
		// copy
		0x44, 0x8A, 0x1A, // 13: mov r11b, [rdx]  (copyLoop)
		0x44, 0x88, 0x19, // 16: mov [rcx], r11b
		0x45, 0x84, 0xDB, // 19: test r11b, r11b
		0x74, 0x08,       // 22: je 32 (done)
		0x48, 0xFF, 0xC1, // 24: inc rcx
		0x48, 0xFF, 0xC2, // 27: inc rdx
		0xEB, 0xED,       // 30: jmp 13 (copyLoop)
		0xC3,             // 32: ret
	})

	// strchr(rcx=str, edx=char) → rax (ptr or 0)
	synth.PatchStub(mem, "strchr", []byte{
		0x8A, 0x01,       //  0: mov al, [rcx]  (loop)
		0x38, 0xD0,       //  2: cmp al, dl
		0x74, 0x09,       //  4: je 15 (found)
		0x84, 0xC0,       //  6: test al, al
		0x74, 0x09,       //  8: je 19 (notfound)
		0x48, 0xFF, 0xC1, // 10: inc rcx
		0xEB, 0xF1,       // 13: jmp 0 (loop)
		// found:
		0x48, 0x89, 0xC8, // 15: mov rax, rcx
		0xC3,             // 18: ret
		// notfound:
		0x48, 0x31, 0xC0, // 19: xor rax, rax
		0xC3,             // 22: ret
	})

	// strrchr(rcx=str, edx=char) → rax (ptr or 0)
	synth.PatchStub(mem, "strrchr", []byte{
		0x48, 0x31, 0xC0, //  0: xor rax, rax (last=NULL)
		0x44, 0x8A, 0x19, //  3: mov r11b, [rcx]  (loop)
		0x41, 0x38, 0xD3, //  6: cmp r11b, dl
		0x75, 0x03,       //  9: jne 14 (skip)
		0x48, 0x89, 0xC8, // 11: mov rax, rcx
		// skip:
		0x45, 0x84, 0xDB, // 14: test r11b, r11b
		0x74, 0x05,       // 17: je 24 (done)
		0x48, 0xFF, 0xC1, // 19: inc rcx
		0xEB, 0xEB,       // 22: jmp 3 (loop)
		0xC3,             // 24: ret
	})

	// wcschr(rcx=str, edx=wchar) → rax
	synth.PatchStub(mem, "wcschr", []byte{
		0x66, 0x8B, 0x01,       //  0: mov ax, [rcx]  (loop)
		0x66, 0x39, 0xD0,       //  3: cmp ax, dx
		0x74, 0x0B,             //  6: je 19 (found)
		0x66, 0x85, 0xC0,       //  8: test ax, ax
		0x74, 0x0A,             // 11: je 23 (notfound)
		0x48, 0x83, 0xC1, 0x02, // 13: add rcx, 2
		0xEB, 0xED,             // 17: jmp 0 (loop)
		// found:
		0x48, 0x89, 0xC8, // 19: mov rax, rcx
		0xC3,             // 22: ret
		// notfound:
		0x48, 0x31, 0xC0, // 23: xor rax, rax
		0xC3,             // 26: ret
	})

	// wcsrchr(rcx=str, edx=wchar) → rax
	synth.PatchStub(mem, "wcsrchr", []byte{
		0x48, 0x31, 0xC0,       //  0: xor rax, rax (last=NULL)
		0x66, 0x44, 0x8B, 0x01, //  3: mov r8w, [rcx]  (loop)
		0x66, 0x41, 0x39, 0xD0, //  7: cmp r8w, dx
		0x75, 0x03,             // 11: jne 16 (skip)
		0x48, 0x89, 0xC8,       // 13: mov rax, rcx
		// skip:
		0x66, 0x45, 0x85, 0xC0, // 16: test r8w, r8w
		0x74, 0x06,             // 20: je 28 (done)
		0x48, 0x83, 0xC1, 0x02, // 22: add rcx, 2
		0xEB, 0xE7,             // 26: jmp 3 (loop)
		0xC3,                   // 28: ret
	})

	// tolower(ecx=char) → eax
	synth.PatchStub(mem, "tolower", []byte{
		0x89, 0xC8,       //  0: mov eax, ecx
		0x83, 0xF8, 0x41, //  2: cmp eax, 'A'
		0x7C, 0x08,       //  5: jl 15 (done)
		0x83, 0xF8, 0x5A, //  7: cmp eax, 'Z'
		0x7F, 0x03,       // 10: jg 15 (done)
		0x83, 0xC0, 0x20, // 12: add eax, 0x20
		0xC3,             // 15: ret
	})

	// towupper(ecx=wchar) → eax
	synth.PatchStub(mem, "towupper", []byte{
		0x89, 0xC8,       //  0: mov eax, ecx
		0x83, 0xF8, 0x61, //  2: cmp eax, 'a'
		0x7C, 0x08,       //  5: jl 15 (done)
		0x83, 0xF8, 0x7A, //  7: cmp eax, 'z'
		0x7F, 0x03,       // 10: jg 15 (done)
		0x83, 0xE8, 0x20, // 12: sub eax, 0x20
		0xC3,             // 15: ret
	})

	// isalnum(ecx=char) → eax (nonzero if alphanumeric)
	synth.PatchStub(mem, "isalnum", []byte{
		0x89, 0xC8,                   //  0: mov eax, ecx
		0x83, 0xF8, 0x30,             //  2: cmp eax, '0'
		0x7C, 0x0B,                   //  5: jl 18 (checkAlpha)
		0x83, 0xF8, 0x39,             //  7: cmp eax, '9'
		0x7F, 0x06,                   // 10: jg 18 (checkAlpha)
		0xB8, 0x01, 0x00, 0x00, 0x00, // 12: mov eax, 1
		0xC3,                         // 17: ret
		// checkAlpha (upper)
		0x83, 0xF9, 0x41,             // 18: cmp ecx, 'A'
		0x7C, 0x0B,                   // 21: jl 34 (checkLower)
		0x83, 0xF9, 0x5A,             // 23: cmp ecx, 'Z'
		0x7F, 0x06,                   // 26: jg 34 (checkLower)
		0xB8, 0x01, 0x00, 0x00, 0x00, // 28: mov eax, 1
		0xC3,                         // 33: ret
		// checkLower
		0x83, 0xF9, 0x61,             // 34: cmp ecx, 'a'
		0x7C, 0x0B,                   // 37: jl 50 (no)
		0x83, 0xF9, 0x7A,             // 39: cmp ecx, 'z'
		0x7F, 0x06,                   // 42: jg 50 (no)
		0xB8, 0x01, 0x00, 0x00, 0x00, // 44: mov eax, 1
		0xC3,                         // 49: ret
		// no
		0x31, 0xC0,                   // 50: xor eax, eax
		0xC3,                         // 52: ret
	})

	// strtol and wcstol are too complex for 64 bytes, keep as handlers

	// Wine debug functions - inline stubs to avoid vmcall overhead and
	// prevent infinite recursion when Wine DLLs use TRACE/WARN/ERR macros.

	// __wine_dbg_get_channel_flags(channel) → 0 (all debug output disabled)
	synth.PatchStub(mem, "__wine_dbg_get_channel_flags", []byte{
		0x31, 0xC0, // xor eax, eax
		0xC3,       // ret
	})

	// __wine_dbg_header(cls, channel, func) → pointer to empty string
	// lea rax, [rip+1] makes RAX point to the 0x00 byte after ret
	synth.PatchStub(mem, "__wine_dbg_header", []byte{
		0x48, 0x8D, 0x05, 0x01, 0x00, 0x00, 0x00, // lea rax, [rip+1]
		0xC3, // ret
		// 0x00 padding byte serves as the empty string's null terminator
	})

	// __wine_dbg_output(str) → 0 (chars written)
	synth.PatchStub(mem, "__wine_dbg_output", []byte{
		0x31, 0xC0, // xor eax, eax
		0xC3,       // ret
	})

	// __wine_dbg_strdup(str) → same pointer (identity)
	synth.PatchStub(mem, "__wine_dbg_strdup", []byte{
		0x48, 0x89, 0xC8, // mov rax, rcx
		0xC3,             // ret
	})
}
