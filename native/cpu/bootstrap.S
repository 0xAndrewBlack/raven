.section .text
.global _start
_start:
	int3
	syscall
	int3
	ud2

.section .note.GNU-stack,"",@progbits
