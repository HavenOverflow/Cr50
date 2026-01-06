.text
.syntax unified

.thumb
.align 2
.global reset

.thumb_func
reset:
	movs r1, #0
	mov r2, r1
	mov r3, r1
	mov r4, r1
	mov r5, r1
	mov r6, r1
	mov r7, r1
	mov r8, r1
	mov r9, r1
	mov r10, r1
	mov r11, r1
	mov r12, r1
	ldr r0, [pc, #0]
	bx r0
	.align 2
	.word main

