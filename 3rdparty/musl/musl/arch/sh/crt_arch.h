__asm__(
".text \n"
".global " START " \n"
START ": \n"
"	mova 1f, r0 \n"
"	mov.l 1f, r5 \n"
"	add r0, r5 \n"
"	mov r15, r4 \n"
"	mov #-16, r0 \n"
"	and r0, r15 \n"
"	bsr " START "_c \n"
"	nop \n"
".align 2 \n"
".weak _DYNAMIC \n"
".hidden _DYNAMIC \n"
"1:	.long _DYNAMIC-. \n"
);

/* used by gcc for switching the FPU between single and double precision */
#ifdef SHARED
__attribute__((__visibility__("hidden")))
#endif
const unsigned long __fpscr_values[2] = { 0, 0x80000 };
