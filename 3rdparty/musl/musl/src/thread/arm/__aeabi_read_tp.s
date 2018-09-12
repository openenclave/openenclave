.syntax unified
.global __aeabi_read_tp
.type __aeabi_read_tp,%function
__aeabi_read_tp:
	push {r1,r2,r3,lr}
	bl __aeabi_read_tp_c
	pop {r1,r2,r3,lr}
	bx lr
