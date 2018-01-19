.text

.global __a_barrier
.hidden __a_barrier
.type __a_barrier,%function
__a_barrier:
	ldr ip,1f
	ldr ip,[pc,ip]
	add pc,pc,ip
1:	.word __a_barrier_ptr-1b
.global __a_barrier_dummy
.hidden __a_barrier_dummy
__a_barrier_dummy:
	tst lr,#1
	moveq pc,lr
	bx lr
.global __a_barrier_oldkuser
.hidden __a_barrier_oldkuser
__a_barrier_oldkuser:
	push {r0,r1,r2,r3,ip,lr}
	mov r1,r0
	mov r2,sp
	ldr ip,=0xffff0fc0
	mov lr,pc
	mov pc,ip
	pop {r0,r1,r2,r3,ip,lr}
	tst lr,#1
	moveq pc,lr
	bx lr
.global __a_barrier_v6
.hidden __a_barrier_v6
__a_barrier_v6:
	mcr p15,0,r0,c7,c10,5
	bx lr
.global __a_barrier_v7
.hidden __a_barrier_v7
__a_barrier_v7:
	.word 0xf57ff05b        /* dmb ish */
	bx lr

.global __a_cas
.hidden __a_cas
.type __a_cas,%function
__a_cas:
	ldr ip,1f
	ldr ip,[pc,ip]
	add pc,pc,ip
1:	.word __a_cas_ptr-1b
.global __a_cas_dummy
.hidden __a_cas_dummy
__a_cas_dummy:
	mov r3,r0
	ldr r0,[r2]
	subs r0,r3,r0
	streq r1,[r2]
	tst lr,#1
	moveq pc,lr
	bx lr
.global __a_cas_v6
.hidden __a_cas_v6
__a_cas_v6:
	mov r3,r0
	mcr p15,0,r0,c7,c10,5
1:	.word 0xe1920f9f        /* ldrex r0,[r2] */
	subs r0,r3,r0
	.word 0x01820f91        /* strexeq r0,r1,[r2] */
	teqeq r0,#1
	beq 1b
	mcr p15,0,r0,c7,c10,5
	bx lr
.global __a_cas_v7
.hidden __a_cas_v7
__a_cas_v7:
	mov r3,r0
	.word 0xf57ff05b        /* dmb ish */
1:	.word 0xe1920f9f        /* ldrex r0,[r2] */
	subs r0,r3,r0
	.word 0x01820f91        /* strexeq r0,r1,[r2] */
	teqeq r0,#1
	beq 1b
	.word 0xf57ff05b        /* dmb ish */
	bx lr

.global __aeabi_read_tp
.type __aeabi_read_tp,%function
__aeabi_read_tp:

.global __a_gettp
.hidden __a_gettp
.type __a_gettp,%function
__a_gettp:
	ldr r0,1f
	ldr r0,[pc,r0]
	add pc,pc,r0
1:	.word __a_gettp_ptr-1b
.global __a_gettp_dummy
.hidden __a_gettp_dummy
__a_gettp_dummy:
	mrc p15,0,r0,c13,c0,3
	bx lr

.data
.global __a_barrier_ptr
.hidden __a_barrier_ptr
__a_barrier_ptr:
	.word 0

.global __a_cas_ptr
.hidden __a_cas_ptr
__a_cas_ptr:
	.word 0

.global __a_gettp_ptr
.hidden __a_gettp_ptr
__a_gettp_ptr:
	.word 0
