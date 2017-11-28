#ifndef _INTERNAL_ATOMIC_H
#define _INTERNAL_ATOMIC_H

#include <stdint.h>

static inline int a_ctz_l(unsigned long x)
{
	static const char debruijn32[32] = {
		0, 1, 23, 2, 29, 24, 19, 3, 30, 27, 25, 11, 20, 8, 4, 13,
		31, 22, 28, 18, 26, 10, 7, 12, 21, 17, 9, 6, 16, 5, 15, 14
	};
	return debruijn32[(x&-x)*0x076be629 >> 27];
}

static inline int a_ctz_64(uint64_t x)
{
	uint32_t y = x;
	if (!y) {
		y = x>>32;
		return 32 + a_ctz_l(y);
	}
	return a_ctz_l(y);
}

#define LLSC_CLOBBERS "r0", "t", "memory"
#define LLSC_START(mem) "synco\n"  \
	"0:	movli.l @" mem ", r0\n"
#define LLSC_END(mem)              \
	"1:	movco.l r0, @" mem "\n"    \
	"	bf 0b\n"                   \
	"	synco\n"

static inline int __sh_cas_llsc(volatile int *p, int t, int s)
{
	int old;
	__asm__ __volatile__(
		LLSC_START("%1")
		"	mov r0, %0\n"
		"	cmp/eq %0, %2\n"
		"	bf 1f\n"
		"	mov %3, r0\n"
		LLSC_END("%1")
		: "=&r"(old) : "r"(p), "r"(t), "r"(s) : LLSC_CLOBBERS);
	return old;
}

static inline int __sh_swap_llsc(volatile int *x, int v)
{
	int old;
	__asm__ __volatile__(
		LLSC_START("%1")
		"	mov r0, %0\n"
		"	mov %2, r0\n"
		LLSC_END("%1")
		: "=&r"(old) : "r"(x), "r"(v) : LLSC_CLOBBERS);
	return old;
}

static inline int __sh_fetch_add_llsc(volatile int *x, int v)
{
	int old;
	__asm__ __volatile__(
		LLSC_START("%1")
		"	mov r0, %0\n"
		"	add %2, r0\n"
		LLSC_END("%1")
		: "=&r"(old) : "r"(x), "r"(v) : LLSC_CLOBBERS);
	return old;
}

static inline void __sh_store_llsc(volatile int *p, int x)
{
	__asm__ __volatile__(
		"	synco\n"
		"	mov.l %1, @%0\n"
		"	synco\n"
		: : "r"(p), "r"(x) : "memory");
}

static inline void __sh_and_llsc(volatile int *x, int v)
{
	__asm__ __volatile__(
		LLSC_START("%0")
		"	and %1, r0\n"
		LLSC_END("%0")
		: : "r"(x), "r"(v) : LLSC_CLOBBERS);
}

static inline void __sh_or_llsc(volatile int *x, int v)
{
	__asm__ __volatile__(
		LLSC_START("%0")
		"	or %1, r0\n"
		LLSC_END("%0")
		: : "r"(x), "r"(v) : LLSC_CLOBBERS);
}

#ifdef __SH4A__
#define a_cas(p,t,s)     __sh_cas_llsc(p,t,s)
#define a_swap(x,v)      __sh_swap_llsc(x,v)
#define a_fetch_add(x,v) __sh_fetch_add_llsc(x, v)
#define a_store(x,v)     __sh_store_llsc(x, v)
#define a_and(x,v)       __sh_and_llsc(x, v)
#define a_or(x,v)        __sh_or_llsc(x, v)
#else

int  __sh_cas(volatile int *, int, int);
int  __sh_swap(volatile int *, int);
int  __sh_fetch_add(volatile int *, int);
void __sh_store(volatile int *, int);
void __sh_and(volatile int *, int);
void __sh_or(volatile int *, int);

#define a_cas(p,t,s)     __sh_cas(p,t,s)
#define a_swap(x,v)      __sh_swap(x,v)
#define a_fetch_add(x,v) __sh_fetch_add(x, v)
#define a_store(x,v)     __sh_store(x, v)
#define a_and(x,v)       __sh_and(x, v)
#define a_or(x,v)        __sh_or(x, v)
#endif

static inline void *a_cas_p(volatile void *p, void *t, void *s)
{
	return (void *)a_cas(p, (int)t, (int)s);
}

static inline void a_inc(volatile int *x)
{
	a_fetch_add(x, 1);
}

static inline void a_dec(volatile int *x)
{
	a_fetch_add(x, -1);
}

#define a_spin a_barrier

static inline void a_barrier()
{
	a_cas(&(int){0}, 0, 0);
}

static inline void a_crash()
{
	*(volatile char *)0=0;
}

static inline void a_or_l(volatile void *p, long v)
{
	a_or(p, v);
}

static inline void a_and_64(volatile uint64_t *p, uint64_t v)
{
	union { uint64_t v; uint32_t r[2]; } u = { v };
	a_and((int *)p,   u.r[0]);
	a_and((int *)p+1, u.r[1]);
}

static inline void a_or_64(volatile uint64_t *p, uint64_t v)
{
	union { uint64_t v; uint32_t r[2]; } u = { v };
	a_or((int *)p,   u.r[0]);
	a_or((int *)p+1, u.r[1]);
}

#endif
