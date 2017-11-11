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

#if __ARM_ARCH_7A__ || __ARM_ARCH_7R__ ||  __ARM_ARCH >= 7

static inline void a_barrier()
{
	__asm__ __volatile__("dmb ish");
}

static inline int a_cas(volatile int *p, int t, int s)
{
	int old;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%3\n"
		"	cmp %0,%1\n"
		"	bne 1f\n"
		"	strex %0,%2,%3\n"
		"	cmp %0, #0\n"
		"	bne 1b\n"
		"	mov %0, %1\n"
		"1:	dmb ish\n"
		: "=&r"(old)
		: "r"(t), "r"(s), "Q"(*p)
		: "memory", "cc" );
	return old;
}

static inline int a_swap(volatile int *x, int v)
{
	int old, tmp;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%3\n"
		"	strex %1,%2,%3\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(old), "=&r"(tmp)
		: "r"(v), "Q"(*x)
		: "memory", "cc" );
	return old;
}

static inline int a_fetch_add(volatile int *x, int v)
{
	int old, tmp;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%3\n"
		"	add %0,%0,%2\n"
		"	strex %1,%0,%3\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(old), "=&r"(tmp)
		: "r"(v), "Q"(*x)
		: "memory", "cc" );
	return old-v;
}

static inline void a_inc(volatile int *x)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%2\n"
		"	add %0,%0,#1\n"
		"	strex %1,%0,%2\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "Q"(*x)
		: "memory", "cc" );
}

static inline void a_dec(volatile int *x)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%2\n"
		"	sub %0,%0,#1\n"
		"	strex %1,%0,%2\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "Q"(*x)
		: "memory", "cc" );
}

static inline void a_and(volatile int *x, int v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%3\n"
		"	and %0,%0,%2\n"
		"	strex %1,%0,%3\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*x)
		: "memory", "cc" );
}

static inline void a_or(volatile int *x, int v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldrex %0,%3\n"
		"	orr %0,%0,%2\n"
		"	strex %1,%0,%3\n"
		"	cmp %1, #0\n"
		"	bne 1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*x)
		: "memory", "cc" );
}

static inline void a_store(volatile int *p, int x)
{
	__asm__ __volatile__(
		"	dmb ish\n"
		"	str %1,%0\n"
		"	dmb ish\n"
		: "=m"(*p)
		: "r"(x)
		: "memory", "cc" );
}

#else

int __a_cas(int, int, volatile int *) __attribute__((__visibility__("hidden")));
#define __k_cas __a_cas

static inline void a_barrier()
{
	__asm__ __volatile__("bl __a_barrier"
		: : : "memory", "cc", "ip", "lr" );
}

static inline int a_cas(volatile int *p, int t, int s)
{
	int old;
	for (;;) {
		if (!__k_cas(t, s, p))
			return t;
		if ((old=*p) != t)
			return old;
	}
}

static inline int a_swap(volatile int *x, int v)
{
	int old;
	do old = *x;
	while (__k_cas(old, v, x));
	return old;
}

static inline int a_fetch_add(volatile int *x, int v)
{
	int old;
	do old = *x;
	while (__k_cas(old, old+v, x));
	return old;
}

static inline void a_inc(volatile int *x)
{
	a_fetch_add(x, 1);
}

static inline void a_dec(volatile int *x)
{
	a_fetch_add(x, -1);
}

static inline void a_store(volatile int *p, int x)
{
	a_barrier();
	*p = x;
	a_barrier();
}

static inline void a_and(volatile int *p, int v)
{
	int old;
	do old = *p;
	while (__k_cas(old, old&v, p));
}

static inline void a_or(volatile int *p, int v)
{
	int old;
	do old = *p;
	while (__k_cas(old, old|v, p));
}

#endif

static inline void *a_cas_p(volatile void *p, void *t, void *s)
{
	return (void *)a_cas(p, (int)t, (int)s);
}

#define a_spin a_barrier

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
	a_and((int *)p, u.r[0]);
	a_and((int *)p+1, u.r[1]);
}

static inline void a_or_64(volatile uint64_t *p, uint64_t v)
{
	union { uint64_t v; uint32_t r[2]; } u = { v };
	a_or((int *)p, u.r[0]);
	a_or((int *)p+1, u.r[1]);
}

#endif
