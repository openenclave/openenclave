#ifndef _INTERNAL_ATOMIC_H
#define _INTERNAL_ATOMIC_H

#include <stdint.h>

static inline int a_ctz_64(uint64_t x)
{
	__asm__(
		"	rbit %0, %1\n"
		"	clz %0, %0\n"
		: "=r"(x) : "r"(x));
	return x;
}

static inline int a_ctz_l(unsigned long x)
{
	return a_ctz_64(x);
}

static inline void a_barrier()
{
	__asm__ __volatile__("dmb ish");
}

static inline void *a_cas_p(volatile void *p, void *t, void *s)
{
	void *old;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %0,%3\n"
		"	cmp %0,%1\n"
		"	b.ne 1f\n"
		"	stxr %w0,%2,%3\n"
		"	cbnz %w0,1b\n"
		"	mov %0,%1\n"
		"1:	dmb ish\n"
		: "=&r"(old)
		: "r"(t), "r"(s), "Q"(*(long*)p)
		: "memory", "cc");
	return old;
}

static inline int a_cas(volatile int *p, int t, int s)
{
	int old;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %w0,%3\n"
		"	cmp %w0,%w1\n"
		"	b.ne 1f\n"
		"	stxr %w0,%w2,%3\n"
		"	cbnz %w0,1b\n"
		"	mov %w0,%w1\n"
		"1:	dmb ish\n"
		: "=&r"(old)
		: "r"(t), "r"(s), "Q"(*p)
		: "memory", "cc");
	return old;
}

static inline int a_swap(volatile int *x, int v)
{
	int old, tmp;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %w0,%3\n"
		"	stxr %w1,%w2,%3\n"
		"	cbnz %w1,1b\n"
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
		"1:	ldxr %w0,%3\n"
		"	add %w0,%w0,%w2\n"
		"	stxr %w1,%w0,%3\n"
		"	cbnz %w1,1b\n"
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
		"1:	ldxr %w0,%2\n"
		"	add %w0,%w0,#1\n"
		"	stxr %w1,%w0,%2\n"
		"	cbnz %w1,1b\n"
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
		"1:	ldxr %w0,%2\n"
		"	sub %w0,%w0,#1\n"
		"	stxr %w1,%w0,%2\n"
		"	cbnz %w1,1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "Q"(*x)
		: "memory", "cc" );
}

static inline void a_and_64(volatile uint64_t *p, uint64_t v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %0,%3\n"
		"	and %0,%0,%2\n"
		"	stxr %w1,%0,%3\n"
		"	cbnz %w1,1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*p)
		: "memory", "cc" );
}

static inline void a_and(volatile int *p, int v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %w0,%3\n"
		"	and %w0,%w0,%w2\n"
		"	stxr %w1,%w0,%3\n"
		"	cbnz %w1,1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*p)
		: "memory", "cc" );
}

static inline void a_or_64(volatile uint64_t *p, uint64_t v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %0,%3\n"
		"	orr %0,%0,%2\n"
		"	stxr %w1,%0,%3\n"
		"	cbnz %w1,1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*p)
		: "memory", "cc" );
}

static inline void a_or_l(volatile void *p, long v)
{
	return a_or_64(p, v);
}

static inline void a_or(volatile int *p, int v)
{
	int tmp, tmp2;
	__asm__ __volatile__(
		"	dmb ish\n"
		"1:	ldxr %w0,%3\n"
		"	orr %w0,%w0,%w2\n"
		"	stxr %w1,%w0,%3\n"
		"	cbnz %w1,1b\n"
		"	dmb ish\n"
		: "=&r"(tmp), "=&r"(tmp2)
		: "r"(v), "Q"(*p)
		: "memory", "cc" );
}

static inline void a_store(volatile int *p, int x)
{
	__asm__ __volatile__(
		"	dmb ish\n"
		"	str %w1,%0\n"
		"	dmb ish\n"
		: "=m"(*p)
		: "r"(x)
		: "memory", "cc" );
}

#define a_spin a_barrier

static inline void a_crash()
{
	*(volatile char *)0=0;
}


#endif
