#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include "test.h"

static __thread char d1 = 11;
static __thread char d64 __attribute__ ((aligned(64))) = 22;
static __thread char d4096 __attribute__ ((aligned(4096))) = 33;
static __thread char z1 = 0;
static __thread char z64 __attribute__ ((aligned(64))) = 0;
static __thread char z4096 __attribute__ ((aligned(4096))) = 0;
static __thread const char *s1 = "s1";

static int tnum;

#define CHECK(c, fmt, ...) do{ \
	if (!(c)) \
		t_error("[thread %d]: "#c" failed"fmt".\n", tnum, __VA_ARGS__); \
}while(0)

static unsigned ptrmod(void *p, unsigned m)
{
	volatile unsigned n = (uintptr_t)p;
	return n % m;
}

static void *check(void *arg)
{
	tnum++;

	CHECK(d1 == 11, " want 11 got %d", d1);
	CHECK(d64 == 22, " want 22 got %d", d64);
	CHECK(d4096 == 33, " want 33 got %d", d4096);

	CHECK(ptrmod(&d64, 64) == 0, " address is %p, want 64 byte alignment", &d64);
	CHECK(ptrmod(&d4096, 4096) == 0, " address is %p, want 4096 byte alignment", &d4096);

	CHECK(z1 == 0, " want 0 got %d", z1);
	CHECK(z64 == 0, " want 0 got %d", z64);
	CHECK(z4096 == 0, " want 0 got %d", z4096);

	CHECK(ptrmod(&z64, 64) == 0, " address is %p, want 64 byte alignment", &z64);
	CHECK(ptrmod(&z4096, 4096) == 0, " address is %p, want 4096 byte alignment", &z4096);

	CHECK(!strcmp(s1, "s1"), " want s1 got %s", s1);
	return 0;
}

int main()
{
	pthread_t td;

	check(0);
	CHECK(pthread_create(&td, 0, check, 0) == 0, "", "");
	CHECK(pthread_join(td, 0) == 0, "", "");

	return t_status;
}
