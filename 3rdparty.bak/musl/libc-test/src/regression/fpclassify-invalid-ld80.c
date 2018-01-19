// commit: f657fe4b9f734d7fdea515af8dffbf7c28ce4fbc 2013-09-05
// classify invalid x86 ld80 representations (this is ub, we follow the fpu)
// test printf("%La") as well
#include <math.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "test.h"

#if LDBL_MANT_DIG==64
static char *strclass(int c)
{
#define C(n) case n: return #n;
	switch (c) {
	C(FP_NAN)
	C(FP_INFINITE)
	C(FP_ZERO)
	C(FP_SUBNORMAL)
	C(FP_NORMAL)
	}
	return "invalid";
}

#define T(f, desc, c, cwant, s, swant) do{ \
	c = fpclassify(f); \
	if (c != cwant) \
		t_error("fpclassify(%s) failed: got %s want %s\n", desc, strclass(c), #cwant); \
	memset(s, 0, sizeof(s)); \
	if (snprintf(s, sizeof(s), "%La", f) >= sizeof(s)) \
		t_error("snprintf(\"%%La\", %s) failed with invalid return value\n", desc); \
	if (strcmp(s,swant) != 0) \
		t_error("snprintf(\"%%La\", %s) failed: got \"%.*s\" want %s\n", desc, sizeof(s), s, #swant); \
}while(0)

int main(void)
{
	union {
		long double f;
		struct {
			uint64_t m;
			uint16_t se;
		} i;
	} u;
	int c;
	int r;
	char s[32];

	u.f = 0;
	u.i.m = (uint64_t)1<<63;
	T(u.f, "zero with msb set", c, FP_NORMAL, s, "0x1p-16382");
	u.i.m++;
	T(u.f, "subnormal with msb set", c, FP_NORMAL, s, "0x1.0000000000000002p-16382");
	u.f=1;
	u.i.m=0;
	T(u.f, "normal with msb unset", c, FP_NAN, s, "nan");
	u.f=INFINITY;
	u.i.m=0;
	T(u.f, "infinity with msb unset", c, FP_NAN, s, "nan");
	u.f=NAN;
	u.i.m&=(uint64_t)-1/2;
	T(u.f, "nan with msb unset", c, FP_NAN, s, "nan");
	return t_status;
}
#else
int main(void)
{
	return 0;
}
#endif
