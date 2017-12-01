#include <stdio.h>
#include <math.h>

#define T(a,b) {__LINE__, a, b},
#define length(a) (sizeof(a)/sizeof*(a))

static struct {
	int line;
	float f;
	int class;
} tf[] = {
	T(0.0/0.0, FP_NAN)
	T(-0.0/0.0, FP_NAN)
	T(1/0.0, FP_INFINITE)
	T(-1/0.0, FP_INFINITE)
	T(0x1.ffffp127, FP_NORMAL)
	T(-0x1.ffffp127, FP_NORMAL)
	T(0x1p-127, FP_SUBNORMAL)
	T(-0x1p-127, FP_SUBNORMAL)
	T(0.0, FP_ZERO)
	T(-0.0, FP_ZERO)
	T(3.14, FP_NORMAL)
	T(-42, FP_NORMAL)
};

static struct {
	int line;
	double f;
	int class;
} td[] = {
	T(0.0/0.0, FP_NAN)
	T(-0.0/0.0, FP_NAN)
	T(1/0.0, FP_INFINITE)
	T(-1/0.0, FP_INFINITE)
	T(0x1.ffffp1023, FP_NORMAL)
	T(-0x1.ffffp1023, FP_NORMAL)
	T(0x1p-1023, FP_SUBNORMAL)
	T(-0x1p-1023, FP_SUBNORMAL)
	T(0.0, FP_ZERO)
	T(-0.0, FP_ZERO)
	T(3.14, FP_NORMAL)
	T(-42, FP_NORMAL)
};

static struct {
	int line;
	long double f;
	int class;
} tl[] = {
	T(0.0/0.0, FP_NAN)
	T(-0.0/0.0, FP_NAN)
	T(1/0.0, FP_INFINITE)
	T(-1/0.0, FP_INFINITE)
#if LDBL_MAX_EXP==16384
	T(0x1.ffffp16383L, FP_NORMAL)
	T(-0x1.ffffp16383L, FP_NORMAL)
	T(0x1p-16383L, FP_SUBNORMAL)
	T(-0x1p-16383L, FP_SUBNORMAL)
#elif LDBL_MAX_EXP==1024
	T(0x1.ffffp1023L, FP_NORMAL)
	T(-0x1.ffffp1023L, FP_NORMAL)
	T(0x1p-1023L, FP_SUBNORMAL)
	T(-0x1p-1023L, FP_SUBNORMAL)
#endif
	T(0.0, FP_ZERO)
	T(-0.0, FP_ZERO)
	T(3.14, FP_NORMAL)
	T(-42, FP_NORMAL)
};

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

#define error(t,c) err++, printf("%s:%d: (at line %d) %La has class %d (%s), but %s returns %d\n", \
	__FILE__, __LINE__, t.line, (long double)t.f, t.class, strclass(t.class), #c, c(t.f))

int main()
{
	int i;
	int err = 0;

	for (i = 0; i < length(tf); i++) {
		if (fpclassify(tf[i].f) != tf[i].class)
			error(tf[i], fpclassify);
		if (!!isinf(tf[i].f) != (tf[i].class == FP_INFINITE))
			error(tf[i], isinf);
		if (!!isnan(tf[i].f) != (tf[i].class == FP_NAN))
			error(tf[i], isnan);
		if (!!isnormal(tf[i].f) != (tf[i].class == FP_NORMAL))
			error(tf[i], isnormal);
		if (!!isfinite(tf[i].f) != (tf[i].class > FP_INFINITE))
			error(tf[i], isfinite);
	}

	for (i = 0; i < length(td); i++) {
		if (fpclassify(td[i].f) != td[i].class)
			error(td[i], fpclassify);
		if (!!isinf(td[i].f) != (td[i].class == FP_INFINITE))
			error(td[i], isinf);
		if (!!isnan(td[i].f) != (td[i].class == FP_NAN))
			error(td[i], isnan);
		if (!!isnormal(td[i].f) != (td[i].class == FP_NORMAL))
			error(td[i], isnormal);
		if (!!isfinite(td[i].f) != (td[i].class > FP_INFINITE))
			error(td[i], isfinite);
	}

	for (i = 0; i < length(tl); i++) {
		if (fpclassify(tl[i].f) != tl[i].class)
			error(tl[i], fpclassify);
		if (!!isinf(tl[i].f) != (tl[i].class == FP_INFINITE))
			error(tl[i], isinf);
		if (!!isnan(tl[i].f) != (tl[i].class == FP_NAN))
			error(tl[i], isnan);
		if (!!isnormal(tl[i].f) != (tl[i].class == FP_NORMAL))
			error(tl[i], isnormal);
		if (!!isfinite(tl[i].f) != (tl[i].class > FP_INFINITE))
			error(tl[i], isfinite);
	}

	return !!err;
}
