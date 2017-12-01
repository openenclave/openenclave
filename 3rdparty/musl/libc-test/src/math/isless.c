#include <math.h>
#include "mtest.h"
#include "test.h"

enum {LESS,EQUAL,GREATER,UNORD};

#define TEST(f,want) do{ \
	int r, e; \
	feclearexcept(FE_ALL_EXCEPT); \
	r = (f); \
	e = fetestexcept(FE_ALL_EXCEPT); \
	if (r != (want)) \
		t_error(#f " failed: got %d want %d\n", r, (want)); \
	if (e & INVALID) \
		t_error(#f " raised the invalid exception\n"); \
}while(0)

#undef T
#define T(a,b,rel) do{ \
	TEST(isunordered(a, b), rel == UNORD); \
	TEST(isless(a, b), rel == LESS); \
	TEST(islessequal(a, b), rel == LESS || rel == EQUAL); \
	TEST(islessgreater(a, b), rel == LESS || rel == GREATER); \
	TEST(isgreater(a, b), rel == GREATER); \
	TEST(isgreaterequal(a, b), rel == GREATER || rel == EQUAL); \
}while(0)

int main()
{
	#pragma STDC FENV_ACCESS ON
	volatile double huge = DBL_MAX;
	volatile double tiny = DBL_MIN;
	volatile double eps = DBL_EPSILON;
	volatile float hugef = FLT_MAX;
	volatile float tinyf = FLT_MIN;
	volatile float epsf = FLT_EPSILON;
	volatile long double hugel = LDBL_MAX;
	volatile long double tinyl = LDBL_MIN;
	volatile long double epsl = LDBL_EPSILON;

	T(nan, 1.0, UNORD);
	T(1.0, nan, UNORD);
	T(nan, nan, UNORD);
	T(nan, nan+1.0, UNORD);
	T(nan, nan+1.0L, UNORD);

	T(1.0, 1.1, LESS);
	T(1.0, 1.0+eps, LESS);
	T(1.0+eps, 1.0, GREATER);
	T(huge-1, huge, EQUAL);
	T(huge, huge*huge, LESS);
	T(-0.0, 0.0, EQUAL);
	T(-tiny, 0.0, LESS);
	T(tiny, 2*tiny, LESS);
	T(tiny*0x1p-9, tiny*0x1p-8, LESS);

	T(1.0f, 1.1f, LESS);
	T(1.0f, 1.0f+epsf, LESS);
	T(1.0f+epsf, 1.0f, GREATER);
	T(hugef-1, hugef, EQUAL);
	T(hugef, hugef*hugef, LESS);
	T(-0.0f, 0.0f, EQUAL);
	T(-tinyf, 0.0f, LESS);
	T(tinyf, 2*tinyf, LESS);
	T(tinyf*0x1p-9f, tinyf*0x1p-8f, LESS);

	T(1.0L, 1.1L, LESS);
	T(1.0L, 1.0L+epsl, LESS);
	T(1.0L+epsl, 1.0L, GREATER);
	T(hugel-1, hugel, EQUAL);
	T(hugel, hugel*hugel, LESS);
	T(-0.0L, 0.0L, EQUAL);
	T(-tinyl, 0.0L, LESS);
	T(tinyl, 2*tinyl, LESS);
	T(tinyl*0x1p-9L, tinyl*0x1p-8L, LESS);

#if FLT_EVAL_METHOD == 2
	T(huge*huge, huge*huge*2, LESS);
	T(tiny*tiny*0.5, tiny*tiny, LESS);
	T(-tiny*tiny, 0.0, LESS);
	T(1.0, 1.0+eps*0.25, LESS);
#else
	T(huge*huge, huge*huge*2, EQUAL);
	T(tiny*tiny*0.5, tiny*tiny, EQUAL);
	T(-tiny*tiny, 0.0, EQUAL);
	T(1.0, 1.0+eps*0.25, EQUAL);
#endif

#if FLT_EVAL_METHOD >= 1
	T(hugef*hugef, hugef*hugef*2, LESS);
	T(tinyf*tinyf*0.5f, tinyf*tinyf, LESS);
	T(-tinyf*tinyf, 0.0f, LESS);
	T(1.0f, 1.0f+epsf*0.25f, LESS);
#else
	T(hugef*hugef, hugef*hugef*2, EQUAL);
	T(tinyf*tinyf*0.5f, tinyf*tinyf, EQUAL);
	T(-tinyf*tinyf, 0.0f, EQUAL);
	T(1.0f, 1.0f+epsf*0.25f, EQUAL);
#endif

	T(hugel*hugel, hugel*hugel*2, EQUAL);
	T(tinyl*tinyl*0.5L, tinyl*tinyl, EQUAL);
	T(-tinyl*tinyl, 0.0L, EQUAL);
	T(1.0L, 1.0L+epsl*0.25L, EQUAL);

	return t_status;
}
