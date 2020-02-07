#include <fenv.h>
#include <float.h>
#include <math.h>

#undef RN
#undef RZ
#undef RD
#undef RU
#ifdef FE_TONEAREST
#define RN FE_TONEAREST
#else
#define RN 0
#endif
#ifdef FE_TOWARDZERO
#define RZ FE_TOWARDZERO
#else
#define RZ -1
#endif
#ifdef FE_DOWNWARD
#define RD FE_DOWNWARD
#else
#define RD -1
#endif
#ifdef FE_UPWARD
#define RU FE_UPWARD
#else
#define RU -1
#endif

#undef INEXACT
#undef INVALID
#undef DIVBYZERO
#undef UNDERFLOW
#undef OVERFLOW
#ifdef FE_INEXACT
#define INEXACT FE_INEXACT
#else
#define INEXACT 0
#endif
#ifdef FE_INVALID
#define INVALID FE_INVALID
#else
#define INVALID 0
#endif
#ifdef FE_DIVBYZERO
#define DIVBYZERO FE_DIVBYZERO
#else
#define DIVBYZERO 0
#endif
#ifdef FE_UNDERFLOW
#define UNDERFLOW FE_UNDERFLOW
#else
#define UNDERFLOW 0
#endif
#ifdef FE_OVERFLOW
#define OVERFLOW FE_OVERFLOW
#else
#define OVERFLOW 0
#endif

#undef inf
#undef nan
#define inf INFINITY
#define nan NAN

#define T(...) {__FILE__, __LINE__, __VA_ARGS__},

#define POS char *file; int line;
struct d_d {POS int r; double x; double y; float dy; int e; };
struct f_f {POS int r; float x; float y; float dy; int e; };
struct l_l {POS int r; long double x; long double y; float dy; int e; };
struct ff_f {POS int r; float x; float x2; float y; float dy; int e; };
struct dd_d {POS int r; double x; double x2; double y; float dy; int e; };
struct ll_l {POS int r; long double x; long double x2; long double y; float dy; int e; };
struct d_di {POS int r; double x; double y; float dy; long long i; int e; };
struct f_fi {POS int r; float x; float y; float dy; long long i; int e; };
struct l_li {POS int r; long double x; long double y; float dy; long long i; int e; };
struct di_d {POS int r; double x; long long i; double y; float dy; int e; };
struct fi_f {POS int r; float x; long long i; float y; float dy; int e; };
struct li_l {POS int r; long double x; long long i; long double y; float dy; int e; };
struct d_i {POS int r; double x; long long i; int e; };
struct f_i {POS int r; float x; long long i; int e; };
struct l_i {POS int r; long double x; long long i; int e; };
struct d_dd {POS int r; double x; double y; float dy; double y2; float dy2; int e; };
struct f_ff {POS int r; float x; float y; float dy; float y2; float dy2; int e; };
struct l_ll {POS int r; long double x; long double y; float dy; long double y2; float dy2; int e; };
struct ff_fi {POS int r; float x; float x2; float y; float dy; long long i; int e; };
struct dd_di {POS int r; double x; double x2; double y; float dy; long long i; int e; };
struct ll_li {POS int r; long double x; long double x2; long double y; float dy; long long i; int e; };
struct fff_f {POS int r; float x; float x2; float x3; float y; float dy; int e; };
struct ddd_d {POS int r; double x; double x2; double x3; double y; float dy; int e; };
struct lll_l {POS int r; long double x; long double x2; long double x3; long double y; float dy; int e; };
#undef POS

char *estr(int);
char *rstr(int);

float ulperr(double got, double want, float dwant);
float ulperrf(float got, float want, float dwant);
float ulperrl(long double got, long double want, float dwant);

static int checkexcept(int got, int want, int r)
{
	if (r == RN)
#if defined CHECK_INEXACT
		return got == want;
#elif defined CHECK_INEXACT_OMISSION
		return got == want || got == (want|INEXACT);
#else
		return (got|INEXACT) == (want|INEXACT);
#endif
	return (got|INEXACT|UNDERFLOW) == (want|INEXACT|UNDERFLOW);
}

static int checkexceptall(int got, int want, int r)
{
	return got == want;
}

static int checkulp(float d, int r)
{
	// TODO: we only care about >=1.5 ulp errors for now, should be 1.0
	if (r == RN)
		return fabsf(d) < 1.5;
	// accept larger error in non-nearest rounding mode
	return fabsf(d) < 3.0;
}

static int checkcr(long double y, long double ywant, int r)
{
	if (isnan(ywant))
		return isnan(y);
	return y == ywant && signbit(y) == signbit(ywant);
}

