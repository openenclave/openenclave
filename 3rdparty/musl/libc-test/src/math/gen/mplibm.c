#include "gen.h"

static int mpf1(struct t *s, float (*f)(float))
{
	s->dy = 0;
	setupfenv(s->r);
	s->y = f(s->x);
	s->e = getexcept();
	return 0;
}

static int mpf2(struct t *s, float (*f)(float,float))
{
	s->dy = 0;
	setupfenv(s->r);
	s->y = f(s->x, s->x2);
	s->e = getexcept();
	return 0;
}

static int mpd1(struct t *s, double (*f)(double))
{
	s->dy = 0;
	setupfenv(s->r);
	s->y = f(s->x);
	s->e = getexcept();
	return 0;
}

static int mpd2(struct t *s, double (*f)(double, double))
{
	s->dy = 0;
	setupfenv(s->r);
	s->y = f(s->x, s->x2);
	s->e = getexcept();
	return 0;
}

static int mpl1(struct t *s, long double (*f)(long double))
{
	s->dy = 0;
	setupfenv(s->r);
	s->y = f(s->x);
	s->e = getexcept();
	return 0;
}

static int mpl2(struct t *s, long double (*f)(long double, long double))
{
	setupfenv(s->r);
	s->y = f(s->x, s->x2);
	s->dy = 0;
	s->e = getexcept();
	return 0;
}

static double sinpi(double x) { return sin(3.141592653589793238*x); }
int mpsinpi(struct t *t) { return mpd1(t, sinpi); }


#define OP(n,op,t) static t n(t x, t y) { t z = x op y; return z; }
OP(add,+,double)
OP(addf,+,float)
OP(addl,+,long double)
OP(mul,*,double)
OP(mulf,*,float)
OP(mull,*,long double)
OP(div,/,double)
OP(divf,/,float)
OP(divl,/,long double)
int mpadd(struct t *t) { return mpd2(t, add); }
int mpaddf(struct t *t) { return mpf2(t, addf); }
int mpaddl(struct t *t) { return mpl2(t, addl); }
int mpmul(struct t *t) { return mpd2(t, mul); }
int mpmulf(struct t *t) { return mpf2(t, mulf); }
int mpmull(struct t *t) { return mpl2(t, mull); }
int mpdiv(struct t *t) { return mpd2(t, div); }
int mpdivf(struct t *t) { return mpf2(t, divf); }
int mpdivl(struct t *t) { return mpl2(t, divl); }

int mpacos(struct t *t) { return mpd1(t, acos); }
int mpacosf(struct t *t) { return mpf1(t, acosf); }
int mpacosl(struct t *t) { return mpl1(t, acosl); }
int mpacosh(struct t *t) { return mpd1(t, acosh); }
int mpacoshf(struct t *t) { return mpf1(t, acoshf); }
int mpacoshl(struct t *t) { return mpl1(t, acoshl); }
int mpasin(struct t *t) { return mpd1(t, asin); }
int mpasinf(struct t *t) { return mpf1(t, asinf); }
int mpasinl(struct t *t) { return mpl1(t, asinl); }
int mpasinh(struct t *t) { return mpd1(t, asinh); }
int mpasinhf(struct t *t) { return mpf1(t, asinhf); }
int mpasinhl(struct t *t) { return mpl1(t, asinhl); }
int mpatan(struct t *t) { return mpd1(t, atan); }
int mpatanf(struct t *t) { return mpf1(t, atanf); }
int mpatanl(struct t *t) { return mpl1(t, atanl); }
int mpatan2(struct t *t) { return mpd2(t, atan2); }
int mpatan2f(struct t *t) { return mpf2(t, atan2f); }
int mpatan2l(struct t *t) { return mpl2(t, atan2l); }
int mpatanh(struct t *t) { return mpd1(t, atanh); }
int mpatanhf(struct t *t) { return mpf1(t, atanhf); }
int mpatanhl(struct t *t) { return mpl1(t, atanhl); }
int mpcbrt(struct t *t) { return mpd1(t, cbrt); }
int mpcbrtf(struct t *t) { return mpf1(t, cbrtf); }
int mpcbrtl(struct t *t) { return mpl1(t, cbrtl); }
int mpceil(struct t *t) { return mpd1(t, ceil); }
int mpceilf(struct t *t) { return mpf1(t, ceilf); }
int mpceill(struct t *t) { return mpl1(t, ceill); }
int mpcopysign(struct t *t) { return mpd2(t, copysign); }
int mpcopysignf(struct t *t) { return mpf2(t, copysignf); }
int mpcopysignl(struct t *t) { return mpl2(t, copysignl); }
int mpcos(struct t *t) { return mpd1(t, cos); }
int mpcosf(struct t *t) { return mpf1(t, cosf); }
int mpcosl(struct t *t) { return mpl1(t, cosl); }
int mpcosh(struct t *t) { return mpd1(t, cosh); }
int mpcoshf(struct t *t) { return mpf1(t, coshf); }
int mpcoshl(struct t *t) { return mpl1(t, coshl); }
int mperf(struct t *t) { return mpd1(t, erf); }
int mperff(struct t *t) { return mpf1(t, erff); }
int mperfl(struct t *t) { return mpl1(t, erfl); }
int mperfc(struct t *t) { return mpd1(t, erfc); }
int mperfcf(struct t *t) { return mpf1(t, erfcf); }
int mperfcl(struct t *t) { return mpl1(t, erfcl); }
int mpexp(struct t *t) { return mpd1(t, exp); }
int mpexpf(struct t *t) { return mpf1(t, expf); }
int mpexpl(struct t *t) { return mpl1(t, expl); }
int mpexp2(struct t *t) { return mpd1(t, exp2); }
int mpexp2f(struct t *t) { return mpf1(t, exp2f); }
int mpexp2l(struct t *t) { return mpl1(t, exp2l); }
int mpexpm1(struct t *t) { return mpd1(t, expm1); }
int mpexpm1f(struct t *t) { return mpf1(t, expm1f); }
int mpexpm1l(struct t *t) { return mpl1(t, expm1l); }
int mpfabs(struct t *t) { return mpd1(t, fabs); }
int mpfabsf(struct t *t) { return mpf1(t, fabsf); }
int mpfabsl(struct t *t) { return mpl1(t, fabsl); }
int mpfdim(struct t *t) { return mpd2(t, fdim); }
int mpfdimf(struct t *t) { return mpf2(t, fdimf); }
int mpfdiml(struct t *t) { return mpl2(t, fdiml); }
int mpfloor(struct t *t) { return mpd1(t, floor); }
int mpfloorf(struct t *t) { return mpf1(t, floorf); }
int mpfloorl(struct t *t) { return mpl1(t, floorl); }
int mpfmax(struct t *t) { return mpd2(t, fmax); }
int mpfmaxf(struct t *t) { return mpf2(t, fmaxf); }
int mpfmaxl(struct t *t) { return mpl2(t, fmaxl); }
int mpfmin(struct t *t) { return mpd2(t, fmin); }
int mpfminf(struct t *t) { return mpf2(t, fminf); }
int mpfminl(struct t *t) { return mpl2(t, fminl); }
int mpfmod(struct t *t) { return mpd2(t, fmod); }
int mpfmodf(struct t *t) { return mpf2(t, fmodf); }
int mpfmodl(struct t *t) { return mpl2(t, fmodl); }
int mphypot(struct t *t) { return mpd2(t, hypot); }
int mphypotf(struct t *t) { return mpf2(t, hypotf); }
int mphypotl(struct t *t) { return mpl2(t, hypotl); }
int mplog(struct t *t) { return mpd1(t, log); }
int mplogf(struct t *t) { return mpf1(t, logf); }
int mplogl(struct t *t) { return mpl1(t, logl); }
int mplog10(struct t *t) { return mpd1(t, log10); }
int mplog10f(struct t *t) { return mpf1(t, log10f); }
int mplog10l(struct t *t) { return mpl1(t, log10l); }
int mplog1p(struct t *t) { return mpd1(t, log1p); }
int mplog1pf(struct t *t) { return mpf1(t, log1pf); }
int mplog1pl(struct t *t) { return mpl1(t, log1pl); }
int mplog2(struct t *t) { return mpd1(t, log2); }
int mplog2f(struct t *t) { return mpf1(t, log2f); }
int mplog2l(struct t *t) { return mpl1(t, log2l); }
int mplogb(struct t *t) { return mpd1(t, logb); }
int mplogbf(struct t *t) { return mpf1(t, logbf); }
int mplogbl(struct t *t) { return mpl1(t, logbl); }
int mpnearbyint(struct t *t) { return mpd1(t, nearbyint); }
int mpnearbyintf(struct t *t) { return mpf1(t, nearbyintf); }
int mpnearbyintl(struct t *t) { return mpl1(t, nearbyintl); }
int mpnextafter(struct t *t) { return mpd2(t, nextafter); }
int mpnextafterf(struct t *t) { return mpf2(t, nextafterf); }
int mpnextafterl(struct t *t) { return mpl2(t, nextafterl); }
int mpnexttoward(struct t *t)
{
	feclearexcept(FE_ALL_EXCEPT);
	t->y = nexttoward(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0;
	return 0;
}
int mpnexttowardf(struct t *t)
{
	feclearexcept(FE_ALL_EXCEPT);
	t->y = nexttowardf(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0;
	return 0;
}
int mpnexttowardl(struct t *t) { return mpl2(t, nexttowardl); }
int mppow(struct t *t) { return mpd2(t, pow); }
int mppowf(struct t *t) { return mpf2(t, powf); }
int mppowl(struct t *t) { return mpl2(t, powl); }
int mpremainder(struct t *t) { return mpd2(t, remainder); }
int mpremainderf(struct t *t) { return mpf2(t, remainderf); }
int mpremainderl(struct t *t) { return mpl2(t, remainderl); }
int mprint(struct t *t) { return mpd1(t, rint); }
int mprintf(struct t *t) { return mpf1(t, rintf); }
int mprintl(struct t *t) { return mpl1(t, rintl); }
int mpround(struct t *t) { return mpd1(t, round); }
int mproundf(struct t *t) { return mpf1(t, roundf); }
int mproundl(struct t *t) { return mpl1(t, roundl); }
int mpsin(struct t *t) { return mpd1(t, sin); }
int mpsinf(struct t *t) { return mpf1(t, sinf); }
int mpsinl(struct t *t) { return mpl1(t, sinl); }
int mpsinh(struct t *t) { return mpd1(t, sinh); }
int mpsinhf(struct t *t) { return mpf1(t, sinhf); }
int mpsinhl(struct t *t) { return mpl1(t, sinhl); }
int mpsqrt(struct t *t) { return mpd1(t, sqrt); }
int mpsqrtf(struct t *t) { return mpf1(t, sqrtf); }
int mpsqrtl(struct t *t) { return mpl1(t, sqrtl); }
int mptan(struct t *t) { return mpd1(t, tan); }
int mptanf(struct t *t) { return mpf1(t, tanf); }
int mptanl(struct t *t) { return mpl1(t, tanl); }
int mptanh(struct t *t) { return mpd1(t, tanh); }
int mptanhf(struct t *t) { return mpf1(t, tanhf); }
int mptanhl(struct t *t) { return mpl1(t, tanhl); }
int mptgamma(struct t *t) { return mpd1(t, tgamma); }
int mptgammaf(struct t *t) { return mpf1(t, tgammaf); }
int mptgammal(struct t *t) { return mpl1(t, tgammal); }
int mptrunc(struct t *t) { return mpd1(t, trunc); }
int mptruncf(struct t *t) { return mpf1(t, truncf); }
int mptruncl(struct t *t) { return mpl1(t, truncl); }
int mpj0(struct t *t) { return mpd1(t, j0); }
int mpj1(struct t *t) { return mpd1(t, j1); }
int mpy0(struct t *t) { return mpd1(t, y0); }
int mpy1(struct t *t) { return mpd1(t, y1); }
int mpscalb(struct t *t) { return mpd2(t, scalb); }
int mpscalbf(struct t *t) { return mpf2(t, scalbf); }
int mpj0f(struct t *t) { return mpf1(t, j0f); }
int mpj0l(struct t *t) { return -1;}//mpl1(t, j0l); }
int mpj1f(struct t *t) { return mpf1(t, j1f); }
int mpj1l(struct t *t) { return -1;}//mpl1(t, j1l); }
int mpy0f(struct t *t) { return mpf1(t, y0f); }
int mpy0l(struct t *t) { return -1;}//mpl1(t, y0l); }
int mpy1f(struct t *t) { return mpf1(t, y1f); }
int mpy1l(struct t *t) { return -1;}//mpl1(t, y1l); }
int mpexp10(struct t *t) { return mpd1(t, exp10); }
int mpexp10f(struct t *t) { return mpf1(t, exp10f); }
int mpexp10l(struct t *t) { return mpl1(t, exp10l); }
int mppow10(struct t *t) { return mpd1(t, pow10); }
int mppow10f(struct t *t) { return mpf1(t, pow10f); }
int mppow10l(struct t *t) { return mpl1(t, pow10l); }

#define mp_fi_f(n) \
int mp##n(struct t *t) \
{ \
	t->dy = 0; \
	setupfenv(t->r); \
	t->y = n(t->x, t->i); \
	t->e = getexcept(); \
	return 0; \
}

mp_fi_f(ldexp)
mp_fi_f(ldexpf)
mp_fi_f(ldexpl)
mp_fi_f(scalbn)
mp_fi_f(scalbnf)
mp_fi_f(scalbnl)
mp_fi_f(scalbln)
mp_fi_f(scalblnf)
mp_fi_f(scalblnl)

#define mp_f_fi(n) \
int mp##n(struct t *t) \
{ \
	int i; \
	t->dy = 0; \
	setupfenv(t->r); \
	t->y = n(t->x, &i); \
	t->e = getexcept(); \
	t->i = i; \
	return 0; \
}

mp_f_fi(frexp)
mp_f_fi(frexpf)
mp_f_fi(frexpl)
mp_f_fi(lgamma_r)
mp_f_fi(lgammaf_r)
mp_f_fi(lgammal_r)

int mplgamma(struct t *t)
{
	t->dy = 0;
	setupfenv(t->r);
	t->y = lgamma(t->x);
	t->e = getexcept();
	t->i = signgam;
	return 0;
}

int mplgammaf(struct t *t)
{
	t->dy = 0;
	setupfenv(t->r);
	t->y = lgammaf(t->x);
	t->e = getexcept();
	t->i = signgam;
	return 0;
}

int mplgammal(struct t *t)
{
	t->dy = 0;
	setupfenv(t->r);
	t->y = lgammal(t->x);
	t->e = getexcept();
	t->i = signgam;
	return 0;
}

#define mp_f_i(n) \
int mp##n(struct t *t) \
{ \
	setupfenv(t->r); \
	t->i = n(t->x); \
	t->e = getexcept(); \
	return 0; \
}

mp_f_i(ilogb)
mp_f_i(ilogbf)
mp_f_i(ilogbl)
mp_f_i(llrint)
mp_f_i(llrintf)
mp_f_i(llrintl)
mp_f_i(lrint)
mp_f_i(lrintf)
mp_f_i(lrintl)
mp_f_i(llround)
mp_f_i(llroundf)
mp_f_i(llroundl)
mp_f_i(lround)
mp_f_i(lroundf)
mp_f_i(lroundl)

int mpmodf(struct t *t)
{
	double y2;

	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	t->y = modf(t->x, &y2);
	t->y2 = y2;
	t->e = getexcept();
	return 0;
}

int mpmodff(struct t *t)
{
	float y2;

	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	t->y = modff(t->x, &y2);
	t->y2 = y2;
	t->e = getexcept();
	return 0;
}

int mpmodfl(struct t *t)
{
	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	t->y = modfl(t->x, &t->y2);
	t->e = getexcept();
	return 0;
}

int mpsincos(struct t *t)
{
	double y, y2;

	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	sincos(t->x, &y, &y2);
	t->y = y;
	t->y2 = y2;
	t->e = getexcept();
	return 0;
}

int mpsincosf(struct t *t)
{
	float y, y2;

	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	sincosf(t->x, &y, &y2);
	t->y = y;
	t->y2 = y2;
	t->e = getexcept();
	return 0;
}

int mpsincosl(struct t *t)
{
	t->dy = t->dy2 = 0;
	setupfenv(t->r);
	sincosl(t->x, &t->y, &t->y2);
	t->e = getexcept();
	return 0;
}

#define mp_ff_fi(n) \
int mp##n(struct t *t) \
{ \
	int i; \
	t->dy = 0; \
	setupfenv(t->r); \
	t->y = n(t->x, t->x2, &i); \
	t->e = getexcept(); \
	t->i = i; \
	return 0; \
}

mp_ff_fi(remquo)
mp_ff_fi(remquof)
mp_ff_fi(remquol)

#define mp_fff_f(n) \
int mp##n(struct t *t) \
{ \
	t->dy = 0; \
	setupfenv(t->r); \
	t->y = n(t->x, t->x2, t->x3); \
	t->e = getexcept(); \
	return 0; \
}

mp_fff_f(fma)
mp_fff_f(fmaf)
mp_fff_f(fmal)

#define mp_if_f(n) \
int mp##n(struct t *t) \
{ \
	t->dy = 0; \
	setupfenv(t->r); \
	t->y = n(t->i, t->x); \
	t->e = getexcept(); \
	return 0; \
}

mp_if_f(jn)
mp_if_f(jnf)
//mp_if_f(jnl)
mp_if_f(yn)
mp_if_f(ynf)
//mp_if_f(ynl)

