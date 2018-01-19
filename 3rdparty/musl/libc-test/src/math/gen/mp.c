#include <stdio.h>
#include <stdint.h>
#include <mpfr.h>
#include "gen.h"

static int rmap(int r)
{
	switch (r) {
	case RN: return MPFR_RNDN;
	case RZ: return MPFR_RNDZ;
	case RD: return MPFR_RNDD;
	case RU: return MPFR_RNDU;
	}
	return -1;
}

enum {FLT, DBL, LDBL};
static const int emin[] = {
[FLT] = -148,
[DBL] = -1073,
[LDBL] = -16444
};
static const int emax[] = {
[FLT] = 128,
[DBL] = 1024,
[LDBL] = 16384
};

void debug(mpfr_t x)
{
	mpfr_out_str(stdout, 10, 0, x, MPFR_RNDN);
	printf("\n");
}

/*
round x into y considering x is already rounded (t = up or down)

only cases where adjustment is done:
	x=...|1...0, t=up    -> x=nextbelow(x)
	x=...|1...0, t=down  -> x=nextabove(x)
where | is the rounding point, ... is 0 or 1 bit patterns
*/

// TODO: adjust(y, 0, 2, RN); when prec is 24 (0 vs 0x1p-149f), special case x=0
static int adjust_round(mpfr_t y, mpfr_t x, int t, int r)
{
	mp_limb_t *p, *q;
	unsigned xp, yp;
	int t2;

	xp = mpfr_get_prec(x);
	yp = mpfr_get_prec(y);
	if (yp >= xp || r != MPFR_RNDN || t == 0 || !mpfr_number_p(x) || mpfr_zero_p(x)) {
		t2 = mpfr_set(y, x, r);
		return t2 ? t2 : t;
	}
	p = x->_mpfr_d;
	yp++;
	q = p + (xp + mp_bits_per_limb - 1)/mp_bits_per_limb - (yp + mp_bits_per_limb - 1)/mp_bits_per_limb;
	if ((*p & 1 << -xp%mp_bits_per_limb) || !(*q & 1 << -yp%mp_bits_per_limb)) {
		t2 = mpfr_set(y, x, r);
		return t2 ? t2 : t;
	}
	if (t > 0)
		mpfr_nextbelow(x);
	else
		mpfr_nextabove(x);
	return mpfr_set(y, x, r);
}

static int adjust(mpfr_t mr, mpfr_t my, int t, int r, int type)
{
//	double d, dn, dp;
//printf("adj %d\n", t);
//debug(my);
	t = adjust_round(mr, my, t, r);
//printf("rnd %d\n", t);
//debug(mr);
	mpfr_set_emin(emin[type]);
	mpfr_set_emax(emax[type]);
	// mpfr could handle this in subnormlize easily but no it doesnt...
	t = mpfr_check_range(mr, t, r);
	t = mpfr_subnormalize(mr, t, r);
	mpfr_set_emax(MPFR_EMAX_DEFAULT);
	mpfr_set_emin(MPFR_EMIN_DEFAULT);
//printf("sub %d\n", t);
//debug(mr);
//	d = mpfr_get_d(mr, r);
//	dn = nextafter(d, INFINITY);
//	dp = nextafter(d, -INFINITY);
//printf("c\n %.21e %a\n %.21e %a\n %.21e %a\n",d,d,dn,dn,dp,dp);
//	dn = nextafterf(d, INFINITY);
//	dp = nextafterf(d, -INFINITY);
//printf("cf\n %.21e %a\n %.21e %a\n %.21e %a\n",d,d,dn,dn,dp,dp);
	return t;
}

// TODO
//static int eflags(mpfr_t mr, mpfr_t my, int t)
static int eflags(int naninput)
{
	int i = 0;

	if (mpfr_inexflag_p())
		i |= FE_INEXACT;
//	if (mpfr_underflow_p() && (t || mpfr_cmp(mr, my) != 0))
	if (mpfr_underflow_p() && i)
		i |= FE_UNDERFLOW;
	if (mpfr_overflow_p())
		i |= FE_OVERFLOW;
	if (mpfr_divby0_p())
		i |= FE_DIVBYZERO;
	if (!naninput && (mpfr_nanflag_p() || mpfr_erangeflag_p()))
		i |= FE_INVALID;
	return i;
}

static void genf(struct t *p, mpfr_t my, int t, int r)
{
	MPFR_DECL_INIT(mr, 24);
	int i;

	t = adjust(mr, my, t, r, FLT);
	p->y = mpfr_get_flt(mr, r);
	p->e = eflags(isnan(p->x) || isnan(p->x2) || isnan(p->x3));
	i = eulpf(p->y);
	if (!isfinite(p->y)) {
		p->dy = 0;
	} else {
		mpfr_sub(my, mr, my, MPFR_RNDN);
		mpfr_div_2si(my, my, i, MPFR_RNDN);
		p->dy = mpfr_get_flt(my, MPFR_RNDN);
		// happens in RU,RD,RZ modes when y is finite but outside the domain
		if (p->dy > 1)
			p->dy = 1;
		if (p->dy < -1)
			p->dy = -1;
	}
}

static int mpf1(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, mpfr_rnd_t))
{
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 24);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_flt(mx, p->x, MPFR_RNDN);
	tn = fmp(my, mx, r);
	p->x2 = 0;
	genf(p, my, tn, r);
	return 0;
}

static int mpf2(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, const mpfr_t, mpfr_rnd_t))
{
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 24);
	MPFR_DECL_INIT(mx2, 24);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_flt(mx, p->x, MPFR_RNDN);
	mpfr_set_flt(mx2, p->x2, MPFR_RNDN);
	tn = fmp(my, mx, mx2, r);
	genf(p, my, tn, r);
	return 0;
}

static void gend(struct t *p, mpfr_t my, int t, int r)
{
	MPFR_DECL_INIT(mr, 53);
	int i;

	t = adjust(mr, my, t, r, DBL);
	p->y = mpfr_get_d(mr, r);
	p->e = eflags(isnan(p->x) || isnan(p->x2) || isnan(p->x3));
	i = eulp(p->y);
	if (!isfinite(p->y)) {
		p->dy = 0;
	} else {
		mpfr_sub(my, mr, my, MPFR_RNDN);
		mpfr_div_2si(my, my, i, MPFR_RNDN);
		p->dy = mpfr_get_flt(my, MPFR_RNDN);
		// happens in RU,RD,RZ modes when y is finite but outside the domain
		if (p->dy > 1)
			p->dy = 1;
		if (p->dy < -1)
			p->dy = -1;
	}
}

static int mpd1(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, mpfr_rnd_t))
{
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 53);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_d(mx, p->x, MPFR_RNDN);
	tn = fmp(my, mx, r);
	p->x2 = 0;
	gend(p, my, tn, r);
	return 0;
}

static int mpd2(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, const mpfr_t, mpfr_rnd_t))
{
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 53);
	MPFR_DECL_INIT(mx2, 53);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_d(mx, p->x, MPFR_RNDN);
	mpfr_set_d(mx2, p->x2, MPFR_RNDN);
	tn = fmp(my, mx, mx2, r);
	gend(p, my, tn, r);
	return 0;
}

#if LDBL_MANT_DIG == 64
static void genl(struct t *p, mpfr_t my, int t, int r)
{
	MPFR_DECL_INIT(mr, 64);
	int i;

	t = adjust(mr, my, t, r, LDBL);
	p->y = mpfr_get_ld(mr, r);
	p->e = eflags(isnan(p->x) || isnan(p->x2) || isnan(p->x3));
	i = eulpl(p->y);
	if (!isfinite(p->y)) {
		p->dy = 0;
	} else {
		mpfr_sub(my, mr, my, MPFR_RNDN);
		mpfr_div_2si(my, my, i, MPFR_RNDN);
		p->dy = mpfr_get_flt(my, MPFR_RNDN);
		// happens in RU,RD,RZ modes when y is finite but outside the domain
		if (p->dy > 1)
			p->dy = 1;
		if (p->dy < -1)
			p->dy = -1;
	}
}
#endif

static int mpl1(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, mpfr_rnd_t))
{
#if LDBL_MANT_DIG == 53
	return mpd1(p, fmp);
#elif LDBL_MANT_DIG == 64
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 64);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_ld(mx, p->x, MPFR_RNDN);
	tn = fmp(my, mx, r);
	p->x2 = 0;
	genl(p, my, tn, r);
	return 0;
#else
	return -1;
#endif
}

static int mpl2(struct t *p, int (*fmp)(mpfr_t, const mpfr_t, const mpfr_t, mpfr_rnd_t))
{
#if LDBL_MANT_DIG == 53
	return mpd2(p, fmp);
#elif LDBL_MANT_DIG == 64
	int tn;
	int r = rmap(p->r);
	MPFR_DECL_INIT(mx, 64);
	MPFR_DECL_INIT(mx2, 64);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_ld(mx, p->x, MPFR_RNDN);
	mpfr_set_ld(mx2, p->x2, MPFR_RNDN);
	tn = fmp(my, mx, mx2, r);
	genl(p, my, tn, r);
	return 0;
#else
	return -1;
#endif
}

// TODO
static int mplgamma_sign;
static int wrap_lgamma(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_lgamma(my, &mplgamma_sign, mx, r);
}
static long mpremquo_q;
static int wrap_remquo(mpfr_t my, const mpfr_t mx, const mpfr_t mx2, mpfr_rnd_t r)
{
	return mpfr_remquo(my, &mpremquo_q, mx, mx2, r);
}
static int mpbessel_n;
static int wrap_jn(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_jn(my, mpbessel_n, mx, r);
}
static int wrap_yn(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_yn(my, mpbessel_n, mx, r);
}
static int wrap_ceil(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_ceil(my, mx);
}
static int wrap_floor(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_floor(my, mx);
}
static int wrap_round(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_round(my, mx);
}
static int wrap_trunc(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_trunc(my, mx);
}
static int wrap_nearbyint(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	int i = mpfr_rint(my, mx, r);
	mpfr_clear_inexflag();
	return i;
}
static int wrap_pow10(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	return mpfr_ui_pow(my, 10, mx, r);
}


static int wrap_sinpi(mpfr_t my, const mpfr_t mx, mpfr_rnd_t r)
{
	// hack because mpfr has no sinpi
	MPFR_DECL_INIT(mz, 4096);
	mpfr_const_pi(mz, r);
	mpfr_mul(mz,mz,mx,r);
	return mpfr_sin(my, mz, r);
}
int mpsinpi(struct t *t) { return mpd1(t, wrap_sinpi); }

int mpadd(struct t *t) { return mpd2(t, mpfr_add); }
int mpaddf(struct t *t) { return mpf2(t, mpfr_add); }
int mpaddl(struct t *t) { return mpl2(t, mpfr_add); }
int mpmul(struct t *t) { return mpd2(t, mpfr_mul); }
int mpmulf(struct t *t) { return mpf2(t, mpfr_mul); }
int mpmull(struct t *t) { return mpl2(t, mpfr_mul); }
int mpdiv(struct t *t) { return mpd2(t, mpfr_div); }
int mpdivf(struct t *t) { return mpf2(t, mpfr_div); }
int mpdivl(struct t *t) { return mpl2(t, mpfr_div); }

int mpacos(struct t *t) { return mpd1(t, mpfr_acos); }
int mpacosf(struct t *t) { return mpf1(t, mpfr_acos); }
int mpacosl(struct t *t) { return mpl1(t, mpfr_acos); }
int mpacosh(struct t *t) { return mpd1(t, mpfr_acosh); }
int mpacoshf(struct t *t) { return mpf1(t, mpfr_acosh); }
int mpacoshl(struct t *t) { return mpl1(t, mpfr_acosh); }
int mpasin(struct t *t) { return mpd1(t, mpfr_asin); }
int mpasinf(struct t *t) { return mpf1(t, mpfr_asin); }
int mpasinl(struct t *t) { return mpl1(t, mpfr_asin); }
int mpasinh(struct t *t) { return mpd1(t, mpfr_asinh); }
int mpasinhf(struct t *t) { return mpf1(t, mpfr_asinh); }
int mpasinhl(struct t *t) { return mpl1(t, mpfr_asinh); }
int mpatan(struct t *t) { return mpd1(t, mpfr_atan); }
int mpatanf(struct t *t) { return mpf1(t, mpfr_atan); }
int mpatanl(struct t *t) { return mpl1(t, mpfr_atan); }
int mpatan2(struct t *t) { return mpd2(t, mpfr_atan2); }
int mpatan2f(struct t *t) { return mpf2(t, mpfr_atan2); }
int mpatan2l(struct t *t) { return mpl2(t, mpfr_atan2); }
int mpatanh(struct t *t) { return mpd1(t, mpfr_atanh); }
int mpatanhf(struct t *t) { return mpf1(t, mpfr_atanh); }
int mpatanhl(struct t *t) { return mpl1(t, mpfr_atanh); }
int mpcbrt(struct t *t) { return mpd1(t, mpfr_cbrt); }
int mpcbrtf(struct t *t) { return mpf1(t, mpfr_cbrt); }
int mpcbrtl(struct t *t) { return mpl1(t, mpfr_cbrt); }
int mpceil(struct t *t) { return mpd1(t, wrap_ceil); }
int mpceilf(struct t *t) { return mpf1(t, wrap_ceil); }
int mpceill(struct t *t) { return mpl1(t, wrap_ceil); }
int mpcopysign(struct t *t) { return mpd2(t, mpfr_copysign); }
int mpcopysignf(struct t *t) { return mpf2(t, mpfr_copysign); }
int mpcopysignl(struct t *t) { return mpl2(t, mpfr_copysign); }
int mpcos(struct t *t) { return mpd1(t, mpfr_cos); }
int mpcosf(struct t *t) { return mpf1(t, mpfr_cos); }
int mpcosl(struct t *t) { return mpl1(t, mpfr_cos); }
int mpcosh(struct t *t) { return mpd1(t, mpfr_cosh); }
int mpcoshf(struct t *t) { return mpf1(t, mpfr_cosh); }
int mpcoshl(struct t *t) { return mpl1(t, mpfr_cosh); }
int mperf(struct t *t) { return mpd1(t, mpfr_erf); }
int mperff(struct t *t) { return mpf1(t, mpfr_erf); }
int mperfl(struct t *t) { return mpl1(t, mpfr_erf); }
int mperfc(struct t *t) { return mpd1(t, mpfr_erfc); }
int mperfcf(struct t *t) { return mpf1(t, mpfr_erfc); }
int mperfcl(struct t *t) { return mpl1(t, mpfr_erfc); }
int mpexp(struct t *t) { return mpd1(t, mpfr_exp); }
int mpexpf(struct t *t) { return mpf1(t, mpfr_exp); }
int mpexpl(struct t *t) { return mpl1(t, mpfr_exp); }
int mpexp2(struct t *t) { return mpd1(t, mpfr_exp2); }
int mpexp2f(struct t *t) { return mpf1(t, mpfr_exp2); }
int mpexp2l(struct t *t) { return mpl1(t, mpfr_exp2); }
int mpexpm1(struct t *t) { return mpd1(t, mpfr_expm1); }
int mpexpm1f(struct t *t) { return mpf1(t, mpfr_expm1); }
int mpexpm1l(struct t *t) { return mpl1(t, mpfr_expm1); }
int mpfabs(struct t *t) { return mpd1(t, mpfr_abs); }
int mpfabsf(struct t *t) { return mpf1(t, mpfr_abs); }
int mpfabsl(struct t *t) { return mpl1(t, mpfr_abs); }
int mpfdim(struct t *t) { return mpd2(t, mpfr_dim); }
int mpfdimf(struct t *t) { return mpf2(t, mpfr_dim); }
int mpfdiml(struct t *t) { return mpl2(t, mpfr_dim); }
int mpfloor(struct t *t) { return mpd1(t, wrap_floor); }
int mpfloorf(struct t *t) { return mpf1(t, wrap_floor); }
int mpfloorl(struct t *t) { return mpl1(t, wrap_floor); }
int mpfmax(struct t *t) { return mpd2(t, mpfr_max); }
int mpfmaxf(struct t *t) { return mpf2(t, mpfr_max); }
int mpfmaxl(struct t *t) { return mpl2(t, mpfr_max); }
int mpfmin(struct t *t) { return mpd2(t, mpfr_min); }
int mpfminf(struct t *t) { return mpf2(t, mpfr_min); }
int mpfminl(struct t *t) { return mpl2(t, mpfr_min); }
int mpfmod(struct t *t) { return mpd2(t, mpfr_fmod); }
int mpfmodf(struct t *t) { return mpf2(t, mpfr_fmod); }
int mpfmodl(struct t *t) { return mpl2(t, mpfr_fmod); }
int mphypot(struct t *t) { return mpd2(t, mpfr_hypot); }
int mphypotf(struct t *t) { return mpf2(t, mpfr_hypot); }
int mphypotl(struct t *t) { return mpl2(t, mpfr_hypot); }
int mplgamma(struct t *t) { return mpd1(t, wrap_lgamma) || (t->i = mplgamma_sign, 0); }
int mplgammaf(struct t *t) { return mpf1(t, wrap_lgamma) || (t->i = mplgamma_sign, 0); }
int mplgammal(struct t *t) { return mpl1(t, wrap_lgamma) || (t->i = mplgamma_sign, 0); }
int mplog(struct t *t) { return mpd1(t, mpfr_log); }
int mplogf(struct t *t) { return mpf1(t, mpfr_log); }
int mplogl(struct t *t) { return mpl1(t, mpfr_log); }
int mplog10(struct t *t) { return mpd1(t, mpfr_log10); }
int mplog10f(struct t *t) { return mpf1(t, mpfr_log10); }
int mplog10l(struct t *t) { return mpl1(t, mpfr_log10); }
int mplog1p(struct t *t) { return mpd1(t, mpfr_log1p); }
int mplog1pf(struct t *t) { return mpf1(t, mpfr_log1p); }
int mplog1pl(struct t *t) { return mpl1(t, mpfr_log1p); }
int mplog2(struct t *t) { return mpd1(t, mpfr_log2); }
int mplog2f(struct t *t) { return mpf1(t, mpfr_log2); }
int mplog2l(struct t *t) { return mpl1(t, mpfr_log2); }
int mplogb(struct t *t)
{
	MPFR_DECL_INIT(mx, 53);

	t->dy = 0;
	t->e = 0;
	if (t->x == 0) {
		t->y = -INFINITY;
		t->e |= DIVBYZERO;
		return 0;
	}
	if (isinf(t->x)) {
		t->y = INFINITY;
		return 0;
	}
	if (isnan(t->x)) {
		t->y = t->x;
		return 0;
	}
	mpfr_set_d(mx, t->x, MPFR_RNDN);
	t->y = mpfr_get_exp(mx) - 1;
	return 0;
}
int mplogbf(struct t *t)
{
	MPFR_DECL_INIT(mx, 24);

	t->dy = 0;
	t->e = 0;
	if (t->x == 0) {
		t->y = -INFINITY;
		t->e |= DIVBYZERO;
		return 0;
	}
	if (isinf(t->x)) {
		t->y = INFINITY;
		return 0;
	}
	if (isnan(t->x)) {
		t->y = t->x;
		return 0;
	}
	mpfr_set_flt(mx, t->x, MPFR_RNDN);
	t->y = mpfr_get_exp(mx) - 1;
	return 0;
}
int mplogbl(struct t *t)
{
	MPFR_DECL_INIT(mx, 64);

	t->dy = 0;
	t->e = 0;
	if (t->x == 0) {
		t->y = -INFINITY;
		t->e |= DIVBYZERO;
		return 0;
	}
	if (isinf(t->x)) {
		t->y = INFINITY;
		return 0;
	}
	if (isnan(t->x)) {
		t->y = t->x;
		return 0;
	}
	mpfr_set_ld(mx, t->x, MPFR_RNDN);
	t->y = mpfr_get_exp(mx) - 1;
	return 0;
}
int mpnearbyint(struct t *t) { return mpd1(t, wrap_nearbyint) || (t->e&=~INEXACT, 0); }
int mpnearbyintf(struct t *t) { return mpf1(t, wrap_nearbyint) || (t->e&=~INEXACT, 0); }
int mpnearbyintl(struct t *t) { return mpl1(t, wrap_nearbyint) || (t->e&=~INEXACT, 0); }
// TODO: hard to implement with mpfr
int mpnextafter(struct t *t)
{
	feclearexcept(FE_ALL_EXCEPT);
	t->y = nextafter(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0;
	return 0;
}
int mpnextafterf(struct t *t)
{
	feclearexcept(FE_ALL_EXCEPT);
	t->y = nextafterf(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0;
	return 0;
}
int mpnextafterl(struct t *t)
{
	feclearexcept(FE_ALL_EXCEPT);
	t->y = nextafterl(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0;
	return 0;
}
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
int mpnexttowardl(struct t *t) { return mpnextafterl(t); }
int mppow(struct t *t) { return mpd2(t, mpfr_pow); }
int mppowf(struct t *t) { return mpf2(t, mpfr_pow); }
int mppowl(struct t *t) { return mpl2(t, mpfr_pow); }
int mpremainder(struct t *t) { return mpd2(t, mpfr_remainder); }
int mpremainderf(struct t *t) { return mpf2(t, mpfr_remainder); }
int mpremainderl(struct t *t) { return mpl2(t, mpfr_remainder); }
int mprint(struct t *t) { return mpd1(t, mpfr_rint); }
int mprintf(struct t *t) { return mpf1(t, mpfr_rint); }
int mprintl(struct t *t) { return mpl1(t, mpfr_rint); }
int mpround(struct t *t) { return mpd1(t, wrap_round); }
int mproundf(struct t *t) { return mpf1(t, wrap_round); }
int mproundl(struct t *t) { return mpl1(t, wrap_round); }
int mpsin(struct t *t) { return mpd1(t, mpfr_sin); }
int mpsinf(struct t *t) { return mpf1(t, mpfr_sin); }
int mpsinl(struct t *t) { return mpl1(t, mpfr_sin); }
int mpsinh(struct t *t) { return mpd1(t, mpfr_sinh); }
int mpsinhf(struct t *t) { return mpf1(t, mpfr_sinh); }
int mpsinhl(struct t *t) { return mpl1(t, mpfr_sinh); }
int mpsqrt(struct t *t) { return mpd1(t, mpfr_sqrt); }
int mpsqrtf(struct t *t) { return mpf1(t, mpfr_sqrt); }
int mpsqrtl(struct t *t) { return mpl1(t, mpfr_sqrt); }
int mptan(struct t *t) { return mpd1(t, mpfr_tan); }
int mptanf(struct t *t) { return mpf1(t, mpfr_tan); }
int mptanl(struct t *t) { return mpl1(t, mpfr_tan); }
int mptanh(struct t *t) { return mpd1(t, mpfr_tanh); }
int mptanhf(struct t *t) { return mpf1(t, mpfr_tanh); }
int mptanhl(struct t *t) { return mpl1(t, mpfr_tanh); }
// TODO: tgamma(2) raises wrong flags
int mptgamma(struct t *t) { return mpd1(t, mpfr_gamma); }
int mptgammaf(struct t *t) { return mpf1(t, mpfr_gamma); }
int mptgammal(struct t *t) { return mpl1(t, mpfr_gamma); }
int mptrunc(struct t *t) { return mpd1(t, wrap_trunc); }
int mptruncf(struct t *t) { return mpf1(t, wrap_trunc); }
int mptruncl(struct t *t) { return mpl1(t, wrap_trunc); }
int mpj0(struct t *t) { return mpd1(t, mpfr_j0); }
int mpj1(struct t *t) { return mpd1(t, mpfr_j1); }
int mpy0(struct t *t) { return mpd1(t, mpfr_y0); }
int mpy1(struct t *t) { return mpd1(t, mpfr_y1); }
// TODO: non standard functions
int mpscalb(struct t *t)
{
	setupfenv(t->r);
	t->y = scalb(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0; // wrong
	return 0;
}
int mpscalbf(struct t *t)
{
	setupfenv(t->r);
	t->y = scalbf(t->x, t->x2);
	t->e = getexcept();
	t->dy = 0; // wrong
	return 0;
}
int mpj0f(struct t *t) { return mpf1(t, mpfr_j0); }
int mpj0l(struct t *t) { return mpl1(t, mpfr_j0); }
int mpj1f(struct t *t) { return mpf1(t, mpfr_j1); }
int mpj1l(struct t *t) { return mpl1(t, mpfr_j1); }
int mpy0f(struct t *t) { return mpf1(t, mpfr_y0); }
int mpy0l(struct t *t) { return mpl1(t, mpfr_y0); }
int mpy1f(struct t *t) { return mpf1(t, mpfr_y1); }
int mpy1l(struct t *t) { return mpl1(t, mpfr_y1); }
int mpexp10(struct t *t) { return mpd1(t, wrap_pow10); }
int mpexp10f(struct t *t) { return mpf1(t, wrap_pow10); }
int mpexp10l(struct t *t) { return mpl1(t, wrap_pow10); }
int mppow10(struct t *t) { return mpd1(t, wrap_pow10); }
int mppow10f(struct t *t) { return mpf1(t, wrap_pow10); }
int mppow10l(struct t *t) { return mpl1(t, wrap_pow10); }

int mpfrexp(struct t *t)
{
	mpfr_exp_t e;
	int k;
	MPFR_DECL_INIT(mx, 53);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_d(mx, t->x, MPFR_RNDN);
	k = mpfr_frexp(&e, mx, mx, t->r);
	t->y = mpfr_get_d(mx, MPFR_RNDN);
	t->i = e;
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpfrexpf(struct t *t)
{
	mpfr_exp_t e;
	int k;
	MPFR_DECL_INIT(mx, 24);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_flt(mx, t->x, MPFR_RNDN);
	k = mpfr_frexp(&e, mx, mx, t->r);
	t->y = mpfr_get_flt(mx, MPFR_RNDN);
	t->i = e;
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpfrexpl(struct t *t)
{
	mpfr_exp_t e;
	int k;
	MPFR_DECL_INIT(mx, 64);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_ld(mx, t->x, MPFR_RNDN);
	k = mpfr_frexp(&e, mx, mx, t->r);
	t->y = mpfr_get_ld(mx, MPFR_RNDN);
	t->i = e;
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpldexp(struct t *t)
{
	int k;
	MPFR_DECL_INIT(mx, 53);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_d(mx, t->x, MPFR_RNDN);
	k = mpfr_mul_2si(mx, mx, t->i, t->r);
	adjust(mx, mx, k, t->r, DBL);
	t->y = mpfr_get_d(mx, MPFR_RNDN);
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpldexpf(struct t *t)
{
	int k;
	MPFR_DECL_INIT(mx, 24);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_flt(mx, t->x, MPFR_RNDN);
	k = mpfr_mul_2si(mx, mx, t->i, t->r);
	adjust(mx, mx, k, t->r, FLT);
	t->y = mpfr_get_flt(mx, MPFR_RNDN);
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpldexpl(struct t *t)
{
	int k;
	MPFR_DECL_INIT(mx, 64);

	t->dy = 0;
	t->y = 0;
	mpfr_clear_flags();
	mpfr_set_ld(mx, t->x, MPFR_RNDN);
	k = mpfr_mul_2si(mx, mx, t->i, t->r);
	adjust(mx, mx, k, t->r, LDBL);
	t->y = mpfr_get_ld(mx, MPFR_RNDN);
	t->e = eflags(isnan(t->x));
	return 0;
}

int mpscalbn(struct t *t) { return mpldexp(t); }
int mpscalbnf(struct t *t) { return mpldexpf(t); }
int mpscalbnl(struct t *t) { return mpldexpl(t); }
int mpscalbln(struct t *t) { return mpldexp(t); }
int mpscalblnf(struct t *t) { return mpldexpf(t); }
int mpscalblnl(struct t *t) { return mpldexpl(t); }

int mplgamma_r(struct t *t) { return mplgamma(t); }
int mplgammaf_r(struct t *t) { return mplgammaf(t); }
int mplgammal_r(struct t *t) { return mplgammal(t); }

int mpilogb(struct t *t)
{
	MPFR_DECL_INIT(mx, 53);

	mpfr_set_d(mx, t->x, MPFR_RNDN);
	t->i = mpfr_get_exp(mx) - 1;
	t->e = 0;
	if (isinf(t->x) || isnan(t->x) || t->x == 0)
		t->e = INVALID;
	return 0;
}
int mpilogbf(struct t *t)
{
	MPFR_DECL_INIT(mx, 24);

	mpfr_set_flt(mx, t->x, MPFR_RNDN);
	t->i = mpfr_get_exp(mx) - 1;
	t->e = 0;
	if (isinf(t->x) || isnan(t->x) || t->x == 0)
		t->e = INVALID;
	return 0;
}
int mpilogbl(struct t *t)
{
	MPFR_DECL_INIT(mx, 64);

	mpfr_set_ld(mx, t->x, MPFR_RNDN);
	t->i = mpfr_get_exp(mx) - 1;
	t->e = 0;
	if (isinf(t->x) || isnan(t->x) || t->x == 0)
		t->e = INVALID;
	return 0;
}

// TODO: ll* is hard to do with mpfr
#define mp_f_i(n) \
int mp##n(struct t *t) \
{ \
	setupfenv(t->r); \
	t->i = n(t->x); \
	t->e = getexcept(); \
	if (t->e & INVALID) \
		t->i = 0; \
	return 0; \
}

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
	int e, r;

	r = mpd1(t, wrap_trunc);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e & ~INEXACT;
	r = mpd1(t, mpfr_frac);
	t->e |= e;
	return r;
}

int mpmodff(struct t *t)
{
	int e, r;

	r = mpf1(t, wrap_trunc);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e & ~INEXACT;
	r = mpf1(t, mpfr_frac);
	t->e |= e;
	return r;
}

int mpmodfl(struct t *t)
{
	int e, r;

	r = mpl1(t, wrap_trunc);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e & ~INEXACT;
	r = mpl1(t, mpfr_frac);
	t->e |= e;
	return r;
}

int mpsincos(struct t *t)
{
	int e, r;

	r = mpd1(t, mpfr_cos);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e;
	r = mpd1(t, mpfr_sin);
	t->e |= e;
	return r;
}

int mpsincosf(struct t *t)
{
	int e, r;

	r = mpf1(t, mpfr_cos);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e;
	r = mpf1(t, mpfr_sin);
	t->e |= e;
	return r;
}

int mpsincosl(struct t *t)
{
	int e, r;

	r = mpl1(t, mpfr_cos);
	if (r)
		return r;
	t->y2 = t->y;
	t->dy2 = t->dy;
	e = t->e;
	r = mpl1(t, mpfr_sin);
	t->e |= e;
	return r;
}

int mpremquo(struct t *t) { return mpd2(t, wrap_remquo) || (t->i = mpremquo_q, 0); }
int mpremquof(struct t *t) { return mpf2(t, wrap_remquo) || (t->i = mpremquo_q, 0); }
int mpremquol(struct t *t) { return mpl2(t, wrap_remquo) || (t->i = mpremquo_q, 0); }

int mpfma(struct t *t)
{
	int tn;
	int r = rmap(t->r);
	MPFR_DECL_INIT(mx, 53);
	MPFR_DECL_INIT(mx2, 53);
	MPFR_DECL_INIT(mx3, 53);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_d(mx, t->x, MPFR_RNDN);
	mpfr_set_d(mx2, t->x2, MPFR_RNDN);
	mpfr_set_d(mx3, t->x3, MPFR_RNDN);
	tn = mpfr_fma(my, mx, mx2, mx3, r);
	gend(t, my, tn, r);
	return 0;
}

int mpfmaf(struct t *t)
{
	int tn;
	int r = rmap(t->r);
	MPFR_DECL_INIT(mx, 24);
	MPFR_DECL_INIT(mx2, 24);
	MPFR_DECL_INIT(mx3, 24);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_flt(mx, t->x, MPFR_RNDN);
	mpfr_set_flt(mx2, t->x2, MPFR_RNDN);
	mpfr_set_flt(mx3, t->x3, MPFR_RNDN);
	tn = mpfr_fma(my, mx, mx2, mx3, r);
	genf(t, my, tn, r);
	return 0;
}

int mpfmal(struct t *t)
{
#if LDBL_MANT_DIG == 53
	return mpfma(t);
#elif LDBL_MANT_DIG == 64
	int tn;
	int r = rmap(t->r);
	MPFR_DECL_INIT(mx, 64);
	MPFR_DECL_INIT(mx2, 64);
	MPFR_DECL_INIT(mx3, 64);
	MPFR_DECL_INIT(my, 128);

	mpfr_clear_flags();
	mpfr_set_ld(mx, t->x, MPFR_RNDN);
	mpfr_set_ld(mx2, t->x2, MPFR_RNDN);
	mpfr_set_ld(mx3, t->x3, MPFR_RNDN);
	tn = mpfr_fma(my, mx, mx2, mx3, r);
	genl(t, my, tn, r);
	return 0;
#else
	return -1;
#endif
}

int mpjn(struct t *t) { mpbessel_n = t->i; return mpd1(t, wrap_jn); }
int mpjnf(struct t *t) { mpbessel_n = t->i; return mpf1(t, wrap_jn); }
int mpjnl(struct t *t) { mpbessel_n = t->i; return mpl1(t, wrap_jn); }
int mpyn(struct t *t) { mpbessel_n = t->i; return mpd1(t, wrap_yn); }
int mpynf(struct t *t) { mpbessel_n = t->i; return mpf1(t, wrap_yn); }
int mpynl(struct t *t) { mpbessel_n = t->i; return mpl1(t, wrap_yn); }

