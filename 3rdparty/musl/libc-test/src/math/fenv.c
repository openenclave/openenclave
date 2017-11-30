#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include "mtest.h"

static int test_status;

#define error(...) print(__FILE__, __LINE__, __VA_ARGS__)
static void print(char *f, int l, char *fmt, ...)
{
	test_status = 1;
	va_list ap;
	printf("%s:%d: ", f, l);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

#define F(n) {#n, n}

static struct {
	char *name;
	int i;
} te[] = {
#ifdef FE_DIVBYZERO
	F(FE_DIVBYZERO),
#endif
#ifdef FE_INEXACT
	F(FE_INEXACT),
#endif
#ifdef FE_INVALID
	F(FE_INVALID),
#endif
#ifdef FE_OVERFLOW
	F(FE_OVERFLOW),
#endif
#ifdef FE_UNDERFLOW
	F(FE_UNDERFLOW),
#endif
	{0, 0}
};

static void test_except()
{
	#pragma STDC FENV_ACCESS ON
	int i,r;
	fenv_t env;

	for (i=0; te[i].i; i++) {
		feclearexcept(FE_ALL_EXCEPT);

		r = feraiseexcept(te[i].i);
		if (r)
			error("feraiseexcept(%s) returned %d\n", te[i].name, r);
		r = fetestexcept(FE_ALL_EXCEPT);
		if (r != te[i].i) {
#if defined FE_OVERFLOW && defined FE_INEXACT
			if (te[i].i == FE_OVERFLOW && r == (FE_OVERFLOW|FE_INEXACT))
				continue;
#endif
#if defined FE_UNDERFLOW && defined FE_INEXACT
			if (te[i].i == FE_UNDERFLOW && r == (FE_UNDERFLOW|FE_INEXACT))
				continue;
#endif
			error("feraiseexcept(%s) want %d got %d\n",
				te[i].name, te[i].i, r);
		}
	}

	r = feraiseexcept(FE_ALL_EXCEPT);
	if (r != 0)
		error("feraisexcept(FE_ALL_EXCEPT) failed\n");
	r = fegetenv(&env);
	if (r != 0)
		error("fegetenv(&env) = %d\n", r);
	r = fetestexcept(FE_ALL_EXCEPT);
	if (r != FE_ALL_EXCEPT)
		error("fetestexcept failed: got 0x%x, want 0x%x (FE_ALL_ECXEPT)\n", r, FE_ALL_EXCEPT);
	r = fesetenv(FE_DFL_ENV);
	if (r != 0)
		error("fesetenv(FE_DFL_ENV) = %d\n", r);
	r = fetestexcept(FE_ALL_EXCEPT);
	if (r != 0)
		error("fesetenv(FE_DFL_ENV) did not clear exceptions: 0x%x\n", r);
	r = fesetenv(&env);
	if (r != 0)
		error("fesetenv(&env) = %d\n", r);
	r = fetestexcept(FE_ALL_EXCEPT);
	if (r != FE_ALL_EXCEPT)
		error("fesetenv(&env) did not restore exceptions: 0x%x\n", r);
}

static struct {
	char *name;
	int i;
} tr[] = {
	F(FE_TONEAREST),
#ifdef FE_UPWARD
	F(FE_UPWARD),
#endif
#ifdef FE_DOWNWARD
	F(FE_DOWNWARD),
#endif
#ifdef FE_TOWARDZERO
	F(FE_TOWARDZERO),
#endif
};

static void test_round()
{
	#pragma STDC FENV_ACCESS ON
	int i,r;
	fenv_t env;
	volatile float two100 = 0x1p100;
	volatile float x;

	for (i=0; i < sizeof tr/sizeof*tr; i++) {
		if (tr[i].i < 0)
			error("%s (%d) < 0\n", tr[i].name, tr[i].i);
		for (r=0; r < i; r++)
			if (tr[r].i == tr[i].i)
				error("%s (%d) == %s (%d)\n",
					tr[r].name, tr[r].i, tr[i].name, tr[i].i);
	}

	for (i=0; i < sizeof tr/sizeof*tr; i++) {
		r = fesetround(tr[i].i);
		if (r != 0)
			error("fesetround(%s) = %d\n", tr[i].name, r);
		r = fegetround();
		if (r != tr[i].i)
			error("fegetround() = 0x%x, wanted 0x%x (%s)\n", r, tr[i].i, tr[i].name);
	}

#ifdef FE_UPWARD
	r = fesetround(FE_UPWARD);
	if (r != 0)
		error("fesetround(FE_UPWARD) failed\n");
#endif
	r = fegetenv(&env);
	if (r != 0)
		error("fegetenv(&env) = %d\n", r);
	i = fegetround();
	r = fesetenv(FE_DFL_ENV);
	if (r != 0)
		error("fesetenv(FE_DFL_ENV) = %d\n", r);
	r = fegetround();
	if (r != FE_TONEAREST)
		error("fesetenv(FE_DFL_ENV) did not set FE_TONEAREST (0x%x), got 0x%x\n", FE_TONEAREST, r);
	x = two100 + 1;
	if (x != two100)
		error("fesetenv(FE_DFL_ENV) did not set FE_TONEAREST, arithmetics rounds upward\n");
	x = two100 - 1;
	if (x != two100)
		error("fesetenv(FE_DFL_ENV) did not set FE_TONEAREST, arithmetics rounds downward or tozero\n");
	r = fesetenv(&env);
	if (r != 0)
		error("fesetenv(&env) = %d\n", r);
	r = fegetround();
	if (r != i)
		error("fesetenv(&env) did not restore 0x%x, got 0x%x\n", i, r);
#ifdef FE_UPWARD
	x = two100 + 1;
	if (x == two100)
		error("fesetenv did not restore upward rounding\n");
#endif

}

/* ieee double precision add operation */
static struct dd_d t[] = {
T(RN,                  0x1p+0,                 0x1p-52,    0x1.0000000000001p+0,          0x0p+0, 0)
T(RN,                  0x1p+0,                 0x1p-53,                  0x1p+0,         -0x1p-1, INEXACT)
T(RN,                  0x1p+0,              0x1.01p-53,    0x1.0000000000001p+0,       0x1.fep-2, INEXACT)
T(RN,                  0x1p+0,                -0x1p-54,                  0x1p+0,          0x1p-2, INEXACT)
T(RN,                  0x1p+0,             -0x1.01p-54,    0x1.fffffffffffffp-1,      -0x1.fep-2, INEXACT)
T(RN,                 -0x1p+0,                -0x1p-53,                 -0x1p+0,          0x1p-1, INEXACT)
T(RN,                 -0x1p+0,             -0x1.01p-53,   -0x1.0000000000001p+0,      -0x1.fep-2, INEXACT)
T(RN,                 -0x1p+0,                 0x1p-54,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RN,                 -0x1p+0,              0x1.01p-54,   -0x1.fffffffffffffp-1,       0x1.fep-2, INEXACT)

T(RU,                  0x1p+0,                 0x1p-52,    0x1.0000000000001p+0,          0x0p+0, 0)
T(RU,                  0x1p+0,                 0x1p-53,    0x1.0000000000001p+0,          0x1p-1, INEXACT)
T(RU,                  0x1p+0,              0x1.01p-53,    0x1.0000000000001p+0,       0x1.fep-2, INEXACT)
T(RU,                  0x1p+0,                -0x1p-54,                  0x1p+0,          0x1p-2, INEXACT)
T(RU,                  0x1p+0,             -0x1.01p-54,                  0x1p+0,       0x1.01p-2, INEXACT)
T(RU,                 -0x1p+0,                -0x1p-53,                 -0x1p+0,          0x1p-1, INEXACT)
T(RU,                 -0x1p+0,             -0x1.01p-53,                 -0x1p+0,       0x1.01p-1, INEXACT)
T(RU,                 -0x1p+0,                 0x1p-54,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RU,                 -0x1p+0,              0x1.01p-54,   -0x1.fffffffffffffp-1,       0x1.fep-2, INEXACT)

T(RD,                  0x1p+0,                 0x1p-52,    0x1.0000000000001p+0,          0x0p+0, 0)
T(RD,                  0x1p+0,                 0x1p-53,                  0x1p+0,         -0x1p-1, INEXACT)
T(RD,                  0x1p+0,              0x1.01p-53,                  0x1p+0,      -0x1.01p-1, INEXACT)
T(RD,                  0x1p+0,                -0x1p-54,    0x1.fffffffffffffp-1,         -0x1p-1, INEXACT)
T(RD,                  0x1p+0,             -0x1.01p-54,    0x1.fffffffffffffp-1,      -0x1.fep-2, INEXACT)
T(RD,                 -0x1p+0,                -0x1p-53,   -0x1.0000000000001p+0,         -0x1p-1, INEXACT)
T(RD,                 -0x1p+0,             -0x1.01p-53,   -0x1.0000000000001p+0,      -0x1.fep-2, INEXACT)
T(RD,                 -0x1p+0,                 0x1p-54,                 -0x1p+0,         -0x1p-2, INEXACT)
T(RD,                 -0x1p+0,              0x1.01p-54,                 -0x1p+0,      -0x1.01p-2, INEXACT)

T(RZ,                  0x1p+0,                 0x1p-52,    0x1.0000000000001p+0,          0x0p+0, 0)
T(RZ,                  0x1p+0,                 0x1p-53,                  0x1p+0,         -0x1p-1, INEXACT)
T(RZ,                  0x1p+0,              0x1.01p-53,                  0x1p+0,      -0x1.01p-1, INEXACT)
T(RZ,                  0x1p+0,                -0x1p-54,    0x1.fffffffffffffp-1,         -0x1p-1, INEXACT)
T(RZ,                  0x1p+0,             -0x1.01p-54,    0x1.fffffffffffffp-1,      -0x1.fep-2, INEXACT)
T(RZ,                 -0x1p+0,                -0x1p-53,                 -0x1p+0,          0x1p-1, INEXACT)
T(RZ,                 -0x1p+0,             -0x1.01p-53,                 -0x1p+0,       0x1.01p-1, INEXACT)
T(RZ,                 -0x1p+0,                 0x1p-54,   -0x1.fffffffffffffp-1,          0x1p-1, INEXACT)
T(RZ,                 -0x1p+0,              0x1.01p-54,   -0x1.fffffffffffffp-1,       0x1.fep-2, INEXACT)
};

static void test_round_add(void)
{
	#pragma STDC FENV_ACCESS ON
	double y;
	float d;
	int i;
	struct dd_d *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		y = p->x + p->x2;
		d = ulperr(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r)) {
			printf("%s:%d: %s %a+%a want %a got %a ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, y, d, d-p->dy, p->dy);
			test_status = 1;
		}
	}
}

static void test_bad(void)
{
	fexcept_t f;
	int r;

	r = feclearexcept(FE_ALL_EXCEPT);
	if (r != 0)
		error("feclearexcept(FE_ALL_EXCEPT) failed\n");
	r = fetestexcept(-1);
	if (r != 0)
		error("fetestexcept(-1) should return 0 when all exceptions are cleared, got %d\n", r);
	r = feraiseexcept(1234567|FE_ALL_EXCEPT);
	if (r != 0)
		error("feraiseexcept returned non-zero for non-supported exceptions: %d\n", r);
	r = feclearexcept(1234567|FE_ALL_EXCEPT);
	if (r != 0)
		error("feclearexcept returned non-zero for non-supported exceptions: %d\n", r);
	r = fesetround(1234567);
	if (r == 0)
		error("fesetround should fail on invalid rounding mode\n");
	r = fegetexceptflag(&f, 1234567);
	if (r != 0)
		error("fegetexceptflag returned non-zero for non-supported exceptions: %d\n", r);
	r = fegetexceptflag(&f, 0);
	if (r != 0)
		error("fegetexceptflag(0) failed\n");
	r = fesetexceptflag(&f, 1234567);
	if (r != 0)
		error("fesetexceptflag returned non-zero fir non-supported exceptions: %d\n", r);
}

int main(void)
{
	test_except();
	test_round();
	test_round_add();
	test_bad();
	return test_status;
}
