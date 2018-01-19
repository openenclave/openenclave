#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct lll_l t[] = {
#if LDBL_MANT_DIG == 53
#include "sanity/fma.h"
#include "special/fma.h"
#elif LDBL_MANT_DIG == 64
#include "sanity/fmal.h"
#include "special/fmal.h"
#endif
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	long double y;
	float d;
	int e, i, err = 0;
	struct lll_l *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = fmal(p->x, p->x2, p->x3);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		/* do not check inexact by default */
#if defined CHECK_INEXACT || defined CHECK_INEXACT_OMISSION
		if (!checkexceptall(e, p->e, p->r)) {
#else
		if (!checkexceptall(e|INEXACT, p->e|INEXACT, p->r)) {
#endif
			printf("%s:%d: bad fp exception: %s fmal(%La,%La,%La)=%La, want %s",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->x3, p->y, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrl(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r)) {
			printf("%s:%d: %s fmal(%La,%La,%La) want %La got %La ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->x3, p->y, y, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
