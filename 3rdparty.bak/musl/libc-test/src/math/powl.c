#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct ll_l t[] = {
#if LDBL_MANT_DIG == 53
#include "crlibm/pow.h"
#include "ucb/pow.h"
#include "sanity/pow.h"
#include "special/pow.h"

#elif LDBL_MANT_DIG == 64
#include "sanity/powl.h"
#include "special/powl.h"

#endif
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	long double y;
	float d;
	int e, i, err = 0;
	struct ll_l *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = powl(p->x, p->x2);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s powl(%La,%La)=%La, want %s",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrl(y, p->y, p->dy);
		if (!checkulp(d, p->r)) {
			printf("%s:%d: %s powl(%La,%La) want %La got %La ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, y, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
