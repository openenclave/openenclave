#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct l_ll t[] = {
#if LDBL_MANT_DIG == 53
#include "sanity/sincos.h"
#include "special/sincos.h"
#elif LDBL_MANT_DIG == 64
#include "sanity/sincosl.h"
#include "special/sincosl.h"
#endif
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	long double ysin, ycos;
	float dsin, dcos;
	int e, i, err = 0;
	struct l_ll *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		sincosl(p->x, &ysin, &ycos);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s sincosl(%La)=%La,%La, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		dsin = ulperr(ysin, p->y, p->dy);
		dcos = ulperr(ycos, p->y2, p->dy2);
		if (!checkulp(dsin, p->r) || !checkulp(dcos, p->r)) {
			printf("%s:%d: %s sincosl(%La) want %La,%La got %La,%La, ulperr %.3f = %a + %a, %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, ysin, ycos,
				dsin, dsin-p->dy, p->dy, dcos, dcos-p->dy2, p->dy2);
			err++;
		}
	}
	return !!err;
}
