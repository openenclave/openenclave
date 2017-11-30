#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct ll_li t[] = {
#if LDBL_MANT_DIG == 53
#include "sanity/remquo.h"
#include "special/remquo.h"

#elif LDBL_MANT_DIG == 64
#include "sanity/remquol.h"
#include "special/remquol.h"

#endif
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	int yi;
	long double y;
	float d;
	int e, i, err = 0;
	struct ll_li *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = remquol(p->x, p->x2, &yi);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s remquol(%La,%La)=%La,%lld, want %s",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, p->i, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperr(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r) ||
		(!isnan(p->y) && (yi & 7) != (p->i & 7)) ||
		(!isnan(p->y) && (yi < 0) != (p->i < 0))) {
			printf("%s:%d: %s remquol(%La,%La) want %La,%lld got %La,%d ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, p->i, y, yi, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
