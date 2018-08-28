#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct l_li t[] = {
#if LDBL_MANT_DIG == 53
#include "sanity/frexp.h"
#include "special/frexp.h"

#elif LDBL_MANT_DIG == 64
#include "sanity/frexpl.h"
#include "special/frexpl.h"

#endif
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	int yi;
	long double y;
	float d;
	int e, i, err = 0;
	struct l_li *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = frexpl(p->x, &yi);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexceptall(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s frexpl(%La)=%La,%lld, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, p->i, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrl(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r) || (isfinite(p->x) && yi != p->i)) {
			printf("%s:%d: %s frexpl(%La) want %La,%lld got %La,%d ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, p->i, y, yi, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
