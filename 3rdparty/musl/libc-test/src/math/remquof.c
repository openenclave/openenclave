#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct ff_fi t[] = {
#include "sanity/remquof.h"
#include "special/remquof.h"
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	int yi;
	float y;
	float d;
	int e, i, err = 0;
	struct ff_fi *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = remquof(p->x, p->x2, &yi);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s remquof(%a,%a)=%a,%lld, want %s",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, p->i, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperr(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r) ||
		(!isnan(p->y) && (yi & 7) != (p->i & 7)) ||
		(!isnan(p->y) && (yi < 0) != (p->i < 0))) {
			printf("%s:%d: %s remquof(%a,%a) want %a,%lld got %a,%d ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->x2, p->y, p->i, y, yi, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
