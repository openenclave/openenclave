#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct f_ff t[] = {
#include "sanity/modff.h"
#include "special/modff.h"
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	float y, yi;
	float d, di;
	int e, i, err = 0;
	struct f_ff *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = modff(p->x, &yi);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		/* TODO: fix inexact */
		if (!checkexceptall(e|INEXACT, p->e|INEXACT, p->r)) {
			printf("%s:%d: bad fp exception: %s modff(%a)=%a,%a, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperr(y, p->y, p->dy);
		di = ulperr(yi, p->y2, p->dy2);
		if (!checkcr(y, p->y, p->r) || !checkcr(yi, p->y2, p->r)) {
			printf("%s:%d: %s modff(%a) want %a,%a got %a,%a, ulperr %.3f = %a + %a, %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, y, yi, d, d-p->dy, p->dy, di, di-p->dy2, p->dy2);
			err++;
		}
	}
	return !!err;
}
