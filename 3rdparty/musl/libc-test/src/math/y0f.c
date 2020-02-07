#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct f_f t[] = {
#include "sanity/y0f.h"
#include "special/y0f.h"

};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	float y;
	float d;
	int e, i, bad, err = 0;
	struct f_f *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = y0f(p->x);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s y0f(%a)=%a, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrf(y, p->y, p->dy);
		bad = p->x < 0 && !isnan(y) && y != -inf;
		if (bad || (!(p->x < 0) && !checkulp(d, p->r))) {
			if (!bad && fabsf(d) < 0x1p23f)
				printf("X ");
			else
				err++;
			printf("%s:%d: %s y0f(%a) want %a got %a ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, y, d, d-p->dy, p->dy);
		}
	}
	return !!err;
}
