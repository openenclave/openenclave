#define _XOPEN_SOURCE 700
#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct d_di t[] = {
#include "sanity/lgamma.h"
#include "special/lgamma.h"

};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	int yi;
	double y;
	float d;
	int e, i, bad, err = 0;
	struct d_di *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = lgamma(p->x);
		yi = signgam;
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s lgamma(%a)=%a,%lld, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, p->i, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperr(y, p->y, p->dy);
		bad = !isnan(p->x) && p->x!=-inf && !(p->e&DIVBYZERO) && yi != p->i;
		if (bad || !checkulp(d, p->r)) {
			if (!bad && fabsf(d) < 11.0f)
				printf("X ");
			else
				err++;
			printf("%s:%d: %s lgamma(%a) want %a,%lld got %a,%d ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, p->i, y, yi, d, d-p->dy, p->dy);
		}
	}
	return !!err;
}
