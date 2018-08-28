#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct fi_f t[] = {
#include "sanity/ldexpf.h"
#include "special/ldexpf.h"

};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	float y;
	float d;
	int e, i, err = 0;
	struct fi_f *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = ldexpf(p->x, p->i);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexceptall(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s ldexpf(%a, %lld)=%a, want %s",
				p->file, p->line, rstr(p->r), p->x, p->i, p->y, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrf(y, p->y, p->dy);
		if (!checkcr(y, p->y, p->r)) {
			printf("%s:%d: %s ldexpf(%a, %lld) want %a got %a, ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->i, p->y, y, d, d-p->dy, p->dy);
			err++;
		}
	}
	return !!err;
}
