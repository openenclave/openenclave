#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct fi_f t[] = {
#include "sanity/jnf.h"
#include "special/jnf.h"
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	double y;
	float d;
	int e, i, err = 0;
	struct fi_f *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		y = jnf(p->i, p->x);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s jnf(%lld, %a)=%a, want %s",
				p->file, p->line, rstr(p->r), p->i, p->x, p->y, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		d = ulperrf(y, p->y, p->dy);
		if (!checkulp(d, p->r)) {
			if (fabsf(d) < 3.0f)
				printf("X ");
			else
				err++;
			printf("%s:%d: %s jnf(%lld, %a) want %a got %a, ulperr %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->i, p->x, p->y, y, d, d-p->dy, p->dy);
		}
	}
	return !!err;
}
