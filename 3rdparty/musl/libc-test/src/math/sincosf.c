#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include "mtest.h"

static struct f_ff t[] = {
#include "sanity/sincosf.h"
#include "special/sincosf.h"
};

int main(void)
{
	#pragma STDC FENV_ACCESS ON
	float ysin, ycos;
	float dsin, dcos;
	int e, i, err = 0;
	struct f_ff *p;

	for (i = 0; i < sizeof t/sizeof *t; i++) {
		p = t + i;

		if (p->r < 0)
			continue;
		fesetround(p->r);
		feclearexcept(FE_ALL_EXCEPT);
		sincosf(p->x, &ysin, &ycos);
		e = fetestexcept(INEXACT|INVALID|DIVBYZERO|UNDERFLOW|OVERFLOW);

		if (!checkexcept(e, p->e, p->r)) {
			printf("%s:%d: bad fp exception: %s sincosf(%a)=%a,%a, want %s",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, estr(p->e));
			printf(" got %s\n", estr(e));
			err++;
		}
		dsin = ulperrf(ysin, p->y, p->dy);
		dcos = ulperrf(ycos, p->y2, p->dy2);
		if (!checkulp(dsin, p->r) || !checkulp(dcos, p->r)) {
			printf("%s:%d: %s sincosf(%a) want %a,%a got %a,%a, ulperr %.3f = %a + %a, %.3f = %a + %a\n",
				p->file, p->line, rstr(p->r), p->x, p->y, p->y2, ysin, ycos,
				dsin, dsin-p->dy, p->dy, dcos, dcos-p->dy2, p->dy2);
			err++;
		}
	}
	return !!err;
}
