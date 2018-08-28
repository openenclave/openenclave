#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "test.h"

/* r = place to store result
 * f = function call to test (or any expression)
 * x = expected result
 * m = message to print on failure (with formats for r & x)
 */

#define TEST(r, f, x, m) ( \
	((r) = (f)) == (x) || \
	(t_error("%s failed (" m ")\n", #f, r, x, r-x), 0) )

int main(void)
{
	int i;
	double d, d2;
	char buf[1000];

	for (i=0; i<100; i++) {
		d = sin(i);
		snprintf(buf, sizeof buf, "%.300f", d);
		TEST(d2, strtod(buf, 0), d, "round trip fail %a != %a (%a)");
	}

	TEST(d, strtod("0x1p4", 0), 16.0, "hex float %a != %a");
	TEST(d, strtod("0x1.1p4", 0), 17.0, "hex float %a != %a");
	return t_status;
}

