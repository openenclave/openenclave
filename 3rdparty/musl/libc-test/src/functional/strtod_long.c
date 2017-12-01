#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

int main(void)
{
	double x, want = .1111111111111111111111;
	char buf[40000];

	memset(buf, '1', sizeof buf);
	buf[0] = '.';
	buf[sizeof buf - 1] = 0;

	if ((x=strtod(buf, 0)) != want)
		t_error("strtod(.11[...]1) got %a want %a\n", x, want);
	return t_status;
}

