// introduced by d6c855caa88ddb1ab6e24e23a14b1e7baf4ba9c7 2018-09-15
// sscanf may crash on short input
#include <stdio.h>
#include "test.h"

int main(void)
{
	const char *s = "0";
	const char *fmt = "%f%c";
	float f = 1.0f;
	char c = 'x';
	int r = sscanf(s, fmt, &f, &c);
	if (r != 1)
		t_error("sscanf(\"%s\", \"%s\",..) returned %d, wanted 1\n", s, fmt, r);
	if (f != 0.0f || c != 'x')
		t_error("sscanf(\"%s\", \"%s\",..) assigned f=%f c='%c', wanted i=0 c='x'\n", s, fmt, f, c);
	return t_status;
}
