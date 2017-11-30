#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <sys/resource.h>
#include "test.h"

int main(void)
{
	enum {n = 8*1024*1024};
	char *s = malloc(n);
	int i;
	float f;
	char c;

	if (!s)
		return t_error("out of memory");
	t_setrlim(RLIMIT_STACK, 100*1024);

	for (i = 0; i < n; i++) s[i] = '1';
	s[n-3] = ' ';
	s[n-1] = 0;

	/*
	 * stack overflow if scanf copies s on the stack (glibc)
	 * same issue with %d except then storing the conversion
	 * result is undefined behaviour
	 */
	i = sscanf(s, "%f %c", &f, &c);

	if (i != 2)
		t_error("sscanf returned %d, want 2\n", i);
	if (f != INFINITY)
		t_error("sscanf(longnum, \"%%f\") read %f, want inf\n", f);
	if (c != '1')
		t_error("sscanf(\"1\", %%c) read '%c', want '1'\n", c);
	free(s);
	return t_status;
}
