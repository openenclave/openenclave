#include <string.h>
#include <stdio.h>
#include "test.h"

/* relative path to p */
char *t_pathrel(char *buf, size_t n, char *argv0, char *p)
{
	char *s = strrchr(argv0, '/');
	int k;

	if (s)
		k = snprintf(buf, n, "%.*s/%s", (int)(s-argv0), argv0, p);
	else
		k = snprintf(buf, n, "./%s", p);
	if ((size_t)k >= n)
		return 0;
	return buf;
}
