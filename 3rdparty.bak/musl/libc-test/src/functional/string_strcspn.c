#include <stddef.h>
#include <string.h>
#include "test.h"

#define T(s, c, n) { \
	char *p = s; \
	char *q = c; \
	size_t r = strcspn(p, q); \
	if (r != n) \
		t_error("strcspn(%s,%s) returned %lu, wanted %lu\n", #s, #c, (unsigned long)r, (unsigned long)(n)); \
}

int main(void)
{
	int i;
	char a[128];
	char s[256];

	for (i = 0; i < 128; i++)
		a[i] = (i+1) & 127;
	for (i = 0; i < 256; i++)
		*((unsigned char*)s+i) = i+1;

	T("", "", 0)
	T("a", "", 1)
	T("", "a", 0)
	T("abc", "cde", 2)
	T("abc", "ccc", 2)
	T("abc", a, 0)
	T("\xff\x80 abc", a, 2)
	T(s, "\xff", 254)

	return t_status;
}
