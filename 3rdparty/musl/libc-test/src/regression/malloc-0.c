// commit: 26031da0f83a2a3ed52190077931ee6c18dfd689 2011-02-20
// malloc(0) should return unique pointers
// (often expected and gnulib replaces malloc if malloc(0) returns 0)
#include <stdlib.h>
#include "test.h"

int main(void)
{
	void *p = malloc(0);
	void *q = malloc(0);
	void *r = malloc(0);
	if (!p || !q || !r)
		t_error("malloc(0) returned NULL\n");
	if (p == q || p == r || q == r)
		t_error("malloc(0) returned non-unique pointers: %p, %p, %p\n", p, q, r);
	free(q);
	free(p);
	free(r);
	return t_status;
}
