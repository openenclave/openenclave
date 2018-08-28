// lrand48 should give deterministic results
#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include "test.h"

int main(void)
{
	long r;
	r = lrand48();
	if (r != 0) t_error("1st lrand48() got %ld want 0\n", r);
	r = lrand48();
	if (r != 2116118) t_error("2nd lrand48() got %ld want 2116118\n", r);
	r = lrand48();
	if (r != 89401895) t_error("3rd lrand48() got %ld want 89401895\n", r);
	return t_status;
}
