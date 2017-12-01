// commit cef0f289f666b6c963bfd11537a6d80916ff889e 2014-06-19
// memmem should not access oob data
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include "test.h"

int main(void)
{
	const unsigned char haystack[] = { 0,0,0,0,0,0,0,1,2 };
	const unsigned char needle[] =   { 0,0,0,0,0,0,0,1,3 };
	unsigned char *p = memmem(haystack, 8, needle, 8);
	if (!p)
		t_error("memmem(A,8,A,8) returned 0, want A\n");
	return t_status;
}
