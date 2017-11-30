#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <string.h>
#include <search.h>
#include "test.h"

#define W 80
static char tab[100][W];
static size_t nel;

#define set(k) do{ \
	char *r = lsearch(k, tab, &nel, W, (int(*)(const void*,const void*))strcmp); \
	if (strcmp(r, k) != 0) \
		t_error("lsearch %s failed\n", #k); \
}while(0)

#define get(k) lfind(k, tab, &nel, W, (int(*)(const void*,const void*))strcmp)

int main()
{
	size_t n;

	set("");
	set("a");
	set("b");
	set("abc");
	set("cd");
	set("e");
	set("ef");
	set("g");
	set("h");
	set("iiiiiiiiii");
	if (!get("a"))
		t_error("lfind a failed\n");
	if (get("c"))
		t_error("lfind c should fail\n");
	n = nel;
	set("g");
	if (nel != n)
		t_error("lsearch g should not modify the table size (%d, was %d)\n", nel, n);
	n = nel;
	set("j");
	if (nel != n+1)
		t_error("lsearch j should increase the table size (%d, was %d)\n", nel, n);
	return t_status;
}
