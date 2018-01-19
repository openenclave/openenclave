#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <search.h>
#include <errno.h>
#include "test.h"

#define set(k,v) do{ \
	e = hsearch((ENTRY){.key = k, .data = (void*)v}, ENTER); \
	if (!e || strcmp(e->key, k) != 0) \
		t_error("hsearch ENTER %s %d failed\n", k, v); \
}while(0)

#define get(k) hsearch((ENTRY){.key = k, .data = 0}, FIND)

#define getdata(e) ((intptr_t)(e)->data)

int main()
{
	ENTRY *e;

	if (hcreate(-1) || errno != ENOMEM)
		t_error("hcreate((size_t)-1) should fail with ENOMEM got %s\n", strerror(errno));
	if (!hcreate(13))
		t_error("hcreate(13) failed\n");
	set("", 0);
	set("a", 1);
	set("b", 2);
	set("abc", 3);
	set("cd", 4);
	set("e", 5);
	set("ef", 6);
	set("g", 7);
	set("h", 8);
	set("iiiiiiiiii", 9);
	if (!get("a"))
		t_error("hsearch FIND a failed\n");
	if (get("c"))
		t_error("hsearch FIND c should fail\n");
	set("g", 10);
	if (e && getdata(e) != 7)
		t_error("hsearch ENTER g 10 returned data %d, wanted 7\n", getdata(e));
	set("g", 10);
	if (e && getdata(e) != 7)
		t_error("hsearch ENTER g 10 returned data %d, wanted 7\n", getdata(e));
	set("j", 10);
	if (e && getdata(e) != 10)
		t_error("hsearch ENTER j 10 returned data %d, wanted 10\n", getdata(e));
	hdestroy();
	return t_status;
}
