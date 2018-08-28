// fgets must not modify the buffer on eof
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

#define ASSERT(c) do { if (!(c)) t_error("%s failed\n", #c); } while(0)

int main(void)
{
	char buf[] = "test";
	char s[10];
	FILE *f;

	ASSERT((f = fmemopen(buf, sizeof buf, "r")) != 0);
	ASSERT(fgets(s, sizeof s, f) == s);
	ASSERT(strcmp(s, buf) == 0);
	ASSERT(fgets(s, sizeof s, f) == 0);
	if (s[0] != 't')
		t_error("fgets modified the buffer after eof\n");
	return t_status;
}
