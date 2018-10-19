// commit: 9cad27a3dc1a4eb349b6591e4dc8cc89dce32277
// ungetc after setvbuf should not clobber memory below buffer
#include <stdio.h>
#include <string.h>
#include "test.h"

int main(void)
{
	char buf[1024] = "hello world";
	setvbuf(stdin, buf+12, _IOFBF, sizeof buf - 12);
	while (ungetc('x', stdin)!=EOF);
	if (strcmp(buf, "hello world"))
		t_error("ungetc clobbered outside buffer: [%.12s]\n", buf);
	return t_status;
}
