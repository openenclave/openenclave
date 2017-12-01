// commit 543787039098c121917cb5f3e129d84b61afa61b 2013-10-04
// setenv should not crash on oom
#include <stdlib.h>
#include <sys/resource.h>
#include <string.h>
#include <errno.h>
#include "test.h"

int main(void)
{
	char buf[10000];

	if (t_memfill() < 0)
		t_error("memfill failed\n");

	memset(buf, 'x', sizeof buf);
	buf[sizeof buf - 1] = 0;

	errno = 0;
	if (setenv("TESTVAR", buf, 1) != -1)
		t_error("setenv was successful\n");
	if (errno != ENOMEM)
		t_error("expected ENOMEM, got %s\n", strerror(errno));

	return t_status;
}
