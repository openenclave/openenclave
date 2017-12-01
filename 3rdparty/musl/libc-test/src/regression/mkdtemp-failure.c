// commit: 69ecbd0f3188be97f91cc0d6415836d23e88f7fc 2011-02-19
// commit: 382584724308442f03f3d29f7fc6de9e9d140982 2011-06-12
// commit: c4685ae429a0cce4b285859d62a71fe603f0a864 2013-08-02
// mkdtemp should return -1 on bad template
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "test.h"

char *mkdtemp(char *);

#define S "/dev/null/fooXXXX"

int main(void)
{
	char p[] = S;
	char *r;

	r = mkdtemp(p);
	if (r)
		t_error("mkdtemp(" S ") did not fail\n");
	if (memcmp(p, S, sizeof p) != 0)
		t_error("mkdtemp(" S ") modified the template: %s\n", p);
	if (r == 0 && errno != EINVAL)
		t_error("mkdtemp(" S ") failed with %d [%s] instead of %d [%s]\n",
			errno, strerror(errno), EINVAL, strerror(EINVAL));
	return t_status;
}
