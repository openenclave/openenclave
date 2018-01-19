// commit: 2e6239dd064d201c6e1b0f589bae9ff27949d2eb 2011-02-19
// commit: 382584724308442f03f3d29f7fc6de9e9d140982 2011-06-12
// mkstemp should return -1 on bad template
#define _DEFAULT_SOURCE 1
#define _BSD_SOURCE 1
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "test.h"

int mkstemp(char *);

#define S "/dev/null/fooXXXX"

int main(void)
{
	char p[] = S;
	int r;

	r = mkstemp(p);
	if (r != -1)
		t_error("mkstemp(" S ") did not fail\n");
	if (memcmp(p, S, sizeof p) != 0)
		t_error("mkstemp(" S ") modified the template: %s\n", p);
	if (r == -1 && errno != EINVAL)
		t_error("mkstemp(" S ") failed with %d [%s] instead of %d [%s]\n",
			errno, strerror(errno), EINVAL, strerror(EINVAL));
	return t_status;
}
