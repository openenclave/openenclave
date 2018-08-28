// commit 0afef1aa24b784c86ae6121ca39e999824086c7c
// preexisting errno should not be interpreted by passwd/group functions

#include <pwd.h>
#include <errno.h>
#include "test.h"

int main(void)
{
	int baderr = EOWNERDEAD; // arbitrary absurd error
	struct passwd *pw, pwbuf;
	char buf[1024];
	errno = baderr;
	if (getpwnam_r("nonsensical_user", &pwbuf, buf, sizeof buf, &pw) == baderr)
		t_error("getpwnam_r used preexisting errno for nonexisting user\n");
	return t_status;
}
