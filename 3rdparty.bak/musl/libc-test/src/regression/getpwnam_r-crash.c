// commit fc5a96c9c8aa186effad7520d5df6b616bbfd29d
// getpwnam_r should not crash on nonexistant users when errno is 0

#include <pwd.h>
#include "test.h"

int main(void)
{
	struct passwd *pw, pwbuf;
	char buf[1024];
	getpwnam_r("nonsensical_user", &pwbuf, buf, sizeof buf, &pw);
	return t_status;
}
