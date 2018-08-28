#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include "test.h"

int t_setrlim(int r, long lim)
{
	struct rlimit rl;

	if (getrlimit(r, &rl)) {
		t_error("getrlimit %d: %s\n", r, strerror(errno));
		return -1;
	}
	if (lim > rl.rlim_max)
		return -1;
	if (lim == rl.rlim_max && lim == rl.rlim_cur)
		return 0;
	rl.rlim_max = lim;
	rl.rlim_cur = lim;
	if (setrlimit(r, &rl)) {
		t_error("setrlimit(%d, %ld): %s\n", r, lim, strerror(errno));
		return -1;
	}
	return 0;
}

