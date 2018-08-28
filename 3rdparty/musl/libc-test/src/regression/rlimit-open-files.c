// rlimit should be able to set file limits
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include "test.h"

int main(void)
{
	static const long lim = 42;
	static const int r = RLIMIT_NOFILE;
	struct rlimit rl;
	int fd, maxfd = 0;

	rl.rlim_max = lim;
	rl.rlim_cur = lim;
	if (setrlimit(r, &rl))
		t_error("setrlimit(%d, %ld) failed: %s\n", r, lim, strerror(errno));
	if (getrlimit(r, &rl))
		t_error("getrlimit(%d) failed: %s\n", r, strerror(errno));
	if (rl.rlim_max != lim || rl.rlim_cur != lim)
		t_error("getrlimit %d says cur=%ld,max=%ld after setting the limit to %ld\n", r, rl.rlim_cur, rl.rlim_max, lim);

	while((fd=dup(1)) != -1)
		if (fd > maxfd) maxfd = fd;
	if (errno != EMFILE)
		t_error("dup(1) failed with %s, wanted EMFILE\n", strerror(errno));
	if (maxfd+1 != lim)
		t_error("more fds are open than rlimit allows: fd=%d, limit=%d\n", maxfd, lim);

	return t_status;
}
