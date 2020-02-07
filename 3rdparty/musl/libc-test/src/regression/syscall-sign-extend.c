// commit 5f95f965e933c5b155db75520ac27c92ddbcf400 2014-03-18
// syscall should not sign extend pointers on x32
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "test.h"

#define T(f) (!(f) && (t_error(#f " failed: %s\n", strerror(errno)), 0))

int main(void)
{
	char buf[1] = {1};
	int fd;
	int r;

	// test syscall with pointer
	T((fd = open("/dev/zero", O_RDONLY)) >= 0);
	T((r = syscall(SYS_read, fd, buf, 1)) == 1);
	if (buf[0] != 0)
		t_error("read %d instead of 0\n", buf[0]);

	return t_status;
}
