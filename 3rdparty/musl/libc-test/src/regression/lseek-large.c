// lseek should work with >2G offset
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "test.h"

#define A(c) ((c) || (t_error(#c " failed: %s\n", strerror(errno)), 0))

int main(void)
{
	off_t a[] = {0x7fffffff, 0x80000000, 0x80000001, 0xffffffff, 0x100000001, 0x1ffffffff, 0 };
	off_t r;
	FILE *f;
	int fd;
	int i;

	A((f = tmpfile()) != 0);
	A((fd = fileno(f)) != -1);
	for (i = 0; a[i]; i++) {
		r = lseek(fd, a[i], SEEK_SET);
		if (r != a[i])
			t_error("lseek(fd, 0x%llx, SEEK_SET) got 0x%llx\n", (long long)a[i], (long long)r);
	}
	return t_status;
}
