// commit 5446303328adf4b4e36d9fba21848e6feb55fab4 2014-04-02
// malloc should not fail if brk fails but mmap can still allocate
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "test.h"

#define T(f) ((f)==0 || (t_error(#f " failed: %s\n", strerror(errno)), 0))

int main(void)
{
	void *p;
	void *q;
	size_t n;
	int r;

	// fill memory, largest mmaped area is [p,p+n)
	if (t_vmfill(&p, &n, 1) < 1 || n < 2*65536) {
		t_error("vmfill failed\n");
		return 1;
	}
	errno = 0;
	T(t_setrlim(RLIMIT_DATA, 0));

	// malloc should fail here
	errno = 0;
	q = malloc(10000);
	if (q)
		t_error("malloc(10000) succeeded after memory is filled\n");
	else if (errno != ENOMEM)
		t_error("malloc did not fail with ENOMEM, got %s\n", strerror(errno));

	// make some space available for mmap
	T(munmap((char*)p+65536, 65536));

	// malloc should succeed now
	q = malloc(10000);
	if (!q)
		t_error("malloc(10000) failed (eventhough 64k is available to mmap): %s\n", strerror(errno));

	return t_status;
}
