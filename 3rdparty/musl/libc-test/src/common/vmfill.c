#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include "test.h"
#ifndef PAGE_SIZE
	#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#endif
#ifndef MAP_ANONYMOUS
	#define MAP_ANONYMOUS 0
#endif

/* max mmap size, *start is the largest power-of-2 size considered */
static size_t mmax(int fd, size_t *start)
{
	size_t i, n;
	void *p;

	for (i=n=*start; i>=PAGE_SIZE; i/=2) {
		if ((p=mmap(0, n, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, fd, 0)) == MAP_FAILED) {
			n -= i/2;
		} else {
			munmap(p, n);
			if (n == i)
				*start = n;
			n += i/2;
		}
	}
	return n & -PAGE_SIZE;
}

/*
fills the virtual memory with anonymous PROT_NONE mmaps,
returns the mappings in *p and *n in decreasing size order,
the return value is the number of mappings or -1 on failure.
*/
int t_vmfill(void **p, size_t *n, int len)
{
	int fd = MAP_ANONYMOUS ? -1 : open("/dev/zero", O_RDWR);
	size_t start = SIZE_MAX/2 + 1;
	size_t m;
	void *q;
	int i;

	for (i=0;;i++) {
		m = mmax(fd, &start);
		if (!m)
			break;
		q = mmap(0, m, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);
		if (q == MAP_FAILED)
			return -1;
		if (i < len) {
			p[i] = q;
			n[i] = m;
		}
	}
	return i;
}
