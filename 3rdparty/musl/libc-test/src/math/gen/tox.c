#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int i;
	union {float f; uint32_t i;} f;
	union {double f; uint64_t i;} d;
	union {long double f; struct {uint64_t m; uint16_t se;} i;} ld;
	char *eptr;

	for (i = 1; i < argc; i++) {
		errno = 0;
		f.f = strtof(argv[i], &eptr);
		printf("0x%08x  (*eptr:%d errno:%d)\n", f.i, *eptr, errno);
		errno = 0;
		d.f = strtod(argv[i], &eptr);
		printf("0x%08x %08x  (*eptr:%d errno:%d)\n",
			(unsigned)(d.i>>32), (unsigned)d.i, *eptr, errno);
		errno = 0;
		ld.f = strtold(argv[i], &eptr);
		printf("0x%04x %08x %08x  (*eptr:%d errno:%d)\n",
			ld.i.se, (unsigned)(ld.i.m>>32), (unsigned)ld.i.m, *eptr, errno);
	}
	return 0;
}
