#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>

int main(int argc, char *argv[])
{
	int i;
	float f;
	double d;
	long double ld;
	char *eptr;

	for (i = 1; i < argc; i++) {
		errno = 0;
		f = strtof(argv[i], &eptr);
		f = nextafterf(f, INFINITY);
		printf("%a  (*eptr:%d errno:%d)\n", f, *eptr, errno);
		errno = 0;
		d = strtod(argv[i], &eptr);
		d = nextafter(d, INFINITY);
		printf("%a  (*eptr:%d errno:%d)\n", d, *eptr, errno);
		errno = 0;
		ld = strtold(argv[i], &eptr);
		ld = nextafterl(ld, INFINITY);
		printf("%La  (*eptr:%d errno:%d)\n", ld, *eptr, errno);
	}
	return 0;
}
