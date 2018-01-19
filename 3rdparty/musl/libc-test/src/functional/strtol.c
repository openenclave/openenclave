#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "test.h"

/* r = place to store result
 * f = function call to test (or any expression)
 * x = expected result
 * m = message to print on failure (with formats for r & x)
**/

#define TEST(r, f, x, m) ( \
	errno = 0, msg = #f, ((r) = (f)) == (x) || \
	(t_error("%s failed (" m ")\n", #f, r, x), 0) )

#define TEST2(r, f, x, m) ( \
	((r) = (f)) == (x) || \
	(t_error("%s failed (" m ")\n", msg, r, x), 0) )

int main(void)
{
	int i;
	long l;
	unsigned long ul;
	long long ll;
	unsigned long long ull;
	char *msg="";
	char *s, *c;

	TEST(l, atol("2147483647"), 2147483647L, "max 32bit signed %ld != %ld");
	TEST(l, strtol("2147483647", 0, 0), 2147483647L, "max 32bit signed %ld != %ld");
	TEST(ul, strtoul("4294967295", 0, 0), 4294967295UL, "max 32bit unsigned %lu != %lu");

	if (sizeof(long) == 4) {
		TEST(l, strtol(s="2147483648", &c, 0), 2147483647L, "uncaught overflow %ld != %ld");
		TEST2(i, c-s, 10, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(l, strtol(s="-2147483649", &c, 0), -2147483647L-1, "uncaught overflow %ld != %ld");
		TEST2(i, c-s, 11, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ul, strtoul(s="4294967296", &c, 0), 4294967295UL, "uncaught overflow %lu != %lu");
		TEST2(i, c-s, 10, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ul, strtoul(s="-1", &c, 0), -1UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-2", &c, 0), -2UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-2147483648", &c, 0), -2147483648UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 11, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-2147483649", &c, 0), -2147483649UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 11, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-4294967296", &c, 0), 4294967295UL, "uncaught negative overflow %lu != %lu");
		TEST2(i, c-s, 11, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "spurious errno %d != %d");
	} else if (sizeof(long) == 8) {
		TEST(l, strtol(s="9223372036854775808", &c, 0), 9223372036854775807L, "uncaught overflow %ld != %ld");
		TEST2(i, c-s, 19, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(l, strtol(s="-9223372036854775809", &c, 0), -9223372036854775807L-1, "uncaught overflow %ld != %ld");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ul, strtoul(s="18446744073709551616", &c, 0), 18446744073709551615UL, "uncaught overflow %lu != %lu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ul, strtoul(s="-1", &c, 0), -1UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-2", &c, 0), -2UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-9223372036854775808", &c, 0), -9223372036854775808UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-9223372036854775809", &c, 0), -9223372036854775809UL, "rejected negative %lu != %lu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ul, strtoul(s="-18446744073709551616", &c, 0), 18446744073709551615UL, "uncaught negative overflow %lu != %lu");
		TEST2(i, c-s, 21, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "spurious errno %d != %d");
	} else {
		t_error("sizeof(long) == %d, not implemented\n", (int)sizeof(long));
	}

	if (sizeof(long long) == 8) {
		TEST(ll, strtoll(s="9223372036854775808", &c, 0), 9223372036854775807LL, "uncaught overflow %lld != %lld");
		TEST2(i, c-s, 19, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ll, strtoll(s="-9223372036854775809", &c, 0), -9223372036854775807LL-1, "uncaught overflow %lld != %lld");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ull, strtoull(s="18446744073709551616", &c, 0), 18446744073709551615ULL, "uncaught overflow %llu != %llu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "missing errno %d != %d");
		TEST(ull, strtoull(s="-1", &c, 0), -1ULL, "rejected negative %llu != %llu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ull, strtoull(s="-2", &c, 0), -2ULL, "rejected negative %llu != %llu");
		TEST2(i, c-s, 2, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ull, strtoull(s="-9223372036854775808", &c, 0), -9223372036854775808ULL, "rejected negative %llu != %llu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ull, strtoull(s="-9223372036854775809", &c, 0), -9223372036854775809ULL, "rejected negative %llu != %llu");
		TEST2(i, c-s, 20, "wrong final position %d != %d");
		TEST2(i, errno, 0, "spurious errno %d != %d");
		TEST(ull, strtoull(s="-18446744073709551616", &c, 0), 18446744073709551615ULL, "uncaught negative overflow %llu != %llu");
		TEST2(i, c-s, 21, "wrong final position %d != %d");
		TEST2(i, errno, ERANGE, "spurious errno %d != %d");
	} else {
		t_error("sizeof(long long) == %d, not implemented\n", (int)sizeof(long long));
	}

	TEST(l, strtol("z", 0, 36), 35, "%ld != %ld");
	TEST(l, strtol("00010010001101000101011001111000", 0, 2), 0x12345678, "%ld != %ld");
	TEST(l, strtol(s="0F5F", &c, 16), 0x0f5f, "%ld != %ld");

	TEST(l, strtol(s="0xz", &c, 16), 0, "%ld != %ld");
	TEST2(i, c-s, 1, "wrong final position %ld != %ld");

	TEST(l, strtol(s="0x1234", &c, 16), 0x1234, "%ld != %ld");
	TEST2(i, c-s, 6, "wrong final position %ld != %ld");

	c = NULL;
	TEST(l, strtol(s="123", &c, 37), 0, "%ld != %ld");
	TEST2(i, c-s, 0, "wrong final position %d != %d");
	TEST2(i, errno, EINVAL, "%d != %d");

	TEST(l, strtol(s="  15437", &c, 8), 015437, "%ld != %ld");
	TEST2(i, c-s, 7, "wrong final position %d != %d");

	TEST(l, strtol(s="  1", &c, 0), 1, "%ld != %ld");
	TEST2(i, c-s, 3, "wrong final position %d != %d");
	return t_status;
}
