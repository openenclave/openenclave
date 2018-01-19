#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include "test.h"

#define TEST(r, f, x, m) ( \
	errno = 0, ((r) = (f)) == (x) || \
	(t_error("%s failed (" m ")\n", #f, r, x, strerror(errno)), 0) )

#define TEST_S(s, x, m) ( \
	!strcmp((s),(x)) || \
	(t_error("[%s] != [%s] (%s)\n", s, x, m), 0) )

int main(void)
{
	int i;
	char a[100];
	FILE *f;

	TEST(i, !(f = tmpfile()), 0, "failed to create temp file %d!=%d (%s)");

	if (!f) return t_status;

	TEST(i, fprintf(f, "hello, world\n"), 13, "%d != %d (%m)");
	TEST(i, fseek(f, 0, SEEK_SET), 0, "%d != %d (%m)");

	TEST(i, feof(f), 0, "%d != %d");
	TEST(i, fgetc(f), 'h', "'%c' != '%c'");
	TEST(i, ftell(f), 1, "%d != %d");
	TEST(i, ungetc('x', f), 'x', "%d != %d");
	TEST(i, ftell(f), 0, "%d != %d");
	TEST(i, fscanf(f, "%[h]", a), 0, "got %d fields, expected %d");
	TEST(i, ftell(f), 0, "%d != %d");
	TEST(i, fgetc(f), 'x', "'%c' != '%c'");
	TEST(i, ftell(f), 1, "%d != %d");

	TEST(i, fseek(f, 0, SEEK_SET), 0, "%d != %d");
	TEST(i, ungetc('x', f), 'x', "%d != %d");
	TEST(i, fread(a, 1, sizeof a, f), 14, "read %d, expected %d");
	a[14] = 0;
	TEST_S(a, "xhello, world\n", "mismatch reading ungot character");

	TEST(i, fseek(f, 0, SEEK_SET), 0, "%d != %d");
	TEST(i, fscanf(f, "%[x]", a), 0, "got %d fields, expected %d");
	TEST(i, ungetc('x', f), 'x', "unget failed after fscanf: %d != %d");
	TEST(i, fgetc(f), 'x', "'%c' != '%c'");
	TEST(i, fgetc(f), 'h', "'%c' != '%c'");

	fclose(f);
	return t_status;
}
