#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define TEST(r, f, x, m) ( \
((r) = (f)) == (x) || \
(t_error("%s failed (" m ")\n", #f, r, x), 0) )

#define TEST_E(f) ( (errno = 0), (f) || \
(t_error("%s failed (errno = %d)\n", #f, errno), 0) )

#define TEST_S(s, x, m) ( \
!strcmp((s),(x)) || \
(t_error("[%s] != [%s] (%s)\n", s, x, m), 0) )

#define TEST_M(s, x, n, m) ( \
!memcmp((s),(x),(n)) || \
(t_error("[%s] != [%s] (%s)\n", s, x, m), 0) )

int main(void)
{
	FILE *f;
	char *s;
	size_t l;
	char buf[100];
	int i;

	s = 0;
	TEST_E(f = open_memstream(&s, &l));
	TEST_E(putc('a', f) == 'a');
	TEST_E(putc('b', f) == 'b');
	TEST_E(putc('c', f) == 'c');
	TEST_E(!fflush(f));
	fclose(f);
	if (s) TEST_S(s, "abc", "wrong output");
	free(s);

	s = 0;
	TEST_E(f = open_memstream(&s, &l));
	TEST_E(fseek(f,1,SEEK_CUR)>=0);
	TEST_E(putc('q', f) == 'q');
	TEST_E(!fflush(f));
	if (s) TEST_M(s, "\0q", 3, "wrong output");
	TEST(i, fseek(f,-3,SEEK_CUR), -1, "invalid seek allowed");
	TEST(i, errno, EINVAL, "%d != %d");
	TEST(i, ftell(f), 2, "%d != %d");
	TEST_E(fseek(f,-2,SEEK_CUR)>=0);
	TEST_E(putc('e', f) == 'e');
	TEST_E(!fflush(f));
	if (s) TEST_S(s, "eq", "wrong output");
	fclose(f);
	free(s);

	TEST_E(f = fmemopen(buf, 10, "r+"));
	TEST_E(fputs("hello", f) >= 0);
	TEST_E(fputc(0, f)==0);
	TEST_E(fseek(f, 0, SEEK_SET)>=0);
	i=0;
	TEST_E(fscanf(f, "hello%n", &i)==0);
	TEST(i, i, 5, "%d != %d");
	TEST(i, ftell(f), 5, "%d != %d");
	errno = 0;
	TEST(i, fseek(f, 6, SEEK_CUR)<0, 1, "");
	TEST(i, errno!=0, 1, "");
	TEST(i, ftell(f), 5, "%d != %d");
	TEST_S(buf, "hello", "");
	fclose(f);

	TEST_E(f = fmemopen(buf, 10, "a+"));
	TEST(i, ftell(f), 5, "%d != %d");
	TEST_E(fseek(f, 0, SEEK_SET)>=0);
	TEST(i, getc(f), 'h', "%d != %d");
	TEST(i, getc(f), 'e', "%d != %d");
	TEST(i, getc(f), 'l', "%d != %d");
	TEST(i, getc(f), 'l', "%d != %d");
	TEST(i, getc(f), 'o', "%d != %d");
	TEST(i, getc(f), EOF, "%d != %d");
	TEST_E(fseek(f, 6, SEEK_SET)>=0);
	TEST(i, ftell(f), 6, "%d != %d");
	TEST(i, getc(f), EOF, "%d != %d");
	TEST(i, ftell(f), 6, "%d != %d");
	TEST_E(fseek(f, 0, SEEK_SET)>=0);
	TEST(i, getc(f), 'h', "%d != %d");
	TEST_E(fseek(f, 0, SEEK_CUR)>=0);
	buf[7] = 'x';
	TEST_E(fprintf(f, "%d", i)==3);
	TEST_E(fflush(f)==0);
	TEST(i, ftell(f), 8, "%d != %d");
	TEST_S(buf, "hello104", "");
	fclose(f);
	return t_status;
}
