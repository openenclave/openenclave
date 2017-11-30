#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "test.h"

#define N 400
static char buf[N];
static char buf2[N];

static void *(*volatile pmemset)(void *, int, size_t);

static char *aligned(void *p)
{
	return (char*)(((uintptr_t)p + 63) & -64);
}

static void test_align(int align, int len)
{
	char *s = aligned(buf+64) + align;
	char *want = aligned(buf2+64) + align;
	char *p;
	int i;

	if (len + 64 > buf + N - s || len + 64 > buf2 + N - want)
		abort();
	for (i = 0; i < N; i++)
		buf[i] = buf2[i] = ' ';
	for (i = 0; i < len; i++)
		want[i] = '#';
	p = pmemset(s, '#', len);
	if (p != s)
		t_error("memset(%p,...) returned %p\n", s, p);
	for (i = -64; i < len+64; i++)
		if (s[i] != want[i]) {
			t_error("memset(align %d, '#', %d) failed at pos %d\n", align, len, i);
			t_printf("got : '%.*s'\n", len+128, s-64);
			t_printf("want: '%.*s'\n", len+128, want-64);
			break;
		}
}

static void test_value(int c)
{
	int i;

	pmemset(buf, c, 10);
	for (i = 0; i < 10; i++)
		if ((unsigned char)buf[i] != (unsigned char)c) {
			t_error("memset(%d) failed: got %d\n", c, buf[i]);
			break;
		}
}

int main(void)
{
	int i,j,k;

	pmemset = memset;

	for (i = 0; i < 16; i++)
		for (j = 0; j < 200; j++)
			test_align(i,j);

	test_value('c');
	test_value(0);
	test_value(-1);
	test_value(-5);
	test_value(0xab);
	return t_status;
}
