// testing musl internal __pleval api used in dcngettext
#include <string.h>
#include "test.h"

unsigned long __pleval(const char *, unsigned long);

static void t(const char *s, unsigned long n, unsigned long want)
{
	unsigned long got = __pleval(s, n);
	if (got != want)
		t_error("__pleval(\"%s\",%lu) failed: got %lu want %lu\n", s, n, got, want);
}

// evals the expr with the compiler: gettext plural rules follow c syntax
#define T(e) do { \
	unsigned long n, _w; \
	for (n=0; n<200; n++) { \
		_w = e \
		t(#e, n, _w); \
	} \
} while(0)

int main()
{
	char buf[210];

	// recursion depth limit check
	memset(buf, '!', 200);
	memcpy(buf+200, "n;", 3);
	t(buf, 7, -1);

	memcpy(buf+51, "n;", 3);
	t(buf, 3, 0);
	t(buf, 0, 1);
	memcpy(buf+50, "n;", 3);
	t(buf, 3, 1);
	t(buf, 0, 0);

	// bad expr
	t("!n n;", 1, -1);
	t("32n;", 1, -1);
	t("n/n;", 0, -1);
	t("n*3-;", 1, -1);
	t("4*;", 13, -1);
	t("n?1:;", 13, -1);

	// good expr
	T(n % 4;);
	T(n== 1 || n == 2 ||n%9==7;);
	T((n==1)+!n+(n  ==3););
	T(n - 13 - 5 + n * 3 / 7 - 8;);
	T(n+n>n==n-n<n?n/(n||!!!n):0-n;);
	T((n<=3>=0)+n+n+n-n-n*1*1*1/1%12345678;);
	T(5<6-4*n&&n%3==n-1;);
	T(n%7&&n||0&&n-1;);

	// the following plural rules are from
	// http://localization-guide.readthedocs.org/en/latest/l10n/pluralforms.html
	T(0;);
	T((n > 1););
	T((n != 1););
	T((n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 ? 4 : 5););
	T((n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2););
	T((n==1) ? 0 : (n>=2 && n<=4) ? 1 : 2;);
	T((n==1) ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2;);
	T((n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2););
	T((n==1) ? 0 : (n==2) ? 1 : (n != 8 && n != 11) ? 2 : 3;);
	T((n==1 ? 0 : (n==0 || (n%100 > 0 && n%100 < 20)) ? 1 : 2););
	T((n==1) ? 0 : n==2 ? 1 : n<7 ? 2 : n<11 ? 3 : 4;);
	T((n==1 || n==11) ? 0 : (n==2 || n==12) ? 1 : (n > 2 && n < 20) ? 2 : 3;);
	T((n%10!=1 || n%100==11););
	T((n != 0););
	T((n==1) ? 0 : (n==2) ? 1 : (n == 3) ? 2 : 3;);
	T((n%10==1 && n%100!=11 ? 0 : n != 0 ? 1 : 2););
	T((n==0 ? 0 : n==1 ? 1 : 2););
	T((n==1 ? 0 : n==0 || ( n%100>1 && n%100<11) ? 1 : (n%100>10 && n%100<20 ) ? 2 : 3););
	T((n==1) ? 0 : (n>=2 && n<=4) ? 1 : 2;);
	T((n%100==1 ? 1 : n%100==2 ? 2 : n%100==3 || n%100==4 ? 3 : 0););

	return t_status;
}
