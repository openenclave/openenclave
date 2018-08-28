// [^aBcC] with REG_ICASE should match d,D but not a,A,b,B,c,C according to
// http://austingroupbugs.net/view.php?id=872
#include <regex.h>
#include <limits.h>
#include <stdio.h>
#include "test.h"

int main(void)
{
	char buf[100];
	char *pat;
	regex_t re;
	int n, i;
	struct {
		char *s;
		int n;
	} t[] = {
		{"a", REG_NOMATCH},
		{"A", REG_NOMATCH},
		{"b", REG_NOMATCH},
		{"B", REG_NOMATCH},
		{"c", REG_NOMATCH},
		{"C", REG_NOMATCH},
		{"d", 0},
		{"D", 0},
		{0,0}
	};

	pat = "[^aBcC]";
	n = regcomp(&re, pat, REG_ICASE);
	if (n) {
		regerror(n, &re, buf, sizeof buf);
		t_error("regcomp(\"%s\") failed: %d (%s)\n", pat, n, buf);
	}

	for (i = 0; t[i].s; i++) {
		n = regexec(&re, t[i].s, 0, 0, 0);
		if (n != t[i].n) {
			regerror(n, &re, buf, sizeof buf);
			t_error("regexec(/%s/, \"%s\") returned %d (%s), wanted %d\n",
				pat, t[i].s, n, buf, t[i].n);
		}
	}

	return t_status;
}
