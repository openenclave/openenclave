// \0 is not a valid backref, it is undefined by the standard
// we treat such cases as literal char
#include <regex.h>
#include "test.h"

int main(void)
{
	char buf[200];
	char pat[] = "a\\0";
	regex_t r;
	int n;

	n = regcomp(&r, pat, 0);
	if (n) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regcomp(%s) returned %d (%s) wanted 0\n", pat, n, buf);
	}
	n = regexec(&r, "a0", 0, 0, 0);
	if (n) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regexec(/%s/ ~ \"a0\") returned %d (%s), wanted 0\n",
			pat, n, buf);
	}

	return t_status;
}
