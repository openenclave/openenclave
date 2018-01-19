// commit 7c8c86f6308c7e0816b9638465a5917b12159e8f 2015-03-20
// backref is not valid in ere
#include <regex.h>
#include "test.h"

int main(void)
{
	char buf[200];
	char pat[] = "(a)\\1";
	regex_t r;
	int n;

	n = regcomp(&r, pat, REG_EXTENDED);
	if (n) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regcomp(%s) returned %d (%s) wanted 0\n", pat, n, buf);
	}

	n = regexec(&r, "aa", 0, 0, 0);
	if (n != REG_NOMATCH) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regexec(/%s/ ~ \"aa\") returned %d (%s), wanted REG_NOMATCH\n",
			pat, n, buf);
	}

	n = regexec(&r, "a1", 0, 0, 0);
	if (n) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regexec(/%s/ ~ \"a1\") returned %d (%s), wanted 0\n",
			pat, n, buf);
	}

	return t_status;
}
