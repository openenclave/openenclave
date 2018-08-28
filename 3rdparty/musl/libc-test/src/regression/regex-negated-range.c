// negated overlapping ranges in a regex bracket
// were not handled correctly by tre
#include <regex.h>
#include "test.h"

int main(void)
{
	char buf[200];
	regex_t r;
	int n;

	n = regcomp(&r, "[^aa-z]", 0);
	if (n) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regcomp returned %d (%s)\n", n, buf);
	}

	n = regexec(&r, "k", 0, 0, 0);
	if (n != REG_NOMATCH) {
		regerror(n, &r, buf, sizeof buf);
		t_error("regexec(/[^aa-z]/ ~ \"k\") returned %d (%s), wanted REG_NOMATCH\n",
			n, buf);
	}

	return t_status;
}
