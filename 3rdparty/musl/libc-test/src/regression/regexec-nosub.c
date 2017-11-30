// commit: 72ed3d47e567b1635a35d3c1d174c8a8b2787e30 2014-07-17
// regexec should not crash on non-zero nmatch with REG_NOSUB
#include <regex.h>
#include "test.h"

int main(void)
{
	regex_t re;
	int r;

	r = regcomp(&re, "abc", REG_NOSUB);
	if (r)
		t_error("regcomp failed: %d\n", r);
	r = regexec(&re, "zyx abc", 1, 0, 0);
	if (r == REG_NOMATCH)
		t_error("regexec failed to match\n");
	else if (r)
		t_error("regexec returned invalid code: %d\n", r);
	regfree(&re);
	return t_status;
}
