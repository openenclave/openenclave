// commit 89740868c9f1c84b8ee528468d12df1fa72cd392 2014-04-07
// %g should not print trailing zeros
#include <stdio.h>
#include <string.h>
#include "test.h"

static void t(const char *fmt, double d, const char *want)
{
	char buf[256];
	int n = strlen(want);
	int r = snprintf(buf, sizeof buf, fmt, d);
	if (r != n || memcmp(buf, want, n+1) != 0)
		t_error("snprintf(\"%s\",%f) want %s got %s\n", fmt, d, want, buf);
}

int main()
{
	t("%.50g", 100000000000000.5, "100000000000000.5");
	t("%.50g", 987654321098765.0, "987654321098765");
	return t_status;
}
