// commit e94d0692864ecf9522fd6a97610a47a2f718d3de 2014-04-07
// %g midpoint cases should be rounded to even
#include <stdio.h>
#include <string.h>
#include "test.h"

static void t(const char *fmt, double d, const char *want)
{
	char buf[256];
	int n = strlen(want);
	int r = snprintf(buf, sizeof buf, fmt, d);
	if (r != n || memcmp(buf, want, n+1) != 0)
		t_error("snprintf(\"%s\", %f) want %s got %s\n", fmt, d, want, buf);
}

int main()
{
	t("%.12g", 1000000000005.0, "1e+12");
	t("%.12g", 100000000002500.0, "1.00000000002e+14");
	return t_status;
}
