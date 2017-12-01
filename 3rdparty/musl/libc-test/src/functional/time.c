#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "test.h"

/* We use this instead of memcmp because some broken C libraries
 * add additional nonstandard fields to struct tm... */

int tm_cmp(struct tm tm1, struct tm tm2)
{
	return  tm1.tm_sec  != tm2.tm_sec  ||
		tm1.tm_min  != tm2.tm_min  ||
		tm1.tm_hour != tm2.tm_hour ||
		tm1.tm_mday != tm2.tm_mday ||
		tm1.tm_mon  != tm2.tm_mon  ||
		tm1.tm_year != tm2.tm_year ||
		tm1.tm_wday != tm2.tm_wday ||
		tm1.tm_yday != tm2.tm_yday ||
		tm1.tm_isdst!= tm2.tm_isdst;
}

char *tm_str(struct tm tm)
{
	static int i;
	static char b[4][64];
	i = (i+1)%4;
	snprintf(b[i], sizeof b[i],
		"s=%02d m=%02d h=%02d mday=%02d mon=%02d year=%04d wday=%d yday=%d isdst=%d",
		tm.tm_sec, tm.tm_min, tm.tm_hour,
		tm.tm_mday, tm.tm_mon, tm.tm_year,
		tm.tm_wday, tm.tm_yday, tm.tm_isdst);
	return b[i];
}

#define TM(ss,mm,hh,md,mo,yr,wd,yd,dst) (struct tm){ \
	.tm_sec = ss, .tm_min = mm, .tm_hour = hh,    \
	.tm_mday = md, .tm_mon = mo, .tm_year = yr,    \
	.tm_wday = wd, .tm_yday = yd, .tm_isdst = dst }

#define TM_EPOCH    TM(0,0,0,1,0,70,4,0,0)
#define TM_Y2038_1S TM(7,14,3,19,0,138,2,18,0)
#define TM_Y2038    TM(8,14,3,19,0,138,2,18,0)

static void sec2tm(time_t t, char *m)
{
	struct tm *tm;
	time_t r;

	errno = 0;
	tm = gmtime(&t);
	if (errno != 0)
		t_error("%s: gmtime((time_t)%lld) should not set errno, got %s\n",
			m, (long long)t, strerror(errno));
	errno = 0;
	r = mktime(tm);
	if (errno != 0)
		t_error("%s: mktime(%s) should not set errno, got %s\n",
			m, tm_str(*tm), strerror(errno));
	if (t != r)
		t_error("%s: mktime(gmtime(%lld)) roundtrip failed: got %lld (gmtime is %s)\n",
			m, (long long)t, (long long)r, tm_str(*tm));
}

static void tm2sec(struct tm *tm, int big, char *m)
{
	struct tm *r;
	time_t t;
	int overflow = big && (time_t)LLONG_MAX!=LLONG_MAX;

	errno = 0;
	t = mktime(tm);
	if (overflow && t != -1)
		t_error("%s: mktime(%s) expected -1, got (time_t)%ld\n",
			m, tm_str(*tm), (long)t);
	if (overflow && errno != EOVERFLOW)
		t_error("%s: mktime(%s) expected EOVERFLOW (%s), got (%s)\n",
			m, tm_str(*tm), strerror(EOVERFLOW), strerror(errno));
	if (!overflow && t == -1)
		t_error("%s: mktime(%s) expected success, got (time_t)-1\n",
			m, tm_str(*tm));
	if (!overflow && errno)
		t_error("%s: mktime(%s) expected no error, got (%s)\n",
			m, tm_str(*tm), strerror(errno));
	r = gmtime(&t);
	if (!overflow && tm_cmp(*r, *tm))
		t_error("%s: gmtime(mktime(%s)) roundtrip failed: got %s\n",
			m, tm_str(*tm), tm_str(*r));
}

int main(void)
{
	time_t t;

	putenv("TZ=GMT");
	tzset();
	tm2sec(&TM_EPOCH, 0, "gmtime(0)");
	tm2sec(&TM_Y2038_1S, 0, "2038-1s");
	tm2sec(&TM_Y2038, 1, "2038");

	sec2tm(0, "EPOCH");
	for (t = 1; t < 1000; t++)
		sec2tm(t*100003, "EPOCH+eps");

	/* FIXME: set a TZ var and check DST boundary conditions */
	return t_status;
}
