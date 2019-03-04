// SPDX-License-Identifier: MIT

#define _GNU_SOURCE	/* For tm_gmtoff */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "test.h"

/**
 * checkStrptime - parse time and check if it matches expected value
 *
 * This function compares time and date fields of tm structure only.
 * It's because tm_wday and tm_yday may - but don't have to - be set
 * while parsing a date.
 */
static void checkStrptime(const char *s, const char *format, const struct tm *expected) {
	struct tm tm = { };
	const char *ret;

	ret = strptime(s, format, &tm);
	if (!ret || *ret != '\0') {
		t_error("\"%s\": failed to parse \"%s\"\n", format, s);
	} else if (tm.tm_sec != expected->tm_sec ||
		   tm.tm_min != expected->tm_min ||
		   tm.tm_hour != expected->tm_hour ||
		   tm.tm_mday != expected->tm_mday ||
		   tm.tm_mon != expected->tm_mon ||
		   tm.tm_year != expected->tm_year) {
		char buf1[64];
		char buf2[64];

		strftime(buf1, sizeof(buf1), "%FT%H:%M:%S%Z", expected);
		strftime(buf2, sizeof(buf2), "%FT%H:%M:%S%Z", &tm);

		t_error("\"%s\": for \"%s\" expected %s but got %s\n", format, s, buf1, buf2);
	}
}

static void checkStrptimeTz(const char *s, int h, int m) {
	long int expected = h * 3600 + m * 60;
	struct tm tm = { };
	const char *ret;

	ret = strptime(s, "%z", &tm);
	if (!ret || *ret != '\0') {
		t_error("\"%%z\": failed to parse \"%s\"\n", s);
	} else if (tm.tm_gmtoff != expected) {
		t_error("\"%%z\": for \"%s\" expected tm_gmtoff %ld but got %ld\n", s, tm.tm_gmtoff, expected);
	}
}

static struct tm tm1 = {
	.tm_sec = 8,
	.tm_min = 57,
	.tm_hour = 20,
	.tm_mday = 0,
	.tm_mon = 0,
	.tm_year = 0,
};

static struct tm tm2 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 0,
	.tm_mday = 25,
	.tm_mon = 8 - 1,
	.tm_year = 1991 - 1900,
};

static struct tm tm3 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 0,
	.tm_mday = 21,
	.tm_mon = 10 - 1,
	.tm_year = 2015 - 1900,
};

static struct tm tm4 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 0,
	.tm_mday = 10,
	.tm_mon = 7 - 1,
	.tm_year = 1856 - 1900,
};

int main() {
	setenv("TZ", "UTC0", 1);

	/* Time */
	checkStrptime("20:57:08", "%H:%M:%S", &tm1);
	checkStrptime("20:57:8", "%R:%S", &tm1);
	checkStrptime("20:57:08", "%T", &tm1);

	/* Format */
	checkStrptime("20:57:08", "%H : %M  :  %S", &tm1);
	checkStrptime("20 57  08", "%H %M %S", &tm1);
	checkStrptime("20%57%08", "%H %% %M%%%S", &tm1);
	checkStrptime("foo20bar57qux08      ", "foo %Hbar %M qux%S ", &tm1);

	/* Date */
	checkStrptime("1991-08-25", "%Y-%m-%d", &tm2);
	checkStrptime("25.08.91", "%d.%m.%y", &tm2);
	checkStrptime("08/25/91", "%D", &tm2);
	checkStrptime("21.10.15", "%d.%m.%y", &tm3);
	checkStrptime("10.7.56 in 18th", "%d.%m.%y in %C th", &tm4);

	/* Glibc */
	checkStrptime("1856-07-10", "%F", &tm4);
	checkStrptime("683078400", "%s", &tm2);
	checkStrptimeTz("+0200", 2, 0);
	checkStrptimeTz("-0530", -5, -30);
	checkStrptimeTz("-06", -6, 0);

	return t_status;
}
