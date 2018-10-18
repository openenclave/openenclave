#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "test.h"

static char buffer[100];

static void checkStrftime(const char* format, const struct tm* tm,
		const char* expected) {
	size_t resultLength = strftime(buffer, sizeof(buffer), format, tm);

	if (resultLength != 0 && strcmp(buffer, expected) != 0) {
		t_error("\"%s\": expected \"%s\", got \"%s\"\n", format, expected, buffer);
	} else if (resultLength == 0 && strlen(expected) != 0) {
		t_error("\"%s\": expected \"%s\", got nothing\n", format, expected);
	}
}

static struct tm tm1 = {
	.tm_sec = 45,
	.tm_min = 23,
	.tm_hour = 13,
	.tm_mday = 3,
	.tm_mon = 0,
	.tm_year = 2016 - 1900,
	.tm_wday = 0,
	.tm_yday = 2,
	.tm_isdst = 0
};

static struct tm tm2 = {
	.tm_sec = 53,
	.tm_min = 17,
	.tm_hour = 5,
	.tm_mday = 5,
	.tm_mon = 0,
	.tm_year = 10009 - 1900,
	.tm_wday = 1,
	.tm_yday = 4,
	.tm_isdst = 0
};

static struct tm tm3 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 12,
	.tm_mday = 23,
	.tm_mon = 1,
	.tm_year = 0 - 1900,
	.tm_wday = 3,
	.tm_yday = 53,
	.tm_isdst = 0
};

static struct tm tm4 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 0,
	.tm_mday = 1,
	.tm_mon = 0,
	.tm_year = -123 - 1900,
	.tm_wday = 1,
	.tm_yday = 0,
	.tm_isdst = 0
};

static struct tm tm5 = {
	.tm_sec = 0,
	.tm_min = 0,
	.tm_hour = 0,
	.tm_mday = 1,
	.tm_mon = 0,
	.tm_year = INT_MAX,
	.tm_wday = 3,
	.tm_yday = 0,
	.tm_isdst = 0
};

int main() {
	setenv("TZ", "UTC0", 1);

	checkStrftime("%c", &tm1, "Sun Jan  3 13:23:45 2016");
	checkStrftime("%c", &tm2, "Mon Jan  5 05:17:53 +10009");
	checkStrftime("%c", &tm3, "Wed Feb 23 12:00:00 0000");

	// The POSIX.1-2008 standard does not specify the padding character for
	// "%C". The C standard requires that the number is padded by '0'.
	// See also http://austingroupbugs.net/view.php?id=1184
	checkStrftime("%C", &tm1, "20");
	checkStrftime("%03C", &tm1, "020");
	checkStrftime("%+3C", &tm1, "+20");
	checkStrftime("%C", &tm2, "100");
	checkStrftime("%C", &tm3, "00");
	checkStrftime("%01C", &tm3, "0");

	checkStrftime("%F", &tm1, "2016-01-03");
	checkStrftime("%012F", &tm1, "002016-01-03");
	checkStrftime("%+10F", &tm1, "2016-01-03");
	checkStrftime("%+11F", &tm1, "+2016-01-03");
	checkStrftime("%F", &tm2, "+10009-01-05");
	checkStrftime("%011F", &tm2, "10009-01-05");
	checkStrftime("%F", &tm3, "0000-02-23");
	checkStrftime("%01F", &tm3, "0-02-23");
	checkStrftime("%06F", &tm3, "0-02-23");
	checkStrftime("%010F", &tm3, "0000-02-23");
	checkStrftime("%F", &tm4, "-123-01-01");
	checkStrftime("%011F", &tm4, "-0123-01-01");

	checkStrftime("%g", &tm1, "15");
	checkStrftime("%g", &tm2, "09");

	checkStrftime("%G", &tm1, "2015");
	checkStrftime("%+5G", &tm1, "+2015");
	checkStrftime("%04G", &tm2, "10009");

	checkStrftime("%r", &tm1, "01:23:45 PM");
	checkStrftime("%r", &tm2, "05:17:53 AM");
	checkStrftime("%r", &tm3, "12:00:00 PM");
	checkStrftime("%r", &tm4, "12:00:00 AM");

	// The "%s" specifier was accepted by the Austin Group for the next POSIX.1
	// revision. See http://austingroupbugs.net/view.php?id=169
	checkStrftime("%s", &tm1, "1451827425");
	if (sizeof(time_t) * CHAR_BIT >= 64) {
		checkStrftime("%s", &tm2, "253686748673");
	}

	checkStrftime("%T", &tm1, "13:23:45");
	checkStrftime("%T", &tm2, "05:17:53");
	checkStrftime("%T", &tm3, "12:00:00");
	checkStrftime("%T", &tm4, "00:00:00");

	checkStrftime("%U", &tm1, "01");
	checkStrftime("%U", &tm2, "01");
	checkStrftime("%U", &tm3, "08");

	checkStrftime("%V", &tm1, "53");
	checkStrftime("%V", &tm2, "02");
	checkStrftime("%V", &tm3, "08");

	checkStrftime("%W", &tm1, "00");
	checkStrftime("%W", &tm2, "01");
	checkStrftime("%W", &tm3, "08");

	checkStrftime("%x", &tm1, "01/03/16");
	checkStrftime("%X", &tm1, "13:23:45");
	checkStrftime("%y", &tm1, "16");

	// There is no standard that explicitly specifies the exact format of "%Y".
	// The C standard says that "%F" is equivalent to "%Y-%m-%d". The
	// POSIX.1-2008 standard says that "%F" is equivalent to "%+4Y-%m-%d".
	// This implies that to conform to both standards "%Y" needs to be
	// equivalent to "%+4Y".
	// See also http://austingroupbugs.net/view.php?id=739
	checkStrftime("%Y", &tm1, "2016");
	checkStrftime("%05Y", &tm1, "02016");
	checkStrftime("%+4Y", &tm1, "2016");
	checkStrftime("%+5Y", &tm1, "+2016");
	checkStrftime("%Y", &tm2, "+10009");
	checkStrftime("%05Y", &tm2, "10009");
	checkStrftime("%Y", &tm3, "0000");
	checkStrftime("%02Y", &tm3, "00");
	checkStrftime("%+5Y", &tm3, "+0000");
	checkStrftime("%Y", &tm4, "-123");
	checkStrftime("%+4Y", &tm4, "-123");
	checkStrftime("%+5Y", &tm4, "-0123");

	if (INT_MAX == 0x7FFFFFFF) {
		// The standard does not specify any range for tm_year, so INT_MAX
		// should be valid.
		checkStrftime("%y", &tm5, "47");
		checkStrftime("%Y", &tm5, "+2147485547");
		checkStrftime("%011Y", &tm5, "02147485547");
		if (sizeof(time_t) * CHAR_BIT >= 64) {
			checkStrftime("%s", &tm5, "67768036160140800");
		}
	}

	return t_status;
}
