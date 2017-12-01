// leading zero handling according to the manual
#define _GNU_SOURCE
#include <string.h>
#include "test.h"

#define ASSERT(x) ((x) || (t_error(#x " failed\n"),0))

int main()
{
	ASSERT(strverscmp("", "") == 0);
	ASSERT(strverscmp("a", "a") == 0);
	ASSERT(strverscmp("a", "b") < 0);
	ASSERT(strverscmp("b", "a") > 0);
	ASSERT(strverscmp("000", "00") < 0);
	ASSERT(strverscmp("00", "000") > 0);
	ASSERT(strverscmp("a0", "a") > 0);
	ASSERT(strverscmp("00", "01") < 0);
	ASSERT(strverscmp("01", "010") < 0);
	ASSERT(strverscmp("010", "09") < 0);
	ASSERT(strverscmp("09", "0") < 0);
	ASSERT(strverscmp("9", "10") < 0);
	ASSERT(strverscmp("0a", "0") > 0);
	ASSERT(strverscmp("foobar-1.1.2", "foobar-1.1.3") < 0);
	ASSERT(strverscmp("foobar-1.1.2", "foobar-1.01.3") > 0);
	return t_status;
}
