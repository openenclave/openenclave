#include <locale.h>
#include <string.h>
#include <langinfo.h>
#include "test.h"

int t_setutf8()
{
	(void)(
	setlocale(LC_CTYPE, "C.UTF-8") ||
	setlocale(LC_CTYPE, "POSIX.UTF-8") ||
	setlocale(LC_CTYPE, "en_US.UTF-8") ||
	setlocale(LC_CTYPE, "en_GB.UTF-8") ||
	setlocale(LC_CTYPE, "en.UTF-8") ||
	setlocale(LC_CTYPE, "UTF-8") ||
	setlocale(LC_CTYPE, "") );
	
	if (strcmp(nl_langinfo(CODESET), "UTF-8"))
		return t_error("cannot set UTF-8 locale for test (codeset=%s)\n", nl_langinfo(CODESET));

	return 0;
}
