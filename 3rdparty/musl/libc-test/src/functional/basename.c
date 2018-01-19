#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "test.h"

#define T(path, want) \
{ \
	char tmp[100]; \
	char *got = basename(strcpy(tmp, path)); \
	if (strcmp(want, got) != 0) \
		t_error("basename(\"%s\") got \"%s\" want \"%s\"\n", path, got, want); \
}

int main()
{
	if (strcmp(basename(0), ".") != 0)
		t_error("basename(0) returned \"%s\"; expected \".\"\n", basename(0));
	T("", ".");
	T("/usr/lib", "lib");
	T("/usr/", "usr");
	T("usr/", "usr");
	T("/", "/");
	T("///", "/");
	T("//usr//lib//", "lib");
	T(".", ".");
	T("..", "..");
	return t_status;
}
