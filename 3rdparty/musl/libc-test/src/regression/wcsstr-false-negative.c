// commit 476cd1d96560aaf7f210319597556e7fbcd60469 2014-04-18
// wcsstr (strstr and memmem) failed to match repetitive needles in some cases
#include <wchar.h>
#include "test.h"

int main(int argc, char* argv[])
{
	wchar_t const *haystack = L"playing play play play always";
	wchar_t const *needle = L"play play play";
	wchar_t *p = wcsstr(haystack, needle);
	if (p != haystack+8)
		t_error("wcsstr(L\"%S\",L\"%S\") failed: got %p, want %p\n", haystack, needle, p, haystack+8);
	return t_status;
}
