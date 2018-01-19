// commit 211264e46a2f1bc382a84435e904d1548de672b0 2013-09-27
// mbsrtowcs should not write outside the ws array
#include <wchar.h>
#include "test.h"

int main(void)
{
	wchar_t ws[] = L"XXXXX";
	const char *src = "abcd";
	const char *want = src + 4;
	size_t r;

	r = mbsrtowcs(ws, &src, 4, 0);
	if (r != 4)
		t_error("mbsrtowcs(ws, &abcd, 4, 0) returned %zu, wanted 4\n", r);
	if (src != want)
		t_error("mbsrtowcs(ws, &abcd, 4, 0) set abcd to %p wanted %p\n", src, want);
	if (wcscmp(ws, L"abcdX") != 0)
		t_error("ws is L\"%ls\", wanted L\"abcdX\"\n", ws);

	return t_status;
}
