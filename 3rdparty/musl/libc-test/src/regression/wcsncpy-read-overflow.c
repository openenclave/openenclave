// commit: e98136207ad1a6df1cdc1578e4ad56f8f0db4047 2011-05-22
#include <wchar.h>
#include "test.h"

int main(void)
{
	wchar_t dst[] = { 'a', 'a' };
	wchar_t src[] = { 0, 'b' };

	wcsncpy(dst, src, 1);
	if(dst[1] != 'a')
		t_error("wcsncpy copied more than N\n");
	return t_status;
}
