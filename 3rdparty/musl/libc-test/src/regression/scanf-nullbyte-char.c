// commit: ef5507867b59d19f21437970e87b5d0415c07b2e 2013-06-22
// scanf should not append null byte after scanning %c
#include <stdio.h>
#include "test.h"

int main(void)
{
	char dst[] = { 'a', 'a' }; 
	char src[] = { 'b', 'b' };

	if (sscanf(src, "%c", dst) != 1)
		t_error("sscanf %%c failed\n");
	if (dst[1] != 'a')
		t_error("scanf clobbered the char buffer for %%c conversion\n");
	return t_status;
}
