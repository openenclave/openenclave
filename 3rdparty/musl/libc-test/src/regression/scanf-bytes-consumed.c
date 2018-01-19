// commit: 5efc6af4ebb9d50eb978d0338835544fdfea0396 2011-04-25
// scanf misreports bytes consumed when EOF is hit (or null for sscanf)
#include <stdio.h>
#include "test.h"

int main(void)
{
	char buf[] = { 'a', 'a', 0 };
	char dest[3];
	int read_count;
	int n;

	n = sscanf(buf, "%s%n", dest, &read_count);
	if(n != 1)
		t_error("sscanf matched 1 input items but returned %d\n", n);
	if(read_count != 2)
		t_error("sscanf consumed 2 bytes but reported %d\n", read_count);
	return t_status;
}
