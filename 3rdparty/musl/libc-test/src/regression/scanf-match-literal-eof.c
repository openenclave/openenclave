// commit: 5efc6af4ebb9d50eb978d0338835544fdfea0396 2011-04-25
// scanf misreports literal match as input failure when reading EOF (null for sscanf)
#include <stdio.h>
#include "test.h"

int main(void)
{
	char buf[] = { 0 };
	int match_count;

	match_count = sscanf(buf, "a");
	if(match_count != EOF)
		t_error("scanf reported match failure instead of input failure on literal EOF match\n");

	return t_status;
}
