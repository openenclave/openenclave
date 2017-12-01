// commit 9543656cc32fda48fc463f332ee20e91eed2b768 2016-03-06
// __putenv could be confused into freeing storage that does not belong to the implementation
#define _XOPEN_SOURCE 700
#include <stdlib.h>
#include <string.h>

int main(void)
{
	setenv("A", "1", 1);
	setenv("A", "2", 1);
	char *c = strdup("A=3");
	putenv(c);
	setenv("A", "4", 1);
	free(c);
	return 0;
}
