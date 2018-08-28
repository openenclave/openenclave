// commit: a6238c30d169cbac6bc4c4977622242063e32270 2011-02-22
// rewind should clear error
#include <stdio.h>
#include <unistd.h>
#include "test.h"

int main(void)
{
	char buf[1];
	size_t n;
	int fd;

	// make sure fread fails
	fd = dup(0);
	close(0);

	n = fread(buf, 1, sizeof buf, stdin);
	if (n != 0 || !ferror(stdin))
		t_error("fread(stdin) should have failed, got %d ferror %d feof %d\n",
			n, ferror(stdin), feof(stdin));
	if (dup(fd) != 0)
		t_error("dup failed\n");

	rewind(stdin);
	if (ferror(stdin))
		t_error("rewind failed to clear ferror\n");
	return t_status;
}
