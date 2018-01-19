#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "test.h"

void t_fdfill(void)
{
	int fd = 1;
	if (dup(fd) == -1) {
		if (errno == EMFILE)
			return;
		fd = open("/dev/null", O_RDONLY);
	}
	while(dup(fd) != -1);
}
