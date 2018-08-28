#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>
#include "test.h"

#define TEST(f, x) (void)( \
	(r = (f)) == (x) || \
	t_error("%s failed, got %d want %d\n", #f, r, x) )

#define TEST_E(f) (void)( \
	(errno = 0), (f) || \
	t_error("%s failed (errno = %d \"%s\")\n", #f, errno, strerror(errno)) )

int main(void)
{
	int r;
	char foo[10];
	int p[2];
	pid_t pid;
	int status;
	posix_spawn_file_actions_t fa;

	TEST_E(!pipe(p));
	TEST(posix_spawn_file_actions_init(&fa), 0);
	TEST(posix_spawn_file_actions_addclose(&fa, p[0]), 0);
	TEST(posix_spawn_file_actions_adddup2(&fa, p[1], 1), 0);
	TEST(posix_spawn_file_actions_addclose(&fa, p[1]), 0);
	TEST(posix_spawnp(&pid, "echo", &fa, 0, (char *[]){"echo","hello",0}, 0), 0);
	close(p[1]);
	TEST(waitpid(pid, &status, 0), pid);
	TEST(read(p[0], foo, sizeof foo), 6);
	close(p[0]);
	TEST(posix_spawn_file_actions_destroy(&fa), 0);
	return t_status;
}
