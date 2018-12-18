#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "test.h"

#define TEST(c, ...) ((c) ? 1 : (t_error(#c" failed: " __VA_ARGS__),0))

static void handler_errno(void)
{
	errno = 0;
}

int main(void)
{
	t_setrlim(RLIMIT_NPROC, 0);
	pthread_atfork(handler_errno, handler_errno, handler_errno);

	pid_t pid;
	if (!TEST((pid = fork()) == -1, "fork succeeded despite rlimit\n")) {
		if (!pid) _exit(0);
		while (waitpid(pid, NULL, 0)<0 && errno==EINTR);
	} else {
		TEST(errno != 0, "fork failed but errno was clobbered\n");
	}

	return t_status;
}

