#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include "test.h"

static void handler(int s)
{
}

static int start(char *wrap, char *argv[])
{
	int pid;

	pid = fork();
	if (pid == 0) {
		t_setrlim(RLIMIT_STACK, 100*1024);
		if (*wrap) {
			argv--;
			argv[0] = wrap;
		}
		execv(argv[0], argv);
		t_error("%s exec failed: %s\n", argv[0], strerror(errno));
		exit(1);
	}
	return pid;
}

static void usage(char *argv[])
{
	t_error("usage: %s [-t timeoutsec] [-w wrapcmd] cmd [args..]\n", argv[0]);
	exit(-1);
}

int main(int argc, char *argv[])
{
	char *wrap = "";
	int timeoutsec = 5;
	int timeout = 0;
	int status;
	sigset_t set;
	int opt;
	int pid;

	while ((opt = getopt(argc, argv, "w:t:")) != -1) {
		switch (opt) {
		case 'w':
			wrap = optarg;
			break;
		case 't':
			timeoutsec = atoi(optarg);
			break;
		default:
			usage(argv);
		}
	}
	if (optind >= argc)
		usage(argv);
	argv += optind;
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, 0);
	signal(SIGCHLD, handler);
	pid = start(wrap, argv);
	if (pid == -1) {
		t_error("%s fork failed: %s\n", argv[0], strerror(errno));
		t_printf("FAIL %s [internal]\n", argv[0]);
		return -1;
	}
	if (sigtimedwait(&set, 0, &(struct timespec){timeoutsec,0}) == -1) {
		if (errno == EAGAIN)
			timeout = 1;
		else
			t_error("%s sigtimedwait failed: %s\n", argv[0], strerror(errno));
		if (kill(pid, SIGKILL) == -1)
			t_error("%s kill failed: %s\n", argv[0], strerror(errno));
	}
	if (waitpid(pid, &status, 0) != pid) {
		t_error("%s waitpid failed: %s\n", argv[0], strerror(errno));
		t_printf("FAIL %s [internal]\n", argv[0]);
		return -1;
	}
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0)
			return t_status;
		t_printf("FAIL %s [status %d]\n", argv[0], WEXITSTATUS(status));
	} else if (timeout) {
		t_printf("FAIL %s [timed out]\n", argv[0]);
	} else if (WIFSIGNALED(status)) {
		t_printf("FAIL %s [signal %s]\n", argv[0], strsignal(WTERMSIG(status)));
	} else
		t_printf("FAIL %s [unknown]\n", argv[0]);
	return 1;
}
