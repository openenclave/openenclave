// commit: 370f78f2c80c64b7b0780a01e672494a26b5678e 2011-03-09
// commit: 0bed7e0acfd34e3fb63ca0e4d99b7592571355a9 2011-03-09
// raise should be robust against async fork in a signal handler
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "test.h"

static volatile int c0;
static volatile int c1;
static volatile int child;

static void handler0(int sig)
{
	c0++;
}

static void handler1(int sig)
{
	c1++;
	switch (fork()) {
	case 0: child=1; break;
	case -1: t_error("fork failed: %s\n", strerror(errno));
	}
}

static void *start(void *arg)
{
	int i,r,s;

	for (i = 0; i < 1000; i++) {
		r = raise(SIGRTMIN);
		if (r)
			t_error("raise failed: %s\n", strerror(errno));
	}
	if (c0 != 1000)
		t_error("lost signals: got %d, wanted 1000 (ischild %d forks %d)\n", c0, child, c1);
	if (child)
		_exit(t_status);

	/* make sure we got all pthread_kills, then wait the forked children */
	while (c1 < 100);
	for (i = 0; i < 100; i++) {
		r = wait(&s);
		if (r == -1)
			t_error("wait failed: %s\n", strerror(errno));
		else if (!WIFEXITED(s) || WTERMSIG(s))
			t_error("child failed: pid:%d status:%d\n", r, s);
	}
	return 0;
}

int main(void)
{
	pthread_t t;
	void *p;
	int r, i, s;

	if (signal(SIGRTMIN, handler0) == SIG_ERR)
		t_error("registering signal handler failed: %s\n", strerror(errno));
	if (signal(SIGRTMIN+1, handler1) == SIG_ERR)
		t_error("registering signal handler failed: %s\n", strerror(errno));

	r = pthread_create(&t, 0, start, 0);
	if (r)
		t_error("pthread_create failed: %s\n", strerror(r));
	for (i = 0; i < 100; i++) {
		r = pthread_kill(t, SIGRTMIN+1);
		if (r)
			t_error("phread_kill failed: %s\n", strerror(r));
	}
	r = pthread_join(t,&p);
	if (r)
		t_error("pthread_join failed: %s\n", strerror(r));
	return t_status;
}
