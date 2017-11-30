// commit: fb11b6b85e1e01daf17228be32d7f98b47517363 2011-02-19
// pthread_exit should call dtors (even in the last thread)
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#include "test.h"

#define TEST(r, f) if (((r)=(f))) t_error(#f " failed: %s\n", strerror(r))
#define TESTC(c, m) ( (c) || (t_error("%s failed (" m ")\n", #c), 0) )

static pthread_key_t k;
static int data;

static void dtor(void *p)
{
	*(int *)p = 1;
}

static void *start(void *arg)
{
	if (pthread_setspecific(k, arg))
		return arg;
	return 0;
}

static void cleanup(void)
{
	TESTC(data == 1, "dtor was not run for the last thread");
	_exit(t_status);
}

static void die(void)
{
	_exit(1);
}

int main(void)
{
	pthread_t td;
	int r, arg=0, pid;
	void *res;

	// test if atexit handlers are run after pthread_exit
	// (early musl failed this test)
	pid = fork();
	switch (pid) {
	case -1:
		t_error("fork failed: %s\n", strerror(errno));
		return 1;
	case 0:
		atexit(die);
		pthread_exit(0);
	default:
		if (waitpid(pid, &r, 0) != pid) {
			t_error("waitpid failed: %s\n", strerror(errno));
			return 1;
		}
		if (!WIFEXITED(r) || WEXITSTATUS(r) != 1) {
			t_error("atexit handler was not run after last thread exited"
				" (exited=%d, signal=%d, status=%d, want exit status=1)\n",
				WIFEXITED(r), !WIFEXITED(r)&&WIFSIGNALED(r)?WTERMSIG(r):0, WIFEXITED(r)?WEXITSTATUS(r):0);
			return 1;
		}
	}

	// dtor should set tsd (arg and data) from 0 to 1
	if (atexit(cleanup)) {
		t_error("atexit failed\n");
		return 1;
	}
	TEST(r, pthread_key_create(&k, dtor));
	TEST(r, pthread_setspecific(k, &data));
	TEST(r, pthread_create(&td, 0, start, &arg));
	TEST(r, pthread_join(td, &res));
	TESTC(res == 0, "pthread_setspecific failed in thread");
	TESTC(arg == 1, "dtor failed to run");
	TESTC(data == 0, "tsd in main thread is corrupted");
	TESTC(pthread_getspecific(k) == &data, "tsd in main thread is corrupted");
	pthread_exit(0);
}
