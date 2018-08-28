// commit: 1a9a2ff7b0daf99100db53440a0b18b2801566ca 2011-02-13
// pthread_exit should call cancelation handlers
#include <pthread.h>
#include <string.h>
#include "test.h"

#define TEST(r, f) if (((r)=(f))) t_error(#f " failed: %s\n", strerror(r))

static void cleanup(void *arg)
{
	*(int *)arg = 1;
}

static void *start(void *arg)
{
	pthread_cleanup_push(cleanup, arg);
	pthread_exit(0);
	pthread_cleanup_pop(0);
	return arg;
}

int main(void)
{
	pthread_t td;
	void *status;
	int arg = 0;
	int r;

	TEST(r, pthread_create(&td, 0, start, &arg));
	TEST(r, pthread_join(td, &status));
	if (status)
		t_error("expected 0 thread exit status, got 0x%lx\n", (long)status);
	if (arg != 1)
		t_error("cleanup handler failed to run\n");
	return t_status;
}
