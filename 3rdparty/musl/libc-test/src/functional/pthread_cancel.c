#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include "test.h"

#define TESTC(c, m) ( (c) || (t_error("%s failed (" m ")\n", #c), 0) )
#define TESTR(r, f, m) ( \
	((r) = (f)) == 0 || (t_error("%s failed: %s (" m ")\n", #f, strerror(r)), 0) )

static void *start_async(void *arg)
{
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	sem_post(arg);
	for (;;);
	return 0;
}

static void cleanup1(void *arg)
{
	*(int *)arg = 1;
}

static void cleanup2(void *arg)
{
	*(int *)arg += 2;
}

static void cleanup3(void *arg)
{
	*(int *)arg += 3;
}

static void cleanup4(void *arg)
{
	*(int *)arg += 4;
}

static void *start_single(void *arg)
{
	pthread_cleanup_push(cleanup1, arg);
	sleep(3);
	pthread_cleanup_pop(0);
	return 0;
}

static void *start_nested(void *arg)
{
	int *foo = arg;
	pthread_cleanup_push(cleanup1, foo);
	pthread_cleanup_push(cleanup2, foo+1);
	pthread_cleanup_push(cleanup3, foo+2);
	pthread_cleanup_push(cleanup4, foo+3);
	sleep(3);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);
	pthread_cleanup_pop(0);
	return 0;
}

int main(void)
{
	pthread_t td;
	sem_t sem1;
	int r;
	void *res;
	int foo[4];

	TESTR(r, sem_init(&sem1, 0, 0), "creating semaphore");

	/* Asynchronous cancellation */
	TESTR(r, pthread_create(&td, 0, start_async, &sem1), "failed to create thread");
	while (sem_wait(&sem1));
	TESTR(r, pthread_cancel(td), "canceling");
	TESTR(r, pthread_join(td, &res), "joining canceled thread");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status");

	/* Cancellation cleanup handlers */
	foo[0] = 0;
	TESTR(r, pthread_create(&td, 0, start_single, foo), "failed to create thread");
	TESTR(r, pthread_cancel(td), "cancelling");
	TESTR(r, pthread_join(td, &res), "joining canceled thread");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status");
	TESTC(foo[0] == 1, "cleanup handler failed to run");

	/* Nested cleanup handlers */
	memset(foo, 0, sizeof foo);
	TESTR(r, pthread_create(&td, 0, start_nested, foo), "failed to create thread");
	TESTR(r, pthread_cancel(td), "cancelling");
	TESTR(r, pthread_join(td, &res), "joining canceled thread");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status");
	TESTC(foo[0] == 1, "cleanup handler failed to run");
	TESTC(foo[1] == 2, "cleanup handler failed to run");
	TESTC(foo[2] == 3, "cleanup handler failed to run");
	TESTC(foo[3] == 4, "cleanup handler failed to run");

	return t_status;
}
