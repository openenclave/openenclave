// sem_wait and sem_timedwait are cancellation points
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include "test.h"

#define TESTC(c, m) ( (c) || (t_error("%s failed (" m ")\n", #c), 0) )
#define TESTR(r, f, m) ( \
	((r) = (f)) == 0 || (t_error("%s failed: %s (" m ")\n", #f, strerror(r)), 0) )

static sem_t sem1, sem2;

static int seqno;

static void wait_cancel(void *arg)
{
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, 0);
	while (sem_wait(&sem1));
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0);
	seqno = 1;
}

static void *start_sem_wait(void *arg)
{
	wait_cancel(arg);
	sem_wait(&sem2);
	seqno = 2;
	return 0;
}

static void *start_sem_timedwait(void *arg)
{
	wait_cancel(arg);
	sem_timedwait(&sem2, &(struct timespec){1, 0});
	seqno = 2;
	return 0;
}

int main(void)
{
	pthread_t td;
	int r;
	void *res;

	TESTR(r, sem_init(&sem1, 0, 0), "creating semaphore");
	TESTR(r, sem_init(&sem2, 0, 1), "creating semaphore");

	/* Cancellation on uncontended sem_wait */
	seqno = 0;
	TESTR(r, pthread_create(&td, 0, start_sem_wait, 0), "failed to create thread");
	TESTR(r, pthread_cancel(td), "canceling");
	sem_post(&sem1);
	TESTR(r, pthread_join(td, &res), "joining canceled thread after uncontended sem_wait");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status after uncontended sem_wait");
	TESTC(seqno == 1, "uncontended sem_wait");

	/* Cancellation on blocking sem_wait */
	seqno = 0;
	sem_trywait(&sem2);
	TESTR(r, pthread_create(&td, 0, start_sem_wait, 0), "failed to create thread");
	TESTR(r, pthread_cancel(td), "canceling");
	sem_post(&sem1);
	TESTR(r, pthread_join(td, &res), "joining canceled thread after blocking sem_wait");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status after blocking sem_wait");
	TESTC(seqno == 1, "blocking sem_wait");

	/* Cancellation on uncontended sem_timedwait */
	seqno = 0;
	sem_post(&sem2);
	TESTR(r, pthread_create(&td, 0, start_sem_timedwait, 0), "failed to create thread");
	TESTR(r, pthread_cancel(td), "canceling");
	sem_post(&sem1);
	TESTR(r, pthread_join(td, &res), "joining canceled thread after uncontended sem_timedwait");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status after uncontended sem_timedwait");
	TESTC(seqno == 1, "uncontended sem_timedwait");

	/* Cancellation on blocking sem_timedwait */
	seqno = 0;
	sem_trywait(&sem2);
	TESTR(r, pthread_create(&td, 0, start_sem_timedwait, 0), "failed to create thread");
	TESTR(r, pthread_cancel(td), "canceling");
	sem_post(&sem1);
	TESTR(r, pthread_join(td, &res), "joining canceled thread after blocking sem_timedwait");
	TESTC(res == PTHREAD_CANCELED, "canceled thread exit status after blocking sem_timedwait");
	TESTC(seqno == 1, "blocking sem_timedwait");

	return t_status;
}
