// testing cancellation points
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "test.h"

#define TESTC(c, m) ( (c) || (t_error(#c " failed (%s, " m ")\n", cdescr), 0) )
#define TESTR(f, m) do {int r; \
	if ((r = (f))) t_error(#f " failed: %s (%s, " m ")\n", strerror(r), cdescr); } while (0)
#define TESTE(f, m) do { \
	if ((f)==-1) t_error(#f " failed: %s (%s, " m ")\n", strerror(errno), cdescr); } while (0)

static sem_t sem_seq, sem_test;

static int seqno;

static const char *cdescr = "global initialization";

static void prepare_sem(void *arg)
{
	TESTR(sem_init(&sem_test, 0, (long)arg), "creating semaphore");
}

static void cleanup_sem(void *arg)
{
	TESTR(sem_destroy(&sem_test), "destroying semaphore");
}

static void execute_sem_wait(void *arg)
{
	TESTR(sem_wait(&sem_test), "waiting on semaphore in the canceled thread");
}

static void execute_sem_timedwait(void *arg)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 1;
	TESTR(sem_timedwait(&sem_test, &ts), "timed-waiting on semaphore in the canceled thread");
}

static pthread_t td_test;

static void *run_test(void *arg)
{
	while (sem_wait(&sem_test));
	return 0;
}

static void prepare_thread(void *arg)
{
	prepare_sem(arg);
	TESTR(pthread_create(&td_test, 0, run_test, 0), "creating auxiliary thread");
}

static void cleanup_thread(void *arg)
{
	void *res;
	if (td_test) {
		TESTR(sem_post(&sem_test), "posting semaphore");
		TESTR(pthread_join(td_test, &res), "joining auxiliary thread");
		TESTC(res == 0, "auxiliary thread exit status");
	}
	cleanup_sem(arg);
}

static void execute_thread_join(void *arg)
{
	TESTR(pthread_join(td_test, 0), "joining in the canceled thread");
	td_test = 0;
}

static void prepare_dummy(void *arg)
{
}

static void execute_shm_open(void *arg)
{
	int *fd = arg;
	TESTE(*fd = shm_open("/testshm", O_RDWR|O_CREAT, 0666), "");
}

static void cleanup_shm(void *arg)
{
	int *fd = arg;
	if (*fd > 0) {
		TESTE(close(*fd), "shm fd");
		TESTE(shm_unlink("/testshm"), "");
	}
}

static struct {
	int want_cancel;
	void (*prepare)(void *);
	void (*execute)(void *);
	void (*cleanup)(void *);
	void *arg;
	const char *descr;
} scenarios[] = {
	{1, prepare_sem, execute_sem_wait, cleanup_sem, 0, "blocking sem_wait"},
	{1, prepare_sem, execute_sem_wait, cleanup_sem, (void*)1, "non-blocking sem_wait"},
	{1, prepare_sem, execute_sem_timedwait, cleanup_sem, 0, "blocking sem_timedwait"},
	{1, prepare_sem, execute_sem_timedwait, cleanup_sem, (void*)1, "non-blocking sem_timedwait"},
	{1, prepare_thread, execute_thread_join, cleanup_thread, 0, "blocking pthread_join"},
	{1, prepare_thread, execute_thread_join, cleanup_thread, (void*)1, "non-blocking pthread_join"},
	{0, prepare_dummy, execute_shm_open, cleanup_shm, &(int){0}, "shm_open"},
	{ 0 }
}, *cur_sc = scenarios;

static void *run_execute(void *arg)
{
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, 0);
	while (sem_wait(&sem_seq));
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, 0);
	seqno = 1;
	cur_sc->execute(cur_sc->arg);
	seqno = 2;
	return 0;
}

int main(void)
{
	TESTR(sem_init(&sem_seq, 0, 0), "creating semaphore");

	for (; cur_sc->prepare; cur_sc++) {
		pthread_t td;
		void *res;

		cdescr = cur_sc->descr;
		cur_sc->prepare(cur_sc->arg);
		seqno = 0;
		TESTR(pthread_create(&td, 0, run_execute, 0), "creating thread to be canceled");
		TESTR(pthread_cancel(td), "canceling");
		TESTR(sem_post(&sem_seq), "unblocking canceled thread");
		TESTR(pthread_join(td, &res), "joining canceled thread");
		if (cur_sc->want_cancel) {
			TESTC(res == PTHREAD_CANCELED, "canceled thread exit status")
			&& TESTC(seqno == 1, "seqno");
		} else {
			TESTC(res != PTHREAD_CANCELED, "canceled thread exit status")
			&& TESTC(seqno == 2, "seqno");
		}
		cur_sc->cleanup(cur_sc->arg);
	}

	return t_status;
}
