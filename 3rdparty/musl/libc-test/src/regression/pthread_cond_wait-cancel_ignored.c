// commit 76ca7a5446a8aec2b671a401d5e1878c4704754e
// pthread_cond_wait should act on cancellation arriving after unlocking mutex

#include <pthread.h>
#include <errno.h>
#include <time.h>

#include "test.h"

static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int waiting;

static void cleanup(void *p)
{
	waiting = 0;
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mx);
}

static void *waiter(void *p)
{
	pthread_mutex_lock(&mx);
	waiting = 1;
	pthread_cond_signal(&cv);
	pthread_cleanup_push(cleanup, 0);
	while (waiting) pthread_cond_wait(&cv, &mx);
	pthread_cleanup_pop(1);
	return 0;
}

int main(void)
{
	pthread_t td;
	struct timespec ts;
	void *rv;
	pthread_mutex_lock(&mx);
	pthread_create(&td, 0, waiter, 0);
	while (!waiting) pthread_cond_wait(&cv, &mx);
	pthread_cancel(td);
	clock_gettime(CLOCK_REALTIME, &ts);
	if ((ts.tv_nsec+=30000000) >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}
	while (waiting && !pthread_cond_timedwait(&cv, &mx, &ts));
	waiting = 0;
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mx);
	pthread_join(td, &rv);
	if (rv != PTHREAD_CANCELED)
		t_error("pthread_cond_wait did not act on cancellation\n");
	return t_status;
}
