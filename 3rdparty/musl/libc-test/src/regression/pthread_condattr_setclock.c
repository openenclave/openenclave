// commit: 9d5251f72b627974bcf438501e07ad42c24d94be 2011-03-08
// disallow cpu time clocks in condattr
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include "test.h"

#define T(r,f) if ((r=(f))) t_error(#f " failed: %s\n", strerror(r))

int main(void)
{
	pthread_cond_t c;
	pthread_condattr_t a;
	pthread_mutex_t m;
	clockid_t clk;
	struct timespec ts;
	void *p;
	int r;

	T(r,pthread_condattr_init(&a));
	r = pthread_condattr_setclock(&a, CLOCK_PROCESS_CPUTIME_ID);
	if (r != EINVAL)
		t_error("pthread_condattr_setclock CLOCK_PROCESS_CPUTIME_ID should fail with EINVAL, got %s\n", strerror(r));
	r = pthread_condattr_setclock(&a, CLOCK_THREAD_CPUTIME_ID);
	if (r != EINVAL)
		t_error("pthread_condattr_setclock CLOCK_THREAD_CPUTIME_ID should fail with EINVAL, got %s\n", strerror(r));
	T(r,pthread_condattr_getclock(&a, &clk));
	if (clk != CLOCK_REALTIME)
		t_error("condattr default clock is %d, wanted CLOCK_REALTIME (%d)\n", (int)clk, (int)CLOCK_REALTIME);

	T(r,pthread_cond_init(&c, &a));
	T(r,pthread_mutex_init(&m, 0));
	T(r,pthread_mutex_lock(&m));
	r = clock_gettime(CLOCK_REALTIME, &ts);
	if (r)
		t_error("clock_gettime failed: %s\n", strerror(errno));
	/* wait 10ms */
	ts.tv_nsec += 10*1000*1000;
	if (ts.tv_nsec >= 1000*1000*1000) {
		ts.tv_nsec -= 1000*1000*1000;
		ts.tv_sec += 1;
	}
	r = pthread_cond_timedwait(&c, &m, &ts);
	if (r != ETIMEDOUT)
		t_error("pthread_cond_timedwait did not timeout, returned %s\n", strerror(r));
	T(r,pthread_mutex_unlock(&m));

	T(r,pthread_mutex_destroy(&m));
	T(r,pthread_cond_destroy(&c));
	T(r,pthread_condattr_destroy(&a));
	return t_status;
}
