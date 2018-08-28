// commit: 7e6be42a77989c01155bdc7333ea58206e1563d4 2011-03-08
// pthread_once should not deadlock
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define T(f) if ((r=(f))) t_error(#f " failed: %s\n", strerror(r))
#define E(f) if (f) t_error(#f " failed: %s\n", strerror(errno))

static int count;

static void init(void)
{
	count++;
}

static void *start(void *arg)
{
	void **a = arg;
	int r;
	E(sem_post(a[1]));
	T(pthread_once(a[0], init));
	E(sem_post(a[1]));
	return 0;
}

static int deadlocked(sem_t *s)
{
	struct timespec ts;

	E(sem_wait(s));
	E(clock_gettime(CLOCK_REALTIME, &ts));
	ts.tv_nsec += 100*1000*1000;
	if (ts.tv_nsec >= 1000*1000*1000) {
		ts.tv_nsec -= 1000*1000*1000;
		ts.tv_sec += 1;
	}
	errno = 0;
	E(sem_timedwait(s,&ts));
	if (errno != ETIMEDOUT)
		return 0;
	t_error("pthread_once deadlocked\n");
	return 1;
}

int main(void)
{
	pthread_t t1,t2,t3;
	pthread_once_t once = PTHREAD_ONCE_INIT;
	sem_t s1,s2,s3;
	void *p;
	int r;

	E(sem_init(&s1,0,0));
	E(sem_init(&s2,0,0));
	E(sem_init(&s3,0,0));
	T(pthread_create(&t1, 0, start, (void*[]){&once,&s1}));
	T(pthread_create(&t2, 0, start, (void*[]){&once,&s2}));
	T(pthread_create(&t3, 0, start, (void*[]){&once,&s3}));
	if (!deadlocked(&s1)) T(pthread_join(t1,&p));
	if (!deadlocked(&s2)) T(pthread_join(t2,&p));
	if (!deadlocked(&s3)) T(pthread_join(t3,&p));
	if (count != 1)
		t_error("pthread_once ran init %d times instead of once\n", count);
	E(sem_destroy(&s1));
	E(sem_destroy(&s2));
	E(sem_destroy(&s3));
	return t_status;
}
