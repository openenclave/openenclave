/* testing pthread mutex behaviour with various attributes */
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define T(f) if ((r=(f))) t_error(#f " failed: %s\n", strerror(r))
#define E(f) if (f) t_error(#f " failed: %s\n", strerror(errno))

static void *relock(void *arg)
{
	void **a = arg;
	int r;

	T(pthread_mutex_lock(a[0]));
	E(sem_post(a[1]));
	*(int*)a[2] = pthread_mutex_lock(a[0]);
	E(sem_post(a[1]));

	T(pthread_mutex_unlock(a[0]));
	if (*(int*)a[2] == 0)
		T(pthread_mutex_unlock(a[0]));
	return 0;
}

static int test_relock(int mtype)
{
	struct timespec ts;
	pthread_t t;
	pthread_mutex_t m;
	pthread_mutexattr_t ma;
	sem_t s;
	int i;
	int r;
	void *p;
	void *a[] = {&m,&s,&i};

	T(pthread_mutexattr_init(&ma));
	T(pthread_mutexattr_settype(&ma, mtype));
	T(pthread_mutex_init(a[0], &ma));
	T(pthread_mutexattr_destroy(&ma));
	E(sem_init(a[1], 0, 0));
	T(pthread_create(&t, 0, relock, a));
	E(sem_wait(a[1]));
	E(clock_gettime(CLOCK_REALTIME, &ts));
	ts.tv_nsec += 100*1000*1000;
	if (ts.tv_nsec >= 1000*1000*1000) {
		ts.tv_nsec -= 1000*1000*1000;
		ts.tv_sec += 1;
	}
	r = sem_timedwait(a[1],&ts);
	if (r == -1) {
		if (errno != ETIMEDOUT)
			t_error("sem_timedwait failed with unexpected error: %s\n", strerror(errno));
		/* leave the deadlocked relock thread running */
		return -1;
	}
	T(pthread_join(t, &p));
	T(pthread_mutex_destroy(a[0]));
	E(sem_destroy(a[1]));
	return i;
}

static void *unlock(void *arg)
{
	void **a = arg;

	*(int*)a[1] = pthread_mutex_unlock(a[0]);
	return 0;
}

static int test_unlock(int mtype)
{
	pthread_t t;
	pthread_mutex_t m;
	pthread_mutexattr_t ma;
	int i;
	int r;
	void *p;
	void *a[] = {&m,&i};

	T(pthread_mutexattr_init(&ma));
	T(pthread_mutexattr_settype(&ma, mtype));
	T(pthread_mutex_init(a[0], &ma));
	T(pthread_mutexattr_destroy(&ma));
	T(pthread_create(&t, 0, unlock, a));
	T(pthread_join(t, &p));
	T(pthread_mutex_destroy(a[0]));
	return i;
}

static int test_unlock_other(int mtype)
{
	pthread_t t;
	pthread_mutex_t m;
	pthread_mutexattr_t ma;
	int i;
	int r;
	void *p;
	void *a[] = {&m,&i};

	T(pthread_mutexattr_init(&ma));
	T(pthread_mutexattr_settype(&ma, mtype));
	T(pthread_mutex_init(a[0], &ma));
	T(pthread_mutexattr_destroy(&ma));
	T(pthread_mutex_lock(a[0]));
	T(pthread_create(&t, 0, unlock, a));
	T(pthread_join(t, &p));
	T(pthread_mutex_unlock(a[0]));
	T(pthread_mutex_destroy(a[0]));
	return i;
}

static void test_mutexattr()
{
	pthread_mutex_t m;
	pthread_mutexattr_t a;
	int r;
	int i;

	T(pthread_mutexattr_init(&a));
	T(pthread_mutexattr_gettype(&a, &i));
	if (i != PTHREAD_MUTEX_DEFAULT)
		t_error("default mutex type is %d, wanted PTHREAD_MUTEX_DEFAULT (%d)\n", i, PTHREAD_MUTEX_DEFAULT);
	T(pthread_mutexattr_settype(&a, PTHREAD_MUTEX_ERRORCHECK));
	T(pthread_mutexattr_gettype(&a, &i));
	if (i != PTHREAD_MUTEX_ERRORCHECK)
		t_error("setting error check mutex type failed failed: got %d, wanted %d\n", i, PTHREAD_MUTEX_ERRORCHECK);
	T(pthread_mutexattr_destroy(&a));
}

int main(void)
{
	int i;

	test_mutexattr();

	i = test_relock(PTHREAD_MUTEX_NORMAL);
	if (i != -1)
		t_error("PTHREAD_MUTEX_NORMAL relock did not deadlock, got %s\n", strerror(i));
	i = test_relock(PTHREAD_MUTEX_ERRORCHECK);
	if (i != EDEADLK)
		t_error("PTHREAD_MUTEX_ERRORCHECK relock did not return EDEADLK, got %s\n", i==-1?"deadlock":strerror(i));
	i = test_relock(PTHREAD_MUTEX_RECURSIVE);
	if (i != 0)
		t_error("PTHREAD_MUTEX_RECURSIVE relock did not succed, got %s\n", i==-1?"deadlock":strerror(i));

	i = test_unlock(PTHREAD_MUTEX_ERRORCHECK);
	if (i != EPERM)
		t_error("PTHREAD_MUTEX_ERRORCHECK unlock did not return EPERM, got %s\n", strerror(i));
	i = test_unlock(PTHREAD_MUTEX_RECURSIVE);
	if (i != EPERM)
		t_error("PTHREAD_MUTEX_RECURSIVE unlock did not return EPERM, got %s\n", strerror(i));

	i = test_unlock_other(PTHREAD_MUTEX_ERRORCHECK);
	if (i != EPERM)
		t_error("PTHREAD_MUTEX_ERRORCHECK unlock did not return EPERM, got %s\n", strerror(i));
	i = test_unlock_other(PTHREAD_MUTEX_RECURSIVE);
	if (i != EPERM)
		t_error("PTHREAD_MUTEX_RECURSIVE unlock did not return EPERM, got %s\n", strerror(i));

	return t_status;
}
