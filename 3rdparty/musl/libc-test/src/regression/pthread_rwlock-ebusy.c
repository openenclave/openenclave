// commit: e5dd18319bbd47c89aac5e1571771958a43e067d 2011-03-08
// pthread_rwlock_try* should fail with EBUSY
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include "test.h"

#define T(f) if ((r=(f))) t_error(#f " failed: %s\n", strerror(r))

static void *tryrdlock(void *arg)
{
	int r = pthread_rwlock_tryrdlock(arg);
	if (r != EBUSY)
		t_error("tryrdlock for wrlocked lock returned %s, want EBUSY\n", strerror(r));
	return 0;
}

static void *trywrlock(void *arg)
{
	int r = pthread_rwlock_trywrlock(arg);
	if (r != EBUSY)
		t_error("trywrlock for rdlocked lock returned %s, want EBUSY\n", strerror(r));
	return 0;
}

int main(void)
{
	pthread_t t;
	pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
	void *p;
	int r;

	T(pthread_rwlock_rdlock(&rw));
	T(pthread_create(&t, 0, trywrlock, &rw));
	T(pthread_join(t, &p));
	T(pthread_rwlock_unlock(&rw));

	T(pthread_rwlock_wrlock(&rw));
	T(pthread_create(&t, 0, tryrdlock, &rw));
	T(pthread_join(t, &p));
	T(pthread_rwlock_unlock(&rw));

	return t_status;
}
