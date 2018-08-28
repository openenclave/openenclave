#include "pthread_impl.h"

int pthread_kill(pthread_t t, int sig)
{
	int r;
	LOCK(t->killlock);
	r = t->dead ? ESRCH : -__syscall(SYS_tkill, t->tid, sig);
	UNLOCK(t->killlock);
	return r;
}
