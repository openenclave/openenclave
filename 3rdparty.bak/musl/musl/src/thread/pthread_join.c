#include "pthread_impl.h"
#include <sys/mman.h>

int __munmap(void *, size_t);
void __pthread_testcancel(void);
int __pthread_setcancelstate(int, int *);

int __pthread_join(pthread_t t, void **res)
{
	int tmp, cs;
	__pthread_testcancel();
	__pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	if (cs == PTHREAD_CANCEL_ENABLE) __pthread_setcancelstate(cs, 0);
	while ((tmp = t->tid)) __timedwait_cp(&t->tid, tmp, 0, 0, 0);
	__pthread_setcancelstate(cs, 0);
	if (res) *res = t->result;
	if (t->map_base) __munmap(t->map_base, t->map_size);
	return 0;
}

weak_alias(__pthread_join, pthread_join);
