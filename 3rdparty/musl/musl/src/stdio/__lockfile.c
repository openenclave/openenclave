#include "stdio_impl.h"
#include "pthread_impl.h"

#define MAYBE_WAITERS 0x40000000

int __lockfile(FILE *f)
{
	int owner = f->lock, tid = __pthread_self()->tid;
	if ((owner & ~MAYBE_WAITERS) == tid)
		return 0;
	for (;;) {
		owner = a_cas(&f->lock, 0, tid);
		if (!owner) return 1;
		if (a_cas(&f->lock, owner, owner|MAYBE_WAITERS)==owner) break;
	}
	while ((owner = a_cas(&f->lock, 0, tid|MAYBE_WAITERS)))
		__futexwait(&f->lock, owner, 1);
	return 1;
}

void __unlockfile(FILE *f)
{
	if (a_swap(&f->lock, 0) & MAYBE_WAITERS)
		__wake(&f->lock, 1, 1);
}
