#include "stdio_impl.h"
#include "pthread_impl.h"

void __register_locked_file(FILE *, pthread_t);

void flockfile(FILE *f)
{
	if (!ftrylockfile(f)) return;
	__lockfile(f);
	__register_locked_file(f, __pthread_self());
}
