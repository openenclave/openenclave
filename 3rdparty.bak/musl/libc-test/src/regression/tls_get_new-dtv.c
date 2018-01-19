// __tls_get_new did not allocate new dtv for threads properly
#include <pthread.h>
#include <dlfcn.h>
#include "test.h"

#define N 10

#define T(c) ((c) || (t_error(#c " failed\n"),0))

static pthread_barrier_t b;
static void *mod;

static void *start(void *a)
{
	void *(*f)(void);

	pthread_barrier_wait(&b);
	T(f = dlsym(mod, "f"));
	f();
	return 0;
}

int main()
{
	pthread_t td[N];
	int i;

	pthread_barrier_init(&b, 0, N+1);
	for (i=0; i<N; i++)
		T(!pthread_create(td+i, 0, start, 0));

	T(mod = dlopen("tls_get_new-dtv_dso.so", RTLD_NOW));
	pthread_barrier_wait(&b);

	for (i=0; i<N; i++)
		T(!pthread_join(td[i], 0));
	return t_status;
}
