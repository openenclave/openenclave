#include <pthread.h>
#include "test.h"

__thread int tls_fix = 23;
__thread int tls_zero;

static void *f(void *arg)
{
	if (tls_fix != 23)
		t_error("fixed init failed: want 23 got %d\n", tls_fix);
	if (tls_zero != 0)
		t_error("zero init failed: want 0 got %d\n", tls_zero);
	tls_fix++;
	tls_zero++;
	return 0;
}

#define CHECK(f) do{ if(f) t_error("%s failed.\n", #f); }while(0)
#define length(a) (sizeof(a)/sizeof*(a))

int main()
{
	pthread_t t[5];
	int i, j;

	if (tls_fix != 23)
		t_error("fixed init failed: want 23 got %d\n", tls_fix);
	if (tls_zero != 0)
		t_error("zero init failed: want 0 got %d\n", tls_zero);

	for (j = 0; j < 2; j++) {
		for (i = 0; i < length(t); i++) {
			CHECK(pthread_create(t+i, 0, f, 0));
			tls_fix++;
			tls_zero++;
		}
		for (i = 0; i < length(t); i++)
			CHECK(pthread_join(t[i], 0));
	}

	return t_status;
}
