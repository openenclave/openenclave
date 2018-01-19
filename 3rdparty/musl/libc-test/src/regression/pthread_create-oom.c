// commit: 59666802fba592a59f2f4ea4dcb053287fd55826 2011-02-15
// pthread_create should return EAGAIN on failure
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include "test.h"

static void *start(void *arg)
{
	return 0;
}

int main(void)
{
	pthread_t td;
	int r, arg;

	if (t_memfill() < 0)
		t_error("memfill failed\n");
	r = pthread_create(&td, 0, start, &arg);
	if (r == 0)
		t_error("pthread_create succeeded\n");
	else if (r != EAGAIN)
		t_error("pthread_create should fail with EAGAIN but failed with %d (%s)\n", r, strerror(r));

	return t_status;
}
