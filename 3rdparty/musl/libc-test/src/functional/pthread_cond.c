#include <pthread.h>
#include <string.h>
#include "test.h"

#define TEST(r, f, m) ( \
	((r) = (f)) == 0 || (t_error("%s failed: %s (" m ")\n", #f, strerror(r)), 0) )


static void *start_signal(void *arg)
{
	void **args = arg;
	pthread_mutex_lock(args[1]);
	pthread_cond_signal(args[0]);
	pthread_mutex_unlock(args[1]);
	return 0;
}

static void *start_wait(void *arg)
{
	void **args = arg;
	pthread_mutex_t *m = args[1];
	pthread_cond_t *c = args[0];
	int *x = args[2];

	pthread_mutex_lock(m);
	while (*x) pthread_cond_wait(c, m);
	pthread_mutex_unlock(m);

	return 0;
}

int main(void)
{
	pthread_t td, td1, td2, td3;
	int r;
	void *res;
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	int foo[1];

	/* Condition variables */
	TEST(r, pthread_mutex_init(&mtx, 0), "");
	TEST(r, pthread_cond_init(&cond, 0), "");
	TEST(r, pthread_mutex_lock(&mtx), "");
	TEST(r, pthread_create(&td, 0, start_signal, (void *[]){ &cond, &mtx }), "");
	TEST(r, pthread_cond_wait(&cond, &mtx), "");
	TEST(r, pthread_join(td, &res), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	TEST(r, pthread_mutex_destroy(&mtx), "");
	TEST(r, pthread_cond_destroy(&cond), "");

	/* Condition variables with multiple waiters */
	TEST(r, pthread_mutex_init(&mtx, 0), "");
	TEST(r, pthread_cond_init(&cond, 0), "");
	TEST(r, pthread_mutex_lock(&mtx), "");
	foo[0] = 1;
	TEST(r, pthread_create(&td1, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_create(&td2, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_create(&td3, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	nanosleep(&(struct timespec){.tv_nsec=1000000}, 0);
	foo[0] = 0;
	TEST(r, pthread_mutex_lock(&mtx), "");
	TEST(r, pthread_cond_signal(&cond), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	TEST(r, pthread_mutex_lock(&mtx), "");
	TEST(r, pthread_cond_signal(&cond), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	TEST(r, pthread_mutex_lock(&mtx), "");
	TEST(r, pthread_cond_signal(&cond), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	TEST(r, pthread_join(td1, 0), "");
	TEST(r, pthread_join(td2, 0), "");
	TEST(r, pthread_join(td3, 0), "");
	TEST(r, pthread_mutex_destroy(&mtx), "");
	TEST(r, pthread_cond_destroy(&cond), "");

	/* Condition variables with broadcast signals */
	TEST(r, pthread_mutex_init(&mtx, 0), "");
	TEST(r, pthread_cond_init(&cond, 0), "");
	TEST(r, pthread_mutex_lock(&mtx), "");
	foo[0] = 1;
	TEST(r, pthread_create(&td1, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_create(&td2, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_create(&td3, 0, start_wait, (void *[]){ &cond, &mtx, foo }), "");
	TEST(r, pthread_mutex_unlock(&mtx), "");
	nanosleep(&(struct timespec){.tv_nsec=1000000}, 0);
	TEST(r, pthread_mutex_lock(&mtx), "");
	foo[0] = 0;
	TEST(r, pthread_mutex_unlock(&mtx), "");
	TEST(r, pthread_cond_broadcast(&cond), "");
	TEST(r, pthread_join(td1, 0), "");
	TEST(r, pthread_join(td2, 0), "");
	TEST(r, pthread_join(td3, 0), "");
	TEST(r, pthread_mutex_destroy(&mtx), "");
	TEST(r, pthread_cond_destroy(&cond), "");

	return t_status;
}
