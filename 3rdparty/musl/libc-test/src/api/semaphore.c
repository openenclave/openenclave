#include <semaphore.h>
static void f()
{
{sem_t *x = SEM_FAILED;}
{int(*p)(sem_t*) = sem_close;}
{int(*p)(sem_t*) = sem_destroy;}
{int(*p)(sem_t*restrict,int*restrict) = sem_getvalue;}
{int(*p)(sem_t*,int,unsigned) = sem_init;}
{sem_t*(*p)(const char*,int,...) = sem_open;}
{int(*p)(sem_t*) = sem_post;}
{int(*p)(sem_t*) = sem_trywait;}
{int(*p)(const char*) = sem_unlink;}
{int(*p)(sem_t*) = sem_wait;}
}
#include <time.h>
static void g()
{
{int(*p)(sem_t*restrict,const struct timespec*restrict) = sem_timedwait;}
}
