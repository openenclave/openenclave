#include <sys/resource.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(rlim_t)
T(id_t)
T(struct timeval)
C(PRIO_PROCESS)
C(PRIO_PGRP)
C(PRIO_USER)
C(RLIM_INFINITY)
C(RLIM_SAVED_MAX)
C(RLIM_SAVED_CUR)
C(RUSAGE_SELF)
C(RUSAGE_CHILDREN)
{
struct rlimit x;
F(rlim_t, rlim_cur)
F(rlim_t, rlim_max)
}
{
struct rusage x;
F(struct timeval, ru_utime)
F(struct timeval, ru_stime)
}
C(RLIMIT_CORE)
C(RLIMIT_CPU)
C(RLIMIT_DATA)
C(RLIMIT_FSIZE)
C(RLIMIT_NOFILE)
C(RLIMIT_STACK)
C(RLIMIT_AS)
{int(*p)(int,id_t) = getpriority;}
{int(*p)(int,struct rlimit*) = getrlimit;}
{int(*p)(int,struct rusage*) = getrusage;}
{int(*p)(int,id_t,int) = setpriority;}
{int(*p)(int,const struct rlimit*) = setrlimit;}
}
