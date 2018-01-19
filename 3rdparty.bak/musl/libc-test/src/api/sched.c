#include <sched.h>
#include "options.h"
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(struct timespec)
{
struct sched_param x;
F(int,sched_priority)
#if defined(POSIX_SPORADIC_SERVER) || defined(POSIX_THREAD_SPORADIC_SERVER)
F(int,sched_ss_low_priority)
F(struct timespec,sched_ss_repl_period)
F(struct timespec,sched_ss_init_budget)
F(int,sched_ss_max_repl)
T(time_t)
C(SCHED_SPORADIC)
#endif
}
#ifdef POSIX_PRIORITY_SCHEDULING
T(pid_t)
{int(*p)(pid_t,struct sched_param*) = sched_getparam;}
{int(*p)(pid_t) = sched_getscheduler;}
{int(*p)(pid_t,const struct sched_param*) = sched_setparam;}
{int(*p)(pid_t,int,const struct sched_param*) = sched_setscheduler;}
#endif
C(SCHED_FIFO)
C(SCHED_RR)
C(SCHED_OTHER)
{int(*p)(int) = sched_get_priority_max;}
{int(*p)(int) = sched_get_priority_min;}
{int(*p)(pid_t,struct timespec*) = sched_rr_get_interval;}
{int(*p)(void) = sched_yield;}
}
