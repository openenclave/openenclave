#include <pthread.h>
#define T(t) (t*)0;
#define C(n) switch(n){case n:;}
static void f()
{
T(pthread_attr_t)
T(pthread_barrier_t)
T(pthread_barrierattr_t)
T(pthread_cond_t)
T(pthread_condattr_t)
T(pthread_key_t)
T(pthread_mutex_t)
T(pthread_mutexattr_t)
T(pthread_once_t)
T(pthread_rwlock_t)
T(pthread_rwlockattr_t)
T(pthread_spinlock_t)
T(pthread_t)
C(PTHREAD_BARRIER_SERIAL_THREAD)
C(PTHREAD_CANCEL_ASYNCHRONOUS)
C(PTHREAD_CANCEL_ENABLE)
C(PTHREAD_CANCEL_DEFERRED)
C(PTHREAD_CANCEL_DISABLE)
{void *x = PTHREAD_CANCELED;}
C(PTHREAD_CREATE_DETACHED)
C(PTHREAD_CREATE_JOINABLE)
C(PTHREAD_MUTEX_DEFAULT)
C(PTHREAD_MUTEX_ERRORCHECK)
C(PTHREAD_MUTEX_NORMAL)
C(PTHREAD_MUTEX_RECURSIVE)
C(PTHREAD_MUTEX_ROBUST)
C(PTHREAD_MUTEX_STALLED)
C(PTHREAD_ONCE_INIT)
#if defined(POSIX_THREAD_ROBUST_PRIO_INHERIT) || defined(POSIX_THREAD_PRIO_INHERIT)
C(PTHREAD_PRIO_INHERIT)
#endif
#if defined(POSIX_THREAD_ROBUST_PRIO_INHERIT) || defined(POSIX_THREAD_PRIO_INHERIT) \
 || defined(POSIX_THREAD_ROBUST_PRIO_PROTECT) || defined(POSIX_THREAD_PRIO_PROTECT)
C(PTHREAD_PRIO_NONE)
#endif
#if defined(POSIX_THREAD_ROBUST_PRIO_PROTECT) || defined(POSIX_THREAD_PRIO_PROTECT)
C(PTHREAD_PRIO_PROTECT)
#endif
C(PTHREAD_PROCESS_SHARED)
C(PTHREAD_PROCESS_PRIVATE)
#ifdef POSIX_THREAD_PRIORITY_SCHEDULING
C(PTHREAD_EXPLICIT_SCHED)
C(PTHREAD_INHERIT_SCHED)
C(PTHREAD_SCOPE_PROCESS)
C(PTHREAD_SCOPE_SYSTEM)
#endif
{pthread_cond_t x = PTHREAD_COND_INITIALIZER;}
{pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;}
{pthread_rwlock_t x = PTHREAD_RWLOCK_INITIALIZER;}
{int(*p)(void(*)(void),void(*)(void),void(*)(void)) = pthread_atfork;}
{int(*p)(pthread_attr_t*) = pthread_attr_destroy;}
{int(*p)(const pthread_attr_t*,int*) = pthread_attr_getdetachstate;}
{int(*p)(const pthread_attr_t*restrict,size_t*restrict) = pthread_attr_getguardsize;}
{int(*p)(const pthread_attr_t*restrict,struct sched_param*restrict) = pthread_attr_getschedparam;}
{int(*p)(const pthread_attr_t*restrict,void**restrict,size_t*restrict) = pthread_attr_getstack;}
{int(*p)(const pthread_attr_t*restrict,size_t*restrict) = pthread_attr_getstacksize;}
{int(*p)(pthread_attr_t*) = pthread_attr_init;}
{int(*p)(pthread_attr_t*,int) = pthread_attr_setdetachstate;}
{int(*p)(pthread_attr_t*,size_t) = pthread_attr_setguardsize;}
{int(*p)(pthread_attr_t*restrict,const struct sched_param*restrict) = pthread_attr_setschedparam;}
{int(*p)(pthread_attr_t*,void*,size_t) = pthread_attr_setstack;}
{int(*p)(pthread_attr_t*,size_t) = pthread_attr_setstacksize;}
{int(*p)(pthread_barrier_t*) = pthread_barrier_destroy;}
{int(*p)(pthread_barrier_t*restrict,const pthread_barrierattr_t*restrict,unsigned) = pthread_barrier_init;}
{int(*p)(pthread_barrier_t*) = pthread_barrier_wait;}
{int(*p)(pthread_barrierattr_t*) = pthread_barrierattr_destroy;}
{int(*p)(const pthread_barrierattr_t*restrict,int*restrict) = pthread_barrierattr_getpshared;}
{int(*p)(pthread_barrierattr_t*) = pthread_barrierattr_init;}
{int(*p)(pthread_barrierattr_t*,int) = pthread_barrierattr_setpshared;}
{int(*p)(pthread_t) = pthread_cancel;}
#ifndef pthread_cleanup_pop
{void(*p)(int) = pthread_cleanup_pop;}
#endif
#ifndef pthread_cleanup_push
{void(*p)(void(*)(void*),void*) = pthread_cleanup_push;}
#endif
{int(*p)(pthread_cond_t*) = pthread_cond_broadcast;}
{int(*p)(pthread_cond_t*) = pthread_cond_destroy;}
{int(*p)(pthread_cond_t*restrict,const pthread_condattr_t*restrict) = pthread_cond_init;}
{int(*p)(pthread_cond_t*) = pthread_cond_signal;}
{int(*p)(pthread_cond_t*restrict,pthread_mutex_t*restrict,const struct timespec*restrict) = pthread_cond_timedwait;}
{int(*p)(pthread_cond_t*restrict,pthread_mutex_t*restrict) = pthread_cond_wait;}
{int(*p)(pthread_condattr_t*) = pthread_condattr_destroy;}
{int(*p)(const pthread_condattr_t*restrict,clockid_t*restrict) = pthread_condattr_getclock;}
{int(*p)(const pthread_condattr_t*restrict,int*restrict) = pthread_condattr_getpshared;}
{int(*p)(pthread_condattr_t*) = pthread_condattr_init;}
{int(*p)(pthread_condattr_t*,clockid_t) = pthread_condattr_setclock;}
{int(*p)(pthread_condattr_t*,int) = pthread_condattr_setpshared;}
{int(*p)(pthread_t*restrict,const pthread_attr_t*restrict,void*(*)(void*),void*restrict) = pthread_create;}
{int(*p)(pthread_t) = pthread_detach;}
{int(*p)(pthread_t,pthread_t) = pthread_equal;}
{void(*p)(void*) = pthread_exit;}
{void*(*p)(pthread_key_t) = pthread_getspecific;}
{int(*p)(pthread_t,void**) = pthread_join;}
{int(*p)(pthread_key_t*,void(*)(void*)) = pthread_key_create;}
{int(*p)(pthread_key_t) = pthread_key_delete;}
{int(*p)(pthread_mutex_t*) = pthread_mutex_consistent;}
{int(*p)(pthread_mutex_t*) = pthread_mutex_destroy;}
{int(*p)(pthread_mutex_t*restrict,const pthread_mutexattr_t*restrict) = pthread_mutex_init;}
{int(*p)(pthread_mutex_t*) = pthread_mutex_lock;}
{int(*p)(pthread_mutex_t*) = pthread_mutex_trylock;}
{int(*p)(pthread_mutex_t*) = pthread_mutex_unlock;}
{int(*p)(pthread_mutexattr_t*) = pthread_mutexattr_destroy;}
#if defined(POSIX_THREAD_ROBUST_PRIO_INHERIT) || defined(POSIX_THREAD_PRIO_INHERIT) \
 || defined(POSIX_THREAD_ROBUST_PRIO_PROTECT) || defined(POSIX_THREAD_PRIO_PROTECT)
{int(*p)(const pthread_mutexattr_t*restrict,int*restrict) = pthread_mutexattr_getprotocol;}
{int(*p)(pthread_mutexattr_t*,int) = pthread_mutexattr_setprotocol;}
#endif
{int(*p)(const pthread_mutexattr_t*restrict,int*restrict) = pthread_mutexattr_getpshared;}
{int(*p)(const pthread_mutexattr_t*restrict,int*restrict) = pthread_mutexattr_getrobust;}
{int(*p)(const pthread_mutexattr_t*restrict,int*restrict) = pthread_mutexattr_gettype;}
{int(*p)(pthread_mutexattr_t*) = pthread_mutexattr_init;}
{int(*p)(pthread_mutexattr_t*,int) = pthread_mutexattr_setpshared;}
{int(*p)(pthread_mutexattr_t*,int) = pthread_mutexattr_setrobust;}
{int(*p)(pthread_mutexattr_t*,int) = pthread_mutexattr_settype;}
{int(*p)(pthread_once_t*,void(*)(void)) = pthread_once;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_destroy;}
{int(*p)(pthread_rwlock_t*restrict,const pthread_rwlockattr_t*restrict) = pthread_rwlock_init;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_rdlock;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_tryrdlock;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_trywrlock;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_unlock;}
{int(*p)(pthread_rwlock_t*) = pthread_rwlock_wrlock;}
{int(*p)(pthread_rwlockattr_t*) = pthread_rwlockattr_destroy;}
{int(*p)(const pthread_rwlockattr_t*restrict,int*restrict) = pthread_rwlockattr_getpshared;}
{int(*p)(pthread_rwlockattr_t*) = pthread_rwlockattr_init;}
{int(*p)(pthread_rwlockattr_t*,int) = pthread_rwlockattr_setpshared;}
{pthread_t(*p)(void) = pthread_self;}
{int(*p)(int,int*) = pthread_setcancelstate;}
{int(*p)(int,int*) = pthread_setcanceltype;}
#if defined _XOPEN_SOURCE && defined OBSOLETE
{int(*p)(void) = pthread_getconcurrency;}
{int(*p)(int) = pthread_setconcurrency;}
#endif
{int(*p)(pthread_t,int) = pthread_setschedprio;}
{int(*p)(pthread_key_t,const void*) = pthread_setspecific;}
{int(*p)(pthread_spinlock_t*) = pthread_spin_destroy;}
{int(*p)(pthread_spinlock_t*,int) = pthread_spin_init;}
{int(*p)(pthread_spinlock_t*) = pthread_spin_lock;}
{int(*p)(pthread_spinlock_t*) = pthread_spin_trylock;}
{int(*p)(pthread_spinlock_t*) = pthread_spin_unlock;}
{void(*p)(void) = pthread_testcancel;}
#if defined(POSIX_THREAD_ROBUST_PRIO_PROTECT) || defined(POSIX_THREAD_PRIO_PROTECT)
{int(*p)(const pthread_mutex_t*restrict,int*restrict) = pthread_mutex_getprioceiling;}
{int(*p)(pthread_mutex_t*restrict,int,int*restrict) = pthread_mutex_setprioceiling;}
{int(*p)(const pthread_mutexattr_t*restrict,int*restrict) = pthread_mutexattr_getprioceiling;}
{int(*p)(pthread_mutexattr_t*,int) = pthread_mutexattr_setprioceiling;}
#endif
#ifdef POSIX_THREAD_PRIORITY_SCHEDULING
{int(*p)(const pthread_attr_t*restrict,int*restrict) = pthread_attr_getinheritsched;}
{int(*p)(const pthread_attr_t*restrict,int*restrict) = pthread_attr_getschedpolicy;}
{int(*p)(const pthread_attr_t*restrict,int*restrict) = pthread_attr_getscope;}
{int(*p)(pthread_attr_t*,int) = pthread_attr_setinheritsched;}
{int(*p)(pthread_attr_t*,int) = pthread_attr_setschedpolicy;}
{int(*p)(pthread_attr_t*,int) = pthread_attr_setscope;}
{int(*p)(pthread_t,int*restrict,struct sched_param*restrict) = pthread_getschedparam;}
{int(*p)(pthread_t,int,const struct sched_param*) = pthread_setschedparam;}
#endif
}
#include <time.h>
static void g()
{
{int(*p)(pthread_t,clockid_t*) = pthread_getcpuclockid;}
{int(*p)(pthread_mutex_t*restrict,const struct timespec*restrict) = pthread_mutex_timedlock;}
{int(*p)(pthread_rwlock_t*restrict,const struct timespec*restrict) = pthread_rwlock_timedrdlock;}
{int(*p)(pthread_rwlock_t*restrict,const struct timespec*restrict) = pthread_rwlock_timedwrlock;}
}
