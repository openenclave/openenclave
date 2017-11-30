#include <sys/types.h>
#define T(t) (t*)0;
#define N(t) {t x = 1;}
static void f()
{
N(blkcnt_t)
N(blksize_t)
N(clock_t)
N(clockid_t)
N(dev_t)
N(gid_t)
N(id_t)
N(ino_t)
N(mode_t)
N(nlink_t)
N(off_t)
N(pid_t)
N(size_t)
N(ssize_t)
N(time_t)
T(timer_t)
N(uid_t)
#ifdef _XOPEN_SOURCE
N(fsblkcnt_t)
N(fsfilcnt_t)
N(key_t)
N(suseconds_t)
#endif
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
}

