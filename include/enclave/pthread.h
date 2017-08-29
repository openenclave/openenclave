#ifndef __ELIBC_PTHREAD_H
#define __ELIBC_PTHREAD_H

#include <features.h>
#include <bits/alltypes.h>
#include <time.h>

__ELIBC_BEGIN

/*
**==============================================================================
**
** pthread_attr_t
**
**==============================================================================
*/

typedef struct _pthread_attr_t 
{
    int attr;
}
pthread_attr_t;

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_init(pthread_attr_t *attr);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_destroy(pthread_attr_t *attr);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_getguardsize(const pthread_attr_t *attr, size_t *guardsize);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);
#endif

/*
**==============================================================================
**
** pthread_t
**
**==============================================================================
*/

#define PTHREAD_CREATE_DETACHED 0

#define PTHREAD_CANCEL_DISABLE 0

#define PTHREAD_CANCEL_DEFERRED 0

typedef struct __pthread* pthread_t;

pthread_t pthread_self(void);

int pthread_equal(pthread_t thread1, pthread_t thread2);

#ifdef __ELIBC_UNSUPPORTED
int pthread_create(
    pthread_t* thread, 
    const pthread_attr_t* attr,
    void* (*start_routine)(void* arg), 
    void* arg);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_join(pthread_t thread, void** ret);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_detach(pthread_t thread);
#endif

#ifdef __ELIBC_UNSUPPORTED
void pthread_cleanup_push(void (*routine)(void *), void *arg);
#endif

#ifdef __ELIBC_UNSUPPORTED
void pthread_cleanup_pop(int execute);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_cancel(pthread_t thread);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_setcancelstate(int state, int *oldstate);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_setcanceltype(int type, int *oldtype);
#endif

#ifdef __ELIBC_UNSUPPORTED
void pthread_testcancel(void);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_atfork(
    void (*prepare)(void), 
    void (*parent)(void),
    void (*child)(void));
#endif

/*
**==============================================================================
**
** pthread_once_t
**
**==============================================================================
*/

#define PTHREAD_ONCE_INIT 0

typedef unsigned int pthread_once_t;

int pthread_once(pthread_once_t* once, void (*func)(void));

/*
**==============================================================================
**
** pthread_spinlock_t
**
**==============================================================================
*/

#define PTHREAD_SPINLOCK_INITIALIZER 0

typedef volatile unsigned int pthread_spinlock_t;

int pthread_spin_init(pthread_spinlock_t* spinlock, int pshared);

int pthread_spin_lock(pthread_spinlock_t* spinlock);

int pthread_spin_unlock(pthread_spinlock_t* spinlock);

int pthread_spin_destroy(pthread_spinlock_t* spinlock);

/*
**==============================================================================
**
** pthread_mutex_t
**
**==============================================================================
*/

#define PTHREAD_MUTEX_INITIALIZER \
    { 0, PTHREAD_SPINLOCK_INITIALIZER, { NULL, NULL }, { 0 } }

#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_RECURSIVE 1

typedef struct _pthread_mutexattr_t 
{
    int type;
}
pthread_mutexattr_t;

int pthread_mutexattr_init(pthread_mutexattr_t* attr);

int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type);

int pthread_mutexattr_destroy(pthread_mutexattr_t* attr);

typedef struct _pthread_mutex_t
{
    pthread_spinlock_t lock;
    unsigned int refs;
    unsigned char __padding[16]; /* align with system pthread_t */
    struct 
    {
        void* front;
        void* back;
    }
    queue;
}
pthread_mutex_t;

/* This must be the same size as pthread_mutex_t in GLIBC */
__STATIC_ASSERT((sizeof(pthread_mutex_t) == 40));

int pthread_mutex_init(pthread_mutex_t* mutex, pthread_mutexattr_t* attr);

int pthread_mutex_lock_u(pthread_mutex_t* mutex);

int pthread_mutex_unlock_u(pthread_mutex_t* mutex);

int pthread_mutex_destroy(pthread_mutex_t* mutex);

int pthread_mutex_trylock_u(pthread_mutex_t* mutex);

#ifdef __ELIBC_UNSUPPORTED
int pthread_mutex_lock(pthread_mutex_t* mutex);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_mutex_unlock(pthread_mutex_t* mutex);
#endif

/*
**==============================================================================
**
** pthread_rwlock_t
**
**==============================================================================
*/

#define PTHREAD_RWLOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER

typedef struct _pthread_rwlockattr_t 
{
    int __impl;
}
pthread_rwlockattr_t;

typedef struct _pthread_rwlock_t
{
    pthread_mutex_t __impl;
}
pthread_rwlock_t;

int pthread_rwlock_init(pthread_rwlock_t* rwlock, pthread_rwlockattr_t* attr);

int pthread_rwlock_rdlock_u(pthread_rwlock_t* rwlock);

int pthread_rwlock_wrlock_u(pthread_rwlock_t* rwlock);

int pthread_rwlock_unlock_u(pthread_rwlock_t* rwlock);

int pthread_rwlock_destroy(pthread_rwlock_t* rwlock);

int pthread_rwlock_trylock_u(pthread_rwlock_t* rwlock);

#ifdef __ELIBC_UNSUPPORTED
int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_rwlock_unlock(pthread_rwlock_t* rwlock);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_rwlock_trylock(pthread_rwlock_t* rwlock);
#endif

/*
**==============================================================================
**
** pthread_cond_t
**
**==============================================================================
*/

#define PTHREAD_COND_INITIALIZER \
    { PTHREAD_SPINLOCK_INITIALIZER, { NULL, NULL }, { 0, 0, 0} }

typedef struct _pthread_cond_t
{
    pthread_spinlock_t lock;
    struct 
    {
        void* front;
        void* back;
    }
    queue;
    unsigned long padding[3];
}
pthread_cond_t;

/* This must the same size as pthread_cond_t in GLIBC */
__STATIC_ASSERT((sizeof(pthread_cond_t) == 48));

typedef struct _pthread_condattr_t pthread_condattr_t;

int pthread_cond_init(pthread_cond_t* cond, pthread_condattr_t* attr);

int pthread_cond_destroy(pthread_cond_t *cond);

int pthread_cond_wait_u(pthread_cond_t *cond, pthread_mutex_t* mutex);

int pthread_cond_signal_u(pthread_cond_t *cond);

int pthread_cond_broadcast_u(pthread_cond_t *cond);

/* ATTN: implement! */
int pthread_cond_timedwait(
    pthread_cond_t *cond, 
    pthread_mutex_t* mutex,
    struct timespec* ts);

/*
**==============================================================================
**
** pthread_key_t
**
**==============================================================================
*/

#define PTHREAD_KEY_INITIALIZER 0

typedef unsigned int pthread_key_t;

int pthread_key_create(pthread_key_t* key, void (*destructor)(void* value));

int pthread_key_delete(pthread_key_t key);

int pthread_setspecific(pthread_key_t key, const void* value);

void* pthread_getspecific(pthread_key_t key);

/*
**==============================================================================
**
** pthread_barrier_t
**
**==============================================================================
*/

typedef struct _pthread_barrier_t { int __dummy; } pthread_barrier_t;

#ifdef __ELIBC_UNSUPPORTED
int pthread_barrier_wait(pthread_barrier_t* barrier);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_barrier_init(pthread_barrier_t* barrier, int, int);
#endif

#ifdef __ELIBC_UNSUPPORTED
int pthread_barrier_destroy(pthread_barrier_t* barrier);
#endif

__ELIBC_END

#endif /* __ELIBC_PTHREAD_H */
