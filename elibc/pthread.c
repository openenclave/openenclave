#include <pthread.h>
#include <assert.h>
#include <openenclave.h>
#include <__openenclave/mem.h>
#include <__openenclave/calls.h>
#include "../enclave/td.h"

/*
**==============================================================================
**
** Host requests:
**
**==============================================================================
*/

static int _ThreadWait(OE_ThreadData* self)
{
    const void* tcs = TD_ToTCS((TD*)self);

    if (__OE_OCall(OE_FUNC_THREAD_WAIT, (uint64_t)tcs, NULL) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWake(OE_ThreadData* self)
{
    const void* tcs = TD_ToTCS((TD*)self);

    if (__OE_OCall(OE_FUNC_THREAD_WAKE, (uint64_t)tcs, NULL) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWakeWait(OE_ThreadData* waiter, OE_ThreadData* self)
{
    int ret = -1;
    OE_ThreadWakeWaitArgs* args = NULL;

    if (!(args = malloc(sizeof(OE_ThreadWakeWaitArgs))))
        goto done;

    args->waiter_tcs = TD_ToTCS((TD*)waiter);
    args->self_tcs = TD_ToTCS((TD*)self);

    if (__OE_OCall(OE_FUNC_THREAD_WAKE_WAIT, (uint64_t)args, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (args)
        free(args);

    return ret;
}

/*
**==============================================================================
**
** queue_t
**
**==============================================================================
*/

typedef struct _queue_t
{
    OE_ThreadData* front;
    OE_ThreadData* back;
}
queue_t;

static void _queue_push_back(queue_t* queue, OE_ThreadData* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

static OE_ThreadData* _queue_pop_front(queue_t* queue)
{
    OE_ThreadData* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->next;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

static bool _queue_contains(queue_t* queue, OE_ThreadData* thread)
{
    OE_ThreadData* p;

    for (p = queue->front; p; p = p->next)
    {
        if (p == thread)
            return true;
    }

    return false;
}

static __inline__ bool _queue_empty(queue_t* queue)
{
    return queue->front ? false : true;
}

/*
**==============================================================================
**
** pthread_t
**
**==============================================================================
*/

pthread_t pthread_self()
{
    return (pthread_t)OE_GetThreadData();
}

int pthread_equal(pthread_t thread1, pthread_t thread2)
{
    return thread1 == thread2;
}

/*
**==============================================================================
**
** pthread_once_t
**
**==============================================================================
*/

int pthread_once(pthread_once_t* once, void (*func)(void))
{
    if (!once)
        return -1;

    if (*once == 0)
    {
        static pthread_spinlock_t _lock = PTHREAD_SPINLOCK_INITIALIZER;

        pthread_spin_lock(&_lock);

        if (*once == 0)
        {
            if (func)
                func();
            *once = 1;
        }

        pthread_spin_unlock(&_lock);
    }

    return 0;
}

/*
**==============================================================================
**
** pthread_spinlock_t
**
**==============================================================================
*/

int pthread_spin_init(pthread_spinlock_t* spinlock, int pshared)
{
    return OE_SpinInit((OE_Spinlock*)spinlock);
}

int pthread_spin_lock(pthread_spinlock_t* spinlock)
{
    return OE_SpinLock((OE_Spinlock*)spinlock);
}

int pthread_spin_unlock(pthread_spinlock_t* spinlock)
{
    return OE_SpinUnlock((OE_Spinlock*)spinlock);
}

int pthread_spin_destroy(pthread_spinlock_t* spinlock)
{
    return OE_SpinDestroy((OE_Spinlock*)spinlock);
}

/*
**==============================================================================
**
** pthread_mutex_t
**
**==============================================================================
*/

int pthread_mutexattr_init(pthread_mutexattr_t* attr)
{
    return 0;
}

int pthread_mutexattr_settype(pthread_mutexattr_t* attr, int type)
{
    if (attr)
        attr->type = type;
    return 0;
}

int pthread_mutexattr_destroy(pthread_mutexattr_t* attr)
{
    if (attr)
        attr->type = 0;
    return 0;
}

int pthread_mutex_init(pthread_mutex_t* m, pthread_mutexattr_t* attr)
{
    if (m)
    {
        memset(m, 0, sizeof(pthread_mutex_t));
        m->lock = PTHREAD_SPINLOCK_INITIALIZER;
    }

    return 0;
}

int pthread_mutex_lock(pthread_mutex_t* m)
{
    OE_ThreadData* self = OE_GetThreadData();

    if (!m)
        return -1;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        pthread_spin_lock(&m->lock);
        {
            /* If SELF not on queue, insert at back */
            if (!_queue_contains((queue_t*)&m->queue, self))
            {
                _queue_push_back((queue_t*)&m->queue, self);
            }

            /* If self at front of queue */
            if (m->queue.front == self)
            {
                m->refs++;
                pthread_spin_unlock(&m->lock);
                return 0;
            }
        }
        pthread_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        _ThreadWait(self);
    }

    /* Unreachable! */
}

int pthread_mutex_trylock(pthread_mutex_t* m)
{
    OE_ThreadData* self = OE_GetThreadData();

    if (!m)
        return -1;

    pthread_spin_lock(&m->lock);
    {
        /* If this thread is already the owner, grab the lock */
        if (m->queue.front == self)
        {
            m->refs++;
            pthread_spin_unlock(&m->lock);
            return 0;
        }

        /* If waiter queue is empty, grab the lock */
        if (_queue_empty((queue_t*)&m->queue))
        {
            _queue_push_back((queue_t*)&m->queue, self);
            m->refs++;
            pthread_spin_unlock(&m->lock);
            return 0;
        }

    }
    pthread_spin_unlock(&m->lock);

    return 0;
}

static int _mutex_unlock(pthread_mutex_t* m, OE_ThreadData** waiter)
{
    OE_ThreadData* self = OE_GetThreadData();
    int ret = -1;

    if (!m || !waiter)
        goto done;

    pthread_spin_lock(&m->lock);
    {
        /* If SELF is the owner */
        if (m->queue.front == self)
        {
            if (--m->refs == 0)
            {
                _queue_pop_front((queue_t*)&m->queue);
                *waiter = m->queue.front;
            }

            ret = 0;
        }
    }
    pthread_spin_unlock(&m->lock);

done:
    return ret;
}

int pthread_mutex_unlock(pthread_mutex_t* m)
{
    OE_ThreadData* waiter = NULL;

    if (!m)
        return -1;

    if (_mutex_unlock(m, &waiter) != 0)
        return -1;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        _ThreadWake(waiter);
    }

    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t* m)
{
    int ret = -1;

    if (!m)
        goto done;

    pthread_spin_lock(&m->lock);
    {
        if (_queue_empty((queue_t*)&m->queue))
        {
            memset(m, 0, sizeof(pthread_mutex_t));
            ret = 0;
        }
    }
    pthread_spin_unlock(&m->lock);

done:
    return ret;
}

/*
**==============================================================================
**
** pthread_rwlock_t
**
**==============================================================================
*/

#define PTHREAD_RWLOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER

int pthread_rwlock_init(pthread_rwlock_t* rwlock, pthread_rwlockattr_t* attr)
{
    if (rwlock)
        return pthread_mutex_init(&rwlock->__impl, NULL);

    return -1;
}

int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock)
{
    if (rwlock)
        return pthread_mutex_lock(&rwlock->__impl);

    return -1;
}

int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock)
{
    if (rwlock)
        return pthread_mutex_lock(&rwlock->__impl);

    return -1;
}

int pthread_rwlock_unlock(pthread_rwlock_t* rwlock)
{
    if (rwlock)
        return pthread_mutex_unlock(&rwlock->__impl);

    return -1;
}

int pthread_rwlock_trylock(pthread_rwlock_t* rwlock)
{
    if (rwlock)
        pthread_mutex_trylock(&rwlock->__impl);

    return -1;
}

int pthread_rwlock_destroy(pthread_rwlock_t* rwlock)
{
    if (rwlock)
        return pthread_mutex_destroy(&rwlock->__impl);

    return -1;
}

/*
**==============================================================================
**
** pthread_cond_t
**
**==============================================================================
*/

int pthread_cond_init(pthread_cond_t* cond, pthread_condattr_t* attr)
{
    if (cond)
    {
        memset(cond, 0, sizeof(pthread_cond_t));
        cond->lock = PTHREAD_SPINLOCK_INITIALIZER;
    }

    return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t* mutex)
{
    OE_ThreadData* self = OE_GetThreadData();

    pthread_spin_lock(&cond->lock);
    {
        OE_ThreadData* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        _queue_push_back((queue_t*)&cond->queue, self);

        /* Unlock whichever thread is waiting on this mutex (the waiter) */
        if (_mutex_unlock(mutex, &waiter) != 0)
        {
            pthread_spin_unlock(&cond->lock);
            return -1;
        }

        for (;;)
        {
            pthread_spin_unlock(&cond->lock);
            {
                if (waiter)
                {
                    _ThreadWakeWait(waiter, self);
                    waiter = NULL;
                }
                else 
                {
                    _ThreadWait(self);
                }
            }
            pthread_spin_lock(&cond->lock);

            /* If self is no longer in the queue, then it was selected */
            if (!_queue_contains((queue_t*)&cond->queue, self))
                break;
        }
    }
    pthread_spin_unlock(&cond->lock);
    pthread_mutex_unlock(mutex);

    return 0;
}

int pthread_cond_timedwait(
    pthread_cond_t *cond, 
    pthread_mutex_t* mutex,
    struct timespec* ts)
{
    assert("pthread_cond_timedwait(): not implemented" == NULL);
    return -1;
}

int pthread_cond_signal(pthread_cond_t *cond)
{
    OE_ThreadData* waiter;

    pthread_spin_lock(&cond->lock);
    waiter = _queue_pop_front((queue_t*)&cond->queue);
    pthread_spin_unlock(&cond->lock);

    if (!waiter)
        return 0;

    _ThreadWake(waiter);
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t* cond)
{
    queue_t waiters = { NULL, NULL };

    pthread_spin_lock(&cond->lock);
    {
        OE_ThreadData* p;

        while ((p = _queue_pop_front((queue_t*)&cond->queue)))
            _queue_push_back(&waiters, p);
    }
    pthread_spin_unlock(&cond->lock);

    /* ATTN: write OCALL that does all this in one call */
    for (OE_ThreadData* p = waiters.front; p; p = p->next)
        _ThreadWake(p);

    return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond)
{
    if (!cond)
        return -1;

    pthread_spin_lock(&cond->lock);

    /* Fail if queue is not empty */
    if (cond->queue.front)
    {
        pthread_spin_unlock(&cond->lock);
        return -1;
    }

    pthread_spin_unlock(&cond->lock);

    return 0;
}

/*
**==============================================================================
**
** pthread_key_t (thread specific data)
**
**==============================================================================
*/

#define MAX_KEYS (OE_PAGE_SIZE / sizeof(void*))

typedef struct _key_slot_t
{
    bool used;
    void (*destructor)(void* value);
}
key_slot_t;

static key_slot_t _slots[MAX_KEYS];
static pthread_spinlock_t _lock = PTHREAD_SPINLOCK_INITIALIZER;

static void** _get_tsd_page(void)
{
    OE_ThreadData* td = OE_GetThreadData();

    if (!td)
        return NULL;

    return (void**)((unsigned char*)td + OE_PAGE_SIZE);
}

int pthread_key_create(pthread_key_t* key, void (*destructor)(void* value))
{
    int rc = -1;

    if (!key)
        return OE_INVALID_PARAMETER;

    /* Search for an available slot (the first slot is not used) */
    {
        pthread_spin_lock(&_lock);

        for (unsigned int i = 1; i < MAX_KEYS; i++)
        {
            /* If this key is available */
            if (!_slots[i].used)
            {
                /* Initialize this slot */
                _slots[i].used = true;
                _slots[i].destructor = destructor;

                /* Initialize new key */
                *key = i;

                rc = 0;
                break;
            }
        }

        pthread_spin_unlock(&_lock);
    }

    return rc;
}

int pthread_key_delete(pthread_key_t key)
{
    /* If key parameter is invalid */
    if (key == 0 || key >= MAX_KEYS)
        return -1;

    /* Mark this key as unused */
    {
        pthread_spin_lock(&_lock);

        /* Call destructor */
        if (_slots[key].destructor)
            _slots[key].destructor(pthread_getspecific(key));

        /* Clear this slot */
        _slots[key].used = false;
        _slots[key].destructor = NULL;

        pthread_spin_unlock(&_lock);
    }

    return 0;
}

int pthread_setspecific(pthread_key_t key, const void* value)
{
    void** tsd_page;

    if (key == 0)
        return -1;

    if (!(tsd_page = _get_tsd_page()))
        return -1;

    tsd_page[key] = (void*)value;

    return OE_OK;
}

void* pthread_getspecific(pthread_key_t key)
{
    void** tsd_page;

    if (key == 0 || key >= MAX_KEYS)
        return NULL;

    if (!(tsd_page = _get_tsd_page()))
        return NULL;

    return tsd_page[key];
}
