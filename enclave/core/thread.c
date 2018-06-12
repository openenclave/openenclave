// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/sgxtypes.h>
#include "td.h"

/*
**==============================================================================
**
** Host requests:
**
**==============================================================================
*/

static int _ThreadWait(oe_thread_data_t* self)
{
    const void* tcs = TD_ToTCS((TD*)self);

    if (oe_ocall(
            OE_FUNC_THREAD_WAIT,
            (uint64_t)tcs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWake(oe_thread_data_t* self)
{
    const void* tcs = TD_ToTCS((TD*)self);

    if (oe_ocall(
            OE_FUNC_THREAD_WAKE,
            (uint64_t)tcs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWakeWait(oe_thread_data_t* waiter, oe_thread_data_t* self)
{
    int ret = -1;
    oe_thread_wake_wait_args_t* args = NULL;

    if (!(args = oe_host_alloc_for_call_host(sizeof(oe_thread_wake_wait_args_t))))
        goto done;

    args->waiter_tcs = TD_ToTCS((TD*)waiter);
    args->self_tcs = TD_ToTCS((TD*)self);

    if (oe_ocall(
            OE_FUNC_THREAD_WAKE_WAIT,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    ret = 0;

done:
    oe_host_free_for_call_host(args);
    return ret;
}

/*
**==============================================================================
**
** Queue
**
**==============================================================================
*/

typedef struct _Queue
{
    oe_thread_data_t* front;
    oe_thread_data_t* back;
} Queue;

static void _QueuePushBack(Queue* queue, oe_thread_data_t* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

static oe_thread_data_t* _QueuePopFront(Queue* queue)
{
    oe_thread_data_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->next;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

static bool _QueueContains(Queue* queue, oe_thread_data_t* thread)
{
    oe_thread_data_t* p;

    for (p = queue->front; p; p = p->next)
    {
        if (p == thread)
            return true;
    }

    return false;
}

static __inline__ bool _QueueEmpty(Queue* queue)
{
    return queue->front ? false : true;
}

/*
**==============================================================================
**
** oe_thread_t
**
**==============================================================================
*/

oe_thread_t oe_thread_self(void)
{
    return (oe_thread_t)oe_get_thread_data();
}

bool oe_thread_equal(oe_thread_t thread1, oe_thread_t thread2)
{
    return thread1 == thread2;
}

/*
**==============================================================================
**
** oe_mutex_t
**
**==============================================================================
*/

/* Internal mutex implementation */
typedef struct _oe_mutex_impl
{
    /* Lock used to synchronize access to oe_thread_data_t queue */
    oe_spinlock_t lock;

    /* Number of references to support recursive locking */
    unsigned int refs;

    /* The thread that has locked this mutex */
    oe_thread_data_t* owner;

    /* Queue of waiting threads (front holds the mutex) */
    Queue queue;
} oe_mutex_impl_t;

OE_STATIC_ASSERT(sizeof(oe_mutex_impl_t) <= sizeof(oe_mutex_t));

oe_result_t oe_mutex_init(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;

    if (!m)
        return OE_INVALID_PARAMETER;

    oe_memset(m, 0, sizeof(oe_mutex_t));
    m->lock = OE_SPINLOCK_INITIALIZER;

    return OE_OK;
}

/* Caller manages the spinlock */
static int _MutexLock(oe_mutex_impl_t* m, oe_thread_data_t* self)
{
    /* If this thread has already locked the mutex */
    if (m->owner == self)
    {
        /* Increase the reference count */
        m->refs++;
        return 0;
    }

    /* If no thread has locked this mutex yet */
    if (m->owner == NULL)
    {
        /* If the waiters queue is empty */
        if (m->queue.front == NULL)
        {
            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }

        /* If this thread is at the front of the waiters queue */
        if (m->queue.front == self)
        {
            /* Remove this thread from front of the waiters queue */
            _QueuePopFront(&m->queue);

            /* Obtain the mutex */
            m->owner = self;
            m->refs = 1;
            return 0;
        }
    }

    return -1;
}

oe_result_t oe_mutex_lock(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!m)
        return OE_INVALID_PARAMETER;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        oe_spin_lock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (_MutexLock(m, self) == 0)
            {
                oe_spin_unlock(&m->lock);
                return OE_OK;
            }

            /* If the waiters queue does not contain this thread */
            if (!_QueueContains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                _QueuePushBack(&m->queue, self);
            }
        }
        oe_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        _ThreadWait(self);
    }

    /* Unreachable! */
}

oe_result_t oe_mutex_try_lock(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!m)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (_MutexLock(m, self) == 0)
        {
            oe_spin_unlock(&m->lock);
            return OE_OK;
        }
    }
    oe_spin_unlock(&m->lock);

    return OE_BUSY;
}

static int _MutexUnlock(oe_mutex_t* mutex, oe_thread_data_t** waiter)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_thread_data_t* self = oe_get_thread_data();
    int ret = -1;

    oe_spin_lock(&m->lock);
    {
        /* If this thread has the mutex locked */
        if (m->owner == self)
        {
            /* If decreasing the reference count causes it to become zero */
            if (--m->refs == 0)
            {
                /* Thread no longer has this mutex locked */
                m->owner = NULL;

                /* Set waiter to the next thread on the queue (maybe none) */
                *waiter = m->queue.front;
            }

            ret = 0;
        }
    }
    oe_spin_unlock(&m->lock);

    return ret;
}

oe_result_t oe_mutex_unlock(oe_mutex_t* m)
{
    oe_thread_data_t* waiter = NULL;

    if (!m)
        return OE_INVALID_PARAMETER;

    if (_MutexUnlock(m, &waiter) != 0)
        return OE_NOT_OWNER;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        _ThreadWake(waiter);
    }

    return OE_OK;
}

oe_result_t oe_mutex_destroy(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;

    if (!m)
        return OE_INVALID_PARAMETER;

    oe_result_t result = OE_BUSY;

    oe_spin_lock(&m->lock);
    {
        if (_QueueEmpty(&m->queue))
        {
            oe_memset(m, 0, sizeof(oe_mutex_t));
            result = OE_OK;
        }
    }
    oe_spin_unlock(&m->lock);

    return result;
}

/*
**==============================================================================
**
** oe_cond_t
**
**==============================================================================
*/

/* Internal condition variable implementation */
typedef struct _oe_cond_impl
{
    /* Spinlock for synchronizing access to thread queue and mutex parameter */
    oe_spinlock_t lock;

    /* Queue of threads waiting on this condition variable */
    struct
    {
        oe_thread_data_t* front;
        oe_thread_data_t* back;
    } queue;
} oe_cond_impl_t;

OE_STATIC_ASSERT(sizeof(oe_cond_impl_t) <= sizeof(oe_cond_t));

oe_result_t oe_cond_init(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;

    if (!cond)
        return OE_INVALID_PARAMETER;

    oe_memset(cond, 0, sizeof(oe_cond_t));
    cond->lock = OE_SPINLOCK_INITIALIZER;

    return OE_OK;
}

oe_result_t oe_cond_destroy(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;

    if (!cond)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);

    /* Fail if queue is not empty */
    if (cond->queue.front)
    {
        oe_spin_unlock(&cond->lock);
        return OE_BUSY;
    }

    oe_spin_unlock(&cond->lock);

    return OE_OK;
}

oe_result_t oe_cond_wait(oe_cond_t* condition, oe_mutex_t* mutex)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!cond || !mutex)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);
    {
        oe_thread_data_t* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        _QueuePushBack((Queue*)&cond->queue, self);

        /* Unlock this mutex and get the waiter at the front of the queue */
        if (_MutexUnlock(mutex, &waiter) != 0)
        {
            oe_spin_unlock(&cond->lock);
            return OE_BUSY;
        }

        for (;;)
        {
            oe_spin_unlock(&cond->lock);
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
            oe_spin_lock(&cond->lock);

            /* If self is no longer in the queue, then it was selected */
            if (!_QueueContains((Queue*)&cond->queue, self))
                break;
        }
    }
    oe_spin_unlock(&cond->lock);
    oe_mutex_lock(mutex);

    return OE_OK;
}

oe_result_t oe_cond_signal(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;
    oe_thread_data_t* waiter;

    if (!cond)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);
    waiter = _QueuePopFront((Queue*)&cond->queue);
    oe_spin_unlock(&cond->lock);

    if (!waiter)
        return OE_OK;

    _ThreadWake(waiter);
    return OE_OK;
}

oe_result_t oe_cond_broadcast(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;
    Queue waiters = {NULL, NULL};

    if (!cond)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);
    {
        oe_thread_data_t* p;

        while ((p = _QueuePopFront((Queue*)&cond->queue)))
            _QueuePushBack(&waiters, p);
    }
    oe_spin_unlock(&cond->lock);

    oe_thread_data_t* p_next = NULL;
    for (oe_thread_data_t* p = waiters.front; p; p = p_next)
    {
        // p could wake up and immediately use a synchronization
        // primitive that could modify the next field.
        // Therefore fetch the next thread before waking up p.
        p_next = p->next;
        _ThreadWake(p);
    }

    return OE_OK;
}

/*
**==============================================================================
**
** oe_rwlock_t
**
**==============================================================================
*/

/* Internal readers-writer lock variable implementation. */
typedef struct _oe_rwlock_impl
{
    /* Spinlock for synchronizing readers and writers.*/
    oe_spinlock_t lock;

    /* Number of reader threads owning this lock. */
    uint32_t readers;

    /* The writer thread that currently owns this lock.*/
    oe_thread_data_t* writer;

    /* Queue of threads waiting on this variable. */
    Queue queue;

} oe_rwlock_impl_t;

OE_STATIC_ASSERT(sizeof(oe_rwlock_impl_t) <= sizeof(oe_rwlock_t));

oe_result_t oe_rwlock_init(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_memset(rwLock, 0, sizeof(oe_rwlock_t));
    rwLock->lock = OE_SPINLOCK_INITIALIZER;

    return OE_OK;
}

oe_result_t oe_rwlock_read_lock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    // Wait for writer to finish.
    // Multiple readers can concurrently operate.
    while (rwLock->writer != NULL)
    {
        // Add self to list of waiters, and go to wait state.
        if (!_QueueContains(&rwLock->queue, self))
            _QueuePushBack(&rwLock->queue, self);

        oe_spin_unlock(&rwLock->lock);
        _ThreadWait(self);

        // Upon waking, re-acquire the lock.
        // Just like a condition variable.
        oe_spin_lock(&rwLock->lock);
    }

    // Increment number of readers.
    rwLock->readers++;

    oe_spin_unlock(&rwLock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_try_read_lock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    oe_result_t result = OE_BUSY;

    // If no writer is active, then lock is successful.
    if (rwLock->writer == NULL)
    {
        rwLock->readers++;
        result = OE_OK;
    }

    oe_spin_unlock(&rwLock->lock);

    return result;
}

// The current thread must hold the spinlock.
// _WakeWaiters releases ownership of the spinlock.
static oe_result_t _WakeWaiters(oe_rwlock_impl_t* rwLock)
{
    oe_thread_data_t* p = NULL;
    Queue waiters = {NULL, NULL};

    // Take a snapshot of current list of waiters.
    while ((p = _QueuePopFront(&rwLock->queue)))
        _QueuePushBack(&waiters, p);

    // Release the lock and wake up the waiters. This allows waiter that is
    // woken up to immediately acquire the spinlock and subsequently, the
    // ownership of the rwLock.
    oe_spin_unlock(&rwLock->lock);

    // Wake the waiters in FIFO order. However actual acquisition of the lock
    // will be dependent on OS scheduling of the threads.
    while ((p = _QueuePopFront(&waiters)))
        _ThreadWake(p);

    return OE_OK;
}

oe_result_t oe_rwlock_read_unlock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    // There must be at least 1 reader and no writers.
    if (rwLock->readers < 1 || rwLock->writer != NULL)
    {
        oe_spin_unlock(&rwLock->lock);
        return OE_NOT_OWNER;
    }

    if (--rwLock->readers == 0)
    {
        // This is the last reader. Wake up all waiting threads.
        return _WakeWaiters(rwLock);
    }

    oe_spin_unlock(&rwLock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_write_lock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    // Recursive writer lock.
    if (rwLock->writer == self)
    {
        oe_spin_unlock(&rwLock->lock);
        return OE_BUSY;
    }

    // Wait for all readers and any other writer to finish.
    while (rwLock->readers > 0 || rwLock->writer != NULL)
    {
        // Add self to list of waiters, and go to wait state.
        if (!_QueueContains(&rwLock->queue, self))
            _QueuePushBack(&rwLock->queue, self);

        oe_spin_unlock(&rwLock->lock);

        _ThreadWait(self);

        // Upon waking, re-acquire the lock.
        // Just like a condition variable.
        oe_spin_lock(&rwLock->lock);
    }

    rwLock->writer = self;
    oe_spin_unlock(&rwLock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_try_write_lock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_result_t result = OE_BUSY;
    oe_spin_lock(&rwLock->lock);

    // If no readers and no writers are active, then lock is successful.
    if (rwLock->readers == 0 && rwLock->writer == NULL)
    {
        rwLock->writer = self;
        result = OE_OK;
    }

    oe_spin_unlock(&rwLock->lock);

    return result;
}

oe_result_t oe_rwlock_write_unlock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    // Self must be the owner.
    if (rwLock->writer != self)
    {
        oe_spin_unlock(&rwLock->lock);
        return OE_NOT_OWNER;
    }

    // No readers should exist.
    if (rwLock->readers > 0)
    {
        oe_spin_unlock(&rwLock->lock);
        return OE_BUSY;
    }

    // Mark writer as done.
    rwLock->writer = NULL;

    // Wake waiting threads.
    return _WakeWaiters(rwLock);
}

oe_result_t oe_rwlock_destroy(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rwLock->lock);

    // There must not be any active readers or writers.
    if (rwLock->readers != 0 || rwLock->writer != NULL)
    {
        oe_spin_unlock(&rwLock->lock);
        return OE_BUSY;
    }

    oe_spin_unlock(&rwLock->lock);

    return OE_OK;
}

// For compatibility with pthread_rwlock API.
oe_result_t oe_rwlock_unlock(oe_rwlock_t* readWriteLock)
{
    oe_rwlock_impl_t* rwLock = (oe_rwlock_impl_t*)readWriteLock;
    oe_thread_data_t* self = oe_get_thread_data();

    if (!rwLock)
        return OE_INVALID_PARAMETER;

    // If the current thread is the writer that owns the lock, then call
    // oe_rwlock_write_unlock. Call oe_rwlock_read_unlock otherwise. No locking is
    // necessary here since the condition is expected to be true only when the
    // current thread is the writer thread.
    if (rwLock->writer == self)
        return oe_rwlock_write_unlock(readWriteLock);
    else
        return oe_rwlock_read_unlock(readWriteLock);
}

/*
**==============================================================================
**
** oe_thread_key_t
**
**==============================================================================
*/

#define MAX_KEYS (OE_PAGE_SIZE / sizeof(void*))

typedef struct _KeySlot
{
    bool used;
    void (*destructor)(void* value);
} KeySlot;

static KeySlot _slots[MAX_KEYS];
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

static void** _GetTSDPage(void)
{
    oe_thread_data_t* td = oe_get_thread_data();

    if (!td)
        return NULL;

    return (void**)((unsigned char*)td + OE_PAGE_SIZE);
}

oe_result_t oe_thread_key_create(oe_thread_key_t* key, void (*destructor)(void* value))
{
    if (!key)
        return OE_INVALID_PARAMETER;

    oe_result_t result = OE_OUT_OF_MEMORY;

    /* Search for an available slot (the first slot is not used) */
    {
        oe_spin_lock(&_lock);

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

                result = OE_OK;
                break;
            }
        }

        oe_spin_unlock(&_lock);
    }

    return result;
}

oe_result_t oe_thread_key_delete(oe_thread_key_t key)
{
    /* If key parameter is invalid */
    if (key == 0 || key >= MAX_KEYS)
        return OE_INVALID_PARAMETER;

    /* Mark this key as unused */
    {
        oe_spin_lock(&_lock);

        /* Call destructor */
        if (_slots[key].destructor)
            _slots[key].destructor(oe_thread_get_specific(key));

        /* Clear this slot */
        _slots[key].used = false;
        _slots[key].destructor = NULL;

        oe_spin_unlock(&_lock);
    }

    return OE_OK;
}

oe_result_t oe_thread_set_specific(oe_thread_key_t key, const void* value)
{
    void** tsd_page;

    /* If key parameter is invalid */
    if (key == 0 || key >= MAX_KEYS)
        return OE_INVALID_PARAMETER;

    if (!(tsd_page = _GetTSDPage()))
        return OE_INVALID_PARAMETER;

    tsd_page[key] = (void*)value;

    return OE_OK;
}

void* oe_thread_get_specific(oe_thread_key_t key)
{
    void** tsd_page;

    if (key == 0 || key >= MAX_KEYS)
        return NULL;

    if (!(tsd_page = _GetTSDPage()))
        return NULL;

    return tsd_page[key];
}
