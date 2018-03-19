// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/enclave.h>
#include "td.h"

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

    if (OE_OCall(
            OE_FUNC_THREAD_WAIT,
            (uint64_t)tcs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWake(OE_ThreadData* self)
{
    const void* tcs = TD_ToTCS((TD*)self);

    if (OE_OCall(
            OE_FUNC_THREAD_WAKE,
            (uint64_t)tcs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        return -1;

    return 0;
}

static int _ThreadWakeWait(OE_ThreadData* waiter, OE_ThreadData* self)
{
    int ret = -1;
    OE_ThreadWakeWaitArgs* args = NULL;

    // OE_HostAllocForCallHost allocates memory on the host stack.
    // This allocated memory does not have to be explicitly freed.
    if (!(args =
              OE_HostAllocForCallHost(sizeof(OE_ThreadWakeWaitArgs), 0, false)))
        goto done;

    args->waiter_tcs = TD_ToTCS((TD*)waiter);
    args->self_tcs = TD_ToTCS((TD*)self);

    if (OE_OCall(
            OE_FUNC_THREAD_WAKE_WAIT,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    ret = 0;

done:
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
    OE_ThreadData* front;
    OE_ThreadData* back;
} Queue;

static void _QueuePushBack(Queue* queue, OE_ThreadData* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

static OE_ThreadData* _QueuePopFront(Queue* queue)
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

static bool _QueueContains(Queue* queue, OE_ThreadData* thread)
{
    OE_ThreadData* p;

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
** OE_Thread
**
**==============================================================================
*/

OE_Thread OE_ThreadSelf(void)
{
    return (OE_Thread)OE_GetThreadData();
}

int OE_ThreadEqual(OE_Thread thread1, OE_Thread thread2)
{
    return thread1 == thread2 ? 1 : 0;
}

/*
**==============================================================================
**
** OE_Mutex
**
**==============================================================================
*/

/* Internal mutex implementation */
typedef struct _OE_MutexImpl
{
    /* Lock used to synchronize access to OE_ThreadData queue */
    OE_Spinlock lock;

    /* Number of references to support recursive locking */
    unsigned int refs;

    /* The thread that has locked this mutex */
    OE_ThreadData* owner;

    /* Queue of waiting threads (front holds the mutex) */
    Queue queue;
} OE_MutexImpl;

OE_STATIC_ASSERT(sizeof(OE_MutexImpl) <= sizeof(OE_Mutex));

int OE_MutexInit(OE_Mutex* mutex)
{
    OE_MutexImpl* m = (OE_MutexImpl*)mutex;

    if (!m)
        return -1;

    OE_Memset(m, 0, sizeof(OE_Mutex));
    m->lock = OE_SPINLOCK_INITIALIZER;

    return 0;
}

/* Caller manages the spinlock */
static int _MutexLock(OE_MutexImpl* m, OE_ThreadData* self)
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

int OE_MutexLock(OE_Mutex* mutex)
{
    OE_MutexImpl* m = (OE_MutexImpl*)mutex;
    OE_ThreadData* self = OE_GetThreadData();

    if (!m)
        return -1;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        OE_SpinLock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (_MutexLock(m, self) == 0)
            {
                OE_SpinUnlock(&m->lock);
                return 0;
            }

            /* If the waiters queue does not contain this thread */
            if (!_QueueContains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                _QueuePushBack(&m->queue, self);
            }
        }
        OE_SpinUnlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        _ThreadWait(self);
    }

    /* Unreachable! */
}

int OE_MutexTryLock(OE_Mutex* mutex)
{
    OE_MutexImpl* m = (OE_MutexImpl*)mutex;
    OE_ThreadData* self = OE_GetThreadData();

    if (!m)
        return -1;

    OE_SpinLock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (_MutexLock(m, self) == 0)
        {
            OE_SpinUnlock(&m->lock);
            return 0;
        }
    }
    OE_SpinUnlock(&m->lock);

    return -1;
}

static int _MutexUnlock(OE_Mutex* mutex, OE_ThreadData** waiter)
{
    OE_MutexImpl* m = (OE_MutexImpl*)mutex;
    OE_ThreadData* self = OE_GetThreadData();
    int ret = -1;

    if (!m || !waiter)
        goto done;

    OE_SpinLock(&m->lock);
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
    OE_SpinUnlock(&m->lock);

done:
    return ret;
}

int OE_MutexUnlock(OE_Mutex* m)
{
    OE_ThreadData* waiter = NULL;

    if (!m)
        return -1;

    if (_MutexUnlock(m, &waiter) != 0)
        return -1;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        _ThreadWake(waiter);
    }

    return 0;
}

int OE_MutexDestroy(OE_Mutex* mutex)
{
    OE_MutexImpl* m = (OE_MutexImpl*)mutex;
    int ret = -1;

    if (!m)
        goto done;

    OE_SpinLock(&m->lock);
    {
        if (_QueueEmpty(&m->queue))
        {
            OE_Memset(m, 0, sizeof(OE_Mutex));
            ret = 0;
        }
    }
    OE_SpinUnlock(&m->lock);

done:
    return ret;
}

/*
**==============================================================================
**
** OE_Cond
**
**==============================================================================
*/

/* Internal condition variable implementation */
typedef struct _OE_CondImpl
{
    /* Spinlock for synchronizing access to thread queue and mutex parameter */
    OE_Spinlock lock;

    /* Queue of threads waiting on this condition variable */
    struct
    {
        OE_ThreadData* front;
        OE_ThreadData* back;
    } queue;
} OE_CondImpl;

OE_STATIC_ASSERT(sizeof(OE_CondImpl) <= sizeof(OE_Cond));

int OE_CondInit(OE_Cond* condition)
{
    OE_CondImpl* cond = (OE_CondImpl*)condition;

    if (cond)
    {
        OE_Memset(cond, 0, sizeof(OE_Cond));
        cond->lock = OE_SPINLOCK_INITIALIZER;
    }

    return 0;
}

int OE_CondDestroy(OE_Cond* condition)
{
    OE_CondImpl* cond = (OE_CondImpl*)condition;

    if (!cond)
        return -1;

    OE_SpinLock(&cond->lock);

    /* Fail if queue is not empty */
    if (cond->queue.front)
    {
        OE_SpinUnlock(&cond->lock);
        return -1;
    }

    OE_SpinUnlock(&cond->lock);

    return 0;
}

int OE_CondWait(OE_Cond* condition, OE_Mutex* mutex)
{
    OE_CondImpl* cond = (OE_CondImpl*)condition;
    OE_ThreadData* self = OE_GetThreadData();

    OE_SpinLock(&cond->lock);
    {
        OE_ThreadData* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        _QueuePushBack((Queue*)&cond->queue, self);

        /* Unlock whichever thread is waiting on this mutex (the waiter) */
        if (_MutexUnlock(mutex, &waiter) != 0)
        {
            OE_SpinUnlock(&cond->lock);
            return -1;
        }

        for (;;)
        {
            OE_SpinUnlock(&cond->lock);
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
            OE_SpinLock(&cond->lock);

            /* If self is no longer in the queue, then it was selected */
            if (!_QueueContains((Queue*)&cond->queue, self))
                break;
        }
    }
    OE_SpinUnlock(&cond->lock);
    OE_MutexLock(mutex);

    return 0;
}

int OE_CondSignal(OE_Cond* condition)
{
    OE_CondImpl* cond = (OE_CondImpl*)condition;
    OE_ThreadData* waiter;

    OE_SpinLock(&cond->lock);
    waiter = _QueuePopFront((Queue*)&cond->queue);
    OE_SpinUnlock(&cond->lock);

    if (!waiter)
        return 0;

    _ThreadWake(waiter);
    return 0;
}

int OE_CondBroadcast(OE_Cond* condition)
{
    OE_CondImpl* cond = (OE_CondImpl*)condition;
    Queue waiters = {NULL, NULL};

    OE_SpinLock(&cond->lock);
    {
        OE_ThreadData* p;

        while ((p = _QueuePopFront((Queue*)&cond->queue)))
            _QueuePushBack(&waiters, p);
    }
    OE_SpinUnlock(&cond->lock);

    OE_ThreadData* p_next = NULL;
    for (OE_ThreadData* p = waiters.front; p; p = p_next)
    {
        // p could wake up and immediately use a synchronization
        // primitve that could modify the next field.
        // Therefore fetch the next thread before waking up p.
        p_next = p->next;
        _ThreadWake(p);
    }

    return 0;
}

/*
**==============================================================================
**
** OE_RWLock
**
**==============================================================================
*/

/* Internal readers-writer lock variable implementation. */
typedef struct _OE_RWLockImpl
{
    /* Number of reader threads owning this lock. */
    unsigned int readers;

    /* Number of writer threads owning this lock. 0 or 1.*/
    unsigned int writers;

    /* Mutex for synchronizing readers and writers.
    ** Held only for a brief time.
    */
    OE_Mutex mutex;

    /* Condition variable that indicates whether the r/w lock is unlocked. */
    OE_Cond unlocked;
} OE_RWLockImpl;

OE_STATIC_ASSERT(sizeof(OE_RWLockImpl) <= sizeof(OE_RWLock));

int OE_RWLockInit(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_Memset(rwLock, 0, sizeof(OE_RWLock));
    OE_MutexInit(&rwLock->mutex);
    OE_CondInit(&rwLock->unlocked);

    return 0;
}

int OE_RWLockReadLock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    // Wait for writer to finish.
    // Multiple readers can concurrently operate.
    while (rwLock->writers > 0)
    {
        // Release mutex and wait for the r/w lock to be unlocked.
        OE_CondWait(&rwLock->unlocked, &rwLock->mutex);
    }

    // Increment number of readers.
    rwLock->readers++;

    OE_MutexUnlock(&rwLock->mutex);

    return 0;
}

int OE_RWLockTryReadLock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    int r = -1;
    // If no writer is active, then lock is successful.
    if (rwLock->writers == 0)
    {
        rwLock->readers++;
        r = 0;
    }

    OE_MutexUnlock(&rwLock->mutex);

    return r;
}

int OE_RWLockReadUnlock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    // There must be atleast 1 reader and no writers.
    if (rwLock->readers < 1 || rwLock->writers > 0)
    {
        OE_MutexUnlock(&rwLock->mutex);
        return -1;
    }

    if (--rwLock->readers == 0)
    {
        // This is the last reader.
        // Signal waiting threads by marking the r/w lock as unlocked.
        OE_CondBroadcast(&rwLock->unlocked);
    }

    OE_MutexUnlock(&rwLock->mutex);

    return 0;
}

int OE_RWLockWriteLock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    // Wait for all readers and any other writer to finish.
    while (rwLock->readers > 0 || rwLock->writers > 0)
    {
        // Release mutex and wait for the r/w lock to be unlocked.
        OE_CondWait(&rwLock->unlocked, &rwLock->mutex);
    }

    rwLock->writers = 1;
    OE_MutexUnlock(&rwLock->mutex);

    return 0;
}

int OE_RWLockTryWriteLock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    int r = -1;
    OE_MutexLock(&rwLock->mutex);

    // If no readers and no writers are active, then lock is successful.
    if (rwLock->readers == 0 && rwLock->writers == 0)
    {
        rwLock->writers = 1;
        r = 0;
    }

    OE_MutexUnlock(&rwLock->mutex);

    return r;
}

int OE_RWLockWriteUnlock(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    // There must be one writer and no readers.
    if (rwLock->writers != 1 || rwLock->readers > 0)
    {
        OE_MutexUnlock(&rwLock->mutex);
        return -1;
    }

    // Mark writer as done.
    rwLock->writers = 0;

    // Signal waiting threads by marking the lock as unlocked.
    OE_CondBroadcast(&rwLock->unlocked);

    OE_MutexUnlock(&rwLock->mutex);

    return 0;
}

int OE_RWLockDestroy(OE_RWLock* readWriteLock)
{
    OE_RWLockImpl* rwLock = (OE_RWLockImpl*)readWriteLock;

    if (!rwLock)
        return -1;

    OE_MutexLock(&rwLock->mutex);

    // There must not be any active readers or writers.
    if (rwLock->readers != 0 || rwLock->writers != 0)
    {
        OE_MutexUnlock(&rwLock->mutex);
        return -1;
    }

    OE_CondDestroy(&rwLock->unlocked);
    OE_MutexUnlock(&rwLock->mutex);
    OE_MutexDestroy(&rwLock->mutex);

    return 0;
}

/*
**==============================================================================
**
** OE_ThreadKey
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
static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

static void** _GetTSDPage(void)
{
    OE_ThreadData* td = OE_GetThreadData();

    if (!td)
        return NULL;

    return (void**)((unsigned char*)td + OE_PAGE_SIZE);
}

int OE_ThreadKeyCreate(OE_ThreadKey* key, void (*destructor)(void* value))
{
    int rc = -1;

    if (!key)
        return OE_INVALID_PARAMETER;

    /* Search for an available slot (the first slot is not used) */
    {
        OE_SpinLock(&_lock);

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

        OE_SpinUnlock(&_lock);
    }

    return rc;
}

int OE_ThreadKeyDelete(OE_ThreadKey key)
{
    /* If key parameter is invalid */
    if (key == 0 || key >= MAX_KEYS)
        return -1;

    /* Mark this key as unused */
    {
        OE_SpinLock(&_lock);

        /* Call destructor */
        if (_slots[key].destructor)
            _slots[key].destructor(OE_ThreadGetSpecific(key));

        /* Clear this slot */
        _slots[key].used = false;
        _slots[key].destructor = NULL;

        OE_SpinUnlock(&_lock);
    }

    return 0;
}

int OE_ThreadSetSpecific(OE_ThreadKey key, const void* value)
{
    void** tsd_page;

    if (key == 0)
        return -1;

    if (!(tsd_page = _GetTSDPage()))
        return -1;

    tsd_page[key] = (void*)value;

    return OE_OK;
}

void* OE_ThreadGetSpecific(OE_ThreadKey key)
{
    void** tsd_page;

    if (key == 0 || key >= MAX_KEYS)
        return NULL;

    if (!(tsd_page = _GetTSDPage()))
        return NULL;

    return tsd_page[key];
}
