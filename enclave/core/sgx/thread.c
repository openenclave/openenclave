// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "thread.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include "platform_t.h"
#include "td.h"

/*
**==============================================================================
**
** Host requests:
**
**==============================================================================
*/

static int _thread_wait(oe_sgx_td_t* self)
{
    const void* tcs = td_to_tcs((oe_sgx_td_t*)self);

    if (oe_ocall(OE_OCALL_THREAD_WAIT, (uint64_t)tcs, NULL) != OE_OK)
        return -1;

    return 0;
}

static int _thread_wake(oe_sgx_td_t* self)
{
    const void* tcs = td_to_tcs((oe_sgx_td_t*)self);

    if (oe_ocall(OE_OCALL_THREAD_WAKE, (uint64_t)tcs, NULL) != OE_OK)
        return -1;

    return 0;
}

oe_result_t _oe_sgx_thread_wake_wait_ocall(
    oe_enclave_t* enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs)
{
    OE_UNUSED(enclave);
    OE_UNUSED(waiter_tcs);
    OE_UNUSED(self_tcs);

    return OE_UNSUPPORTED;
}

OE_WEAK_ALIAS(_oe_sgx_thread_wake_wait_ocall, oe_sgx_thread_wake_wait_ocall);

static int _thread_wake_wait(oe_sgx_td_t* waiter, oe_sgx_td_t* self)
{
    int ret = -1;
    uint64_t waiter_tcs = (uint64_t)td_to_tcs((oe_sgx_td_t*)waiter);
    uint64_t self_tcs = (uint64_t)td_to_tcs((oe_sgx_td_t*)self);

    if (oe_sgx_thread_wake_wait_ocall(oe_get_enclave(), waiter_tcs, self_tcs) !=
        OE_OK)
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

typedef struct _queue
{
    oe_sgx_td_t* front;
    oe_sgx_td_t* back;
} Queue;

static void _queue_push_back(Queue* queue, oe_sgx_td_t* thread)
{
    thread->next = NULL;

    if (queue->back)
        queue->back->next = thread;
    else
        queue->front = thread;

    queue->back = thread;
}

static oe_sgx_td_t* _queue_pop_front(Queue* queue)
{
    oe_sgx_td_t* thread = queue->front;

    if (thread)
    {
        queue->front = queue->front->next;

        if (!queue->front)
            queue->back = NULL;
    }

    return thread;
}

static bool _queue_contains(Queue* queue, oe_sgx_td_t* thread)
{
    oe_sgx_td_t* p;

    for (p = queue->front; p; p = p->next)
    {
        if (p == thread)
            return true;
    }

    return false;
}

static __inline__ bool _queue_empty(Queue* queue)
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
    /* Lock used to synchronize access to oe_sgx_td_t queue */
    oe_spinlock_t lock;

    /* Number of references to support recursive locking */
    unsigned int refs;

    /* The thread that has locked this mutex */
    oe_sgx_td_t* owner;

    /* Queue of waiting threads (front holds the mutex) */
    Queue queue;
} oe_mutex_impl_t;

OE_STATIC_ASSERT(sizeof(oe_mutex_impl_t) <= sizeof(oe_mutex_t));

oe_result_t oe_mutex_init(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_result_t result = OE_UNEXPECTED;

    if (!m)
        return OE_INVALID_PARAMETER;

    memset(m, 0, sizeof(oe_mutex_t));
    m->lock = OE_SPINLOCK_INITIALIZER;

    result = OE_OK;

    return result;
}

/* Caller manages the spinlock */
static int _mutex_lock(oe_mutex_impl_t* m, oe_sgx_td_t* self)
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
            _queue_pop_front(&m->queue);

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
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!m)
        return OE_INVALID_PARAMETER;

    /* Loop until SELF obtains mutex */
    for (;;)
    {
        oe_spin_lock(&m->lock);
        {
            /* Attempt to acquire lock */
            if (_mutex_lock(m, self) == 0)
            {
                oe_spin_unlock(&m->lock);
                return OE_OK;
            }

            /* If the waiters queue does not contain this thread */
            if (!_queue_contains(&m->queue, self))
            {
                /* Insert thread at back of waiters queue */
                _queue_push_back(&m->queue, self);
            }
        }
        oe_spin_unlock(&m->lock);

        /* Ask host to wait for an event on this thread */
        _thread_wait(self);
    }

    /* Unreachable! */
}

oe_result_t oe_mutex_trylock(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!m)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&m->lock);
    {
        /* Attempt to acquire lock */
        if (_mutex_lock(m, self) == 0)
        {
            oe_spin_unlock(&m->lock);
            return OE_OK;
        }
    }
    oe_spin_unlock(&m->lock);

    return OE_BUSY;
}

static int _mutex_unlock(oe_mutex_t* mutex, oe_sgx_td_t** waiter)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;
    oe_sgx_td_t* self = oe_sgx_get_td();
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
    oe_sgx_td_t* waiter = NULL;

    if (!m)
        return OE_INVALID_PARAMETER;

    if (_mutex_unlock(m, &waiter) != 0)
        return OE_NOT_OWNER;

    if (waiter)
    {
        /* Ask host to wake up this thread */
        _thread_wake(waiter);
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
        if (_queue_empty(&m->queue))
        {
            memset(m, 0, sizeof(oe_mutex_t));
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
        oe_sgx_td_t* front;
        oe_sgx_td_t* back;
    } queue;
} oe_cond_impl_t;

OE_STATIC_ASSERT(sizeof(oe_cond_impl_t) <= sizeof(oe_cond_t));

oe_result_t oe_cond_init(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;
    oe_result_t result = OE_UNEXPECTED;

    if (!cond)
        return OE_INVALID_PARAMETER;

    memset(cond, 0, sizeof(oe_cond_t));
    cond->lock = OE_SPINLOCK_INITIALIZER;

    result = OE_OK;

    return result;
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
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!cond || !mutex)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);
    {
        oe_sgx_td_t* waiter = NULL;

        /* Add the self thread to the end of the wait queue */
        _queue_push_back((Queue*)&cond->queue, self);

        /* Unlock this mutex and get the waiter at the front of the queue */
        if (_mutex_unlock(mutex, &waiter) != 0)
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
                    _thread_wake_wait(waiter, self);
                    waiter = NULL;
                }
                else
                {
                    _thread_wait(self);
                }
            }
            oe_spin_lock(&cond->lock);

            /* If self is no longer in the queue, then it was selected */
            if (!_queue_contains((Queue*)&cond->queue, self))
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
    oe_sgx_td_t* waiter;

    if (!cond)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&cond->lock);
    waiter = _queue_pop_front((Queue*)&cond->queue);
    oe_spin_unlock(&cond->lock);

    if (!waiter)
        return OE_OK;

    _thread_wake(waiter);
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
        oe_sgx_td_t* p;

        while ((p = _queue_pop_front((Queue*)&cond->queue)))
            _queue_push_back(&waiters, p);
    }
    oe_spin_unlock(&cond->lock);

    oe_sgx_td_t* p_next = NULL;
    for (oe_sgx_td_t* p = waiters.front; p; p = p_next)
    {
        // p could wake up and immediately use a synchronization
        // primitive that could modify the next field.
        // Therefore fetch the next thread before waking up p.
        p_next = p->next;
        _thread_wake(p);
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
    oe_sgx_td_t* writer;

    /* Queue of threads waiting on this variable. */
    Queue queue;

} oe_rwlock_impl_t;

OE_STATIC_ASSERT(sizeof(oe_rwlock_impl_t) <= sizeof(oe_rwlock_t));

oe_result_t oe_rwlock_init(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_result_t result = OE_UNEXPECTED;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    memset(rw_lock, 0, sizeof(oe_rwlock_t));
    rw_lock->lock = OE_SPINLOCK_INITIALIZER;

    result = OE_OK;

    return result;
}

oe_result_t oe_rwlock_rdlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    // Wait for writer to finish.
    // Multiple readers can concurrently operate.
    while (rw_lock->writer != NULL)
    {
        // Add self to list of waiters, and go to wait state.
        if (!_queue_contains(&rw_lock->queue, self))
            _queue_push_back(&rw_lock->queue, self);

        oe_spin_unlock(&rw_lock->lock);
        _thread_wait(self);

        // Upon waking, re-acquire the lock.
        // Just like a condition variable.
        oe_spin_lock(&rw_lock->lock);
    }

    // Increment number of readers.
    rw_lock->readers++;

    oe_spin_unlock(&rw_lock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_tryrdlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    oe_result_t result = OE_BUSY;

    // If no writer is active, then lock is successful.
    if (rw_lock->writer == NULL)
    {
        rw_lock->readers++;
        result = OE_OK;
    }

    oe_spin_unlock(&rw_lock->lock);

    return result;
}

// The current thread must hold the spinlock.
// _wake_waiters releases ownership of the spinlock.
static oe_result_t _wake_waiters(oe_rwlock_impl_t* rw_lock)
{
    oe_sgx_td_t* p = NULL;
    Queue waiters = {NULL, NULL};

    // Take a snapshot of current list of waiters.
    while ((p = _queue_pop_front(&rw_lock->queue)))
        _queue_push_back(&waiters, p);

    // Release the lock and wake up the waiters. This allows waiter that is
    // woken up to immediately acquire the spinlock and subsequently, the
    // ownership of the rw_lock.
    oe_spin_unlock(&rw_lock->lock);

    // Wake the waiters in FIFO order. However actual acquisition of the lock
    // will be dependent on OS scheduling of the threads.
    while ((p = _queue_pop_front(&waiters)))
        _thread_wake(p);

    return OE_OK;
}

static oe_result_t _rwlock_rdunlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    // There must be at least 1 reader and no writers.
    if (rw_lock->readers < 1 || rw_lock->writer != NULL)
    {
        oe_spin_unlock(&rw_lock->lock);
        return OE_NOT_OWNER;
    }

    if (--rw_lock->readers == 0)
    {
        // This is the last reader. Wake up all waiting threads.
        return _wake_waiters(rw_lock);
    }

    oe_spin_unlock(&rw_lock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_wrlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    // Recursive writer lock.
    if (rw_lock->writer == self)
    {
        oe_spin_unlock(&rw_lock->lock);
        return OE_BUSY;
    }

    // Wait for all readers and any other writer to finish.
    while (rw_lock->readers > 0 || rw_lock->writer != NULL)
    {
        // Add self to list of waiters, and go to wait state.
        if (!_queue_contains(&rw_lock->queue, self))
            _queue_push_back(&rw_lock->queue, self);

        oe_spin_unlock(&rw_lock->lock);

        _thread_wait(self);

        // Upon waking, re-acquire the lock.
        // Just like a condition variable.
        oe_spin_lock(&rw_lock->lock);
    }

    rw_lock->writer = self;
    oe_spin_unlock(&rw_lock->lock);

    return OE_OK;
}

oe_result_t oe_rwlock_trywrlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_result_t result = OE_BUSY;
    oe_spin_lock(&rw_lock->lock);

    // If no readers and no writers are active, then lock is successful.
    if (rw_lock->readers == 0 && rw_lock->writer == NULL)
    {
        rw_lock->writer = self;
        result = OE_OK;
    }

    oe_spin_unlock(&rw_lock->lock);

    return result;
}

static oe_result_t _rwlock_wrunlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    // Self must be the owner.
    if (rw_lock->writer != self)
    {
        oe_spin_unlock(&rw_lock->lock);
        return OE_NOT_OWNER;
    }

    // No readers should exist.
    if (rw_lock->readers > 0)
    {
        oe_spin_unlock(&rw_lock->lock);
        return OE_BUSY;
    }

    // Mark writer as done.
    rw_lock->writer = NULL;

    // Wake waiting threads.
    return _wake_waiters(rw_lock);
}

oe_result_t oe_rwlock_destroy(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    oe_spin_lock(&rw_lock->lock);

    // There must not be any active readers or writers.
    if (rw_lock->readers != 0 || rw_lock->writer != NULL)
    {
        oe_spin_unlock(&rw_lock->lock);
        return OE_BUSY;
    }

    oe_spin_unlock(&rw_lock->lock);

    return OE_OK;
}

// For compatibility with pthread_rwlock API.
oe_result_t oe_rwlock_unlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;
    oe_sgx_td_t* self = oe_sgx_get_td();

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    // If the current thread is the writer that owns the lock, then call
    // oe_rwlock_wrunlock. Call oe_rwlock_rdunlock otherwise. No locking is
    // necessary here since the condition is expected to be true only when the
    // current thread is the writer thread.
    if (rw_lock->writer == self)
        return _rwlock_wrunlock(read_write_lock);
    else
        return _rwlock_rdunlock(read_write_lock);
}

/*
**==============================================================================
**
** oe_thread_key_t
**
**==============================================================================
*/

// We use the FS segment as both the start of the enclave thread data and the
// user thread-specific data (TSD) space. To prevent TSD from overwriting the
// enclave thread data, we reserve the first pthread_key indices up to
// MIN_THREAD_KEY_INDEX so that they are not used by oe_thread_key_create.
#define MIN_THREAD_KEY_INDEX \
    ((sizeof(oe_sgx_td_t) - OE_THREAD_SPECIFIC_DATA_SIZE) / sizeof(void*))
#define MAX_THREAD_KEY_INDEX (OE_PAGE_SIZE / sizeof(void*))

typedef struct _key_slot
{
    bool used;
    void (*destructor)(void* value);
} KeySlot;

static KeySlot _slots[MAX_THREAD_KEY_INDEX];
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

static void** _get_tsd_page(void)
{
    oe_thread_data_t* td = oe_get_thread_data();

    if (!td)
        return NULL;

    return (void**)td;
}

oe_result_t oe_thread_key_create(
    oe_thread_key_t* key,
    void (*destructor)(void* value))
{
    if (!key)
        return OE_INVALID_PARAMETER;

    oe_result_t result = OE_OUT_OF_MEMORY;

    /* Search for an available slot (the first slot is not used) */
    {
        oe_spin_lock(&_lock);

        for (unsigned int i = MIN_THREAD_KEY_INDEX; i < MAX_THREAD_KEY_INDEX;
             i++)
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
    if (key < MIN_THREAD_KEY_INDEX || key >= MAX_THREAD_KEY_INDEX)
        return OE_INVALID_PARAMETER;

    /* Mark this key as unused */
    {
        oe_spin_lock(&_lock);

        /* Clear this slot */
        _slots[key].used = false;
        _slots[key].destructor = NULL;

        oe_spin_unlock(&_lock);
    }

    return OE_OK;
}

oe_result_t oe_thread_setspecific(oe_thread_key_t key, const void* value)
{
    void** tsd_page;

    /* If key parameter is invalid */
    if (key < MIN_THREAD_KEY_INDEX || key >= MAX_THREAD_KEY_INDEX)
        return OE_INVALID_PARAMETER;

    if (!(tsd_page = _get_tsd_page()))
        return OE_INVALID_PARAMETER;

    tsd_page[key] = (void*)value;

    return OE_OK;
}

void* oe_thread_getspecific(oe_thread_key_t key)
{
    void** tsd_page;

    if (key < MIN_THREAD_KEY_INDEX || key >= MAX_THREAD_KEY_INDEX)
        return NULL;

    if (!(tsd_page = _get_tsd_page()))
        return NULL;

    return tsd_page[key];
}

void oe_thread_destruct_specific(void)
{
    void** tsd_page;

    /* Get the thread-specific-data page for the current thread. */
    if ((tsd_page = _get_tsd_page()))
    {
        oe_spin_lock(&_lock);
        {
            /* For each thread-specific-data key */
            for (oe_thread_key_t key = MIN_THREAD_KEY_INDEX;
                 key < MAX_THREAD_KEY_INDEX;
                 key++)
            {
                /* If this key is in use: */
                if (_slots[key].used)
                {
                    /* Call the destructor if any. */
                    if (_slots[key].destructor && tsd_page[key])
                        (_slots[key].destructor)(tsd_page[key]);

                    /* Clear the value. */
                    tsd_page[key] = NULL;
                }
            }
        }
        oe_spin_unlock(&_lock);
    }
}
