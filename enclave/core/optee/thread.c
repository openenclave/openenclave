// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// TODO: This file is a stub!

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>

/*
**==============================================================================
**
** Queue
**
**==============================================================================
*/

typedef void oe_thread_data_t;

typedef struct _queue
{
    oe_thread_data_t* front;
    oe_thread_data_t* back;
} Queue;

/*
**==============================================================================
**
** oe_thread_t
**
**==============================================================================
*/

static oe_thread_t g_thread;

oe_thread_t oe_thread_self(void)
{
    return (oe_thread_t)g_thread;
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
    oe_result_t result = OE_UNEXPECTED;

    if (!m)
        return OE_INVALID_PARAMETER;

    memset(m, 0, sizeof(oe_mutex_t));
    m->lock = OE_SPINLOCK_INITIALIZER;

    result = OE_OK;

    return result;
}

oe_result_t oe_mutex_lock(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;

    if (!m)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_mutex_trylock(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;

    if (!m)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_mutex_unlock(oe_mutex_t* m)
{
    if (!m)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_mutex_destroy(oe_mutex_t* mutex)
{
    oe_mutex_impl_t* m = (oe_mutex_impl_t*)mutex;

    if (!m)
        return OE_INVALID_PARAMETER;

    return OE_OK;
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

    if (!cond || !mutex)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_cond_signal(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;

    if (!cond)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_cond_broadcast(oe_cond_t* condition)
{
    oe_cond_impl_t* cond = (oe_cond_impl_t*)condition;

    if (!cond)
        return OE_INVALID_PARAMETER;

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

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_rwlock_tryrdlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_rwlock_wrlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_rwlock_trywrlock(oe_rwlock_t* read_write_lock)
{
    oe_rwlock_impl_t* rw_lock = (oe_rwlock_impl_t*)read_write_lock;

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
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

    if (!rw_lock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

/*
**==============================================================================
**
** oe_thread_key_t
**
**==============================================================================
*/

#define MAX_KEYS (OE_PAGE_SIZE / sizeof(void*))

typedef struct _key_slot
{
    bool used;
    void (*destructor)(void* value);
} KeySlot;

static KeySlot _slots[MAX_KEYS];
static KeySlot g_tsd_page[MAX_KEYS];
static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

static void** _get_tsd_page(void)
{
    return (void**)g_tsd_page;
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
    if (key == 0 || key >= MAX_KEYS)
        return OE_INVALID_PARAMETER;

    if (!(tsd_page = _get_tsd_page()))
        return OE_INVALID_PARAMETER;

    tsd_page[key] = (void*)value;

    return OE_OK;
}

void* oe_thread_getspecific(oe_thread_key_t key)
{
    void** tsd_page;

    if (key == 0 || key >= MAX_KEYS)
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
            for (oe_thread_key_t key = 1; key < MAX_KEYS; key++)
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
