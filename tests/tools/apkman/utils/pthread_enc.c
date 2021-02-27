// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/pthreadhooks.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include <pthread.h>

#include "pthread_t.h"

typedef struct _thread_info
{
    pthread_t pthread_id;
    uint64_t host_thread_id;
    void* arg;
    void* (*function)(void*);
    void* ret_val;
    uint64_t ref_count;
    bool done;
    struct _thread_info* next;
    struct _thread_info* prev;
} oe_thread_info_t;

static oe_thread_info_t* _waiting = NULL;
static oe_thread_info_t* _running = NULL;
static oe_spinlock_t _lock;

extern void* oe_malloc(long n);
extern void oe_free(void* p);

static oe_thread_info_t* _thread_info_new(
    void* (*start_routine)(void*),
    void* arg)
{
    oe_thread_info_t* thread = (oe_thread_info_t*)oe_malloc(sizeof(*thread));
    thread->pthread_id = NULL;
    thread->host_thread_id = (uint64_t)-1;
    thread->arg = arg;
    thread->function = start_routine;
    thread->ret_val = NULL;
    thread->ref_count = 0;
    thread->next = NULL;
    thread->prev = NULL;
    return thread;
}

static void _thread_info_inc_ref(oe_thread_info_t* thread)
{
    oe_atomic_increment(&thread->ref_count);
}

static void _thread_info_dec_ref(oe_thread_info_t* thread)
{
    oe_spin_lock(&_lock);
    if (oe_atomic_decrement(&thread->ref_count) == 0)
    {
        if (thread->prev)
        {
            thread->prev->next = thread->next;
            if (thread->next)
                thread->next->prev = thread->prev;
        }
        else if (_running == thread)
        {
            _running = thread->next;
            if (_running)
                _running->prev = NULL;
        }
        oe_free(thread);
    }
    oe_spin_unlock(&_lock);
}

static int _pthread_create_hook(
    pthread_t* enc_thread,
    const pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    OE_UNUSED(attr);
    oe_result_t result = OE_UNEXPECTED;
    oe_thread_info_t* thread = _thread_info_new(start_routine, arg);

    {
        oe_spin_lock(&_lock);
        thread->next = _waiting;
        _waiting = thread;
        oe_spin_unlock(&_lock);
    }
    _thread_info_inc_ref(thread);

    OE_CHECK(oe_host_thread_create_ocall(oe_get_enclave()));
    if (thread->pthread_id == NULL)
        OE_RAISE(OE_FAILURE);
    *enc_thread = thread->pthread_id;

    _thread_info_dec_ref(thread);
    result = OE_OK;
done:
    return result == OE_OK ? 0 : -1;
}

// Launches the new thread in the enclave
void oe_enclave_thread_launch_ecall(
    uint64_t host_thread_id,
    uint64_t* thread_started)
{
    oe_result_t result = OE_UNEXPECTED;
    if (!oe_is_outside_enclave(thread_started, sizeof(*thread_started)))
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_thread_info_t* thread = NULL;
    {
        oe_spin_lock(&_lock);
        if (_waiting)
        {
            thread = _waiting;
            _waiting = thread->next;

            thread->next = _running;
            if (_running)
                _running->prev = thread;
            _running = thread;
        }
        oe_spin_unlock(&_lock);
    }

    if (!thread)
        OE_RAISE(OE_INVALID_PARAMETER);

    _thread_info_inc_ref(thread);
    thread->pthread_id = pthread_self();
    thread->host_thread_id = host_thread_id;
    oe_atomic_increment(thread_started);

    thread->ret_val = thread->function(thread->arg);
    // needs acquire release since done must be set after ret_val
    thread->done = true;
    _thread_info_dec_ref(thread);

done:
    return;
}

static int _pthread_join_hook(pthread_t enc_thread, void** retval)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_thread_info_t* thread = NULL;
    {
        oe_spin_lock(&_lock);
        for (oe_thread_info_t* t = _running; t; t = t->next)
        {
            if (t->pthread_id == enc_thread)
            {
                thread = t;
                _thread_info_inc_ref(thread);
                break;
            }
        }
        oe_spin_unlock(&_lock);
    }
    if (!thread)
    {
        // OE_RAISE(OE_NOT_FOUND);
        // Assume that the thread has exited.
        result = OE_OK;
        goto done;
    }

    int r = 0;
    while (!thread->done)
    {
        OE_CHECK(
            oe_host_thread_join_ocall(&r, thread->host_thread_id) == OE_OK);
    }
    *retval = thread->ret_val;
    if (r == 0)
        result = OE_OK;
done:
    if (thread)
        _thread_info_dec_ref(thread);
    return (result == OE_OK) ? 0 : -1;
}

static int _pthread_detach_hook(pthread_t enc_thread)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_thread_info_t* thread = NULL;
    {
        oe_spin_lock(&_lock);
        for (oe_thread_info_t* t = _running; t; t = t->next)
        {
            if (t->pthread_id == enc_thread)
            {
                thread = t;
                _thread_info_inc_ref(thread);
                if (thread->prev)
                    thread->prev->next = thread->next;
                if (thread->next)
                    thread->next->prev = thread->prev;
                thread->prev = thread->next = NULL;
                break;
            }
        }
        oe_spin_unlock(&_lock);
    }
    if (!thread)
        OE_RAISE(OE_NOT_FOUND);

    int r = 0;
    OE_CHECK(oe_host_thread_detach_ocall(&r, thread->host_thread_id));
    if (r == 0)
        result = OE_OK;

done:
    if (thread)
        _thread_info_dec_ref(thread);

    return (result == OE_OK) ? 0 : -1;
}

static oe_pthread_hooks_t _hooks = {.create = _pthread_create_hook,
                                    .join = _pthread_join_hook,
                                    .detach = _pthread_detach_hook};

void register_pthread_hooks()
{
    oe_register_pthread_hooks(&_hooks);
}

__attribute__((constructor)) static void _initializer(void)
{
    register_pthread_hooks();
}
