// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/pthread.h>
#include <openenclave/corelibc/sched.h>
#include <openenclave/corelibc/setjmp.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/atomic.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>

#include "platform_t.h"

typedef struct _thread_info
{
    // The id of this thread. Monotonically increasing calue that
    // is unique within the enclave.
    oe_pthread_t pthread_id;
    // The id of the corresponding host thread.
    uint64_t host_thread_id;

    // Thread function and argument.
    void* (*function)(void*);
    void* arg;

    // The return value of the thread function.
    // This can also be set via pthread_exit.
    void* ret_val;

    // The jmp_buf used by pthread_exit.
    oe_jmp_buf jmp_buf;

    // Is this thread joinable.
    bool joinable;
    bool joined;
    bool terminated;

    // Linked list nodes.
    struct _thread_info* next;
    struct _thread_info* prev;

    uint64_t ref_count;

} oe_thread_info_t;

static oe_thread_info_t* _waiting = NULL;
static oe_thread_info_t* _running = NULL;
static oe_thread_info_t* _exited = NULL;

static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
static oe_once_t _once = OE_ONCE_INITIALIZER;

static void _free_thread_info(oe_thread_info_t* thread_info)
{
    oe_thread_info_t* next = thread_info->next;
    oe_thread_info_t* prev = thread_info->prev;

    if (next)
        next->prev = prev;

    if (prev)
        prev->next = next;
    else
    {
        if (_running == thread_info)
            _running = next;
        else if (_waiting == thread_info)
            _waiting = next;
        else if (_exited == thread_info)
            _exited = next;
    }

    oe_memset_s(thread_info, sizeof(*thread_info), 0, sizeof(*thread_info));
    oe_free(thread_info);
}

static void _cleanup_thread_infos(void)
{
    oe_spin_lock(&_lock);

    while (_waiting)
        _free_thread_info(_waiting);

    while (_running)
        _free_thread_info(_running);

    while (_exited)
        _free_thread_info(_exited);

    oe_spin_unlock(&_lock);
}

static void _thread_info_inc_ref(oe_thread_info_t* thread_info)
{
    oe_atomic_increment(&thread_info->ref_count);
}

static void _thread_info_dec_ref(oe_thread_info_t* thread_info)
{
    oe_spin_lock(&_lock);
    if (oe_atomic_decrement(&thread_info->ref_count) == 0)
    {
        // If the thread is joinable, then we need to wait for it to be joined
        // before releasing all resources.
        if (!thread_info->joinable || thread_info->joined)
            _free_thread_info(thread_info);
    }
    oe_spin_unlock(&_lock);
}

static oe_thread_info_t* _get_thread_info(
    oe_pthread_t thread_id,
    oe_thread_info_t* list)
{
    oe_thread_info_t* thread_info = NULL;
    bool fetch_last = (list == _exited);
    for (oe_thread_info_t* t = list; t; t = t->next)
    {
        if (t->pthread_id == thread_id)
        {
            thread_info = t;
            if (!fetch_last)
                break;
        }
    }
    if (thread_info)
        _thread_info_inc_ref(thread_info);

    return thread_info;
}

static void _register_cleanup_thread_infos(void)
{
    oe_atexit(_cleanup_thread_infos);
}

static oe_thread_info_t* _thread_info_new(
    void* (*start_routine)(void*),
    void* arg)
{
    oe_thread_info_t* thread_info =
        (oe_thread_info_t*)oe_malloc(sizeof(*thread_info));
    oe_memset_s(thread_info, sizeof(*thread_info), 0, sizeof(*thread_info));

    thread_info->arg = arg;
    thread_info->function = start_routine;
    thread_info->joinable = true;

    oe_once(&_once, _register_cleanup_thread_infos);

    return thread_info;
}

int oe_pthread_create(
    oe_pthread_t* thread,
    const oe_pthread_attr_t* attr,
    void* (*start_routine)(void*),
    void* arg)
{
    int ret = OE_EAGAIN;
    oe_thread_info_t* thread_info = _thread_info_new(start_routine, arg);
    bool detached = attr ? attr->detachstate : false;
    thread_info->joinable = !detached;

    // Add the thread_info to list of waiting threads.
    {
        oe_spin_lock(&_lock);
        thread_info->next = _waiting;
        _waiting = thread_info;

        // Increment the ref count so that we can be sure that the info will
        // be alive till end of this function.
        _thread_info_inc_ref(thread_info);
        oe_spin_unlock(&_lock);
    }

    // Ask host to launch a new thread.
    {
        int r = 0;
        if (oe_host_thread_create_ocall(&r, oe_get_enclave(), detached) !=
                OE_OK ||
            r != 0)
        {
            // Insufficient resources to create a thread.
            ret = OE_EAGAIN;
            goto done;
        }
    }

    // Wait until a thread-id is assigned.
    while (thread_info->pthread_id == 0)
        oe_sched_yield();

    // At this point, the thread info has been moved from waiting to running
    // list.

    *thread = thread_info->pthread_id;
    ret = 0;
done:
    if (thread_info)
        _thread_info_dec_ref(thread_info);

    return ret;
}

// Launches the new thread in the enclave.
void oe_enclave_thread_launch_ecall(
    uint64_t host_thread_id,
    uint64_t* thread_started)
{
    oe_result_t result = OE_UNEXPECTED;
    if (!oe_is_outside_enclave(thread_started, sizeof(*thread_started)))
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_thread_info_t* thread_info = NULL;
    oe_spin_lock(&_lock);

    // Pop the first waiting thread info.
    if (_waiting)
    {
        thread_info = _waiting;
        _waiting = thread_info->next;
        thread_info->prev = thread_info->prev = NULL;
    }

    // Add the thread info to list of running threads.
    if (thread_info)
    {
        thread_info->next = _running;
        if (_running)
            _running->prev = thread_info;
        _running = thread_info;

        // Set the host thread id.
        thread_info->host_thread_id = host_thread_id;
        thread_info->prev = NULL;

        _thread_info_inc_ref(thread_info);
    }

    oe_spin_unlock(&_lock);

    if (!thread_info)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Set the thread id. It is important that the id is set as the final item
    // during thread launch. pthread_create waits on the id.
    thread_info->pthread_id = oe_pthread_self();
    *thread_started = 1;

    if (oe_setjmp(&thread_info->jmp_buf) == 0)
    {
        thread_info->ret_val = thread_info->function(thread_info->arg);
    }
    else
    {
        // Reach here via a pthread_exit.
    }

    // Move the thread from running to exited list.
    oe_spin_lock(&_lock);
    {
        // Remove from running list.
        oe_thread_info_t* next = thread_info->next;
        oe_thread_info_t* prev = thread_info->prev;

        if (next)
            next->prev = prev;

        if (prev)
            prev->next = next;
        else
            _running = next;

        // Add to exited list.
        thread_info->prev = NULL;
        thread_info->next = _exited;
        if (_exited)
            _exited->prev = thread_info;
        _exited = thread_info;
    }
    // Mark the thread as terminated.
    thread_info->terminated = true;
    oe_spin_unlock(&_lock);

    _thread_info_dec_ref(thread_info);

done:
    return;
}

int oe_pthread_join(oe_pthread_t thread_id, void** retval)
{
    oe_thread_info_t* thread_info = NULL;
    int ret = -1;

    {
        oe_spin_lock(&_lock);
        thread_info = _get_thread_info(thread_id, _exited);
        if (!thread_info)
            thread_info = _get_thread_info(thread_id, _running);
        if (!thread_info)
            thread_info = _get_thread_info(thread_id, _waiting);
        oe_spin_unlock(&_lock);
    }

    if (!thread_info)
    {
        // No thread found with given id.
        ret = OE_ESRCH;
        goto done;
    }

    if (!thread_info->joinable)
    {
        ret = OE_EINVAL;
        goto done;
    }

    // Issue a join call to the host.
    {
        int r = -1;
        // Wait until the host thread is joined. This is essential for two
        // reasons:
        // - Ensure that the host thread resources are released. A joinable
        //   thread must be joined for resources to be released.
        // - Ensure that the ecall for the thread has completed. Otherwise, the
        //   joining thread may continue execution and perform
        //   oe_terminate_enclave before the joined thread has returned from the
        //   ecall.
        while (!thread_info->terminated || r != 0)
            oe_host_thread_join_ocall(&r, thread_info->host_thread_id);
    }

    thread_info->joined = true;
    if (retval)
        *retval = thread_info->ret_val;
    ret = 0;

done:
    if (thread_info)
        _thread_info_dec_ref(thread_info);
    return ret;
}

int oe_pthread_detach(oe_pthread_t thread_id)
{
    int ret = -1;
    oe_thread_info_t* thread_info = NULL;

    {
        oe_spin_lock(&_lock);
        thread_info = _get_thread_info(thread_id, _exited);
        if (!thread_info)
            thread_info = _get_thread_info(thread_id, _running);
        if (!thread_info)
            thread_info = _get_thread_info(thread_id, _waiting);
        oe_spin_unlock(&_lock);
    }

    if (!thread_info)
    {
        // No thread found with given id.
        ret = OE_ESRCH;
        goto done;
    }

    if (!thread_info->joinable)
    {
        // The thread is not joinable.
        ret = OE_EINVAL;
        goto done;
    }

    // Mark the thread as not joinable.
    thread_info->joinable = false;

    // Issue a host call to mark the OS thread as detached.
    {
        int r = 0;
        oe_host_thread_detach_ocall(&r, thread_info->host_thread_id);
        // Even if the host does not honor the call, enclave security is not
        // affected.
    }

    ret = 0;

done:
    if (thread_info)
        _thread_info_dec_ref(thread_info);

    return ret;
}

OE_NO_RETURN
void oe_pthread_exit(void* retval)
{
    oe_spin_lock(&_lock);
    oe_thread_info_t* thread_info =
        _get_thread_info(oe_pthread_self(), _running);
    oe_spin_unlock(&_lock);

    if (!thread_info)
    {
        // Decrement refcount before doing longjmp.
        thread_info->ret_val = retval;
        _thread_info_dec_ref(thread_info);
        oe_longjmp(&thread_info->jmp_buf, 1);
    }
    // Control should never reach here.
    oe_abort();
}
