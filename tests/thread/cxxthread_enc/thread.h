// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Intentionally using the same guard as the internal thread.h as we
// want the pthread_enc test to be routed to the pthread* libc calls.
// Include this first to ensure that the internal/thread.h will not be
// included.
#ifndef _OE_INCLUDE_THREAD_H
#define _OE_INCLUDE_THREAD_H

#include <condition_variable>
#include <shared_mutex>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <ostream>

#define CXX_THREADS

//==============================================================================
//
// Thread
//
//==============================================================================

struct oe_thread_t
{
    std::thread::id rep;

    oe_thread_t(int)
    {
    }

    oe_thread_t(const oe_thread_t& x)
    {
    }

private:

    oe_thread_t(const std::thread::id& id) : rep(id)
    {
    }

    friend oe_thread_t oe_thread_self();
};

inline std::ostream& operator<<(std::ostream& os, const oe_thread_t& x)
{
    return os << x.rep;
}

inline bool operator==(const oe_thread_t& x, const oe_thread_t& y)
{
    return x.rep == y.rep;
}

inline oe_thread_t oe_thread_self()
{
    return oe_thread_t(std::this_thread::get_id());
}

//==============================================================================
//
// Mutex:
//
//==============================================================================

enum oe_mutex_initializer_t
{
    OE_MUTEX_INITIALIZER
};

struct oe_mutex_t
{
    std::mutex rep;

    oe_mutex_t(oe_mutex_initializer_t)
    {
    }

    oe_mutex_t(const oe_mutex_t&)
    {
    }
};

inline int oe_mutex_lock(oe_mutex_t* m)
{
    m->rep.lock();
    return 0;
}

inline int oe_mutex_unlock(oe_mutex_t* m)
{
    m->rep.unlock();
    return 0;
}

//==============================================================================
//
// Spinlock:
//
//==============================================================================

enum oe_spinlock_initializer_t
{
    OE_SPINLOCK_INITIALIZER
};

struct oe_spinlock_t
{
    std::atomic_flag impl;

    oe_spinlock_t()
    {
    }

    oe_spinlock_t(oe_spinlock_initializer_t)
    {
    }
    
    oe_spinlock_t(const oe_spinlock_t&)
    {
    }
};

inline int oe_spin_lock(oe_spinlock_t* lock)
{
    while (lock->impl.test_and_set(std::memory_order_acquire))
        ;
    return 0;
}

inline int oe_spin_unlock(oe_spinlock_t* lock)
{
    lock->impl.clear(std::memory_order_release);
    return 0;
}

//==============================================================================
//
// Condition:
//
//==============================================================================

enum oe_cond_initializer_t
{
    OE_COND_INITIALIZER
};

struct oe_cond_t
{
    std::condition_variable_any c;

    oe_cond_t(oe_cond_initializer_t)
    {
    }

    oe_cond_t(const oe_cond_t&)
    {
    }
};

inline int oe_cond_wait(oe_cond_t* cond, oe_mutex_t* mutex)
{
    cond->c.wait(mutex->rep);
    return 0;
}

inline int oe_cond_signal(oe_cond_t* cond)
{
    cond->c.notify_one();
    return 0;
}

inline int oe_cond_broadcast(oe_cond_t* cond)
{
    cond->c.notify_all();
    return 0;
}

//==============================================================================
//
// Read-write lock not supported (excpept in C++17 where std::shared_mutex()
// can be used).
//
//==============================================================================

#define SUPPRESS_READ_WRITE_LOCKS

#endif /* _OE_INCLUDE_THREAD_H */
