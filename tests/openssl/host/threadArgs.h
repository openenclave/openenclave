// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _THREAD_ARGS_H
#define _THREAD_ARGS_H

#include <atomic>
#include <mutex>

const uint64_t MAX_ENC_KEYS = 16;

class atomic_flag_lock
{
  public:
    void lock()
    {
        while (_flag.test_and_set())
        {
            continue;
        }
    }
    void unlock()
    {
        _flag.clear();
    }

  private:
    std::atomic_flag _flag = ATOMIC_FLAG_INIT;
};

typedef std::unique_lock<atomic_flag_lock> atomic_lock;

#endif /* _THREAD_ARGS_H */
