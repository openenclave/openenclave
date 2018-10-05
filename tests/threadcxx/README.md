C++11 std::thread tests
=======================

Test various C++11 synchronization primitives provided for std::thread.
- **std::mutex**  and **std::recursive_mutex**
  1. *TestMutex* : Tests basic locking, unlocking, recursive locking.
  1. *TestThreadLockingPatterns* : Tests various locking patterns A/B, A/B/C, A/A/B/C etc in a tight-loop across multiple threads.


- **std::condition_variable**, **std::unique_lock**, **std::lock_guard**
  1. *TestCond* : Tests basic condition variable use.
  1. *TestThreadWakeWait* : Tests internal _ThreadWakeWait function.
  1. *TestCondBroadcast* : Tests notify_all function in a tight-loop to verify that all waiting threads are woken.

Uses and tests the **std::atomic types** as well.
