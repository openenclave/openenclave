Thread library tests
=====================

Test various OE synchronization primitives:
- **oe_mutex_t**
  1. *TestMutex* : Tests basic locking, unlocking, recursive locking.
  1. *TestThreadLockingPatterns* : Tests various locking patterns A/B, A/B/C, A/A/B/C etc in a tight-loop across multiple threads.


- **oe_cond_t**
  1. *TestCond* : Tests basic condition variable use.
  1. *TestThreadWakeWait* : Tests internal `_ThreadWakeWait` function.
  1. *TestCondBroadcast* : Tests `oe_cond_broadcast` function in a tight-loop to assert that all waiting threads are woken.


  **oe_rwlock_t**
  1. *TestReadersWriterLock* : Tests readers-writer lock invariants by launching multiple reader and writer threads racing against each other. Asserts that multiple/all readers can be simultaneously active, only one writer is active,  readers and writers are never simultaneously active.

  **oe_spinlock_t**
  DISABLED: These tests are disabled due to an open investigation into
  deadlock in the oethread/pthread tests.
  1. *TestErrnoMultiThreadsSameenclave* : Tests errno can be set correctly in multi-threads for same enclaves.
  2. *TestErrnoMultiThreadsDiffenclave* : Tests errno can be set correctly in multi-threads for different enclaves.

This directory builds test enclaves for both OE threads and pthreads.
