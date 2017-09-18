[Index](index.md)

---
# OE_MutexUnlock()

Releases a mutex.

## Syntax

    int OE_MutexUnlock(
        mutex);
## Description 

This function releases the lock on a mutex obtained with either OE_MutexLock() or OE_MutexTryLock().

In enclaves, this function performs an OCALL, where it wakes the next thread waiting on a mutex.



## Parameters

#### mutex

Release the lock on this mutex.

## Returns

Returns zero on success.

---
[Index](index.md)

