[Index](index.md)

---
# OE_SpinLock()

Acquire a lock on a spin lock.

## Syntax

    int OE_SpinLock(OE_Spinlock *spinlock)
## Description 

A thread calls this function to acquire a lock on a spin lock. If another thread has already acquired a lock, the calling thread spins until the lock is available. If more than one thread is waiting on the spin lock, the selection of the next thread to obtain the lock is arbitrary.



## Parameters

#### spinlock

Lock this spin lock.

## Returns

Return zero if successful

---
[Index](index.md)

